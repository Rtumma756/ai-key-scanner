"""Docker Hub source: scan public images for leaked AI API keys.

Flow per image:
  1. Docker Hub search API finds public repositories matching the query.
  2. Registry token (anonymous, public images only) + manifest fetch.
  3. Image config blob first — ENV vars are a common leak spot.
  4. Layers streamed with a per-image byte cap (default 50 MB); oversized
     layers are skipped, never downloaded whole.

Anonymous pulls; auth challenges, rate limits and oversized layers are
handled gracefully with clear messages and recorded in ``stats`` — the
scan never crashes the whole run for one bad image. Bounded by
``--max-images`` (default 5).

Candidates only: no verification of found keys (candidates are redacted
and shown masked). Verification stays off unless the user passes
explicit --verify for keys they own.
"""
from __future__ import annotations

import io
import json
import tarfile
import urllib.error
import urllib.parse
import urllib.request

from .base import Source

HUB_SEARCH_URL = "https://hub.docker.com/v2/search/repositories/"
TOKEN_URL = "https://auth.docker.io/token"
REGISTRY_URL = "https://registry-1.docker.io/v2"

MANIFEST_ACCEPT = (
    "application/vnd.docker.distribution.manifest.list.v2+json,"
    "application/vnd.docker.distribution.manifest.v2+json,"
    "application/vnd.oci.image.manifest.v1+json,"
    "application/vnd.oci.image.index.v1+json"
)
DEFAULT_MAX_BYTES_PER_IMAGE = 50_000_000
DEFAULT_MAX_FILE_BYTES = 2_000_000
BINARY_PROBE_BYTES = 8192


class DockerHubError(RuntimeError):
    pass


class DockerHubSource(Source):
    name = "dockerhub"

    def __init__(self, query: str, max_images: int = 5,
                 max_bytes_per_image: int = DEFAULT_MAX_BYTES_PER_IMAGE,
                 max_file_bytes: int = DEFAULT_MAX_FILE_BYTES):
        self.query = query
        self.max_images = max_images
        self.max_bytes_per_image = max_bytes_per_image
        self.max_file_bytes = max_file_bytes
        self.api_requests = 0
        self.rate_limit_hits = 0
        self.images_scanned = 0
        self.images_skipped = 0
        self.layers_scanned = 0
        self.bytes_downloaded = 0
        self.skipped_reasons: list = []

    # -- HTTP helpers ----------------------------------------------------
    def _get(self, url: str, headers: dict | None = None,
             timeout: int = 30) -> bytes:
        """GET with rate-limit accounting. Raises DockerHubError on failure."""
        req = urllib.request.Request(url, headers=headers or {})
        self.api_requests += 1
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            if e.code == 429:
                self.rate_limit_hits += 1
                retry = e.headers.get("Retry-After") if e.headers else None
                raise DockerHubError(
                    f"Docker Hub rate limit (429) on {url}. "
                    + (f"Retry after {retry}s." if retry else
                       "Anonymous pulls are limited (100/6h per IP); "
                       "try again later or use fewer images.")
                )
            if e.code in (401, 403):
                raise DockerHubError(
                    f"Docker Hub refused access (HTTP {e.code}) on {url}. "
                    "The image may be private or the token request failed."
                )
            raise DockerHubError(
                f"Docker Hub request failed (HTTP {e.code}) on {url}.")
        except urllib.error.URLError as e:
            raise DockerHubError(f"Network error reaching {url}: {e}")

    def _get_stream_capped(self, url: str, headers: dict | None,
                           budget: int, timeout: int = 60) -> bytes | None:
        """Download at most ``budget`` bytes; return None if it overflows."""
        req = urllib.request.Request(url, headers=headers or {})
        self.api_requests += 1
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                chunks: list = []
                total = 0
                while True:
                    chunk = resp.read(1024 * 256)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > budget:
                        return None
                    chunks.append(chunk)
                return b"".join(chunks)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                self.rate_limit_hits += 1
            return None
        except urllib.error.URLError:
            return None

    # -- Registry API ------------------------------------------------------
    def _registry_token(self, repo: str) -> str | None:
        params = urllib.parse.urlencode({
            "service": "registry.docker.io",
            "scope": f"repository:{repo}:pull",
        })
        try:
            body = self._get(f"{TOKEN_URL}?{params}")
        except DockerHubError:
            return None
        try:
            return json.loads(body.decode("utf-8", errors="replace")).get("token")
        except (ValueError, AttributeError):
            return None

    def _fetch_manifest(self, repo: str, token: str, ref: str = "latest"):
        headers = {"Accept": MANIFEST_ACCEPT,
                   "Authorization": f"Bearer {token}"}
        body = self._get(f"{REGISTRY_URL}/{repo}/manifests/{ref}", headers)
        data = json.loads(body.decode("utf-8", errors="replace"))
        if "manifests" in data:
            # Manifest list (multi-arch): prefer linux/amd64, else first.
            entries = data["manifests"]
            chosen = next((m for m in entries
                           if m.get("platform", {}).get("os") == "linux"
                           and m.get("platform", {}).get("architecture") == "amd64"),
                          entries[0] if entries else None)
            if not chosen:
                raise DockerHubError(f"No manifest entries for {repo}.")
            digest = chosen["digest"]
            body = self._get(f"{REGISTRY_URL}/{repo}/manifests/{digest}",
                             headers)
            data = json.loads(body.decode("utf-8", errors="replace"))
        return data

    # -- Scanning ----------------------------------------------------------
    def _scan_config(self, repo: str, tag: str, token: str, manifest: dict,
                     budget: int):
        """Yield ENV lines from the image config blob (prime leak spot)."""
        config = manifest.get("config", {})
        digest = config.get("digest")
        if not digest:
            return
        headers = {"Authorization": f"Bearer {token}"}
        body = self._get_stream_capped(
            f"{REGISTRY_URL}/{repo}/blobs/{digest}", headers, budget)
        if body is None:
            self.skipped_reasons.append(
                f"{repo}:{tag} config blob exceeded byte budget; skipped")
            return
        self.bytes_downloaded += len(body)
        self._image_bytes = getattr(self, "_image_bytes", 0) + len(body)
        try:
            cfg = json.loads(body.decode("utf-8", errors="replace"))
        except ValueError:
            return
        env = []
        container_cfg = cfg.get("config") or {}
        env.extend(container_cfg.get("Env") or [])
        env.extend(cfg.get("config", {}).get("Env") or [])
        seen = set()
        for entry in env:
            if entry in seen:
                continue
            seen.add(entry)
            yield (f"dockerhub:{repo}:{tag}/config.env", 0, str(entry),
                   {"source": "dockerhub", "repo": repo, "tag": tag})

    def _scan_layer(self, repo: str, tag: str, token: str, layer: dict,
                    budget: int):
        """Stream one layer (capped), extract text files, yield lines."""
        digest = layer.get("digest", "")
        size = layer.get("size", 0) or 0
        if size > budget:
            self.skipped_reasons.append(
                f"{repo}:{tag} layer {digest[:19]}... is {size} bytes "
                f"(over remaining {budget} byte budget); skipped")
            return
        headers = {"Authorization": f"Bearer {token}"}
        data = self._get_stream_capped(
            f"{REGISTRY_URL}/{repo}/blobs/{digest}", headers, budget)
        if data is None:
            self.skipped_reasons.append(
                f"{repo}:{tag} layer {digest[:19]}... exceeded byte budget; "
                "skipped")
            return
        self.bytes_downloaded += len(data)
        self._image_bytes = getattr(self, "_image_bytes", 0) + len(data)
        self.layers_scanned += 1
        try:
            tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
        except tarfile.TarError:
            return
        with tf:
            for member in tf:
                if not member.isfile():
                    continue
                if member.size > self.max_file_bytes:
                    continue
                try:
                    f = tf.extractfile(member)
                    if f is None:
                        continue
                    head = f.read(BINARY_PROBE_BYTES)
                    if b"\x00" in head:
                        continue
                    content = head + f.read()
                except (tarfile.TarError, OSError, EOFError):
                    continue
                text = content.decode("utf-8", errors="replace")
                display = f"dockerhub:{repo}:{tag}/{member.name}"
                for i, line in enumerate(text.splitlines(), 1):
                    yield (display, i, line,
                           {"source": "dockerhub", "repo": repo, "tag": tag})

    def _search_repos(self) -> list:
        params = urllib.parse.urlencode({
            "query": self.query,
            "page_size": max(1, min(self.max_images, 25)),
        })
        body = self._get(f"{HUB_SEARCH_URL}?{params}")
        data = json.loads(body.decode("utf-8", errors="replace"))
        repos = []
        for r in data.get("results", []):
            name = r.get("repo_name", "")
            if not name:
                continue
            # Official images come back without a namespace ("hello-world");
            # the registry path is "library/hello-world".
            if "/" not in name:
                name = f"library/{name}"
            repos.append(name)
        return repos

    def iter_lines(self):
        repos = self._search_repos()
        for repo in repos[:self.max_images]:
            tag = "latest"
            budget = self.max_bytes_per_image
            try:
                token = self._registry_token(repo)
                if not token:
                    self.images_skipped += 1
                    self.skipped_reasons.append(
                        f"{repo}:{tag} no registry token (private or "
                        "auth failure); skipped")
                    continue
                manifest = self._fetch_manifest(repo, token, tag)
            except DockerHubError as e:
                self.images_skipped += 1
                self.skipped_reasons.append(f"{repo}:{tag} {e}")
                continue
            self.images_scanned += 1
            self._image_bytes = 0
            try:
                yield from self._scan_config(repo, tag, token, manifest,
                                             budget)
            except DockerHubError as e:
                self.skipped_reasons.append(f"{repo}:{tag} config: {e}")
            for layer in manifest.get("layers", []):
                remaining = max(0, self.max_bytes_per_image
                                - self._image_bytes)
                yield from self._scan_layer(repo, tag, token, layer,
                                            remaining)

    @property
    def stats(self) -> dict:
        return {
            "images_scanned": self.images_scanned,
            "images_skipped": self.images_skipped,
            "layers_scanned": self.layers_scanned,
            "bytes_downloaded": self.bytes_downloaded,
            "api_requests": self.api_requests,
            "rate_limit_hits": self.rate_limit_hits,
            "skipped_reasons": self.skipped_reasons[:10],
        }
