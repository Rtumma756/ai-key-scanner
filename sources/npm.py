"""npm registry source: scan public package tarballs for leaked keys.

Free, no token needed. Flow:
  1. npm search API (``/-/v1/search``) finds packages matching the query.
  2. For each package (bounded by ``--max-packages``, default 5), fetch
     its packument, take the latest version's tarball, download it with a
     per-package byte cap (default 10 MB), extract text files and scan.

Candidates only: no verification of found keys (redacted, masked).
Verification stays off unless the user passes explicit --verify for keys
they own.
"""
from __future__ import annotations

import io
import json
import tarfile
import urllib.error
import urllib.parse
import urllib.request

from .base import Source

SEARCH_URL = "https://registry.npmjs.org/-/v1/search"
PACKUMENT_URL = "https://registry.npmjs.org"
DEFAULT_MAX_BYTES_PER_PACKAGE = 10_000_000
DEFAULT_MAX_FILE_BYTES = 2_000_000
BINARY_PROBE_BYTES = 8192


class NpmError(RuntimeError):
    pass


class NpmSource(Source):
    name = "npm"

    def __init__(self, query: str, max_packages: int = 5,
                 max_bytes_per_package: int = DEFAULT_MAX_BYTES_PER_PACKAGE,
                 max_file_bytes: int = DEFAULT_MAX_FILE_BYTES):
        self.query = query
        self.max_packages = max_packages
        self.max_bytes_per_package = max_bytes_per_package
        self.max_file_bytes = max_file_bytes
        self.api_requests = 0
        self.rate_limit_hits = 0
        self.packages_scanned = 0
        self.packages_skipped = 0
        self.files_scanned = 0
        self.bytes_downloaded = 0
        self.skipped_reasons: list = []

    def _get_json(self, url: str) -> dict:
        req = urllib.request.Request(
            url, headers={"User-Agent": "aiscan-prototype/0.1",
                          "Accept": "application/json"})
        self.api_requests += 1
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as e:
            if e.code == 429:
                self.rate_limit_hits += 1
                raise NpmError(
                    "npm registry rate limit (429). Back off and retry "
                    "later; the free search API is rate-limited.")
            raise NpmError(f"npm request failed (HTTP {e.code}) on {url}.")
        except urllib.error.URLError as e:
            raise NpmError(f"Network error reaching {url}: {e}")

    def _download_capped(self, url: str, budget: int) -> bytes | None:
        """Download at most ``budget`` bytes; None if it overflows/fails."""
        req = urllib.request.Request(
            url, headers={"User-Agent": "aiscan-prototype/0.1"})
        self.api_requests += 1
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
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
        except (urllib.error.HTTPError, urllib.error.URLError):
            return None

    def _search(self) -> list:
        params = urllib.parse.urlencode({
            "text": self.query,
            "size": max(1, min(self.max_packages, 20)),
        })
        data = self._get_json(f"{SEARCH_URL}?{params}")
        names = []
        for obj in data.get("objects", []):
            pkg = obj.get("package", {})
            if pkg.get("name"):
                names.append(pkg["name"])
        return names

    def _scan_package(self, name: str):
        """Yield lines from one package tarball."""
        safe = urllib.parse.quote(name, safe="@/")
        data = self._get_json(f"{PACKUMENT_URL}/{safe}")
        versions = data.get("versions", {})
        dist_tags = data.get("dist-tags", {})
        latest = dist_tags.get("latest")
        version_info = versions.get(latest) if latest else None
        if not version_info:
            if not versions:
                self.skipped_reasons.append(f"{name}: no versions published")
                return
            version_info = versions[sorted(versions)[-1]]
        tarball = (version_info.get("dist") or {}).get("tarball")
        if not tarball:
            self.skipped_reasons.append(f"{name}: no tarball URL")
            return
        blob = self._download_capped(tarball, self.max_bytes_per_package)
        if blob is None:
            self.skipped_reasons.append(
                f"{name}: tarball over {self.max_bytes_per_package} byte "
                "cap or download failed; skipped")
            return
        self.bytes_downloaded += len(blob)
        self.packages_scanned += 1
        try:
            tf = tarfile.open(fileobj=io.BytesIO(blob), mode="r:*")
        except tarfile.TarError:
            self.skipped_reasons.append(f"{name}: tarball not readable")
            return
        with tf:
            for member in tf:
                if not member.isfile() or member.size > self.max_file_bytes:
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
                self.files_scanned += 1
                text = content.decode("utf-8", errors="replace")
                display = f"npm:{name}/{member.name.lstrip('./')}"
                for i, line in enumerate(text.splitlines(), 1):
                    yield (display, i, line,
                           {"source": "npm", "package": name})

    def iter_lines(self):
        try:
            names = self._search()
        except NpmError as e:
            raise NpmError(str(e))
        for name in names[:self.max_packages]:
            try:
                yield from self._scan_package(name)
            except NpmError as e:
                self.packages_skipped += 1
                self.skipped_reasons.append(f"{name}: {e}")

    @property
    def stats(self) -> dict:
        return {
            "packages_scanned": self.packages_scanned,
            "packages_skipped": self.packages_skipped,
            "files_scanned": self.files_scanned,
            "bytes_downloaded": self.bytes_downloaded,
            "api_requests": self.api_requests,
            "rate_limit_hits": self.rate_limit_hits,
            "skipped_reasons": self.skipped_reasons[:10],
        }
