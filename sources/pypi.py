"""PyPI source: scan public package distributions for leaked keys.

Free, no token needed. PyPI has no free search API, and its HTML search
page serves a JS "Client Challenge" to non-browser clients, so search
uses the PEP 503 simple index (``https://pypi.org/simple/``) instead:
the index is streamed in chunks with a byte cap, and project names
containing the query substring are collected (exact match first, then
prefix, then substring). For each project (bounded by
``--max-packages``, default 5), fetch its JSON metadata
(``https://pypi.org/pypi/<name>/json``), pick the latest sdist (or a
wheel if no sdist), download it with a per-package byte cap (default
10 MB), extract text files and scan.

Wheels are ZIP archives (``zipfile``), sdists are tarballs (``tarfile``).

Candidates only: no verification of found keys (redacted, masked).
Verification stays off unless the user passes explicit --verify for keys
they own.
"""
from __future__ import annotations

import io
import json
import re
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from .base import Source

SEARCH_URL = "https://pypi.org/simple/"
JSON_URL = "https://pypi.org/pypi"
DEFAULT_MAX_BYTES_PER_PACKAGE = 10_000_000
DEFAULT_MAX_FILE_BYTES = 2_000_000
BINARY_PROBE_BYTES = 8192
SIMPLE_INDEX_MAX_BYTES = 60_000_000
_PROJECT_RE = re.compile(r'href="/simple/([A-Za-z0-9_.\-]+)/"')


class PypiError(RuntimeError):
    pass


class PypiSource(Source):
    name = "pypi"

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

    def _get(self, url: str, timeout: int = 30) -> bytes:
        req = urllib.request.Request(
            url, headers={"User-Agent": "aiscan-prototype/0.1"})
        self.api_requests += 1
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            if e.code == 429:
                self.rate_limit_hits += 1
                raise PypiError(
                    "PyPI rate limit (429). Back off and retry later.")
            if e.code == 404:
                raise PypiError(f"PyPI has nothing at {url} (404).")
            raise PypiError(f"PyPI request failed (HTTP {e.code}) on {url}.")
        except urllib.error.URLError as e:
            raise PypiError(f"Network error reaching {url}: {e}")

    def _download_capped(self, url: str, budget: int) -> bytes | None:
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
        """Stream the PEP 503 simple index, collecting names that contain
        the query substring. Stops early once enough matches are found;
        the index is ~50 MB, so the read is byte-capped."""
        want = max(1, min(self.max_packages, 20))
        query = self.query.lower()
        req = urllib.request.Request(
            SEARCH_URL, headers={"User-Agent": "aiscan-prototype/0.1"})
        self.api_requests += 1
        matches: list = []
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                buf = ""
                total = 0
                while total < SIMPLE_INDEX_MAX_BYTES:
                    chunk = resp.read(1024 * 256)
                    if not chunk:
                        break
                    total += len(chunk)
                    buf += chunk.decode("utf-8", errors="replace")
                    for m in _PROJECT_RE.finditer(buf):
                        name = m.group(1)
                        if query in name.lower() and name not in matches:
                            matches.append(name)
                    # Keep only a small tail — a name may straddle chunks.
                    buf = buf[-256:]
                    if len(matches) >= want * 4:
                        break
        except urllib.error.HTTPError as e:
            if e.code == 429:
                self.rate_limit_hits += 1
                raise PypiError(
                    "PyPI rate limit (429). Back off and retry later.")
            raise PypiError(f"PyPI request failed (HTTP {e.code}).")
        except urllib.error.URLError as e:
            raise PypiError(f"Network error reaching {SEARCH_URL}: {e}")
        # Exact match first, then prefix, then substring (index order).
        matches.sort(key=lambda n: (0 if n.lower() == query else
                                    1 if n.lower().startswith(query) else 2))
        return matches[:want]

    def _pick_file(self, data: dict) -> dict | None:
        """Prefer the latest sdist; fall back to a wheel."""
        urls = data.get("urls", [])
        sdist = next((u for u in urls if u.get("packagetype") == "sdist"), None)
        if sdist:
            return sdist
        return next((u for u in urls if u.get("packagetype") == "bdist_wheel"),
                    None)

    def _scan_archive(self, name: str, blob: bytes, filename: str):
        if filename.endswith(".whl") or filename.endswith(".zip"):
            try:
                zf = zipfile.ZipFile(io.BytesIO(blob))
            except zipfile.BadZipFile:
                self.skipped_reasons.append(f"{name}: unreadable wheel/zip")
                return
            members = [(i.filename, i.file_size) for i in zf.infolist()
                       if not i.is_dir()]
            for arcname, size in members:
                if size > self.max_file_bytes:
                    continue
                try:
                    content = zf.read(arcname)
                except (KeyError, zipfile.BadZipFile, OSError):
                    continue
                if b"\x00" in content[:BINARY_PROBE_BYTES]:
                    continue
                yield from self._yield_text(
                    name, arcname, content)
            return
        try:
            tf = tarfile.open(fileobj=io.BytesIO(blob), mode="r:*")
        except tarfile.TarError:
            self.skipped_reasons.append(f"{name}: unreadable sdist tarball")
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
                yield from self._yield_text(name, member.name, content)

    def _yield_text(self, name: str, arcname: str, content: bytes):
        self.files_scanned += 1
        text = content.decode("utf-8", errors="replace")
        display = f"pypi:{name}/{arcname.lstrip('./')}"
        for i, line in enumerate(text.splitlines(), 1):
            yield (display, i, line, {"source": "pypi", "package": name})

    def _scan_package(self, name: str):
        safe = urllib.parse.quote(name, safe="")
        data = json.loads(
            self._get(f"{JSON_URL}/{safe}/json").decode("utf-8", errors="replace"))
        picked = self._pick_file(data)
        if not picked or not picked.get("url"):
            self.skipped_reasons.append(f"{name}: no downloadable file")
            return
        blob = self._download_capped(picked["url"],
                                     self.max_bytes_per_package)
        if blob is None:
            self.skipped_reasons.append(
                f"{name}: file over {self.max_bytes_per_package} byte cap "
                "or download failed; skipped")
            return
        self.bytes_downloaded += len(blob)
        self.packages_scanned += 1
        yield from self._scan_archive(name, blob, picked.get("filename", ""))

    def iter_lines(self):
        try:
            names = self._search()
        except PypiError as e:
            raise PypiError(str(e))
        for name in names[:self.max_packages]:
            try:
                yield from self._scan_package(name)
            except PypiError as e:
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
