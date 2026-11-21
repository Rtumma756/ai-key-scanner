"""GitHub public gists source: scan recent public gists for leaked keys.

Uses the Gist API (``GET /gists/public``), which lists recent public
gists in reverse chronological order — there is no keyword search on
gists, so this source sweeps the recent firehose, bounded by
``--max-gists``. Token is optional (env GITHUB_TOKEN / --token):
anonymous callers get 60 API requests/hour, authenticated 5,000/hour.
Each gist file is fetched via its raw_url (size-capped).

Candidates only: no verification of found keys (redacted, masked).
Verification stays off unless the user passes explicit --verify for keys
they own.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from .base import Source

GISTS_URL = "https://api.github.com/gists/public"
DEFAULT_MAX_FILE_BYTES = 500_000


class GistError(RuntimeError):
    pass


class GistSource(Source):
    name = "gists"

    def __init__(self, token: str | None = None, max_gists: int = 10,
                 max_pages: int = 1, per_page: int = 30,
                 max_file_bytes: int = DEFAULT_MAX_FILE_BYTES):
        self.token = token
        self.max_gists = max_gists
        self.max_pages = max_pages
        self.per_page = per_page
        self.max_file_bytes = max_file_bytes
        self.api_requests = 0
        self.rate_limit_hits = 0
        self.gists_scanned = 0
        self.files_scanned = 0
        self.files_skipped_large = 0

    def _headers(self) -> dict:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "aiscan-prototype/0.1",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _request(self, url: str):
        req = urllib.request.Request(url, headers=self._headers())
        self.api_requests += 1
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as e:
            headers = dict(e.headers or {})
            if e.code == 403 and headers.get("X-RateLimit-Remaining") == "0":
                self.rate_limit_hits += 1
                reset = int(headers.get("X-RateLimit-Reset", "0") or 0)
                wait = max(0, reset - int(time.time()))
                if wait > 120:
                    raise GistError(
                        f"GitHub gist rate limit hit; resets in {wait}s "
                        "(over the 120s cap). Anonymous callers get 60 "
                        "requests/hour — set GITHUB_TOKEN to raise the limit."
                    )
                time.sleep(wait + 1)
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return resp.status, dict(resp.headers), resp.read()
            if e.code == 401:
                raise GistError(
                    "GitHub rejected the token (401). Check GITHUB_TOKEN "
                    "or --token."
                )
            if e.code == 403:
                raise GistError(
                    f"GitHub refused the gist request (403): "
                    f"{e.read().decode('utf-8', errors='replace')[:200]}"
                )
            raise GistError(f"GitHub API error HTTP {e.code} on {url}.")
        except urllib.error.URLError as e:
            raise GistError(f"Network error reaching {url}: {e}")

    def _fetch_raw(self, url: str) -> bytes | None:
        """Fetch a gist file's raw content. None on any failure (skip)."""
        req = urllib.request.Request(url, headers={"User-Agent": "aiscan-prototype/0.1"})
        self.api_requests += 1
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.read()
        except (urllib.error.HTTPError, urllib.error.URLError):
            return None

    def iter_lines(self):
        page = 1
        fetched = 0
        while page <= self.max_pages and fetched < self.max_gists:
            params = urllib.parse.urlencode({
                "per_page": self.per_page,
                "page": page,
            })
            status, _headers, body = self._request(f"{GISTS_URL}?{params}")
            if status != 200:
                raise GistError(f"GitHub gists API returned HTTP {status}.")
            gists = json.loads(body.decode("utf-8", errors="replace"))
            if not gists:
                return
            for gist in gists:
                if fetched >= self.max_gists:
                    return
                fetched += 1
                self.gists_scanned += 1
                gist_id = gist.get("id", "?")
                for filename, info in (gist.get("files") or {}).items():
                    size = info.get("size", 0) or 0
                    if size > self.max_file_bytes:
                        self.files_skipped_large += 1
                        continue
                    raw_url = info.get("raw_url")
                    if not raw_url:
                        continue
                    content = self._fetch_raw(raw_url)
                    if content is None:
                        continue
                    self.files_scanned += 1
                    text = content.decode("utf-8", errors="replace")
                    display = f"gist:{gist_id}/{filename}"
                    for i, line in enumerate(text.splitlines(), 1):
                        yield (display, i, line,
                               {"source": "gists", "gist": gist_id})
            if len(gists) < self.per_page:
                return
            page += 1

    @property
    def stats(self) -> dict:
        return {
            "gists_scanned": self.gists_scanned,
            "files_scanned": self.files_scanned,
            "files_skipped_large": self.files_skipped_large,
            "api_requests": self.api_requests,
            "rate_limit_hits": self.rate_limit_hits,
        }
