"""Common Crawl source: scan a tiny sample of the public web archive.

Free, no key needed. Flow:
  1. ``https://index.commoncrawl.org/collinfo.json`` picks the newest crawl
     index (no hardcoded index name to go stale).
  2. The index API returns JSON lines (url, filename, offset, length,
     status, mime) for a URL pattern the user supplies (wildcards
     allowed, e.g. ``example.com/*``).
  3. A bounded sample of records (default 3) is fetched from
     ``https://data.commoncrawl.org/<filename>`` with an HTTP Range
     request, gunzipped, parsed as a WARC response record, and its body
     text is scanned.

The sample is deliberately tiny: full-scale Common Crawl use needs batch
processing (Athena/Spark), not a prototype CLI. Only ``text/*`` records
with HTTP 200 are fetched.

Candidates only: no verification of found keys (redacted, masked).
Verification stays off unless the user passes explicit --verify for keys
they own.
"""
from __future__ import annotations

import gzip
import io
import json
import urllib.error
import urllib.parse
import urllib.request

from .base import Source

COLLINFO_URL = "https://index.commoncrawl.org/collinfo.json"
DATA_URL = "https://data.commoncrawl.org"


class CommonCrawlError(RuntimeError):
    pass


class CommonCrawlSource(Source):
    name = "commoncrawl"

    def __init__(self, url_pattern: str, max_records: int = 3):
        self.url_pattern = url_pattern
        self.max_records = max_records
        self.api_requests = 0
        self.records_scanned = 0
        self.records_skipped = 0
        self.bytes_downloaded = 0
        self.index_used = ""

    def _get(self, url: str, headers: dict | None = None,
             timeout: int = 30) -> bytes:
        req = urllib.request.Request(
            url, headers=headers or {"User-Agent": "aiscan-prototype/0.1"})
        self.api_requests += 1
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise CommonCrawlError(
                    f"Common Crawl has no index entry for this query (404 "
                    f"on {url}). Try a different URL pattern.")
            raise CommonCrawlError(
                f"Common Crawl request failed (HTTP {e.code}) on {url}.")
        except urllib.error.URLError as e:
            raise CommonCrawlError(f"Network error reaching {url}: {e}")

    def _latest_index(self) -> str:
        data = json.loads(self._get(COLLINFO_URL).decode("utf-8", errors="replace"))
        if not data:
            raise CommonCrawlError("Common Crawl returned an empty index list.")
        # collinfo.json is ordered newest-first; the first entry is newest.
        newest = data[0]
        self.index_used = newest.get("id", "")
        return self.index_used

    def _query_index(self, index: str) -> list:
        params = urllib.parse.urlencode({
            "url": self.url_pattern,
            "output": "json",
            "limit": max(1, self.max_records * 2),
        })
        url = f"https://index.commoncrawl.org/{index}-index?{params}"
        raw = self._get(url).decode("utf-8", errors="replace")
        records = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if rec.get("status") == "200" and str(rec.get("mime", "")).startswith("text/"):
                records.append(rec)
            else:
                self.records_skipped += 1
        return records

    def _fetch_record_text(self, rec: dict) -> str | None:
        filename = rec.get("filename", "")
        try:
            offset = int(rec.get("offset", 0))
            length = int(rec.get("length", 0))
        except (TypeError, ValueError):
            return None
        if not filename or length <= 0:
            return None
        headers = {
            "Range": f"bytes={offset}-{offset + length - 1}",
            "User-Agent": "aiscan-prototype/0.1",
        }
        try:
            raw = self._get(f"{DATA_URL}/{filename}", headers=headers,
                            timeout=60)
        except CommonCrawlError:
            return None
        self.bytes_downloaded += len(raw)
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
                warc = gz.read()
        except (OSError, EOFError):
            return None
        # WARC record: WARC headers, blank line, HTTP response (status
        # line, headers, blank line, body).
        try:
            _warc_headers, rest = warc.split(b"\r\n\r\n", 1)
            _http_headers, body = rest.split(b"\r\n\r\n", 1)
        except ValueError:
            return None
        return body.decode("utf-8", errors="replace")

    def iter_lines(self):
        index = self._latest_index()
        records = self._query_index(index)
        for rec in records[:self.max_records]:
            text = self._fetch_record_text(rec)
            if text is None:
                self.records_skipped += 1
                continue
            self.records_scanned += 1
            display = f"commoncrawl:{rec.get('url', '?')}"
            for i, line in enumerate(text.splitlines(), 1):
                yield (display, i, line,
                       {"source": "commoncrawl",
                        "url": rec.get("url", ""),
                        "index": index})

    @property
    def stats(self) -> dict:
        return {
            "records_scanned": self.records_scanned,
            "records_skipped": self.records_skipped,
            "bytes_downloaded": self.bytes_downloaded,
            "api_requests": self.api_requests,
            "rate_limit_hits": 0,
            "index_used": self.index_used,
        }
