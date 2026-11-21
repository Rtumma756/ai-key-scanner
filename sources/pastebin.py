"""Pastebin source: scan recent public pastes for leaked keys.

FREE-TIER ONLY, and the limitation is real: Pastebin has no free search
API — keyword search and the scraping API need a paid PRO key. What the
free tier does offer is the public archive page, which lists recent
public pastes, and raw fetch of any public paste. This source uses only
that:
  1. GET https://pastebin.com/archive (one page) and parse recent paste IDs.
  2. GET https://pastebin.com/raw/<id> for a bounded number of pastes
     (default 5), with a 1s delay between requests.

Pastebin rate-limits aggressively; on 403/429 the source stops cleanly
and records the limit instead of retrying in a loop. This is a
firehose sample, not a search — it finds whatever was pasted recently,
which is exactly why it is useful for trial runs but not a targeted
search. See sources/roadmap.md for the paid-API gap.
"""
from __future__ import annotations

import re
import time
import urllib.error
import urllib.request

from .base import Source

ARCHIVE_URL = "https://pastebin.com/archive"
RAW_URL = "https://pastebin.com/raw"
# Archive links look like href="/AbCdEfGh?source=archive" — 8 alphanumerics
# followed by a query string or the closing quote.
_PASTE_RE = re.compile(r'href="/([A-Za-z0-9]{8})(\?|")')
REQUEST_DELAY_S = 1.0
DEFAULT_MAX_PASTE_BYTES = 500_000


class PastebinError(RuntimeError):
    pass


class PastebinSource(Source):
    name = "pastebin"

    def __init__(self, max_pastes: int = 5,
                 max_paste_bytes: int = DEFAULT_MAX_PASTE_BYTES):
        self.max_pastes = max_pastes
        self.max_paste_bytes = max_paste_bytes
        self.api_requests = 0
        self.rate_limit_hits = 0
        self.pastes_scanned = 0
        self.pastes_skipped = 0
        self.limited = False

    def _get(self, url: str, timeout: int = 30) -> bytes:
        req = urllib.request.Request(
            url, headers={"User-Agent": "aiscan-prototype/0.1"})
        self.api_requests += 1
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):
                self.rate_limit_hits += 1
                self.limited = True
                raise PastebinError(
                    f"Pastebin rate limit (HTTP {e.code}). Pastebin limits "
                    "free raw fetches aggressively; wait and retry later.")
            raise PastebinError(
                f"Pastebin request failed (HTTP {e.code}) on {url}.")
        except urllib.error.URLError as e:
            raise PastebinError(f"Network error reaching {url}: {e}")

    def _list_recent(self) -> list:
        html = self._get(ARCHIVE_URL).decode("utf-8", errors="replace")
        ids: list = []
        for m in _PASTE_RE.finditer(html):
            if m.group(1) not in ids:
                ids.append(m.group(1))
        return ids

    def iter_lines(self):
        try:
            paste_ids = self._list_recent()
        except PastebinError as e:
            raise PastebinError(str(e))
        for paste_id in paste_ids[:self.max_pastes]:
            time.sleep(REQUEST_DELAY_S)
            try:
                raw = self._get(f"{RAW_URL}/{paste_id}")
            except PastebinError as e:
                self.pastes_skipped += 1
                # A rate limit stops the whole run cleanly — no hammering.
                if self.limited:
                    return
                continue
            if len(raw) > self.max_paste_bytes:
                self.pastes_skipped += 1
                continue
            self.pastes_scanned += 1
            text = raw.decode("utf-8", errors="replace")
            display = f"pastebin:{paste_id}"
            for i, line in enumerate(text.splitlines(), 1):
                yield (display, i, line,
                       {"source": "pastebin", "paste": paste_id})

    @property
    def stats(self) -> dict:
        return {
            "pastes_scanned": self.pastes_scanned,
            "pastes_skipped": self.pastes_skipped,
            "api_requests": self.api_requests,
            "rate_limit_hits": self.rate_limit_hits,
            "rate_limited": self.limited,
        }
