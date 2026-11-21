"""Stack Overflow source: scan questions for pasted AI API keys.

Free, no key required at low volume. Uses the Stack Exchange API
(``/2.3/search/advanced``) with the ``withbody`` filter, which returns
question bodies. Anonymous quota is 300 requests/day per IP; the API
returns ``quota_remaining`` and a ``backoff`` field — both are honoured
here (sleep on backoff, stop cleanly when the quota is exhausted).

Bodies arrive as HTML; tags are stripped before scanning. Bounded by
``--max-questions`` (default 10) and one page of results.

Candidates only: no verification of found keys (redacted, masked).
Verification stays off unless the user passes explicit --verify for keys
they own.
"""
from __future__ import annotations

import html
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from .base import Source

API_URL = "https://api.stackexchange.com/2.3/search/advanced"
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"[ \t]+")


class StackOverflowError(RuntimeError):
    pass


class StackOverflowSource(Source):
    name = "stackoverflow"

    def __init__(self, query: str, max_questions: int = 10):
        self.query = query
        self.max_questions = max_questions
        self.api_requests = 0
        self.rate_limit_hits = 0
        self.questions_scanned = 0
        self.quota_remaining: int | None = None

    def _strip_html(self, body: str) -> str:
        text = _TAG_RE.sub(" ", html.unescape(body or ""))
        return _WS_RE.sub(" ", text)

    def iter_lines(self):
        params = urllib.parse.urlencode({
            "order": "desc",
            "sort": "relevance",
            "q": self.query,
            "site": "stackoverflow",
            "pagesize": max(1, min(self.max_questions, 25)),
            "filter": "withbody",
        })
        url = f"{API_URL}?{params}"
        req = urllib.request.Request(
            url, headers={"User-Agent": "aiscan-prototype/0.1"})
        self.api_requests += 1
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as e:
            if e.code == 429:
                self.rate_limit_hits += 1
                raise StackOverflowError(
                    "Stack Exchange rate limit (429). Anonymous quota is "
                    "300 requests/day; wait or add an API key.")
            raise StackOverflowError(
                f"Stack Exchange request failed (HTTP {e.code}).")
        except urllib.error.URLError as e:
            raise StackOverflowError(f"Network error reaching {url}: {e}")
        if data.get("backoff"):
            self.rate_limit_hits += 1
            time.sleep(min(int(data["backoff"]), 60))
        self.quota_remaining = data.get("quota_remaining")
        if self.quota_remaining == 0:
            raise StackOverflowError(
                "Stack Exchange anonymous quota exhausted (0 remaining). "
                "Wait for the daily reset or add an API key.")
        for item in data.get("items", [])[:self.max_questions]:
            qid = item.get("question_id", "?")
            self.questions_scanned += 1
            title = item.get("title", "")
            body = self._strip_html(item.get("body", ""))
            display = f"stackoverflow:question/{qid}"
            lines = [f"TITLE: {title}"] + body.splitlines()
            for i, line in enumerate(lines, 1):
                yield (display, i, line,
                       {"source": "stackoverflow", "question": qid,
                        "url": item.get("link", "")})

    @property
    def stats(self) -> dict:
        return {
            "questions_scanned": self.questions_scanned,
            "api_requests": self.api_requests,
            "rate_limit_hits": self.rate_limit_hits,
            "quota_remaining": self.quota_remaining,
        }
