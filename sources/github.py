"""GitHub code-search source: live internet mode.

Uses the authenticated GitHub code search API with text-match fragments, so
matching lines arrive without fetching every file. Rate limits are handled
explicitly: GitHub allows 10 code-search requests per minute for
authenticated users (current docs — the 30/min figure applies to GitHub's
other search endpoints, not code search). Requests are paced at least 6s
apart so the run stays under the limit; on a limit hit we sleep for the
wait GitHub asks for (or until reset, or a fixed 60s) and retry up to 3
times. Dropped connections and timeouts are retried the same way. Every
failure surfaces only as GitHubError — nothing raw ever escapes _request.

The query is always supplied by the user (their own key fingerprint/prefix,
org name, or a test pattern). This source never invents a query.
"""
from __future__ import annotations

import http.client
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from .base import Source


class GitHubError(RuntimeError):
    pass


# Code search allows 10 requests/min authenticated. Pace every request
# (across all GitHubSource instances — a stress run creates one per query)
# so the run never trips the limit by firing back-to-back.
_MIN_REQUEST_INTERVAL = 6.0
_last_request_at = 0.0


def _pace() -> None:
    global _last_request_at
    now = time.monotonic()
    gap = now - _last_request_at
    if gap < _MIN_REQUEST_INTERVAL:
        time.sleep(_MIN_REQUEST_INTERVAL - gap)
    _last_request_at = time.monotonic()


class GitHubSource(Source):
    name = "github"

    def __init__(self, query: str, token: str, max_pages: int = 1,
                 per_page: int = 100, max_items: int = 150,
                 start_page: int = 1):
        self.query = query
        self.token = token
        self.max_pages = max_pages
        self.per_page = per_page
        self.max_items = max_items
        self.start_page = max(1, start_page)
        self.items_seen = 0
        self.rate_limit_hits = 0
        self.api_requests = 0
        self.total_count = None  # estimated total matches (API field)
        self.pages_seen = {}     # page number -> items returned on it

    def _request(self, url: str):
        """One API call with retries. Every failure mode the network can
        throw (403/429 rate limits, dropped connections, timeouts) is
        retried with backoff and only ever surfaces as GitHubError — a
        raw exception must never escape and kill a long run."""
        headers = {
            "Accept": "application/vnd.github+json, "
                      "application/vnd.github.text-match+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "aiscan-prototype/0.1",
        }
        req = urllib.request.Request(url, headers=headers)
        attempts = 0
        while True:
            attempts += 1
            _pace()
            self.api_requests += 1
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return resp.status, dict(resp.headers), resp.read()
            except urllib.error.HTTPError as e:
                body = e.read().decode("utf-8", errors="replace")
                resp_headers = dict(e.headers or {})
                if e.code == 401:
                    raise GitHubError(
                        "GitHub rejected the token (401). Check "
                        "GITHUB_TOKEN or --token; it must be a valid "
                        "personal access token."
                    )
                if e.code == 422:
                    raise GitHubError(
                        f"GitHub rejected the query (422): {body[:200]}. "
                        "Try a more specific search pattern."
                    )
                if e.code in (403, 429):
                    # Rate limit (primary or secondary/abuse). Retry
                    # with the wait GitHub asks for, else until reset,
                    # else a fixed 60s backoff.
                    self.rate_limit_hits += 1
                    if attempts >= 3:
                        raise GitHubError(
                            f"GitHub rate limit (HTTP {e.code}) still in "
                            f"effect after {attempts} attempts: "
                            f"{body[:200]}"
                        )
                    if resp_headers.get("Retry-After"):
                        wait = min(int(resp_headers["Retry-After"]), 120)
                    elif resp_headers.get("X-RateLimit-Reset"):
                        reset = int(resp_headers["X-RateLimit-Reset"] or 0)
                        wait = min(max(0, reset - int(time.time())) + 1,
                                   120)
                    else:
                        wait = 60
                    time.sleep(wait)
                    continue
                raise GitHubError(
                    f"GitHub API error HTTP {e.code}: {body[:200]}")
            except (urllib.error.URLError, http.client.HTTPException,
                    TimeoutError, ConnectionError, OSError) as e:
                # Dropped connection, DNS/TLS failure, timeout: retry
                # with backoff, then fail cleanly as GitHubError.
                if attempts >= 3:
                    raise GitHubError(
                        "Network error reaching api.github.com after "
                        f"{attempts} attempts: {e}"
                    )
                time.sleep(min(10 * attempts, 60))
                continue

    def iter_lines(self):
        page = self.start_page
        end_page = self.start_page + self.max_pages - 1
        while page <= end_page and self.items_seen < self.max_items:
            params = urllib.parse.urlencode({
                "q": self.query,
                "per_page": self.per_page,
                "page": page,
            })
            url = f"https://api.github.com/search/code?{params}"
            status, headers, body = self._request(url)
            if status != 200:
                raise GitHubError(f"GitHub API returned HTTP {status}.")
            data = json.loads(body.decode("utf-8", errors="replace"))
            if self.total_count is None:
                self.total_count = data.get("total_count")
            items = data.get("items", [])
            self.pages_seen[page] = len(items)
            if not items:
                return
            for item in items:
                if self.items_seen >= self.max_items:
                    return
                self.items_seen += 1
                repo = item.get("repository", {}).get("full_name", "?")
                path = item.get("path", "?")
                display = f"github:{repo}/{path}"
                fragments = [tm.get("fragment", "")
                             for tm in item.get("text_matches", [])]
                if not fragments:
                    # No fragment returned; nothing to scan without a fetch.
                    continue
                for frag in fragments:
                    for i, line in enumerate(frag.splitlines(), 1):
                        yield (display, i, line, {
                            "source": "github",
                            "repo": repo,
                            "url": item.get("html_url", ""),
                        })
            if len(items) < self.per_page:
                return
            page += 1

    @property
    def stats(self) -> dict:
        return {
            "items_seen": self.items_seen,
            "api_requests": self.api_requests,
            "rate_limit_hits": self.rate_limit_hits,
            "total_count": self.total_count,
            "pages": dict(self.pages_seen),
        }
