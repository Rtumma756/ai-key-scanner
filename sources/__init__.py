"""Source package: local filesystem, git history, GitHub code search, demo,
Docker Hub, gists, npm, PyPI, Pastebin, Stack Overflow, Common Crawl."""
from .base import Source
from .commoncrawl import CommonCrawlError, CommonCrawlSource
from .demo import DemoSource
from .dockerhub import DockerHubError, DockerHubSource
from .gists import GistError, GistSource
from .git_history import GitHistorySource
from .github import GitHubError, GitHubSource
from .local import LocalSource
from .npm import NpmError, NpmSource
from .pastebin import PastebinError, PastebinSource
from .pypi import PypiError, PypiSource
from .stackoverflow import StackOverflowError, StackOverflowSource

__all__ = ["Source", "DemoSource", "GitHistorySource", "GitHubError",
           "GitHubSource", "LocalSource", "DockerHubError", "DockerHubSource",
           "GistError", "GistSource", "NpmError", "NpmSource",
           "PypiError", "PypiSource", "PastebinError", "PastebinSource",
           "StackOverflowError", "StackOverflowSource", "CommonCrawlError",
           "CommonCrawlSource"]
