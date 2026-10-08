"""Collection + enrichment source: public GitHub code naming the domain's
hostnames and IPs - leaked configs, manifests, hardcoded endpoints - and
secrets in those files.

Per domain (`collect`), one search for the apex (`"example.com"`) covers
every subdomain - the code-search index tokenizes, so a hit on
`sub.example.com` contains `example.com`. Each hit's file is fetched and every
in-scope hostname in it becomes a "reference" exposure (and a related
hostname, fed back into the pipeline). Only `max_hits` files are examined; a
domain with more hits than that has `overflowed: true` in its data (some
references/secrets in the tail weren't seen - raise `max_hits` to reach them).
Per IP (`enrich`), the IP itself is searched - unless it's not a public
address or looks like shared/CDN infrastructure, where GitHub hits say
nothing about the target's owner.

Hits are post-filtered: the legacy search API ignores punctuation, so
`"10.0.0.5"` also matches `10 0 0 5` - a hit only counts when the exact
name/IP (as a whole token) is in the fragment or file. Forks are dropped, as
are docs/vendored/lock files (`deny_paths`) - unless a secret is in them.
Each kept file is scanned for secrets (see secret_scan.py); found secrets
are stored in full but never tried.

Needs a GitHub token (`token`, any PAT - no scopes needed for public code):
the code-search API has no anonymous access. It allows 10 searches a minute;
file downloads (raw.githubusercontent.com) aren't counted against that and
are bounded by `max_file_fetches` per call instead. See github_web.py for the
web-search scraper, which uses GitHub's newer exact-match search engine.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from typing import ClassVar
from urllib.parse import quote

import requests

from posint_scanner.asn import lookup_asn
from posint_scanner.models import CodeExposure, EnrichmentResult
from posint_scanner.retry import AuthError, with_retry
from posint_scanner.scope import in_scope
from posint_scanner.secret_scan import find_secrets
from posint_scanner.sources.base import (
    DEFAULT_TTL_DAYS,
    QuotaExhaustedError,
    Source,
    SourceSettings,
    SourceUnavailableError,
)
from posint_scanner.sources.common import TIMEOUT_SECONDS, USER_AGENT, VERIFY_TLS

logger = logging.getLogger(__name__)

SEARCH_URL = "https://api.github.com/search/code"
RAW_URL = "https://raw.githubusercontent.com/{repo}/{ref}/{path}"
BLOB_URL = "https://github.com/{repo}/blob/{commit}/{path}"
PER_PAGE = 100
MAX_FILE_BYTES = 1024 * 1024
SNIPPET_CHARS = 300
# Longest rate-limit wait sat out in place; a longer one ends the source's run.
MAX_RATE_LIMIT_WAIT_SECONDS = 60
# Same threshold as the orchestrator's shared-hosting check: an IP serving
# more hostnames than this is someone's shared infrastructure.
SHARED_IP_HOSTNAMES = 25

DEFAULT_DENY_PATHS = [
    "*.md", "*.markdown", "*.rst", "*.html", "*.htm", "*.svg", "*.map", "*.min.js",
    "*.lock", "*package-lock.json", "*package.json", "*changelog*", "*license*",
    "*node_modules/*", "*vendor/*", "*dist/*",
]
# CDN / DDoS-protection networks: Cloudflare, Akamai, Fastly, Imperva
# Incapsula, Sucuri.
DEFAULT_SKIP_ASNS = [13335, 209242, 20940, 16625, 32787, 54113, 19551, 30148]

_BLOB_COMMIT_RE = re.compile(r"/blob/([0-9a-f]{40})/")


class GitHubSearchSettings(SourceSettings):
    # Files (with a hit) looked at per search; more hits than this for the
    # apex domain switches to per-hostname searches.
    max_hits: int = 100
    # Raw file downloads per call; hits past it are judged on their
    # search-result fragments alone.
    max_file_fetches: int = 50
    deny_paths: list[str] = DEFAULT_DENY_PATHS
    skip_asns: list[int] = DEFAULT_SKIP_ASNS
    use_gitleaks: bool = True
    # Off by default: extra binary, slower. On PATH + this = a third engine.
    use_trufflehog: bool = False


class GitHubSettings(GitHubSearchSettings):
    token: str | None = None


@dataclass
class CodeHit:
    """One file a code search returned."""

    repo: str
    path: str
    commit: str
    fragments: list[str]
    fork: bool = False


@dataclass
class SearchPage:
    total: int
    hits: list[CodeHit]
    more: bool  # a further page exists


@dataclass
class _CallBudget:
    """The first request of a call is the call itself (already charged by
    the governor); later ones must ask `extra_request`."""

    source: Source
    used: int = 0
    files_fetched: int = 0

    def request(self) -> bool:
        self.used += 1
        return self.used == 1 or self.source.extra_request()


@dataclass
class _Search:
    target: str  # what the query named (domain or IP)
    matcher: re.Pattern[str]
    exposures: list[CodeExposure] = field(default_factory=list)
    found_names: set[str] = field(default_factory=set)
    total: int = 0
    kept_files: int = 0
    truncated: bool = False


def hostname_matcher(domain: str) -> re.Pattern[str]:
    """Hostnames under `domain` as whole names - not `example.com.evil.org`
    or `notexample.com`."""
    return re.compile(
        r"(?<![a-z0-9-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
        + re.escape(domain)
        + r")(?![a-z0-9-]|\.[a-z0-9])",
        re.IGNORECASE,
    )


def ip_matcher(ip: str) -> re.Pattern[str]:
    """`ip` as a whole address - not inside `110.0.0.51` or `10.0.0.5.1`."""
    return re.compile(r"(?<![\d.])(" + re.escape(ip) + r")(?!\d|\.\d)")


class GitHubCodeSearchSource(Source):
    """The search-backend-independent part: running a search, filtering and
    fetching its hits, and turning them into exposures. Subclasses implement
    `_search_page` for their backend."""

    ttl_days = DEFAULT_TTL_DAYS
    settings_model: ClassVar[type[SourceSettings]] = GitHubSearchSettings
    # Most results a backend will return for one query.
    result_cap: ClassVar[int] = 1000

    def __init__(self, settings: GitHubSearchSettings) -> None:
        self.max_hits = settings.max_hits
        self.max_file_fetches = settings.max_file_fetches
        self.deny_paths = [p.lower() for p in settings.deny_paths]
        self.skip_asns = set(settings.skip_asns)
        self.use_gitleaks = settings.use_gitleaks
        self.use_trufflehog = settings.use_trufflehog
        self._lock = threading.Lock()
        self._files: dict[tuple[str, str, str], str | None] = {}

    @classmethod
    def from_settings(cls, settings: SourceSettings) -> Source:
        assert isinstance(settings, GitHubSearchSettings)
        return cls(settings)

    # -- backend ------------------------------------------------------------

    def _search_page(self, query: str, page: int) -> SearchPage:
        raise NotImplementedError

    def _queries(self, target: str) -> list[str]:
        return [f'"{target}"']

    # -- file fetching ------------------------------------------------------

    def _fetch_file(self, hit: CodeHit, budget: _CallBudget) -> str | None:
        """The file's text (cached per run by repo+commit+path), or None if
        the download budget is spent or the fetch failed."""
        key = (hit.repo, hit.commit, hit.path)
        with self._lock:
            if key in self._files:
                return self._files[key]
        if budget.files_fetched >= self.max_file_fetches:
            return None
        budget.files_fetched += 1
        url = RAW_URL.format(repo=hit.repo, ref=hit.commit, path=quote(hit.path))
        text: str | None = None
        try:
            response = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT_SECONDS, verify=VERIFY_TLS)
            if response.status_code == 200 and len(response.content) <= MAX_FILE_BYTES:
                text = response.text
        except requests.RequestException as exc:
            logger.warning("github: fetching %s failed: %s", url, exc)
        with self._lock:
            self._files[key] = text
        return text

    def _denied(self, path: str) -> bool:
        low = path.lower()
        return any(fnmatch.fnmatch(low, pattern) for pattern in self.deny_paths)

    # -- turning hits into exposures ---------------------------------------

    def _line_of(self, text: str, name: str) -> tuple[int | None, str | None]:
        for number, raw in enumerate(text.splitlines(), start=1):
            if name in raw.lower():  # `name` is already lower-cased
                return number, raw.strip()[:SNIPPET_CHARS]
        return None, None

    def _process_hit(self, hit: CodeHit, search: _Search, budget: _CallBudget) -> None:
        """Add reference + secret exposures for one hit, fetching its file
        when needed. Forks are dropped and denied paths skipped, unless the
        file holds a secret."""
        fragment_text = "\n".join(hit.fragments)
        fragment_names = {m.group(1).lower() for m in search.matcher.finditer(fragment_text)}
        text = self._fetch_file(hit, budget)
        # Prefer the whole file for secret scanning (fragments are short); fall
        # back to the fragment when the file couldn't be fetched.
        scan_text = text if text is not None else fragment_text
        secrets = (
            find_secrets(scan_text, use_gitleaks=self.use_gitleaks,
                         use_trufflehog=self.use_trufflehog)
            if scan_text else []
        )

        if hit.fork and not secrets:
            return
        if self._denied(hit.path) and not secrets:
            return

        names = fragment_names
        if text is not None:
            names = {m.group(1).lower() for m in search.matcher.finditer(text)} or fragment_names
        if not names and not secrets:
            return

        search.kept_files += 1
        for name in sorted(names):
            search.found_names.add(name)
            line, snippet = (self._line_of(text, name) if text else (None, None))
            if snippet is None:
                snippet = next((f.strip()[:SNIPPET_CHARS] for f in hit.fragments if name in f.lower()), None)
            search.exposures.append(CodeExposure(
                kind="reference", target=name, repo=hit.repo, path=hit.path,
                commit=hit.commit, url=self._blob_url(hit, line), line=line, snippet=snippet,
            ))
        secret_target = sorted(names)[0] if names else search.target
        for secret in secrets:
            # Line numbers from a fragment scan don't map to the real file.
            line = secret.line if text is not None else None
            search.exposures.append(CodeExposure(
                kind="secret", target=secret_target, repo=hit.repo, path=hit.path,
                commit=hit.commit, url=self._blob_url(hit, line), line=line,
                rule=secret.rule, secret=secret.value,
            ))

    def _blob_url(self, hit: CodeHit, line: int | None) -> str:
        url = BLOB_URL.format(repo=hit.repo, commit=hit.commit, path=hit.path)
        return f"{url}#L{line}" if line else url

    def _run_search(self, target: str, matcher: re.Pattern[str], budget: _CallBudget) -> _Search:
        """Page through the search for `target`, processing hits until the
        result cap, `max_hits` kept files, or the budget runs out."""
        search = _Search(target=target, matcher=matcher)
        for query in self._queries(target):
            page = 1
            while budget.request():
                try:
                    result = self._search_page(query, page)
                except StopIteration:
                    break
                search.total = max(search.total, result.total)
                for hit in result.hits:
                    if search.kept_files >= self.max_hits:
                        search.truncated = True
                        break
                    self._process_hit(hit, search, budget)
                if search.kept_files >= self.max_hits or not result.more:
                    break
                page += 1
        return search

    # -- pipeline entry points ---------------------------------------------

    def collect(self, domain: str) -> EnrichmentResult:
        """Search the apex domain - one query covers every subdomain, since
        the code-search index tokenizes and a hit on `sub.example.com`
        contains `example.com`. Each in-scope hostname found in a hit becomes
        a reference exposure and a related hostname. `overflowed` in the data
        flags that the domain has more hits than `max_hits` could examine
        (some references/secrets in the tail were not seen)."""
        budget = _CallBudget(self)
        search = self._run_search(domain, hostname_matcher(domain), budget)
        overflowed = search.truncated or search.total > self.result_cap
        related = sorted(n for n in search.found_names if in_scope(n, domain))
        return EnrichmentResult(
            source=self.name, target_type="domain", target=domain,
            data={"total_hits": search.total, "overflowed": overflowed,
                  "files_examined": search.kept_files},
            code_exposures=search.exposures, related_hostnames=related,
        )

    def enrich(self, target: str, hostnames: list[str]) -> EnrichmentResult:
        """Search the IP itself (a hardcoded address in a config/manifest),
        unless it's a private/reserved address or looks like shared/CDN
        infrastructure - there its GitHub hits say nothing about the owner."""
        result = EnrichmentResult(
            source=self.name, target_type="ip", target=target, data={"searched": False},
        )
        if self._skip_ip(target, hostnames):
            return result
        budget = _CallBudget(self)
        search = self._run_search(target, ip_matcher(target), budget)
        return EnrichmentResult(
            source=self.name, target_type="ip", target=target,
            data={"searched": True, "total_hits": search.total, "files_examined": search.kept_files},
            code_exposures=search.exposures,
        )

    def _skip_ip(self, ip: str, hostnames: list[str]) -> bool:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return True
        if not address.is_global:
            return True
        if len(hostnames) > SHARED_IP_HOSTNAMES:
            logger.info("github: %s serves %d hostnames - shared hosting, skipping", ip, len(hostnames))
            return True
        if self.skip_asns:
            asn = lookup_asn(ip)
            if asn in self.skip_asns:
                logger.info("github: %s is on AS%s (CDN/shared) - skipping", ip, asn)
                return True
        return False


def _parse_search_items(payload: dict) -> SearchPage:
    hits = []
    for item in payload.get("items", []):
        repo = item.get("repository", {}) or {}
        commit_match = _BLOB_COMMIT_RE.search(item.get("html_url", ""))
        commit = commit_match.group(1) if commit_match else ""
        fragments = [
            m.get("fragment", "")
            for m in item.get("text_matches", [])
            if m.get("property") == "content" and m.get("fragment")
        ]
        hits.append(CodeHit(
            repo=repo.get("full_name", ""), path=item.get("path", ""),
            commit=commit, fragments=fragments, fork=bool(repo.get("fork")),
        ))
    total = int(payload.get("total_count", len(hits)))
    more = len(payload.get("items", [])) == PER_PAGE
    return SearchPage(total=total, hits=hits, more=more)


class GitHubSource(GitHubCodeSearchSource):
    """Code search via GitHub's REST API (`/search/code`). Needs a token."""

    name = "github"
    category = "passive"
    settings_model = GitHubSettings
    result_cap = 1000  # the API returns at most 1000 results per query

    def __init__(self, settings: GitHubSettings) -> None:
        super().__init__(settings)
        self.token = settings.token

    @classmethod
    def from_settings(cls, settings: SourceSettings) -> Source:
        assert isinstance(settings, GitHubSettings)
        return cls(settings)

    @property
    def is_configured(self) -> bool:
        return bool(self.token)

    def _require_token(self) -> str:
        if not self.token:
            raise SourceUnavailableError("github: no API token configured (code search needs one)")
        return self.token

    @with_retry
    def _search_page(self, query: str, page: int) -> SearchPage:
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/vnd.github.text-match+json",
            "Authorization": f"Bearer {self._require_token()}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        params: dict[str, str | int] = {"q": query, "per_page": PER_PAGE, "page": page}
        for _ in range(2):  # one retry after sitting out a short rate-limit wait
            response = requests.get(
                SEARCH_URL, headers=headers, timeout=TIMEOUT_SECONDS, params=params,
                verify=VERIFY_TLS,
            )
            if response.status_code == 401:
                raise AuthError("github: token rejected (HTTP 401) - check the PAT")
            if response.status_code in (403, 429):
                self._sit_out_rate_limit(response)  # or raises QuotaExhaustedError
                continue
            if response.status_code == 422:
                # "Validation failed" - past the 1000-result window; stop paging.
                raise StopIteration
            response.raise_for_status()
            return _parse_search_items(response.json())
        raise QuotaExhaustedError("github: still rate-limited after waiting - stopping for this run")

    def _sit_out_rate_limit(self, response: requests.Response) -> None:
        """Sleep off a short rate-limit window; a long one (or none given)
        ends the source's run this scan."""
        retry_after = response.headers.get("Retry-After", "")
        reset = response.headers.get("X-RateLimit-Reset", "")
        wait = None
        if retry_after.isdigit():
            wait = int(retry_after)
        elif response.headers.get("X-RateLimit-Remaining") == "0" and reset.isdigit():
            wait = int(reset) - int(time.time())
        if wait is not None and 0 < wait <= MAX_RATE_LIMIT_WAIT_SECONDS:
            logger.info("github: rate-limited, waiting %ds", wait)
            time.sleep(wait)
            return
        raise QuotaExhaustedError(f"github: rate limit hit (wait {wait}s) - stopping for this run")
