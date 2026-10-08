"""Discovery source that guesses subdomains from a wordlist and keeps the
ones that resolve.

For every word in a wordlist (SecLists' DNS lists are the usual source),
`<word>.<domain>` is resolved against public DNS resolvers - so this finds
hosts that no certificate, crawl or passive-DNS record ever exposed, as long
as they answer DNS. It queries resolvers, not the target, so it's a passive
source; but it's high-volume and needs a wordlist, so it's off by default and
opt-in (`--source dnsbrute`, or `sources: {dnsbrute: {enabled: true}}`).

Wildcard DNS (a domain that answers every name with the same address) would
otherwise turn every guess into a false positive. A few random labels are
resolved first; any address they return is treated as the wildcard set, and
a candidate is kept only if it resolves to something outside that set. A
domain rotating wildcard addresses can still slip a few through - the results
are candidates, not proof.

Point it at a wordlist with `sources: {dnsbrute: {wordlist: /path/...}}` or
`OSINT_DNSBRUTE_WORDLIST`; with none set it tries the common SecLists
install locations. Missing wordlist => the source is skipped with a warning.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import dns.exception
import dns.resolver

from posint_scanner.models import DiscoveredHostname
from posint_scanner.sources.base import DEFAULT_TTL_DAYS, Source, SourceSettings, SourceUnavailableError

logger = logging.getLogger(__name__)

# Public resolvers to query (the same baseline the netblock sweep uses).
DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
DEFAULT_WORKERS = 50
RESOLVE_TIMEOUT_SECONDS = 3.0
WILDCARD_PROBES = 3

# Tried in order when no wordlist is configured - standard SecLists layouts.
DEFAULT_WORDLIST_CANDIDATES = (
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    str(Path.home() / "SecLists/Discovery/DNS/subdomains-top1million-5000.txt"),
)


def load_wordlist(path: str) -> list[str]:
    """Labels from a wordlist file: lowercased, comments (`#`) and blanks
    dropped, deduped in first-seen order. Missing file => SourceUnavailableError."""
    try:
        text = Path(path).read_text()
    except OSError as exc:
        raise SourceUnavailableError(f"dnsbrute wordlist not readable ({path}): {exc}") from exc
    labels: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        label = line.strip().lower()
        if not label or label.startswith("#") or label in seen:
            continue
        seen.add(label)
        labels.append(label)
    return labels


def candidate_hostname(label: str, domain: str) -> str:
    return f"{label}.{domain}"


def resolve_names(hostname: str, resolvers: list[str]) -> list[str]:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = list(resolvers)
    resolver.timeout = RESOLVE_TIMEOUT_SECONDS
    resolver.lifetime = RESOLVE_TIMEOUT_SECONDS
    addresses: list[str] = []
    for record_type in ("A", "AAAA"):
        try:
            addresses.extend(str(record) for record in resolver.resolve(hostname, record_type))
        except dns.exception.DNSException:
            continue
    return addresses


def _wildcard_ips(
    domain: str, probes: Iterable[str], resolve: Callable[[str], list[str]]
) -> set[str]:
    ips: set[str] = set()
    for label in probes:
        ips.update(resolve(candidate_hostname(label, domain)))
    return ips


class DnsBruteSettings(SourceSettings):
    wordlist: str | None = None
    resolvers: list[str] | None = None
    workers: int = DEFAULT_WORKERS
    # Cap on words tried (None = whole list); a guard for very large lists.
    max_words: int | None = None


class DnsBruteSource(Source):
    name = "dnsbrute"
    settings_model = DnsBruteSettings
    default_enabled = False  # opt-in: high query volume, needs a wordlist
    ttl_days = DEFAULT_TTL_DAYS

    def __init__(
        self,
        wordlist: str | None = None,
        resolvers: list[str] | None = None,
        workers: int = DEFAULT_WORKERS,
        max_words: int | None = None,
        resolve: Callable[[str], list[str]] | None = None,
        probe_labels: list[str] | None = None,
    ) -> None:
        self.wordlist = wordlist
        self.resolvers = resolvers or list(DEFAULT_RESOLVERS)
        self.workers = workers
        self.max_words = max_words
        self._resolve = resolve or (lambda host: resolve_names(host, self.resolvers))
        self._probe_labels = (
            probe_labels
            if probe_labels is not None
            else [uuid.uuid4().hex[:12] for _ in range(WILDCARD_PROBES)]
        )

    @classmethod
    def from_settings(cls, settings: SourceSettings) -> DnsBruteSource:
        assert isinstance(settings, DnsBruteSettings)
        return cls(
            wordlist=settings.wordlist,
            resolvers=settings.resolvers,
            workers=settings.workers,
            max_words=settings.max_words,
        )

    def _wordlist_path(self) -> str:
        if self.wordlist:
            return self.wordlist
        for candidate in DEFAULT_WORDLIST_CANDIDATES:
            if Path(candidate).is_file():
                return candidate
        raise SourceUnavailableError(
            "dnsbrute: no wordlist configured and none found in the default SecLists "
            "locations - set sources.dnsbrute.wordlist or OSINT_DNSBRUTE_WORDLIST"
        )

    def discover(self, domain: str) -> list[DiscoveredHostname]:
        labels = load_wordlist(self._wordlist_path())
        if self.max_words is not None:
            labels = labels[: self.max_words]
        wildcard = _wildcard_ips(domain, self._probe_labels, self._resolve)
        if wildcard:
            logger.info(
                "dnsbrute: %s wildcards DNS (%s) - keeping only names resolving elsewhere",
                domain,
                ", ".join(sorted(wildcard)),
            )

        candidates = [candidate_hostname(label, domain) for label in labels]

        def check(hostname: str) -> str | None:
            addresses = self._resolve(hostname)
            if addresses and not set(addresses) <= wildcard:
                return hostname
            return None

        found: list[DiscoveredHostname] = []
        with ThreadPoolExecutor(max_workers=max(1, self.workers)) as executor:
            for hostname in executor.map(check, candidates):
                if hostname is not None:
                    found.append(DiscoveredHostname(name=hostname, source=self.name))
        logger.info("dnsbrute for %s: %d of %d guesses resolved", domain, len(found), len(candidates))
        return found
