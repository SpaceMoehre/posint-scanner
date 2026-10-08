"""Discovery + enrichment source using HackerTarget: host search (passive
DNS) for discovery, reverse IP lookup for enrichment (other names on the IP,
fed back as related hostnames).

Works without a key at a small daily quota; a paid key (`api_key`) raises
it. Errors - including an exhausted quota - come back as HTTP 200 plain text
rather than a status code, so they're told apart from results by content.
"""

from __future__ import annotations

from posint_scanner.models import DiscoveredHostname, EnrichmentResult
from posint_scanner.retry import with_retry
from posint_scanner.sources.base import QuotaExhaustedError
from posint_scanner.sources.common import (
    ApiKeySource,
    http_get,
    normalized_names,
    scoped_hostnames,
)

HOSTSEARCH_URL = "https://api.hackertarget.com/hostsearch/"
REVERSE_IP_URL = "https://api.hackertarget.com/reverseiplookup/"
QUOTA_MESSAGE = "API count exceeded"


def parse_hostsearch(body: str, domain: str) -> list[DiscoveredHostname]:
    names = [line.split(",", 1)[0] for line in body.splitlines() if "," in line]
    return scoped_hostnames(domain, names, "hackertarget")


class HackerTargetSource(ApiKeySource):
    name = "hackertarget"
    key_required = False
    # Keyless tier allowance - raise it in config if you have a membership key.
    daily_budget = 50

    def _query(self, url: str, query: str) -> str:
        params = {"q": query}
        if self.api_key:
            params["apikey"] = self.api_key
        body = http_get(self.name, url, params=params).text
        if body.startswith(QUOTA_MESSAGE):
            raise QuotaExhaustedError(f"hackertarget quota exhausted: {body.strip()}")
        return body

    @with_retry
    def discover(self, domain: str) -> list[DiscoveredHostname]:
        return parse_hostsearch(self._query(HOSTSEARCH_URL, domain), domain)

    @with_retry
    def enrich(self, target: str, hostnames: list[str]) -> EnrichmentResult:
        body = self._query(REVERSE_IP_URL, target)
        # "No DNS A records found for ..." and other messages aren't names
        names = [line for line in body.splitlines() if line and " " not in line.strip()]
        related = normalized_names(names)
        return EnrichmentResult(
            source=self.name,
            target_type="ip",
            target=target,
            data={"reverse_ip_count": len(related)},
            related_hostnames=related,
        )
