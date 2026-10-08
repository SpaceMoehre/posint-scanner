"""Discovery + enrichment source using urlscan.io's public scan search.

Discovery: hostnames of pages scanned under the domain. Enrichment (IP): what
urlscan has seen served from the IP - recent scans, and the hostnames behind
them (fed back as related hostnames). Search answers keyless at a lower rate;
a free key (`api_key`) raises it.
"""

from __future__ import annotations

from posint_scanner.models import DiscoveredHostname, EnrichmentResult
from posint_scanner.retry import with_retry
from posint_scanner.sources.common import (
    ApiKeySource,
    http_get,
    normalized_names,
    scoped_hostnames,
)

SEARCH_URL = "https://urlscan.io/api/v1/search/"
PAGE_SIZE = 100
SCANS_KEPT = 10  # recent scans stored per IP (the rest only counted)


def _hosts(results: list[dict]) -> list[str]:
    names = []
    for result in results:
        names.append(result.get("page", {}).get("domain", ""))
        names.append(result.get("task", {}).get("domain", ""))
    return [name for name in names if name]


class UrlScanSource(ApiKeySource):
    name = "urlscan"
    key_required = False

    def _search(self, query: str) -> dict:
        headers = {"API-Key": self.api_key} if self.api_key else {}
        return dict(
            http_get(
                self.name, SEARCH_URL, params={"q": query, "size": PAGE_SIZE}, headers=headers
            ).json()
        )

    @with_retry
    def discover(self, domain: str) -> list[DiscoveredHostname]:
        results = self._search(f"domain:{domain}").get("results", [])
        return scoped_hostnames(domain, _hosts(results), self.name)

    @with_retry
    def enrich(self, target: str, hostnames: list[str]) -> EnrichmentResult:
        data = self._search(f'ip:"{target}"')
        results = data.get("results", [])
        scans = [
            {
                "url": r.get("page", {}).get("url"),
                "domain": r.get("page", {}).get("domain"),
                "title": r.get("page", {}).get("title"),
                "server": r.get("page", {}).get("server"),
                "time": r.get("task", {}).get("time"),
                "result": r.get("result"),
            }
            for r in results[:SCANS_KEPT]
        ]
        return EnrichmentResult(
            source=self.name,
            target_type="ip",
            target=target,
            data={"total": data.get("total", len(results)), "scans": scans},
            related_hostnames=normalized_names(_hosts(results)),
        )
