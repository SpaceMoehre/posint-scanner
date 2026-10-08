"""Discovery + enrichment source using AlienVault OTX passive DNS: names
under the domain for discovery, names seen on an IP for enrichment (fed back
as related hostnames).

Needs a free OTX account key (`api_key`); anonymous access to the passive
DNS endpoint is throttled to effectively nothing (HTTP 429).
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

IPV4_PASSIVE_DNS_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/passive_dns"
IPV6_PASSIVE_DNS_URL = "https://otx.alienvault.com/api/v1/indicators/IPv6/{ip}/passive_dns"
PASSIVE_DNS_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"


def parse_otx_passive_dns(data: dict, domain: str) -> list[DiscoveredHostname]:
    names = [entry.get("hostname", "") for entry in data.get("passive_dns", [])]
    return scoped_hostnames(domain, names, "otx")


class OtxSource(ApiKeySource):
    name = "otx"

    @with_retry
    def discover(self, domain: str) -> list[DiscoveredHostname]:
        response = http_get(
            self.name,
            PASSIVE_DNS_URL.format(domain=domain),
            headers={"X-OTX-API-KEY": self.require_key()},
        )
        return parse_otx_passive_dns(response.json(), domain)

    @with_retry
    def enrich(self, target: str, hostnames: list[str]) -> EnrichmentResult:
        data = http_get(
            self.name,
            (IPV6_PASSIVE_DNS_URL if ":" in target else IPV4_PASSIVE_DNS_URL).format(ip=target),
            headers={"X-OTX-API-KEY": self.require_key()},
        ).json()
        related = normalized_names(e.get("hostname", "") for e in data.get("passive_dns", []))
        return EnrichmentResult(
            source=self.name,
            target_type="ip",
            target=target,
            data={"passive_dns_count": data.get("count", len(related))},
            related_hostnames=related,
        )
