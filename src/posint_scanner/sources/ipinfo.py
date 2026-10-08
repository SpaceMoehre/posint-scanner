"""Enrichment source using IPinfo: geolocation, owning org/ASN, and the PTR
hostname (fed back as a related hostname).

Answers keyless at a lower allowance; a free token (`api_key`) raises it.
"""

from __future__ import annotations

from posint_scanner.models import EnrichmentResult
from posint_scanner.retry import with_retry
from posint_scanner.sources.common import ApiKeySource, http_get, normalized_names

IPINFO_URL = "https://ipinfo.io/{ip}/json"


class IpInfoSource(ApiKeySource):
    name = "ipinfo"
    key_required = False

    @with_retry
    def enrich(self, target: str, hostnames: list[str]) -> EnrichmentResult:
        params = {"token": self.api_key} if self.api_key else None
        data = dict(http_get(self.name, IPINFO_URL.format(ip=target), params=params).json())
        data.pop("readme", None)  # "you have no token" nag, not data
        ptr = data.get("hostname")
        return EnrichmentResult(
            source=self.name,
            target_type="ip",
            target=target,
            data=data,
            related_hostnames=normalized_names([ptr] if ptr else []),
        )
