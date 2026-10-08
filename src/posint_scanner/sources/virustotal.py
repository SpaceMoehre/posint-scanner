"""Discovery + enrichment source using VirusTotal (API v3): the domain's
subdomains relationship for discovery, the IP's passive-DNS resolutions for
enrichment (names seen on the IP, fed back as related hostnames).

Needs a free VirusTotal key. The free tier allows 4 requests/min and 500/day,
which are this source's defaults; raise them in config for a premium key.
Results are paged via a cursor - each extra page is another request, paced
and charged to the budget like a call, capped by `max_pages`.
"""

from __future__ import annotations

from posint_scanner.models import DiscoveredHostname, EnrichmentResult
from posint_scanner.retry import with_retry
from posint_scanner.sources.base import SourceSettings
from posint_scanner.sources.common import (
    ApiKeySettings,
    ApiKeySource,
    http_get,
    normalized_names,
    scoped_hostnames,
)

IP_RESOLUTIONS_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions"
SUBDOMAINS_URL = "https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
PAGE_SIZE = 40
DEFAULT_MAX_PAGES = 5


class VirusTotalSettings(ApiKeySettings):
    max_pages: int = DEFAULT_MAX_PAGES


class VirusTotalSource(ApiKeySource):
    name = "virustotal"
    settings_model = VirusTotalSettings
    requests_per_minute = 4
    daily_budget = 500

    def __init__(self, api_key: str | None = None, max_pages: int = DEFAULT_MAX_PAGES) -> None:
        super().__init__(api_key)
        self.max_pages = max_pages

    @classmethod
    def from_settings(cls, settings: SourceSettings) -> VirusTotalSource:
        assert isinstance(settings, VirusTotalSettings)
        return cls(api_key=settings.api_key, max_pages=settings.max_pages)

    @with_retry
    def discover(self, domain: str) -> list[DiscoveredHostname]:
        headers = {"x-apikey": self.require_key()}
        names: list[str] = []
        cursor = None
        for page in range(self.max_pages):
            if page and not self.extra_request():
                break
            params: dict[str, str | int] = {"limit": PAGE_SIZE}
            if cursor:
                params["cursor"] = cursor
            data = http_get(
                self.name, SUBDOMAINS_URL.format(domain=domain), params=params, headers=headers
            ).json()
            names.extend(item.get("id", "") for item in data.get("data", []))
            cursor = data.get("meta", {}).get("cursor")
            if not cursor:
                break
        return scoped_hostnames(domain, names, self.name)

    @with_retry
    def enrich(self, target: str, hostnames: list[str]) -> EnrichmentResult:
        data = http_get(
            self.name,
            IP_RESOLUTIONS_URL.format(ip=target),
            params={"limit": PAGE_SIZE},
            headers={"x-apikey": self.require_key()},
        ).json()
        names = [
            item.get("attributes", {}).get("host_name", "") for item in data.get("data", [])
        ]
        related = normalized_names(names)
        return EnrichmentResult(
            source=self.name,
            target_type="ip",
            target=target,
            data={"resolutions": related},
            related_hostnames=related,
        )
