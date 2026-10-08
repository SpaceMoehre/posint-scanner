"""Enrichment source using the Censys Search API v2 (https://search.censys.io/api).

Requires a free Censys account and API ID/secret (censys.io) - their free
tier has a monthly query cap. Independent view of open ports/services/
versions that doesn't depend on Shodan's plan tier, since the two products
maintain separate internet-wide scan datasets.
"""

from __future__ import annotations

import requests

from posint_scanner.models import EnrichmentResult, ServiceInfo
from posint_scanner.retry import VERIFY_TLS, raise_for_auth_error, with_retry
from posint_scanner.sources.base import (
    DEFAULT_TTL_DAYS,
    Source,
    SourceSettings,
    SourceUnavailableError,
)

BASE_URL = "https://search.censys.io/api/v2/hosts/{ip}"
TIMEOUT_SECONDS = 30


def parse_censys_response(raw: dict) -> EnrichmentResult:
    result = raw.get("result", {})
    services = []
    for svc in result.get("services", []):
        software_list = svc.get("software") or []
        first_software = software_list[0] if software_list else {}
        services.append(
            ServiceInfo(
                port=svc["port"],
                protocol=svc.get("transport_protocol", "tcp").lower(),
                banner=first_software.get("product"),
                version=first_software.get("version"),
            )
        )
    return EnrichmentResult(
        source="censys",
        target_type="ip",
        target=result.get("ip", ""),
        data=raw,
        services=services,
    )


class CensysSettings(SourceSettings):
    api_id: str | None = None
    api_secret: str | None = None


class CensysSource(Source):
    name = "censys"
    settings_model = CensysSettings
    ttl_days = DEFAULT_TTL_DAYS

    def __init__(self, api_id: str | None, api_secret: str | None) -> None:
        self.api_id = api_id
        self.api_secret = api_secret

    @classmethod
    def from_settings(cls, settings: SourceSettings) -> CensysSource:
        assert isinstance(settings, CensysSettings)
        return cls(api_id=settings.api_id, api_secret=settings.api_secret)

    @property
    def is_configured(self) -> bool:
        return bool(self.api_id and self.api_secret)

    @with_retry
    def enrich(self, target: str, hostnames: list[str]) -> EnrichmentResult:
        if not (self.api_id and self.api_secret):
            raise SourceUnavailableError("censys API credentials not configured")

        response = requests.get(
            BASE_URL.format(ip=target),
            auth=(self.api_id, self.api_secret),
            timeout=TIMEOUT_SECONDS,
            verify=VERIFY_TLS,
        )
        raise_for_auth_error(response, "censys rejected the configured credentials")
        if response.status_code == 404:
            # Censys has no data on this host - not an error, just nothing found.
            return EnrichmentResult(source="censys", target_type="ip", target=target, data={})
        response.raise_for_status()
        return parse_censys_response(response.json())
