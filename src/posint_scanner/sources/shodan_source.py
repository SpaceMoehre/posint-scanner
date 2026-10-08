"""Enrichment source using the Shodan host lookup API (https://developer.shodan.io/api)."""

from __future__ import annotations

import logging
import time

import requests

from posint_scanner.models import EnrichmentResult, ServiceInfo
from posint_scanner.retry import VERIFY_TLS, raise_for_auth_error, with_retry
from posint_scanner.sources.base import (
    DEFAULT_TTL_DAYS,
    Source,
    SourceSettings,
    SourceUnavailableError,
)

logger = logging.getLogger(__name__)

BASE_URL = "https://api.shodan.io/shodan/host/{ip}"
TIMEOUT_SECONDS = 30
# Used when a 429 doesn't carry a Retry-After header. Shodan's own free-tier
# rate limit is roughly 1 req/s, so a few seconds is a conservative cooldown
# for a batch of concurrent lookups tripping it.
DEFAULT_RATE_LIMIT_SLEEP_SECONDS = 5.0


def parse_retry_after(header_value: str | None, default: float) -> float:
    """Parse a Retry-After header's delta-seconds form (what Shodan sends on
    a 429) - falls back to `default` if the header is missing or isn't a
    plain number (the less common HTTP-date form isn't handled)."""
    if header_value is None:
        return default
    try:
        return float(header_value)
    except ValueError:
        return default


def _first_cpe(entry: dict) -> str | None:
    cpe_list = entry.get("cpe23") or entry.get("cpe")
    if isinstance(cpe_list, list) and cpe_list:
        return str(cpe_list[0])
    return None


def parse_shodan_response(raw: dict) -> EnrichmentResult:
    services = [
        ServiceInfo(
            port=entry["port"],
            protocol=entry.get("transport", "tcp"),
            banner=entry.get("product"),
            version=entry.get("version"),
            cpe=_first_cpe(entry),
        )
        for entry in raw.get("data", [])
    ]
    # Keep the whole raw response, including the per-service `data` list -
    # that's where Shodan puts version/CPE/vulns detail beyond what fits in
    # ServiceInfo's normalized fields (port/protocol/banner/version). This
    # used to strip `data` out entirely, silently discarding vulnerability
    # and CPE information even though Shodan returned it.
    return EnrichmentResult(
        source="shodan",
        target_type="ip",
        target=raw.get("ip_str", ""),
        data=dict(raw),
        services=services,
        related_hostnames=[str(name) for name in raw.get("hostnames", [])],
    )


class ShodanSettings(SourceSettings):
    api_key: str | None = None


class ShodanSource(Source):
    name = "shodan"
    settings_model = ShodanSettings
    ttl_days = DEFAULT_TTL_DAYS

    def __init__(self, api_key: str | None) -> None:
        self.api_key = api_key

    @classmethod
    def from_settings(cls, settings: SourceSettings) -> ShodanSource:
        assert isinstance(settings, ShodanSettings)
        return cls(api_key=settings.api_key)

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    @with_retry
    def enrich(self, target: str, hostnames: list[str]) -> EnrichmentResult:
        if not self.api_key:
            raise SourceUnavailableError("shodan API key not configured")

        response = requests.get(
            BASE_URL.format(ip=target),
            params={"key": self.api_key},
            timeout=TIMEOUT_SECONDS,
            verify=VERIFY_TLS,
        )
        raise_for_auth_error(response, "shodan rejected the configured API key")
        if response.status_code == 429:
            delay = parse_retry_after(
                response.headers.get("Retry-After"), DEFAULT_RATE_LIMIT_SLEEP_SECONDS
            )
            logger.warning("shodan rate limited (429) for %s, sleeping %.1fs", target, delay)
            time.sleep(delay)
        response.raise_for_status()
        return parse_shodan_response(response.json())
