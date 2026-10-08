"""Enrichment source using GreyNoise's Community API: is this IP a known
internet scanner ("noise") or a known benign business service ("riot")?

Answers keyless at a small allowance; a free community key raises it. An IP
GreyNoise hasn't seen comes back as HTTP 404 *with* a normal JSON body, which
is a result ("not observed"), not an error.
"""

from __future__ import annotations

from posint_scanner.models import EnrichmentResult
from posint_scanner.retry import with_retry
from posint_scanner.sources.common import ApiKeySource, http_get

COMMUNITY_URL = "https://api.greynoise.io/v3/community/{ip}"


class GreyNoiseSource(ApiKeySource):
    name = "greynoise"
    key_required = False
    # Guard against burning the anonymous allowance on a big scan - not the
    # official quota; raise it in config with a key.
    daily_budget = 100

    @with_retry
    def enrich(self, target: str, hostnames: list[str]) -> EnrichmentResult:
        headers = {"key": self.api_key} if self.api_key else {}
        response = http_get(
            self.name, COMMUNITY_URL.format(ip=target), headers=headers, ok_statuses=(404,)
        )
        return EnrichmentResult(
            source=self.name, target_type="ip", target=target, data=dict(response.json())
        )
