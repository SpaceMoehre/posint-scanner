"""Enrichment source using AbuseIPDB: abuse-report score/history for an IP
(is our address reported for attacks/spam?) plus the hostnames AbuseIPDB
associates with it (fed back as related hostnames).

Needs a free key; the free tier allows 1000 checks/day (default budget).
"""

from __future__ import annotations

from posint_scanner.models import EnrichmentResult
from posint_scanner.retry import with_retry
from posint_scanner.sources.common import ApiKeySource, http_get, normalized_names

CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
MAX_AGE_DAYS = 90


class AbuseIpDbSource(ApiKeySource):
    name = "abuseipdb"
    daily_budget = 1000

    @with_retry
    def enrich(self, target: str, hostnames: list[str]) -> EnrichmentResult:
        data = http_get(
            self.name,
            CHECK_URL,
            params={"ipAddress": target, "maxAgeInDays": MAX_AGE_DAYS},
            headers={"Key": self.require_key(), "Accept": "application/json"},
        ).json().get("data", {})
        return EnrichmentResult(
            source=self.name,
            target_type="ip",
            target=target,
            data=dict(data),
            related_hostnames=normalized_names(data.get("hostnames") or []),
        )
