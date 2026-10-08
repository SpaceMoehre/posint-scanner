"""Discovery source using FullHunt's domain subdomains endpoint.

Needs a key; the free tier is 100 credits/month (this source's default
monthly budget).
"""

from __future__ import annotations

from posint_scanner.models import DiscoveredHostname
from posint_scanner.retry import with_retry
from posint_scanner.sources.common import ApiKeySource, http_get, scoped_hostnames

SUBDOMAINS_URL = "https://fullhunt.io/api/v1/domain/{domain}/subdomains"


class FullHuntSource(ApiKeySource):
    name = "fullhunt"
    monthly_budget = 100

    @with_retry
    def discover(self, domain: str) -> list[DiscoveredHostname]:
        data = http_get(
            self.name,
            SUBDOMAINS_URL.format(domain=domain),
            headers={"X-API-KEY": self.require_key()},
        ).json()
        return scoped_hostnames(domain, data.get("hosts", []), self.name)
