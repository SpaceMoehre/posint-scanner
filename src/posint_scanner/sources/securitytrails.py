"""Discovery source using SecurityTrails' subdomain list.

Needs a key. The free tier is 50 queries/month - this source's default
monthly budget; with the 7-day TTL that's roughly a dozen domains a week.
The API returns bare labels (`www`), which are expanded under the domain.
"""

from __future__ import annotations

from posint_scanner.models import DiscoveredHostname
from posint_scanner.retry import with_retry
from posint_scanner.sources.common import ApiKeySource, http_get, scoped_hostnames

SUBDOMAINS_URL = "https://api.securitytrails.com/v1/domain/{domain}/subdomains"


class SecurityTrailsSource(ApiKeySource):
    name = "securitytrails"
    monthly_budget = 50

    @with_retry
    def discover(self, domain: str) -> list[DiscoveredHostname]:
        data = http_get(
            self.name,
            SUBDOMAINS_URL.format(domain=domain),
            params={"children_only": "false", "include_inactive": "true"},
            headers={"APIKEY": self.require_key()},
        ).json()
        labels = data.get("subdomains", [])
        return scoped_hostnames(domain, (f"{label}.{domain}" for label in labels), self.name)
