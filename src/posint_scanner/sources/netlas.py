"""Discovery source using Netlas' DNS domains search.

Answers anonymously at a lower allowance; a free key allows 50 requests/day
(this source's default daily budget). Only the first page of results (20
domains) is fetched per call; raise `max_pages` with a paid plan.
"""

from __future__ import annotations

from posint_scanner.models import DiscoveredHostname
from posint_scanner.retry import with_retry
from posint_scanner.sources.base import SourceSettings
from posint_scanner.sources.common import (
    ApiKeySettings,
    ApiKeySource,
    http_get,
    scoped_hostnames,
)

DOMAINS_URL = "https://app.netlas.io/api/domains/"
PAGE_SIZE = 20


class NetlasSettings(ApiKeySettings):
    max_pages: int = 1


class NetlasSource(ApiKeySource):
    name = "netlas"
    settings_model = NetlasSettings
    key_required = False
    daily_budget = 50

    def __init__(self, api_key: str | None = None, max_pages: int = 1) -> None:
        super().__init__(api_key)
        self.max_pages = max_pages

    @classmethod
    def from_settings(cls, settings: SourceSettings) -> NetlasSource:
        assert isinstance(settings, NetlasSettings)
        return cls(api_key=settings.api_key, max_pages=settings.max_pages)

    @with_retry
    def discover(self, domain: str) -> list[DiscoveredHostname]:
        headers = {"X-API-Key": self.api_key} if self.api_key else {}
        names: list[str] = []
        for page in range(self.max_pages):
            if page and not self.extra_request():
                break
            data = http_get(
                self.name,
                DOMAINS_URL,
                params={
                    "q": f"domain:*.{domain}",
                    "fields": "domain",
                    "source_type": "include",
                    "start": page * PAGE_SIZE,
                },
                headers=headers,
            ).json()
            items = data.get("items", [])
            names.extend(item.get("data", {}).get("domain", "") for item in items)
            if len(items) < PAGE_SIZE:
                break
        return scoped_hostnames(domain, names, self.name)
