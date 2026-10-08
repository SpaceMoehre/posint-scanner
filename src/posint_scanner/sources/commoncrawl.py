"""Discovery source using the Common Crawl URL index.

Free, no key. Like the Wayback CDX index, every crawled URL carries its
hostname. Common Crawl publishes one index per monthly crawl; only the latest
is queried (a full sweep of every crawl would be dozens of slow requests),
listed via collinfo.json.
"""

from __future__ import annotations

import json

from posint_scanner.models import DiscoveredHostname
from posint_scanner.retry import with_retry
from posint_scanner.sources.base import DEFAULT_TTL_DAYS, Source, SourceSettings
from posint_scanner.sources.common import http_get, scoped_hostnames

COLLINFO_URL = "https://index.commoncrawl.org/collinfo.json"
TIMEOUT_SECONDS = 90
DEFAULT_LIMIT = 20_000


class CommonCrawlSettings(SourceSettings):
    limit: int = DEFAULT_LIMIT


def parse_commoncrawl_lines(body: str, domain: str) -> list[DiscoveredHostname]:
    urls = []
    for line in body.splitlines():
        try:
            urls.append(json.loads(line)["url"])
        except (ValueError, KeyError, TypeError):
            continue
    return scoped_hostnames(domain, urls, "commoncrawl")


class CommonCrawlSource(Source):
    name = "commoncrawl"
    settings_model = CommonCrawlSettings
    ttl_days = DEFAULT_TTL_DAYS

    def __init__(self, limit: int = DEFAULT_LIMIT) -> None:
        self.limit = limit

    @classmethod
    def from_settings(cls, settings: SourceSettings) -> CommonCrawlSource:
        assert isinstance(settings, CommonCrawlSettings)
        return cls(limit=settings.limit)

    @with_retry
    def discover(self, domain: str) -> list[DiscoveredHostname]:
        indexes = http_get(self.name, COLLINFO_URL).json()
        response = http_get(
            self.name,
            indexes[0]["cdx-api"],
            params={"url": f"*.{domain}", "output": "json", "fl": "url", "limit": self.limit},
            timeout=TIMEOUT_SECONDS,
            ok_statuses=(404,),  # "No Captures found"
        )
        if response.status_code == 404:
            return []
        return parse_commoncrawl_lines(response.text, domain)
