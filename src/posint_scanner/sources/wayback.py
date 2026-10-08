"""Discovery source using the Internet Archive's Wayback Machine CDX index.

Free, no key. Every archived URL under the domain carries its hostname, so
the capture index doubles as a historical subdomain list - including hosts
that have since disappeared from DNS (still worth knowing about: a dangling
record, an old admin panel).

The CDX server is slow and times out under load (504s), so this gets a long
timeout and a TTL: archive history barely changes week to week.
"""

from __future__ import annotations

import json

from posint_scanner.models import DiscoveredHostname
from posint_scanner.retry import with_retry
from posint_scanner.sources.base import DEFAULT_TTL_DAYS, Source, SourceSettings
from posint_scanner.sources.common import http_get, scoped_hostnames

CDX_URL = "https://web.archive.org/cdx/search/cdx"
TIMEOUT_SECONDS = 120
DEFAULT_LIMIT = 50_000


class WaybackSettings(SourceSettings):
    # Max capture rows fetched (collapsed per URL, so ~distinct URLs).
    limit: int = DEFAULT_LIMIT


def parse_wayback_response(body: str, domain: str) -> list[DiscoveredHostname]:
    """The server writes one `["<url>"],` row per line. Parsed line by line
    rather than as one JSON document: large responses sometimes get cut off
    mid-stream, and the complete rows before the cut are still good."""
    urls = []
    for line in body.splitlines()[1:]:  # line 0 is the field header
        line = line.strip().rstrip(",")
        if line.endswith("]]"):  # last row closes the outer array too
            line = line[:-1]
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row:
            urls.append(row[0])
    return scoped_hostnames(domain, urls, "wayback")


class WaybackSource(Source):
    name = "wayback"
    settings_model = WaybackSettings
    ttl_days = DEFAULT_TTL_DAYS

    def __init__(self, limit: int = DEFAULT_LIMIT) -> None:
        self.limit = limit

    @classmethod
    def from_settings(cls, settings: SourceSettings) -> WaybackSource:
        assert isinstance(settings, WaybackSettings)
        return cls(limit=settings.limit)

    @with_retry
    def discover(self, domain: str) -> list[DiscoveredHostname]:
        response = http_get(
            self.name,
            CDX_URL,
            params={
                "url": domain,
                "matchType": "domain",
                "output": "json",
                "fl": "original",
                "collapse": "urlkey",
                "limit": self.limit,
            },
            timeout=TIMEOUT_SECONDS,
        )
        return parse_wayback_response(response.text, domain)
