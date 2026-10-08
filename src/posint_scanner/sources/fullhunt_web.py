"""Discovery source scraping FullHunt's public search page - the keyless
stand-in for the `fullhunt` API source (skipped while that has a key, unless
forced; see registry.py).

robots.txt allows everything. The page always renders a "Discovered assets
for <domain>" heading, with one host heading per result below it; a page
without that heading means the markup changed (ScrapeParseError).
"""

from __future__ import annotations

from bs4 import BeautifulSoup

from posint_scanner.models import DiscoveredHostname
from posint_scanner.retry import with_retry
from posint_scanner.sources.base import ScrapeParseError, Source
from posint_scanner.sources.common import http_get, scoped_hostnames

SEARCH_URL = "https://fullhunt.io/search"


def parse_fullhunt_search(html: str, domain: str) -> list[DiscoveredHostname]:
    soup = BeautifulSoup(html, "html.parser")
    if soup.find(id="search-results") is None:
        raise ScrapeParseError("fullhunt_web: results heading not found")
    names = [a.get_text(strip=True) for a in soup.select("h2.sr-host a")]
    return scoped_hostnames(domain, names, "fullhunt_web")


class FullHuntWebSource(Source):
    name = "fullhunt_web"
    category = "scrape"
    fallback_for = "fullhunt"
    requests_per_minute = 6

    @with_retry
    def discover(self, domain: str) -> list[DiscoveredHostname]:
        response = http_get(self.name, SEARCH_URL, params={"query": domain})
        return parse_fullhunt_search(response.text, domain)
