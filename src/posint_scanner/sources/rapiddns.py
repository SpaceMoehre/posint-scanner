"""Discovery source scraping rapiddns.io's subdomain search page.

No API exists, so this parses the public HTML results table (robots.txt
allows it). Category "scrape": off unless enabled. The page always renders
the results table - empty when there's nothing - so a page *without* it
means the markup changed, raised as ScrapeParseError rather than silently
returning nothing.
"""

from __future__ import annotations

from bs4 import BeautifulSoup

from posint_scanner.models import DiscoveredHostname
from posint_scanner.retry import with_retry
from posint_scanner.sources.base import ScrapeParseError, Source
from posint_scanner.sources.common import http_get, scoped_hostnames

SUBDOMAIN_URL = "https://rapiddns.io/subdomain/{domain}"


def parse_rapiddns_page(html: str, domain: str) -> list[DiscoveredHostname]:
    table = BeautifulSoup(html, "html.parser").find("table", id="table")
    if table is None:
        raise ScrapeParseError("rapiddns: results table not found")
    names = []
    for row in table.select("tbody tr"):
        cell = row.find("td")  # first <td> is the name (the row number is a <th>)
        if cell is not None:
            names.append(cell.get_text(strip=True))
    return scoped_hostnames(domain, names, "rapiddns")


class RapidDnsSource(Source):
    name = "rapiddns"
    category = "scrape"
    requests_per_minute = 6  # be polite to a free site

    @with_retry
    def discover(self, domain: str) -> list[DiscoveredHostname]:
        response = http_get(self.name, SUBDOMAIN_URL.format(domain=domain), params={"full": 1})
        return parse_rapiddns_page(response.text, domain)
