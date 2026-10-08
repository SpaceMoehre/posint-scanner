"""Enrichment/discovery source that scrapes Shodan's public website
(https://www.shodan.io/host/<ip> and https://www.shodan.io/domain/<domain>)
rather than the paid API (see shodan_source.py). Free supplement/fallback
for when no Shodan API key is configured, and the only way to pull the
subdomain list Shodan shows on the domain page (not exposed by the free
API tier).

robots.txt (https://www.shodan.io/robots.txt) sets `Crawl-delay: 10` for
all user agents and disallows `/domain/` outright - only `/host/` is
unrestricted. Every request this source makes (host or domain page alike)
is paced to that 10s interval via a shared, lock-protected timestamp (same
pattern as NvdClient in nvd.py). It still fetches `/domain/` pages, per
explicit instruction - enabling this source (it's opt-in, see
`include_shodan_web` in registry.py) means knowingly scraping a path
Shodan's robots.txt asks crawlers not to.

HTML scraping is inherently brittle: it breaks silently whenever Shodan
changes markup, unlike the versioned JSON API. Parsing here is best-effort
and returns whatever it can find rather than raising on unexpected shape.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time

import requests
from bs4 import BeautifulSoup

from posint_scanner.models import DiscoveredHostname, EnrichmentResult, ServiceInfo
from posint_scanner.retry import VERIFY_TLS, with_retry
from posint_scanner.sources.base import ScrapeParseError, Source
from posint_scanner.sources.dnsrecon import hostname_from_zone_label

logger = logging.getLogger(__name__)

HOST_URL = "https://www.shodan.io/host/{ip}"
DOMAIN_URL = "https://www.shodan.io/domain/{domain}"
TIMEOUT_SECONDS = 30
USER_AGENT = "posint-scanner/0.1 (passive OSINT recon tool)"
MIN_REQUEST_INTERVAL_SECONDS = 10.0
_PORT_ID_RE = re.compile(r"^\d+$")
# The Vulnerabilities card isn't in the server-rendered DOM at all - it's
# built client-side (see host-*.js's renderVulnsTable) from a JSON object,
# keyed by CVE ID with `ports` (which services it affects), `cvss`,
# `verified`, and `summary` per entry. As actually observed on a host with
# vulns, the object is assigned to a local `const VULNS = {...}` first and
# `setupVulns(VULNS)` is called with the bare variable name - not the
# object literal inline - so that's the primary pattern matched here. The
# `setupVulns({...})` literal-argument form is kept as a fallback in case
# Shodan ever inlines it directly. Both the script and the whole card are
# omitted entirely when a host has no known vulns.
_VULNS_PATTERNS = (
    re.compile(r"const VULNS = (\{.*?\});", re.DOTALL),
    re.compile(r"setupVulns\((\{.*?\})\);", re.DOTALL),
)


def _label_value(soup: BeautifulSoup, label_text: str) -> str | None:
    """Reads the `<label>X</label><div>...</div>` pairs the host page's
    General Information card is built from."""
    label = soup.find("label", string=label_text)
    if label is None:
        return None
    value = label.find_next_sibling("div")
    if value is None:
        return None
    text = value.get_text(strip=True)
    return text or None


def _parse_hostnames(soup: BeautifulSoup) -> list[str]:
    # The Hostnames block wraps the registered-domain suffix of each name in
    # <b> and separates multiple hostnames with <br/> - plain get_text()
    # would run every hostname together, so split on <br/> first.
    label = soup.find("label", string="Hostnames")
    if label is None:
        return []
    value = label.find_next_sibling("div")
    if value is None:
        return []
    fragments = re.split(r"<br\s*/?>", value.decode_contents())
    return [text for fragment in fragments if (text := BeautifulSoup(fragment, "html.parser").get_text().strip())]


def _parse_domains(soup: BeautifulSoup) -> list[str]:
    label = soup.find("label", string="Domains")
    if label is None:
        return []
    value = label.find_next_sibling("div")
    if value is None:
        return []
    return [text for a in value.find_all("a") if (text := a.get_text(strip=True))]


def _parse_service_banner(banner_div) -> tuple[str | None, str | None]:
    """Returns (banner, version). When Shodan has fingerprinted a product
    for this service, the card has a `.banner-title` with the product name
    in <em> and the version in <span> - use that, matching
    shodan_source.py's convention of banner=product for the API. Otherwise
    fall back to the raw response/handshake text in the first <pre>, the
    only signal available for a service with no fingerprinted product
    (e.g. a bare DNS banner)."""
    title = banner_div.find(class_="banner-title")
    if title is not None:
        product_el = title.find("em")
        product = product_el.get_text(strip=True) if product_el else None
        if product:
            version_el = title.find("span")
            version = version_el.get_text(strip=True) if version_el else None
            return product, version
    pre = banner_div.find("pre")
    if pre is not None:
        text = pre.get_text().strip()
        return (text or None), None
    return None, None


def _parse_services(soup: BeautifulSoup) -> list[ServiceInfo]:
    services = []
    for heading in soup.find_all("h6", class_="grid-heading"):
        port_id = heading.get("id")
        if not port_id or not _PORT_ID_RE.match(port_id):
            continue
        span = heading.find("span", attrs={"data-clipboard": True})
        protocol = "udp" if span is not None and "udp" in span.get_text().lower() else "tcp"
        banner, version = None, None
        banner_div = heading.find_next_sibling("div", class_="banner")
        if banner_div is not None:
            banner, version = _parse_service_banner(banner_div)
        services.append(
            ServiceInfo(port=int(port_id), protocol=protocol, banner=banner, version=version)
        )
    return services


def _parse_vulns(html: str) -> dict:
    for pattern in _VULNS_PATTERNS:
        match = pattern.search(html)
        if match is None:
            continue
        try:
            return dict(json.loads(match.group(1)))
        except json.JSONDecodeError:
            logger.warning("shodan_web: found a vulns blob but couldn't parse its JSON")
            return {}
    return {}


def parse_shodan_host_page(html: str, ip: str) -> EnrichmentResult:
    soup = BeautifulSoup(html, "html.parser")
    # `vulns` mirrors the Shodan API's own vulns shape (CVE ID -> cvss/
    # summary) plus a `ports` list per CVE tying it to the affected
    # service(s) - kept in `data` alongside the raw per-service banners
    # rather than on ServiceInfo, same convention shodan_source.py uses for
    # the API's vulns field (see its module docstring).
    hostnames = _parse_hostnames(soup)
    data = {
        "hostnames": hostnames,
        "domains": _parse_domains(soup),
        "country": _label_value(soup, "Country"),
        "city": _label_value(soup, "City"),
        "organization": _label_value(soup, "Organization"),
        "isp": _label_value(soup, "ISP"),
        "asn": _label_value(soup, "ASN"),
        "vulns": _parse_vulns(html),
    }
    return EnrichmentResult(
        source="shodan_web",
        target_type="ip",
        target=ip,
        data=data,
        services=_parse_services(soup),
        related_hostnames=list(hostnames),
    )


def parse_shodan_domain_page(html: str, domain: str) -> list[DiscoveredHostname]:
    soup = BeautifulSoup(html, "html.parser")
    labels: set[str] = set()

    subdomains_ul = soup.find("ul", id="subdomains")
    if subdomains_ul is not None:
        for li in subdomains_ul.find_all("li"):
            text = li.get_text(strip=True)
            if text:
                labels.add(text)

    # The DNS Records table's first column is the subdomain label relative
    # to `domain`, empty for an apex record - hostname_from_zone_label
    # turns "" back into the apex domain itself.
    records_table = soup.find("table", class_="u-full-width")
    if records_table is not None:
        for row in records_table.find_all("tr"):
            cells = row.find_all("td")
            if len(cells) >= 2:
                labels.add(cells[0].get_text(strip=True))

    return [
        DiscoveredHostname(name=hostname_from_zone_label(label, domain), source="shodan_web")
        for label in sorted(labels)
    ]


class ShodanWebSource(Source):
    """Instances are shared across the whole scan run (see registry.py /
    base.py's thread-safety note) so the crawl-delay pacing below is a
    process-wide limit rather than one enforced per concurrent caller."""

    name = "shodan_web"
    category = "scrape"
    fallback_for = "shodan"

    def __init__(self) -> None:
        self._last_request_at: float | None = None
        self._lock = threading.Lock()

    def _get(self, url: str) -> requests.Response:
        with self._lock:
            if self._last_request_at is not None:
                elapsed = time.monotonic() - self._last_request_at
                if elapsed < MIN_REQUEST_INTERVAL_SECONDS:
                    time.sleep(MIN_REQUEST_INTERVAL_SECONDS - elapsed)
            try:
                return self._request(url)
            finally:
                self._last_request_at = time.monotonic()

    @with_retry
    def _request(self, url: str) -> requests.Response:
        response = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT_SECONDS, verify=VERIFY_TLS)
        if response.status_code == 404:
            return response
        response.raise_for_status()
        return response

    def discover(self, domain: str) -> list[DiscoveredHostname]:
        response = self._get(DOMAIN_URL.format(domain=domain))
        if response.status_code == 404:
            return []
        return parse_shodan_domain_page(response.text, domain)

    def enrich(self, target: str, hostnames: list[str]) -> EnrichmentResult:
        response = self._get(HOST_URL.format(ip=target))
        if response.status_code == 404:
            logger.info("shodan_web has no host page for %s", target)
            return EnrichmentResult(source=self.name, target_type="ip", target=target, data={})
        result = parse_shodan_host_page(response.text, target)
        if not result.services and not any(result.data.values()):
            # Shodan answers 404 for hosts it doesn't know, so a 200 page
            # with none of these fields means the markup changed.
            raise ScrapeParseError("shodan_web: host page has none of the expected fields")
        return result
