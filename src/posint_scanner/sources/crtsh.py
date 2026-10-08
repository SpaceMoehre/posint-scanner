"""Discovery source using crt.sh certificate-transparency log search.

Free, no API key. crt.sh is often slow or briefly down; a failed call is
retried (with_retry), then logged and skipped like any other source failure,
so it never costs the rest of the scan.
"""

from __future__ import annotations

import requests

from posint_scanner.models import DiscoveredHostname
from posint_scanner.normalize import InvalidDomainError, normalize_domain
from posint_scanner.retry import VERIFY_TLS, with_retry
from posint_scanner.sources.base import Source

BASE_URL = "https://crt.sh/"
TIMEOUT_SECONDS = 30


def parse_crtsh_response(entries: list[dict]) -> list[DiscoveredHostname]:
    seen: set[str] = set()
    hostnames: list[DiscoveredHostname] = []
    for entry in entries:
        raw_value = entry.get("name_value", "")
        for raw_name in raw_value.splitlines():
            try:
                name = normalize_domain(raw_name)
            except InvalidDomainError:
                continue
            if name not in seen:
                seen.add(name)
                hostnames.append(DiscoveredHostname(name=name, source="crtsh"))
    return hostnames


class CrtShSource(Source):
    name = "crtsh"

    @with_retry
    def discover(self, domain: str) -> list[DiscoveredHostname]:
        response = requests.get(
            BASE_URL,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=TIMEOUT_SECONDS,
            verify=VERIFY_TLS,
        )
        response.raise_for_status()
        return parse_crtsh_response(response.json())
