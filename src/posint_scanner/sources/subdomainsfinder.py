"""Stub for subdomainsfinder.com.

subdomainsfinder.com has no documented public API - it's a browser-only
form-submit tool backed by an undocumented internal endpoint. Rather than
scrape an unversioned internal API blind, this connector is wired into the
architecture but left unimplemented until real endpoint details (a HAR
capture, official API docs, etc.) are available.
"""

from __future__ import annotations

from posint_scanner.models import DiscoveredHostname
from posint_scanner.sources.base import Source


class SubdomainsFinderSource(Source):
    name = "subdomainsfinder"
    default_enabled = False

    def discover(self, domain: str) -> list[DiscoveredHostname]:
        raise NotImplementedError(
            "subdomainsfinder.com has no documented API; this connector needs "
            "real endpoint details before it can run"
        )
