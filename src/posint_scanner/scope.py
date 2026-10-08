"""What's in scope for a scan, and what a related out-of-scope name points at.

A scan of `example.com` covers the domain and every name under it. Names
outside it that sources relate to the target (reverse-IP neighbours, cert
SANs, WHOIS siblings) are reduced to their registrable domain (per the Public
Suffix List: `shop.brand.co.uk` -> `brand.co.uk`) and recorded as candidate
domains for a human to review - never scanned automatically, since that's
how a scan wanders onto infrastructure nobody authorized.

The one exception is a TLD sibling: the same registrable name under a
different public suffix (`example.com` -> `example.net`, `example.co.uk`).
Those count as the target's own and are scanned in the same run.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

import tldextract

from posint_scanner.normalize import InvalidDomainError, normalize_domain

# Bundled PSL snapshot only - no network fetch at runtime. Private suffixes
# included so `team.github.io` counts as its own site, not `github.io`.
_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
)


def in_scope(hostname: str, domain: str) -> bool:
    return hostname == domain or hostname.endswith("." + domain)


def registrable_domain(hostname: str) -> str | None:
    """`a.b.brand.co.uk` -> `brand.co.uk`; None for IPs, bare TLDs and
    single-label names."""
    try:
        ipaddress.ip_address(hostname)
        return None
    except ValueError:
        pass
    result = _EXTRACT(hostname)
    return result.top_domain_under_public_suffix or None


def is_tld_sibling(candidate: str, domain: str) -> bool:
    """True if registrable `candidate` is `domain` under another public suffix
    (`example.net` for `example.com`). Only ICANN suffixes: names under a
    private suffix (`example.github.io`) belong to whoever registered them."""
    a, b = _EXTRACT(candidate), _EXTRACT(domain)
    return (
        bool(a.domain)
        and a.domain == b.domain
        and a.suffix != b.suffix
        and not a.subdomain
        and not b.subdomain
        and not a.is_private
        and not b.is_private
    )


def split_related(domain: str, names: Iterable[str]) -> tuple[list[str], list[str]]:
    """Split related names into (in-scope hostnames, out-of-scope registrable
    domains), each normalized, deduped and in first-seen order."""
    hostnames: list[str] = []
    candidates: list[str] = []
    for raw in names:
        try:
            name = normalize_domain(raw)
        except InvalidDomainError:
            continue
        if in_scope(name, domain):
            if name not in hostnames:
                hostnames.append(name)
            continue
        registrable = registrable_domain(name)
        if registrable and registrable != domain and registrable not in candidates:
            candidates.append(registrable)
    return hostnames, candidates
