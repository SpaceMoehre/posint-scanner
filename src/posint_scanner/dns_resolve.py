"""Fixed hostname -> IP resolution stage.

Not a registry Source - every IP-based enrichment source depends on this
running first, so it's a plain orchestrator step rather than a plugin.
"""

from __future__ import annotations

import dns.resolver

RECORD_TYPES = ("A", "AAAA")


def query_record_type(hostname: str, record_type: str) -> list[str]:
    """Look up one DNS record type, returning [] (not raising) if there's no
    answer - shared by this module's A/AAAA resolution and dnsrecon's
    NS/MX/TXT/SOA lookups, since both need the same query-and-degrade shape."""
    try:
        answer = dns.resolver.resolve(hostname, record_type)
        return [str(record) for record in answer]
    except dns.exception.DNSException:
        return []


def resolve_hostname(hostname: str) -> list[str]:
    addresses: list[str] = []
    for record_type in RECORD_TYPES:
        addresses.extend(query_record_type(hostname, record_type))
    return addresses


def lookup_domain_nameserver_ip(domain: str) -> str | None:
    """Resolve one of the domain's own authoritative nameservers to an IP.

    Used by the netblock sweep: if the target manages its own reverse-DNS
    zone (common for an org that owns its netblock outright), querying its
    nameserver directly can see records a public resolver's cache wouldn't.
    """
    for ns_hostname in query_record_type(domain, "NS"):
        ns_hostname = ns_hostname.rstrip(".")
        for ip in query_record_type(ns_hostname, "A"):
            return ip
    return None
