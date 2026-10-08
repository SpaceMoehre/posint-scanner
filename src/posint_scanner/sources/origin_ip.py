"""Collection source: candidate origin IPs behind a CDN/WAF (the de-cloaking
step HatCloud and similar tools do). Keyless, purely passive - it reads only
DNS the target itself publishes and never sends a probe to the origin.

When a domain is fronted by Cloudflare (etc.), its A record shows the CDN's
IP, not the real server. But the origin frequently leaks through DNS the
same zone publishes anyway:

  - MX hosts (mail is almost never proxied and often runs on the origin);
  - SPF `ip4:`/`ip6:` literals and `a:` hosts (sending servers);
  - direct-connect subdomains people leave pointed straight at the box
    (`direct`, `origin`, `ftp`, `cpanel`, `mail`, `dev`, ...).

Any resulting IP that is NOT itself in a known CDN range is reported as a
candidate origin - a real "the WAF may be bypassable" finding. Kept in the
domain's data (with the hint that surfaced each IP); origin IPs are not fed
back as related hostnames (they're IPs, not names) - the operator reviews
them.

The bundled CDN ranges are a snapshot (Cloudflare's are stable and small);
an IP outside them is treated as a possible origin, so a stale snapshot errs
toward showing more candidates, never toward hiding the origin.
"""

from __future__ import annotations

import ipaddress
import logging
import re

from posint_scanner.dns_resolve import query_record_type, resolve_hostname
from posint_scanner.models import EnrichmentResult
from posint_scanner.sources.base import DEFAULT_TTL_DAYS, Source

logger = logging.getLogger(__name__)

# Snapshot of major CDN/WAF ranges. Cloudflare (the usual de-cloaking target)
# from https://www.cloudflare.com/ips/; a few Fastly/Google ranges too. Not
# exhaustive - see the module docstring on why a miss is the safe direction.
_CDN_RANGES: dict[str, tuple[str, ...]] = {
    "cloudflare": (
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
        "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
    ),
    "fastly": ("151.101.0.0/16", "199.232.0.0/16"),
}

_COMPILED: list[tuple[str, ipaddress._BaseNetwork]] = [
    (name, ipaddress.ip_network(cidr))
    for name, cidrs in _CDN_RANGES.items()
    for cidr in cidrs
]

# Subdomains commonly left pointing straight at the origin.
DEFAULT_LEAKY_SUBDOMAINS = (
    "direct", "origin", "ftp", "cpanel", "webmail", "mail", "smtp", "webdisk",
    "server", "dev", "staging", "test", "vpn", "remote",
)

_SPF_IP = re.compile(r"\b(?:ip4|ip6):([^\s]+)")
# Only `a:` hosts: they name the domain's *own* servers. `include:` and `mx:`
# delegate to third-party providers (Microsoft 365, SendGrid, ...) whose IPs
# are never the origin - reporting them would be a confident false positive.
_SPF_HOST = re.compile(r"\ba:([^\s]+)")


def cdn_of(ip: str) -> str | None:
    """The CDN whose published range contains `ip`, or None."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for name, network in _COMPILED:
        if address.version == network.version and address in network:
            return name
    return None


def spf_hosts_and_ips(txt_records: list[str]) -> tuple[list[str], list[str]]:
    """(ip literals/CIDRs, `a:` hostnames) referenced by any SPF TXT record.
    `include:`/`mx:` mechanisms are deliberately excluded - they point at
    third-party mail infrastructure, not the target's origin."""
    ips: list[str] = []
    hosts: list[str] = []
    for record in txt_records:
        value = record.strip().strip('"')
        if "v=spf1" not in value:
            continue
        ips.extend(_SPF_IP.findall(value))
        hosts.extend(_SPF_HOST.findall(value))
    return ips, hosts


def _first_ip_of_cidr(literal: str) -> str | None:
    """`198.51.100.7` -> itself; `203.0.113.0/24` -> the network id (a stable
    representative to resolve/flag). None if it isn't an address/CIDR."""
    try:
        if "/" in literal:
            return str(ipaddress.ip_network(literal, strict=False).network_address)
        return str(ipaddress.ip_address(literal))
    except ValueError:
        return None


class OriginIpSource(Source):
    name = "origin_ip"
    category = "passive"
    ttl_days = DEFAULT_TTL_DAYS

    def __init__(self, subdomains: tuple[str, ...] | list[str] | None = None) -> None:
        self.subdomains = tuple(DEFAULT_LEAKY_SUBDOMAINS if subdomains is None else subdomains)

    def collect(self, domain: str) -> EnrichmentResult:
        frontend_ips = resolve_hostname(domain)
        cdn = next((c for ip in frontend_ips if (c := cdn_of(ip))), None)

        # Gather (ip -> set of hints) for every origin clue the zone leaks.
        hints: dict[str, set[str]] = {}

        def add(ip: str, via: str) -> None:
            hints.setdefault(ip, set()).add(via)

        # MX targets
        for mx in query_record_type(domain, "MX"):
            parts = mx.split()
            mx_host = parts[-1].rstrip(".").lower() if parts else ""
            if mx_host:
                for ip in resolve_hostname(mx_host):
                    add(ip, f"mx:{mx_host}")

        # SPF
        spf_ips, spf_hosts = spf_hosts_and_ips(query_record_type(domain, "TXT"))
        for literal in spf_ips:
            spf_ip = _first_ip_of_cidr(literal)
            if spf_ip:
                add(spf_ip, "spf")
        for host in spf_hosts:
            if not host.startswith("_") and "." in host:
                for ip in resolve_hostname(host.rstrip(".").lower()):
                    add(ip, f"spf:{host}")

        # Direct-connect subdomains
        for label in self.subdomains:
            host = f"{label}.{domain}"
            for ip in resolve_hostname(host):
                add(ip, f"subdomain:{host}")

        frontend_set = set(frontend_ips)
        origin_candidates = [
            {"ip": ip, "via": sorted(via)}
            for ip, via in sorted(hints.items())
            # a candidate origin is an IP that isn't the CDN front and isn't
            # itself in a CDN range
            if ip not in frontend_set and cdn_of(ip) is None
        ]

        if cdn and origin_candidates:
            logger.info(
                "origin_ip: %s is behind %s; %d candidate origin IP(s) leaked via DNS",
                domain, cdn, len(origin_candidates),
            )

        return EnrichmentResult(
            source=self.name,
            target_type="domain",
            target=domain,
            data={
                "behind_cdn": cdn is not None,
                "cdn": cdn,
                "frontend_ips": frontend_ips,
                "origin_candidates": origin_candidates,
            },
            # IPs, not hostnames - kept in data, never fed back as candidate
            # domains. The operator reviews and can scan them by hand.
            related_hostnames=[],
        )
