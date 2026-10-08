"""DNS reconnaissance source: reverse PTR lookups, AXFR zone-transfer attempts,
and NS/MX/TXT/SOA record lookups.

All of these are standard, low-risk passive/DNS-protocol techniques. A zone
transfer is a single AXFR query; properly configured nameservers refuse it
(a no-op), and it carries none of the authorization risk that active
scanning does - unlike Qualys VMDR scan-triggering, this needs no gate.

Implements both discovery (a successful zone transfer dumps the whole zone
at once - a real discovery event, flagged via `axfr_successful` in the
returned data) and enrichment (PTR + record lookups per already-known
hostname/IP).
"""

from __future__ import annotations

import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.query
import dns.resolver
import dns.zone

from posint_scanner.dns_resolve import query_record_type
from posint_scanner.models import DiscoveredHostname, EnrichmentResult
from posint_scanner.sources.base import Source

RECORD_TYPES = ("NS", "MX", "TXT", "SOA")
XFR_TIMEOUT_SECONDS = 10
SWEEP_WORKERS = 150
SWEEP_RESOLVER_TIMEOUT_SECONDS = 3
# Process-wide cap on sweep queries in flight (each holds a UDP socket and an
# epoll fd): concurrent domains and web UI scans each run their own sweep pool.
MAX_CONCURRENT_SWEEP_QUERIES = SWEEP_WORKERS
_SWEEP_SLOTS = threading.BoundedSemaphore(MAX_CONCURRENT_SWEEP_QUERIES)


def hostname_from_zone_label(label: str, domain: str) -> str:
    if label in ("@", ""):
        return domain.lower()
    return f"{label}.{domain}".lower()


def make_resolver(nameserver_ip: str) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [nameserver_ip]
    resolver.timeout = SWEEP_RESOLVER_TIMEOUT_SECONDS
    resolver.lifetime = SWEEP_RESOLVER_TIMEOUT_SECONDS
    return resolver


def reverse_lookup(ip: str, resolver: dns.resolver.Resolver | None = None) -> list[str]:
    try:
        if resolver is not None:
            answer = resolver.resolve_address(ip)
        else:
            answer = dns.resolver.resolve_address(ip)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return []
    return [str(record.target).rstrip(".") for record in answer]


def lookup_records(hostname: str) -> dict[str, list[str]]:
    return {record_type: query_record_type(hostname, record_type) for record_type in RECORD_TYPES}


def belongs_to_domain(hostname: str, domain: str) -> bool:
    hostname = hostname.rstrip(".").lower()
    domain = domain.rstrip(".").lower()
    return hostname == domain or hostname.endswith(f".{domain}")


def _sweep_lookup(ip: str, resolver: dns.resolver.Resolver) -> list[str]:
    with _SWEEP_SLOTS:
        return reverse_lookup(ip, resolver)


def sweep_netblocks(
    networks: list[ipaddress.IPv4Network],
    domain: str,
    resolver_ips: list[str],
    workers: int = SWEEP_WORKERS,
) -> list[DiscoveredHostname]:
    """Reverse-PTR every address across all of `networks` against each of
    `resolver_ips`, keeping only hostnames that actually belong to `domain`.
    A forward-discovery blind spot: a host with no public cert and no naming
    link to anything else we've found is still visible this way if it sits
    in a range announced by the same network operator and has a PTR record -
    purely passive (plain DNS queries), no new external dependency.

    All networks share ONE thread pool rather than each getting its own, so
    sweeping several networks (a fallback /24 plus its neighbors, or several
    same-ASN prefixes) has one bounded, predictable concurrency budget
    instead of nested per-network pools multiplying together.

    Querying more than one resolver matters: if the target manages its own
    reverse-DNS zone, its own nameserver may have records a public resolver
    doesn't (or disagrees with) - all configured resolvers are checked and
    any hit counts.
    """
    resolvers = [make_resolver(ip) for ip in resolver_ips]
    matches: list[DiscoveredHostname] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {}
        for network in networks:
            for address in network.hosts():
                for resolver, resolver_ip in zip(resolvers, resolver_ips):
                    future = executor.submit(_sweep_lookup, str(address), resolver)
                    futures[future] = (str(address), resolver_ip)

        for future in as_completed(futures):
            ip, resolver_ip = futures.pop(future)
            for hostname in future.result():
                if belongs_to_domain(hostname, domain):
                    matches.append(
                        DiscoveredHostname(
                            name=hostname.lower(),
                            source="dnsrecon",
                            data={
                                "discovered_via": "netblock_sweep",
                                "ip": ip,
                                "resolver": resolver_ip,
                            },
                        )
                    )
    return matches


class DnsReconSource(Source):
    name = "dnsrecon"

    def discover(self, domain: str) -> list[DiscoveredHostname]:
        try:
            ns_records = dns.resolver.resolve(domain, "NS")
        except dns.exception.DNSException:
            return []

        for ns_record in ns_records:
            nameserver = str(ns_record.target).rstrip(".")
            hostnames = self._try_zone_transfer(domain, nameserver)
            if hostnames:
                return hostnames
        return []

    def _try_zone_transfer(self, domain: str, nameserver: str) -> list[DiscoveredHostname]:
        # dns.query.xfr() takes an IP to connect to, not a hostname - it
        # doesn't resolve one internally.
        nameserver_ips = query_record_type(nameserver, "A")
        if not nameserver_ips:
            return []

        try:
            xfr = dns.query.xfr(nameserver_ips[0], domain, timeout=XFR_TIMEOUT_SECONDS)
            zone = dns.zone.from_xfr(xfr)
        except (OSError, dns.exception.DNSException):
            return []

        return [
            DiscoveredHostname(
                name=hostname_from_zone_label(str(label), domain),
                source="dnsrecon",
                data={"axfr_successful": True, "nameserver": nameserver},
            )
            for label in zone.nodes.keys()
        ]

    def enrich(self, target: str, hostnames: list[str]) -> EnrichmentResult:
        data = {
            "ptr": reverse_lookup(target),
            "records": {hostname: lookup_records(hostname) for hostname in hostnames},
        }
        return EnrichmentResult(source="dnsrecon", target_type="ip", target=target, data=data)
