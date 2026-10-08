"""ASN lookup and prefix listing, used to widen the netblock sweep from a
single /24 to every range actually announced by the IP's network operator.

Both steps are free, keyless, standard OSINT techniques and purely passive
(a DNS query and an HTTP GET to a public data service - nothing touches the
target):

- IP -> ASN via Team Cymru's DNS-based whois (origin.asn.cymru.com)
- ASN -> announced prefixes via RIPEstat's public API, which mirrors global
  BGP data via RIS route collectors rather than only the RIPE region, so it
  works for any ASN worldwide, not just European ones.
"""

from __future__ import annotations

import ipaddress

import dns.exception
import dns.resolver
import requests

from posint_scanner.retry import VERIFY_TLS, with_retry

CYMRU_ORIGIN_SUFFIX = "origin.asn.cymru.com"
RIPESTAT_URL = "https://stat.ripe.net/data/announced-prefixes/data.json"
TIMEOUT_SECONDS = 15


def lookup_asn(ip: str) -> int | None:
    """IP -> ASN via Team Cymru's DNS whois. IPv4 only."""
    reversed_octets = ".".join(reversed(ip.split(".")))
    query_name = f"{reversed_octets}.{CYMRU_ORIGIN_SUFFIX}"
    try:
        answer = dns.resolver.resolve(query_name, "TXT")
    except dns.exception.DNSException:
        return None

    # Response format: "15366 | 212.86.32.0/19 | DE | ripencc | 1999-06-07"
    # A multi-origin IP lists several space-separated ASNs in the first
    # field - we just take the first.
    txt = str(answer[0]).strip('"')
    first_field = txt.split("|", 1)[0].strip()
    try:
        return int(first_field.split()[0])
    except (ValueError, IndexError):
        return None


@with_retry
def lookup_asn_prefixes(asn: int) -> list[ipaddress.IPv4Network]:
    """ASN -> all its announced IPv4 prefixes via RIPEstat."""
    response = requests.get(
        RIPESTAT_URL, params={"resource": f"AS{asn}"}, timeout=TIMEOUT_SECONDS,
        verify=VERIFY_TLS,
    )
    response.raise_for_status()
    data = response.json()

    prefixes = []
    for entry in data.get("data", {}).get("prefixes", []):
        try:
            prefixes.append(ipaddress.IPv4Network(entry["prefix"]))
        except ValueError:
            continue  # IPv6 - the sweep only supports IPv4 for now
    return prefixes
