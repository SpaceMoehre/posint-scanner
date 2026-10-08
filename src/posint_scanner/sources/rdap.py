"""Collection source: the domain's registration record via RDAP (the
structured successor to WHOIS). Free, keyless; rdap.org redirects to the
registry's own RDAP server.

Kept: registrar, registration/expiry/last-changed dates, EPP status,
nameservers and whether the delegation is DNSSEC-signed - an expiry date
coming up or a missing transfer lock are exposure findings. Registrant and
contact entities are deliberately dropped: they're personal data, and
usually redacted anyway.
"""

from __future__ import annotations

from posint_scanner.models import EnrichmentResult
from posint_scanner.retry import with_retry
from posint_scanner.scope import in_scope
from posint_scanner.sources.base import DEFAULT_TTL_DAYS, Source
from posint_scanner.sources.common import http_get, normalized_names

RDAP_URL = "https://rdap.org/domain/{domain}"
_EVENTS = {"registration": "registered", "expiration": "expires", "last changed": "last_changed"}


def _registrar(entities: list[dict]) -> str | None:
    for entity in entities:
        if "registrar" not in entity.get("roles", []):
            continue
        vcard = entity.get("vcardArray", [None, []])
        for field in vcard[1] if len(vcard) > 1 else []:
            if field and field[0] == "fn":
                return str(field[3])
    return None


def parse_rdap(data: dict, domain: str) -> EnrichmentResult:
    summary: dict = {
        "registrar": _registrar(data.get("entities", [])),
        "registered": None,
        "expires": None,
        "last_changed": None,
        "status": list(data.get("status", [])),
        "nameservers": normalized_names(
            ns.get("ldhName", "") for ns in data.get("nameservers", [])
        ),
        "dnssec": bool(data.get("secureDNS", {}).get("delegationSigned", False)),
    }
    for event in data.get("events", []):
        key = _EVENTS.get(event.get("eventAction", ""))
        if key:
            summary[key] = event.get("eventDate")
    return EnrichmentResult(
        source="rdap",
        target_type="domain",
        target=domain,
        data=summary,
        related_hostnames=[ns for ns in summary["nameservers"] if in_scope(ns, domain)],
    )


class RdapSource(Source):
    name = "rdap"
    ttl_days = DEFAULT_TTL_DAYS

    @with_retry
    def collect(self, domain: str) -> EnrichmentResult:
        response = http_get(
            self.name,
            RDAP_URL.format(domain=domain),
            headers={"Accept": "application/rdap+json"},
            ok_statuses=(404,),
        )
        if response.status_code == 404:
            return EnrichmentResult(source=self.name, target_type="domain", target=domain)
        return parse_rdap(response.json(), domain)
