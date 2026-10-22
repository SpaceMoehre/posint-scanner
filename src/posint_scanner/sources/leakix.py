"""Enrichment + collection source using LeakIX (https://leakix.net).

LeakIX continuously indexes *exposed services and leaks* across the internet -
open databases, exposed `.env`/`.git`, default/no-auth credentials, world-open
admin panels - the highest-signal "bad IT hygiene" feed available passively.

  - enrich (IP): `GET /host/<ip>` - services and leaks seen on the address.
  - collect (domain): `GET /domain/<domain>` for the domain's leaks/services,
    plus `GET /api/subdomains/<domain>` whose names feed back for resolution.

Both responses are l9format events (https://github.com/LeakIX/l9format), split
into `Services` and `Leaks` arrays. Leaks become severity-graded findings;
services become ServiceInfo rows. Needs a free API key (leakix.net), sent in
the `api-key` header; the free tier is roughly one request per second.
"""

from __future__ import annotations

import logging

from posint_scanner.models import EnrichmentResult, ServiceInfo
from posint_scanner.retry import with_retry
from posint_scanner.sources.common import ApiKeySource, http_get, normalized_names

logger = logging.getLogger(__name__)

HOST_URL = "https://leakix.net/host/{ip}"
DOMAIN_URL = "https://leakix.net/domain/{domain}"
SUBDOMAINS_URL = "https://leakix.net/api/subdomains/{domain}"

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _port(event: dict) -> int | None:
    raw = event.get("port")
    if raw is None:
        return None
    try:
        return int(raw)  # l9format sends the port as a string
    except (TypeError, ValueError):
        return None


def _service_info(event: dict) -> ServiceInfo | None:
    port = _port(event)
    if port is None:
        return None
    software = (event.get("service") or {}).get("software") or {}
    return ServiceInfo(
        port=port,
        protocol=event.get("protocol") or event.get("transport") or "tcp",
        banner=software.get("name") or None,
        version=software.get("version") or None,
    )


def _finding(event: dict) -> dict:
    leak = event.get("leak") or {}
    port = _port(event)
    where = event.get("ip") or event.get("host") or ""
    detail = " ".join(
        part for part in (event.get("protocol"), f"port {port}" if port else "", where) if part
    )
    return {
        "id": event.get("event_source") or "leak",
        "severity": (leak.get("severity") or "medium").lower(),
        "title": event.get("summary") or event.get("event_source") or "exposure",
        "detail": detail,
    }


def _related(event: dict) -> list[str]:
    names = [event.get("host"), event.get("reverse")]
    # `certificate` can be JSON null (not just absent), so `or {}` both times.
    certificate = (event.get("ssl") or {}).get("certificate") or {}
    names.extend(certificate.get("domain") or [])
    return [n for n in names if n]


def _split(payload: object) -> tuple[list[dict], list[dict]]:
    """(service events, leak events) from either the wrapped host/domain
    response (`{"Services": [...], "Leaks": [...]}`) or a bare event list
    (classified by `event_type`)."""
    if isinstance(payload, dict):
        return payload.get("Services") or [], payload.get("Leaks") or []
    if isinstance(payload, list):
        events = [e for e in payload if isinstance(e, dict)]
        services = [e for e in events if e.get("event_type") != "leak"]
        leaks = [e for e in events if e.get("event_type") == "leak"]
        return services, leaks
    return [], []


def parse_events(payload: object) -> tuple[list[ServiceInfo], list[dict], list[str]]:
    """Parse a LeakIX host/domain response into (services, findings, related
    hostnames). Findings are sorted most-severe first."""
    service_events, leak_events = _split(payload)
    services = [s for e in service_events if (s := _service_info(e)) is not None]
    findings = [_finding(e) for e in leak_events]
    findings.sort(key=lambda f: _SEVERITY_RANK.get(f["severity"], 9))
    related_raw: list[str] = []
    for event in [*service_events, *leak_events]:
        related_raw.extend(_related(event))
    return services, findings, normalized_names(related_raw)


def parse_subdomains(payload: object) -> list[str]:
    if not isinstance(payload, list):
        return []
    return [row["subdomain"] for row in payload
            if isinstance(row, dict) and row.get("subdomain")]


class LeakIxSource(ApiKeySource):
    name = "leakix"
    # ~1 request/second on the free tier; the governor paces to this.
    requests_per_minute = 50

    def _get(self, url: str):
        headers = {"api-key": self.require_key(), "Accept": "application/json"}
        # 404 = nothing indexed for this target, not an error.
        return http_get(self.name, url, headers=headers, ok_statuses=(404,))

    def _events(self, url: str) -> object:
        response = self._get(url)
        return [] if response.status_code == 404 else response.json()

    @with_retry
    def enrich(self, target: str, hostnames: list[str]) -> EnrichmentResult:
        services, findings, related = parse_events(self._events(HOST_URL.format(ip=target)))
        return EnrichmentResult(
            source=self.name,
            target_type="ip",
            target=target,
            data={"findings": findings, "service_count": len(services)},
            services=services,
            related_hostnames=related,
        )

    @with_retry
    def collect(self, domain: str) -> EnrichmentResult:
        _, findings, related = parse_events(self._events(DOMAIN_URL.format(domain=domain)))
        # Second request of the call: ask the governor so it's paced (and
        # charged) like any extra request, not fired back-to-back into the
        # ~1 req/s free-tier limit.
        subdomains = (
            parse_subdomains(self._events(SUBDOMAINS_URL.format(domain=domain)))
            if self.extra_request()
            else []
        )
        related = normalized_names([*related, *subdomains])
        return EnrichmentResult(
            source=self.name,
            target_type="domain",
            target=domain,
            data={"findings": findings, "subdomain_count": len(subdomains)},
            related_hostnames=related,
        )
