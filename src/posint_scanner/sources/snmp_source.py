"""Active source: check SNMP (UDP 161) on each IP and analyze what it discloses.

Sends an SNMPv3 engine-discovery request (no credentials) and a v2c/v1 GET
of the system group for each configured community (default: `public`) -
see snmp.py. An agent that answers is recorded as service 161/udp, and its
sysDescr gives the OS: on Linux the exact running kernel (`uname -a`), with
the distro and release its build implies.

Trying a community string is a login attempt, so this is **off by
default** (like container_exposure): enable with `--source snmp`, only
against hosts you're authorized to test. UDP can't go through the SOCKS5
proxy, so it's skipped while one is set.
"""

from __future__ import annotations

from pydantic import field_validator

from posint_scanner import proxy, snmp
from posint_scanner.models import EnrichmentResult, ServiceInfo
from posint_scanner.sources.base import Source, SourceSettings, SourceUnavailableError
from posint_scanner.sources.portscan import _PROBE_SLOTS

DEFAULT_COMMUNITIES = ["public"]


class SnmpSettings(SourceSettings):
    # Tried in order until one answers; env: OSINT_SNMP_COMMUNITIES=public,private
    communities: list[str] = DEFAULT_COMMUNITIES

    @field_validator("communities", mode="before")
    @classmethod
    def _split(cls, value: object) -> object:
        if isinstance(value, str):
            return [c.strip() for c in value.split(",") if c.strip()]
        return value


def service_banner(analysis: dict) -> str:
    """One line for the services table: "SNMP - Linux 6.1.0-18-amd64 (Debian 12 (bookworm))"."""
    os_info = analysis.get("os") or {}
    parts = [os_info.get("family"), os_info.get("kernel") or os_info.get("version")]
    label = " ".join(p for p in parts if p)
    if detail := os_info.get("distro") or os_info.get("release"):
        label += f" ({detail})"
    return f"SNMP - {label}" if label else "SNMP"


class SnmpSource(Source):
    name = "snmp"
    category = "active"
    default_enabled = False
    settings_model = SnmpSettings

    def __init__(self, communities: list[str] | None = None) -> None:
        self.communities = communities if communities is not None else list(DEFAULT_COMMUNITIES)

    @classmethod
    def from_settings(cls, settings: SourceSettings) -> SnmpSource:
        assert isinstance(settings, SnmpSettings)
        return cls(communities=settings.communities)

    def enrich(self, target: str, hostnames: list[str]) -> EnrichmentResult:
        if reason := proxy.unavailable_reason("snmp (UDP)"):
            raise SourceUnavailableError(reason)
        with _PROBE_SLOTS:
            record = snmp.probe(target, self.communities)
        analysis = snmp.analyze(record)
        services = []
        if record["state"] == "open":
            services.append(ServiceInfo(port=record["port"], protocol="udp",
                                        banner=service_banner(analysis)))
        return EnrichmentResult(
            source=self.name,
            target_type="ip",
            target=target,
            data={**record, "analysis": analysis},
            services=services,
        )
