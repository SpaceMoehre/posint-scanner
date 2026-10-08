"""Collection source wrapping the `theHarvester` CLI
(https://github.com/laramies/theHarvester): email addresses at the domain,
gathered from search engines, certificate logs and the OSINT APIs it
bundles. Hostnames it finds feed back as related hostnames (in-scope only -
its search-engine hits are too noisy to seed candidate domains).

`backends` is passed to `-b`: source names or, on current theHarvester,
capabilities (`emails` = every source that yields addresses). Sources that
need a key read it from theHarvester's own api-keys.yaml; without one they
are skipped by theHarvester itself.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from posint_scanner import proxy
from posint_scanner.models import EmailAddress, EnrichmentResult
from posint_scanner.sources.base import (
    DEFAULT_TTL_DAYS,
    Source,
    SourceSettings,
    SourceUnavailableError,
)
from posint_scanner.sources.common import host_of, scoped_email
from posint_scanner.scope import in_scope

BINARIES = ("theHarvester", "theharvester")
DEFAULT_BACKENDS = "emails"
DEFAULT_LIMIT = 500
DEFAULT_TIMEOUT_SECONDS = 900


class TheHarvesterSettings(SourceSettings):
    backends: str = DEFAULT_BACKENDS
    limit: int = DEFAULT_LIMIT
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS


def parse_theharvester_json(domain: str, data: dict) -> tuple[list[EmailAddress], list[str]]:
    """(in-scope email addresses, in-scope hostnames) from theHarvester's
    JSON report. Hosts may come as `host:ip` when it resolved them."""
    emails: list[EmailAddress] = []
    seen: set[str] = set()
    for raw in data.get("emails") or []:
        address = scoped_email(domain, str(raw))
        if address and address not in seen:
            seen.add(address)
            emails.append(EmailAddress(address=address))
    hosts: list[str] = []
    for raw in data.get("hosts") or []:
        name = host_of(str(raw).split(":", 1)[0])
        if name and in_scope(name, domain) and name not in hosts:
            hosts.append(name)
    return emails, hosts


class TheHarvesterSource(Source):
    name = "theharvester"
    settings_model = TheHarvesterSettings
    ttl_days = DEFAULT_TTL_DAYS

    def __init__(
        self,
        backends: str = DEFAULT_BACKENDS,
        limit: int = DEFAULT_LIMIT,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.backends = backends
        self.limit = limit
        self.timeout_seconds = timeout_seconds

    @classmethod
    def from_settings(cls, settings: SourceSettings) -> Source:
        assert isinstance(settings, TheHarvesterSettings)
        return cls(settings.backends, settings.limit, settings.timeout_seconds)

    def collect(self, domain: str) -> EnrichmentResult:
        # theHarvester's own proxy support is HTTP-only and its backends do
        # their own DNS - it can't be kept inside the tunnel.
        if reason := proxy.unavailable_reason("theHarvester"):
            raise SourceUnavailableError(reason)
        binary_path = next((p for p in map(shutil.which, BINARIES) if p), None)
        if binary_path is None:
            raise SourceUnavailableError(
                "theHarvester not found on PATH - install from "
                "https://github.com/laramies/theHarvester"
            )
        with tempfile.TemporaryDirectory(prefix="posint-theharvester-") as tmp:
            report = Path(tmp) / "report"
            result = subprocess.run(
                [binary_path, "-d", domain, "-b", self.backends, "-l", str(self.limit),
                 "-f", str(report)],
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
                cwd=tmp,
            )
            json_path = report.with_suffix(".json")
            if not json_path.exists():
                if result.returncode != 0:
                    raise RuntimeError(
                        f"theHarvester exited {result.returncode}: "
                        f"{(result.stderr or result.stdout).strip()[-500:]}"
                    )
                data: dict = {}
            else:
                data = json.loads(json_path.read_text() or "{}")
        emails, hosts = parse_theharvester_json(domain, data)
        return EnrichmentResult(
            source=self.name, target_type="domain", target=domain,
            data={"backends": self.backends, "email_count": len(emails), "host_count": len(hosts)},
            email_addresses=emails,
            related_hostnames=hosts,
        )
