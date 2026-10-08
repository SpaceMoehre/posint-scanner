"""Enrichment source that pings each known IP via the system `ping` binary.

This is the one source in the whole tool that isn't purely passive - it
sends ICMP echo requests directly to the target, unlike every other source
which only talks to public resolvers or third-party APIs. It's about as
low-impact as an active technique gets (a single packet, standard network
hygiene - every router and monitoring tool does this). Runs by default;
opt out with `--no-ping` (cli.py) / `include_ping=False` (registry.py).

Assumes Linux iputils `ping` (the `-W <seconds>` per-packet timeout flag);
this project is Linux-first, so no cross-platform ping abstraction.
"""

from __future__ import annotations

import re
import shutil
import subprocess

from posint_scanner import proxy
from posint_scanner.models import EnrichmentResult
from posint_scanner.sources.base import Source, SourceUnavailableError

BINARY = "ping"
TIMEOUT_SECONDS = 3
RTT_RE = re.compile(r"time[=<]([\d.]+)\s*ms")


def parse_ping_output(returncode: int, stdout: str) -> dict:
    alive = returncode == 0
    rtt_ms = None
    if alive:
        match = RTT_RE.search(stdout)
        if match:
            rtt_ms = float(match.group(1))
    return {"alive": alive, "rtt_ms": rtt_ms}


class PingSource(Source):
    name = "ping"
    category = "active"

    def enrich(self, target: str, hostnames: list[str]) -> EnrichmentResult:
        if reason := proxy.unavailable_reason("ping (ICMP)"):
            raise SourceUnavailableError(reason)
        binary_path = shutil.which(BINARY)
        if binary_path is None:
            raise SourceUnavailableError(f"{BINARY} not found on PATH")

        result = subprocess.run(
            [binary_path, "-c", "1", "-W", str(TIMEOUT_SECONDS), target],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS + 2,
            check=False,
        )
        data = parse_ping_output(result.returncode, result.stdout)
        return EnrichmentResult(source="ping", target_type="ip", target=target, data=data)
