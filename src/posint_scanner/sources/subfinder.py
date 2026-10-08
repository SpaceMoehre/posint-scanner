"""Discovery source wrapping the `subfinder` CLI (https://github.com/projectdiscovery/subfinder)."""

from __future__ import annotations

import shutil
import subprocess

from posint_scanner import proxy
from posint_scanner.models import DiscoveredHostname
from posint_scanner.sources.base import Source, SourceUnavailableError

BINARY = "subfinder"
TIMEOUT_SECONDS = 120


def parse_subfinder_output(raw: str) -> list[DiscoveredHostname]:
    hostnames = []
    for line in raw.splitlines():
        name = line.strip().lower()
        if not name:
            continue
        hostnames.append(DiscoveredHostname(name=name, source="subfinder"))
    return hostnames


class SubfinderSource(Source):
    name = "subfinder"

    def discover(self, domain: str) -> list[DiscoveredHostname]:
        binary_path = shutil.which(BINARY)
        if binary_path is None:
            raise SourceUnavailableError(
                f"{BINARY} not found on PATH - install from "
                "https://github.com/projectdiscovery/subfinder"
            )
        cmd = [binary_path, "-d", domain, "-silent"]
        if proxy_url := proxy.tool_proxy_url():
            cmd += ["-proxy", proxy_url]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
            check=False,
        )
        return parse_subfinder_output(result.stdout)
