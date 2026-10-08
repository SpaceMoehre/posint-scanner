"""Active vulnerability scanning via Nuclei (https://github.com/projectdiscovery/nuclei).

Nuclei probes a URL against its template library (thousands of community
templates for known CVEs, misconfigurations and exposures) and reports what
matched. Unlike the rest of the pipeline this is *active and intrusive* - it
sends crafted requests to the target - so it's opt-in (`--nuclei`, off by
default) and, like every active source, only for hosts you're authorized to
test.

This wraps the `nuclei` binary: gracefully absent when it isn't on PATH.
Templates come from Nuclei's own template directory; populate it with the
community set via `cent` (see the Dockerfile / README) or point at a specific
directory with `templates_dir`.

Findings feed the same reporting path as the NVD lookup - each carries its
severity and any CVE ids - so a template-confirmed vuln (e.g. the GeoServer
RCE) shows up alongside the version-inferred CVEs.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from posint_scanner import proxy

logger = logging.getLogger(__name__)

# Nuclei can take a while against a big template set; generous ceiling since
# it's an explicit, opt-in stage the operator chose to run.
NUCLEI_TIMEOUT_SECONDS = 1800

SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")


def parse_nuclei_line(line: str) -> dict | None:
    """One finding from a line of `nuclei -jsonl` output, or None for a blank,
    non-JSON, or template-id-less line."""
    line = line.strip()
    if not line:
        return None
    try:
        data = json.loads(line)
    except ValueError:
        return None
    template_id = data.get("template-id")
    if not template_id:
        return None
    info = data.get("info") or {}
    classification = info.get("classification") or {}
    cves = classification.get("cve-id") or []
    if isinstance(cves, str):
        cves = [cves]
    return {
        "template_id": template_id,
        "name": info.get("name"),
        "severity": (info.get("severity") or "unknown").lower(),
        "matched_at": data.get("matched-at") or data.get("host"),
        "type": data.get("type"),
        "cves": list(cves),
        "cvss_score": classification.get("cvss-score"),
        "tags": info.get("tags") or [],
        "reference": info.get("reference") or [],
    }


class NucleiScanner:
    """One shared instance per scan (like NvdClient / SearchSploitClient). It
    holds only read-only config; each scan() call runs the binary once against
    a batch of URLs, so there's no shared mutable state to lock."""

    def __init__(self, templates_dir: str | None = None, extra_args: list[str] | None = None) -> None:
        self._binary = shutil.which("nuclei")
        self.templates_dir = templates_dir
        self.extra_args = list(extra_args or [])
        self._warned = False

    @property
    def available(self) -> bool:
        return self._binary is not None

    def scan(self, urls: list[str]) -> list[dict]:
        """Run Nuclei against `urls` and return parsed findings, or [] (never
        raises). No-op when the binary is missing or there are no targets."""
        targets = [u for u in dict.fromkeys(urls) if u]  # dedupe, keep order
        if not targets:
            return []
        if self._binary is None:
            if not self._warned:
                self._warned = True
                logger.warning("nuclei not on PATH - skipping active template scan")
            return []
        return self._run(targets)

    def _run(self, targets: list[str]) -> list[dict]:
        assert self._binary is not None  # guarded by scan()
        with tempfile.TemporaryDirectory(prefix="posint-nuclei-") as tmp:
            targets_file = Path(tmp) / "targets.txt"
            targets_file.write_text("\n".join(targets))
            cmd = [
                self._binary,
                "-list", str(targets_file),
                "-jsonl",
                "-silent",
                "-no-color",
                "-disable-update-check",  # never self-update mid-scan
            ]
            if self.templates_dir:
                cmd += ["-t", self.templates_dir]
            if proxy_url := proxy.tool_proxy_url():
                cmd += ["-proxy", proxy_url]
            cmd += self.extra_args
            try:
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=NUCLEI_TIMEOUT_SECONDS,
                )
            except (subprocess.SubprocessError, OSError) as exc:
                logger.warning("nuclei run failed: %s", exc)
                return []
        findings = []
        for line in proc.stdout.splitlines():
            parsed = parse_nuclei_line(line)
            if parsed is not None:
                findings.append(parsed)
        return findings
