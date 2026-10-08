"""Active web-application & subdomain-takeover scanning via Nikto, WPScan and
takeover.

Three more binaries the pipeline wraps thinly (like nuclei.py / cloudscan.py):
gracefully absent when not on PATH, each parses its own output into the shared
finding shape, and never raises out of a scan. All three are **active and
intrusive** - they send crafted requests to the target - so every stage is
opt-in (off by default) and only for hosts you're authorized to test.

  * **Nikto** (https://github.com/sullo/nikto) - a web-server scanner: probes a
    URL for thousands of known dangerous files, outdated components, and unsafe
    configuration. Runs against every resolved web service found.

  * **WPScan** (https://github.com/wpscanteam/wpscan) - a WordPress scanner:
    enumerates the core/plugin/theme versions and the vulnerabilities filed
    against them. A no-op on a non-WordPress URL (it aborts fast). An optional
    API token (`wpscan.api_token`) unlocks the vulnerability database.

  * **takeover** (https://github.com/edoardottt/takeover) - subdomain-takeover
    detection: checks each discovered hostname's CNAME against the
    `can-i-take-over-xyz` fingerprints for a dangling, claimable service. This
    is the subdomain-takeover capability Sn1per would otherwise provide.

Findings reuse the cloudscan shape (a plain dict persisted as a generic result
row, like nuclei's), with a couple of web-specific keys:

    {
        "tool": "nikto" | "wpscan" | "takeover",
        "kind": "web" | "vulnerability" | "misconfig" | "info" | "takeover",
        "severity": "critical" | "high" | "medium" | "low" | "info" | "unknown",
        "id": "<test id / CVE / wpvulndb id / service>",
        "title": "<human-readable>",
        "resource": "<what the finding is on: component, path, service>",
        "url": "<the URL / host scanned>",
        "target": "<same as url; kept for parity with cloud findings>",
        "cves": ["CVE-..."],
        "reference": "<url>" | None,
        "location": "<method + path / region>" | None,
    }

Nikto and WPScan don't emit a severity of their own, so we assign a sensible
default per finding kind (raised to `medium` when a finding carries a CVE).
"""

from __future__ import annotations

import json
import logging
import re
import tempfile
from pathlib import Path

# Reuse cloudscan's shared plumbing: the binary locator/runner base, the
# severity scale and its normaliser. These three tools are the same "thin
# wrapper around an opt-in binary" as the cloud scanners.
from posint_scanner import proxy
from posint_scanner.cloudscan import _BinaryTool

logger = logging.getLogger(__name__)

# Web-app scans hit one host at a time and can be slow (Nikto especially walks a
# large plugin database); per-target ceilings keep one unresponsive host from
# stalling the whole stage. takeover fans out over many hosts in one run.
NIKTO_TIMEOUT_SECONDS = 900
WPSCAN_TIMEOUT_SECONDS = 900
TAKEOVER_TIMEOUT_SECONDS = 900

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def _cves_in(*values: object) -> list[str]:
    """Every CVE id mentioned in the given strings/lists, uppercased & deduped."""
    found: list[str] = []
    for value in values:
        items = value if isinstance(value, (list, tuple)) else [value]
        for item in items:
            for match in _CVE_RE.findall(str(item or "")):
                cve = match.upper()
                if cve not in found:
                    found.append(cve)
    return found


# ---------------------------------------------------------------------------
# Parsers - pure functions over each tool's output, unit-tested against
# captured fixtures so a schema change is caught without the binary present.
# ---------------------------------------------------------------------------


def parse_nikto(stdout: str, target: str) -> list[dict]:
    """Findings from `nikto -Format json`. Nikto emits either a single host
    object or a list of them, each with a `vulnerabilities` array; both are
    handled. Nikto has no severity field, so each item defaults to `low`
    (raised to `medium` when the message names a CVE)."""
    try:
        data = json.loads(stdout)
    except ValueError:
        return []
    hosts = data if isinstance(data, list) else [data]
    findings: list[dict] = []
    for host in hosts:
        if not isinstance(host, dict):
            continue
        for vuln in host.get("vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            path = str(vuln.get("url") or "")
            method = str(vuln.get("method") or "GET")
            msg = str(vuln.get("msg") or "").strip()
            references = vuln.get("references") or vuln.get("reference")
            cves = _cves_in(msg, references)
            findings.append(
                {
                    "tool": "nikto",
                    "kind": "web",
                    "severity": "medium" if cves else "low",
                    "id": str(vuln.get("id") or ""),
                    "title": msg or "nikto finding",
                    "resource": path or "/",
                    "url": target,
                    "target": target,
                    "cves": cves,
                    "reference": references if isinstance(references, str) else None,
                    "location": f"{method} {path}".strip() if path else None,
                }
            )
    return findings


def _wpscan_vulnerabilities(entries: object, resource: str, target: str) -> list[dict]:
    """Normalise a WPScan `vulnerabilities` array (attached to core, a plugin,
    or a theme) into findings. WPScan vulns are CVE-backed, so `high`."""
    findings: list[dict] = []
    for vuln in entries or []:
        if not isinstance(vuln, dict):
            continue
        references = vuln.get("references") if isinstance(vuln.get("references"), dict) else {}
        # WPScan lists CVEs as bare numbers ("2021-1234"); qualify any that
        # aren't already prefixed before extracting.
        raw_cves = references.get("cve") or []
        cves = _cves_in([c if str(c).upper().startswith("CVE-") else f"CVE-{c}" for c in raw_cves])
        urls = references.get("url")
        wpvulndb = references.get("wpvulndb")
        finding_id = (cves[0] if cves else None) or (
            (wpvulndb or [None])[0] if isinstance(wpvulndb, list) else None
        )
        fixed = vuln.get("fixed_in")
        findings.append(
            {
                "tool": "wpscan",
                "kind": "vulnerability",
                "severity": "high",
                "id": str(finding_id or vuln.get("title") or ""),
                "title": str(vuln.get("title") or "WordPress vulnerability"),
                "resource": resource,
                "url": target,
                "target": target,
                "cves": cves,
                "reference": (urls[0] if isinstance(urls, list) and urls else None),
                "location": f"fixed in {fixed}" if fixed else None,
            }
        )
    return findings


def parse_wpscan(stdout: str, target: str) -> list[dict]:
    """Findings from `wpscan --format json`: vulnerabilities filed against the
    detected core version, plugins and themes, plus the interesting findings it
    surfaces (as `info`). Returns [] for a non-WordPress target (WPScan reports
    `scan_aborted`) or unparseable output."""
    try:
        data = json.loads(stdout)
    except ValueError:
        return []
    if not isinstance(data, dict) or data.get("scan_aborted"):
        return []
    findings: list[dict] = []

    version = data.get("version")
    if isinstance(version, dict):
        label = f"WordPress core {version.get('number') or ''}".strip()
        findings += _wpscan_vulnerabilities(version.get("vulnerabilities"), label, target)

    for section, prefix in (("plugins", "plugin"), ("themes", "theme")):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, component in block.items():
            if not isinstance(component, dict):
                continue
            ver = component.get("version")
            ver_num = ver.get("number") if isinstance(ver, dict) else None
            label = f"{prefix} {name}" + (f" {ver_num}" if ver_num else "")
            findings += _wpscan_vulnerabilities(component.get("vulnerabilities"), label, target)

    main_theme = data.get("main_theme")
    if isinstance(main_theme, dict):
        findings += _wpscan_vulnerabilities(
            main_theme.get("vulnerabilities"),
            f"theme {main_theme.get('slug') or 'main'}",
            target,
        )

    for item in data.get("interesting_findings") or []:
        if not isinstance(item, dict):
            continue
        findings.append(
            {
                "tool": "wpscan",
                "kind": "info",
                "severity": "info",
                "id": str(item.get("type") or ""),
                "title": str(item.get("to_s") or item.get("type") or "interesting finding"),
                "resource": str(item.get("url") or target),
                "url": target,
                "target": target,
                "cves": [],
                "reference": None,
                "location": None,
            }
        )
    return findings


def parse_takeover(report: str) -> list[dict]:
    """Findings from takeover's `-o <file>.json` report:
    `{"domains": {"<host>": {"service": ..., "error": ...}}}`, one entry per
    host it judges claimable (`error` is the provider's "no such site"
    fingerprint it matched). Subdomain takeover is high-impact, so `high`."""
    try:
        domains = (json.loads(report) or {}).get("domains") or {}
    except (ValueError, AttributeError):
        return []
    findings: list[dict] = []
    for host, info in domains.items():
        host = str(host).strip()
        if not host:
            continue
        service = str((info or {}).get("service") or "unknown")
        findings.append(
            {
                "tool": "takeover",
                "kind": "takeover",
                "severity": "high",
                "id": service,
                "title": f"Potential subdomain takeover ({service})",
                "resource": host,
                "url": host,
                "target": host,
                "cves": [],
                "reference": None,
                "location": None,
            }
        )
    return findings


# ---------------------------------------------------------------------------
# Binary wrappers - one shared instance per scan (like the cloudscan tools),
# holding only read-only config. Every run returns findings or [] and never
# raises.
# ---------------------------------------------------------------------------


class NiktoScanner(_BinaryTool):
    """`nikto -h <url> -Format json` - one web service at a time. Findings for
    a batch of URLs are aggregated across per-URL runs so one slow or hostile
    host never aborts the rest."""

    binary_name = "nikto"

    def scan(self, urls: list[str]) -> list[dict]:
        # Nikto only speaks HTTP proxies, not SOCKS.
        if self._missing() or self._proxy_blocked():
            return []
        findings: list[dict] = []
        for url in dict.fromkeys(u for u in urls if u):  # dedupe, keep order
            findings += self._scan_one(url)
        return findings

    def _scan_one(self, url: str) -> list[dict]:
        # Nikto writes JSON to a file (stdout carries its progress chatter), so
        # point -output at a temp file and read it back.
        with tempfile.TemporaryDirectory(prefix="posint-nikto-") as tmp:
            out = Path(tmp) / "nikto.json"
            args = [
                "-h", url,
                "-Format", "json",
                "-output", str(out),
                "-nointeractive",
                "-ask", "no",
                *self.extra_args,
            ]
            proc = self._run(args, NIKTO_TIMEOUT_SECONDS)
            if proc is None:
                return []
            try:
                text = out.read_text()
            except OSError:
                text = proc.stdout  # some builds honour `-output -`/stream to stdout
            return parse_nikto(text, url)


class WpscanScanner(_BinaryTool):
    """`wpscan --url <url> --format json` - one URL at a time; a fast no-op on a
    non-WordPress site. An optional API token unlocks the vulnerability data."""

    binary_name = "wpscan"

    def __init__(self, api_token: str | None = None, extra_args: list[str] | None = None) -> None:
        super().__init__(extra_args)
        self.api_token = api_token or None

    def scan(self, urls: list[str]) -> list[dict]:
        if self._missing():
            return []
        findings: list[dict] = []
        for url in dict.fromkeys(u for u in urls if u):
            findings += self._scan_one(url)
        return findings

    def _scan_one(self, url: str) -> list[dict]:
        args = [
            "--url", url,
            "--format", "json",
            "--no-banner",
            "--no-update",
            # Don't let a missing-token warning or a WAF block turn into a
            # non-zero-only run with nothing on stdout.
            "--disable-tls-checks",
        ]
        if self.api_token:
            args += ["--api-token", self.api_token]
        if settings := proxy.active():
            args += ["--proxy", settings.url()]  # libcurl: socks5h = remote DNS
        args += self.extra_args
        proc = self._run(args, WPSCAN_TIMEOUT_SECONDS)
        # wpscan exits non-zero when it finds vulnerabilities - expected, so we
        # parse stdout regardless of return code.
        if proc is None or not proc.stdout:
            return []
        return parse_wpscan(proc.stdout, url)


class TakeoverScanner(_BinaryTool):
    """`takeover -l <file> -o <report>.json` - all discovered hostnames in one
    run. Reports only hosts it judges claimable."""

    binary_name = "takeover"

    def scan(self, hosts: list[str]) -> list[dict]:
        # takeover resolves CNAMEs with local DNS - that can't be tunnelled.
        if self._missing() or self._proxy_blocked():
            return []
        targets = [h for h in dict.fromkeys(hosts) if h]  # dedupe, keep order
        if not targets:
            return []
        with tempfile.TemporaryDirectory(prefix="posint-takeover-") as tmp:
            list_file = Path(tmp) / "hosts.txt"
            list_file.write_text("\n".join(targets))
            report = Path(tmp) / "report.json"
            args = ["-l", str(list_file), "-o", str(report), *self.extra_args]
            proc = self._run(args, TAKEOVER_TIMEOUT_SECONDS)
            if proc is None or not report.exists():
                return []
            return parse_takeover(report.read_text())
