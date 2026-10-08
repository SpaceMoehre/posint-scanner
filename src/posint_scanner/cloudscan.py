"""Cloud / container / IaC scanning via Trivy, Checkov, Prowler and ScoutSuite.

These four tools extend the pipeline past passive OSINT into detailed cloud
posture assessment. Each is a separate binary this module wraps thinly (like
nuclei.py / exploitdb.py): gracefully absent when not on PATH, parses its JSON
output into one normalized finding shape, and never raises out of a scan.

Two very different trust levels, kept apart deliberately:

  * **Artifact scanning** (Trivy, Checkov) is credential-free and doesn't
    touch the target's infrastructure - it inspects *artifacts* the passive
    stages already surfaced: public GitHub repos (Checkov for IaC misconfig,
    `trivy fs` for vulnerable deps/secrets/misconfig) and public container
    images (`trivy image`). Off by default only because it needs the binaries
    and clones third-party repos.

  * **Cloud account auditing** (Prowler, ScoutSuite) needs *credentials for
    the target's own cloud account* (AWS/Azure/GCP/K8s). It reads those from
    the ambient environment the way the vendor CLIs do (AWS_PROFILE,
    AWS_ACCESS_KEY_ID, `~/.aws`, `gcloud`/`az` logins, KUBECONFIG, ...) - this
    module never handles secrets itself. Strictly opt-in and only for accounts
    you are authorized to audit.

A finding is a plain dict (persisted as a generic result row, like nuclei's):

    {
        "tool": "trivy" | "checkov" | "prowler" | "scoutsuite",
        "kind": "vulnerability" | "misconfig" | "secret",
        "severity": "critical" | "high" | "medium" | "low" | "info" | "unknown",
        "id": "<CVE / check id / rule id>",
        "title": "<human-readable>",
        "resource": "<package, file, or cloud resource the finding is on>",
        "target": "<what was scanned: image ref, repo, cloud provider>",
        "cves": ["CVE-..."],          # trivy vuln findings
        "reference": "<url>" | None,
        "location": "<file:line / region>" | None,
    }
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterable
from pathlib import Path

from posint_scanner import proxy

logger = logging.getLogger(__name__)

# Cloud/IaC scans can be slow (a big image, a whole account); generous ceilings
# since each is an explicit, opt-in stage the operator chose to run.
TRIVY_TIMEOUT_SECONDS = 900
CHECKOV_TIMEOUT_SECONDS = 900
PROWLER_TIMEOUT_SECONDS = 3600
SCOUTSUITE_TIMEOUT_SECONDS = 3600
CLONE_TIMEOUT_SECONDS = 180

SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
_SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}


def severity_rank(severity: str | None) -> int:
    """Sort key: lower is more severe (critical=0). Unknown severities sort
    last, alongside the explicit "unknown" bucket."""
    return _SEVERITY_RANK.get((severity or "unknown").lower(), len(SEVERITIES))


def _norm_severity(value: object) -> str:
    """Map any tool's severity spelling onto our shared scale. ScoutSuite's
    danger/warning and assorted casings all funnel through here."""
    text = str(value or "").strip().lower()
    mapping = {
        "danger": "high",
        "warning": "medium",
        "informational": "info",
        "negligible": "low",
        "": "unknown",
        "none": "unknown",
    }
    text = mapping.get(text, text)
    return text if text in SEVERITIES else "unknown"


def count_by_severity(findings: Iterable[dict]) -> dict[str, int]:
    counts = {name: 0 for name in SEVERITIES}
    for finding in findings:
        counts[_norm_severity(finding.get("severity"))] += 1
    return {name: n for name, n in counts.items() if n}


def _first(data: dict, *keys: str) -> object:
    """First present, non-None value among `keys` (tools disagree on casing
    and naming between and across their own versions)."""
    for key in keys:
        if key in data and data[key] is not None:
            return data[key]
    return None


# ---------------------------------------------------------------------------
# Parsers - pure functions over each tool's stdout, unit-tested against
# captured fixtures so a schema change is caught without the binary present.
# ---------------------------------------------------------------------------

_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)


def parse_trivy(stdout: str, target: str) -> list[dict]:
    """Findings from `trivy ... -f json`: vulnerabilities, misconfigurations
    and secrets across every result block."""
    try:
        data = json.loads(stdout)
    except ValueError:
        return []
    findings: list[dict] = []
    for block in data.get("Results") or []:
        where = block.get("Target") or target
        for vuln in block.get("Vulnerabilities") or []:
            vid = vuln.get("VulnerabilityID") or ""
            pkg = " ".join(
                p for p in (vuln.get("PkgName"), vuln.get("InstalledVersion")) if p
            )
            fixed = vuln.get("FixedVersion")
            findings.append(
                {
                    "tool": "trivy",
                    "kind": "vulnerability",
                    "severity": _norm_severity(vuln.get("Severity")),
                    "id": vid,
                    "title": vuln.get("Title") or (vuln.get("Description") or "")[:200] or vid,
                    "resource": pkg or where,
                    "target": target,
                    "cves": [vid] if _CVE_RE.match(vid) else [],
                    "reference": vuln.get("PrimaryURL"),
                    "location": f"fixed in {fixed}" if fixed else None,
                }
            )
        for misc in block.get("Misconfigurations") or []:
            findings.append(
                {
                    "tool": "trivy",
                    "kind": "misconfig",
                    "severity": _norm_severity(misc.get("Severity")),
                    "id": misc.get("ID") or misc.get("AVDID") or "",
                    "title": misc.get("Title") or misc.get("Message") or "",
                    "resource": where,
                    "target": target,
                    "cves": [],
                    "reference": misc.get("PrimaryURL"),
                    "location": (misc.get("CauseMetadata") or {}).get("Resource"),
                }
            )
        for secret in block.get("Secrets") or []:
            findings.append(
                {
                    "tool": "trivy",
                    "kind": "secret",
                    "severity": _norm_severity(secret.get("Severity")),
                    "id": secret.get("RuleID") or "",
                    "title": secret.get("Title") or "exposed secret",
                    "resource": where,
                    "target": target,
                    "cves": [],
                    "reference": None,
                    "location": f"line {secret.get('StartLine')}" if secret.get("StartLine") else None,
                }
            )
    return findings


def parse_checkov(stdout: str, target: str) -> list[dict]:
    """Failed checks from `checkov -o json`. Checkov emits a single object for
    one framework or a list of them for several; both are handled."""
    try:
        data = json.loads(stdout)
    except ValueError:
        return []
    documents = data if isinstance(data, list) else [data]
    findings: list[dict] = []
    for document in documents:
        if not isinstance(document, dict):
            continue
        results = document.get("results") or {}
        for check in results.get("failed_checks") or []:
            line_range = check.get("file_line_range") or []
            line = line_range[0] if line_range else None
            path = check.get("file_path") or ""
            findings.append(
                {
                    "tool": "checkov",
                    "kind": "misconfig",
                    "severity": _norm_severity(check.get("severity")),
                    "id": check.get("check_id") or "",
                    "title": check.get("check_name") or "",
                    "resource": check.get("resource") or path,
                    "target": target,
                    "cves": [],
                    "reference": check.get("guideline"),
                    "location": f"{path}:{line}" if path and line else (path or None),
                }
            )
    return findings


def parse_prowler(stdout: str, provider: str) -> list[dict]:
    """Failing findings from Prowler JSON. Handles both the v3 native JSON
    (list of PascalCase records) and the v4+ OCSF JSON (list of records with
    `status_code`/`finding_info`), pulling fields defensively since the shape
    differs between and within major versions."""
    try:
        data = json.loads(stdout)
    except ValueError:
        return []
    items = data if isinstance(data, list) else (data.get("findings") or [])
    findings: list[dict] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        status = str(_first(item, "status_code", "Status", "status") or "").upper()
        # Only surface failures; PASS/MANUAL/INFO checks aren't findings.
        if status and status not in ("FAIL", "FAILED", "ALARM"):
            continue
        raw_info = item.get("finding_info")
        info: dict = raw_info if isinstance(raw_info, dict) else {}
        resources = item.get("resources") or []
        resource = ""
        if resources and isinstance(resources[0], dict):
            resource = str(_first(resources[0], "uid", "name") or "")
        resource = resource or str(_first(item, "ResourceId", "ResourceArn", "resource_uid") or "")
        check_id = str(_first(item, "CheckID", "check_id") or info.get("uid") or "")
        title = str(
            _first(item, "CheckTitle", "check_title") or info.get("title") or item.get("message") or ""
        )
        findings.append(
            {
                "tool": "prowler",
                "kind": "misconfig",
                "severity": _norm_severity(_first(item, "severity", "Severity")),
                "id": check_id,
                "title": title,
                "resource": resource or provider,
                "target": provider,
                "cves": [],
                "reference": str(_first(item, "remediation_url", "Remediation") or "") or None,
                "location": str(_first(item, "region", "Region", "location") or "") or None,
            }
        )
    return findings


def parse_scoutsuite(js_text: str, provider: str) -> list[dict]:
    """Flagged findings from a ScoutSuite results file. ScoutSuite writes a
    JavaScript assignment (`scoutsuite_results = {...}`), not plain JSON, so we
    slice out the object literal and load that. Only services with
    flagged_items > 0 become findings; ScoutSuite's `danger`/`warning` levels
    map onto our high/medium via _norm_severity."""
    start = js_text.find("{")
    end = js_text.rfind("}")
    if start == -1 or end == -1 or end < start:
        return []
    try:
        data = json.loads(js_text[start : end + 1])
    except ValueError:
        return []
    findings: list[dict] = []
    for service_name, service in (data.get("services") or {}).items():
        if not isinstance(service, dict):
            continue
        for finding_id, finding in (service.get("findings") or {}).items():
            if not isinstance(finding, dict):
                continue
            flagged = finding.get("flagged_items") or 0
            if not flagged:
                continue
            findings.append(
                {
                    "tool": "scoutsuite",
                    "kind": "misconfig",
                    "severity": _norm_severity(finding.get("level")),
                    "id": finding_id,
                    "title": finding.get("description") or finding_id,
                    "resource": f"{service_name} ({flagged} affected)",
                    "target": provider,
                    "cves": [],
                    "reference": finding.get("rationale"),
                    "location": service_name,
                }
            )
    return findings


# ---------------------------------------------------------------------------
# Binary wrappers - one shared instance per scan, holding only read-only config
# (like NucleiScanner). Every run returns findings or [] and never raises.
# ---------------------------------------------------------------------------


class _BinaryTool:
    """Shared plumbing: locate the binary once, warn once when it's missing."""

    binary_name: str = ""

    def __init__(self, extra_args: list[str] | None = None) -> None:
        self._binary = shutil.which(self.binary_name)
        self.extra_args = list(extra_args or [])
        self._warned = False

    @property
    def available(self) -> bool:
        return self._binary is not None

    def _missing(self) -> bool:
        if self._binary is None:
            if not self._warned:
                self._warned = True
                logger.warning("%s not on PATH - skipping its scan stage", self.binary_name)
            return True
        return False

    def _proxy_blocked(self) -> bool:
        """For tools that can't be tunnelled: whether a proxy is set, so the
        stage must be skipped (warned once)."""
        reason = proxy.unavailable_reason(self.binary_name)
        if reason and not self._warned:
            self._warned = True
            logger.warning(reason)
        return reason is not None

    def _run(self, args: list[str], timeout: int) -> subprocess.CompletedProcess | None:
        """Run the binary with `args` (the binary itself is prepended). Callers
        guard with `_missing()` first, so the binary is known present here."""
        assert self._binary is not None
        try:
            return subprocess.run(
                [self._binary, *args], capture_output=True, text=True, timeout=timeout
            )
        except (subprocess.SubprocessError, OSError) as exc:
            logger.warning("%s run failed: %s", self.binary_name, exc)
            return None


class TrivyScanner(_BinaryTool):
    """`trivy image <ref>` and `trivy fs <path>` - vulnerable dependencies,
    misconfigurations and secrets in a container image or a filesystem tree."""

    binary_name = "trivy"

    def _scan(self, mode: str, target: str) -> list[dict]:
        if self._missing():
            return []
        args = [
            mode,
            "--quiet",
            "--format", "json",
            "--scanners", "vuln,misconfig,secret",
            *self.extra_args,
            target,
        ]
        proc = self._run(args, TRIVY_TIMEOUT_SECONDS)
        if proc is None or not proc.stdout:
            return []
        return parse_trivy(proc.stdout, target)

    def scan_image(self, ref: str) -> list[dict]:
        return self._scan("image", ref)

    def scan_fs(self, path: str) -> list[dict]:
        return self._scan("fs", path)


class CheckovScanner(_BinaryTool):
    """`checkov -d <dir> -o json` - infrastructure-as-code misconfigurations
    (Terraform, CloudFormation, Kubernetes manifests, Dockerfiles, ...)."""

    binary_name = "checkov"

    def scan_dir(self, path: str) -> list[dict]:
        if self._missing():
            return []
        args = [
            "-d", path,
            "-o", "json",
            "--compact",
            "--quiet",
            *self.extra_args,
        ]
        proc = self._run(args, CHECKOV_TIMEOUT_SECONDS)
        # checkov exits non-zero when it finds failures - that's expected, so
        # we parse stdout regardless of return code.
        if proc is None or not proc.stdout:
            return []
        return parse_checkov(proc.stdout, path)


class ProwlerScanner(_BinaryTool):
    """`prowler <provider>` - hundreds of cloud-security checks against an
    account you have credentials for. Reads credentials from the ambient
    environment (this class never touches secrets). OCSF JSON output."""

    binary_name = "prowler"

    def scan(self, provider: str) -> list[dict]:
        if self._missing():
            return []
        with tempfile.TemporaryDirectory(prefix="posint-prowler-") as tmp:
            args = [
                provider,
                "-M", "json-ocsf",
                "--output-directory", tmp,
                "--output-filename", "prowler",
                *self.extra_args,
            ]
            proc = self._run(args, PROWLER_TIMEOUT_SECONDS)
            if proc is None:
                return []
            # Prefer the JSON file (stdout is a progress bar); fall back to
            # stdout for a version that streams JSON there.
            for candidate in sorted(Path(tmp).glob("*.json")):
                try:
                    text = candidate.read_text()
                except OSError:
                    continue
                findings = parse_prowler(text, provider)
                if findings:
                    return findings
            return parse_prowler(proc.stdout, provider)


class ScoutSuiteScanner(_BinaryTool):
    """`scout <provider>` - multi-cloud configuration auditing. Reads ambient
    credentials like Prowler; findings come from its results JS file."""

    binary_name = "scout"

    def scan(self, provider: str) -> list[dict]:
        if self._missing():
            return []
        with tempfile.TemporaryDirectory(prefix="posint-scoutsuite-") as tmp:
            args = [
                provider,
                "--report-dir", tmp,
                "--no-browser",
                "--force",
                *self.extra_args,
            ]
            proc = self._run(args, SCOUTSUITE_TIMEOUT_SECONDS)
            if proc is None:
                return []
            for candidate in Path(tmp).rglob("scoutsuite_results_*.js"):
                try:
                    return parse_scoutsuite(candidate.read_text(), provider)
                except OSError:
                    continue
            return []


def clone_repo(url: str, dest: str, timeout: int = CLONE_TIMEOUT_SECONDS) -> bool:
    """Shallow-clone `url` into `dest` for filesystem scanning. Returns whether
    it succeeded; a no-op False when `git` isn't installed. Never raises."""
    git = shutil.which("git")
    if git is None:
        logger.warning("git not on PATH - cannot clone %s for scanning", url)
        return False
    cmd = [git, "clone", "--depth", "1", "--quiet", url, dest]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.SubprocessError, OSError) as exc:
        logger.warning("git clone of %s failed: %s", url, exc)
        return False
    if proc.returncode != 0:
        logger.warning("git clone of %s failed: %s", url, proc.stderr.strip()[:200])
        return False
    return True
