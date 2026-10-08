"""Secret detection over a file's text: a built-in regex ruleset, plus
gitleaks' (https://github.com/gitleaks/gitleaks) much larger one when the
binary is on PATH, and optionally trufflehog
(https://github.com/trufflesecurity/trufflehog) as a third engine.

Found secrets are only reported, never tried - no rule and no tool here
verifies a credential against its service. trufflehog is always run with
`--no-verification` for exactly this reason: verification would mean logging
in with someone's leaked key, which this tool must never do.
"""

from __future__ import annotations

import json
import logging
import math
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

GITLEAKS_TIMEOUT_SECONDS = 60
TRUFFLEHOG_TIMEOUT_SECONDS = 120


@dataclass(frozen=True)
class SecretMatch:
    rule: str
    value: str
    line: int  # 1-based


@dataclass(frozen=True)
class _Rule:
    name: str
    pattern: re.Pattern[str]
    # Generic "password = ..." style rules match plenty of placeholders and
    # code; they only count with an entropy floor and no placeholder look.
    generic: bool = False


def _rule(name: str, pattern: str, generic: bool = False) -> _Rule:
    return _Rule(name, re.compile(pattern), generic)


# The capture group (if any) is the secret value, else the whole match.
RULES: tuple[_Rule, ...] = (
    _rule("aws_access_key_id", r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
    _rule(
        "aws_secret_access_key",
        r"(?i)aws.{0,20}?(?:secret|private).{0,20}?[\"'=:\s]+([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
    ),
    _rule("github_token", r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b"),
    _rule("github_fine_grained_pat", r"\b(github_pat_[A-Za-z0-9_]{80,255})\b"),
    _rule("gitlab_token", r"\b(glpat-[A-Za-z0-9_-]{20,})\b"),
    _rule("slack_token", r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"),
    _rule("slack_webhook", r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)"),
    _rule("stripe_secret_key", r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,})\b"),
    _rule("google_api_key", r"\b(AIza[0-9A-Za-z_-]{35})(?![0-9A-Za-z_-])"),
    _rule("sendgrid_api_key", r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})(?![A-Za-z0-9_-])"),
    _rule("npm_token", r"\b(npm_[A-Za-z0-9]{36})\b"),
    _rule("openai_api_key", r"\b(sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]*T3BlbkFJ[A-Za-z0-9_-]+)"),
    _rule("anthropic_api_key", r"\b(sk-ant-[A-Za-z0-9_-]{20,})"),
    _rule(
        "azure_storage_connection_string",
        r"(DefaultEndpointsProtocol=https?;AccountName=[^;\s]+;AccountKey=[A-Za-z0-9+/=]{80,})",
    ),
    _rule(
        "private_key",
        r"(-----BEGIN (?:[A-Z]+ )?PRIVATE KEY(?: BLOCK)?-----"
        r"(?:[\s\S]{0,8000}?-----END (?:[A-Z]+ )?PRIVATE KEY(?: BLOCK)?-----)?)",
    ),
    _rule("jwt", r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"),
    _rule(
        "credentials_in_url",
        r"\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver"
        r"|ftp|sftp|ldaps?|smtp)://[^\s:/@'\"]+:[^\s@/'\"]+@[^\s'\"<>]+)",
    ),
    _rule(
        "generic_secret",
        r"(?i)(?<![a-z0-9])(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token"
        r"|client[_-]?secret|private[_-]?key)\b[\"']?\s*[:=]>?\s*[\"']?([^\s\"',;<>]{8,})",
        generic=True,
    ),
)

_PLACEHOLDER_RE = re.compile(
    r"(?i)^[$%{<(]|\$\{|\{\{|x{4,}|\*{3,}|changeme|example|placeholder|your[_-]|redacted|dummy"
    r"|^(?:true|false|null|none|undefined)$|^[a-z_]+\(|\.get\(|process\.env|os\.environ|getenv"
)
_GENERIC_MIN_ENTROPY = 3.0


def _entropy(value: str) -> float:
    counts = {c: value.count(c) for c in set(value)}
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def _plausible(rule: _Rule, value: str) -> bool:
    if not rule.generic:
        return True
    return not _PLACEHOLDER_RE.search(value) and _entropy(value) >= _GENERIC_MIN_ENTROPY


def _builtin(text: str) -> list[SecretMatch]:
    found = []
    for rule in RULES:
        for match in rule.pattern.finditer(text):
            value = match.group(1) if rule.pattern.groups else match.group(0)
            if _plausible(rule, value):
                line = text.count("\n", 0, match.start(1 if rule.pattern.groups else 0)) + 1
                found.append(SecretMatch(rule.name, value, line))
    return found


_gitleaks_missing_warned = False


def _gitleaks(text: str) -> list[SecretMatch]:
    global _gitleaks_missing_warned
    binary = shutil.which("gitleaks")
    if binary is None:
        if not _gitleaks_missing_warned:
            _gitleaks_missing_warned = True
            logger.warning("gitleaks not on PATH - secret scanning uses the built-in rules only")
        return []
    with tempfile.TemporaryDirectory(prefix="posint-gitleaks-") as tmp:
        source = Path(tmp) / "content"
        report = Path(tmp) / "report.json"
        try:
            # errors="surrogatepass" so text carrying lone surrogates (or a
            # non-UTF-8 locale) can't raise UnicodeEncodeError and abort the
            # whole scan; the write is inside the try either way.
            source.write_text(text, encoding="utf-8", errors="surrogatepass")
            subprocess.run(
                [binary, "detect", "--no-git", "--no-banner", "--source", str(source),
                 "--report-format", "json", "--report-path", str(report), "--exit-code", "0"],
                capture_output=True, timeout=GITLEAKS_TIMEOUT_SECONDS, check=True,
            )
            findings = json.loads(report.read_text() or "[]")
        except (subprocess.SubprocessError, OSError, ValueError) as exc:
            logger.warning("gitleaks failed: %s", exc)
            return []
    return [
        SecretMatch(f"gitleaks:{f.get('RuleID', 'unknown')}", f["Secret"], int(f.get("StartLine") or 0))
        for f in findings
        if f.get("Secret")
    ]


_trufflehog_missing_warned = False


def _trufflehog(text: str) -> list[SecretMatch]:
    global _trufflehog_missing_warned
    binary = shutil.which("trufflehog")
    if binary is None:
        if not _trufflehog_missing_warned:
            _trufflehog_missing_warned = True
            logger.warning("trufflehog not on PATH - skipping it")
        return []
    with tempfile.TemporaryDirectory(prefix="posint-trufflehog-") as tmp:
        source = Path(tmp) / "content"
        try:
            # write inside the try (with surrogatepass) so odd encodings can't
            # crash the scan; --no-verification is mandatory - this tool
            # reports leaked secrets, it never authenticates with them.
            source.write_text(text, encoding="utf-8", errors="surrogatepass")
            proc = subprocess.run(
                [binary, "filesystem", str(source), "--json", "--no-verification"],
                capture_output=True, text=True, timeout=TRUFFLEHOG_TIMEOUT_SECONDS,
            )
        except (subprocess.SubprocessError, OSError, ValueError) as exc:
            logger.warning("trufflehog failed: %s", exc)
            return []
    found = []
    for raw_line in proc.stdout.splitlines():
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            finding = json.loads(raw_line)
        except ValueError:
            continue  # trufflehog prints non-JSON log lines too
        # Some detectors populate only RawV2 (structured/multi-part creds),
        # leaving Raw empty - fall back so those aren't silently dropped.
        secret = finding.get("Raw") or finding.get("RawV2")
        if not secret:
            continue
        fs = (finding.get("SourceMetadata") or {}).get("Data", {}).get("Filesystem", {})
        found.append(SecretMatch(
            f"trufflehog:{finding.get('DetectorName', 'unknown')}",
            secret,
            int(fs.get("line") or 0),
        ))
    return found


def find_secrets(
    text: str, use_gitleaks: bool = True, use_trufflehog: bool = False
) -> list[SecretMatch]:
    """Secrets in `text`: every built-in finding, then any gitleaks and (when
    enabled) trufflehog finding whose value an earlier engine didn't already
    report. Deduping by value (not value+line) is deliberate - the engines
    number lines differently, so keying on the line would let the same secret
    through more than once. trufflehog is off by default (extra dependency,
    slower); enable it in the GitHub source's config."""
    unique = _builtin(text)
    # Dedup on the stripped value: the engines capture the same credential
    # with differing surrounding whitespace/delimiters, so an exact-string
    # key would let the same secret through more than once.
    seen_values = {match.value.strip() for match in unique}

    external = []
    if use_gitleaks:
        external += _gitleaks(text)
    if use_trufflehog:
        external += _trufflehog(text)
    for match in external:
        key = match.value.strip()
        if key in seen_values:
            continue
        seen_values.add(key)
        unique.append(match)
    return unique
