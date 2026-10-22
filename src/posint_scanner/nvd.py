"""CVE lookup via the NVD (NIST) public API - free, no API key required
(though providing one, via config, raises the rate limit substantially).

Given a service's CPE (or a best-effort guess built from product+version),
look up matching CVEs. Purely passive: queries NIST's public database,
never touches the target. Depends on service data already populated by an
enrichment source (Shodan, Censys, or the port scanner), so it runs as its
own orchestrator stage after enrichment rather than as a registry Source -
same reasoning as the netblock sweep's ASN lookup.

NVD's rate limit is strict and documented: 5 requests per rolling 30s
window without an API key, 50/30s with one, and it signals rate-limiting
via HTTP 403 rather than 429. Rather than reactively retrying after a
rejection, this client proactively paces requests to stay under the limit -
firing a burst of lookups against a 5-per-30s budget would just waste the
whole budget on 403s.
"""

from __future__ import annotations

import re
import threading
import time

import requests

from posint_scanner.retry import VERIFY_TLS

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TIMEOUT_SECONDS = 30
UNAUTHENTICATED_MIN_INTERVAL_SECONDS = 6.5
AUTHENTICATED_MIN_INTERVAL_SECONDS = 0.7
MAX_CVES_PER_LOOKUP = 20
# NVD doesn't only signal rate-limiting via 403 - it sometimes returns
# HTTP 200 with resultsPerPage: 0 and an empty `vulnerabilities` array
# despite a nonzero totalResults (observed directly: a request that legitimately
# returned 81 results moments earlier degraded to this shape under load).
# Treating that as "0 CVEs found" would be a false negative, so it gets one
# retry after a longer cooldown before giving up.
THROTTLE_RETRY_COOLDOWN_SECONDS = 15


class NvdUnavailableError(Exception):
    """NVD gave no usable answer (rate-limited, or throttled even after the
    retry) - unlike an empty result, this says nothing about the CPE."""


def cpe_version(cpe: str) -> str | None:
    """The concrete version component of a CPE, or None if it has none - i.e.
    the version field is absent, a wildcard (`*`) or N/A (`-`). Handles both
    the 2.3 formatted-string form (version is the 6th `:`-field) and the older
    2.2 URI form (`cpe:/a:vendor:product:version`). A versionless CPE matched
    against NVD returns every CVE ever filed for the product regardless of the
    running version, so the caller must not look one up."""
    parts = cpe.split(":")
    if cpe.startswith("cpe:2.3:"):
        version = parts[5] if len(parts) > 5 else ""
    elif cpe.startswith("cpe:/"):
        version = parts[4] if len(parts) > 4 else ""
    else:
        return None
    version = version.strip()
    return version if version and version not in ("*", "-") else None


_BOUNDS = (
    ("versionStartIncluding", ">="),
    ("versionStartExcluding", ">"),
    ("versionEndIncluding", "<="),
    ("versionEndExcluding", "<"),
)


def _version_key(version: str) -> tuple:
    """Sort key for a version string: numeric runs compare as numbers, so
    7.10 > 7.9; a trailing letter run (7.1.0-beta1) sorts before the release."""
    key = [
        (1, int(token)) if token.isdigit() else (0, token)
        for token in re.findall(r"\d+|[a-z]+", version.lower())
    ]
    return (*key, (0.5,))


def _in_range(version: str, match: dict) -> bool:
    """Whether `version` satisfies every bound a cpeMatch entry states."""
    key = _version_key(version)
    for field, op in _BOUNDS:
        bound = match.get(field)
        if not bound:
            continue
        other = _version_key(bound)
        if not {">=": key >= other, ">": key > other, "<=": key <= other, "<": key < other}[op]:
            return False
    return True


def affected_versions(cve: dict, cpe: str) -> str | None:
    """How the CVE says the CPE's version is affected - the matching
    vulnerable entry's version or range, e.g. "<= 6.9.4" or ">= 6.9.0, < 6.9.5"
    - or None when it doesn't state one that covers the version.

    A `cpeName` lookup also returns CVEs that name the product only with a
    wildcard version and no range ("every version" - typically the product
    listed as the platform another component runs on, e.g. WordPress for a
    plugin CVE) or only as a non-vulnerable platform. Those say nothing about
    the version actually running, so the caller drops them."""
    parts = cpe.lower().split(":")
    version = cpe_version(cpe)
    if not cpe.startswith("cpe:2.3:") or version is None:
        return None
    product = parts[2:5]  # part, vendor, product
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            if node.get("negate"):
                continue
            for match in node.get("cpeMatch", []):
                criteria = str(match.get("criteria", "")).lower().split(":")
                if not match.get("vulnerable") or criteria[2:5] != product:
                    continue
                criteria_version = criteria[5] if len(criteria) > 5 else "*"
                if criteria_version not in ("*", "-"):
                    if criteria_version == version.lower():
                        return f"= {criteria_version}"
                    continue
                bounds = [f"{op} {match[field]}" for field, op in _BOUNDS if match.get(field)]
                if criteria_version == "*" and bounds and _in_range(version, match):
                    return ", ".join(bounds)
    return None


def build_cpe(product: str, version: str) -> str:
    """Best-effort CPE 2.3 string, guessing vendor == product - works for a
    lot of well-known open-source software (nginx, openssh, apache) but not
    universally. Only used when a source didn't already give us a real CPE
    (e.g. Shodan's cpe23 field)."""
    slug = product.strip().lower().replace(" ", "_")
    return f"cpe:2.3:a:{slug}:{slug}:{version}:*:*:*:*:*:*:*"


def _extract_cvss(metrics: dict) -> tuple[float | None, str | None]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            return cvss_data.get("baseScore"), cvss_data.get("baseSeverity")
    return None, None


def _extract_summary(cve: dict) -> str | None:
    for description in cve.get("descriptions", []):
        if description.get("lang") == "en":
            return str(description.get("value"))
    return None


class NvdClient:
    """Paced NVD API client - construct one per scan run and reuse it (one
    shared instance across every concurrently-running domain, not one per
    domain) so the rate limit is respected globally, not just within a
    single caller. NVD enforces its limit against this machine's IP
    regardless of how many client objects exist in our process, so
    concurrent domains sharing one un-synchronized client would each think
    they're pacing correctly while together blowing through the real
    external limit.

    A plain Lock (not RLock) is enough here since lookup_cves doesn't call
    any other locked method - the whole lookup (pacing + request + retry)
    is one atomic unit against other threads, which is also correct
    behavior: the rate limit is global, so concurrent lookups from
    different domains must be fully serialized against each other, not
    just individually paced."""

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key
        self._last_request_at: float | None = None
        self._lock = threading.Lock()

    def _wait_for_rate_limit(self) -> None:
        min_interval = (
            AUTHENTICATED_MIN_INTERVAL_SECONDS if self.api_key else UNAUTHENTICATED_MIN_INTERVAL_SECONDS
        )
        if self._last_request_at is not None:
            elapsed = time.monotonic() - self._last_request_at
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
        self._last_request_at = time.monotonic()

    def lookup_cves(self, cpe: str) -> list[dict]:
        """CVEs that state the CPE's version as affected (see
        affected_versions). Raises NvdUnavailableError when NVD didn't
        answer, so a caller can keep what an earlier lookup stored."""
        with self._lock:
            data = self._request(cpe)
            if data is None:
                raise NvdUnavailableError(f"NVD rate-limited the lookup of {cpe}")

            if self._looks_throttled(data):
                # One retry after a longer cooldown before treating it as
                # "0 CVEs found", which would otherwise be a false negative.
                time.sleep(THROTTLE_RETRY_COOLDOWN_SECONDS)
                data = self._request(cpe)
                if data is None or self._looks_throttled(data):
                    raise NvdUnavailableError(f"NVD throttled the lookup of {cpe}")

            return self._parse_vulnerabilities(data, cpe)

    @staticmethod
    def _looks_throttled(data: dict) -> bool:
        return bool(data.get("totalResults")) and not data.get("vulnerabilities")

    def _request(self, cpe: str) -> dict | None:
        self._wait_for_rate_limit()
        headers = {"apiKey": self.api_key} if self.api_key else {}
        response = requests.get(
            NVD_URL, params={"cpeName": cpe}, headers=headers,
            timeout=TIMEOUT_SECONDS, verify=VERIFY_TLS,
        )
        if response.status_code == 403:
            # Rate-limited despite pacing (e.g. another process is also
            # hitting NVD) - "no data available", not "no CVEs".
            return None
        response.raise_for_status()
        return dict(response.json())

    @staticmethod
    def _parse_vulnerabilities(data: dict, cpe: str) -> list[dict]:
        cves = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            affected = affected_versions(cve, cpe)
            if affected is None:
                continue
            score, severity = _extract_cvss(cve.get("metrics", {}))
            cves.append(
                {
                    "cve_id": cve.get("id"),
                    "summary": _extract_summary(cve),
                    "cvss_score": score,
                    "cvss_severity": severity,
                    "affected": affected,
                }
            )
        cves.sort(key=lambda c: c["cvss_score"] or 0, reverse=True)
        return cves[:MAX_CVES_PER_LOOKUP]
