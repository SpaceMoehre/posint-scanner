"""Security overview note for the Obsidian export.

A single top-level `_Overview.md` (the underscore sorts it to the top of the
vault's file list) that triages the whole scan into what a reviewer actually
wants first: which hosts expose services that generally shouldn't face the
public internet, and which run software with known CVEs. It's a lens over the
per-host/IP notes the rest of the export already writes, not a new data
source - every row links back to the IP note it summarizes.

"Should not be exposed" is a judgement call, so SENSITIVE_PORTS below is
deliberately conservative: remote-access, file-sharing, database and
management services that are near-always meant to sit behind a VPN or
firewall, not the specific web ports (80/443) that are supposed to be public.
It's a heuristic surfacing candidates for review, not an assertion that a
given port is definitely misconfigured.
"""

from __future__ import annotations

# port -> (short service name, why it's sensitive). Kept narrow on purpose -
# see the module docstring. Web ports are intentionally absent.
SENSITIVE_PORTS: dict[int, tuple[str, str]] = {
    21: ("FTP", "cleartext file transfer"),
    23: ("Telnet", "cleartext remote shell"),
    135: ("MS RPC", "endpoint mapper - Windows lateral movement"),
    137: ("NetBIOS", "name service"),
    138: ("NetBIOS", "datagram service"),
    139: ("NetBIOS", "session service / SMB over NetBIOS"),
    445: ("SMB", "file sharing - ransomware/lateral-movement target"),
    1433: ("MSSQL", "database"),
    1521: ("Oracle DB", "database"),
    2049: ("NFS", "network file share"),
    2375: ("Docker API", "unauthenticated container control"),
    3306: ("MySQL", "database"),
    3389: ("RDP", "remote desktop"),
    5432: ("PostgreSQL", "database"),
    5900: ("VNC", "remote desktop"),
    5984: ("CouchDB", "database"),
    6379: ("Redis", "database, often unauthenticated"),
    9200: ("Elasticsearch", "database/search, often unauthenticated"),
    9300: ("Elasticsearch", "cluster transport"),
    11211: ("Memcached", "cache, often unauthenticated / DDoS reflector"),
    27017: ("MongoDB", "database"),
}

# CVSS base-score cutoffs, used to derive a severity when NVD gives a score
# but no textual severity (CVSS v2 records often have no baseSeverity).
_CRITICAL_MIN = 9.0
_HIGH_MIN = 7.0
_MEDIUM_MIN = 4.0

_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "UNKNOWN": 0}


def severity_of(cve: dict) -> str:
    """Normalize a CVE's severity to one of CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN,
    falling back to the CVSS base score when NVD supplied no textual
    severity (common for v2-only records)."""
    label = (cve.get("cvss_severity") or "").upper()
    if label in _SEVERITY_RANK and label != "NONE":
        return label
    score = cve.get("cvss_score")
    if score is None:
        return "UNKNOWN"
    if score >= _CRITICAL_MIN:
        return "CRITICAL"
    if score >= _HIGH_MIN:
        return "HIGH"
    if score >= _MEDIUM_MIN:
        return "MEDIUM"
    return "LOW"


def _smbv1(banner: str | None) -> bool:
    """SMBv1 is independently a critical finding (EternalBlue-class), beyond
    SMB merely being exposed - the shodan_web/portscan SMB banner spells the
    dialect out as 'SMB Version: 1'."""
    return bool(banner) and "smb version: 1" in banner.lower()


def _ip_link(address: str) -> str:
    # IP notes live in IPs/ but Obsidian wikilinks resolve by basename, so the
    # bare address is enough and matches how the IP notes are named.
    return f"[[{address}]]"


def _hostnames_cell(hostnames: list[str]) -> str:
    if not hostnames:
        return "-"
    shown = ", ".join(f"[[{h}]]" for h in hostnames[:3])
    if len(hostnames) > 3:
        shown += f" +{len(hostnames) - 3} more"
    return shown


def _collect(hosts: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
    """Split every host into (exposed sensitive services, vuln rows, critical
    findings). A `host` is {address, hostnames, domains?, services, vulns} where each
    service is {port, protocol, banner, version} and each vuln is
    {port, technology, cpe, cve_id, cvss_score, cvss_severity, summary}."""
    exposures: list[dict] = []
    vuln_rows: list[dict] = []
    criticals: list[dict] = []

    for host in hosts:
        address = host["address"]
        hostnames = host.get("hostnames", [])
        domains = host.get("domains", [])

        for service in host.get("services", []):
            port = service["port"]
            sensitive = SENSITIVE_PORTS.get(port)
            if sensitive is None:
                continue
            name, reason = sensitive
            smbv1 = _smbv1(service.get("banner"))
            exposures.append(
                {
                    "address": address,
                    "hostnames": hostnames,
                    "domains": domains,
                    "port": port,
                    "protocol": service.get("protocol", "tcp"),
                    "service": name + (" (SMBv1)" if smbv1 else ""),
                    "banner": service.get("banner"),
                    "version": service.get("version"),
                    "reason": reason,
                }
            )
            if smbv1:
                criticals.append(
                    {
                        "kind": "SMBv1 enabled",
                        "address": address,
                        "hostnames": hostnames,
                        "domains": domains,
                        "detail": f"port {port} - {name}, SMB dialect 1 "
                        "(EternalBlue-class exposure)",
                        "rank": 11.0,  # above any CVSS score (max 10.0)
                    }
                )

        # group this host's CVEs by (port, technology/cpe) for the vuln table
        by_component: dict[tuple, list[dict]] = {}
        for vuln in host.get("vulns", []):
            key = (vuln.get("port"), vuln.get("technology") or vuln.get("cpe"))
            by_component.setdefault(key, []).append(vuln)

        for (port, component), cves in by_component.items():
            severities = [severity_of(cve) for cve in cves]
            worst = max(severities, key=lambda s: _SEVERITY_RANK[s])
            max_score = max((cve.get("cvss_score") or 0.0) for cve in cves)
            vuln_rows.append(
                {
                    "address": address,
                    "hostnames": hostnames,
                    "domains": domains,
                    "port": port,
                    "component": component or "-",
                    "cve_count": len(cves),
                    "max_score": max_score,
                    "worst": worst,
                }
            )
            for cve, sev in zip(cves, severities):
                if sev == "CRITICAL":
                    criticals.append(
                        {
                            "kind": cve["cve_id"],
                            "address": address,
                            "hostnames": hostnames,
                            "domains": domains,
                            "detail": f"port {port} {component or ''} "
                            f"(CVSS {cve.get('cvss_score')}) - "
                            f"{(cve.get('summary') or '').strip()[:160]}",
                            "rank": cve.get("cvss_score") or 0.0,
                        }
                    )

    exposures.sort(key=lambda e: (e["address"], e["port"]))
    vuln_rows.sort(key=lambda v: (-v["max_score"], v["address"], v["port"] or 0))
    criticals.sort(key=lambda c: (-c["rank"], c["address"]))
    return exposures, vuln_rows, criticals


def render_overview_note(hosts: list[dict]) -> str:
    """Render `_Overview.md` from the per-host findings (see _collect for the
    `hosts` shape). Always returns a valid note, even when nothing risky was
    found - an explicit "nothing found" reads better than an empty file."""
    exposures, vuln_rows, criticals = _collect(hosts)

    hosts_with_exposure = {e["address"] for e in exposures}
    hosts_with_vulns = {v["address"] for v in vuln_rows}

    lines = [
        "---",
        "tags:",
        "  - overview",
        "  - security",
        "---",
        "# Security Overview",
        "",
        "Triage of the scan: hosts exposing services that generally should "
        "not be public, and hosts running software with known CVEs. Each row "
        "links to the full IP note.",
        "",
        "## Summary",
        "",
        "| metric | count |",
        "|--------|-------|",
        f"| Hosts (IPs) scanned | {len({h['address'] for h in hosts})} |",
        f"| Hosts exposing sensitive services | {len(hosts_with_exposure)} |",
        f"| Sensitive service exposures | {len(exposures)} |",
        f"| Hosts with known vulnerabilities | {len(hosts_with_vulns)} |",
        f"| Critical findings | {len(criticals)} |",
        "",
    ]

    lines += ["## Critical findings", ""]
    if criticals:
        lines.append("Most severe first (SMBv1 exposure and CVSS-critical CVEs).")
        lines.append("")
        for finding in criticals:
            names = _hostnames_cell(finding["hostnames"])
            lines.append(
                f"- **{finding['kind']}** — {_ip_link(finding['address'])} "
                f"({names}): {finding['detail']}"
            )
    else:
        lines.append("None. No SMBv1 exposure and no CVSS-critical CVEs found.")
    lines.append("")

    lines += ["## Exposed sensitive services", ""]
    if exposures:
        lines += [
            "| IP | Hostname(s) | Port | Service | Why it matters |",
            "|----|-------------|------|---------|----------------|",
        ]
        for e in exposures:
            lines.append(
                f"| {_ip_link(e['address'])} | {_hostnames_cell(e['hostnames'])} "
                f"| {e['port']}/{e['protocol']} | {e['service']} | {e['reason']} |"
            )
    else:
        lines.append("None found.")
    lines.append("")

    lines += ["## Hosts with known vulnerabilities", ""]
    if vuln_rows:
        lines += [
            "| IP | Hostname(s) | Port | Component | CVEs | Max CVSS | Worst |",
            "|----|-------------|------|-----------|------|----------|-------|",
        ]
        for v in vuln_rows:
            score = f"{v['max_score']:.1f}" if v["max_score"] else "-"
            port = f"{v['port']}" if v["port"] is not None else "-"
            lines.append(
                f"| {_ip_link(v['address'])} | {_hostnames_cell(v['hostnames'])} "
                f"| {port} | {v['component']} | {v['cve_count']} | {score} | {v['worst']} |"
            )
    else:
        lines.append("None found.")
    lines.append("")

    return "\n".join(lines) + "\n"


__all__ = ["render_overview_note", "severity_of", "SENSITIVE_PORTS"]
