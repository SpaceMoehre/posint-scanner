"""One markdown file with what matters most: every source's findings on one
severity scale, most severe first.

The web UI spreads findings over the overview, domain and IP pages; this
report pulls them into a single document to hand on or read offline:
CVEs, SMBv1, Nuclei/Nikto/WPScan hits, container and LeakIX exposures,
subdomain takeovers, cloud/IaC findings, leaked secrets, email-auth
posture, SNMP and HTTP-header findings, plus CDN origin leaks.

Critical and high findings are written out in full, medium ones as a
table, low/info only counted. The same finding on several hosts (one CVE
on five IPs, a missing header everywhere) is one entry listing where it
was seen. Secrets are masked - the domain page shows them in full.
"""

from __future__ import annotations

from collections.abc import Collection
from datetime import datetime, timezone

from posint_scanner.cloudscan import SEVERITIES, severity_rank
from posint_scanner.db import Database
from posint_scanner.export.overview import _collect, severity_of
from posint_scanner.readmodel import domain_findings, ip_findings, queries
from posint_scanner.readmodel.views import IP_FINDING_SOURCES, hosts_with_vulns
from posint_scanner.readmodel.queries import Scope

# Locations listed per merged finding before "+N more".
MAX_WHERE = 8


def _severity(value: object) -> str:
    text = str(value or "unknown").lower()
    return text if text in SEVERITIES else "unknown"


def _mask(secret: str | None) -> str:
    if not secret:
        return "-"
    return secret[:4] + "…" if len(secret) > 8 else "…"


def _finding(severity: object, category: str, title: str, where: str,
             detail: object = "", reference: str | None = None) -> dict:
    return {
        "severity": _severity(severity),
        "category": category,
        "title": " ".join(str(title or "-").split()),
        "where": where,
        "detail": " ".join(str(detail or "").split()),
        "reference": reference,
    }


def _ip_findings(host: dict) -> list[dict]:
    ip = ip_findings(host["results"])
    address = host["address"]
    names = host["hostnames"]
    label = address + (f" ({', '.join(names[:3])}{', …' if len(names) > 3 else ''})" if names else "")
    out = []
    _, _, criticals = _collect([host])
    for c in criticals:
        if not c["kind"].startswith("CVE-"):  # SMBv1; CVEs come from ip["vulns"]
            out.append(_finding("critical", "Exposure", c["kind"], label, c["detail"]))
    for v in ip["vulns"]:
        component = v.get("technology") or v.get("cpe") or "?"
        out.append(_finding(
            severity_of(v), "Known CVE", v["cve_id"], f"{label} port {v.get('port')}",
            f"{component}, CVSS {v.get('cvss_score') or '?'}: {v.get('summary') or ''}",
            f"https://nvd.nist.gov/vuln/detail/{v['cve_id']}",
        ))
    for f in ip["nuclei"]:
        out.append(_finding(f.get("severity"), "Nuclei", f.get("name") or f.get("template_id"),
                            f.get("matched_at") or label,
                            ", ".join(f.get("cves") or []) or f.get("template_id")))
    for f in ip["web_findings"]:
        out.append(_finding(f.get("severity"), f.get("tool") or "Web scan", f.get("title"),
                            f"{label} {f.get('resource') or ''}".strip(), f.get("id"),
                            f.get("reference")))
    for e in ip["container_exposures"]:
        out.append(_finding(e.get("severity"), "Container exposure", e.get("kind"),
                            f"{label} port {e.get('port')}", e.get("detail")))
    for f in ip["leakix_findings"]:
        out.append(_finding(f.get("severity"), "LeakIX", f.get("title"), label, f.get("detail")))
    for f in ip["header_findings"]:
        out.append(_finding(f.get("severity"), "HTTP headers", f.get("title"),
                            f.get("url") or label, f.get("detail")))
    for s in ip["snmp"]:
        for f in s["analysis"].get("findings") or []:
            out.append(_finding(f.get("severity"), "SNMP", f.get("detail"),
                                f"{label} udp/161 ({s['source']})"))
    return out


def _domain_findings(name: str, d: dict, secrets: list) -> list[dict]:
    out = []
    for f in d["takeovers"]:
        out.append(_finding(f.get("severity"), "Subdomain takeover",
                            f"Dangling CNAME to {f.get('id') or 'a claimable service'}",
                            f.get("resource") or name, f.get("location")))
    for f in d["cloud_findings"]:
        out.append(_finding(f.get("severity"), f.get("tool") or "Cloud", f.get("title"),
                            f.get("target") or f.get("resource") or name,
                            f"{f.get('id') or ''} {f.get('resource') or ''}", f.get("reference")))
    for f in d["leakix_findings"]:
        out.append(_finding(f.get("severity"), "LeakIX", f.get("title"), name, f.get("detail")))
    for f in (d["email_auth"] or {}).get("findings") or []:
        out.append(_finding(f.get("severity"), "Email auth", f.get("title"), name, f.get("detail")))
    for e in secrets:
        out.append(_finding(
            "high", "Leaked secret", f"{e['rule'] or 'Secret'} in public code",
            f"{e['repo']}/{e['path']}" + (f":{e['line']}" if e["line"] else ""),
            f"value {_mask(e['secret'])} (names {e['target']})", e["url"],
        ))
    origin = d["origin"] or {}
    if origin.get("behind_cdn"):
        for c in origin.get("origin_candidates") or []:
            out.append(_finding(
                "medium", "CDN origin leak", f"Possible origin IP behind {origin.get('cdn')}",
                c["ip"], f"leaked via {', '.join(c.get('via') or [])} - may bypass the WAF",
            ))
    return out


def _merge(findings: list[dict]) -> list[dict]:
    """One entry per (severity, category, title), listing every place seen."""
    merged: dict[tuple, dict] = {}
    for f in findings:
        key = (f["severity"], f["category"], f["title"])
        if key not in merged:
            merged[key] = {**f, "wheres": []}
        if f["where"] not in merged[key]["wheres"]:
            merged[key]["wheres"].append(f["where"])
    return sorted(
        merged.values(),
        key=lambda f: (severity_rank(f["severity"]), -len(f["wheres"]), f["category"], f["title"]),
    )


def collect_findings(db: Database, domains: Collection[str] | None = None) -> dict:
    """Findings (merged), sensitive-service exposures and scope counts for
    `domains` (None: everything, IPs no domain claims included)."""
    ids = queries.domain_ids(db, domains)
    scope = Scope() if domains is None else Scope.domains(ids.values())
    hosts = hosts_with_vulns(db, scope, IP_FINDING_SOURCES)
    results = queries.domain_results(db, ids.values())
    takeovers = queries.hostname_results_by_domain(db, ids.values(), ["takeover"])
    secrets = queries.secret_exposures(db, ids.values())
    findings = []
    for name, domain_id in ids.items():
        d = domain_findings(results.get(domain_id, []), takeovers.get(domain_id, []))
        findings += _domain_findings(name, d, secrets.get(domain_id, []))
    for host in hosts:
        findings += _ip_findings(host)
    exposures, _, _ = _collect(hosts)
    return {
        "domains": list(ids),
        "all_domains": domains is None,
        "ip_count": len(hosts),
        "hostname_count": len({n for h in hosts for n in h["hostnames"]}),
        "findings": _merge(findings),
        "exposures": exposures,
    }


def _cell(text: object) -> str:
    return str(text if text not in (None, "") else "-").replace("|", "\\|").replace("\n", " ")


def _wheres(wheres: list[str]) -> str:
    shown = ", ".join(f"`{w}`" for w in wheres[:MAX_WHERE])
    return shown + (f" +{len(wheres) - MAX_WHERE} more" if len(wheres) > MAX_WHERE else "")


def render_report(db: Database, domains: Collection[str] | None = None,
                  now: datetime | None = None) -> str:
    data = collect_findings(db, domains)
    findings = data["findings"]
    by_severity = {s: [f for f in findings if f["severity"] == s] for s in SEVERITIES}
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M UTC")
    scope = "all domains" if data["all_domains"] else ", ".join(data["domains"]) or "nothing"

    lines = [
        "# Security findings report",
        "",
        f"Generated {stamp} by posint-scanner · scope: {scope} · "
        f"{data['hostname_count']} hostnames, {data['ip_count']} IPs",
        "",
        "Findings from every scan stage on one severity scale, most severe "
        "first. The same finding on several hosts is listed once, with "
        "everywhere it was seen. Version-inferred CVEs and passive index data "
        "(Shodan, LeakIX) need confirming before acting.",
        "",
        "## Summary",
        "",
        "| Severity | Findings | Places |",
        "|----------|----------|--------|",
    ]
    for severity in SEVERITIES:
        group = by_severity[severity]
        if group or severity in ("critical", "high", "medium"):
            places = sum(len(f["wheres"]) for f in group)
            lines.append(f"| {severity.capitalize()} | {len(group)} | {places} |")
    lines += [
        f"| Sensitive services exposed | {len(data['exposures'])} | "
        f"{len({e['address'] for e in data['exposures']})} IPs |",
        "",
    ]

    for severity in ("critical", "high"):
        group = by_severity[severity]
        lines += [f"## {severity.capitalize()} ({len(group)})", ""]
        if not group:
            lines += ["None found.", ""]
        for i, f in enumerate(group, 1):
            lines += [f"### {i}. {f['title']}", "", f"- **Category:** {f['category']}",
                      f"- **Where:** {_wheres(f['wheres'])}"]
            if f["detail"]:
                lines.append(f"- **Detail:** {f['detail']}")
            if f["reference"]:
                lines.append(f"- **Reference:** <{f['reference']}>")
            lines.append("")

    group = by_severity["medium"]
    lines += [f"## Medium ({len(group)})", ""]
    if group:
        lines += ["| Category | Finding | Where | Detail |", "|---|---|---|---|"]
        lines += [f"| {_cell(f['category'])} | {_cell(f['title'])} | {_cell(_wheres(f['wheres']))} "
                  f"| {_cell(f['detail'])} |" for f in group]
    else:
        lines.append("None found.")
    lines.append("")

    lines += ["## Exposed sensitive services", ""]
    if data["exposures"]:
        lines += ["| IP | Hostname(s) | Port | Service | Why it matters |", "|---|---|---|---|---|"]
        for e in data["exposures"]:
            names = ", ".join(e["hostnames"][:3]) + (" …" if len(e["hostnames"]) > 3 else "")
            lines.append(f"| {e['address']} | {_cell(names)} | {e['port']}/{e['protocol']} "
                         f"| {_cell(e['service'])} | {_cell(e['reason'])} |")
    else:
        lines.append("None found.")
    lines.append("")

    rest = [(s, len(by_severity[s])) for s in ("low", "info", "unknown") if by_severity[s]]
    if rest:
        counts = ", ".join(f"{n} {s}" for s, n in rest)
        lines += ["## Not listed", "",
                  f"{counts} finding(s) - see the web UI or the zip export for every detail.", ""]
    return "\n".join(lines)


__all__ = ["collect_findings", "render_report"]
