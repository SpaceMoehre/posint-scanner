"""Read-side helpers: turn the scan DB into the structures the templates render.

Kept separate from the FastAPI routes so it's testable without HTTP, and so
the security triage stays defined in exactly one place - these reuse the
Obsidian export's overview logic (`_collect`, `severity_of`) rather than
re-deriving "what counts as a finding" for the browser.
"""

from __future__ import annotations

import json

from posint_scanner.cloudscan import severity_rank
from posint_scanner.db import Database
from posint_scanner.export.obsidian_export import _flatten_nvd_vulns
from posint_scanner.export.overview import (
    _SEVERITY_RANK,
    SENSITIVE_PORTS,
    _collect,
    severity_of,
)
from posint_scanner import snmp
from posint_scanner.scope import tld_family
from posint_scanner.sources.portscan import TLS_PORTS

# Ports assumed to serve a browsable web app when nothing better says so.
_WEB_PORTS = {80, 81, 443, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9443}
_HTTPS_PORTS = TLS_PORTS | {9443}


# Nuclei severities, most severe first, for sorting its findings table.
_NUCLEI_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

# Tools whose results are cloud/container/IaC findings (see cloudscan.py).
_CLOUD_TOOLS = ("trivy", "checkov", "prowler", "scoutsuite")
# Web scanners whose IP results share the webscan finding shape.
_WEB_TOOLS = ("nikto", "wpscan", "php2shell")


def cloud_findings(results: list[dict]) -> list[dict]:
    """Flatten the cloud/IaC scan results (each holds a `findings` list per
    scanned target) into one severity-sorted list of finding rows for the
    domain page's table."""
    rows = []
    for result in results:
        if result["source"] not in _CLOUD_TOOLS:
            continue
        data = result["data"]
        for finding in data.get("findings") or []:
            rows.append({**finding, "target": finding.get("target") or data.get("target")})
    rows.sort(key=lambda f: (severity_rank(f.get("severity")), f.get("tool", ""), f.get("id", "")))
    return rows


def web_findings(results: list[dict]) -> list[dict]:
    """Nikto/WPScan findings on one IP (each result is already one finding),
    severity-sorted for the IP page's table."""
    rows = [result["data"] for result in results if result["source"] in _WEB_TOOLS]
    rows.sort(key=lambda f: (severity_rank(f.get("severity")), f.get("tool", ""), f.get("id", "")))
    return rows


def _results_for(db: Database, target_type: str, target_id: int) -> list[dict]:
    return [
        {
            "source": row["source"],
            "data": json.loads(row["data"]),
            "fetched_at": row["fetched_at"],
        }
        for row in db.list_results_for_target(target_type, target_id)
    ]


def web_url(address: str, service: dict, webtech_urls: dict[int, str]) -> str | None:
    """A URL to open `service` in a browser, or None if it isn't a web
    service. Prefers the URL the fingerprint stage actually reached, then an
    HTTP response in the banner (the port scan sends a GET), then the port."""
    port = service["port"]
    if service.get("protocol", "tcp") != "tcp":
        return None
    if port in webtech_urls:
        return webtech_urls[port]
    banner = (service.get("banner") or "").lstrip()
    if not banner.startswith("HTTP/") and port not in _WEB_PORTS:
        return None
    scheme = "https" if port in _HTTPS_PORTS else "http"
    host = f"[{address}]" if ":" in address else address
    default = 443 if scheme == "https" else 80
    return f"{scheme}://{host}/" if port == default else f"{scheme}://{host}:{port}/"


def _overview_hosts(db: Database) -> list[dict]:
    domain_names = {row["id"]: row["name"] for row in db.list_domains()}
    hosts = []
    for ip_row in db.list_all_ips():
        results = _results_for(db, "ip", ip_row["id"])
        hostname_rows = db.list_hostnames_for_ip(ip_row["id"])
        hosts.append(
            {
                "address": ip_row["address"],
                "hostnames": [r["name"] for r in hostname_rows],
                # An IP belongs to every apex domain one of its hostnames sits
                # under; IPs with no hostname (e.g. netblock-sweep hits) get none.
                "domains": sorted({domain_names[r["domain_id"]] for r in hostname_rows}),
                "services": [dict(s) for s in db.list_services_for_ip(ip_row["id"])],
                "vulns": _flatten_nvd_vulns([(r["source"], r["data"]) for r in results]),
            }
        )
    return hosts


def build_overview(db: Database, domain: str | None = None) -> dict:
    """Summary counts + the three finding lists (exposures, vuln rows,
    criticals), exactly as the `_Overview.md` note is built. `domain`
    narrows everything to IPs attributed to that apex domain."""
    all_hosts = _overview_hosts(db)
    hosts = [h for h in all_hosts if domain in h["domains"]] if domain else all_hosts
    exposures, vuln_rows, criticals = _collect(hosts)
    return {
        "cves": _cve_rows(hosts),
        "domains": [row["name"] for row in db.list_domains()],
        "selected_domain": domain,
        "unattributed_ips": sum(1 for h in all_hosts if not h["domains"]),
        "total_ips": len(hosts),
        "hosts_with_exposure": len({e["address"] for e in exposures}),
        "exposures": exposures,
        "vuln_rows": vuln_rows,
        "hosts_with_vulns": len({v["address"] for v in vuln_rows}),
        "criticals": criticals,
    }


def _cve_rows(hosts: list[dict]) -> list[dict]:
    """One row per (IP, CVE) - the unaggregated view behind the grouped
    vuln table, for sorting/filtering by individual CVE."""
    rows = [
        {
            "domains": host["domains"],
            "address": host["address"],
            "hostnames": host["hostnames"],
            "port": vuln.get("port"),
            "component": vuln.get("technology") or vuln.get("cpe") or "-",
            "cve_id": vuln["cve_id"],
            "cvss_score": vuln.get("cvss_score"),
            "severity": severity_of(vuln),
            "summary": (vuln.get("summary") or "").strip(),
        }
        for host in hosts
        for vuln in host["vulns"]
    ]
    rows.sort(key=lambda r: (-(r["cvss_score"] or 0), r["address"], r["cve_id"]))
    return rows


def _host_stats(hosts: list[dict]) -> dict:
    exposures, _, criticals = _collect(hosts)
    return {
        "ip_count": len(hosts),
        "service_count": sum(len(h["services"]) for h in hosts),
        "exposure_count": len(exposures),
        "cve_count": sum(len(h["vulns"]) for h in hosts),
        "critical_count": len(criticals),
    }


def _dashboard_group(key: str, name: str, kind: str, members: list[dict]) -> dict:
    """A dashboard row group. Its counts are over the members' combined
    IPs - two domains on one IP count it once."""
    hosts = {h["address"]: h for m in members for h in m["hosts"]}
    return {
        "key": key,
        "name": name,
        "kind": kind,  # "user" (made on the dashboard) or "tld" (same name, other TLDs)
        "members": members,
        "hostname_count": sum(m["hostname_count"] for m in members),
        **_host_stats(list(hosts.values())),
        "secret_count": sum(m["secret_count"] for m in members),
        "added_at": min(m["added_at"] for m in members),
    }


def build_dashboard(db: Database) -> dict:
    """`entries` is the Domains table: a group ({"members": [...], ...}) or
    a single domain each. User groups come first; the other domains are
    grouped with their TLD siblings (example.com + example.de) when they
    have any."""
    hosts = _overview_hosts(db)
    domains = []
    total_hosts = 0
    for domain_row in db.list_domains():
        hostname_rows = db.list_hostnames_for_domain(domain_row["id"])
        total_hosts += len(hostname_rows)
        domain_hosts = [h for h in hosts if domain_row["name"] in h["domains"]]
        domains.append(
            {
                "name": domain_row["name"],
                "added_at": domain_row["added_at"],
                "hosts": domain_hosts,
                "hostname_count": len(hostname_rows),
                **_host_stats(domain_hosts),
                "secret_count": db.count_secret_exposures(domain_row["id"]),
            }
        )

    user_group = db.domain_groups()
    user: dict[str, list[dict]] = {}
    family: dict[str, list[dict]] = {}
    singles: list[dict] = []
    for d in domains:
        if d["name"] in user_group:
            user.setdefault(user_group[d["name"]], []).append(d)
        elif (label := tld_family(d["name"])) is not None:
            family.setdefault(label, []).append(d)
        else:
            singles.append(d)
    others: list[dict] = []
    for label, members in family.items():
        if len(members) == 1:
            singles += members
        else:
            others.append(_dashboard_group(f"tld:{label}", f"{label}.*", "tld", members))
    others += singles
    entries = [
        _dashboard_group(f"user:{name}", name, "user", members)
        for name, members in sorted(user.items(), key=lambda kv: kv[0].lower())
    ]
    entries += sorted(others, key=lambda e: e["name"])
    for d in domains:
        del d["hosts"]  # only needed for the group counts
    return {
        "domains": domains,
        "entries": entries,
        "group_names": sorted(user, key=str.lower),
        "total_hosts": total_hosts,
        "total_ips": len(db.list_all_ips()),
    }


def build_domain(db: Database, name: str) -> dict | None:
    domain_row = db.get_domain_by_name(name)
    if domain_row is None:
        return None
    # Per-IP detail, fetched once per IP however many hostnames share it.
    ips: dict[str, dict] = {}
    hostnames = []
    takeovers: list[dict] = []
    for h in db.list_hostnames_for_domain(domain_row["id"]):
        takeovers += [
            r["data"] for r in _results_for(db, "hostname", h["id"]) if r["source"] == "takeover"
        ]
        addresses = []
        for ip_row in db.list_ips_for_hostname(h["id"]):
            address = ip_row["address"]
            addresses.append(address)
            if address not in ips:
                results = _results_for(db, "ip", ip_row["id"])
                ips[address] = {
                    "services": [dict(s) for s in db.list_services_for_ip(ip_row["id"])],
                    "vulns": _flatten_nvd_vulns([(r["source"], r["data"]) for r in results]),
                    "hostnames": [],
                }
            ips[address]["hostnames"].append(h["name"])
        services = [s for a in addresses for s in ips[a]["services"]]
        severities = [severity_of(v) for a in addresses for v in ips[a]["vulns"]]
        hostnames.append(
            {
                "name": h["name"],
                "ips": addresses,
                "ports": sorted({s["port"] for s in services}),
                "sensitive": sorted({SENSITIVE_PORTS[s["port"]][0] for s in services
                                     if s["port"] in SENSITIVE_PORTS}),
                "cve_count": len(severities),
                "worst": max(severities, key=lambda s: _SEVERITY_RANK[s]) if severities else None,
                "first_seen": h["first_seen"],
                "last_seen": h["last_seen"],
            }
        )
    services = [
        {
            **service,
            "address": address,
            "hostnames": info["hostnames"],
            "sensitive": SENSITIVE_PORTS.get(service["port"], (None,))[0],
        }
        for address, info in sorted(ips.items())
        for service in info["services"]
    ]
    candidates = [
        {**dict(row), "scanned": db.get_domain_by_name(row["name"]) is not None}
        for row in db.list_candidate_domains(domain_row["id"])
    ]
    domain_results = _results_for(db, "domain", domain_row["id"])
    lookalikes = next(
        (r["data"].get("registered", []) for r in domain_results if r["source"] == "lookalike"),
        [],
    )
    origin = next((r["data"] for r in domain_results if r["source"] == "origin_ip"), None)
    email_auth = next((r["data"] for r in domain_results if r["source"] == "email_auth"), None)
    # Already severity-sorted by the source (leakix.parse_events).
    leakix_findings = [
        finding
        for r in domain_results
        if r["source"] == "leakix"
        for finding in r["data"].get("findings") or []
    ]
    # Takeover findings live on their hostname, but any that didn't map back to
    # a known hostname were persisted on the domain - include both.
    takeovers += [r["data"] for r in domain_results if r["source"] == "takeover"]
    return {
        "name": name,
        "hostnames": hostnames,
        "services": services,
        "ip_count": len(ips),
        "candidates": candidates,
        "lookalikes": lookalikes,
        "origin": origin,
        "email_auth": email_auth,
        "leakix_findings": leakix_findings,
        "results": domain_results,
        "takeovers": takeovers,
        "cloud_findings": cloud_findings(domain_results),
        "cloud_assets": [dict(row) for row in db.list_cloud_assets(domain_row["id"])],
        "code_exposures": [dict(row) for row in db.list_code_exposures(domain_row["id"])],
        "email_addresses": [dict(row) for row in db.list_email_addresses(domain_row["id"])],
        "tool_outputs": [dict(row) for row in db.list_tool_outputs(domain_row["id"])],
    }


def build_host(db: Database, name: str) -> dict | None:
    row = db.get_hostname_by_name(name)
    if row is None:
        return None
    return {
        "name": name,
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "ips": [ip["address"] for ip in db.list_ips_for_hostname(row["id"])],
        "results": _results_for(db, "hostname", row["id"]),
        "code_exposures": [dict(r) for r in db.list_code_exposures_for_target(name)],
    }


def _tls_grade(data: dict, address: str) -> str | None:
    """SSL Labs grade for this IP's endpoint, else all endpoints' grades."""
    endpoints = [e for e in data.get("endpoints") or [] if e.get("grade")]
    own = [e["grade"] for e in endpoints if e.get("ipAddress") == address]
    return ", ".join(own or sorted({e["grade"] for e in endpoints})) or None


def _ip_hostnames(db: Database, ip_id: int, address: str) -> list[dict]:
    """Everything known per hostname pointing at this IP - the IP page is the
    only place hostname-level results are shown."""
    hosts = []
    for h in db.list_hostnames_for_ip(ip_id):
        results = _results_for(db, "hostname", h["id"])
        grades = [
            g for r in results if r["source"] == "qualys_ssllabs"
            if (g := _tls_grade(r["data"], address))
        ]
        hosts.append(
            {
                "name": h["name"],
                "first_seen": h["first_seen"],
                "last_seen": h["last_seen"],
                "other_ips": [
                    i["address"] for i in db.list_ips_for_hostname(h["id"]) if i["id"] != ip_id
                ],
                "found_by": sorted({r["source"] for r in results if r["source"] != "qualys_ssllabs"}),
                "tls_grade": grades[-1] if grades else None,
                "results": results,
            }
        )
    return hosts


def snmp_findings(results: list[dict]) -> list[dict]:
    """What SNMP disclosed about an IP, per source: the snmp probe's own
    analysis, and Shodan's SNMP banners analyzed the same way."""
    out = []
    for r in results:
        data = r["data"]
        if r["source"] == "snmp" and data.get("state") == "open":
            out.append({"source": "snmp probe", "fetched_at": r["fetched_at"],
                        "record": data, "analysis": data.get("analysis") or snmp.analyze(data)})
        elif r["source"] == "shodan":
            for entry in data.get("data") or []:
                if isinstance(entry, dict) and (record := snmp.shodan_snmp(entry)):
                    out.append({"source": "shodan", "fetched_at": r["fetched_at"],
                                "record": record, "analysis": snmp.analyze(record)})
    return out


def build_ip(db: Database, address: str) -> dict | None:
    row = db.get_ip_by_address(address)
    if row is None:
        return None
    results = _results_for(db, "ip", row["id"])
    # Attach a normalized severity to every CVE so the template can style it.
    vulns = _flatten_nvd_vulns([(r["source"], r["data"]) for r in results])
    for vuln in vulns:
        vuln["severity"] = severity_of(vuln)
    webtech_urls = {
        r["data"]["port"]: r["data"]["url"]
        for r in results
        if r["source"] == "webtech" and r["data"].get("port") and r["data"].get("url")
    }
    services = [dict(s) for s in db.list_services_for_ip(row["id"])]
    for service in services:
        service["web_url"] = web_url(address, service, webtech_urls)
    nuclei = sorted(
        (r["data"] for r in results if r["source"] == "nuclei"),
        key=lambda f: _NUCLEI_SEVERITY_ORDER.get((f.get("severity") or "unknown").lower(), 9),
    )
    container_exposures = sorted(
        (
            exposure
            for r in results
            if r["source"] == "container_exposure"
            for exposure in r["data"].get("exposures") or []
        ),
        key=lambda e: severity_rank(e.get("severity")),
    )
    header_findings = sorted(
        (
            {**finding, "url": r["data"].get("url")}
            for r in results
            if r["source"] == "webtech"
            for finding in (r["data"].get("security_headers") or {}).get("findings") or []
        ),
        key=lambda f: severity_rank(f.get("severity")),
    )
    # Already severity-sorted by the source (leakix.parse_events).
    leakix_findings = [
        finding
        for r in results
        if r["source"] == "leakix"
        for finding in r["data"].get("findings") or []
    ]
    return {
        "address": address,
        "snmp": snmp_findings(results),
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "hostnames": _ip_hostnames(db, row["id"], address),
        "services": services,
        "results": results,
        "vulns": sorted(vulns, key=lambda v: -(v.get("cvss_score") or 0)),
        "nuclei": nuclei,
        "web_findings": web_findings(results),
        "header_findings": header_findings,
        "leakix_findings": leakix_findings,
        "container_exposures": container_exposures,
        "code_exposures": [dict(r) for r in db.list_code_exposures_for_target(address)],
    }
