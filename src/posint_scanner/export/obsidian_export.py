"""Obsidian-vault markdown export.

Flat folders per entity type (Domains/, Hosts/, IPs/) rather than nesting by
DNS depth - relationships are expressed via frontmatter properties, wikilinks,
and tags instead, since that's what supports fast cross-cutting access
(backlinks, graph view, search) rather than a folder tree that only mirrors
one axis (naming hierarchy) of the data.

Regenerated (overwritten) on every export run so stale entries don't linger.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from posint_scanner.db import Database
from posint_scanner.export.overview import render_overview_note

_UNSAFE_CHARS = re.compile(r"[^a-zA-Z0-9._-]")


def slugify(name: str) -> str:
    return _UNSAFE_CHARS.sub("_", name)


def _render_results_section(results: list[tuple[str, dict]]) -> list[str]:
    if not results:
        return []
    lines = ["## Results", ""]
    for source, data in results:
        lines.append(f"### {source}")
        lines.append(f"```json\n{json.dumps(data, indent=2, default=str)}\n```")
        lines.append("")
    return lines


def render_domain_note(
    name: str,
    hostnames: list[str],
    candidates: list[dict] | None = None,
    results: list[tuple[str, dict]] | None = None,
    cloud_assets: list[dict] | None = None,
    code_exposures: list[dict] | None = None,
    email_addresses: list[dict] | None = None,
) -> str:
    """`candidates`: out-of-scope domains sources related to this one (dicts
    with name/source/via), listed as plain text - they were never scanned,
    so there's no note to link to."""
    lines = [
        "---",
        "tags:",
        "  - domain",
        "---",
        f"# {name}",
        "",
        "## Hostnames",
        "",
    ]
    lines.extend(f"- [[{hostname}]]" for hostname in sorted(hostnames))
    if cloud_assets:
        lines += ["", "## Cloud storage", ""]
        for asset in cloud_assets:
            lines.append(
                f"- **{asset['exposure']}** {asset['provider']}: [{asset['name']}]({asset['url']})"
            )
    if code_exposures:
        secrets = [e for e in code_exposures if e["kind"] == "secret"]
        lines += ["", f"## GitHub exposures ({len(secrets)} secret{'s' if len(secrets) != 1 else ''})", ""]
        for e in code_exposures:
            if e["kind"] == "secret":
                lines.append(f"- **SECRET** `{e['rule']}` in [{e['repo']}/{e['path']}]({e['url']}) "
                             f"→ `{e['secret']}`")
            else:
                lines.append(f"- {e['target']} in [{e['repo']}/{e['path']}]({e['url']})")
    if email_addresses:
        lines += ["", f"## Email addresses ({len(email_addresses)})", ""]
        for e in email_addresses:
            who = ", ".join(x for x in (e.get("name"), e.get("position")) if x)
            lines.append(f"- {e['address']}" + (f" - {who}" if who else "") + f" (via {e['sources']})")
    if candidates:
        lines += ["", "## Candidate domains (not scanned)", ""]
        lines.extend(f"- {c['name']} - via {c['source']} ({c['via']})" for c in candidates)
    if results:
        lines.append("")
        lines.extend(_render_results_section(results))
    return "\n".join(lines) + "\n"


def render_hostname_note(
    name: str,
    domain: str,
    ip_addresses: list[str],
    results: list[tuple[str, dict]],
    first_seen: str,
    last_seen: str,
) -> str:
    tags = ["host"] + sorted({f"source/{source}" for source, _ in results})
    front_matter = [
        "---",
        "tags:",
        *(f"  - {tag}" for tag in tags),
        f'parent: "[[{domain}]]"',
        "resolves_to:",
        *(f'  - "[[{ip}]]"' for ip in ip_addresses),
        f"first_seen: {first_seen}",
        f"last_seen: {last_seen}",
        "---",
    ]
    body = [f"# {name}", "", f"Parent domain: [[{domain}]]", ""]
    if ip_addresses:
        body.append("## Resolves to")
        body.extend(f"- [[{ip}]]" for ip in ip_addresses)
        body.append("")
    body.extend(_render_results_section(results))
    return "\n".join(front_matter + body) + "\n"


def render_ip_note(
    address: str,
    hostnames: list[str],
    services: list[dict],
    results: list[tuple[str, dict]],
    first_seen: str,
    last_seen: str,
) -> str:
    tags = (
        ["ip"]
        + sorted({f"source/{source}" for source, _ in results})
        + sorted({f"port/{service['port']}" for service in services})
    )
    front_matter = [
        "---",
        "tags:",
        *(f"  - {tag}" for tag in tags),
        "resolved_from:",
        *(f'  - "[[{hostname}]]"' for hostname in hostnames),
        f"first_seen: {first_seen}",
        f"last_seen: {last_seen}",
        "---",
    ]
    body = [f"# {address}", ""]
    if hostnames:
        body.append("## Hostnames pointing here")
        body.extend(f"- [[{hostname}]]" for hostname in hostnames)
        body.append("")
    if services:
        body.append("## Services")
        for service in services:
            label = service.get("banner") or ""
            if service.get("version"):
                label = f"{label} {service['version']}".strip()
            suffix = f" - {label}" if label else ""
            body.append(f"- {service['port']}/{service['protocol']}{suffix}")
        body.append("")
    body.extend(_render_results_section(results))
    return "\n".join(front_matter + body) + "\n"


def _flatten_nvd_vulns(results: list[tuple[str, dict]]) -> list[dict]:
    """Pull every CVE out of an IP's `nvd` result rows into flat records the
    overview groups by (port, component). Each row carries the port,
    technology/CPE it was found under, and the per-CVE score/severity/summary."""
    vulns = []
    for source, data in results:
        if source != "nvd":
            continue
        component = data.get("technology") or data.get("cpe")
        for cve in data.get("cves", []):
            vulns.append(
                {
                    "port": data.get("port"),
                    "technology": component,
                    "cpe": data.get("cpe"),
                    "cve_id": cve.get("cve_id"),
                    "cvss_score": cve.get("cvss_score"),
                    "cvss_severity": cve.get("cvss_severity"),
                    "summary": cve.get("summary"),
                    "exploits": cve.get("exploits", []),
                }
            )
    return vulns


def export_obsidian(db: Database, output_dir: Path) -> None:
    output_dir = Path(output_dir)
    if output_dir.exists():
        shutil.rmtree(output_dir)
    domains_dir = output_dir / "Domains"
    hosts_dir = output_dir / "Hosts"
    ips_dir = output_dir / "IPs"
    for directory in (domains_dir, hosts_dir, ips_dir):
        directory.mkdir(parents=True, exist_ok=True)

    for domain_row in db.list_domains():
        hostname_rows = db.list_hostnames_for_domain(domain_row["id"])
        content = render_domain_note(
            domain_row["name"],
            [row["name"] for row in hostname_rows],
            [dict(row) for row in db.list_candidate_domains(domain_row["id"])],
            [
                (row["source"], json.loads(row["data"]))
                for row in db.list_results_for_target("domain", domain_row["id"])
            ],
            [dict(row) for row in db.list_cloud_assets(domain_row["id"])],
            [dict(row) for row in db.list_code_exposures(domain_row["id"])],
            [dict(row) for row in db.list_email_addresses(domain_row["id"])],
        )
        (domains_dir / f"{slugify(domain_row['name'])}.md").write_text(content)

        for hostname_row in hostname_rows:
            ip_addresses = [row["address"] for row in db.list_ips_for_hostname(hostname_row["id"])]
            results = [
                (row["source"], json.loads(row["data"]))
                for row in db.list_results_for_target("hostname", hostname_row["id"])
            ]
            content = render_hostname_note(
                name=hostname_row["name"],
                domain=domain_row["name"],
                ip_addresses=ip_addresses,
                results=results,
                first_seen=hostname_row["first_seen"],
                last_seen=hostname_row["last_seen"],
            )
            (hosts_dir / f"{slugify(hostname_row['name'])}.md").write_text(content)

    overview_hosts = []
    for ip_row in db.list_all_ips():
        hostnames = [row["name"] for row in db.list_hostnames_for_ip(ip_row["id"])]
        services = [dict(row) for row in db.list_services_for_ip(ip_row["id"])]
        results = [
            (row["source"], json.loads(row["data"]))
            for row in db.list_results_for_target("ip", ip_row["id"])
        ]
        content = render_ip_note(
            address=ip_row["address"],
            hostnames=hostnames,
            services=services,
            results=results,
            first_seen=ip_row["first_seen"],
            last_seen=ip_row["last_seen"],
        )
        (ips_dir / f"{slugify(ip_row['address'])}.md").write_text(content)

        overview_hosts.append(
            {
                "address": ip_row["address"],
                "hostnames": hostnames,
                "services": services,
                "vulns": _flatten_nvd_vulns(results),
            }
        )

    # `_Overview.md` at the vault root - the underscore sorts it to the top of
    # Obsidian's file list so it's the first thing a reviewer opens.
    (output_dir / "_Overview.md").write_text(render_overview_note(overview_hosts))
