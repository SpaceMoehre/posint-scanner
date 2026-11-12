"""Obsidian-vault markdown export, as one zip.

One note per host in Hosts/: a host is an IP address - or a hostname, when
that name resolves to several IPs (a load balancer, a CDN), which then
covers all of them (see group_hosts). Hostnames on a single IP are part of
that IP's note. Domains/ holds a note per scanned domain and `_Overview.md`
the findings across hosts, both linking to the host notes. Relationships
are frontmatter properties, wikilinks and tags rather than nested folders,
since that's what supports cross-cutting access (backlinks, graph view,
search).

Built fresh on every export - a view of the database, never read back.
"""

from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path
from typing import Any

from posint_scanner.db import Database
from posint_scanner.nvd import cpe_version
from posint_scanner.export.overview import _link, render_overview_note

_UNSAFE_CHARS = re.compile(r"[^a-zA-Z0-9._-]")


def slugify(name: str) -> str:
    return _UNSAFE_CHARS.sub("_", name)


def _render_results_section(results: list[tuple[str, dict]], level: int = 2) -> list[str]:
    if not results:
        return []
    lines = ["#" * level + " Results", ""]
    for source, data in results:
        lines.append("#" * (level + 1) + f" {source}")
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
    note_for: dict[str, str] | None = None,
) -> str:
    """`candidates`: out-of-scope domains sources related to this one (dicts
    with name/source/via), listed as plain text - they were never scanned,
    so there's no note to link to. `note_for` maps a hostname to its host
    note (see group_hosts); without it every hostname links to its own name,
    with it one that has no host note (resolves nowhere) is plain text."""
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
    for hostname in sorted(hostnames):
        if note_for is None or hostname in note_for:
            lines.append(f"- {_link(hostname, note_for, in_table=False)}")
        else:
            lines.append(f"- {hostname} (unresolved)")
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


def group_hosts(
    ips_of: dict[str, list[str]], addresses: list[str]
) -> tuple[list[dict], dict[str, str]]:
    """The host notes, as {name, ips, hostnames}, and which note covers each
    IP and hostname. `ips_of`: hostname -> the IPs it resolves to;
    `addresses`: every IP.

    A hostname on several IPs gets a note for all of them (hostnames on the
    same set share it, named after the first); every other IP gets its own.
    A hostname on one IP belongs to the note covering that IP. An IP behind
    several such hostnames is described in each of their notes; links go to
    the first."""
    groups: dict[tuple[str, ...], list[str]] = {}
    for name in sorted(ips_of):
        ips = tuple(sorted(set(ips_of[name])))
        if len(ips) > 1:
            groups.setdefault(ips, []).append(name)
    notes: list[dict[str, Any]] = []
    note_for: dict[str, str] = {}
    owner: dict[str, dict[str, Any]] = {}
    for ips, names in sorted(groups.items(), key=lambda group: group[1][0]):
        note: dict[str, Any] = {"name": names[0], "ips": list(ips), "hostnames": list(names)}
        notes.append(note)
        note_for.update({name: note["name"] for name in names})
        for ip in ips:
            owner.setdefault(ip, note)
    for ip in addresses:
        if ip not in owner:
            owner[ip] = {"name": ip, "ips": [ip], "hostnames": []}
            notes.append(owner[ip])
        note_for[ip] = owner[ip]["name"]
    for name in sorted(ips_of):
        resolved = set(ips_of[name])
        if len(resolved) == 1 and (ip := resolved.pop()) in owner:
            owner[ip]["hostnames"].append(name)
            note_for[name] = owner[ip]["name"]
    return notes, note_for


def _service_line(service: dict) -> str:
    label = service.get("banner") or ""
    if service.get("version"):
        label = f"{label} {service['version']}".strip()
    return f"- {service['port']}/{service['protocol']}" + (f" - {label}" if label else "")


def render_host_note(note: dict, ips: dict[str, dict], hostnames: dict[str, dict]) -> str:
    """One host's note. `note` is a group_hosts entry; `ips` maps an address
    to {services, results, first_seen, last_seen}, `hostnames` a name to
    {domain, results}."""
    own_ips = [ips[a] | {"address": a} for a in note["ips"]]
    own_names = [hostnames[n] | {"name": n} for n in note["hostnames"]]
    results = [r for ip in own_ips for r in ip["results"]] + [
        r for h in own_names for r in h["results"]]
    tags = (["host"] + sorted({f"source/{source}" for source, _ in results})
            + sorted({f"port/{s['port']}" for ip in own_ips for s in ip["services"]}))
    domains = sorted({h["domain"] for h in own_names})
    lines = [
        "---",
        "tags:",
        *(f"  - {tag}" for tag in tags),
        "domains:",
        *(f'  - "[[{d}]]"' for d in domains),
        "ips:",
        *(f"  - {ip['address']}" for ip in own_ips),
        "hostnames:",
        *(f"  - {h['name']}" for h in own_names),
        f"first_seen: {min(ip['first_seen'] for ip in own_ips)}",
        f"last_seen: {max(ip['last_seen'] for ip in own_ips)}",
        "---",
        f"# {note['name']}",
        "",
    ]
    if domains:
        lines += ["Domains: " + ", ".join(f"[[{d}]]" for d in domains), ""]
    if own_names:
        lines += ["## Hostnames", "", *(f"- {h['name']}" for h in own_names), ""]
    for ip in own_ips:
        lines += [f"## {ip['address']}" if len(own_ips) > 1 else "## Services", ""]
        if len(own_ips) > 1:
            lines += ["### Services", ""]
        lines += [_service_line(s) for s in ip["services"]] or ["None found."]
        lines.append("")
        lines += _render_results_section(ip["results"], level=3 if len(own_ips) > 1 else 2)
    for h in own_names:
        if h["results"]:
            lines += [f"## {h['name']}", ""]
            lines += _render_results_section(h["results"], level=3)
    return "\n".join(lines) + "\n"


def _flatten_nvd_vulns(results: list[tuple[str, dict]]) -> list[dict]:
    """Pull every CVE out of an IP's `nvd` result rows into flat records the
    overview groups by (port, component). Each row carries the port,
    technology (with its version)/CPE it was found under, and the per-CVE
    score/severity/summary.

    A row matched for a CPE without a concrete version is dropped: it holds
    every CVE ever filed for the product, whatever version runs. The lookup
    no longer stores such rows; this keeps ones stored before from showing."""
    vulns = []
    for source, data in results:
        if source != "nvd":
            continue
        cpe_field = data.get("cpe")
        cpes = cpe_field if isinstance(cpe_field, list) else [cpe_field]
        if not any(isinstance(cpe, str) and cpe_version(cpe) for cpe in cpes):
            continue
        component = data.get("technology") or data.get("cpe")
        if data.get("technology") and data.get("version"):
            component = f"{data['technology']} {data['version']}"
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
                    "affected": cve.get("affected"),
                    "exploits": cve.get("exploits", []),
                }
            )
    return vulns


def vault_files(db: Database) -> dict[str, str]:
    """The vault's notes: path inside the vault -> markdown."""
    def results_of(target_type: str) -> dict[int, list[tuple[str, dict]]]:
        out: dict[int, list[tuple[str, dict]]] = {}
        for row in db.query(
            "SELECT target_id, source, data FROM results WHERE target_type = ? "
            "ORDER BY fetched_at, id", (target_type,)
        ):
            out.setdefault(row["target_id"], []).append((row["source"], json.loads(row["data"])))
        return out

    ip_results, hostname_results = results_of("ip"), results_of("hostname")
    services: dict[int, list[dict]] = {}
    for row in db.query("SELECT * FROM services ORDER BY port, protocol"):
        services.setdefault(row["ip_id"], []).append(dict(row))
    ips = {
        row["address"]: {"id": row["id"], "services": services.get(row["id"], []),
                         "results": ip_results.get(row["id"], []),
                         "first_seen": row["first_seen"], "last_seen": row["last_seen"]}
        for row in db.query("SELECT * FROM ip_addresses ORDER BY address")
    }
    hostnames = {
        row["name"]: {"domain": row["domain"], "results": hostname_results.get(row["id"], [])}
        for row in db.query("SELECT h.id, h.name, d.name AS domain FROM hostnames h "
                            "JOIN domains d ON d.id = h.domain_id ORDER BY h.name")
    }
    ips_of: dict[str, list[str]] = {}
    for row in db.query("SELECT h.name, i.address FROM resolutions r "
                        "JOIN hostnames h ON h.id = r.hostname_id "
                        "JOIN ip_addresses i ON i.id = r.ip_id"):
        ips_of.setdefault(row["name"], []).append(row["address"])
    notes, note_for = group_hosts(ips_of, list(ips))

    files: dict[str, str] = {}
    for note in notes:
        files[f"Hosts/{slugify(note['name'])}.md"] = render_host_note(note, ips, hostnames)
    for domain_row in db.list_domains():
        files[f"Domains/{slugify(domain_row['name'])}.md"] = render_domain_note(
            domain_row["name"],
            [row["name"] for row in db.list_hostnames_for_domain(domain_row["id"])],
            [dict(row) for row in db.list_candidate_domains(domain_row["id"])],
            [
                (row["source"], json.loads(row["data"]))
                for row in db.list_results_for_target("domain", domain_row["id"])
            ],
            [dict(row) for row in db.list_cloud_assets(domain_row["id"])],
            [dict(row) for row in db.list_code_exposures(domain_row["id"])],
            [dict(row) for row in db.list_email_addresses(domain_row["id"])],
            note_for=note_for,
        )
    names_on: dict[str, list[str]] = {}
    for name, addresses in sorted(ips_of.items()):
        for address in addresses:
            names_on.setdefault(address, []).append(name)
    overview_hosts = [
        {"address": address, "hostnames": names_on.get(address, []), "services": ip["services"],
         "vulns": _flatten_nvd_vulns(ip["results"])}
        for address, ip in ips.items()
    ]
    # `_Overview.md` at the vault root - the underscore sorts it to the top of
    # Obsidian's file list so it's the first thing a reviewer opens.
    files["_Overview.md"] = render_overview_note(overview_hosts, note_for)
    return files


def export_obsidian(db: Database, output_path: str | Path) -> None:
    """Write the vault to `output_path` as a zip (replacing any file there)."""
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, content in sorted(vault_files(db).items()):
            archive.writestr(path, content)
