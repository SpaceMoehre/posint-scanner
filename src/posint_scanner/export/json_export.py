"""Plain JSON export of the full scan database."""

from __future__ import annotations

import json
from pathlib import Path

from posint_scanner.db import Database


def export_json(db: Database) -> dict:
    domains = []
    for domain_row in db.list_domains():
        hostnames = []
        for hostname_row in db.list_hostnames_for_domain(domain_row["id"]):
            ip_addresses = [row["address"] for row in db.list_ips_for_hostname(hostname_row["id"])]
            results = [
                {"source": row["source"], "data": json.loads(row["data"]), "fetched_at": row["fetched_at"]}
                for row in db.list_results_for_target("hostname", hostname_row["id"])
            ]
            hostnames.append(
                {
                    "name": hostname_row["name"],
                    "first_seen": hostname_row["first_seen"],
                    "last_seen": hostname_row["last_seen"],
                    "ips": ip_addresses,
                    "results": results,
                }
            )
        domains.append(
            {
                "name": domain_row["name"],
                "added_at": domain_row["added_at"],
                "hostnames": hostnames,
                "results": [
                    {
                        "source": row["source"],
                        "data": json.loads(row["data"]),
                        "fetched_at": row["fetched_at"],
                    }
                    for row in db.list_results_for_target("domain", domain_row["id"])
                ],
                "cloud_assets": [
                    {
                        "provider": row["provider"],
                        "name": row["name"],
                        "url": row["url"],
                        "exposure": row["exposure"],
                        "source": row["source"],
                    }
                    for row in db.list_cloud_assets(domain_row["id"])
                ],
                "email_addresses": [
                    {
                        "address": row["address"],
                        "sources": row["sources"].split(", "),
                        "name": row["name"],
                        "position": row["position"],
                        "confidence": row["confidence"],
                        "url": row["url"],
                        "first_seen": row["first_seen"],
                        "last_seen": row["last_seen"],
                    }
                    for row in db.list_email_addresses(domain_row["id"])
                ],
                "candidate_domains": [
                    {
                        "name": row["name"],
                        "source": row["source"],
                        "via": row["via"],
                        "first_seen": row["first_seen"],
                        "last_seen": row["last_seen"],
                    }
                    for row in db.list_candidate_domains(domain_row["id"])
                ],
                "code_exposures": [
                    {
                        "kind": row["kind"],
                        "target": row["target"],
                        "repo": row["repo"],
                        "path": row["path"],
                        "commit": row["commit_sha"],
                        "url": row["url"],
                        "line": row["line"],
                        "rule": row["rule"],
                        "secret": row["secret"],
                        "first_seen": row["first_seen"],
                        "last_seen": row["last_seen"],
                    }
                    for row in db.list_code_exposures(domain_row["id"])
                ],
            }
        )

    ips = []
    for ip_row in db.list_all_ips():
        services = [
            {
                "port": row["port"],
                "protocol": row["protocol"],
                "banner": row["banner"],
                "version": row["version"],
            }
            for row in db.list_services_for_ip(ip_row["id"])
        ]
        results = [
            {"source": row["source"], "data": json.loads(row["data"]), "fetched_at": row["fetched_at"]}
            for row in db.list_results_for_target("ip", ip_row["id"])
        ]
        hostnames_for_ip = [row["name"] for row in db.list_hostnames_for_ip(ip_row["id"])]
        ips.append(
            {
                "address": ip_row["address"],
                "first_seen": ip_row["first_seen"],
                "last_seen": ip_row["last_seen"],
                "hostnames": hostnames_for_ip,
                "services": services,
                "results": results,
            }
        )

    return {"domains": domains, "ips": ips}


def write_json(db: Database, output_path: str | Path) -> None:
    Path(output_path).write_text(json.dumps(export_json(db), indent=2, default=str))
