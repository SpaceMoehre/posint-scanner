"""CSV export: one row per service (or one placeholder row for an IP with none)."""

from __future__ import annotations

import csv
from pathlib import Path

from posint_scanner.db import Database

FIELDNAMES = ["ip", "hostnames", "port", "protocol", "banner", "version"]


def export_service_rows(db: Database) -> list[dict]:
    rows = []
    for ip_row in db.list_all_ips():
        hostnames = ", ".join(row["name"] for row in db.list_hostnames_for_ip(ip_row["id"]))
        services = db.list_services_for_ip(ip_row["id"])
        if not services:
            rows.append(
                {
                    "ip": ip_row["address"],
                    "hostnames": hostnames,
                    "port": "",
                    "protocol": "",
                    "banner": "",
                    "version": "",
                }
            )
            continue
        for service in services:
            rows.append(
                {
                    "ip": ip_row["address"],
                    "hostnames": hostnames,
                    "port": service["port"],
                    "protocol": service["protocol"],
                    "banner": service["banner"] or "",
                    "version": service["version"] or "",
                }
            )
    return rows


EXPOSURE_FIELDNAMES = [
    "domain", "kind", "target", "repo", "path", "commit", "url", "line",
    "rule", "secret", "first_seen", "last_seen",
]


def export_code_exposure_rows(db: Database) -> list[dict]:
    """One row per stored GitHub code exposure (reference or secret)."""
    rows = []
    for domain_row in db.list_domains():
        for e in db.list_code_exposures(domain_row["id"]):
            rows.append({
                "domain": domain_row["name"],
                "kind": e["kind"],
                "target": e["target"],
                "repo": e["repo"],
                "path": e["path"],
                "commit": e["commit_sha"],
                "url": e["url"],
                "line": e["line"] if e["line"] is not None else "",
                "rule": e["rule"] or "",
                "secret": e["secret"] or "",
                "first_seen": e["first_seen"],
                "last_seen": e["last_seen"],
            })
    return rows


EMAIL_FIELDNAMES = [
    "domain", "address", "name", "position", "confidence", "sources", "url",
    "first_seen", "last_seen",
]


def export_email_rows(db: Database) -> list[dict]:
    """One row per email address found for a domain (sources merged)."""
    rows = []
    for domain_row in db.list_domains():
        for e in db.list_email_addresses(domain_row["id"]):
            rows.append({
                "domain": domain_row["name"],
                "address": e["address"],
                "name": e["name"] or "",
                "position": e["position"] or "",
                "confidence": e["confidence"] if e["confidence"] is not None else "",
                "sources": e["sources"],
                "url": e["url"] or "",
                "first_seen": e["first_seen"],
                "last_seen": e["last_seen"],
            })
    return rows


def _write_sibling(output_path: str | Path, kind: str, fieldnames: list[str], rows: list[dict]) -> None:
    path = Path(output_path)
    sibling = path.with_name(f"{path.stem}.{kind}{path.suffix or '.csv'}")
    with open(sibling, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_csv(db: Database, output_path: str | Path) -> None:
    """Write the service inventory, plus sibling `*.code_exposures.csv`
    (secrets in full) and `*.emails.csv` files when the scan found any."""
    rows = export_service_rows(db)
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)

    exposures = export_code_exposure_rows(db)
    if exposures:
        _write_sibling(output_path, "code_exposures", EXPOSURE_FIELDNAMES, exposures)
    emails = export_email_rows(db)
    if emails:
        _write_sibling(output_path, "emails", EMAIL_FIELDNAMES, emails)
