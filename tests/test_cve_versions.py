"""A CVE is only shown for a service whose version is known: matching a
product without its version would flag every CVE ever filed for it."""

from __future__ import annotations

from posint_scanner.db import Database
from posint_scanner.readmodel import build_ip

CVE = {"cve_id": "CVE-2021-23017", "cvss_score": 7.7, "cvss_severity": "HIGH",
       "summary": "resolver off-by-one"}


def _ip_with(*nvd_rows: dict) -> Database:
    db = Database(":memory:")
    db.init_schema()
    ip = db.upsert_ip("192.0.2.1")
    for row in nvd_rows:
        db.insert_result("nvd", "ip", ip, row)
    return db


def test_the_component_shows_the_version_its_cves_were_matched_for():
    db = _ip_with({"port": 443, "technology": "Nginx", "version": "1.18.0",
                   "cpe": "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*", "cves": [CVE]})
    [vuln] = build_ip(db, "192.0.2.1")["vulns"]
    assert vuln["technology"] == "Nginx 1.18.0"


def test_cves_stored_for_a_versionless_product_are_not_shown():
    # Stored before versionless CPEs were skipped at lookup time.
    db = _ip_with(
        {"port": 443, "technology": "Nginx", "version": None,
         "cpe": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "cves": [CVE]},
        {"port": 80, "cpe": "cpe:/a:apache:http_server", "cves": [CVE]},
        {"port": 8080, "cpe": ["cpe:2.3:a:x:y:-:*:*:*:*:*:*:*"], "cves": [CVE]},
    )
    assert build_ip(db, "192.0.2.1")["vulns"] == []


def test_a_service_cpe_with_a_version_keeps_its_cves():
    db = _ip_with({"port": 22, "cpe": "cpe:/a:openbsd:openssh:7.4", "cves": [CVE]})
    [vuln] = build_ip(db, "192.0.2.1")["vulns"]
    assert vuln["cve_id"] == "CVE-2021-23017"
