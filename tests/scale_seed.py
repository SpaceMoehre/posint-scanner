"""A synthetic scan DB of a chosen size, for the query-count tests
(test_read_queries.py) and the latency benchmark (scripts/bench_web.py).

Every page's query count must not grow with the data: seeding the same
shape at two sizes and comparing counts catches a per-row query loop.
"""

from __future__ import annotations

from posint_scanner.db import Database


def seed(db: Database, domains: int, ips_per_domain: int, rescans: int = 1) -> None:
    """`domains` apex domains, each with `ips_per_domain` hostnames on their
    own IP plus one shared IP, services, CVEs and findings on every IP, and
    every result stored `rescans` times (as repeated scans leave them)."""
    shared = db.upsert_ip("203.0.113.250")
    for d in range(domains):
        domain_id = db.upsert_domain(f"example{d}.com")
        apex = db.upsert_hostname(domain_id, f"example{d}.com")
        db.upsert_resolution(apex, shared)
        db.insert_result("email_auth", "domain", domain_id, {
            "spoofable": True, "spf": {"found": False}, "dmarc": {"found": False},
            "dkim": {"selectors_present": []}, "caa": {"found": False, "records": []},
            "findings": [{"severity": "high", "title": "No DMARC record", "detail": ""}]})
        db.upsert_code_exposure(
            domain_id, kind="secret", target=f"example{d}.com", repo="acme/app", path=".env",
            commit="a" * 40, url="https://github.com/acme/app/blob/x/.env", line=1,
            rule="aws_access_key_id", secret="AKIA" + "X" * 16)
        for i in range(ips_per_domain):
            host = db.upsert_hostname(domain_id, f"h{i}.example{d}.com", parent_hostname_id=apex)
            ip = db.upsert_ip(f"10.{d // 256}.{d % 256}.{i + 1}")
            db.upsert_resolution(host, ip)
            db.upsert_service(ip, 443, "tcp", "HTTP/1.1 200 OK")
            db.upsert_service(ip, 3306, "tcp", "MySQL 8.0")
            for _ in range(rescans):
                db.insert_result("nvd", "ip", ip, {
                    "port": 443, "technology": "Apache 2.4.49",
                    "cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
                    "cves": [{"cve_id": "CVE-2021-41773", "cvss_score": 9.8,
                              "cvss_severity": "CRITICAL", "summary": "path traversal"}]})
                db.insert_result("nuclei", "ip", ip, {
                    "template_id": "git-config", "name": "Exposed .git/config",
                    "severity": "high", "matched_at": f"https://10.0.0.{i}/.git/config"})
                db.insert_result("webtech", "ip", ip, {
                    "port": 443, "url": f"https://h{i}.example{d}.com/",
                    "security_headers": {"findings": [
                        {"severity": "medium", "title": "No HSTS", "detail": ""}]}})
                db.insert_result("crtsh", "hostname", host, {"name": f"h{i}.example{d}.com"})
