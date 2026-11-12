from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from posint_scanner.db import Database
from posint_scanner.export.findings_report import collect_findings, render_report
from posint_scanner.web.app import create_app

NOW = datetime(2026, 10, 31, 12, 0, tzinfo=timezone.utc)
SECRET = "AKIASECRETVALUE12345"


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "r.db")
    database.init_schema()
    d1 = database.upsert_domain("example.com")
    d2 = database.upsert_domain("other.org")
    www = database.upsert_hostname(d1, "www.example.com")
    api = database.upsert_hostname(d1, "api.example.com")
    mail = database.upsert_hostname(d2, "mail.other.org")
    ip1, ip2, ip3 = (database.upsert_ip(a) for a in ("192.0.2.1", "192.0.2.2", "198.51.100.7"))
    database.upsert_resolution(www, ip1)
    database.upsert_resolution(api, ip2)
    database.upsert_resolution(mail, ip3)
    database.upsert_service(ip1, 445, "tcp", "SMB Status:\n  SMB Version: 1")
    database.upsert_service(ip3, 3306, "tcp", "MySQL 8.0")
    critical_cve = {"cve_id": "CVE-2021-41773", "cvss_score": 9.8,
                    "cvss_severity": "CRITICAL", "summary": "Apache path traversal | RCE"}
    for ip in (ip1, ip2):  # the same CVE on two IPs
        database.insert_result("nvd", "ip", ip, {"port": 443, "technology": "Apache 2.4.49",
                                                "cpe": "cpe:/a:apache:http_server:2.4.49", "cves": [critical_cve]})
    database.insert_result("nuclei", "ip", ip2, {
        "template_id": "git-config", "name": "Exposed .git/config", "severity": "high",
        "matched_at": "https://api.example.com/.git/config", "cves": []})
    database.insert_result("webtech", "ip", ip1, {
        "port": 443, "url": "https://www.example.com/",
        "security_headers": {"findings": [
            {"severity": "medium", "title": "No HSTS", "detail": "Strict-Transport-Security missing"},
            {"severity": "low", "title": "No Referrer-Policy", "detail": ""},
        ]}})
    database.insert_result("takeover", "hostname", api, {
        "severity": "high", "resource": "api.example.com", "id": "github",
        "location": "acme.github.io"})
    database.insert_result("email_auth", "domain", d2, {
        "spoofable": True, "findings": [
            {"severity": "high", "title": "No DMARC record", "detail": "mail can be forged"}]})
    database.upsert_code_exposure(
        d1, kind="secret", target="www.example.com", repo="acme/app", path=".env",
        commit="a" * 40, url="https://github.com/acme/app/blob/" + "a" * 40 + "/.env#L4",
        line=4, rule="aws_access_key_id", secret=SECRET)
    yield database
    database.close()


def _titles(data, severity):
    return [f["title"] for f in data["findings"] if f["severity"] == severity]


class TestCollect:
    def test_every_source_lands_on_one_scale(self, db):
        data = collect_findings(db)
        assert set(_titles(data, "critical")) == {"SMBv1 enabled", "CVE-2021-41773"}
        assert set(_titles(data, "high")) == {
            "Exposed .git/config", "Dangling CNAME to github",
            "No DMARC record", "aws_access_key_id in public code"}
        assert _titles(data, "medium") == ["No HSTS"]
        assert _titles(data, "low") == ["No Referrer-Policy"]

    def test_same_finding_on_several_hosts_is_one_entry(self, db):
        cve = next(f for f in collect_findings(db)["findings"] if f["title"] == "CVE-2021-41773")
        assert cve["wheres"] == ["192.0.2.1 (www.example.com) port 443",
                                 "192.0.2.2 (api.example.com) port 443"]
        # seen in more places sorts first within a severity
        criticals = [f for f in collect_findings(db)["findings"] if f["severity"] == "critical"]
        assert criticals[0]["title"] == "CVE-2021-41773"

    def test_scoped_to_selected_domains(self, db):
        data = collect_findings(db, ["other.org"])
        assert data["domains"] == ["other.org"]
        assert data["ip_count"] == 1
        assert {f["title"] for f in data["findings"]} == {"No DMARC record"}
        assert [e["address"] for e in data["exposures"]] == ["198.51.100.7"]

    def test_unknown_domain_scopes_to_nothing(self, db):
        data = collect_findings(db, ["nope.net"])
        assert data["findings"] == [] and data["ip_count"] == 0


class TestRender:
    def test_report_layout(self, db):
        text = render_report(db, now=NOW)
        assert text.startswith("# Security findings report")
        assert "Generated 2026-10-31 12:00 UTC" in text and "scope: all domains" in text
        assert "| Critical | 2 | 3 |" in text  # 2 findings, 3 places
        assert text.index("## Critical (2)") < text.index("## High (4)") < text.index("## Medium (1)")
        assert "<https://nvd.nist.gov/vuln/detail/CVE-2021-41773>" in text
        assert "| HTTP headers | No HSTS |" in text
        assert "| 198.51.100.7 | mail.other.org | 3306/tcp | MySQL |" in text
        assert "1 low finding(s)" in text
        assert "No Referrer-Policy" not in text

    def test_secrets_are_masked(self, db):
        text = render_report(db, now=NOW)
        assert SECRET not in text
        assert "AKIA…" in text

    def test_table_cells_escape_pipes(self, db):
        db.insert_result("webtech", "ip", db.get_ip_by_address("192.0.2.2")["id"], {
            "port": 80, "url": "http://api.example.com/",
            "security_headers": {"findings": [
                {"severity": "medium", "title": "Weak CSP | unsafe-inline", "detail": "a|b"}]}})
        assert "Weak CSP \\| unsafe-inline" in render_report(db, now=NOW)

    @pytest.mark.parametrize("cvss, severity", [(9.8, "CRITICAL"), (5.3, "MEDIUM")])
    def test_a_long_cve_description_is_kept_whole(self, db, cvss, severity):
        summary = "An issue was discovered in Example Server. " * 20 + "The end."
        ip = db.upsert_ip("203.0.113.9")
        host = db.upsert_hostname(db.get_domain_by_name("example.com")["id"], "old.example.com")
        db.upsert_resolution(host, ip)
        db.insert_result("nvd", "ip", ip, {"port": 80, "technology": "Example 1.0", "cpe": "cpe:/a:example:server:1.0",
                                          "cves": [{"cve_id": "CVE-2026-0001", "cvss_score": cvss,
                                                    "cvss_severity": severity,
                                                    "summary": summary}]})
        assert summary.strip() in render_report(db, now=NOW)

    def test_empty_database(self, tmp_path):
        with Database(tmp_path / "e.db") as empty:
            empty.init_schema()
            text = render_report(empty, now=NOW)
        assert "## Critical (0)\n\nNone found." in text
        assert "Not listed" not in text


class TestDownload:
    @pytest.fixture
    def client(self, db, tmp_path):
        return TestClient(create_app(db_path=str(db.path), config_path=str(tmp_path / "none.yaml")))

    def test_download(self, client):
        r = client.get("/findings.md")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/markdown")
        assert 'attachment; filename="posint-findings-' in r.headers["content-disposition"]
        assert "CVE-2021-41773" in r.text and "No DMARC record" in r.text

    def test_selected_domains_only(self, client):
        r = client.get("/findings.md", params={"domain": "example.com"})
        assert "scope: example.com" in r.text
        assert "No DMARC record" not in r.text

    def test_linked_from_dashboard_overview_and_domain(self, client):
        assert 'formaction="/findings.md"' in client.get("/").text
        assert 'href="/findings.md?domain=example.com"' in client.get(
            "/overview", params={"domain": "example.com"}).text
        assert 'href="/findings.md?domain=example.com"' in client.get("/domains/example.com").text


def test_cli_export_findings(db, tmp_path):
    from typer.testing import CliRunner

    from posint_scanner.cli import app

    out = tmp_path / "findings.md"
    result = CliRunner().invoke(
        app, ["export", "--format", "findings", "--output", str(out), "--db", db.path])
    assert result.exit_code == 0, result.output
    assert "CVE-2021-41773" in out.read_text()
