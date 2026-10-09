import time
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from posint_scanner.db import Database
from posint_scanner.web.app import create_app


@pytest.fixture
def seeded_db(tmp_path):
    """A DB with one host exposing SMBv1 on 445 and carrying a critical CVE."""
    db_path = tmp_path / "web.db"
    with Database(db_path) as db:
        db.init_schema()
        domain_id = db.upsert_domain("dns-net.de")
        hostname_id = db.upsert_hostname(domain_id, "diamant-db.dns-net.de")
        ip_id = db.upsert_ip("212.86.33.249")
        db.upsert_resolution(hostname_id, ip_id)
        db.upsert_service(ip_id, 445, "tcp", "SMB Status:\n  SMB Version: 1\n  OS: Windows")
        db.upsert_service(ip_id, 135, "tcp", "Microsoft RPC Endpoint Mapper")
        db.insert_result(
            "nvd", "ip", ip_id,
            {"port": 445, "technology": "SMB", "cpe": "c",
             "cves": [{"cve_id": "CVE-2017-0144", "cvss_score": 9.3,
                       "cvss_severity": "CRITICAL", "summary": "EternalBlue"}]},
        )
    return str(db_path)


@pytest.fixture
def client(seeded_db, tmp_path):
    app = create_app(db_path=seeded_db, config_path=str(tmp_path / "none.yaml"),
                     vault_dir=str(tmp_path / "vault"))
    return TestClient(app)


class TestReadPages:
    def test_dashboard_lists_domain_and_scan_form(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert "dns-net.de" in r.text
        assert 'action="/scans"' in r.text

    def test_dashboard_renders_a_toggle_per_source(self, client):
        r = client.get("/")
        assert 'name="source" value="crtsh" checked' in r.text
        assert 'name="source" value="shodan_web">' in r.text  # scraper: opt-in
        assert "scrape" in r.text

    def test_overview_shows_smbv1_and_links_ip(self, client):
        r = client.get("/overview")
        assert r.status_code == 200
        assert "SMBv1 enabled" in r.text
        assert "/ips/212.86.33.249" in r.text
        assert "445/tcp" in r.text

    def test_overview_tags_and_filters_by_domain(self, seeded_db, tmp_path):
        with Database(seeded_db) as db:
            other_id = db.upsert_domain("other.org")
            hostname_id = db.upsert_hostname(other_id, "db.other.org")
            ip_id = db.upsert_ip("198.51.100.7")
            db.upsert_resolution(hostname_id, ip_id)
            db.upsert_service(ip_id, 3306, "tcp", "MySQL")
        app = create_app(db_path=seeded_db, config_path=str(tmp_path / "none.yaml"),
                         vault_dir=str(tmp_path / "vault"))
        c = TestClient(app)

        r = c.get("/overview")
        assert "/overview?domain=other.org" in r.text
        assert "198.51.100.7" in r.text and "212.86.33.249" in r.text

        r = c.get("/overview?domain=other.org")
        assert "198.51.100.7" in r.text
        assert "212.86.33.249" not in r.text

        r = c.get("/overview?domain=dns-net.de")
        assert "212.86.33.249" in r.text
        assert "198.51.100.7" not in r.text

    def test_ip_page_shows_services_and_cve(self, client):
        r = client.get("/ips/212.86.33.249")
        assert r.status_code == 200
        assert "445/tcp" in r.text
        assert "CVE-2017-0144" in r.text
        assert "CRITICAL" in r.text

    def test_host_page_redirects_to_ip(self, client):
        r = client.get("/hosts/diamant-db.dns-net.de", follow_redirects=False)
        assert r.status_code == 302
        assert r.headers["location"] == "/ips/212.86.33.249#host-diamant-db.dns-net.de"

    def test_unresolved_host_keeps_own_page(self, seeded_db, tmp_path):
        with Database(seeded_db) as db:
            domain_id = db.get_domain_by_name("dns-net.de")["id"]
            db.upsert_hostname(domain_id, "gone.dns-net.de")
        app = create_app(db_path=seeded_db, config_path=str(tmp_path / "none.yaml"),
                         vault_dir=str(tmp_path / "vault"))
        r = TestClient(app).get("/hosts/gone.dns-net.de")
        assert r.status_code == 200
        assert "No resolved IP addresses" in r.text

    def test_ip_page_shows_hostname_details(self, seeded_db, tmp_path):
        with Database(seeded_db) as db:
            h_id = db.get_hostname_by_name("diamant-db.dns-net.de")["id"]
            db.insert_result("crtsh", "hostname", h_id, {"issuer": "R11"})
            db.insert_result("qualys_ssllabs", "hostname", h_id, {
                "endpoints": [{"ipAddress": "212.86.33.249", "grade": "B"},
                              {"ipAddress": "10.0.0.1", "grade": "A"}]})
        app = create_app(db_path=seeded_db, config_path=str(tmp_path / "none.yaml"),
                         vault_dir=str(tmp_path / "vault"))
        r = TestClient(app).get("/ips/212.86.33.249")
        assert 'id="host-diamant-db.dns-net.de"' in r.text
        assert "crtsh" in r.text and '"issuer": "R11"' in r.text
        assert "<td data-values=\"B\">B</td>" in r.text

    def test_domain_page_lists_hostname(self, client):
        r = client.get("/domains/dns-net.de")
        assert r.status_code == 200
        assert "diamant-db.dns-net.de" in r.text

    def test_domain_page_has_detailed_hostname_and_service_tables(self, client):
        r = client.get("/domains/dns-net.de")
        assert r.text.count('<table class="dt">') >= 2
        assert "/ips/212.86.33.249" in r.text  # hostname row links its IP
        assert "445" in r.text and "SMB" in r.text  # service + sensitive flag
        assert "CRITICAL" in r.text  # worst CVE severity for the hostname

    def test_overview_lists_individual_cves(self, client):
        r = client.get("/overview")
        assert "All CVEs" in r.text
        assert "nvd.nist.gov/vuln/detail/CVE-2017-0144" in r.text

    def test_dashboard_shows_per_domain_stats(self, client):
        r = client.get("/")
        assert "/overview?domain=dns-net.de" in r.text
        assert '<span class="sev sev-CRITICAL">2</span>' in r.text  # SMBv1 + CVE

    def test_domain_page_shows_domain_level_results(self, seeded_db, tmp_path):
        with Database(seeded_db) as db:
            domain_id = db.get_domain_by_name("dns-net.de")["id"]
            db.insert_result("rdap", "domain", domain_id, {"registrar": "Example Registrar"})
        app = create_app(db_path=seeded_db, config_path=str(tmp_path / "none.yaml"),
                         vault_dir=str(tmp_path / "vault"))
        r = TestClient(app).get("/domains/dns-net.de")
        assert "rdap" in r.text
        assert "Example Registrar" in r.text

    def test_domain_page_flags_public_cloud_bucket(self, seeded_db, tmp_path):
        with Database(seeded_db) as db:
            domain_id = db.get_domain_by_name("dns-net.de")["id"]
            db.upsert_cloud_asset(domain_id, "s3", "dnsnet-backups",
                                  "https://dnsnet-backups.s3.amazonaws.com/", "public", "bucketsearch")
        app = create_app(db_path=seeded_db, config_path=str(tmp_path / "none.yaml"),
                         vault_dir=str(tmp_path / "vault"))
        r = TestClient(app).get("/domains/dns-net.de")
        assert "dnsnet-backups" in r.text
        assert "public" in r.text

    def test_domain_page_lists_email_addresses(self, seeded_db, tmp_path):
        with Database(seeded_db) as db:
            domain_id = db.get_domain_by_name("dns-net.de")["id"]
            db.upsert_email_address(domain_id, "jane@dns-net.de", "hunter", name="Jane Doe",
                                    position="CTO", confidence=94, url="https://dns-net.de/team")
            db.upsert_email_address(domain_id, "jane@dns-net.de", "theharvester")
        app = create_app(db_path=seeded_db, config_path=str(tmp_path / "none.yaml"),
                         vault_dir=str(tmp_path / "vault"))
        r = TestClient(app).get("/domains/dns-net.de")
        assert "Email addresses (1)" in r.text
        assert 'href="https://dns-net.de/team"' in r.text
        assert "hunter, theharvester" in r.text

    def test_domain_page_shows_cloud_findings(self, seeded_db, tmp_path):
        with Database(seeded_db) as db:
            domain_id = db.get_domain_by_name("dns-net.de")["id"]
            db.insert_result("trivy", "domain", domain_id, {
                "target": "acme/api:latest", "target_kind": "image",
                "counts": {"high": 1},
                "findings": [{"tool": "trivy", "kind": "vulnerability", "severity": "high",
                              "id": "CVE-2021-23337", "title": "lodash command injection",
                              "resource": "lodash 4.17.11", "target": "acme/api:latest",
                              "cves": ["CVE-2021-23337"], "reference": None, "location": None}],
            })
        app = create_app(db_path=seeded_db, config_path=str(tmp_path / "none.yaml"),
                         vault_dir=str(tmp_path / "vault"))
        r = TestClient(app).get("/domains/dns-net.de")
        assert "Cloud &amp; IaC findings" in r.text
        assert "CVE-2021-23337" in r.text
        assert "lodash command injection" in r.text

    def test_ip_page_shows_container_exposure(self, seeded_db, tmp_path):
        with Database(seeded_db) as db:
            ip_id = db.upsert_ip("212.86.33.249")
            db.insert_result("container_exposure", "ip", ip_id, {
                "exposures": [{"kind": "docker-api", "port": 2375, "severity": "critical",
                               "detail": "unauthenticated Docker Engine API"}],
                "images": [],
            })
        app = create_app(db_path=seeded_db, config_path=str(tmp_path / "none.yaml"),
                         vault_dir=str(tmp_path / "vault"))
        r = TestClient(app).get("/ips/212.86.33.249")
        assert "Container / orchestration exposure" in r.text
        assert "docker-api" in r.text

    def test_ip_page_shows_web_app_findings(self, seeded_db, tmp_path):
        with Database(seeded_db) as db:
            ip_id = db.get_ip_by_address("212.86.33.249")["id"]
            db.insert_result("nikto", "ip", ip_id, {
                "tool": "nikto", "kind": "web", "severity": "medium",
                "id": "600123", "title": "Vulnerable to Shellshock", "resource": "/cgi-bin/",
                "url": "http://x/", "target": "http://x/", "cves": ["CVE-2014-6271"],
                "reference": None, "location": "GET /cgi-bin/"})
        app = create_app(db_path=seeded_db, config_path=str(tmp_path / "none.yaml"),
                         vault_dir=str(tmp_path / "vault"))
        r = TestClient(app).get("/ips/212.86.33.249")
        assert "Web app scan findings" in r.text
        assert "Vulnerable to Shellshock" in r.text
        assert "CVE-2014-6271" in r.text

    def test_domain_page_shows_subdomain_takeover(self, seeded_db, tmp_path):
        with Database(seeded_db) as db:
            h_id = db.get_hostname_by_name("diamant-db.dns-net.de")["id"]
            db.insert_result("takeover", "hostname", h_id, {
                "tool": "takeover", "kind": "takeover", "severity": "high",
                "id": "github", "title": "Potential subdomain takeover (github)",
                "resource": "diamant-db.dns-net.de", "url": "diamant-db.dns-net.de",
                "target": "diamant-db.dns-net.de", "cves": [], "reference": None,
                "location": "example.github.io"})
        app = create_app(db_path=seeded_db, config_path=str(tmp_path / "none.yaml"),
                         vault_dir=str(tmp_path / "vault"))
        r = TestClient(app).get("/domains/dns-net.de")
        assert "Subdomain takeover" in r.text
        assert "diamant-db.dns-net.de" in r.text
        assert "github" in r.text

    def test_domain_page_offers_candidate_domains_for_scanning(self, seeded_db, tmp_path):
        with Database(seeded_db) as db:
            domain_id = db.get_domain_by_name("dns-net.de")["id"]
            db.upsert_candidate_domain(domain_id, "brand.co.uk", "virustotal", "212.86.33.249")
        app = create_app(db_path=seeded_db, config_path=str(tmp_path / "none.yaml"),
                         vault_dir=str(tmp_path / "vault"))
        r = TestClient(app).get("/domains/dns-net.de")
        assert "brand.co.uk" in r.text
        assert "virustotal" in r.text
        assert 'name="domain" value="brand.co.uk"' in r.text  # one-click scan form
        # the one-click scan runs the default stages, not a stripped-down scan
        for stage in ("netblock_sweep", "vuln_lookup", "fingerprint"):
            assert f'name="{stage}" value="on"' in r.text

    def test_missing_ip_returns_404(self, client):
        assert client.get("/ips/9.9.9.9").status_code == 404

    def test_missing_host_returns_404(self, client):
        assert client.get("/hosts/nope.example.com").status_code == 404


class TestEmptyDb:
    def test_pages_render_before_any_scan(self, tmp_path):
        app = create_app(db_path=str(tmp_path / "empty.db"),
                         config_path=str(tmp_path / "none.yaml"),
                         vault_dir=str(tmp_path / "vault"))
        c = TestClient(app)
        assert c.get("/").status_code == 200
        r = c.get("/overview")
        assert r.status_code == 200
        assert "None found." in r.text


class TestScanLaunch:
    def _wait(self, client, job_id, timeout=5.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            status = client.get(f"/api/scans/{job_id}").json()["status"]
            if status in ("completed", "failed"):
                return status
            time.sleep(0.02)
        return "timeout"

    def test_post_scan_starts_job_and_completes(self, tmp_path):
        app = create_app(db_path=str(tmp_path / "s.db"),
                         config_path=str(tmp_path / "none.yaml"),
                         vault_dir=str(tmp_path / "vault"))
        client = TestClient(app)
        with (
            patch("posint_scanner.web.scans.run_scan") as mock_run,
        ):
            r = client.post("/scans", data={"domain": "example.com"},
                            follow_redirects=False)
            assert r.status_code == 303
            job_id = r.headers["location"].rsplit("/", 1)[1]
            assert self._wait(client, job_id) == "completed"
        mock_run.assert_called_once()
        assert mock_run.call_args.kwargs["tech_fingerprint"] is False  # unchecked box omitted

    def test_scan_options_reflect_checkboxes(self, tmp_path):
        app = create_app(db_path=str(tmp_path / "s.db"),
                         config_path=str(tmp_path / "none.yaml"),
                         vault_dir=str(tmp_path / "vault"))
        client = TestClient(app)
        with (
            patch("posint_scanner.web.scans.run_scan") as mock_run,
        ):
            r = client.post(
                "/scans",
                data={"domain": "example.com", "fingerprint": "on", "vuln_lookup": "on",
                      "netblock_sweep": "on"},
                follow_redirects=False,
            )
            self._wait(client, r.headers["location"].rsplit("/", 1)[1])
        kwargs = mock_run.call_args.kwargs
        assert kwargs["tech_fingerprint"] is True
        assert kwargs["vuln_lookup"] is True
        assert kwargs["netblock_sweep"] is True

    def _post(self, tmp_path, data, config_text=""):
        config_path = tmp_path / "config.yaml"
        config_path.write_text(config_text)
        app = create_app(db_path=str(tmp_path / "s.db"), config_path=str(config_path),
                         vault_dir=str(tmp_path / "vault"))
        client = TestClient(app)
        with (
            patch("posint_scanner.web.scans.run_scan") as mock_run,
        ):
            r = client.post("/scans", data={"domain": "example.com", **data},
                            follow_redirects=False)
            assert self._wait(client, r.headers["location"].rsplit("/", 1)[1]) == "completed"
        return {s.name for s in mock_run.call_args.args[2]}, mock_run.call_args.kwargs

    def test_checked_sources_are_exactly_what_runs(self, tmp_path):
        names, _ = self._post(
            tmp_path, {"sources_form": "1", "source": ["crtsh", "shodan_web"]}
        )
        assert names == {"crtsh", "shodan_web"}

    def test_no_sources_checked_runs_none(self, tmp_path):
        names, _ = self._post(tmp_path, {"sources_form": "1"})
        assert names == set()

    def test_without_source_toggles_config_defaults_apply(self, tmp_path):
        names, _ = self._post(tmp_path, {}, config_text="sources:\n  ping:\n    enabled: false\n")
        assert "ping" not in names
        assert "crtsh" in names

    def test_fresh_and_authorize_scans_reach_the_scan(self, tmp_path):
        names, kwargs = self._post(
            tmp_path,
            {"sources_form": "1", "source": ["qualys_vmdr"], "fresh": "on",
             "authorize_scans": "on"},
        )
        assert kwargs["fresh"] is True

    def test_cloud_scan_and_audit_toggles_reach_the_scan(self, tmp_path):
        _, kwargs = self._post(tmp_path, {"cloud_scan": "on", "cloud_audit": "on"})
        assert kwargs["cloud_scan"] is True
        assert kwargs["cloud_audit"] is True

    def test_cloud_stages_off_when_unchecked(self, tmp_path):
        _, kwargs = self._post(tmp_path, {})
        assert kwargs["cloud_scan"] is False
        assert kwargs["cloud_audit"] is False

    def test_webscan_toggles_reach_the_scan(self, tmp_path):
        _, kwargs = self._post(tmp_path, {"nikto": "on", "wpscan": "on", "takeover": "on"})
        assert kwargs["nikto_scan"] is True
        assert kwargs["wpscan_scan"] is True
        assert kwargs["takeover_scan"] is True

    def test_webscan_stages_off_when_unchecked(self, tmp_path):
        _, kwargs = self._post(tmp_path, {})
        assert kwargs["nikto_scan"] is False
        assert kwargs["wpscan_scan"] is False
        assert kwargs["takeover_scan"] is False

    def test_failed_scan_surfaces_error(self, tmp_path):
        app = create_app(db_path=str(tmp_path / "s.db"),
                         config_path=str(tmp_path / "none.yaml"),
                         vault_dir=str(tmp_path / "vault"))
        client = TestClient(app)
        with (
            patch("posint_scanner.web.scans.run_scan", side_effect=RuntimeError("boom")),
        ):
            r = client.post("/scans", data={"domain": "example.com"}, follow_redirects=False)
            job_id = r.headers["location"].rsplit("/", 1)[1]
            assert self._wait(client, job_id) == "failed"
        assert "boom" in client.get(f"/api/scans/{job_id}").json()["error"]

    def test_api_status_404_for_unknown_job(self, client):
        assert client.get("/api/scans/deadbeef").status_code == 404


class TestScanProgressAndCancel:
    def _app(self, tmp_path):
        return create_app(db_path=str(tmp_path / "s.db"),
                          config_path=str(tmp_path / "none.yaml"),
                          vault_dir=str(tmp_path / "vault"))

    def _wait_status(self, client, job_id, wanted, timeout=5.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if client.get(f"/api/scans/{job_id}").json()["status"] in wanted:
                return client.get(f"/api/scans/{job_id}").json()["status"]
            time.sleep(0.02)
        return client.get(f"/api/scans/{job_id}").json()["status"]

    def test_current_stage_is_reported_in_status(self, tmp_path):
        client = TestClient(self._app(tmp_path))

        def fake_run(db, domains, sources, control=None, **kw):
            control.progress("enrichment", domains[0])

        with (
            patch("posint_scanner.web.scans.run_scan", side_effect=fake_run),
        ):
            r = client.post("/scans", data={"domain": "example.com"}, follow_redirects=False)
            job_id = r.headers["location"].rsplit("/", 1)[1]
            assert self._wait_status(client, job_id, {"completed"}) == "completed"
        job = client.get(f"/api/scans/{job_id}").json()
        assert job["stage"] == "enrichment"

    def test_cancel_stops_a_running_scan(self, tmp_path):
        client = TestClient(self._app(tmp_path))

        def fake_run(db, domains, sources, control=None, **kw):
            control.progress("enrichment", domains[0])
            deadline = time.time() + 5
            while not control.cancelled() and time.time() < deadline:
                time.sleep(0.02)

        with (
            patch("posint_scanner.web.scans.run_scan", side_effect=fake_run),
        ):
            r = client.post("/scans", data={"domain": "example.com"}, follow_redirects=False)
            job_id = r.headers["location"].rsplit("/", 1)[1]
            self._wait_status(client, job_id, {"running"})
            cancel = client.post(f"/scans/{job_id}/cancel", follow_redirects=False)
            assert cancel.status_code == 303
            assert self._wait_status(client, job_id, {"cancelled"}) == "cancelled"

    def test_cancel_unknown_job_is_404(self, tmp_path):
        client = TestClient(self._app(tmp_path))
        assert client.post("/scans/deadbeef/cancel").status_code == 404

    def test_domain_page_shows_code_exposures_and_secret(self, seeded_db, tmp_path):
        with Database(seeded_db) as db:
            domain_id = db.get_domain_by_name("dns-net.de")["id"]
            db.upsert_code_exposure(
                domain_id, kind="secret", target="diamant-db.dns-net.de", repo="acme/app",
                path="app/.env", commit="a" * 40,
                url="https://github.com/acme/app/blob/" + "a" * 40 + "/app/.env#L4", line=4,
                rule="aws_access_key_id", secret="AKIASECRETVALUE12345")
        app = create_app(db_path=seeded_db, config_path=str(tmp_path / "none.yaml"),
                         vault_dir=str(tmp_path / "vault"))
        r = TestClient(app).get("/domains/dns-net.de")
        assert "GitHub exposures" in r.text
        assert "acme/app" in r.text
        assert "AKIASECRETVALUE12345" in r.text  # full value present (reveal)
        assert "aws_access_key_id" in r.text

    def test_ip_page_shows_code_exposures(self, seeded_db, tmp_path):
        with Database(seeded_db) as db:
            domain_id = db.get_domain_by_name("dns-net.de")["id"]
            db.upsert_code_exposure(
                domain_id, kind="reference", target="212.86.33.249", repo="acme/ops",
                path="hosts.yml", commit="c" * 40,
                url="https://github.com/acme/ops/blob/" + "c" * 40 + "/hosts.yml#L9", line=9)
        app = create_app(db_path=seeded_db, config_path=str(tmp_path / "none.yaml"),
                         vault_dir=str(tmp_path / "vault"))
        r = TestClient(app).get("/ips/212.86.33.249")
        assert "GitHub exposures" in r.text
        assert "acme/ops" in r.text


class TestDeleteAndExport:
    def test_delete_removes_domain_and_redirects(self, client):
        r = client.post("/domains/dns-net.de/delete", follow_redirects=False)
        assert r.status_code == 303
        assert client.get("/domains/dns-net.de").status_code == 404
        assert "dns-net.de" not in client.get("/").text

    def test_delete_unknown_domain_is_404(self, client):
        assert client.post("/domains/nope.com/delete").status_code == 404

    def test_delete_refused_while_a_scan_runs(self, client):
        with patch("posint_scanner.web.scans.ScanManager.busy", return_value=True):
            r = client.post("/domains/dns-net.de/delete")
        assert r.status_code == 409
        assert client.get("/domains/dns-net.de").status_code == 200

    def test_export_zip_has_everything(self, client):
        import io
        import zipfile

        r = client.get("/export.zip")
        assert r.status_code == 200
        assert r.headers["content-type"] == "application/zip"
        assert "attachment" in r.headers["content-disposition"]
        names = zipfile.ZipFile(io.BytesIO(r.content)).namelist()
        assert {"results.json", "services.csv", "posint.db"} <= set(names)
        assert any(n.startswith("vault/Domains/") for n in names)

    def test_export_zip_selected_domains_only(self, client):
        import io
        import json
        import zipfile

        every = [d["name"] for d in json.loads(zipfile.ZipFile(
            io.BytesIO(client.get("/export.zip").content)).read("results.json"))["domains"]]
        assert every
        r = client.get("/export.zip", params={"domain": every[0]})
        z = zipfile.ZipFile(io.BytesIO(r.content))
        got = [d["name"] for d in json.loads(z.read("results.json"))["domains"]]
        assert got == [every[0]]
        assert [n for n in z.namelist() if n.startswith("vault/Domains/")] == [
            f"vault/Domains/{every[0]}.md"]


class TestWebLinks:
    def test_web_url_detection(self):
        from posint_scanner.web.views import web_url

        svc = lambda port, banner=None, protocol="tcp": {  # noqa: E731
            "port": port, "banner": banner, "protocol": protocol}
        assert web_url("192.0.2.1", svc(80), {}) == "http://192.0.2.1/"
        assert web_url("192.0.2.1", svc(443), {}) == "https://192.0.2.1/"
        assert web_url("192.0.2.1", svc(8443), {}) == "https://192.0.2.1:8443/"
        assert web_url("192.0.2.1", svc(8123, "HTTP/1.1 200 OK"), {}) == "http://192.0.2.1:8123/"
        assert web_url("192.0.2.1", svc(8123, "x"), {8123: "https://a.example:8123/"}) == (
            "https://a.example:8123/")
        assert web_url("2001:db8::1", svc(80), {}) == "http://[2001:db8::1]/"
        assert web_url("192.0.2.1", svc(22, "SSH-2.0-OpenSSH_8.9"), {}) is None
        assert web_url("192.0.2.1", svc(80, protocol="udp"), {}) is None

    def test_ip_page_links_hostnames_and_web_ports(self, client):
        r = client.get("/ips/212.86.33.249")
        assert 'href="http://diamant-db.dns-net.de"' in r.text
        assert "open ↗" not in r.text  # seeded services are SMB/RPC only

    def test_ip_page_links_web_service(self, seeded_db, tmp_path):
        with Database(seeded_db) as db:
            db.upsert_service(db.get_ip_by_address("212.86.33.249")["id"], 443, "tcp", None)
        app = create_app(db_path=seeded_db, config_path=str(tmp_path / "none.yaml"),
                         vault_dir=str(tmp_path / "vault"))
        r = TestClient(app).get("/ips/212.86.33.249")
        assert 'href="https://212.86.33.249/"' in r.text


class TestLookalikePage:
    def test_domain_page_shows_registered_lookalikes(self, seeded_db, tmp_path):
        with Database(seeded_db) as db:
            domain_id = db.get_domain_by_name("dns-net.de")["id"]
            db.insert_result("lookalike", "domain", domain_id, {
                "checked": 120,
                "registered": [
                    {"name": "dns-net.co", "addresses": ["9.9.9.9"], "mx": []},
                    {"name": "dsn-net.de", "addresses": [], "mx": ["0 mail.evil."]},
                ],
            })
        app = create_app(db_path=seeded_db, config_path=str(tmp_path / "none.yaml"),
                         vault_dir=str(tmp_path / "vault"))
        r = TestClient(app).get("/domains/dns-net.de")
        assert "Registered look-alike domains (2)" in r.text
        assert "dns-net.co" in r.text
        assert "9.9.9.9" in r.text
        assert "dsn-net.de" in r.text


class TestExploitColumn:
    def test_ip_page_links_exploit_when_present(self, seeded_db, tmp_path):
        with Database(seeded_db) as db:
            ip_id = db.get_ip_by_address("212.86.33.249")["id"]
            db.insert_result("nvd", "ip", ip_id, {
                "port": 445, "technology": "SMB", "cpe": "c",
                "cves": [{
                    "cve_id": "CVE-2017-0144", "cvss_score": 9.3, "cvss_severity": "CRITICAL",
                    "summary": "EternalBlue",
                    "exploits": [{"title": "EternalBlue", "edb_id": "42315",
                                  "url": "https://www.exploit-db.com/exploits/42315"}],
                }],
            })
        app = create_app(db_path=seeded_db, config_path=str(tmp_path / "none.yaml"),
                         vault_dir=str(tmp_path / "vault"))
        r = TestClient(app).get("/ips/212.86.33.249")
        assert "https://www.exploit-db.com/exploits/42315" in r.text
        assert "EDB-42315" in r.text


class TestOriginIpPage:
    def test_domain_page_shows_origin_candidates(self, seeded_db, tmp_path):
        with Database(seeded_db) as db:
            domain_id = db.get_domain_by_name("dns-net.de")["id"]
            db.insert_result("origin_ip", "domain", domain_id, {
                "behind_cdn": True, "cdn": "cloudflare",
                "frontend_ips": ["104.16.5.5"],
                "origin_candidates": [{"ip": "203.0.113.10", "via": ["mx:mail.dns-net.de"]}],
            })
        app = create_app(db_path=seeded_db, config_path=str(tmp_path / "none.yaml"),
                         vault_dir=str(tmp_path / "vault"))
        r = TestClient(app).get("/domains/dns-net.de")
        assert "Possible origin IPs behind cloudflare (1)" in r.text
        assert "203.0.113.10" in r.text
        assert "mx:mail.dns-net.de" in r.text

    def test_no_origin_section_when_not_behind_cdn(self, seeded_db, tmp_path):
        with Database(seeded_db) as db:
            domain_id = db.get_domain_by_name("dns-net.de")["id"]
            db.insert_result("origin_ip", "domain", domain_id, {
                "behind_cdn": False, "cdn": None,
                "frontend_ips": ["203.0.113.5"], "origin_candidates": [],
            })
        app = create_app(db_path=seeded_db, config_path=str(tmp_path / "none.yaml"),
                         vault_dir=str(tmp_path / "vault"))
        r = TestClient(app).get("/domains/dns-net.de")
        assert "Possible origin IPs" not in r.text


class TestNucleiPage:
    def test_ip_page_shows_nuclei_findings_sorted_by_severity(self, seeded_db, tmp_path):
        with Database(seeded_db) as db:
            ip_id = db.get_ip_by_address("212.86.33.249")["id"]
            db.insert_result("nuclei", "ip", ip_id, {
                "template_id": "ssl-dns-names", "name": "SSL", "severity": "info",
                "matched_at": "https://212.86.33.249/", "type": "ssl", "cves": [],
                "cvss_score": None, "tags": [], "reference": []})
            db.insert_result("nuclei", "ip", ip_id, {
                "template_id": "CVE-2024-36401", "name": "GeoServer RCE",
                "severity": "critical", "matched_at": "http://212.86.33.249:8080/geoserver/ows",
                "type": "http", "cves": ["CVE-2024-36401"], "cvss_score": 9.8,
                "tags": ["rce"], "reference": []})
        app = create_app(db_path=seeded_db, config_path=str(tmp_path / "none.yaml"),
                         vault_dir=str(tmp_path / "vault"))
        r = TestClient(app).get("/ips/212.86.33.249")
        assert "Nuclei findings (2)" in r.text
        assert "CVE-2024-36401" in r.text
        assert "geoserver/ows" in r.text
        # critical sorts before the info finding
        assert r.text.index("CVE-2024-36401") < r.text.index("ssl-dns-names")


class TestSettings:
    def test_settings_page_renders_and_is_linked(self, client):
        assert 'href="/settings"' in client.get("/").text
        r = client.get("/settings")
        assert r.status_code == 200
        assert 'name="proxy_url"' in r.text

    def test_save_proxy_normalises_and_persists(self, client, seeded_db):
        with patch("posint_scanner.proxy.check_reachable"):
            r = client.post("/settings", data={"proxy_url": "socks5://127.0.0.1:9050",
                                               "proxy_dns_server": "9.9.9.9"})
        assert r.status_code == 200
        assert "Saved." in r.text
        with Database(seeded_db) as db:
            assert db.get_settings() == {"proxy_url": "socks5h://127.0.0.1:9050",
                                         "proxy_dns_server": "9.9.9.9"}
        assert 'value="socks5h://127.0.0.1:9050"' in client.get("/settings").text

    def test_unreachable_proxy_saves_with_warning(self, client):
        from posint_scanner.proxy import ProxyUnavailableError

        with patch("posint_scanner.proxy.check_reachable",
                   side_effect=ProxyUnavailableError("proxy down")):
            r = client.post("/settings", data={"proxy_url": "127.0.0.1:9"})
        assert "Saved." in r.text and "proxy down" in r.text

    def test_invalid_proxy_rejected(self, client, seeded_db):
        r = client.post("/settings", data={"proxy_url": "http://127.0.0.1:3128"})
        assert r.status_code == 400
        assert "unsupported proxy scheme" in r.text
        with Database(seeded_db) as db:
            assert db.get_settings() == {}

    def test_clearing_proxy_deletes_it(self, client, seeded_db):
        with Database(seeded_db) as db:
            db.set_setting("proxy_url", "socks5h://127.0.0.1:9050")
        client.post("/settings", data={"proxy_url": ""})
        with Database(seeded_db) as db:
            assert db.get_settings() == {}

    def test_save_refused_while_a_scan_runs(self, client):
        with patch("posint_scanner.web.scans.ScanManager.busy", return_value=True):
            r = client.post("/settings", data={"proxy_url": "127.0.0.1:9050"})
        assert r.status_code == 409

    def test_test_button_runs_checks_without_saving(self, client, seeded_db):
        from posint_scanner.proxy import ProxyCheck

        with patch("posint_scanner.proxy.verify_proxy",
                   return_value=[ProxyCheck("Proxy reachable", True, "ok"),
                                 ProxyCheck("HTTPS through proxy", True, "exit IP 203.0.113.9")]) as v:
            r = client.post("/settings/test", data={"proxy_url": "127.0.0.1:9050",
                                                    "proxy_dns_server": "9.9.9.9"})
        assert r.status_code == 200
        assert "Proxy test: working" in r.text and "203.0.113.9" in r.text
        assert v.call_args.args[0].dns_server == "9.9.9.9"
        assert 'value="127.0.0.1:9050"' in r.text  # form keeps what was typed
        with Database(seeded_db) as db:
            assert db.get_settings() == {}

    def test_test_button_shows_failure(self, client):
        from posint_scanner.proxy import ProxyCheck

        with patch("posint_scanner.proxy.verify_proxy",
                   return_value=[ProxyCheck("Proxy reachable", False, "refused")]):
            r = client.post("/settings/test", data={"proxy_url": "127.0.0.1:9"})
        assert "Proxy test: failed" in r.text and "refused" in r.text

    def test_test_button_needs_a_valid_proxy(self, client):
        assert client.post("/settings/test", data={"proxy_url": ""}).status_code == 400
        r = client.post("/settings/test", data={"proxy_url": "http://h:1"})
        assert r.status_code == 400 and "Not tested" in r.text

    def test_settings_page_has_test_button(self, client):
        assert 'formaction="/settings/test"' in client.get("/settings").text
