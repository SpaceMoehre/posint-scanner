import shutil

import pytest

from posint_scanner.db import Database
from posint_scanner.export.obsidian_export import (
    export_obsidian,
    render_domain_note,
    render_hostname_note,
    render_ip_note,
    slugify,
)


class TestSlugify:
    def test_leaves_normal_hostname_untouched(self):
        assert slugify("api.example.com") == "api.example.com"

    def test_replaces_unsafe_characters(self):
        assert slugify("weird/name?.com") == "weird_name_.com"


class TestRenderDomainNote:
    def test_includes_hostnames_as_wikilinks(self):
        content = render_domain_note("example.com", ["api.example.com", "www.example.com"])
        assert "[[api.example.com]]" in content
        assert "[[www.example.com]]" in content
        assert "# example.com" in content
        assert "Candidate domains" not in content

    def test_includes_domain_level_results(self):
        content = render_domain_note(
            "example.com", [], results=[("rdap", {"registrar": "Example Registrar"})]
        )
        assert "rdap" in content
        assert "Example Registrar" in content

    def test_lists_cloud_assets_with_exposure(self):
        content = render_domain_note(
            "example.com", [],
            cloud_assets=[{"provider": "s3", "name": "example-backups",
                           "url": "https://example-backups.s3.amazonaws.com/", "exposure": "public"}],
        )
        assert "## Cloud storage" in content
        assert "example-backups" in content
        assert "public" in content

    def test_lists_candidate_domains_as_plain_text(self):
        content = render_domain_note(
            "example.com",
            [],
            [{"name": "brand.co.uk", "source": "virustotal", "via": "1.2.3.4"}],
        )
        assert "## Candidate domains (not scanned)" in content
        assert "- brand.co.uk - via virustotal (1.2.3.4)" in content
        assert "[[brand.co.uk]]" not in content  # no note exists for it


class TestRenderHostnameNote:
    def test_includes_parent_domain_link_and_resolved_ips(self):
        content = render_hostname_note(
            name="api.example.com",
            domain="example.com",
            ip_addresses=["1.2.3.4"],
            results=[("shodan", {"org": "Example Inc"})],
            first_seen="2026-01-01T00:00:00+00:00",
            last_seen="2026-01-02T00:00:00+00:00",
        )
        assert '"[[example.com]]"' in content
        assert '"[[1.2.3.4]]"' in content
        assert "- source/shodan" in content
        assert "Example Inc" in content

    def test_no_results_still_renders(self):
        content = render_hostname_note(
            name="api.example.com",
            domain="example.com",
            ip_addresses=[],
            results=[],
            first_seen="2026-01-01T00:00:00+00:00",
            last_seen="2026-01-01T00:00:00+00:00",
        )
        assert "# api.example.com" in content


class TestRenderIpNote:
    def test_includes_services_and_backlink_hostnames(self):
        content = render_ip_note(
            address="1.2.3.4",
            hostnames=["api.example.com", "www.example.com"],
            services=[{"port": 443, "protocol": "tcp", "banner": "nginx"}],
            results=[("qualys_ssllabs", {"grade": "A"})],
            first_seen="2026-01-01T00:00:00+00:00",
            last_seen="2026-01-01T00:00:00+00:00",
        )
        assert "443/tcp" in content
        assert "nginx" in content
        assert "[[api.example.com]]" in content
        assert "[[www.example.com]]" in content
        assert "- source/qualys_ssllabs" in content
        assert "- port/443" in content

    def test_includes_service_version_when_present(self):
        content = render_ip_note(
            address="1.2.3.4",
            hostnames=[],
            services=[{"port": 443, "protocol": "tcp", "banner": "nginx", "version": "1.18.0"}],
            results=[],
            first_seen="2026-01-01T00:00:00+00:00",
            last_seen="2026-01-01T00:00:00+00:00",
        )
        assert "443/tcp - nginx 1.18.0" in content

    def test_renders_service_without_banner_or_version(self):
        content = render_ip_note(
            address="1.2.3.4",
            hostnames=[],
            services=[{"port": 22, "protocol": "tcp", "banner": None, "version": None}],
            results=[],
            first_seen="2026-01-01T00:00:00+00:00",
            last_seen="2026-01-01T00:00:00+00:00",
        )
        assert "- 22/tcp" in content


class TestExportObsidian:
    @pytest.fixture
    def db(self):
        database = Database(":memory:")
        database.init_schema()
        yield database
        database.close()

    def test_writes_domain_hostname_and_ip_files(self, db, tmp_path):
        domain_id = db.upsert_domain("example.com")
        hostname_id = db.upsert_hostname(domain_id, "api.example.com")
        ip_id = db.upsert_ip("1.2.3.4")
        db.upsert_resolution(hostname_id, ip_id)
        db.upsert_service(ip_id, 443, "tcp", "nginx")
        db.insert_result("shodan", "ip", ip_id, {"org": "Example Inc"})

        output_dir = tmp_path / "vault"
        export_obsidian(db, output_dir)

        assert (output_dir / "Domains" / "example.com.md").exists()
        assert (output_dir / "Hosts" / "api.example.com.md").exists()
        assert (output_dir / "IPs" / "1.2.3.4.md").exists()
        assert (output_dir / "_Overview.md").exists()

    def test_overview_surfaces_exposed_service_and_cve(self, db, tmp_path):
        domain_id = db.upsert_domain("example.com")
        hostname_id = db.upsert_hostname(domain_id, "db.example.com")
        ip_id = db.upsert_ip("1.2.3.4")
        db.upsert_resolution(hostname_id, ip_id)
        db.upsert_service(ip_id, 3306, "tcp", "MySQL")
        db.insert_result(
            "nvd",
            "ip",
            ip_id,
            {
                "port": 3306,
                "technology": "MySQL",
                "cpe": "cpe:2.3:a:oracle:mysql:5.7:*:*:*:*:*:*:*",
                "cves": [{"cve_id": "CVE-9999-1", "cvss_score": 9.8,
                          "cvss_severity": "CRITICAL", "summary": "rce"}],
            },
        )

        output_dir = tmp_path / "vault"
        export_obsidian(db, output_dir)

        overview = (output_dir / "_Overview.md").read_text()
        assert "| 3306/tcp | MySQL |" in overview  # exposed sensitive service
        assert "CVE-9999-1" in overview  # critical CVE listed
        assert "[[1.2.3.4]]" in overview  # links back to the IP note

    def test_regenerates_and_removes_stale_files(self, db, tmp_path):
        output_dir = tmp_path / "vault"
        output_dir.mkdir()
        (output_dir / "Domains").mkdir()
        stale_file = output_dir / "Domains" / "stale.md"
        stale_file.write_text("stale")

        db.upsert_domain("example.com")
        export_obsidian(db, output_dir)

        assert not stale_file.exists()
        assert (output_dir / "Domains" / "example.com.md").exists()

    def test_lists_code_exposures_with_secret(self):
        content = render_domain_note(
            "example.com", [],
            code_exposures=[{"kind": "secret", "target": "api.example.com", "repo": "acme/app",
                             "path": ".env", "url": "https://github.com/x#L2",
                             "rule": "github_token", "secret": "ghp_xxx"}],
        )
        assert "## GitHub exposures" in content
        assert "ghp_xxx" in content
        assert "github_token" in content
