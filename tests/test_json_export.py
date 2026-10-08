import json

import pytest

from posint_scanner.db import Database
from posint_scanner.export.csv_export import export_service_rows
from posint_scanner.export.json_export import export_json


@pytest.fixture
def db():
    database = Database(":memory:")
    database.init_schema()
    yield database
    database.close()


class TestExportJson:
    def test_structure_includes_domains_and_ips(self, db):
        domain_id = db.upsert_domain("example.com")
        hostname_id = db.upsert_hostname(domain_id, "api.example.com")
        ip_id = db.upsert_ip("1.2.3.4")
        db.upsert_resolution(hostname_id, ip_id)
        db.upsert_service(ip_id, 443, "tcp", "nginx")
        db.insert_result("shodan", "ip", ip_id, {"org": "Example Inc"})

        result = export_json(db)

        assert result["domains"][0]["name"] == "example.com"
        assert result["domains"][0]["hostnames"][0]["name"] == "api.example.com"
        assert result["domains"][0]["hostnames"][0]["ips"] == ["1.2.3.4"]

        ip_entry = result["ips"][0]
        assert ip_entry["address"] == "1.2.3.4"
        assert ip_entry["services"][0]["port"] == 443
        assert ip_entry["results"][0]["data"] == {"org": "Example Inc"}

    def test_includes_domain_level_results(self, db):
        domain_id = db.upsert_domain("example.com")
        db.insert_result("rdap", "domain", domain_id, {"registrar": "Example Registrar"})
        entry = export_json(db)["domains"][0]
        assert entry["results"][0]["source"] == "rdap"
        assert entry["results"][0]["data"] == {"registrar": "Example Registrar"}

    def test_includes_cloud_assets(self, db):
        domain_id = db.upsert_domain("example.com")
        db.upsert_cloud_asset(domain_id, "s3", "example-backups",
                              "https://example-backups.s3.amazonaws.com/", "public", "bucketsearch")
        entry = export_json(db)["domains"][0]
        assert entry["cloud_assets"][0]["name"] == "example-backups"
        assert entry["cloud_assets"][0]["provider"] == "s3"
        assert entry["cloud_assets"][0]["exposure"] == "public"

    def test_includes_candidate_domains(self, db):
        domain_id = db.upsert_domain("example.com")
        db.upsert_candidate_domain(domain_id, "brand.co.uk", "reverse-ip", "1.2.3.4")
        entry = export_json(db)["domains"][0]
        assert entry["candidate_domains"][0]["name"] == "brand.co.uk"
        assert entry["candidate_domains"][0]["source"] == "reverse-ip"
        assert entry["candidate_domains"][0]["via"] == "1.2.3.4"

    def test_includes_service_version(self, db):
        ip_id = db.upsert_ip("1.2.3.4")
        db.upsert_service(ip_id, 443, "tcp", "nginx", "1.18.0")

        result = export_json(db)

        assert result["ips"][0]["services"][0]["version"] == "1.18.0"

    def test_is_json_serializable(self, db):
        db.upsert_domain("example.com")
        result = export_json(db)
        json.dumps(result, default=str)


class TestExportServiceRows:
    def test_one_row_per_service(self, db):
        domain_id = db.upsert_domain("example.com")
        hostname_id = db.upsert_hostname(domain_id, "api.example.com")
        ip_id = db.upsert_ip("1.2.3.4")
        db.upsert_resolution(hostname_id, ip_id)
        db.upsert_service(ip_id, 443, "tcp", "nginx")
        db.upsert_service(ip_id, 22, "tcp", "OpenSSH")

        rows = export_service_rows(db)

        assert len(rows) == 2
        ports = {row["port"] for row in rows}
        assert ports == {443, 22}
        assert rows[0]["hostnames"] == "api.example.com"

    def test_ip_with_no_services_still_gets_a_row(self, db):
        db.upsert_ip("1.2.3.4")
        rows = export_service_rows(db)
        assert len(rows) == 1
        assert rows[0]["port"] == ""

    def test_includes_version_column(self, db):
        ip_id = db.upsert_ip("1.2.3.4")
        db.upsert_service(ip_id, 443, "tcp", "nginx", "1.18.0")
        rows = export_service_rows(db)
        assert rows[0]["version"] == "1.18.0"

    def test_includes_code_exposures(self, db):
        domain_id = db.upsert_domain("example.com")
        db.upsert_code_exposure(domain_id, kind="secret", target="api.example.com",
                                repo="acme/app", path=".env", commit="a" * 40,
                                url="https://github.com/x#L2", line=2,
                                rule="github_token", secret="ghp_xxx")
        entry = export_json(db)["domains"][0]
        assert entry["code_exposures"][0]["kind"] == "secret"
        assert entry["code_exposures"][0]["secret"] == "ghp_xxx"
        assert entry["code_exposures"][0]["commit"] == "a" * 40


class TestCodeExposureCsv:
    def test_sibling_csv_written_with_secrets(self, db, tmp_path):
        from posint_scanner.export.csv_export import write_csv
        domain_id = db.upsert_domain("example.com")
        db.upsert_code_exposure(domain_id, kind="secret", target="api.example.com",
                                repo="acme/app", path=".env", commit="a" * 40,
                                url="https://github.com/x#L2", line=2, rule="jwt", secret="eyJ")
        out = tmp_path / "scan.csv"
        write_csv(db, out)
        sibling = tmp_path / "scan.code_exposures.csv"
        assert sibling.exists()
        text = sibling.read_text()
        assert "acme/app" in text and "eyJ" in text and "example.com" in text
