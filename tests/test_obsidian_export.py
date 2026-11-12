import zipfile

import pytest

from posint_scanner.db import Database
from posint_scanner.export.obsidian_export import (
    export_obsidian,
    group_hosts,
    render_domain_note,
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


class TestGroupHosts:
    """A host note is about one IP - or one hostname, when it has several."""

    def _notes(self, ips_of, addresses):
        notes, note_for = group_hosts(ips_of, addresses)
        return {n["name"]: (n["ips"], n["hostnames"]) for n in notes}, note_for

    def test_a_note_per_ip_with_its_single_ip_hostnames(self):
        notes, note_for = self._notes(
            {"a.example.com": ["192.0.2.1"], "b.example.com": ["192.0.2.1"]},
            ["192.0.2.1", "192.0.2.9"])
        assert notes == {"192.0.2.1": (["192.0.2.1"], ["a.example.com", "b.example.com"]),
                         "192.0.2.9": (["192.0.2.9"], [])}
        assert note_for["a.example.com"] == "192.0.2.1"

    def test_a_hostname_with_several_ips_is_one_note_for_all_of_them(self):
        notes, note_for = self._notes(
            {"www.example.com": ["192.0.2.1", "192.0.2.2"], "cdn.example.com": ["192.0.2.2", "192.0.2.1"],
             "api.example.com": ["192.0.2.2"]},
            ["192.0.2.1", "192.0.2.2", "192.0.2.3"])
        # same IP set: one note, named after the first hostname; a name on one
        # of its IPs lands there too
        assert notes == {
            "cdn.example.com": (["192.0.2.1", "192.0.2.2"],
                                ["cdn.example.com", "www.example.com", "api.example.com"]),
            "192.0.2.3": (["192.0.2.3"], []),
        }
        assert note_for["192.0.2.2"] == note_for["www.example.com"] == "cdn.example.com"


@pytest.fixture
def db():
    database = Database(":memory:")
    database.init_schema()
    domain_id = database.upsert_domain("example.com")
    www = database.upsert_hostname(domain_id, "www.example.com")
    mail = database.upsert_hostname(domain_id, "mail.example.com")
    database.upsert_hostname(domain_id, "old.example.com")  # resolves nowhere
    ip1, ip2, ip3 = (database.upsert_ip(a) for a in ("192.0.2.1", "192.0.2.2", "192.0.2.3"))
    database.upsert_resolution(www, ip1)
    database.upsert_resolution(www, ip2)
    database.upsert_resolution(mail, ip3)
    database.upsert_service(ip1, 443, "tcp", "nginx", "1.18.0")
    database.upsert_service(ip2, 3306, "tcp", "MySQL")
    database.upsert_service(ip3, 25, "tcp", "Postfix")
    database.insert_result("shodan", "ip", ip2, {"org": "Example Inc"})
    database.insert_result("crtsh", "hostname", www, {"issuer": "Let's Encrypt"})
    database.insert_result("nvd", "ip", ip2, {
        "port": 3306, "technology": "MySQL", "cpe": "cpe:/a:oracle:mysql:5.7.30",
        "cves": [{"cve_id": "CVE-9999-1", "cvss_score": 9.8, "cvss_severity": "CRITICAL",
                  "summary": "rce"}]})
    yield database
    database.close()


def _vault(db, tmp_path) -> dict[str, str]:
    path = tmp_path / "vault.zip"
    export_obsidian(db, path)
    with zipfile.ZipFile(path) as archive:
        return {name: archive.read(name).decode() for name in archive.namelist()}


class TestExportObsidian:
    def test_a_zip_with_a_note_per_host_beside_the_domains_and_overview(self, db, tmp_path):
        assert sorted(_vault(db, tmp_path)) == [
            "Domains/example.com.md", "Hosts/192.0.2.3.md", "Hosts/www.example.com.md",
            "_Overview.md"]

    def test_a_multi_ip_hostnames_note_covers_every_ip(self, db, tmp_path):
        note = _vault(db, tmp_path)["Hosts/www.example.com.md"]
        for text in ("192.0.2.1", "192.0.2.2", "443/tcp - nginx 1.18.0", "3306/tcp - MySQL",
                     "Example Inc", "Let's Encrypt", '"[[example.com]]"', "- port/3306",
                     "- source/shodan", "- source/crtsh"):
            assert text in note, text

    def test_an_ip_note_names_its_hostnames(self, db, tmp_path):
        note = _vault(db, tmp_path)["Hosts/192.0.2.3.md"]
        assert "# 192.0.2.3" in note and "mail.example.com" in note and "25/tcp" in note

    def test_the_domain_note_links_each_hostname_to_its_host_note(self, db, tmp_path):
        note = _vault(db, tmp_path)["Domains/example.com.md"]
        assert "[[www.example.com]]" in note
        assert "[[192.0.2.3|mail.example.com]]" in note
        assert "- old.example.com (unresolved)" in note

    def test_the_overview_links_findings_to_host_notes(self, db, tmp_path):
        overview = _vault(db, tmp_path)["_Overview.md"]
        assert "CVE-9999-1" in overview
        assert "[[www.example.com\\|192.0.2.2]]" in overview  # an IP inside a hostname's note

    def test_an_empty_database_still_has_an_overview(self, tmp_path):
        empty = Database(":memory:")
        empty.init_schema()
        assert sorted(_vault(empty, tmp_path)) == ["_Overview.md"]

class TestRenderDomainNoteExposures:
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
