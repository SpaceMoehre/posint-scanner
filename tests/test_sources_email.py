"""Email-address collection sources: theHarvester, Hunter.io, Tomba.io, PGP
keyserver - and the storage/export of what they find."""

import csv
import json
from unittest.mock import patch

import pytest
import responses

from posint_scanner.db import Database
from posint_scanner.export.csv_export import write_csv
from posint_scanner.export.json_export import export_json
from posint_scanner.export.obsidian_export import render_domain_note
from posint_scanner.models import EmailAddress, EnrichmentResult
from posint_scanner.orchestrator import run_scan
from posint_scanner.sources.base import Source, SourceUnavailableError
from posint_scanner.sources.common import scoped_email
from posint_scanner.sources.hunter import DOMAIN_SEARCH_URL as HUNTER_URL
from posint_scanner.sources.hunter import HunterSource
from posint_scanner.sources.pgp_keyserver import LOOKUP_URL, PgpKeyserverSource, parse_mr_index
from posint_scanner.sources.theharvester import TheHarvesterSource, parse_theharvester_json
from posint_scanner.sources.tomba import DOMAIN_SEARCH_URL as TOMBA_URL
from posint_scanner.sources.tomba import TombaSource


@pytest.fixture
def db():
    database = Database(":memory:")
    database.init_schema()
    yield database
    database.close()


class TestScopedEmail:
    @pytest.mark.parametrize("raw, expected", [
        ("Alice@Example.com", "alice@example.com"),
        ("mailto:bob@mail.example.com?subject=hi", "bob@mail.example.com"),
        ("<carol@example.com>", "carol@example.com"),
        ("dave@evil-example.com", None),
        ("eve@example.com.attacker.net", None),
        ("not-an-email", None),
        ("@example.com", None),
    ])
    def test_normalizes_and_scopes(self, raw, expected):
        assert scoped_email("example.com", raw) == expected


class TestTheHarvester:
    def test_parses_emails_and_in_scope_hosts(self):
        emails, hosts = parse_theharvester_json("example.com", {
            "emails": ["Info@example.com", "info@example.com", "x@gmail.com"],
            "hosts": ["www.example.com:93.184.215.14", "api.example.com", "cdn.other.net"],
        })
        assert [e.address for e in emails] == ["info@example.com"]
        assert hosts == ["www.example.com", "api.example.com"]

    def test_raises_when_binary_missing(self):
        with patch("shutil.which", return_value=None):
            with pytest.raises(SourceUnavailableError):
                TheHarvesterSource().collect("example.com")

    def _fake_run(self, report: dict | None, returncode: int = 0):
        def run(cmd, **kwargs):
            if report is not None:
                out = cmd[cmd.index("-f") + 1]
                with open(out + ".json", "w") as f:
                    json.dump(report, f)
            class Result:
                pass
            result = Result()
            result.returncode, result.stdout, result.stderr = returncode, "", "boom"
            return result
        return run

    def test_runs_cli_and_reads_json_report(self):
        run = self._fake_run({"emails": ["a@example.com"], "hosts": ["mx.example.com"]})
        with patch("shutil.which", return_value="/usr/bin/theHarvester"), \
             patch("subprocess.run", side_effect=run) as mock_run:
            result = TheHarvesterSource(backends="crtsh,bing").collect("example.com")
        cmd = mock_run.call_args.args[0]
        assert cmd[:5] == ["/usr/bin/theHarvester", "-d", "example.com", "-b", "crtsh,bing"]
        assert [e.address for e in result.email_addresses] == ["a@example.com"]
        assert result.related_hostnames == ["mx.example.com"]
        assert result.target_type == "domain"

    def test_failed_run_without_report_raises(self):
        with patch("shutil.which", return_value="/usr/bin/theHarvester"), \
             patch("subprocess.run", side_effect=self._fake_run(None, returncode=1)):
            with pytest.raises(RuntimeError, match="boom"):
                TheHarvesterSource().collect("example.com")


HUNTER_BODY = {
    "data": {
        "domain": "example.com", "organization": "Example Inc", "pattern": "{first}.{last}",
        "accept_all": False, "webmail": False,
        "emails": [
            {"value": "jane.doe@example.com", "type": "personal", "confidence": 94,
             "first_name": "Jane", "last_name": "Doe", "position": "CTO",
             "sources": [{"uri": "https://example.com/team"}]},
            {"value": "info@example.com", "type": "generic", "confidence": 80, "sources": []},
            {"value": "someone@partner.org", "confidence": 50},
        ],
    },
    "meta": {"results": 42, "limit": 10, "offset": 0},
}


class TestHunter:
    @responses.activate
    def test_domain_search(self):
        responses.get(HUNTER_URL, json=HUNTER_BODY)
        result = HunterSource(api_key="k").collect("example.com")
        assert [e.address for e in result.email_addresses] == [
            "jane.doe@example.com", "info@example.com"]
        jane = result.email_addresses[0]
        assert (jane.name, jane.position, jane.confidence, jane.url) == (
            "Jane Doe", "CTO", 94, "https://example.com/team")
        assert result.data["pattern"] == "{first}.{last}"
        assert result.data["total"] == 42
        params = responses.calls[0].request.params
        assert params["api_key"] == "k" and params["limit"] == "10"

    def test_needs_key(self):
        assert not HunterSource().is_configured
        with pytest.raises(SourceUnavailableError):
            HunterSource().collect("example.com")

    def test_free_tier_monthly_budget(self):
        assert HunterSource().monthly_budget == 25


class TestTomba:
    @responses.activate
    def test_domain_search(self):
        responses.get(TOMBA_URL, json={
            "data": {
                "organization": {"organization": "Example", "email_pattern": "{first}"},
                "emails": [{"email": "jane@example.com", "full_name": "Jane Doe",
                            "position": "CEO", "score": 99,
                            "sources": [{"uri": "https://example.com/about"}]},
                           {"email": "x@elsewhere.com"}],
            },
            "meta": {"total": 1},
        })
        result = TombaSource(api_key="k", api_secret="s").collect("example.com")
        assert [e.address for e in result.email_addresses] == ["jane@example.com"]
        assert result.email_addresses[0].confidence == 99
        assert result.data["pattern"] == "{first}"
        headers = responses.calls[0].request.headers
        assert headers["X-Tomba-Key"] == "k" and headers["X-Tomba-Secret"] == "s"

    def test_needs_key_and_secret(self):
        assert not TombaSource(api_key="k").is_configured
        with pytest.raises(SourceUnavailableError):
            TombaSource(api_key="k").collect("example.com")


MR_INDEX = """info:1:3
pub:A617098F6A86FD821576A691BCF2CCEC8A188110:1:2048:1401199929::
uid:Jane Doe (work) <jane@example.com>:1477919156::
uid:Jane Doe <jane@gmail.com>:1477919156::
pub:D2442A69BB182BC789EF4897170059970AA953A0:1:4096:1477919156::
uid:ops%3A team <ops@lists.example.com>:1477919156::
uid:bare@example.com:1477919156::
"""


class TestPgpKeyserver:
    def test_parses_uids(self):
        emails = parse_mr_index("example.com", MR_INDEX)
        assert [(e.address, e.name) for e in emails] == [
            ("jane@example.com", "Jane Doe"),
            ("ops@lists.example.com", "ops: team"),
            ("bare@example.com", None),
        ]

    @responses.activate
    def test_no_keys_is_empty(self):
        responses.get(LOOKUP_URL, status=404)
        assert PgpKeyserverSource().collect("example.com").email_addresses == []

    @responses.activate
    def test_server_error_skips_without_retry(self):
        responses.get(LOOKUP_URL, status=500)
        with pytest.raises(SourceUnavailableError):
            PgpKeyserverSource().collect("example.com")
        assert len(responses.calls) == 1


class TestStorage:
    def test_one_row_per_address_with_sources_merged(self, db):
        domain_id = db.upsert_domain("example.com")
        db.upsert_email_address(domain_id, "jane@example.com", "theharvester", now="2026-01-01")
        db.upsert_email_address(domain_id, "jane@example.com", "hunter", name="Jane Doe",
                                confidence=90, now="2026-02-01")
        db.upsert_email_address(domain_id, "jane@example.com", "hunter", now="2026-03-01")
        rows = db.list_email_addresses(domain_id)
        assert len(rows) == 1
        row = rows[0]
        assert row["sources"] == "hunter, theharvester"
        assert row["name"] == "Jane Doe"  # kept when a re-sighting lacks it
        assert row["confidence"] == 90
        assert (row["first_seen"], row["last_seen"]) == ("2026-01-01", "2026-03-01")

    def test_delete_domain_removes_addresses(self, db):
        domain_id = db.upsert_domain("example.com")
        db.upsert_email_address(domain_id, "jane@example.com", "hunter")
        db.delete_domain(domain_id)
        assert db.conn.execute("SELECT COUNT(*) FROM email_addresses").fetchone()[0] == 0


class EmailCollectSource(Source):
    name = "fake-email"

    def collect(self, domain):
        return EnrichmentResult(
            source=self.name, target_type="domain", target=domain, data={},
            email_addresses=[EmailAddress(address=f"jane@{domain}", name="Jane")],
        )


class TestPipelineAndExports:
    def test_collected_addresses_are_stored_and_exported(self, db, tmp_path):
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=[]):
            run_scan(db, ["example.com"], [EmailCollectSource()])
        domain_id = db.get_domain_by_name("example.com")["id"]
        assert [r["address"] for r in db.list_email_addresses(domain_id)] == ["jane@example.com"]

        entry = export_json(db)["domains"][0]
        assert entry["email_addresses"][0]["sources"] == ["fake-email"]

        write_csv(db, tmp_path / "services.csv")
        with open(tmp_path / "services.emails.csv") as f:
            assert next(csv.DictReader(f))["address"] == "jane@example.com"

    def test_obsidian_note_lists_addresses(self):
        content = render_domain_note(
            "example.com", [],
            email_addresses=[{"address": "jane@example.com", "name": "Jane", "position": "CTO",
                              "sources": "hunter"}],
        )
        assert "## Email addresses (1)" in content
        assert "- jane@example.com - Jane, CTO (via hunter)" in content
