"""Other domains found while scanning: listed on the overview, each with a
Scan button whose modal carries the scan options - pre-filled, like the
dashboard's form, from the last scan started."""

from __future__ import annotations

import re
import time
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from posint_scanner import toolrun
from posint_scanner.db import Database
from posint_scanner.web.app import create_app

REPORT = "Location: https://pay.partner-shop.net/checkout\nref https://nvd.nist.gov/x"


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "s.db")
    with Database(path) as db:
        db.init_schema()
        domain_id = db.upsert_domain("example.com")
        db.save_tool_output(domain_id, "nikto", "http://192.0.2.1/", toolrun.compress_text(REPORT))
        db.upsert_candidate_domain(domain_id, "neighbour.org", "hackertarget", "192.0.2.1")
        db.upsert_candidate_domain(domain_id, "scanned-already.com", "crtsh", "www.example.com")
        db.upsert_domain("scanned-already.com")
    return path


@pytest.fixture
def client(db_path, tmp_path):
    app = create_app(db_path=db_path, config_path=str(tmp_path / "none.yaml"))
    app.state.report_domains_collector.join(10)  # stored reports are read off startup
    return TestClient(app)


def _checked(html: str, name: str, value: str | None = None) -> bool:
    """Whether the checkbox `name` (=`value`) is ticked in `html`."""
    value_part = f' value="{value}"' if value else ""
    match = re.search(rf'<input type="checkbox" name="{name}"{value_part}[^>]*>', html)
    assert match, f"no checkbox {name} {value or ''}"
    return " checked" in match.group(0)


def _scan(client, data: dict) -> None:
    """Start a scan from a form post and wait for it, run_scan stubbed out."""
    with patch("posint_scanner.web.scans.run_scan"):
        r = client.post("/scans", data={"domain": "example.com", **data}, follow_redirects=False)
        job_id = r.headers["location"].rsplit("/", 1)[1]
        deadline = time.time() + 5
        while client.get(f"/api/scans/{job_id}").json()["status"] != "completed":
            assert time.time() < deadline
            time.sleep(0.02)


def _modal(html: str) -> str:
    return html[html.index('<dialog id="scan-modal"'):html.index("</dialog>")]


class TestOtherDomainsList:
    def test_domains_in_stored_tool_reports_are_collected_on_startup(self, client):
        page = client.get("/overview").text
        assert "Other domains found" in page
        assert 'data-scan-domain="partner-shop.net"' in page
        assert "nikto" in page
        assert "nvd.nist.gov" not in page and "nist.gov" not in page

    def test_related_domains_are_listed_and_scanned_ones_are_not(self, client):
        page = client.get("/overview").text
        assert 'data-scan-domain="neighbour.org"' in page
        assert 'data-scan-domain="scanned-already.com"' not in page

    def test_a_domain_filter_narrows_the_list(self, client, db_path):
        with Database(db_path) as db:
            other = db.upsert_domain("other.net")
            db.upsert_candidate_domain(other, "only-for-other.io", "crtsh", "other.net")
        assert "only-for-other.io" not in client.get("/overview?domain=example.com").text
        assert "only-for-other.io" in client.get("/overview?domain=other.net").text

    def test_the_scan_modal_posts_a_scan_with_its_options(self, client):
        modal = _modal(client.get("/overview").text)
        assert 'action="/scans"' in modal
        assert 'name="domain"' in modal
        assert 'name="sources_form"' in modal
        assert 'name="nuclei"' in modal and 'name="source"' in modal

    def test_the_domain_page_offers_the_same_modal(self, client):
        page = client.get("/domains/example.com").text
        assert 'data-scan-domain="neighbour.org"' in page
        assert '<dialog id="scan-modal"' in page


class TestRememberedScanOptions:
    def test_defaults_before_any_scan(self, client):
        page = client.get("/").text
        assert _checked(page, "netblock_sweep") and _checked(page, "vuln_lookup")
        assert not _checked(page, "nuclei")

    def test_the_last_scans_options_prefill_the_dashboard_and_the_modal(self, client):
        _scan(client, {"sources_form": "1", "source": ["crtsh"], "nuclei": "on",
                       "takeover": "on"})
        for html in (client.get("/").text, _modal(client.get("/overview").text)):
            assert _checked(html, "nuclei") and _checked(html, "takeover")
            assert not _checked(html, "netblock_sweep")
            assert _checked(html, "source", "crtsh")
            assert not _checked(html, "source", "hackertarget")

    def test_a_source_added_since_keeps_its_default(self, client, db_path):
        _scan(client, {"sources_form": "1", "source": ["crtsh"]})
        with Database(db_path) as db:  # as if crtsh were the only source back then
            stored = db.get_settings()["scan.last_options"]
            db.set_setting("scan.last_options",
                           re.sub(r'"known_sources": \[[^\]]*\]', '"known_sources": ["crtsh"]',
                                  stored))
        page = client.get("/").text
        assert _checked(page, "source", "crtsh")
        assert _checked(page, "source", "hackertarget")  # new: its config default (on)
