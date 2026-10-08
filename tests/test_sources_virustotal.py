import pytest
import responses
from responses import matchers

from conftest import load_fixture
from posint_scanner.sources.base import SourceUnavailableError
from posint_scanner.sources.virustotal import SUBDOMAINS_URL, VirusTotalSource

URL = SUBDOMAINS_URL.format(domain="example.com")


def mock_pages():
    responses.get(
        URL,
        body=load_fixture("virustotal", "subdomains_page2.json"),
        match=[matchers.query_param_matcher({"limit": "40", "cursor": "CURSOR-PAGE-2"})],
    )
    responses.get(
        URL,
        body=load_fixture("virustotal", "subdomains_page1.json"),
        match=[matchers.query_param_matcher({"limit": "40"})],
    )


class TestVirusTotalDiscover:
    @responses.activate
    def test_follows_cursor_across_pages(self):
        mock_pages()
        found = VirusTotalSource(api_key="k", max_pages=5).discover("example.com")
        assert [h.name for h in found] == ["www.example.com", "mail.example.com", "dev.example.com"]
        assert responses.calls[0].request.headers["x-apikey"] == "k"

    @responses.activate
    def test_page_cap(self):
        mock_pages()
        found = VirusTotalSource(api_key="k", max_pages=1).discover("example.com")
        assert len(found) == 2
        assert len(responses.calls) == 1

    def test_requires_key(self):
        with pytest.raises(SourceUnavailableError):
            VirusTotalSource().discover("example.com")

    def test_free_tier_limits_by_default(self):
        source = VirusTotalSource()
        assert source.requests_per_minute == 4
        assert source.daily_budget == 500
