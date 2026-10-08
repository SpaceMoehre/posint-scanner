import pytest
import responses

from conftest import load_fixture
from posint_scanner.sources.base import ScrapeParseError
from posint_scanner.sources.rapiddns import SUBDOMAIN_URL, RapidDnsSource


class TestRapidDnsDiscover:
    @responses.activate
    def test_parses_results_table(self):
        responses.get(
            SUBDOMAIN_URL.format(domain="example.com"),
            body=load_fixture("rapiddns", "example.com.html"),
        )
        found = RapidDnsSource().discover("example.com")
        assert [h.name for h in found] == ["example.com", "www.example.com"]
        assert all(h.source == "rapiddns" for h in found)

    @responses.activate
    def test_empty_results_table_is_no_data(self):
        responses.get(
            SUBDOMAIN_URL.format(domain="example.com"), body=load_fixture("rapiddns", "empty.html")
        )
        assert RapidDnsSource().discover("example.com") == []

    @responses.activate
    def test_missing_results_table_is_a_parse_error(self):
        responses.get(
            SUBDOMAIN_URL.format(domain="example.com"), body="<html><body>redesigned</body></html>"
        )
        with pytest.raises(ScrapeParseError):
            RapidDnsSource().discover("example.com")

    def test_is_an_opt_in_scraper(self):
        assert RapidDnsSource.category == "scrape"
