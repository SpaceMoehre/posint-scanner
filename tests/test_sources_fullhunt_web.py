import pytest
import responses

from conftest import load_fixture
from posint_scanner.sources.base import ScrapeParseError
from posint_scanner.sources.fullhunt_web import SEARCH_URL, FullHuntWebSource


class TestFullHuntWeb:
    @responses.activate
    def test_hosts_from_search_page(self):
        responses.get(SEARCH_URL, body=load_fixture("fullhunt_web", "iana.org.html"))
        found = FullHuntWebSource().discover("iana.org")
        names = [h.name for h in found]
        assert "whois.iana.org" in names
        assert "rdns-public.int.iana.org" in names
        assert len(names) == 10
        assert responses.calls[0].request.params["query"] == "iana.org"

    @responses.activate
    def test_no_results_is_empty(self):
        responses.get(SEARCH_URL, body=load_fixture("fullhunt_web", "empty.html"))
        assert FullHuntWebSource().discover("iana.org") == []

    @responses.activate
    def test_redesigned_page_is_a_parse_error(self):
        responses.get(SEARCH_URL, body="<html><body><div>new layout</div></body></html>")
        with pytest.raises(ScrapeParseError):
            FullHuntWebSource().discover("iana.org")

    def test_is_a_scraper_fallback_for_the_api(self):
        assert FullHuntWebSource.category == "scrape"
        assert FullHuntWebSource.fallback_for == "fullhunt"
