import responses

from conftest import load_fixture
from posint_scanner.sources.wayback import CDX_URL, WaybackSource


class TestWaybackDiscover:
    @responses.activate
    def test_hostnames_from_archived_urls(self):
        responses.get(CDX_URL, body=load_fixture("wayback", "iana.org.json"))
        found = WaybackSource().discover("iana.org")
        assert [h.name for h in found] == ["www.iana.org"]
        assert found[0].source == "wayback"

    @responses.activate
    def test_queries_whole_domain_collapsed(self):
        responses.get(CDX_URL, body="[]")
        WaybackSource(limit=123).discover("iana.org")
        params = responses.calls[0].request.params
        assert params["url"] == "iana.org"
        assert params["matchType"] == "domain"
        assert params["collapse"] == "urlkey"
        assert params["limit"] == "123"

    @responses.activate
    def test_empty_body_means_no_captures(self):
        responses.get(CDX_URL, body="")
        assert WaybackSource().discover("iana.org") == []

    @responses.activate
    def test_truncated_stream_keeps_complete_rows(self):
        # seen live: the CDX server dropped a large response mid-row
        body = '[["original"],\n["https://a.iana.org/x"],\n["https://b.iana.org/y"],\n["https://c.ia'
        responses.get(CDX_URL, body=body)
        assert [h.name for h in WaybackSource().discover("iana.org")] == ["a.iana.org", "b.iana.org"]
