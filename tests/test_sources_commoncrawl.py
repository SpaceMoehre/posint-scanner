import json

import responses

from conftest import load_fixture
from posint_scanner.sources.commoncrawl import COLLINFO_URL, CommonCrawlSource

LATEST = json.loads(load_fixture("commoncrawl", "collinfo.json"))[0]["cdx-api"]


class TestCommonCrawlDiscover:
    @responses.activate
    def test_queries_latest_index_for_hostnames(self):
        responses.get(COLLINFO_URL, body=load_fixture("commoncrawl", "collinfo.json"))
        responses.get(LATEST, body=load_fixture("commoncrawl", "iana.org.jsonl"))
        found = CommonCrawlSource().discover("iana.org")
        assert [h.name for h in found] == ["www.iana.org"]
        assert responses.calls[1].request.params["url"] == "*.iana.org"

    @responses.activate
    def test_404_means_no_captures(self):
        responses.get(COLLINFO_URL, body=load_fixture("commoncrawl", "collinfo.json"))
        responses.get(LATEST, status=404, body='{"message": "No Captures found for: *.iana.org"}')
        assert CommonCrawlSource().discover("iana.org") == []

    @responses.activate
    def test_skips_unparseable_lines(self):
        responses.get(COLLINFO_URL, body=load_fixture("commoncrawl", "collinfo.json"))
        responses.get(LATEST, body='{"url": "https://a.iana.org/"}\nnot json\n\n')
        assert [h.name for h in CommonCrawlSource().discover("iana.org")] == ["a.iana.org"]
