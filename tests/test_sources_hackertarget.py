import pytest
import responses

from conftest import load_fixture
from posint_scanner.sources.base import SourceUnavailableError
from posint_scanner.sources.hackertarget import HOSTSEARCH_URL, HackerTargetSource


class TestHackerTargetDiscover:
    @responses.activate
    def test_parses_host_ip_lines(self):
        responses.get(HOSTSEARCH_URL, body=load_fixture("hackertarget", "example.com.txt"))
        found = HackerTargetSource().discover("example.com")
        assert [h.name for h in found] == ["example.com", "www.example.com"]

    @responses.activate
    def test_runs_keyless_and_sends_key_when_configured(self):
        responses.get(HOSTSEARCH_URL, body="")
        assert HackerTargetSource().is_configured
        HackerTargetSource().discover("example.com")
        assert "apikey" not in responses.calls[0].request.params
        HackerTargetSource(api_key="k").discover("example.com")
        assert responses.calls[1].request.params["apikey"] == "k"

    @responses.activate
    def test_quota_message_is_unavailable_not_empty(self):
        # errors come back as HTTP 200 plain text
        responses.get(HOSTSEARCH_URL, body="API count exceeded - Increase Quota with Membership")
        with pytest.raises(SourceUnavailableError, match="quota"):
            HackerTargetSource().discover("example.com")

    @responses.activate
    def test_no_records_message_is_empty(self):
        responses.get(HOSTSEARCH_URL, body="No DNS A records found for example.com")
        assert HackerTargetSource().discover("example.com") == []


def test_quota_message_is_a_quota_error():
    from posint_scanner.sources.base import QuotaExhaustedError

    with responses.RequestsMock() as mock:
        mock.get(HOSTSEARCH_URL, body="API count exceeded - Increase Quota with Membership")
        with pytest.raises(QuotaExhaustedError):
            HackerTargetSource().discover("example.com")
