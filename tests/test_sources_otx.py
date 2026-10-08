import pytest
import responses

from conftest import load_fixture
from posint_scanner.sources.base import SourceUnavailableError
from posint_scanner.sources.otx import PASSIVE_DNS_URL, OtxSource

URL = PASSIVE_DNS_URL.format(domain="iana.org")


class TestOtxDiscover:
    @responses.activate
    def test_scoped_hostnames_from_passive_dns(self):
        responses.get(URL, body=load_fixture("otx", "iana.org.json"))
        found = OtxSource(api_key="k").discover("iana.org")
        assert [h.name for h in found] == ["www.iana.org", "whois.iana.org"]
        assert responses.calls[0].request.headers["X-OTX-API-KEY"] == "k"

    def test_requires_key(self):
        # anonymous access to passive_dns is now rate-limited to nothing (429)
        assert not OtxSource().is_configured
        with pytest.raises(SourceUnavailableError):
            OtxSource().discover("iana.org")
