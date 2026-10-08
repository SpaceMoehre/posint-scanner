"""SecurityTrails, FullHunt and Netlas: single-key subdomain APIs."""

import pytest
import responses

from conftest import load_fixture
from posint_scanner.sources.base import SourceUnavailableError
from posint_scanner.sources.fullhunt import SUBDOMAINS_URL as FULLHUNT_URL
from posint_scanner.sources.fullhunt import FullHuntSource
from posint_scanner.sources.netlas import DOMAINS_URL as NETLAS_URL
from posint_scanner.sources.netlas import NetlasSource
from posint_scanner.sources.securitytrails import SUBDOMAINS_URL as ST_URL
from posint_scanner.sources.securitytrails import SecurityTrailsSource


class TestSecurityTrails:
    @responses.activate
    def test_expands_labels_to_hostnames(self):
        responses.get(
            ST_URL.format(domain="example.com"),
            body=load_fixture("securitytrails", "example.com.json"),
        )
        found = SecurityTrailsSource(api_key="k").discover("example.com")
        assert [h.name for h in found] == [
            "www.example.com",
            "api.example.com",
            "dev.internal.example.com",
        ]
        assert responses.calls[0].request.headers["APIKEY"] == "k"

    def test_free_tier_monthly_budget(self):
        assert SecurityTrailsSource().monthly_budget == 50


class TestFullHunt:
    @responses.activate
    def test_scoped_hosts(self):
        responses.get(
            FULLHUNT_URL.format(domain="example.com"),
            body=load_fixture("fullhunt", "example.com.json"),
        )
        found = FullHuntSource(api_key="k").discover("example.com")
        assert [h.name for h in found] == ["www.example.com", "vpn.example.com", "example.com"]
        assert responses.calls[0].request.headers["X-API-KEY"] == "k"


class TestNetlas:
    @responses.activate
    def test_domains_search(self):
        responses.get(NETLAS_URL, body=load_fixture("netlas", "iana.org.json"))
        found = NetlasSource(api_key="k").discover("iana.org")
        assert [h.name for h in found] == [
            "rdap-qa.iana.org",
            "registry.int.iana.org",
            "stage.iana.org",
            "autodiscover.iana.org",
            "pch-test.iana.org",
            "whois.iana.org",
        ]
        request = responses.calls[0].request
        assert request.headers["X-API-Key"] == "k"
        assert request.params["q"] == "domain:*.iana.org"

    @responses.activate
    def test_runs_keyless(self):
        # the domains search answers anonymously, at a lower allowance
        responses.get(NETLAS_URL, body=load_fixture("netlas", "iana.org.json"))
        assert NetlasSource().is_configured
        assert NetlasSource().discover("iana.org")
        assert "X-API-Key" not in responses.calls[0].request.headers


@pytest.mark.parametrize("cls", [SecurityTrailsSource, FullHuntSource])
def test_requires_key(cls):
    assert not cls().is_configured
    with pytest.raises(SourceUnavailableError):
        cls().discover("example.com")
