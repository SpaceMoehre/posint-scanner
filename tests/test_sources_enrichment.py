"""IP enrichment sources: reputation/context data plus related hostnames
(reverse IP, PTR) that feed the orchestrator's feedback loop."""

import pytest
import responses

from conftest import load_fixture
from posint_scanner.sources.abuseipdb import CHECK_URL, AbuseIpDbSource
from posint_scanner.sources.base import SourceUnavailableError
from posint_scanner.sources.greynoise import COMMUNITY_URL, GreyNoiseSource
from posint_scanner.sources.hackertarget import REVERSE_IP_URL, HackerTargetSource
from posint_scanner.sources.ipinfo import IPINFO_URL, IpInfoSource
from posint_scanner.sources.otx import IPV4_PASSIVE_DNS_URL, OtxSource
from posint_scanner.sources.urlscan import SEARCH_URL as URLSCAN_URL
from posint_scanner.sources.urlscan import UrlScanSource
from posint_scanner.sources.virustotal import IP_RESOLUTIONS_URL, VirusTotalSource


class TestGreyNoise:
    @responses.activate
    def test_observed_scanner(self):
        responses.get(
            COMMUNITY_URL.format(ip="71.6.199.23"), body=load_fixture("greynoise", "observed.json")
        )
        result = GreyNoiseSource().enrich("71.6.199.23", [])
        assert result.data["noise"] is True
        assert result.data["classification"] == "benign"
        assert result.data["name"] == "Shodan.io"

    @responses.activate
    def test_not_observed_is_a_404_with_a_body(self):
        responses.get(
            COMMUNITY_URL.format(ip="8.8.8.8"),
            status=404,
            body=load_fixture("greynoise", "not_observed.json"),
        )
        result = GreyNoiseSource().enrich("8.8.8.8", [])
        assert result.data["noise"] is False
        assert result.data["riot"] is False

    @responses.activate
    def test_sends_key_when_configured(self):
        responses.get(COMMUNITY_URL.format(ip="8.8.8.8"), body=load_fixture("greynoise", "observed.json"))
        GreyNoiseSource(api_key="k").enrich("8.8.8.8", [])
        assert responses.calls[0].request.headers["key"] == "k"


class TestIpInfo:
    @responses.activate
    def test_context_and_ptr_hostname(self):
        responses.get(IPINFO_URL.format(ip="192.0.43.8"), body=load_fixture("ipinfo", "192.0.43.8.json"))
        result = IpInfoSource().enrich("192.0.43.8", [])
        assert result.data["org"] == "AS16876 ICANN"
        assert "readme" not in result.data
        assert result.related_hostnames == ["43-8.any.icann.org"]

    @responses.activate
    def test_token_param_when_configured(self):
        responses.get(IPINFO_URL.format(ip="8.8.8.8"), body=load_fixture("ipinfo", "8.8.8.8.json"))
        IpInfoSource(api_key="t").enrich("8.8.8.8", [])
        assert responses.calls[0].request.params["token"] == "t"


class TestAbuseIpDb:
    @responses.activate
    def test_score_and_hostnames(self):
        responses.get(CHECK_URL, body=load_fixture("abuseipdb", "check.json"))
        result = AbuseIpDbSource(api_key="k").enrich("203.0.113.10", [])
        assert result.data["abuseConfidenceScore"] == 37
        assert result.data["totalReports"] == 12
        assert "mail.example.com" in result.related_hostnames
        request = responses.calls[0].request
        assert request.headers["Key"] == "k"
        assert request.params["ipAddress"] == "203.0.113.10"

    def test_requires_key(self):
        with pytest.raises(SourceUnavailableError):
            AbuseIpDbSource().enrich("203.0.113.10", [])


class TestUrlScan:
    @responses.activate
    def test_discover_scoped_page_domains(self):
        responses.get(URLSCAN_URL, body=load_fixture("urlscan", "domain_iana.org.json"))
        found = UrlScanSource().discover("iana.org")
        assert [h.name for h in found] == ["www.iana.org"]
        assert responses.calls[0].request.params["q"] == "domain:iana.org"

    @responses.activate
    def test_enrich_ip_relates_hosts_seen_on_it(self):
        responses.get(URLSCAN_URL, body=load_fixture("urlscan", "ip_192.0.43.8.json"))
        result = UrlScanSource().enrich("192.0.43.8", [])
        assert set(result.related_hostnames) >= {"www.iana.org", "iana.com"}
        assert result.data["total"] == 103
        assert result.data["scans"][0]["url"]
        assert responses.calls[0].request.params["q"] == 'ip:"192.0.43.8"'

    @responses.activate
    def test_sends_key_when_configured(self):
        responses.get(URLSCAN_URL, body=load_fixture("urlscan", "ip_192.0.43.8.json"))
        UrlScanSource(api_key="k").enrich("192.0.43.8", [])
        assert responses.calls[0].request.headers["API-Key"] == "k"


class TestReverseIp:
    @responses.activate
    def test_hackertarget(self):
        responses.get(REVERSE_IP_URL, body=load_fixture("hackertarget", "reverse_192.0.43.8.txt"))
        result = HackerTargetSource().enrich("192.0.43.8", [])
        assert result.related_hostnames == ["iana.com", "iana.net", "iana.org", "rs.iana.org"]
        assert result.data == {"reverse_ip_count": 4}

    @responses.activate
    def test_hackertarget_no_records(self):
        responses.get(REVERSE_IP_URL, body="No DNS A records found for 192.0.2.1")
        assert HackerTargetSource().enrich("192.0.2.1", []).related_hostnames == []

    @responses.activate
    def test_virustotal(self):
        responses.get(
            IP_RESOLUTIONS_URL.format(ip="203.0.113.10"),
            body=load_fixture("virustotal", "ip_resolutions.json"),
        )
        result = VirusTotalSource(api_key="k").enrich("203.0.113.10", [])
        assert result.related_hostnames == [
            "mail.example.com",
            "legacy.example.com",
            "partner-portal.net",
        ]

    @responses.activate
    def test_otx(self):
        responses.get(
            IPV4_PASSIVE_DNS_URL.format(ip="203.0.113.10"),
            body=load_fixture("otx", "ipv4_passive_dns.json"),
        )
        result = OtxSource(api_key="k").enrich("203.0.113.10", [])
        assert result.related_hostnames == ["vpn.example.com", "old-site.org"]
