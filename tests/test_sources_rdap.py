import responses

from conftest import load_fixture
from posint_scanner.sources.rdap import RDAP_URL, RdapSource

URL = RDAP_URL.format(domain="iana.org")


class TestRdapCollect:
    @responses.activate
    def test_registration_summary(self):
        responses.get(URL, body=load_fixture("rdap", "iana.org.json"))
        result = RdapSource().collect("iana.org")
        assert result.target_type == "domain"
        assert result.data["registrar"] == "CSC Corporate Domains, Inc."
        assert result.data["registered"] == "1995-06-05T04:00:00.772Z"
        assert result.data["expires"] == "2027-12-08T17:00:53Z"
        assert result.data["last_changed"] == "2026-08-12T01:43:56.776Z"
        assert result.data["dnssec"] is True
        assert "server transfer prohibited" in result.data["status"]
        assert result.data["nameservers"] == [
            "ns.icann.org",
            "a.iana-servers.net",
            "b.iana-servers.net",
            "c.iana-servers.net",
        ]

    @responses.activate
    def test_keeps_no_contact_details(self):
        # registrant/admin contacts are personal data - only the registrar's
        # name is kept
        responses.get(URL, body=load_fixture("rdap", "iana.org.json"))
        data = RdapSource().collect("iana.org").data
        assert set(data) == {
            "registrar", "registered", "expires", "last_changed", "status", "nameservers",
            "dnssec",
        }

    @responses.activate
    def test_in_scope_nameservers_are_related_hostnames(self):
        body = '{"nameservers": [{"ldhName": "NS1.IANA.ORG"}, {"ldhName": "ns.other.net"}]}'
        responses.get(URL, body=body)
        result = RdapSource().collect("iana.org")
        # only in-scope ones: third-party DNS providers aren't candidates
        assert result.related_hostnames == ["ns1.iana.org"]

    @responses.activate
    def test_unknown_domain_is_empty(self):
        responses.get(URL, status=404)
        assert RdapSource().collect("iana.org").data == {}
