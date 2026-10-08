import json

import pytest
import responses

from posint_scanner.sources import entra_id
from posint_scanner.sources.entra_id import (
    AUTODISCOVER_URL,
    CREDENTIAL_TYPE_URL,
    OPENID_URL,
    REALM_URL,
    EntraIdSource,
)

OPENID = {
    "token_endpoint": "https://login.microsoftonline.com/6babcaad-604b-40ac-a9d7-9fd97c0b779f/oauth2/v2.0/token",
    "tenant_region_scope": "EU",
    "cloud_instance_name": "microsoftonline.com",
}
REALM = {
    "NameSpaceType": "Federated",
    "FederationBrandName": "Example AG",
    "AuthURL": "https://sts.example.com/adfs/ls/?username=x%40example.com",
    "FederationProtocol": "WSTrust",
}
CRED = {"EstsProperties": {"DesktopSsoEnabled": True, "UserTenantBranding": [
    {"Locale": 0, "BannerLogo": "https://aadcdn.example/logo.png", "Unused": "x"}]}}
FED_XML = """<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>
<GetFederationInformationResponseMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
<Response><Domains><Domain>example.com</Domain><Domain>Example-Brand.de</Domain>
<Domain>exampleag.onmicrosoft.com</Domain><Domain>exampleag.mail.onmicrosoft.com</Domain>
</Domains></Response></GetFederationInformationResponseMessage></s:Body></s:Envelope>"""

DNS = {
    ("example.com", "MX"): ["0 example-com.mail.protection.outlook.com."],
    ("example.com", "TXT"): ['"v=spf1 include:spf.protection.outlook.com -all"', '"MS=ms123"'],
    ("autodiscover.example.com", "CNAME"): ["autodiscover.outlook.com."],
}


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    monkeypatch.setattr(entra_id, "query_record_type", lambda n, t: DNS.get((n, t), []))
    monkeypatch.setattr(entra_id, "resolve_hostname",
                        lambda n: ["1.2.3.4"] if n == "exampleag.atp.azure.com" else [])


def mock_tenant():
    responses.get(OPENID_URL.format(domain="example.com"), json=OPENID)
    responses.get(REALM_URL, json=REALM)
    responses.post(CREDENTIAL_TYPE_URL, json=CRED)
    responses.post(AUTODISCOVER_URL, body=FED_XML)


class TestEntraIdCollect:
    @responses.activate
    def test_tenant_details(self):
        mock_tenant()
        data = EntraIdSource().collect("example.com").data
        assert data["tenant_found"] is True
        assert data["tenant_id"] == "6babcaad-604b-40ac-a9d7-9fd97c0b779f"
        assert data["region"] == "EU"
        assert data["namespace_type"] == "Federated"
        assert data["brand_name"] == "Example AG"
        assert data["desktop_sso"] is True
        assert data["branding"] == [{"Locale": 0, "BannerLogo": "https://aadcdn.example/logo.png"}]
        assert data["tenant_name"] == "exampleag"
        assert data["mdi_instance"] is True
        assert "example-brand.de" in data["tenant_domains"]
        assert data["dns"] == {
            "mx_exchange_online": True,
            "spf_includes_microsoft": True,
            "ms_verification_txt": ["MS=ms123"],
            "cnames": {"autodiscover": "autodiscover.outlook.com"},
        }

    @responses.activate
    def test_probes_a_made_up_user_only(self):
        mock_tenant()
        EntraIdSource().collect("example.com")
        body = json.loads(responses.calls[2].request.body)
        assert body["Username"] == "posint-nonexistent-user@example.com"

    @responses.activate
    def test_tenant_domains_and_adfs_host_are_related(self):
        mock_tenant()
        related = EntraIdSource().collect("example.com").related_hostnames
        # Microsoft-owned tenant domains aren't the org's
        assert sorted(related) == ["example-brand.de", "example.com", "sts.example.com"]

    @responses.activate
    def test_failing_extra_lookup_keeps_tenant(self):
        responses.get(OPENID_URL.format(domain="example.com"), json=OPENID)
        responses.get(REALM_URL, json=REALM)
        responses.post(CREDENTIAL_TYPE_URL, status=400)
        responses.post(AUTODISCOVER_URL, body="not xml")
        data = EntraIdSource().collect("example.com").data
        assert data["tenant_id"] == "6babcaad-604b-40ac-a9d7-9fd97c0b779f"
        assert data["tenant_domains"] == [] and data["tenant_name"] is None
        assert "desktop_sso" not in data

    @responses.activate
    def test_no_tenant(self):
        responses.get(OPENID_URL.format(domain="example.com"), status=400,
                      json={"error": "invalid_tenant"})
        result = EntraIdSource().collect("example.com")
        assert result.data["tenant_found"] is False
        assert result.data["dns"]["mx_exchange_online"] is True
        assert result.related_hostnames == []
