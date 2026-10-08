"""Collection source: the domain's Microsoft Entra ID (Azure AD) / Microsoft
365 tenant, from Microsoft's own unauthenticated endpoints plus DNS - the
same recon AADInternals' `Invoke-AADIntReconAsOutsider` does. Keyless.

Kept per domain:

  - tenant: ID, region, cloud instance (OpenID discovery document);
  - realm: Managed vs Federated, brand name, and for federated domains the
    IdP's sign-in URL (usually an on-prem ADFS host - an exposure finding);
  - seamless SSO (Desktop SSO) on/off, from GetCredentialType asked about a
    made-up user - no real account is probed;
  - every domain registered in the same tenant (Exchange Online autodiscover
    GetFederationInformation) and the tenant's `.onmicrosoft.com` name;
  - whether a Defender for Identity instance exists (`<tenant>.atp.azure.com`);
  - M365 DNS footprint: MX to Exchange Online, SPF include, MS= verification
    TXT, and the autodiscover/Intune/Skype CNAMEs.

Tenant sibling domains feed back as related hostnames: out-of-scope ones
become candidate domains, which is the main payoff - they're the org's
other brands.
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

import requests

from posint_scanner.dns_resolve import query_record_type, resolve_hostname
from posint_scanner.models import EnrichmentResult
from posint_scanner.retry import with_retry
from posint_scanner.sources.base import DEFAULT_TTL_DAYS, Source
from posint_scanner.sources.common import TIMEOUT_SECONDS, USER_AGENT, VERIFY_TLS, http_get

logger = logging.getLogger(__name__)

OPENID_URL = "https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration"
REALM_URL = "https://login.microsoftonline.com/getuserrealm.srf"
CREDENTIAL_TYPE_URL = "https://login.microsoftonline.com/common/GetCredentialType"
AUTODISCOVER_URL = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"
MDI_HOST = "{tenant}.atp.azure.com"
# A user that won't exist - the realm/credential endpoints answer per domain.
PROBE_USER = "posint-nonexistent-user"

_TENANT_ID_RE = re.compile(r"login\.microsoftonline\.[^/]+/([0-9a-f-]{36})/")
_MICROSOFT_SUFFIXES = (".onmicrosoft.com", ".microsoftonline.com")
# Subdomains Microsoft 365 setup guides tell tenants to CNAME to Microsoft.
_M365_CNAMES = {
    "autodiscover": "autodiscover",
    "enterpriseregistration": "enterpriseregistration",
    "enterpriseenrollment": "enterpriseenrollment",
    "lyncdiscover": "lyncdiscover",
    "sip": "sip",
    "selector1._domainkey": "dkim_selector1",
}

_FEDERATION_SOAP = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:a="http://www.w3.org/2005/08/addressing">
<soap:Header>
<a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
<a:To soap:mustUnderstand="1">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To>
<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>
</soap:Header>
<soap:Body>
<GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
<Request><Domain>{domain}</Domain></Request>
</GetFederationInformationRequestMessage>
</soap:Body>
</soap:Envelope>"""


def parse_openid(data: dict) -> dict:
    match = _TENANT_ID_RE.search(data.get("token_endpoint", ""))
    return {
        "tenant_id": match.group(1) if match else None,
        "region": data.get("tenant_region_scope"),
        "region_sub_scope": data.get("tenant_region_sub_scope"),
        "cloud_instance": data.get("cloud_instance_name"),
    }


def parse_realm(data: dict) -> dict:
    return {
        "namespace_type": data.get("NameSpaceType"),  # Managed | Federated | Unknown
        "brand_name": data.get("FederationBrandName"),
        "federation_auth_url": data.get("AuthURL"),
        "federation_protocol": data.get("FederationProtocol"),
        "federation_issuer": data.get("CloudInstanceIssuerUri"),
    }


def parse_credential_type(data: dict) -> dict:
    ests = data.get("EstsProperties") or {}
    branding = ests.get("UserTenantBranding") or []
    return {
        "desktop_sso": bool(ests.get("DesktopSsoEnabled")),
        "branding": [
            {k: b[k] for k in ("Locale", "BannerLogo", "Illustration", "BoilerPlateText",
                               "UserIdLabel", "KeepMeSignedInDisabled") if b.get(k) is not None}
            for b in branding
        ],
    }


def parse_federation_domains(xml_text: str) -> list[str]:
    root = ET.fromstring(xml_text)
    return sorted(
        {el.text.strip().lower() for el in root.iter() if el.tag.endswith("}Domain") and el.text}
    )


def tenant_name(domains: list[str]) -> str | None:
    """`contoso` for contoso.onmicrosoft.com (not the .mail. routing domain)."""
    for d in domains:
        if d.endswith(".onmicrosoft.com") and d.count(".") == 2:
            return d.split(".")[0]
    return None


def m365_dns(domain: str) -> dict:
    mx = [r.split()[-1].rstrip(".").lower() for r in query_record_type(domain, "MX")]
    txt = [r.strip('"') for r in query_record_type(domain, "TXT")]
    cnames = {}
    for sub, key in _M365_CNAMES.items():
        target = query_record_type(f"{sub}.{domain}", "CNAME")
        if target:
            cnames[key] = target[0].rstrip(".").lower()
    return {
        "mx_exchange_online": any(m.endswith(".mail.protection.outlook.com") for m in mx),
        "spf_includes_microsoft": any("include:spf.protection.outlook.com" in t for t in txt),
        "ms_verification_txt": [t for t in txt if t.startswith("MS=")],
        "cnames": cnames,
    }


class EntraIdSource(Source):
    name = "entra_id"
    ttl_days = DEFAULT_TTL_DAYS

    def _post(self, url: str, **kwargs) -> requests.Response:
        headers = {"User-Agent": USER_AGENT, **kwargs.pop("headers", {})}
        response = requests.post(url, headers=headers, timeout=TIMEOUT_SECONDS, verify=VERIFY_TLS, **kwargs)
        response.raise_for_status()
        return response

    def _optional(self, what: str, domain: str, fetch) -> dict | list | None:
        """The tenant lookup decides whether there's anything to report; the
        other endpoints are extras whose failure shouldn't lose it."""
        try:
            return fetch()
        except (requests.RequestException, ET.ParseError, ValueError) as exc:
            logger.warning("entra_id: %s lookup for %s failed: %s", what, domain, exc)
            return None

    @with_retry
    def collect(self, domain: str) -> EnrichmentResult:
        response = http_get(self.name, OPENID_URL.format(domain=domain), ok_statuses=(400,))
        dns_info = m365_dns(domain)
        if response.status_code == 400:  # AADSTS90002: no such tenant
            return EnrichmentResult(
                source=self.name, target_type="domain", target=domain,
                data={"tenant_found": False, "dns": dns_info},
            )
        data: dict = {"tenant_found": True, **parse_openid(response.json())}
        login = f"{PROBE_USER}@{domain}"

        realm = self._optional("realm", domain, lambda: parse_realm(
            http_get(self.name, REALM_URL, params={"login": login, "json": "1"}).json()))
        data.update(realm or {})

        cred = self._optional("credential type", domain, lambda: parse_credential_type(
            self._post(CREDENTIAL_TYPE_URL, json={
                "Username": login, "isOtherIdpSupported": True,
                "checkPhones": False, "isRemoteNGCSupported": True,
                "isCookieBannerShown": False, "isFidoSupported": True,
            }).json()))
        data.update(cred or {})

        domains = self._optional("tenant domains", domain, lambda: parse_federation_domains(
            self._post(
                AUTODISCOVER_URL,
                data=_FEDERATION_SOAP.format(domain=domain).encode(),
                headers={
                    "Content-Type": "text/xml; charset=utf-8",
                    "SOAPAction": '"http://schemas.microsoft.com/exchange/2010/Autodiscover/'
                                  'Autodiscover/GetFederationInformation"',
                    "User-Agent": "AutodiscoverClient",
                },
            ).text)) or []
        data["tenant_domains"] = domains
        data["tenant_name"] = tenant_name(domains)
        data["mdi_instance"] = (
            bool(resolve_hostname(MDI_HOST.format(tenant=data["tenant_name"])))
            if data["tenant_name"] else None
        )
        data["dns"] = dns_info

        related = [d for d in domains if not d.endswith(_MICROSOFT_SUFFIXES)]
        auth_host = urlparse(data.get("federation_auth_url") or "").hostname
        if auth_host:
            related.append(auth_host.lower())
        return EnrichmentResult(
            source=self.name, target_type="domain", target=domain, data=data,
            related_hostnames=related,
        )
