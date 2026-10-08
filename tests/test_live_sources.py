"""Live canaries: run each HTTP discovery source against its real endpoint.

Skipped unless selected (`pytest -m live`); keyed sources also need their key
in the environment (OSINT_<SOURCE>_API_KEY). These catch what fixture-based
tests can't: an API changing its response shape or a scraped page its markup.
A canary fails if the source errors, or finds nothing for a domain that
certainly has subdomains.
"""

import pytest

from posint_scanner.config import load_config
from posint_scanner.registry import SOURCE_CLASSES

pytestmark = pytest.mark.live

DOMAIN = "iana.org"  # stable, public, has several long-lived subdomains
HTTP_DISCOVERY = [
    "crtsh",
    "wayback",
    "commoncrawl",
    "hackertarget",
    "rapiddns",
    "otx",
    "virustotal",
    "securitytrails",
    "fullhunt",
    "netlas",
    "urlscan",
    "fullhunt_web",
]
HTTP_IP_ENRICHMENT = ["greynoise", "ipinfo", "hackertarget", "urlscan", "abuseipdb", "otx",
                      "virustotal"]
IP = "192.0.43.8"  # iana.org's web server


def build(name):
    cls = next(c for c in SOURCE_CLASSES if c.name == name)
    source = cls.from_settings(load_config(None).source_settings(name, cls.settings_model))
    if not source.is_configured:
        pytest.skip(f"set OSINT_{name.upper()}_API_KEY to run")
    return source


@pytest.mark.parametrize("name", HTTP_DISCOVERY)
def test_discovery_source_finds_subdomains(name):
    source = build(name)
    found = source.discover(DOMAIN)
    assert found, f"{name} returned no hostnames for {DOMAIN}"
    assert all(h.name == DOMAIN or h.name.endswith("." + DOMAIN) for h in found)


def test_rdap_collects_registration_record():
    data = build("rdap").collect(DOMAIN).data
    assert data["registrar"]
    assert data["expires"]


@pytest.mark.parametrize("name", HTTP_IP_ENRICHMENT)
def test_ip_enrichment_source_answers(name):
    result = build(name).enrich(IP, [])
    assert result.target == IP
    assert result.data or result.related_hostnames, f"{name} returned nothing for {IP}"
