import pytest

from posint_scanner.scope import domains_in_report, is_tld_sibling, tld_family


@pytest.mark.parametrize(
    "candidate, domain",
    [
        ("example.net", "example.com"),
        ("example.com", "example.net"),
        ("example.co.uk", "example.com"),
        ("example.de", "example.co.uk"),
    ],
)
def test_same_name_under_another_suffix_is_a_sibling(candidate, domain):
    assert is_tld_sibling(candidate, domain)


@pytest.mark.parametrize(
    "candidate, domain",
    [
        ("example.com", "example.com"),  # itself
        ("other.net", "example.com"),  # different name
        ("examples.net", "example.com"),
        ("www.example.net", "example.com"),  # not registrable
        ("example.net", "shop.example.com"),  # target isn't registrable
        ("example.github.io", "example.com"),  # private suffix: someone else's
        ("example.com", "example.github.io"),
        ("com", "example.com"),
    ],
)
def test_not_a_sibling(candidate, domain):
    assert not is_tld_sibling(candidate, domain)


@pytest.mark.parametrize(
    "domain, family",
    [
        ("example.com", "example"),
        ("example.co.uk", "example"),
        ("shop.example.com", None),  # subdomain
        ("example.github.io", None),  # private suffix
        ("1.2.3.4", None),
        ("localhost", None),
        ("com", None),
    ],
)
def test_tld_family(domain, family):
    assert tld_family(domain) == family


class TestDomainsInReport:
    """Other domains a tool's raw report names - candidates for a scan."""

    def test_finds_out_of_scope_domains_in_urls_and_text(self):
        text = (
            '{"matched-at": "https://shop.example.com/", "location": "https://pay.partner-shop.net/x"}\n'
            "redirects to http://login.acme-sso.de:8443/ ; mail admin@billing-corp.org\n"
            "CNAME api.example.com -> acme.github.io\n"
        )
        assert domains_in_report(text, "example.com") == [
            "partner-shop.net", "acme-sso.de", "billing-corp.org", "acme.github.io"]

    def test_skips_the_targets_own_names_and_ips(self):
        text = "https://example.com/ http://www.example.com/a 192.0.2.1 http://[2001:db8::1]/"
        assert domains_in_report(text, "example.com") == []

    def test_skips_advisory_vendor_and_third_party_domains(self):
        text = ("https://nvd.nist.gov/vuln/detail/CVE-2021-41773 https://github.com/x/y "
                "https://cwe.mitre.org/data/definitions/22.html https://www.exploit-db.com/x "
                "https://fonts.googleapis.com/css https://www.googletagmanager.com/gtm.js")
        assert domains_in_report(text, "example.com") == []

    def test_file_names_are_not_domains(self):
        text = ("README.md setup.py main.tf deploy.sh Makefile.in configure.ac app.zip module.info "
                "/admin/login.do logo.ai Safari.app")
        assert domains_in_report(text, "example.com") == []

    def test_a_file_like_suffix_still_counts_in_a_url(self):
        assert domains_in_report("see https://docs.partner.sh/", "example.com") == ["partner.sh"]
