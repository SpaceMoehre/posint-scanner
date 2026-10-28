import pytest

from posint_scanner.scope import is_tld_sibling, tld_family


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
