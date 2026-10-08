import pytest

from posint_scanner.scope import is_tld_sibling


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
