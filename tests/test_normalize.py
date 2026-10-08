import pytest

from posint_scanner.normalize import InvalidDomainError, dedup_domains, normalize_domain


class TestNormalizeDomain:
    def test_lowercases(self):
        assert normalize_domain("Example.COM") == "example.com"

    def test_strips_https_scheme(self):
        assert normalize_domain("https://example.com") == "example.com"

    def test_strips_http_scheme(self):
        assert normalize_domain("http://example.com") == "example.com"

    def test_strips_path_after_scheme(self):
        assert normalize_domain("https://example.com/path?query=1") == "example.com"

    def test_strips_trailing_dot(self):
        assert normalize_domain("example.com.") == "example.com"

    def test_keeps_www(self):
        assert normalize_domain("www.example.com") == "www.example.com"

    def test_strips_wildcard_prefix(self):
        assert normalize_domain("*.example.com") == "example.com"

    def test_strips_surrounding_whitespace(self):
        assert normalize_domain("  example.com  ") == "example.com"

    def test_rejects_empty_string(self):
        with pytest.raises(InvalidDomainError):
            normalize_domain("")

    def test_rejects_no_dot(self):
        with pytest.raises(InvalidDomainError):
            normalize_domain("localhost")

    def test_rejects_invalid_characters(self):
        with pytest.raises(InvalidDomainError):
            normalize_domain("exa mple.com")

    def test_rejects_invalid_characters_underscore_ok(self):
        # underscores are legal in some DNS labels (e.g. DKIM records) - don't reject
        assert normalize_domain("_dmarc.example.com") == "_dmarc.example.com"


class TestDedupDomains:
    def test_dedups_case_insensitively(self):
        # dedup_domains runs on already-normalize_domain'd (lowercase) input in
        # the real pipeline; it still shouldn't blow up on mixed case, and keeps
        # whichever casing it saw first.
        assert dedup_domains(["Example.com", "example.com", "EXAMPLE.COM"]) == ["Example.com"]

    def test_preserves_first_seen_order(self):
        assert dedup_domains(["b.com", "a.com", "b.com"]) == ["b.com", "a.com"]

    def test_empty_list(self):
        assert dedup_domains([]) == []
