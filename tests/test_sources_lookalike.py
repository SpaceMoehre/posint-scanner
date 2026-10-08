import pytest

from posint_scanner.sources import lookalike
from posint_scanner.sources.lookalike import LookalikeSource, permutations


class TestPermutations:
    def test_returns_distinct_names_excluding_the_original(self):
        result = permutations("example.com")
        assert "example.com" not in result
        assert len(result) == len(set(result))
        assert all(name != "example.com" for name in result)

    def test_every_permutation_is_a_valid_lowercase_domain(self):
        import re

        for name in permutations("example.com"):
            assert name == name.lower()
            assert re.fullmatch(r"[a-z0-9.-]+", name), name
            assert ".." not in name
            assert not name.startswith("-") and not name.startswith(".")

    def test_omission_of_a_character(self):
        # dropping one letter of the label
        assert "exmple.com" in permutations("example.com")

    def test_character_repetition(self):
        assert "exaample.com" in permutations("example.com")

    def test_adjacent_transposition(self):
        assert "exapmle.com" in permutations("example.com")

    def test_homoglyph_substitution(self):
        # o -> 0 is a classic lookalike
        assert "g00gle.com" in permutations("google.com")

    def test_hyphenation(self):
        assert "exa-mple.com" in permutations("example.com")

    def test_tld_swap_keeps_the_label(self):
        swapped = permutations("example.com")
        assert "example.net" in swapped
        assert "example.org" in swapped

    def test_multi_label_public_suffix_is_preserved(self):
        # example.co.uk -> permute "example", keep .co.uk
        result = permutations("example.co.uk")
        assert "exmple.co.uk" in result
        # and TLD swaps replace the whole public suffix
        assert "example.com" in result

    def test_subdomains_are_ignored_and_apex_is_used(self):
        # a hostname reduces to its registrable domain before permuting
        result = permutations("www.example.com")
        assert all("www" not in name for name in result)
        assert "exmple.com" in result

    def test_bounded_size(self):
        # generation is capped so a scan can't explode into tens of thousands
        assert len(permutations("example.com")) <= lookalike.MAX_PERMUTATIONS

    def test_tld_swaps_come_first_so_truncation_never_drops_them(self):
        # TLD swaps are few and high-value; they must sit at the front of the
        # list, ahead of the (large, truncatable) typo-variant block.
        result = permutations("example.com")
        tld_swaps = [f"example.{t}" for t in lookalike._COMMON_TLDS if t != "com"]
        assert set(tld_swaps) <= set(result[: len(tld_swaps)])


class TestLookalikeSource:
    def test_reports_only_registered_lookalikes(self, monkeypatch):
        # example.com's own permutations; pretend two resolve.
        registered = {"examp1e.com": ["1.2.3.4"], "exmple.com": ["5.6.7.8"]}

        def fake_resolve(name):
            return registered.get(name, [])

        monkeypatch.setattr(lookalike, "resolve_hostname", fake_resolve)
        monkeypatch.setattr(lookalike, "query_record_type", lambda n, t: [])
        monkeypatch.setattr(
            lookalike, "permutations",
            lambda d: ["examp1e.com", "exmple.com", "nothere.com"],
        )

        result = LookalikeSource(workers=2).collect("example.com")
        assert result.target_type == "domain"
        assert result.target == "example.com"
        found = {r["name"]: r for r in result.data["registered"]}
        assert set(found) == {"examp1e.com", "exmple.com"}
        assert found["examp1e.com"]["addresses"] == ["1.2.3.4"]
        assert result.data["checked"] == 3

    def test_a_lookalike_with_only_mx_counts_as_registered(self, monkeypatch):
        monkeypatch.setattr(lookalike, "resolve_hostname", lambda n: [])
        monkeypatch.setattr(
            lookalike, "query_record_type",
            lambda n, t: ["0 mail.evil.example."] if n == "examp1e.com" and t == "MX" else [],
        )
        monkeypatch.setattr(lookalike, "permutations", lambda d: ["examp1e.com"])

        result = LookalikeSource(workers=1).collect("example.com")
        found = {r["name"] for r in result.data["registered"]}
        assert found == {"examp1e.com"}
        assert result.data["registered"][0]["mx"] == ["0 mail.evil.example."]

    def test_lookalikes_are_not_fed_back_as_related_hostnames(self, monkeypatch):
        # impersonator domains must never be scanned or recorded as candidates
        monkeypatch.setattr(lookalike, "resolve_hostname", lambda n: ["1.2.3.4"])
        monkeypatch.setattr(lookalike, "query_record_type", lambda n, t: [])
        monkeypatch.setattr(lookalike, "permutations", lambda d: ["examp1e.com"])

        result = LookalikeSource(workers=1).collect("example.com")
        assert result.related_hostnames == []

    def test_category_is_passive(self):
        assert LookalikeSource.category == "passive"
