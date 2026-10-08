import pytest

from posint_scanner.sources.subdomainsfinder import SubdomainsFinderSource


class TestSubdomainsFinderSource:
    def test_discover_raises_not_implemented(self):
        source = SubdomainsFinderSource()
        with pytest.raises(NotImplementedError):
            source.discover("example.com")

    def test_does_not_support_enrichment(self):
        source = SubdomainsFinderSource()
        assert source.can_enrich is False
