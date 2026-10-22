from unittest.mock import patch

from posint_scanner.sources.certspotter import CertSpotterSource, extract_dns_names


class TestExtractDnsNames:
    def test_flattens_dns_names_across_issuances(self):
        raw = [
            {"dns_names": ["example.com", "www.example.com"]},
            {"dns_names": ["api.example.com"]},
        ]
        assert extract_dns_names(raw) == ["example.com", "www.example.com", "api.example.com"]

    def test_handles_missing_dns_names(self):
        assert extract_dns_names([{"id": "1"}]) == []

    def test_empty(self):
        assert extract_dns_names([]) == []


class TestDiscover:
    def _source(self):
        return CertSpotterSource.from_settings(CertSpotterSource.settings_model())

    def test_scopes_to_queried_domain(self):
        # A shared cert lists another tenant's name; it must be dropped.
        page = [{"id": "1", "dns_names": ["www.example.com", "*.example.com",
                                          "unrelated-tenant.com"]}]
        with patch.object(CertSpotterSource, "_get", side_effect=[page, []]):
            found = self._source().discover("example.com")
        assert {h.name for h in found} == {"www.example.com", "example.com"}

    def test_tags_source(self):
        page = [{"id": "1", "dns_names": ["a.example.com"]}]
        with patch.object(CertSpotterSource, "_get", side_effect=[page, []]):
            found = self._source().discover("example.com")
        assert all(h.source == "certspotter" for h in found)

    def test_paginates_until_short_page(self):
        from posint_scanner.sources import certspotter

        first = [{"id": str(i), "dns_names": [f"h{i}.example.com"]}
                 for i in range(certspotter.PAGE_SIZE)]
        second = [{"id": "x", "dns_names": ["last.example.com"]}]
        with patch.object(CertSpotterSource, "_get", side_effect=[first, second]) as get:
            found = self._source().discover("example.com")
        assert get.call_count == 2  # full first page -> fetch second; short -> stop
        assert any(h.name == "last.example.com" for h in found)

    def test_single_short_page_makes_one_request(self):
        with patch.object(CertSpotterSource, "_get",
                          side_effect=[[{"id": "1", "dns_names": ["a.example.com"]}]]) as get:
            self._source().discover("example.com")
        assert get.call_count == 1
