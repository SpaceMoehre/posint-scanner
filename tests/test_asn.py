import ipaddress
from unittest.mock import Mock, patch

import dns.resolver

from posint_scanner.asn import lookup_asn, lookup_asn_prefixes


class TestLookupAsn:
    def test_parses_asn_from_cymru_txt_response(self):
        answer = [Mock(__str__=lambda self: '"15366 | 212.86.32.0/19 | DE | ripencc | 1999-06-07"')]
        with patch("dns.resolver.resolve", return_value=answer):
            assert lookup_asn("212.86.33.249") == 15366

    def test_queries_reversed_octets_under_cymru_suffix(self):
        answer = [Mock(__str__=lambda self: '"15366 | 212.86.32.0/19 | DE | ripencc | 1999-06-07"')]
        with patch("dns.resolver.resolve", return_value=answer) as mock_resolve:
            lookup_asn("212.86.33.249")
        query_name, record_type = mock_resolve.call_args[0]
        assert query_name == "249.33.86.212.origin.asn.cymru.com"
        assert record_type == "TXT"

    def test_returns_none_on_no_record(self):
        with patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
            assert lookup_asn("10.0.0.1") is None

    def test_handles_multiple_asns_in_response(self):
        # some IPs are announced by more than one ASN (multi-origin) - Cymru
        # space-separates them in the first field; take the first.
        answer = [Mock(__str__=lambda self: '"15366 6939 | 212.86.32.0/19 | DE | ripencc | 1999-06-07"')]
        with patch("dns.resolver.resolve", return_value=answer):
            assert lookup_asn("212.86.33.249") == 15366

    def test_returns_none_on_malformed_response(self):
        answer = [Mock(__str__=lambda self: '"not a valid response"')]
        with patch("dns.resolver.resolve", return_value=answer):
            assert lookup_asn("10.0.0.1") is None


class TestLookupAsnPrefixes:
    def test_parses_prefixes_from_ripestat_response(self):
        response = Mock(status_code=200)
        response.json.return_value = {
            "data": {
                "prefixes": [
                    {"prefix": "212.86.32.0/19"},
                    {"prefix": "178.20.88.0/21"},
                ]
            }
        }
        response.raise_for_status = Mock()
        with patch("requests.get", return_value=response):
            result = lookup_asn_prefixes(15366)
        assert result == [
            ipaddress.IPv4Network("212.86.32.0/19"),
            ipaddress.IPv4Network("178.20.88.0/21"),
        ]

    def test_skips_ipv6_prefixes(self):
        response = Mock(status_code=200)
        response.json.return_value = {
            "data": {"prefixes": [{"prefix": "2a03:fc80::/29"}, {"prefix": "1.2.3.0/24"}]}
        }
        response.raise_for_status = Mock()
        with patch("requests.get", return_value=response):
            result = lookup_asn_prefixes(15366)
        assert result == [ipaddress.IPv4Network("1.2.3.0/24")]

    def test_empty_prefix_list(self):
        response = Mock(status_code=200)
        response.json.return_value = {"data": {"prefixes": []}}
        response.raise_for_status = Mock()
        with patch("requests.get", return_value=response):
            assert lookup_asn_prefixes(15366) == []

    def test_queries_ripestat_with_asn_resource(self):
        response = Mock(status_code=200)
        response.json.return_value = {"data": {"prefixes": []}}
        response.raise_for_status = Mock()
        with patch("requests.get", return_value=response) as mock_get:
            lookup_asn_prefixes(15366)
        params = mock_get.call_args[1]["params"]
        assert params["resource"] == "AS15366"
