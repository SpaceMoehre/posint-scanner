from unittest.mock import Mock, patch

import pytest
import requests

from posint_scanner.retry import AuthError
from posint_scanner.sources.shodan_source import (
    DEFAULT_RATE_LIMIT_SLEEP_SECONDS,
    ShodanSource,
    parse_retry_after,
    parse_shodan_response,
)


class TestParseShodanResponse:
    def test_extracts_services_from_data_list(self):
        raw = {
            "ip_str": "1.2.3.4",
            "org": "Example Inc",
            "data": [
                {"port": 443, "transport": "tcp", "product": "nginx"},
                {"port": 22, "transport": "tcp", "product": "OpenSSH"},
            ],
        }
        result = parse_shodan_response(raw)
        ports = {(s.port, s.protocol, s.banner) for s in result.services}
        assert ports == {(443, "tcp", "nginx"), (22, "tcp", "OpenSSH")}

    def test_includes_org_and_asn_in_data(self):
        raw = {"ip_str": "1.2.3.4", "org": "Example Inc", "asn": "AS12345", "data": []}
        result = parse_shodan_response(raw)
        assert result.data["org"] == "Example Inc"
        assert result.data["asn"] == "AS12345"

    def test_defaults_banner_to_none_when_no_product(self):
        raw = {"ip_str": "1.2.3.4", "data": [{"port": 8080, "transport": "tcp"}]}
        result = parse_shodan_response(raw)
        assert result.services[0].banner is None

    def test_extracts_version(self):
        raw = {
            "ip_str": "1.2.3.4",
            "data": [{"port": 443, "transport": "tcp", "product": "nginx", "version": "1.18.0"}],
        }
        result = parse_shodan_response(raw)
        assert result.services[0].version == "1.18.0"

    def test_extracts_first_cpe(self):
        raw = {
            "ip_str": "1.2.3.4",
            "data": [
                {
                    "port": 443,
                    "transport": "tcp",
                    "cpe23": [
                        "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
                        "cpe:2.3:a:igor_sysoev:nginx:1.18.0:*:*:*:*:*:*:*",
                    ],
                }
            ],
        }
        result = parse_shodan_response(raw)
        assert result.services[0].cpe == "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"

    def test_defaults_cpe_to_none_when_absent(self):
        raw = {"ip_str": "1.2.3.4", "data": [{"port": 8080, "transport": "tcp"}]}
        result = parse_shodan_response(raw)
        assert result.services[0].cpe is None

    def test_defaults_version_to_none_when_absent(self):
        raw = {"ip_str": "1.2.3.4", "data": [{"port": 8080, "transport": "tcp"}]}
        result = parse_shodan_response(raw)
        assert result.services[0].version is None

    def test_preserves_per_service_data_including_vulns_and_cpe(self):
        # regression: this used to strip the `data` list out of the stored
        # results blob entirely, silently discarding anything beyond what
        # fit in ServiceInfo (vulns, CPE, raw banner text, etc.)
        raw = {
            "ip_str": "1.2.3.4",
            "data": [
                {
                    "port": 443,
                    "transport": "tcp",
                    "product": "nginx",
                    "version": "1.18.0",
                    "cpe23": ["cpe:2.3:a:nginx:nginx:1.18.0"],
                    "vulns": {"CVE-2021-23017": {"cvss": 7.7}},
                }
            ],
        }
        result = parse_shodan_response(raw)
        assert result.data["data"][0]["vulns"] == {"CVE-2021-23017": {"cvss": 7.7}}
        assert result.data["data"][0]["cpe23"] == ["cpe:2.3:a:nginx:nginx:1.18.0"]

    def test_preserves_host_level_vulns(self):
        raw = {"ip_str": "1.2.3.4", "data": [], "vulns": ["CVE-2021-23017"]}
        result = parse_shodan_response(raw)
        assert result.data["vulns"] == ["CVE-2021-23017"]

    def test_target_type_is_ip(self):
        raw = {"ip_str": "1.2.3.4", "data": []}
        result = parse_shodan_response(raw)
        assert result.target_type == "ip"
        assert result.target == "1.2.3.4"

    def test_source_tagged_shodan(self):
        result = parse_shodan_response({"ip_str": "1.2.3.4", "data": []})
        assert result.source == "shodan"


class TestShodanSourceEnrich:
    def test_raises_source_unavailable_when_no_api_key(self):
        source = ShodanSource(api_key=None)
        with pytest.raises(Exception):
            source.enrich("1.2.3.4", [])

    def test_raises_auth_error_on_401(self):
        source = ShodanSource(api_key="badkey")
        response = Mock(status_code=401)
        response.json.return_value = {"error": "Invalid API key"}
        with patch("requests.get", return_value=response):
            with pytest.raises(AuthError):
                source.enrich("1.2.3.4", [])

    def test_calls_shodan_host_endpoint_with_key(self):
        source = ShodanSource(api_key="goodkey")
        response = Mock(status_code=200)
        response.json.return_value = {"ip_str": "1.2.3.4", "data": []}
        response.raise_for_status = Mock()
        with patch("requests.get", return_value=response) as mock_get:
            source.enrich("1.2.3.4", [])
        url = mock_get.call_args[0][0]
        params = mock_get.call_args[1]["params"]
        assert "1.2.3.4" in url
        assert params["key"] == "goodkey"

    def test_sleeps_for_retry_after_header_on_429(self):
        source = ShodanSource(api_key="goodkey")
        rate_limited = Mock(status_code=429, headers={"Retry-After": "2"})
        rate_limited.raise_for_status = Mock(side_effect=requests.HTTPError(response=rate_limited))
        ok = Mock(status_code=200, headers={})
        ok.json.return_value = {"ip_str": "1.2.3.4", "data": []}
        ok.raise_for_status = Mock()

        with patch("requests.get", side_effect=[rate_limited, ok]):
            with patch("time.sleep") as mock_sleep:
                result = source.enrich("1.2.3.4", [])

        # tenacity's own exponential backoff also calls time.sleep between
        # attempts, so assert our explicit Retry-After sleep happened
        # somewhere in the mix rather than being the only call.
        mock_sleep.assert_any_call(2.0)
        assert result.target == "1.2.3.4"

    def test_sleeps_default_when_retry_after_header_missing(self):
        source = ShodanSource(api_key="goodkey")
        rate_limited = Mock(status_code=429, headers={})
        rate_limited.raise_for_status = Mock(side_effect=requests.HTTPError(response=rate_limited))
        ok = Mock(status_code=200, headers={})
        ok.json.return_value = {"ip_str": "1.2.3.4", "data": []}
        ok.raise_for_status = Mock()

        with patch("requests.get", side_effect=[rate_limited, ok]):
            with patch("time.sleep") as mock_sleep:
                source.enrich("1.2.3.4", [])

        mock_sleep.assert_any_call(DEFAULT_RATE_LIMIT_SLEEP_SECONDS)


class TestParseRetryAfter:
    def test_parses_integer_seconds(self):
        assert parse_retry_after("5", default=1.0) == 5.0

    def test_returns_default_when_header_missing(self):
        assert parse_retry_after(None, default=3.0) == 3.0

    def test_returns_default_when_unparseable(self):
        assert parse_retry_after("Wed, 21 Oct 2026 07:28:00 GMT", default=3.0) == 3.0
