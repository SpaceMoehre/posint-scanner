from unittest.mock import Mock, patch

import pytest

from posint_scanner.retry import AuthError
from posint_scanner.sources.base import SourceUnavailableError
from posint_scanner.sources.censys_source import CensysSource, parse_censys_response

SAMPLE_RESPONSE = {
    "result": {
        "ip": "1.2.3.4",
        "services": [
            {
                "port": 443,
                "transport_protocol": "TCP",
                "software": [{"product": "nginx", "version": "1.18.0", "vendor": "nginx"}],
            },
            {"port": 22, "transport_protocol": "TCP", "software": []},
        ],
    }
}


class TestParseCensysResponse:
    def test_extracts_services_with_product_and_version(self):
        result = parse_censys_response(SAMPLE_RESPONSE)
        ports = {(s.port, s.protocol, s.banner, s.version) for s in result.services}
        assert ports == {(443, "tcp", "nginx", "1.18.0"), (22, "tcp", None, None)}

    def test_target_type_and_target(self):
        result = parse_censys_response(SAMPLE_RESPONSE)
        assert result.target_type == "ip"
        assert result.target == "1.2.3.4"

    def test_source_tagged_censys(self):
        result = parse_censys_response(SAMPLE_RESPONSE)
        assert result.source == "censys"

    def test_preserves_raw_response(self):
        result = parse_censys_response(SAMPLE_RESPONSE)
        assert result.data == SAMPLE_RESPONSE

    def test_handles_no_services(self):
        raw = {"result": {"ip": "1.2.3.4", "services": []}}
        result = parse_censys_response(raw)
        assert result.services == []


class TestCensysSourceEnrich:
    def test_raises_source_unavailable_without_credentials(self):
        source = CensysSource(api_id=None, api_secret=None)
        with pytest.raises(SourceUnavailableError):
            source.enrich("1.2.3.4", [])

    def test_raises_auth_error_on_401(self):
        source = CensysSource(api_id="id", api_secret="badsecret")
        response = Mock(status_code=401)
        with patch("requests.get", return_value=response):
            with pytest.raises(AuthError):
                source.enrich("1.2.3.4", [])

    def test_returns_empty_result_on_404(self):
        # Censys returns 404 for hosts it has no data on - not an error.
        source = CensysSource(api_id="id", api_secret="secret")
        response = Mock(status_code=404)
        with patch("requests.get", return_value=response):
            result = source.enrich("1.2.3.4", [])
        assert result.services == []

    def test_uses_basic_auth_with_id_and_secret(self):
        source = CensysSource(api_id="myid", api_secret="mysecret")
        response = Mock(status_code=200)
        response.json.return_value = SAMPLE_RESPONSE
        response.raise_for_status = Mock()
        with patch("requests.get", return_value=response) as mock_get:
            source.enrich("1.2.3.4", [])
        assert mock_get.call_args[1]["auth"] == ("myid", "mysecret")
        assert "1.2.3.4" in mock_get.call_args[0][0]
