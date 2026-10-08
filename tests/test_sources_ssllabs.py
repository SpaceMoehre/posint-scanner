from unittest.mock import Mock, patch

import pytest

from posint_scanner.sources.ssllabs import SslLabsSource, parse_ssllabs_response


class TestParseSslLabsResponse:
    def test_extracts_grade_per_endpoint(self):
        raw = {
            "host": "example.com",
            "status": "READY",
            "endpoints": [
                {"ipAddress": "1.2.3.4", "grade": "A"},
                {"ipAddress": "5.6.7.8", "grade": "B"},
            ],
        }
        result = parse_ssllabs_response(raw)
        assert result.data["endpoints"] == [
            {"ipAddress": "1.2.3.4", "grade": "A"},
            {"ipAddress": "5.6.7.8", "grade": "B"},
        ]

    def test_target_is_hostname(self):
        raw = {"host": "example.com", "status": "READY", "endpoints": []}
        result = parse_ssllabs_response(raw)
        assert result.target_type == "hostname"
        assert result.target == "example.com"

    def test_source_tagged(self):
        raw = {"host": "example.com", "status": "READY", "endpoints": []}
        result = parse_ssllabs_response(raw)
        assert result.source == "qualys_ssllabs"

    def test_includes_status_for_error_cases(self):
        raw = {"host": "example.com", "status": "ERROR", "statusMessage": "Unable to resolve"}
        result = parse_ssllabs_response(raw)
        assert result.data["status"] == "ERROR"
        assert result.data["statusMessage"] == "Unable to resolve"


class TestSslLabsSourceEnrich:
    def test_polls_until_ready(self):
        source = SslLabsSource()
        in_progress = Mock(status_code=200)
        in_progress.json.return_value = {"host": "example.com", "status": "IN_PROGRESS"}
        in_progress.raise_for_status = Mock()
        ready = Mock(status_code=200)
        ready.json.return_value = {"host": "example.com", "status": "READY", "endpoints": []}
        ready.raise_for_status = Mock()

        with patch("requests.get", side_effect=[in_progress, ready]):
            with patch("time.sleep"):
                result = source.enrich("example.com", ["example.com"])

        assert result.data["status"] == "READY"

    def test_enrich_target_kind_is_hostname(self):
        assert SslLabsSource.enrich_target_kind == "hostname"

    def test_stops_polling_after_max_attempts(self):
        source = SslLabsSource(max_poll_attempts=2)
        in_progress = Mock(status_code=200)
        in_progress.json.return_value = {"host": "example.com", "status": "IN_PROGRESS"}
        in_progress.raise_for_status = Mock()

        with patch("requests.get", return_value=in_progress):
            with patch("time.sleep"):
                with pytest.raises(TimeoutError):
                    source.enrich("example.com", ["example.com"])
