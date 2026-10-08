import threading
import time
from unittest.mock import Mock, patch

from posint_scanner.nvd import NvdClient, build_cpe, cpe_version


class TestBuildCpe:
    def test_guesses_vendor_equals_product(self):
        assert build_cpe("nginx", "1.18.0") == "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"

    def test_lowercases_and_replaces_spaces(self):
        assert build_cpe("Apache HTTP Server", "2.4.1") == (
            "cpe:2.3:a:apache_http_server:apache_http_server:2.4.1:*:*:*:*:*:*:*"
        )


SAMPLE_RESPONSE = {
    "totalResults": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-23017",
                "descriptions": [
                    {"lang": "en", "value": "A security issue in nginx resolver."},
                    {"lang": "es", "value": "Un problema de seguridad..."},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 7.7, "baseSeverity": "HIGH"}}
                    ]
                },
            }
        }
    ],
}


class TestNvdClientLookupCves:
    def test_parses_cve_id_summary_and_cvss(self):
        client = NvdClient()
        response = Mock(status_code=200)
        response.json.return_value = SAMPLE_RESPONSE
        response.raise_for_status = Mock()
        with patch("requests.get", return_value=response):
            with patch("time.sleep"):
                result = client.lookup_cves("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*")

        assert result == [
            {
                "cve_id": "CVE-2021-23017",
                "summary": "A security issue in nginx resolver.",
                "cvss_score": 7.7,
                "cvss_severity": "HIGH",
            }
        ]

    def test_falls_back_through_cvss_versions(self):
        client = NvdClient()
        response = Mock(status_code=200)
        response.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2009-1390",
                        "descriptions": [{"lang": "en", "value": "old CVE"}],
                        "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 6.8, "baseSeverity": "MEDIUM"}}]},
                    }
                }
            ]
        }
        response.raise_for_status = Mock()
        with patch("requests.get", return_value=response):
            with patch("time.sleep"):
                result = client.lookup_cves("cpe:2.3:a:x:x:1.0:*:*:*:*:*:*:*")
        assert result[0]["cvss_score"] == 6.8

    def test_returns_empty_on_no_results(self):
        client = NvdClient()
        response = Mock(status_code=200)
        response.json.return_value = {"vulnerabilities": []}
        response.raise_for_status = Mock()
        with patch("requests.get", return_value=response):
            with patch("time.sleep"):
                result = client.lookup_cves("cpe:2.3:a:x:x:1.0:*:*:*:*:*:*:*")
        assert result == []

    def test_returns_empty_on_403_rather_than_raising(self):
        # NVD signals rate-limiting via 403, not 429 - treat it as "no data"
        # rather than crashing the whole scan.
        client = NvdClient()
        response = Mock(status_code=403)
        with patch("requests.get", return_value=response):
            with patch("time.sleep"):
                result = client.lookup_cves("cpe:2.3:a:x:x:1.0:*:*:*:*:*:*:*")
        assert result == []

    def test_sends_api_key_header_when_configured(self):
        client = NvdClient(api_key="mykey")
        response = Mock(status_code=200)
        response.json.return_value = {"vulnerabilities": []}
        response.raise_for_status = Mock()
        with patch("requests.get", return_value=response) as mock_get:
            with patch("time.sleep"):
                client.lookup_cves("cpe:2.3:a:x:x:1.0:*:*:*:*:*:*:*")
        assert mock_get.call_args[1]["headers"]["apiKey"] == "mykey"

    def test_caps_number_of_cves_returned(self):
        client = NvdClient()
        vulns = [
            {
                "cve": {
                    "id": f"CVE-2020-{i:04d}",
                    "descriptions": [],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": float(i % 10), "baseSeverity": "LOW"}}]},
                }
            }
            for i in range(50)
        ]
        response = Mock(status_code=200)
        response.json.return_value = {"vulnerabilities": vulns}
        response.raise_for_status = Mock()
        with patch("requests.get", return_value=response):
            with patch("time.sleep"):
                result = client.lookup_cves("cpe:2.3:a:x:x:1.0:*:*:*:*:*:*:*")
        assert len(result) <= 20

    def test_retries_once_on_soft_throttle_then_succeeds(self):
        # NVD sometimes returns HTTP 200 with resultsPerPage: 0 and an empty
        # vulnerabilities array despite a nonzero totalResults - a soft
        # throttle signal distinct from a genuine "0 CVEs found".
        client = NvdClient()
        throttled = Mock(status_code=200)
        throttled.json.return_value = {"totalResults": 81, "vulnerabilities": []}
        throttled.raise_for_status = Mock()
        recovered = Mock(status_code=200)
        recovered.json.return_value = SAMPLE_RESPONSE
        recovered.raise_for_status = Mock()

        with patch("requests.get", side_effect=[throttled, recovered]):
            with patch("time.sleep") as mock_sleep:
                result = client.lookup_cves("cpe:2.3:a:openssl:openssl:1.0.1f:*:*:*:*:*:*:*")

        assert len(result) == 1
        assert result[0]["cve_id"] == "CVE-2021-23017"
        mock_sleep.assert_any_call(15)

    def test_gives_up_after_one_retry_if_still_throttled(self):
        client = NvdClient()
        throttled = Mock(status_code=200)
        throttled.json.return_value = {"totalResults": 81, "vulnerabilities": []}
        throttled.raise_for_status = Mock()

        with patch("requests.get", return_value=throttled):
            with patch("time.sleep"):
                result = client.lookup_cves("cpe:2.3:a:openssl:openssl:1.0.1f:*:*:*:*:*:*:*")

        assert result == []

    def test_genuine_zero_results_is_not_treated_as_throttled(self):
        client = NvdClient()
        genuine_empty = Mock(status_code=200)
        genuine_empty.json.return_value = {"totalResults": 0, "vulnerabilities": []}
        genuine_empty.raise_for_status = Mock()

        with patch("requests.get", return_value=genuine_empty) as mock_get:
            with patch("time.sleep") as mock_sleep:
                result = client.lookup_cves("cpe:2.3:a:x:x:1.0:*:*:*:*:*:*:*")

        assert result == []
        mock_get.assert_called_once()  # no retry - this was a real "no CVEs", not a throttle

    def test_paces_consecutive_requests(self):
        client = NvdClient()
        response = Mock(status_code=200)
        response.json.return_value = {"vulnerabilities": []}
        response.raise_for_status = Mock()
        with patch("requests.get", return_value=response):
            with patch("time.sleep") as mock_sleep:
                with patch("time.monotonic", side_effect=[0.0, 0.0, 1.0, 1.0]):
                    client.lookup_cves("cpe:2.3:a:x:x:1.0:*:*:*:*:*:*:*")
                    client.lookup_cves("cpe:2.3:a:y:y:1.0:*:*:*:*:*:*:*")
        # second call happened only 1s after the first, well under the
        # unauthenticated pacing interval - must have slept to catch up
        mock_sleep.assert_called_once()


class TestNvdClientThreadSafety:
    def test_concurrent_calls_are_serialized_and_paced(self):
        # Real timing (not mocked) - this is the one test that specifically
        # proves the lock actually prevents a race, since a mocked clock
        # can't distinguish "correctly serialized" from "raced but got
        # lucky". api_key set to use the shorter 0.7s authenticated
        # interval so the test doesn't take ages.
        client = NvdClient(api_key="testkey")
        call_times: list[float] = []
        lock = threading.Lock()

        def fake_get(*args, **kwargs):
            with lock:
                call_times.append(time.monotonic())
            response = Mock(status_code=200)
            response.json.return_value = {"vulnerabilities": []}
            response.raise_for_status = Mock()
            return response

        def worker(i: int):
            client.lookup_cves(f"cpe:2.3:a:x{i}:x{i}:1.0:*:*:*:*:*:*:*")

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        with patch("requests.get", side_effect=fake_get):
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10)

        assert len(call_times) == 5
        call_times.sort()
        gaps = [b - a for a, b in zip(call_times, call_times[1:])]
        # allow a little scheduling slack below the nominal 0.7s interval
        assert all(gap >= 0.6 for gap in gaps), gaps


class TestCpeVersion:
    def test_concrete_version_23(self):
        assert cpe_version("cpe:2.3:a:drupal:drupal:7.0:*:*:*:*:*:*:*") == "7.0"

    def test_wildcard_version_is_none(self):
        assert cpe_version("cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*") is None

    def test_dash_version_is_none(self):
        assert cpe_version("cpe:2.3:a:drupal:drupal:-:*:*:*:*:*:*:*") is None

    def test_truncated_cpe_has_no_version(self):
        assert cpe_version("cpe:2.3:a:drupal:drupal") is None

    def test_cpe_22_uri_form(self):
        assert cpe_version("cpe:/a:drupal:drupal:7.0") == "7.0"
        assert cpe_version("cpe:/a:drupal:drupal") is None

    def test_junk_is_none(self):
        assert cpe_version("not-a-cpe") is None
