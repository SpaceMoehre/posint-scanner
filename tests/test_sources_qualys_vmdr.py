from unittest.mock import Mock, patch

import pytest

from posint_scanner.sources.base import SourceUnavailableError
from posint_scanner.sources.qualys_vmdr import QualysVmdrSource, parse_vmdr_asset_xml


SAMPLE_ASSET_XML = """<?xml version="1.0" encoding="UTF-8" ?>
<HOST_LIST_VM_DETECTION_OUTPUT>
  <RESPONSE>
    <HOST_LIST>
      <HOST>
        <IP>1.2.3.4</IP>
        <DNS>host.example.com</DNS>
        <OS>Linux</OS>
        <DETECTION_LIST>
          <DETECTION><QID>12345</QID><SEVERITY>4</SEVERITY></DETECTION>
          <DETECTION><QID>67890</QID><SEVERITY>2</SEVERITY></DETECTION>
        </DETECTION_LIST>
      </HOST>
    </HOST_LIST>
  </RESPONSE>
</HOST_LIST_VM_DETECTION_OUTPUT>
"""

NO_ASSET_XML = """<?xml version="1.0" encoding="UTF-8" ?>
<HOST_LIST_VM_DETECTION_OUTPUT>
  <RESPONSE>
    <HOST_LIST></HOST_LIST>
  </RESPONSE>
</HOST_LIST_VM_DETECTION_OUTPUT>
"""


class TestParseVmdrAssetXml:
    def test_extracts_host_fields(self):
        result = parse_vmdr_asset_xml(SAMPLE_ASSET_XML)
        assert result["ip"] == "1.2.3.4"
        assert result["dns"] == "host.example.com"
        assert result["os"] == "Linux"

    def test_extracts_detections(self):
        result = parse_vmdr_asset_xml(SAMPLE_ASSET_XML)
        assert result["detections"] == [
            {"qid": "12345", "severity": "4"},
            {"qid": "67890", "severity": "2"},
        ]

    def test_no_asset_found_returns_empty(self):
        result = parse_vmdr_asset_xml(NO_ASSET_XML)
        assert result["ip"] is None
        assert result["detections"] == []


class TestQualysVmdrSourceEnrich:
    def _source(self, authorize_scans=False):
        return QualysVmdrSource(
            api_user="user",
            api_password="pass",
            platform_url="https://qualysapi.qualys.com",
            authorize_scans=authorize_scans,
        )

    def test_raises_when_credentials_missing(self):
        source = QualysVmdrSource(
            api_user=None, api_password=None, platform_url="https://qualysapi.qualys.com"
        )
        with pytest.raises(SourceUnavailableError):
            source.enrich("1.2.3.4", [])

    def test_reads_asset_data_without_triggering_scan_by_default(self):
        source = self._source(authorize_scans=False)
        response = Mock(status_code=200, text=SAMPLE_ASSET_XML)
        response.raise_for_status = Mock()
        with patch("requests.get", return_value=response) as mock_get:
            result = source.enrich("1.2.3.4", [])

        assert result.data["asset"]["dns"] == "host.example.com"
        assert result.data["scan_triggered"] is False
        mock_get.assert_called_once()

    def test_triggers_scan_when_authorized(self):
        source = self._source(authorize_scans=True)
        asset_response = Mock(status_code=200, text=SAMPLE_ASSET_XML)
        asset_response.raise_for_status = Mock()
        scan_response = Mock(status_code=200, text="<SIMPLE_RETURN><RESPONSE><TEXT>Scan launched</TEXT></RESPONSE></SIMPLE_RETURN>")
        scan_response.raise_for_status = Mock()

        with patch("requests.get", return_value=asset_response):
            with patch("requests.post", return_value=scan_response) as mock_post:
                result = source.enrich("1.2.3.4", [])

        assert result.data["scan_triggered"] is True
        mock_post.assert_called_once()

    def test_trigger_scan_directly_raises_permission_error_when_not_authorized(self):
        source = self._source(authorize_scans=False)
        with pytest.raises(PermissionError):
            source.trigger_scan("1.2.3.4")

    def test_uses_basic_auth(self):
        source = self._source(authorize_scans=False)
        response = Mock(status_code=200, text=NO_ASSET_XML)
        response.raise_for_status = Mock()
        with patch("requests.get", return_value=response) as mock_get:
            source.enrich("1.2.3.4", [])
        auth = mock_get.call_args[1]["auth"]
        assert auth == ("user", "pass")
