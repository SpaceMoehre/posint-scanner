"""Enrichment source for Qualys VMDR (asset/vulnerability management API).

Reading existing asset/vulnerability data is always available. Triggering a
NEW scan against a discovered host is a real active action against
potentially-third-party infrastructure, so it is gated behind
`authorize_scans`, which the CLI only sets true when `--authorize-scans` is
passed (see cli.py) - never on by default.

Qualys's API is XML-based (api2). Parsing here extracts the common fields;
the full raw XML is kept in the result data so nothing is lost if a given
subscription's response includes fields this doesn't explicitly pull out.
"""

from __future__ import annotations

from xml.etree import ElementTree

import requests

from posint_scanner.models import EnrichmentResult
from posint_scanner.retry import VERIFY_TLS, raise_for_auth_error, with_retry
from posint_scanner.sources.base import Source, SourceSettings, SourceUnavailableError

DEFAULT_PLATFORM_URL = "https://qualysapi.qualys.com"
ASSET_ENDPOINT ="/api/2.0/fo/asset/host/vm/detection/"
SCAN_ENDPOINT = "/api/2.0/fo/scan/"
TIMEOUT_SECONDS = 60


def _text(element: ElementTree.Element | None) -> str | None:
    return element.text if element is not None else None


def parse_vmdr_asset_xml(raw_xml: str) -> dict:
    root = ElementTree.fromstring(raw_xml)
    host = root.find("./RESPONSE/HOST_LIST/HOST")
    if host is None:
        return {"ip": None, "dns": None, "os": None, "detections": []}

    detections = [
        {
            "qid": _text(detection.find("QID")),
            "severity": _text(detection.find("SEVERITY")),
        }
        for detection in host.findall("./DETECTION_LIST/DETECTION")
    ]
    return {
        "ip": _text(host.find("IP")),
        "dns": _text(host.find("DNS")),
        "os": _text(host.find("OS")),
        "detections": detections,
    }


class QualysVmdrSettings(SourceSettings):
    api_user: str | None = None
    api_password: str | None = None
    platform_url: str = DEFAULT_PLATFORM_URL
    # Set from the --authorize-scans CLI flag (see cli.py); settable in config
    # too, but opting in per run is the safer habit.
    authorize_scans: bool = False


class QualysVmdrSource(Source):
    name = "qualys_vmdr"
    settings_model = QualysVmdrSettings

    def __init__(
        self,
        api_user: str | None,
        api_password: str | None,
        platform_url: str,
        authorize_scans: bool = False,
    ) -> None:
        self.api_user = api_user
        self.api_password = api_password
        self.platform_url = platform_url.rstrip("/")
        self.authorize_scans = authorize_scans

    @classmethod
    def from_settings(cls, settings: SourceSettings) -> QualysVmdrSource:
        assert isinstance(settings, QualysVmdrSettings)
        return cls(
            api_user=settings.api_user,
            api_password=settings.api_password,
            platform_url=settings.platform_url,
            authorize_scans=settings.authorize_scans,
        )

    @property
    def is_configured(self) -> bool:
        return bool(self.api_user and self.api_password)

    @property
    def _auth(self) -> tuple[str, str]:
        assert self.api_user is not None and self.api_password is not None
        return (self.api_user, self.api_password)

    @with_retry
    def _fetch_asset_data(self, ip: str) -> dict:
        response = requests.get(
            f"{self.platform_url}{ASSET_ENDPOINT}",
            params={"action": "list", "ips": ip, "output_format": "XML"},
            auth=self._auth,
            headers={"X-Requested-With": "posint-scanner"},
            timeout=TIMEOUT_SECONDS,
            verify=VERIFY_TLS,
        )
        raise_for_auth_error(response, "qualys_vmdr rejected the configured credentials")
        response.raise_for_status()
        return parse_vmdr_asset_xml(response.text)

    def trigger_scan(self, ip: str) -> dict:
        if not self.authorize_scans:
            raise PermissionError(
                "scan-triggering is not authorized for this run - pass "
                "--authorize-scans to enable it"
            )
        return self._launch_scan(ip)

    @with_retry
    def _launch_scan(self, ip: str) -> dict:
        response = requests.post(
            f"{self.platform_url}{SCAN_ENDPOINT}",
            params={
                "action": "launch",
                "ip": ip,
                "option_title": "posint-scanner",
            },
            auth=self._auth,
            headers={"X-Requested-With": "posint-scanner"},
            timeout=TIMEOUT_SECONDS,
            verify=VERIFY_TLS,
        )
        raise_for_auth_error(response, "qualys_vmdr rejected the configured credentials")
        response.raise_for_status()
        return {"raw": response.text}

    def enrich(self, target: str, hostnames: list[str]) -> EnrichmentResult:
        if not (self.api_user and self.api_password):
            raise SourceUnavailableError("qualys_vmdr credentials not configured")

        asset = self._fetch_asset_data(target)
        scan_triggered = False
        scan_result = None
        if self.authorize_scans:
            scan_result = self._launch_scan(target)
            scan_triggered = True

        return EnrichmentResult(
            source="qualys_vmdr",
            target_type="ip",
            target=target,
            data={
                "asset": asset,
                "scan_triggered": scan_triggered,
                "scan_result": scan_result,
            },
        )
