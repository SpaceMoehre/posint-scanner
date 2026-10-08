"""Enrichment source using the free Qualys SSL Labs API (https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md).

No API key required. Analysis is keyed by hostname (SNI), not IP - the same
IP can grade differently depending on which hostname's TLS handshake is
tested - so this source declares `enrich_target_kind = "hostname"` and the
orchestrator calls it once per hostname rather than once per IP.

Assessments run asynchronously server-side; this polls until the status is
READY or ERROR, or gives up after `max_poll_attempts`.
"""

from __future__ import annotations

import time

import requests

from posint_scanner.models import EnrichmentResult
from posint_scanner.retry import VERIFY_TLS, with_retry
from posint_scanner.sources.base import Source

BASE_URL = "https://api.ssllabs.com/api/v3/analyze"
TIMEOUT_SECONDS = 30
POLL_INTERVAL_SECONDS = 10
DEFAULT_MAX_POLL_ATTEMPTS = 30
DONE_STATUSES = {"READY", "ERROR"}


def parse_ssllabs_response(raw: dict) -> EnrichmentResult:
    data = {k: v for k, v in raw.items() if k != "host"}
    return EnrichmentResult(
        source="qualys_ssllabs",
        target_type="hostname",
        target=raw.get("host", ""),
        data=data,
    )


class SslLabsSource(Source):
    name = "qualys_ssllabs"
    enrich_target_kind = "hostname"

    def __init__(self, max_poll_attempts: int = DEFAULT_MAX_POLL_ATTEMPTS) -> None:
        self.max_poll_attempts = max_poll_attempts

    @with_retry
    def _request(self, hostname: str, start_new: bool) -> dict:
        params = {"host": hostname, "all": "done"}
        if start_new:
            params["startNew"] = "on"
        else:
            params["fromCache"] = "on"
        response = requests.get(BASE_URL, params=params, timeout=TIMEOUT_SECONDS, verify=VERIFY_TLS)
        response.raise_for_status()
        return dict(response.json())

    def enrich(self, target: str, hostnames: list[str]) -> EnrichmentResult:
        hostname = target
        raw = self._request(hostname, start_new=True)
        attempts = 1
        while raw.get("status") not in DONE_STATUSES:
            if attempts >= self.max_poll_attempts:
                raise TimeoutError(
                    f"ssllabs assessment for {hostname} did not finish after "
                    f"{self.max_poll_attempts} polls"
                )
            time.sleep(POLL_INTERVAL_SECONDS)
            raw = self._request(hostname, start_new=False)
            attempts += 1
        return parse_ssllabs_response(raw)
