"""Shared retry policy for source connectors.

Transient failures (timeouts, connection errors, HTTP 429/5xx) get retried
with exponential backoff. Auth failures (4xx other than 429) are not
retried - retrying a bad API key three times just wastes the request budget.
"""

from __future__ import annotations

import requests
import urllib3
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

# TLS certificate verification for every outbound request in the project. Off
# by default and on purpose: scan targets routinely have expired, self-signed
# or hostname-mismatched certs, and a verification failure would abort recon
# on exactly the misconfigured hosts most worth looking at. We never send
# target credentials, so verify=False's usual MITM risk doesn't apply. Every
# request (common.http_get and the sources that call requests directly)
# threads this through - the one switch to flip if this ever needs to change.
VERIFY_TLS = False
# verify=False makes urllib3 warn on every request; silence it once, here,
# since this module is imported wherever a request is made.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Follow HTTP redirects on every outbound request. On by default and on
# purpose: services routinely 3xx from a bare host/port to where the app
# actually lives (e.g. GeoServer redirects `/` to `/geoserver/web/`), and the
# useful response - headers, version, fingerprint - is at the redirect target.
# It's requests' own default too; making it an explicit, shared switch means
# every call site follows redirects the same way and it can be changed in one
# place. Threaded through http_get and the sources that call requests directly.
FOLLOW_REDIRECTS = True


class AuthError(Exception):
    """Raised by a source when the API rejected its credentials. Never retried."""


def raise_for_auth_error(response: requests.Response, message: str) -> None:
    """Raise AuthError if the response is a 401. Shared by every source that
    does its own auth (API key / basic auth) rather than relying on
    requests' generic raise_for_status, since a 401 needs a distinct,
    non-retried exception rather than a generic HTTPError."""
    if response.status_code == 401:
        raise AuthError(message)


def _is_transient(exc: BaseException) -> bool:
    if isinstance(exc, AuthError):
        return False
    if isinstance(exc, (requests.ConnectionError, requests.Timeout)):
        return True
    if isinstance(exc, requests.HTTPError):
        response = exc.response
        if response is None:
            return True
        return response.status_code == 429 or response.status_code >= 500
    return False


with_retry = retry(
    retry=retry_if_exception(_is_transient),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    reraise=True,
)
