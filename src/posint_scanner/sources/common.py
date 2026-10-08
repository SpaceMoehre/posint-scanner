"""Helpers shared by the HTTP-based discovery/enrichment sources."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

import requests

from posint_scanner.models import DiscoveredHostname
from posint_scanner.normalize import InvalidDomainError, normalize_domain
from posint_scanner.retry import FOLLOW_REDIRECTS, VERIFY_TLS, AuthError
from posint_scanner.scope import in_scope
from posint_scanner.sources.base import (
    DEFAULT_TTL_DAYS,
    Source,
    SourceSettings,
    SourceUnavailableError,
)

# Self-identifying UA, consistent with shodan_web/webtech.
USER_AGENT = "posint-scanner/0.1 (passive OSINT recon tool)"
TIMEOUT_SECONDS = 30

# Re-exported so the many sources that already import from common keep one
# import; the definition (and the why) lives in retry.py.
__all__ = ["VERIFY_TLS", "FOLLOW_REDIRECTS", "USER_AGENT", "TIMEOUT_SECONDS", "http_get",
           "host_of", "scoped_hostnames", "normalized_names", "scoped_email",
           "ApiKeySettings", "ApiKeySource"]

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def host_of(raw: str) -> str | None:
    """The normalized hostname in a raw name or URL (scheme, userinfo, port
    and path stripped), or None if it isn't a plausible hostname."""
    value = _SCHEME_RE.sub("", raw.strip())
    value = value.split("/", 1)[0].split("?", 1)[0]
    value = value.rsplit("@", 1)[-1]
    if value.count(":") == 1:  # host:port (a bare IPv6 address has several)
        value = value.split(":", 1)[0]
    try:
        return normalize_domain(value)
    except InvalidDomainError:
        return None


def scoped_hostnames(domain: str, raw_names: Iterable[str], source: str) -> list[DiscoveredHostname]:
    """Normalize, dedupe (first-seen order) and keep only names under
    `domain` - third-party data sources happily return lookalikes
    (`evil-example.com`) and unrelated co-hosted names."""
    seen: set[str] = set()
    found: list[DiscoveredHostname] = []
    for raw in raw_names:
        name = host_of(raw)
        if name is None or name in seen or not in_scope(name, domain):
            continue
        seen.add(name)
        found.append(DiscoveredHostname(name=name, source=source))
    return found


def normalized_names(raw_names: Iterable[str]) -> list[str]:
    """Normalize and dedupe (first-seen order), keeping out-of-scope names -
    for EnrichmentResult.related_hostnames, which the orchestrator splits
    into in-scope hostnames and candidate domains itself."""
    names: list[str] = []
    for raw in raw_names:
        name = host_of(raw)
        if name is not None and name not in names:
            names.append(name)
    return names


_EMAIL_RE = re.compile(r"^[a-z0-9._%+'-]+@([a-z0-9.-]+\.[a-z]{2,})$")


def scoped_email(domain: str, raw: str) -> str | None:
    """The lowercased address if `raw` is a plausible email at `domain` or a
    subdomain of it, else None - email sources return addresses at
    unrelated domains (a site's vendors, webmail users) too."""
    value = raw.strip().lower()
    value = value.removeprefix("mailto:").split("?", 1)[0].strip("<>.,;'\"")
    match = _EMAIL_RE.match(value)
    if match is None or not in_scope(match.group(1), domain):
        return None
    return value


def http_get(
    source: str,
    url: str,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = TIMEOUT_SECONDS,
    ok_statuses: tuple[int, ...] = (),
) -> requests.Response:
    """GET with the project UA. 401/403 raise AuthError (never retried - a
    bad key stays bad); other non-2xx raise HTTPError, which `with_retry`
    retries when transient (429/5xx). Statuses in `ok_statuses` (e.g. a 404
    meaning "no results") are returned instead of raised."""
    response = requests.get(
        url,
        params=params,
        headers={"User-Agent": USER_AGENT, **(headers or {})},
        timeout=timeout,
        verify=VERIFY_TLS,
        allow_redirects=FOLLOW_REDIRECTS,
    )
    if response.status_code in ok_statuses:
        return response
    if response.status_code in (401, 403):
        raise AuthError(f"{source}: request rejected (HTTP {response.status_code}) - check the API key")
    response.raise_for_status()
    return response


class ApiKeySettings(SourceSettings):
    api_key: str | None = None


class ApiKeySource(Source):
    """Base for a source keyed by one API key (`sources: {<name>: {api_key}}`
    / OSINT_<NAME>_API_KEY). Metered by default: results are reused for
    DEFAULT_TTL_DAYS, so re-scans don't re-spend credits."""

    settings_model = ApiKeySettings
    ttl_days = DEFAULT_TTL_DAYS
    # Whether the source can run without a key (some free APIs just allow
    # less anonymously).
    key_required = True

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key

    @classmethod
    def from_settings(cls, settings: SourceSettings) -> Source:
        assert isinstance(settings, ApiKeySettings)
        return cls(api_key=settings.api_key)

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key) or not self.key_required

    def require_key(self) -> str:
        if not self.api_key:
            raise SourceUnavailableError(f"{self.name} API key not configured")
        return self.api_key
