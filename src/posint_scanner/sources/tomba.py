"""Collection source: Tomba.io domain search - Hunter-style email addresses
at the domain with names, titles, a score and source pages.

Needs a key and secret (both from the Tomba dashboard). The free plan is 25
searches/month, this source's default monthly budget.
"""

from __future__ import annotations

from posint_scanner.models import EmailAddress, EnrichmentResult
from posint_scanner.retry import with_retry
from posint_scanner.sources.base import DEFAULT_TTL_DAYS, Source, SourceSettings, SourceUnavailableError
from posint_scanner.sources.common import http_get, scoped_email

DOMAIN_SEARCH_URL = "https://api.tomba.io/v1/domain-search"


class TombaSettings(SourceSettings):
    api_key: str | None = None
    api_secret: str | None = None


def parse_tomba(domain: str, data: dict) -> tuple[list[EmailAddress], dict]:
    """(in-scope addresses, domain-level summary) from a domain-search body."""
    body = data.get("data") or {}
    emails: list[EmailAddress] = []
    for item in body.get("emails") or []:
        address = scoped_email(domain, item.get("email") or "")
        if address is None:
            continue
        name = item.get("full_name") or " ".join(
            p for p in (item.get("first_name"), item.get("last_name")) if p
        )
        sources = item.get("sources") or []
        emails.append(EmailAddress(
            address=address,
            name=name or None,
            position=item.get("position"),
            confidence=item.get("score"),
            url=sources[0].get("uri") if sources else None,
        ))
    organization = body.get("organization") or {}
    summary = {
        "organization": organization.get("organization"),
        "pattern": organization.get("email_pattern") or body.get("pattern"),
        "accept_all": organization.get("accept_all"),
        "total": (data.get("meta") or {}).get("total"),
    }
    return emails, summary


class TombaSource(Source):
    name = "tomba"
    settings_model = TombaSettings
    ttl_days = DEFAULT_TTL_DAYS
    monthly_budget = 25

    def __init__(self, api_key: str | None = None, api_secret: str | None = None) -> None:
        self.api_key = api_key
        self.api_secret = api_secret

    @classmethod
    def from_settings(cls, settings: SourceSettings) -> Source:
        assert isinstance(settings, TombaSettings)
        return cls(settings.api_key, settings.api_secret)

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key and self.api_secret)

    @with_retry
    def collect(self, domain: str) -> EnrichmentResult:
        if not self.is_configured:
            raise SourceUnavailableError("tomba api_key/api_secret not configured")
        data = http_get(
            self.name,
            DOMAIN_SEARCH_URL,
            params={"domain": domain},
            headers={"X-Tomba-Key": self.api_key or "", "X-Tomba-Secret": self.api_secret or ""},
        ).json()
        emails, summary = parse_tomba(domain, data)
        return EnrichmentResult(
            source=self.name, target_type="domain", target=domain,
            data=summary, email_addresses=emails,
        )
