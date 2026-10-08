"""Collection source: Hunter.io domain search - email addresses at the
domain with the person's name/title, a confidence score and the pages each
was seen on, plus the organization's address pattern (`{first}.{last}`).

Needs a key. The free plan is 25 searches/month (this source's default
monthly budget) and returns at most 10 addresses per search; raise `limit`
(up to 100) on a paid plan.
"""

from __future__ import annotations

from posint_scanner.models import EmailAddress, EnrichmentResult
from posint_scanner.retry import with_retry
from posint_scanner.sources.base import Source, SourceSettings
from posint_scanner.sources.common import ApiKeySettings, ApiKeySource, http_get, scoped_email

DOMAIN_SEARCH_URL = "https://api.hunter.io/v2/domain-search"
DEFAULT_LIMIT = 10


class HunterSettings(ApiKeySettings):
    limit: int = DEFAULT_LIMIT


def _full_name(first: str | None, last: str | None) -> str | None:
    return " ".join(part for part in (first, last) if part) or None


def parse_hunter(domain: str, data: dict) -> tuple[list[EmailAddress], dict]:
    """(in-scope addresses, domain-level summary) from a domain-search body."""
    body = data.get("data") or {}
    emails: list[EmailAddress] = []
    for item in body.get("emails") or []:
        address = scoped_email(domain, item.get("value") or "")
        if address is None:
            continue
        sources = item.get("sources") or []
        emails.append(EmailAddress(
            address=address,
            name=_full_name(item.get("first_name"), item.get("last_name")),
            position=item.get("position"),
            confidence=item.get("confidence"),
            url=sources[0].get("uri") if sources else None,
        ))
    summary = {
        "organization": body.get("organization"),
        "pattern": body.get("pattern"),
        "accept_all": body.get("accept_all"),
        "webmail": body.get("webmail"),
        "total": (data.get("meta") or {}).get("results"),
    }
    return emails, summary


class HunterSource(ApiKeySource):
    name = "hunter"
    settings_model = HunterSettings
    monthly_budget = 25

    def __init__(self, api_key: str | None = None, limit: int = DEFAULT_LIMIT) -> None:
        super().__init__(api_key)
        self.limit = limit

    @classmethod
    def from_settings(cls, settings: SourceSettings) -> Source:
        assert isinstance(settings, HunterSettings)
        return cls(api_key=settings.api_key, limit=settings.limit)

    @with_retry
    def collect(self, domain: str) -> EnrichmentResult:
        data = http_get(
            self.name,
            DOMAIN_SEARCH_URL,
            params={"domain": domain, "limit": self.limit, "api_key": self.require_key()},
        ).json()
        emails, summary = parse_hunter(domain, data)
        return EnrichmentResult(
            source=self.name, target_type="domain", target=domain,
            data=summary, email_addresses=emails,
        )
