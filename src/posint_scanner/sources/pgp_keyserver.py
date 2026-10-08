"""Collection source: email addresses in PGP key user IDs on the public
keyserver (keyserver.ubuntu.com, Hockeypuck - it full-text searches user
IDs, so the domain matches every key with an address there). Keyless, 7-day
TTL. Old keys stay published forever, so these include former staff. The
keyserver caps an index at 100 keys and errors (HTTP 500) on domains with
far more - the source is then skipped for that domain.
"""

from __future__ import annotations

import re
from urllib.parse import unquote

from posint_scanner.models import EmailAddress, EnrichmentResult
from posint_scanner.retry import with_retry
from posint_scanner.sources.base import DEFAULT_TTL_DAYS, Source, SourceUnavailableError
from posint_scanner.sources.common import http_get, scoped_email

LOOKUP_URL = "https://keyserver.ubuntu.com/pks/lookup"

_UID_RE = re.compile(r"^\s*(?P<name>[^<]*?)\s*<(?P<email>[^>]+)>")


def parse_mr_index(domain: str, body: str) -> list[EmailAddress]:
    """In-scope addresses from a machine-readable (`options=mr`) index:
    `uid:<"Name (comment) <email>", ':' percent-encoded>:created:expires:flags`."""
    emails: dict[str, EmailAddress] = {}
    for line in body.splitlines():
        if not line.startswith("uid:"):
            continue
        uid = unquote(line.split(":")[1])
        match = _UID_RE.match(uid)
        raw, name = (match["email"], match["name"]) if match else (uid, "")
        address = scoped_email(domain, raw)
        if address is None or address in emails:
            continue
        name = re.sub(r"\s*\([^)]*\)\s*$", "", name).strip()  # drop "(comment)"
        emails[address] = EmailAddress(address=address, name=name or None)
    return list(emails.values())


class PgpKeyserverSource(Source):
    name = "pgp_keyserver"
    ttl_days = DEFAULT_TTL_DAYS

    @with_retry
    def collect(self, domain: str) -> EnrichmentResult:
        response = http_get(
            self.name,
            LOOKUP_URL,
            params={"op": "index", "options": "mr", "search": domain},
            ok_statuses=(404, 500),
        )
        if response.status_code == 500:
            # Not transient: Hockeypuck errors on domains with very many keys.
            raise SourceUnavailableError(f"keyserver search failed for {domain} (HTTP 500)")
        emails = [] if response.status_code == 404 else parse_mr_index(domain, response.text)
        return EnrichmentResult(
            source=self.name, target_type="domain", target=domain,
            data={"email_count": len(emails)}, email_addresses=emails,
        )
