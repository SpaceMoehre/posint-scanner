"""Discovery source using Cert Spotter's certificate-transparency API
(https://sslmate.com/ct_search_api/).

A second, independent CT feed alongside crt.sh: certificate transparency is
the single highest-yield passive subdomain source, and crt.sh is frequently
slow or briefly down; when it is, this keeps CT discovery working.

Answers keyless at a small hourly allowance; a free SSLMate API token
(`api_key`) raises it. An exhausted allowance comes back as HTTP 429.

Results are paged (`after=<last issuance id>`) up to `MAX_PAGES`, and scoped
to the queried domain: an issuance's `dns_names` carries *every* identity on
the certificate, so a shared/multi-tenant cert lists other tenants' names -
`scoped_hostnames` drops those, like the other discovery sources do.
"""

from __future__ import annotations

from posint_scanner.models import DiscoveredHostname
from posint_scanner.retry import with_retry
from posint_scanner.sources.base import QuotaExhaustedError
from posint_scanner.sources.common import ApiKeySource, http_get, scoped_hostnames

API_URL = "https://api.certspotter.com/v1/issuances"
# Issuances requested per page. The keyless tier caps a response well below
# this; a token lifts it. Pagination continues while a full page comes back.
PAGE_SIZE = 100
MAX_PAGES = 5


def extract_dns_names(entries: list[dict]) -> list[str]:
    """Every DNS name across the issuances on one page (unscoped, with dups -
    `scoped_hostnames` filters and dedupes)."""
    names: list[str] = []
    for entry in entries:
        names.extend(entry.get("dns_names") or [])
    return names


class CertSpotterSource(ApiKeySource):
    name = "certspotter"
    key_required = False

    def _get(self, domain: str, after: str | None) -> list[dict]:
        params: dict[str, str | int] = {
            "domain": domain,
            "include_subdomains": "true",
            "expand": "dns_names",
            "limit": PAGE_SIZE,
        }
        if after:
            params["after"] = after
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        response = http_get(self.name, API_URL, params=params, headers=headers, ok_statuses=(429,))
        if response.status_code == 429:
            raise QuotaExhaustedError("certspotter rate limit reached")
        return response.json()

    @with_retry
    def discover(self, domain: str) -> list[DiscoveredHostname]:
        names: list[str] = []
        after: str | None = None
        for page in range(MAX_PAGES):
            if page and not self.extra_request():
                break
            entries = self._get(domain, after)
            if not entries:
                break
            names.extend(extract_dns_names(entries))
            after = str(entries[-1].get("id") or "")
            if len(entries) < PAGE_SIZE or not after:
                break
        return scoped_hostnames(domain, names, self.name)
