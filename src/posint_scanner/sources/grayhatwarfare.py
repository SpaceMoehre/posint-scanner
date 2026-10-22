"""Collection source using GrayHatWarfare's open-bucket index
(https://buckets.grayhatwarfare.com).

A passive counterpart to `bucketsearch`: instead of guessing bucket names and
probing cloud endpoints directly (active), this queries GrayHatWarfare's
pre-built index of *already-public* buckets by the domain's label - catching
buckets whose names you'd never guess, and world-readable ones that leak
`.env`/`.sql`/backup files. Every result is a public (listable) bucket.

Needs a free API token (grayhatwarfare.com), sent as a Bearer token. Results
are candidates: a name matching the label may belong to someone else, so
confirm ownership before acting - the same caveat as `bucketsearch`.
"""

from __future__ import annotations

import logging

from posint_scanner.models import CloudAsset, EnrichmentResult
from posint_scanner.retry import with_retry
from posint_scanner.scope import registrable_domain
from posint_scanner.sources.common import ApiKeySource, http_get

logger = logging.getLogger(__name__)

API_URL = "https://buckets.grayhatwarfare.com/api/v2/buckets"
# The API's documented maximum page size; one request then covers all but the
# most prolific labels without paging guesswork.
RESULT_LIMIT = 1000
# GrayHatWarfare's `type` enum -> the provider names the rest of the tool uses.
_PROVIDER = {"aws": "s3", "gcp": "gcs", "azure": "azure", "dos": "dos", "ali": "ali"}


def parse_buckets(payload: dict) -> list[CloudAsset]:
    assets: list[CloudAsset] = []
    for bucket in payload.get("buckets") or []:
        host = bucket.get("bucket")
        if not host:
            continue
        type_ = (bucket.get("type") or "").lower()
        assets.append(CloudAsset(
            provider=_PROVIDER.get(type_, type_ or "unknown"),
            name=host,
            url=f"http://{host}",
            exposure="public",  # GrayHatWarfare indexes world-listable buckets
        ))
    return assets


class GrayHatWarfareSource(ApiKeySource):
    name = "grayhatwarfare"

    @with_retry
    def collect(self, domain: str) -> EnrichmentResult:
        label = (registrable_domain(domain) or domain).split(".")[0].lower()
        payload = http_get(
            self.name,
            API_URL,
            params={"keywords": label, "limit": RESULT_LIMIT},
            headers={"Authorization": f"Bearer {self.require_key()}"},
        ).json()
        assets = parse_buckets(payload)
        logger.info("grayhatwarfare for %s: %d public buckets matching %r", domain, len(assets), label)
        return EnrichmentResult(
            source=self.name,
            target_type="domain",
            target=domain,
            data={"keyword": label, "buckets_found": len(assets)},
            cloud_assets=assets,
        )
