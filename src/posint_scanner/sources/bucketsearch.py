"""Collection source that looks for the domain's cloud storage buckets and
whether they're world-readable.

Bucket names are guessed from the domain (its registrable label plus common
suffixes like `-backups`, `-dev`, `-assets`) plus any names you supply, then
each is checked against S3, GCS and Azure Blob:

  - HTTP 200 to a listing request => "public" (the bucket lists its contents
    to anyone) - a real exposure finding;
  - 401/403 => "private" (the bucket exists but denies anonymous access);
  - 404 / no such host => not a bucket, dropped.

This connects straight to the cloud providers' endpoints with guessed names,
so it's an "active" source and off by default. Enable it with
`--source bucketsearch` or `sources: {bucketsearch: {enabled: true, extra:
[...] }}`. It never reads or downloads bucket contents - only the listing
status. Findings are candidates: a same-named bucket may belong to someone
else, so confirm ownership before acting.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

import requests

from posint_scanner.models import CloudAsset, EnrichmentResult
from posint_scanner.scope import registrable_domain
from posint_scanner.sources.base import Source, SourceSettings
from posint_scanner.sources.common import USER_AGENT, VERIFY_TLS

logger = logging.getLogger(__name__)

PROVIDERS = ("s3", "gcs", "azure")
TIMEOUT_SECONDS = 10
DEFAULT_WORKERS = 20

# Common bucket-name suffixes on the domain's label. "" is the bare label.
DEFAULT_PERMUTATIONS = [
    "", "-dev", "-development", "-prod", "-production", "-staging", "-stage",
    "-test", "-backup", "-backups", "-assets", "-static", "-media", "-images",
    "-uploads", "-files", "-data", "-logs", "-public", "-private", "-web",
    "-www", "-cdn", "-storage", "-app", "-api", "-internal", "-archive",
]

_ACCESS_DENIED = {401, 403}


def bucket_url(provider: str, name: str) -> str:
    if provider == "s3":
        return f"https://{name}.s3.amazonaws.com/"
    if provider == "gcs":
        return f"https://storage.googleapis.com/{name}/"
    if provider == "azure":
        return f"https://{name}.blob.core.windows.net/?comp=list&maxresults=1"
    raise ValueError(f"unknown provider {provider!r}")


def classify(provider: str, status: int | None) -> str | None:
    """Map an HTTP status to exposure: "public", "private", or None (no such
    bucket / unreachable). Same mapping across providers today, but kept
    per-provider since their status conventions could diverge."""
    if status == 200:
        return "public"
    if status in _ACCESS_DENIED:
        return "private"
    return None


def candidate_bucket_names(domain: str, extra: list[str], permutations: list[str]) -> list[str]:
    """Guessed bucket names: `<label><suffix>` for the domain's registrable
    label, plus any `extra` names. Lowercased, deduped in first-seen order."""
    label = (registrable_domain(domain) or domain).split(".")[0].lower()
    names: list[str] = []
    seen: set[str] = set()
    for candidate in [f"{label}{suffix}" for suffix in permutations] + list(extra):
        candidate = candidate.strip().lower()
        if candidate and candidate not in seen:
            seen.add(candidate)
            names.append(candidate)
    return names


def _default_http_status(url: str) -> int | None:
    try:
        response = requests.get(
            url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT_SECONDS,
            stream=True, verify=VERIFY_TLS,
        )
        response.close()
        return response.status_code
    except requests.RequestException:
        return None


class BucketSearchSettings(SourceSettings):
    extra: list[str] = []
    providers: list[str] | None = None
    workers: int = DEFAULT_WORKERS


class BucketSearchSource(Source):
    name = "bucketsearch"
    category = "active"
    settings_model = BucketSearchSettings
    default_enabled = False  # probes cloud endpoints with guessed names

    def __init__(
        self,
        extra: list[str] | None = None,
        providers: list[str] | None = None,
        workers: int = DEFAULT_WORKERS,
        permutations: list[str] | None = None,
        http_status: Callable[[str], int | None] | None = None,
    ) -> None:
        self.extra = extra or []
        self.providers = providers or list(PROVIDERS)
        self.workers = workers
        self.permutations = permutations if permutations is not None else DEFAULT_PERMUTATIONS
        self._http_status = http_status or _default_http_status

    @classmethod
    def from_settings(cls, settings: SourceSettings) -> BucketSearchSource:
        assert isinstance(settings, BucketSearchSettings)
        return cls(extra=settings.extra, providers=settings.providers, workers=settings.workers)

    def collect(self, domain: str) -> EnrichmentResult:
        names = candidate_bucket_names(domain, self.extra, self.permutations)
        checks = [(provider, name) for provider in self.providers for name in names]

        def check(job: tuple[str, str]) -> CloudAsset | None:
            provider, name = job
            url = bucket_url(provider, name)
            exposure = classify(provider, self._http_status(url))
            if exposure is None:
                return None
            # Store the browseable base URL, not the listing query string.
            base = url.split("?", 1)[0]
            return CloudAsset(provider=provider, name=name, url=base, exposure=exposure)

        assets: list[CloudAsset] = []
        with ThreadPoolExecutor(max_workers=max(1, self.workers)) as executor:
            for asset in executor.map(check, checks):
                if asset is not None:
                    assets.append(asset)

        public = sum(1 for a in assets if a.exposure == "public")
        logger.info(
            "bucketsearch for %s: %d buckets found (%d public) across %d checks",
            domain, len(assets), public, len(checks),
        )
        return EnrichmentResult(
            source=self.name,
            target_type="domain",
            target=domain,
            data={
                "buckets_checked": len(checks),
                "public": public,
                "private": len(assets) - public,
            },
            cloud_assets=assets,
        )
