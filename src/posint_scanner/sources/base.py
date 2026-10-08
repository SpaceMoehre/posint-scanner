"""Abstract interface every data source implements.

A source can support discovery (domain -> hostnames), enrichment
(ip/hostname -> services + data), collection (domain -> domain-level data,
e.g. registration records), or any mix - nothing requires a source to pick
one role. The registry (registry.py) is what decides which sources
run at which pipeline stage, based on which methods a source overrides.
"""

from __future__ import annotations

import threading
from abc import ABC
from collections.abc import Callable
from typing import ClassVar

from pydantic import BaseModel, ConfigDict

from posint_scanner.models import DiscoveredHostname, EnrichmentResult

# Default time-to-live for a metered source's result: a target it already
# answered for within this many days isn't re-queried (see governor.py).
DEFAULT_TTL_DAYS = 7.0


class SourceSettings(BaseModel):
    """Config-file/env settings every source accepts (`sources: {<name>: ...}`
    in config.yaml, or `OSINT_<SOURCE>_<FIELD>`). A source with its own
    settings (API keys, URLs) subclasses this and points `settings_model` at
    it. Unknown keys are rejected so a typo'd key fails loudly rather than
    silently leaving a source unconfigured.

    Every governance field left as None falls back to the class default the
    source declares (see Source)."""

    model_config = ConfigDict(extra="forbid")

    # None = decided by the source's category default (config `defaults:`).
    enabled: bool | None = None
    # Run a `*_web` fallback source even though its API sibling is configured.
    force: bool = False
    ttl_days: float | None = None
    requests_per_minute: float | None = None
    daily_budget: int | None = None
    monthly_budget: int | None = None


class SourceUnavailableError(Exception):
    """Raised when a source can't run at all (missing binary, missing API key).

    The orchestrator catches this, logs a warning, and skips the source for
    the run rather than failing the whole scan.
    """


class QuotaExhaustedError(SourceUnavailableError):
    """Raised when the provider itself says the quota is used up. Unlike a
    plain SourceUnavailableError (missing key - nothing sent), the request
    was made and counts; the governor stops calling the source for the rest
    of the run."""


# Set by the governor on the thread running a governed call: lets the call
# ask permission (budget + pacing) for each extra request it makes.
_call_context = threading.local()


def set_extra_request_hook(hook: Callable[[Source], bool] | None) -> None:
    _call_context.extra_request = hook


class ScrapeParseError(Exception):
    """Raised by a scraper when a page fetched fine (HTTP 200) but yielded
    none of the fields it expects - the signature of the site's markup having
    changed. The orchestrator logs it as a warning and records it
    (`parse_warning`) on the target instead of treating it as "no data", and
    since it's a failed call, the governor won't count it as a fresh result.
    """


class Source(ABC):
    """Base class for a pluggable OSINT data source.

    Subclasses set `name` and override `discover` and/or `enrich`. A
    subclass that doesn't override one of these simply doesn't participate
    in that pipeline stage - the orchestrator checks `can_discover` /
    `can_enrich` rather than requiring both.

    Thread-safety: one instance of each source is built by
    registry.build_sources() and reused across every concurrently-running
    domain pipeline (see orchestrator.run_scan's cross-domain
    ThreadPoolExecutor) and across every concurrent discover()/enrich()
    call within a single domain's own thread pool. Every source today only
    holds read-only config set in __init__ (API keys, credentials), which
    is safe to share without synchronization. A source that needs to keep
    per-call mutable state (a rate-limit timestamp, a cache) must protect
    it itself - see NvdClient in nvd.py for the pattern (a lock guarding
    the state, one shared instance rather than one per caller).
    """

    name: str = "unnamed-source"

    # "passive" (queries a resolver or third-party API), "scrape" (parses a
    # service's public HTML pages instead of a documented API - ToS/robots
    # sensitive) or "active" (sends traffic straight to the target). Decides
    # the default enablement via config `defaults:` (see registry.py).
    category: ClassVar[str] = "passive"
    # Overrides the category default when set - e.g. False for a stub that
    # can't run yet. Config `enabled:` and CLI flags still win over this.
    default_enabled: ClassVar[bool | None] = None
    # Name of the API source this one is a keyless stand-in for (e.g.
    # shodan_web -> shodan). Skipped when that sibling is configured, unless
    # forced (see registry.py).
    fallback_for: ClassVar[str | None] = None
    settings_model: ClassVar[type[SourceSettings]] = SourceSettings

    # Governance (enforced by governor.py, overridable per source in config).
    # ttl_days: skip a target this source answered for more recently than
    # this (0 = always query). Budgets count calls in a rolling day/30 days.
    ttl_days: float = 0.0
    requests_per_minute: float | None = None
    daily_budget: int | None = None
    monthly_budget: int | None = None

    # What kind of identifier the orchestrator should pass as `target` to
    # `enrich`: "ip" (most sources - Shodan, VMDR, PTR lookups) or
    # "hostname" (SNI-based TLS analysis like SSL Labs, where the same IP
    # can give different results per hostname).
    enrich_target_kind: str = "ip"

    @classmethod
    def from_settings(cls, settings: SourceSettings) -> Source:
        """Build an instance from its resolved settings. Sources with
        credentials/options override this; governance fields are applied
        afterwards by `configure`, so overrides needn't handle them."""
        return cls()

    def configure(self, settings: SourceSettings) -> None:
        """Apply the governance fields a user set in config over the class
        defaults (instance attributes shadow the class ones)."""
        if settings.ttl_days is not None:
            self.ttl_days = settings.ttl_days
        if settings.requests_per_minute is not None:
            self.requests_per_minute = settings.requests_per_minute
        if settings.daily_budget is not None:
            self.daily_budget = settings.daily_budget
        if settings.monthly_budget is not None:
            self.monthly_budget = settings.monthly_budget

    def extra_request(self) -> bool:
        """Ask before an extra request within one call (e.g. the next page).
        Under the governor it's charged to the budget and paced like a call;
        False means the budget is spent - stop and return what you have.
        Outside a governed call (tests, ad-hoc use) it's always allowed."""
        hook = getattr(_call_context, "extra_request", None)
        return True if hook is None else bool(hook(self))

    @property
    def is_configured(self) -> bool:
        """Whether this source has what it needs to run (API keys etc.).
        Keyless sources are always configured."""
        return True

    def discover(self, domain: str) -> list[DiscoveredHostname]:
        raise NotImplementedError(f"{self.name} does not support discovery")

    def enrich(self, target: str, hostnames: list[str]) -> EnrichmentResult:
        """Enrich a single IP address (`target`).

        `hostnames` is the list of hostnames currently known to resolve to
        this IP, provided for sources whose API is hostname-keyed rather
        than IP-keyed.
        """
        raise NotImplementedError(f"{self.name} does not support enrichment")

    def collect(self, domain: str) -> EnrichmentResult:
        """Domain-level data (target_type "domain"), e.g. registration
        records. `related_hostnames` feed back like enrichment's do."""
        raise NotImplementedError(f"{self.name} does not support collection")

    @property
    def can_collect(self) -> bool:
        return type(self).collect is not Source.collect

    @property
    def can_discover(self) -> bool:
        return type(self).discover is not Source.discover

    @property
    def can_enrich(self) -> bool:
        return type(self).enrich is not Source.enrich
