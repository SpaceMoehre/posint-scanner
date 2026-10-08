"""Per-source call governance: TTL skipping, quota budgets, rate limiting.

Free API tiers are tiny (VirusTotal 500/day, SecurityTrails 50/month) and
paid ones bill per call, so every discover/enrich call the orchestrator makes
goes through SourceGovernor.run, which may decline it:

  - TTL: a target this source already answered for successfully within its
    `ttl_days` is skipped - re-scans (automatic continuation) would otherwise
    re-spend credits on unchanged data. `fresh=True` (`--fresh`) bypasses it.
  - Budget: `daily_budget` / `monthly_budget` cap calls in a rolling 24h /
    30-day window. Once hit, the source is skipped for the rest of the run.
  - Rate limit: `requests_per_minute` paces calls to that source.

The TTL/budget ledger lives in the database (`source_calls`), so limits hold
across runs. Pacing is in-memory but shared process-wide (see pacing.py).

Budgets count requests: each call, plus every extra request a call makes
(a further page) via Source.extra_request(). TTL is per call and target.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import TypeVar

from posint_scanner.db import Database
from posint_scanner.pacing import DEFAULT_LIMITERS, RateLimiters
from posint_scanner.sources.base import (
    QuotaExhaustedError,
    Source,
    SourceUnavailableError,
    set_extra_request_hook,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")

DAY = timedelta(days=1)
MONTH = timedelta(days=30)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# Serializes budget check + reservation so concurrent calls can't overspend.
_BUDGET_LOCK = threading.Lock()


class SourceGovernor:
    """Built once per scan run and shared by every stage/thread in it."""

    def __init__(
        self,
        db: Database,
        fresh: bool = False,
        now: Callable[[], datetime] = _utcnow,
        limiters: RateLimiters = DEFAULT_LIMITERS,
    ) -> None:
        self.db = db
        self.fresh = fresh
        self._now = now
        self._limiters = limiters
        self._exhausted: set[str] = set()

    def run(self, source: Source, target_type: str, target: str, call: Callable[[], T]) -> T | None:
        """Make `call` on behalf of `source` for `target`, or return None if
        governance declined it (fresh result exists, budget spent). The
        call's own exceptions propagate after being recorded as a failure."""
        if self._is_fresh(source, target_type, target):
            logger.debug("%s: %s %s still fresh - skipped", source.name, target_type, target)
            return None
        call_id = self._reserve(source, target_type, target)
        if call_id is None:
            return None
        if source.requests_per_minute:
            self._limiters.wait(source.name, source.requests_per_minute)
        set_extra_request_hook(
            lambda src: self._extra_request(src, target_type, target)
        )
        try:
            result = call()
        except QuotaExhaustedError as exc:
            # The provider refused on quota: the request was made, and every
            # further one this run would be refused too.
            self.db.finish_source_call(call_id, ok=False)
            with _BUDGET_LOCK:
                self._exhausted.add(source.name)
            logger.warning("%s: provider quota exhausted (%s) - skipping it for the rest of "
                           "this run", source.name, exc)
            raise
        except SourceUnavailableError:
            # Missing key/binary: nothing was sent, so nothing was spent.
            self.db.cancel_source_call(call_id)
            raise
        except BaseException:
            self.db.finish_source_call(call_id, ok=False)
            raise
        finally:
            set_extra_request_hook(None)
        self.db.finish_source_call(call_id, ok=True)
        return result

    def _extra_request(self, source: Source, target_type: str, target: str) -> bool:
        call_id = self._reserve(source, target_type, target)
        if call_id is None:
            return False
        # Recorded as not-ok so only the call itself marks the target fresh.
        self.db.finish_source_call(call_id, ok=False)
        if source.requests_per_minute:
            self._limiters.wait(source.name, source.requests_per_minute)
        return True

    def _is_fresh(self, source: Source, target_type: str, target: str) -> bool:
        if self.fresh or source.ttl_days <= 0:
            return False
        last = self.db.last_successful_source_call(source.name, target_type, target)
        if last is None:
            return False
        return datetime.fromisoformat(last) > self._now() - timedelta(days=source.ttl_days)

    def _reserve(self, source: Source, target_type: str, target: str) -> int | None:
        with _BUDGET_LOCK:
            if source.name in self._exhausted:
                return None
            now = self._now()
            for budget, window, label in (
                (source.daily_budget, DAY, "daily"),
                (source.monthly_budget, MONTH, "monthly"),
            ):
                if budget is None:
                    continue
                used = self.db.count_source_calls_since(source.name, (now - window).isoformat())
                if used >= budget:
                    self._exhausted.add(source.name)
                    logger.warning(
                        "%s: %s budget of %d calls spent - skipping it for the rest of this run",
                        source.name,
                        label,
                        budget,
                    )
                    return None
            return self.db.begin_source_call(source.name, target_type, target, now.isoformat())
