"""Process-wide request pacing per source name.

An API's rate limit applies to this machine however many scans (e.g.
concurrent web-UI jobs) or source instances are running, so pacers live in
one shared registry (DEFAULT_LIMITERS) keyed by source name - the same
reasoning as NvdClient. The governor paces each call; a source that makes
extra requests within one call (pagination) are paced via
Source.extra_request(), against the same pacer.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable


class _Pacer:
    def __init__(self, monotonic: Callable[[], float], sleep: Callable[[float], None]) -> None:
        self._monotonic = monotonic
        self._sleep = sleep
        self._last: float | None = None
        self._lock = threading.Lock()

    def wait(self, min_interval: float) -> None:
        with self._lock:
            if self._last is not None:
                elapsed = self._monotonic() - self._last
                if elapsed < min_interval:
                    self._sleep(min_interval - elapsed)
            self._last = self._monotonic()


class RateLimiters:
    """One pacer per source name."""

    def __init__(
        self,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._monotonic = monotonic
        self._sleep = sleep
        self._pacers: dict[str, _Pacer] = {}
        self._lock = threading.Lock()

    def wait(self, name: str, requests_per_minute: float) -> None:
        with self._lock:
            pacer = self._pacers.setdefault(name, _Pacer(self._monotonic, self._sleep))
        pacer.wait(60.0 / requests_per_minute)


DEFAULT_LIMITERS = RateLimiters()
