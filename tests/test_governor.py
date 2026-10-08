from datetime import datetime, timedelta, timezone

import pytest

from posint_scanner.db import Database
from posint_scanner.governor import RateLimiters, SourceGovernor
from posint_scanner.sources.base import QuotaExhaustedError, Source, SourceUnavailableError

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


class Clock:
    """Wall clock (for TTL/budget windows) + monotonic clock/sleep (for pacing)."""

    def __init__(self):
        self.now = T0
        self.mono = 0.0
        self.slept: list[float] = []

    def wall(self):
        return self.now

    def monotonic(self):
        return self.mono

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.mono += seconds

    def advance(self, **kwargs):
        self.now += timedelta(**kwargs)
        self.mono += timedelta(**kwargs).total_seconds()


class Metered(Source):
    name = "metered"


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "t.db")
    database.init_schema()
    yield database
    database.close()


@pytest.fixture
def clock():
    return Clock()


def governor(db, clock, fresh=False):
    return SourceGovernor(
        db,
        fresh=fresh,
        now=clock.wall,
        limiters=RateLimiters(monotonic=clock.monotonic, sleep=clock.sleep),
    )


def source(**attrs):
    s = Metered()
    for key, value in attrs.items():
        setattr(s, key, value)
    return s


class TestTtl:
    def test_no_ttl_always_calls(self, db, clock):
        gov, src = governor(db, clock), source(ttl_days=0)
        assert gov.run(src, "ip", "1.2.3.4", lambda: "a") == "a"
        assert gov.run(src, "ip", "1.2.3.4", lambda: "b") == "b"

    def test_fresh_result_skips_same_target(self, db, clock):
        gov, src = governor(db, clock), source(ttl_days=7)
        assert gov.run(src, "ip", "1.2.3.4", lambda: "a") == "a"
        clock.advance(days=6)
        assert gov.run(src, "ip", "1.2.3.4", lambda: "b") is None

    def test_other_targets_unaffected(self, db, clock):
        gov, src = governor(db, clock), source(ttl_days=7)
        gov.run(src, "ip", "1.2.3.4", lambda: "a")
        assert gov.run(src, "ip", "5.6.7.8", lambda: "b") == "b"

    def test_ttl_survives_across_runs(self, db, clock):
        src = source(ttl_days=7)
        governor(db, clock).run(src, "domain", "example.com", lambda: "a")
        assert governor(db, clock).run(src, "domain", "example.com", lambda: "b") is None

    def test_expired_result_is_requeried(self, db, clock):
        gov, src = governor(db, clock), source(ttl_days=7)
        gov.run(src, "ip", "1.2.3.4", lambda: "a")
        clock.advance(days=8)
        assert gov.run(src, "ip", "1.2.3.4", lambda: "b") == "b"

    def test_fresh_flag_bypasses_ttl(self, db, clock):
        src = source(ttl_days=7)
        governor(db, clock).run(src, "ip", "1.2.3.4", lambda: "a")
        assert governor(db, clock, fresh=True).run(src, "ip", "1.2.3.4", lambda: "b") == "b"

    def test_failed_call_does_not_count_as_fresh(self, db, clock):
        gov, src = governor(db, clock), source(ttl_days=7)

        def boom():
            raise RuntimeError("down")

        with pytest.raises(RuntimeError):
            gov.run(src, "ip", "1.2.3.4", boom)
        assert gov.run(src, "ip", "1.2.3.4", lambda: "b") == "b"


class TestBudget:
    def test_daily_budget_stops_calls(self, db, clock):
        gov, src = governor(db, clock), source(daily_budget=2)
        assert gov.run(src, "ip", "a", lambda: 1) == 1
        assert gov.run(src, "ip", "b", lambda: 2) == 2
        assert gov.run(src, "ip", "c", lambda: 3) is None

    def test_budget_persists_across_runs(self, db, clock):
        src = source(daily_budget=1)
        governor(db, clock).run(src, "ip", "a", lambda: 1)
        assert governor(db, clock).run(src, "ip", "b", lambda: 2) is None

    def test_daily_budget_is_rolling(self, db, clock):
        src = source(daily_budget=1)
        governor(db, clock).run(src, "ip", "a", lambda: 1)
        clock.advance(hours=25)
        assert governor(db, clock).run(src, "ip", "b", lambda: 2) == 2

    def test_monthly_budget(self, db, clock):
        src = source(monthly_budget=1)
        governor(db, clock).run(src, "ip", "a", lambda: 1)
        clock.advance(days=20)
        assert governor(db, clock).run(src, "ip", "b", lambda: 2) is None
        clock.advance(days=11)
        assert governor(db, clock).run(src, "ip", "c", lambda: 3) == 3

    def test_failed_calls_still_spend_budget(self, db, clock):
        # a request that errored may still have been billed - count it
        gov, src = governor(db, clock), source(daily_budget=1)
        with pytest.raises(RuntimeError):
            gov.run(src, "ip", "a", lambda: (_ for _ in ()).throw(RuntimeError()))
        assert gov.run(src, "ip", "b", lambda: 2) is None

    def test_unavailable_source_spends_no_budget(self, db, clock):
        # SourceUnavailableError = missing key/binary: no request was made
        gov, src = governor(db, clock), source(daily_budget=1)

        def unavailable():
            raise SourceUnavailableError("no key")

        with pytest.raises(SourceUnavailableError):
            gov.run(src, "ip", "a", unavailable)
        assert gov.run(src, "ip", "b", lambda: 2) == 2

    def test_budget_is_per_source(self, db, clock):
        gov = governor(db, clock)
        one = source(daily_budget=1)
        other = source(daily_budget=1)
        other.name = "other"
        gov.run(one, "ip", "a", lambda: 1)
        assert gov.run(other, "ip", "a", lambda: 2) == 2


class TestRateLimit:
    def test_calls_are_paced(self, db, clock):
        gov, src = governor(db, clock), source(requests_per_minute=6)
        gov.run(src, "ip", "a", lambda: 1)
        gov.run(src, "ip", "b", lambda: 2)
        assert clock.slept == [pytest.approx(10.0)]

    def test_no_wait_when_interval_already_passed(self, db, clock):
        gov, src = governor(db, clock), source(requests_per_minute=6)
        gov.run(src, "ip", "a", lambda: 1)
        clock.advance(seconds=11)
        gov.run(src, "ip", "b", lambda: 2)
        assert clock.slept == []

    def test_pacing_shared_across_governors(self, db, clock):
        # rate limits are enforced against this machine, not per scan
        limiters = RateLimiters(monotonic=clock.monotonic, sleep=clock.sleep)
        src = source(requests_per_minute=6)
        SourceGovernor(db, now=clock.wall, limiters=limiters).run(src, "ip", "a", lambda: 1)
        SourceGovernor(db, now=clock.wall, limiters=limiters).run(src, "ip", "b", lambda: 2)
        assert clock.slept == [pytest.approx(10.0)]

    def test_skipped_calls_are_not_paced(self, db, clock):
        gov, src = governor(db, clock), source(requests_per_minute=6, ttl_days=7)
        gov.run(src, "ip", "a", lambda: 1)
        gov.run(src, "ip", "a", lambda: 1)
        assert clock.slept == []


class Paged(Source):
    """Makes one request per page, asking the governor before each extra one."""

    name = "paged"

    def __init__(self, pages):
        self.pages = pages
        self.fetched = 0

    def fetch_all(self):
        for page in range(self.pages):
            if page and not self.extra_request():
                break
            self.fetched += 1
        return self.fetched


class TestExtraRequests:
    def test_each_extra_page_spends_budget(self, db, clock):
        gov, src = governor(db, clock), Paged(pages=3)
        src.daily_budget = 5
        gov.run(src, "domain", "a.com", src.fetch_all)
        assert db.count_source_calls_since(src.name, "2000-01-01") == 3

    def test_paging_stops_when_budget_runs_out_mid_call(self, db, clock):
        gov, src = governor(db, clock), Paged(pages=5)
        src.daily_budget = 2
        assert gov.run(src, "domain", "a.com", src.fetch_all) == 2

    def test_extra_pages_are_paced(self, db, clock):
        gov, src = governor(db, clock), Paged(pages=2)
        src.requests_per_minute = 6
        gov.run(src, "domain", "a.com", src.fetch_all)
        assert clock.slept == [pytest.approx(10.0)]

    def test_outside_a_governed_call_extra_requests_are_allowed(self):
        assert Paged(pages=2).fetch_all() == 2


class TestQuotaExhausted:
    def test_provider_quota_error_spends_the_call_and_stops_the_source(self, db, clock):
        gov, src = governor(db, clock), source()
        calls = []

        def exhausted():
            calls.append(1)
            raise QuotaExhaustedError("provider says no")

        with pytest.raises(QuotaExhaustedError):
            gov.run(src, "ip", "a", exhausted)
        assert gov.run(src, "ip", "b", exhausted) is None
        assert calls == [1]
        assert db.count_source_calls_since(src.name, "2000-01-01") == 1
