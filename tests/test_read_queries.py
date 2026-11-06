"""Every page reads the DB in a fixed number of queries, whatever its size.

A per-IP or per-hostname query loop makes a page cost thousands of queries
on a real scan DB - and under a running scan each one waits its turn - so
seed the same shape at two sizes and require the same count.
"""

from __future__ import annotations

import pytest

from posint_scanner.db import Database
from posint_scanner.export.findings_report import render_report
from posint_scanner.readmodel import build_dashboard, build_domain, build_ip, build_overview
from scale_seed import seed

PAGES = {
    "dashboard": lambda db: build_dashboard(db),
    "overview": lambda db: build_overview(db),
    "overview of one domain": lambda db: build_overview(db, "example1.com"),
    "domain": lambda db: build_domain(db, "example1.com"),
    "ip": lambda db: build_ip(db, "10.0.1.1"),
    "shared ip": lambda db: build_ip(db, "203.0.113.250"),
    "findings report": lambda db: render_report(db),
    "findings report of one domain": lambda db: render_report(db, ["example1.com"]),
}


def _queries(db: Database, page) -> int:
    count = 0

    def trace(statement: str) -> None:
        nonlocal count
        count += statement.lstrip().upper().startswith(("SELECT", "WITH"))

    db.conn.set_trace_callback(trace)
    try:
        page(db)
    finally:
        db.conn.set_trace_callback(None)
    return count


@pytest.fixture(scope="module")
def dbs(tmp_path_factory):
    small = Database(tmp_path_factory.mktemp("small") / "s.db")
    large = Database(tmp_path_factory.mktemp("large") / "l.db")
    for db, domains, ips in ((small, 2, 2), (large, 6, 12)):
        db.init_schema()
        seed(db, domains, ips)
    yield small, large
    small.close()
    large.close()


@pytest.mark.parametrize("name", PAGES)
def test_query_count_does_not_grow_with_the_data(dbs, name):
    small, large = dbs
    page = PAGES[name]
    assert _queries(large, page) == _queries(small, page)
