import threading

import pytest

from posint_scanner.db import Database


@pytest.fixture
def db():
    database = Database(":memory:")
    database.init_schema()
    yield database
    database.close()


class TestConcurrentAccess:
    def test_many_threads_upserting_the_same_domain_yields_one_row(self, db):
        results: list[int] = []
        errors: list[Exception] = []

        def worker():
            try:
                results.append(db.upsert_domain("example.com"))
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert len(db.list_domains()) == 1
        assert len(set(results)) == 1  # every thread got the same domain id

    def test_many_threads_writing_distinct_hostnames_all_persist(self, db):
        domain_id = db.upsert_domain("example.com")
        errors: list[Exception] = []

        def worker(i: int):
            try:
                db.upsert_hostname(domain_id, f"host{i}.example.com")
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert len(db.list_hostnames_for_domain(domain_id)) == 50

    def test_concurrent_reads_and_writes_do_not_raise(self, db):
        domain_id = db.upsert_domain("example.com")
        errors: list[Exception] = []

        def writer(i: int):
            try:
                db.upsert_hostname(domain_id, f"host{i}.example.com")
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        def reader():
            try:
                db.list_hostnames_for_domain(domain_id)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [
            threading.Thread(target=writer, args=(i,)) if i % 2 == 0 else threading.Thread(target=reader)
            for i in range(60)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
