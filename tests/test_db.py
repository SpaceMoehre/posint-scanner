import json

import pytest

from posint_scanner.db import Database


@pytest.fixture
def db():
    database = Database(":memory:")
    database.init_schema()
    yield database
    database.close()


class TestSchemaUpgrade:
    def test_adds_version_column_to_pre_existing_services_table_without_data_loss(self):
        database = Database(":memory:")
        # simulate a database created before the `version` column existed
        database.conn.executescript(
            """
            CREATE TABLE domains (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, added_at TEXT NOT NULL);
            CREATE TABLE ip_addresses (id INTEGER PRIMARY KEY, address TEXT NOT NULL UNIQUE, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL);
            CREATE TABLE services (
                id INTEGER PRIMARY KEY,
                ip_id INTEGER NOT NULL REFERENCES ip_addresses(id),
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL DEFAULT 'tcp',
                banner TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                UNIQUE (ip_id, port, protocol)
            );
            """
        )
        ip_id = database.upsert_ip("1.2.3.4")
        database.conn.execute(
            "INSERT INTO services (ip_id, port, protocol, banner, first_seen, last_seen) "
            "VALUES (?, 443, 'tcp', 'nginx', '2026-01-01', '2026-01-01')",
            (ip_id,),
        )
        database.conn.commit()

        database.init_schema()  # should add `version` without dropping existing rows

        services = database.list_services_for_ip(ip_id)
        assert len(services) == 1
        assert services[0]["banner"] == "nginx"
        assert services[0]["version"] is None
        database.close()

    def test_running_init_schema_twice_on_a_new_db_is_a_no_op(self, db):
        db.init_schema()  # already called once by the fixture - must not raise
        ip_id = db.upsert_ip("1.2.3.4")
        db.upsert_service(ip_id, 443, version="1.0")
        assert db.list_services_for_ip(ip_id)[0]["version"] == "1.0"


class TestDomains:
    def test_upsert_domain_creates_row(self, db):
        domain_id = db.upsert_domain("example.com")
        row = db.get_domain_by_name("example.com")
        assert row["id"] == domain_id
        assert row["name"] == "example.com"

    def test_upsert_domain_is_idempotent(self, db):
        first_id = db.upsert_domain("example.com")
        second_id = db.upsert_domain("example.com")
        assert first_id == second_id
        assert len(db.list_domains()) == 1


class TestHostnames:
    def test_upsert_hostname_creates_row(self, db):
        domain_id = db.upsert_domain("example.com")
        hostname_id = db.upsert_hostname(domain_id, "api.example.com")
        row = db.get_hostname_by_name("api.example.com")
        assert row["id"] == hostname_id
        assert row["domain_id"] == domain_id
        assert row["first_seen"] == row["last_seen"]

    def test_upsert_hostname_is_idempotent_and_bumps_last_seen(self, db):
        domain_id = db.upsert_domain("example.com")
        first_id = db.upsert_hostname(domain_id, "api.example.com", now="2026-01-01T00:00:00+00:00")
        second_id = db.upsert_hostname(domain_id, "api.example.com", now="2026-01-02T00:00:00+00:00")
        assert first_id == second_id
        row = db.get_hostname_by_name("api.example.com")
        assert row["first_seen"] == "2026-01-01T00:00:00+00:00"
        assert row["last_seen"] == "2026-01-02T00:00:00+00:00"

    def test_hostname_tracks_parent(self, db):
        domain_id = db.upsert_domain("example.com")
        parent_id = db.upsert_hostname(domain_id, "api.example.com")
        child_id = db.upsert_hostname(domain_id, "v2.api.example.com", parent_hostname_id=parent_id)
        row = db.get_hostname_by_name("v2.api.example.com")
        assert row["parent_hostname_id"] == parent_id
        children = db.list_child_hostnames(parent_id)
        assert [c["id"] for c in children] == [child_id]

    def test_list_hostnames_for_domain(self, db):
        domain_id = db.upsert_domain("example.com")
        other_domain_id = db.upsert_domain("other.com")
        db.upsert_hostname(domain_id, "api.example.com")
        db.upsert_hostname(domain_id, "www.example.com")
        db.upsert_hostname(other_domain_id, "www.other.com")
        names = {row["name"] for row in db.list_hostnames_for_domain(domain_id)}
        assert names == {"api.example.com", "www.example.com"}


class TestIpsAndResolutions:
    def test_upsert_ip_is_idempotent(self, db):
        first_id = db.upsert_ip("93.184.216.34")
        second_id = db.upsert_ip("93.184.216.34")
        assert first_id == second_id

    def test_resolution_links_hostname_and_ip(self, db):
        domain_id = db.upsert_domain("example.com")
        hostname_id = db.upsert_hostname(domain_id, "api.example.com")
        ip_id = db.upsert_ip("93.184.216.34")
        db.upsert_resolution(hostname_id, ip_id)

        ips = db.list_ips_for_hostname(hostname_id)
        assert [row["address"] for row in ips] == ["93.184.216.34"]

        hostnames = db.list_hostnames_for_ip(ip_id)
        assert [row["name"] for row in hostnames] == ["api.example.com"]

    def test_shared_ip_has_multiple_hostnames(self, db):
        domain_id = db.upsert_domain("example.com")
        h1 = db.upsert_hostname(domain_id, "www.example.com")
        h2 = db.upsert_hostname(domain_id, "shop.example.com")
        ip_id = db.upsert_ip("1.2.3.4")
        db.upsert_resolution(h1, ip_id)
        db.upsert_resolution(h2, ip_id)

        hostnames = {row["name"] for row in db.list_hostnames_for_ip(ip_id)}
        assert hostnames == {"www.example.com", "shop.example.com"}

    def test_resolution_upsert_is_idempotent(self, db):
        domain_id = db.upsert_domain("example.com")
        hostname_id = db.upsert_hostname(domain_id, "api.example.com")
        ip_id = db.upsert_ip("1.2.3.4")
        db.upsert_resolution(hostname_id, ip_id, now="2026-01-01T00:00:00+00:00")
        db.upsert_resolution(hostname_id, ip_id, now="2026-01-02T00:00:00+00:00")
        ips = db.list_ips_for_hostname(hostname_id)
        assert len(ips) == 1


class TestServices:
    def test_upsert_service_creates_row(self, db):
        ip_id = db.upsert_ip("1.2.3.4")
        service_id = db.upsert_service(ip_id, 443, protocol="tcp", banner="nginx")
        services = db.list_services_for_ip(ip_id)
        assert len(services) == 1
        assert services[0]["id"] == service_id
        assert services[0]["port"] == 443
        assert services[0]["banner"] == "nginx"

    def test_upsert_service_is_idempotent_per_port_protocol(self, db):
        ip_id = db.upsert_ip("1.2.3.4")
        first_id = db.upsert_service(ip_id, 443, protocol="tcp")
        second_id = db.upsert_service(ip_id, 443, protocol="tcp", banner="updated banner")
        assert first_id == second_id
        services = db.list_services_for_ip(ip_id)
        assert len(services) == 1
        assert services[0]["banner"] == "updated banner"

    def test_different_protocol_same_port_is_distinct(self, db):
        ip_id = db.upsert_ip("1.2.3.4")
        db.upsert_service(ip_id, 53, protocol="tcp")
        db.upsert_service(ip_id, 53, protocol="udp")
        services = db.list_services_for_ip(ip_id)
        assert len(services) == 2

    def test_upsert_service_stores_version(self, db):
        ip_id = db.upsert_ip("1.2.3.4")
        db.upsert_service(ip_id, 443, protocol="tcp", banner="nginx", version="1.18.0")
        services = db.list_services_for_ip(ip_id)
        assert services[0]["version"] == "1.18.0"

    def test_upsert_service_keeps_existing_version_if_new_value_is_none(self, db):
        ip_id = db.upsert_ip("1.2.3.4")
        db.upsert_service(ip_id, 443, protocol="tcp", version="1.18.0")
        db.upsert_service(ip_id, 443, protocol="tcp", banner="nginx (updated)")
        services = db.list_services_for_ip(ip_id)
        assert services[0]["version"] == "1.18.0"
        assert services[0]["banner"] == "nginx (updated)"

    def test_upsert_service_stores_cpe(self, db):
        ip_id = db.upsert_ip("1.2.3.4")
        db.upsert_service(ip_id, 443, cpe="cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*")
        services = db.list_services_for_ip(ip_id)
        assert services[0]["cpe"] == "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"


class TestResults:
    def test_insert_result_stores_json_data(self, db):
        ip_id = db.upsert_ip("1.2.3.4")
        db.insert_result("shodan", "ip", ip_id, {"org": "Example Inc", "ports": [80, 443]})
        results = db.list_results_for_target("ip", ip_id)
        assert len(results) == 1
        assert results[0]["source"] == "shodan"
        assert json.loads(results[0]["data"]) == {"org": "Example Inc", "ports": [80, 443]}

    def test_multiple_results_for_same_target_accumulate(self, db):
        ip_id = db.upsert_ip("1.2.3.4")
        db.insert_result("shodan", "ip", ip_id, {"a": 1})
        db.insert_result("qualys_ssllabs", "ip", ip_id, {"grade": "A"})
        results = db.list_results_for_target("ip", ip_id)
        assert len(results) == 2
        sources = {r["source"] for r in results}
        assert sources == {"shodan", "qualys_ssllabs"}


class TestContinuationPruning:
    def _db(self):
        db = Database(":memory:")
        db.init_schema()
        return db

    def test_delete_stale_resolutions_removes_unrefreshed_edge(self):
        db = self._db()
        did = db.upsert_domain("example.com")
        hid = db.upsert_hostname(did, "a.example.com")
        old_ip = db.upsert_ip("1.1.1.1")
        new_ip = db.upsert_ip("2.2.2.2")
        # old mapping from a prior run, plus a fresh one from this run
        db.upsert_resolution(hid, old_ip, now="2020-01-01T00:00:00+00:00")
        db.upsert_resolution(hid, new_ip, now="2026-01-01T00:00:00+00:00")

        removed = db.delete_stale_resolutions(did, cutoff="2025-01-01T00:00:00+00:00")
        assert removed == 1
        remaining = {r["address"] for r in db.list_ips_for_hostname(hid)}
        assert remaining == {"2.2.2.2"}

    def test_stale_edge_kept_when_hostname_had_no_fresh_resolution(self):
        # hostname resolved to nothing this run (e.g. transient DNS failure):
        # all its edges are old, none fresh -> guard keeps them untouched.
        db = self._db()
        did = db.upsert_domain("example.com")
        hid = db.upsert_hostname(did, "a.example.com")
        ip = db.upsert_ip("1.1.1.1")
        db.upsert_resolution(hid, ip, now="2020-01-01T00:00:00+00:00")

        removed = db.delete_stale_resolutions(did, cutoff="2025-01-01T00:00:00+00:00")
        assert removed == 0
        assert [r["address"] for r in db.list_ips_for_hostname(hid)] == ["1.1.1.1"]

    def test_delete_orphan_ips_cascades_services_and_results(self):
        db = self._db()
        did = db.upsert_domain("example.com")
        hid = db.upsert_hostname(did, "a.example.com")
        live_ip = db.upsert_ip("1.1.1.1")
        orphan_ip = db.upsert_ip("9.9.9.9")
        db.upsert_resolution(hid, live_ip)  # only the live IP is referenced
        db.upsert_service(orphan_ip, 445, "tcp", "SMB")
        db.insert_result("shodan_web", "ip", orphan_ip, {"x": 1})

        removed = db.delete_orphan_ips()
        assert removed == 1
        assert db.get_ip_by_address("9.9.9.9") is None
        assert db.get_ip_by_address("1.1.1.1") is not None
        assert db.list_services_for_ip(orphan_ip) == []
        assert db.list_results_for_target("ip", orphan_ip) == []

    def test_delete_orphan_ips_keeps_ip_referenced_by_another_domain(self):
        db = self._db()
        d1 = db.upsert_domain("a.com")
        d2 = db.upsert_domain("b.com")
        h1 = db.upsert_hostname(d1, "x.a.com")
        h2 = db.upsert_hostname(d2, "y.b.com")
        shared = db.upsert_ip("5.5.5.5")
        db.upsert_resolution(h2, shared)  # still referenced via the other domain
        assert db.delete_orphan_ips() == 0
        assert db.get_ip_by_address("5.5.5.5") is not None


class TestPrunedIpLosesFreshness:
    def test_orphan_ip_pruning_makes_its_ledger_entries_stale(self, tmp_path):
        # a pruned IP's results are deleted, so a TTL must not skip it if it
        # comes back - but the calls still count toward budgets
        with Database(tmp_path / "t.db") as db:
            db.init_schema()
            db.upsert_ip("1.2.3.4")
            call = db.begin_source_call("shodan", "ip", "1.2.3.4", "2026-01-01T00:00:00+00:00")
            db.finish_source_call(call, ok=True)
            assert db.delete_orphan_ips() == 1
            assert db.last_successful_source_call("shodan", "ip", "1.2.3.4") is None
            assert db.count_source_calls_since("shodan", "2000-01-01") == 1


class TestCloudAssets:
    def test_upsert_and_list(self, tmp_path):
        with Database(tmp_path / "t.db") as db:
            db.init_schema()
            domain_id = db.upsert_domain("example.com")
            db.upsert_cloud_asset(domain_id, "s3", "example-backups",
                                  "https://example-backups.s3.amazonaws.com/", "public", "bucketsearch")
            db.upsert_cloud_asset(domain_id, "s3", "example-backups",
                                  "https://example-backups.s3.amazonaws.com/", "private", "bucketsearch")
            rows = db.list_cloud_assets(domain_id)
        assert len(rows) == 1  # (domain, provider, name) is unique
        assert rows[0]["provider"] == "s3"
        assert rows[0]["exposure"] == "private"  # latest wins
        assert rows[0]["url"].endswith("amazonaws.com/")


class TestCodeExposures:
    def test_upsert_dedupes_ignoring_commit_and_updates_last_seen(self, tmp_path):
        with Database(tmp_path / "t.db") as db:
            db.init_schema()
            domain_id = db.upsert_domain("example.com")
            db.upsert_code_exposure(
                domain_id, kind="secret", target="api.example.com", repo="acme/app",
                path="app/.env", commit="a" * 40, url="https://github.com/x#L3", line=3,
                snippet=None, rule="aws_access_key_id", secret="AKIA...", now="2026-01-01T00:00:00Z")
            # same finding, later scan, file edited (new commit/line)
            db.upsert_code_exposure(
                domain_id, kind="secret", target="api.example.com", repo="acme/app",
                path="app/.env", commit="b" * 40, url="https://github.com/y#L7", line=7,
                snippet=None, rule="aws_access_key_id", secret="AKIA...", now="2026-02-02T00:00:00Z")
            rows = db.list_code_exposures(domain_id)
        assert len(rows) == 1
        assert rows[0]["first_seen"] == "2026-01-01T00:00:00Z"
        assert rows[0]["last_seen"] == "2026-02-02T00:00:00Z"
        assert rows[0]["commit"] == "b" * 40  # latest metadata wins
        assert rows[0]["line"] == 7

    def test_secrets_sort_before_references(self, tmp_path):
        with Database(tmp_path / "t.db") as db:
            db.init_schema()
            domain_id = db.upsert_domain("example.com")
            db.upsert_code_exposure(domain_id, kind="reference", target="a.example.com",
                                    repo="r", path="p", commit="c", url="u")
            db.upsert_code_exposure(domain_id, kind="secret", target="a.example.com",
                                    repo="r", path="q", commit="c", url="u", rule="jwt", secret="ey")
            rows = db.list_code_exposures(domain_id)
        assert [r["kind"] for r in rows] == ["secret", "reference"]

    def test_filter_by_target(self, tmp_path):
        with Database(tmp_path / "t.db") as db:
            db.init_schema()
            domain_id = db.upsert_domain("example.com")
            db.upsert_code_exposure(domain_id, kind="reference", target="a.example.com",
                                    repo="r", path="p", commit="c", url="u")
            db.upsert_code_exposure(domain_id, kind="reference", target="1.2.3.4",
                                    repo="r", path="p2", commit="c", url="u")
            rows = db.list_code_exposures(domain_id, target="1.2.3.4")
        assert [r["path"] for r in rows] == ["p2"]

    def test_reference_rows_dedupe_on_rescan(self, tmp_path):
        # rule/secret are NULL for references - the identity index must still
        # collapse a repeated sighting instead of inserting a duplicate.
        with Database(tmp_path / "t.db") as db:
            db.init_schema()
            domain_id = db.upsert_domain("example.com")
            for ts in ("2026-01-01T00:00:00Z", "2026-02-02T00:00:00Z"):
                db.upsert_code_exposure(domain_id, kind="reference", target="a.example.com",
                                        repo="acme/infra", path="nginx.conf", commit="c",
                                        url="u", now=ts)
            rows = db.list_code_exposures(domain_id)
        assert len(rows) == 1
        assert rows[0]["first_seen"] == "2026-01-01T00:00:00Z"
        assert rows[0]["last_seen"] == "2026-02-02T00:00:00Z"

    def test_target_lookup_collapses_same_exposure_across_domains(self, tmp_path):
        with Database(tmp_path / "t.db") as db:
            db.init_schema()
            a = db.upsert_domain("example.com")
            b = db.upsert_domain("other.com")
            for domain_id in (a, b):
                db.upsert_code_exposure(domain_id, kind="reference", target="1.2.3.4",
                                        repo="acme/ops", path="hosts.yml", commit="c", url="u")
            rows = db.list_code_exposures_for_target("1.2.3.4")
        assert len(rows) == 1

    def test_count_secret_exposures(self, tmp_path):
        with Database(tmp_path / "t.db") as db:
            db.init_schema()
            domain_id = db.upsert_domain("example.com")
            db.upsert_code_exposure(domain_id, kind="reference", target="a.example.com",
                                    repo="r", path="p", commit="c", url="u")
            db.upsert_code_exposure(domain_id, kind="secret", target="a.example.com",
                                    repo="r", path="q", commit="c", url="u", rule="jwt", secret="ey")
            assert db.count_secret_exposures(domain_id) == 1


class TestDeleteDomain:
    def _seed(self, db):
        gone = db.upsert_domain("gone.com")
        kept = db.upsert_domain("kept.com")
        www = db.upsert_hostname(gone, "www.gone.com")
        other = db.upsert_hostname(kept, "www.kept.com")
        own_ip = db.upsert_ip("192.0.2.1")
        shared_ip = db.upsert_ip("192.0.2.2")
        db.upsert_resolution(www, own_ip)
        db.upsert_resolution(www, shared_ip)
        db.upsert_resolution(other, shared_ip)
        db.upsert_service(own_ip, 443, "tcp", "nginx")
        db.insert_result("x", "hostname", www, {})
        db.insert_result("x", "domain", gone, {})
        db.insert_result("x", "ip", own_ip, {})
        db.insert_result("x", "ip", shared_ip, {})
        db.upsert_candidate_domain(gone, "else.org", "x", "www.gone.com")
        db.upsert_cloud_asset(gone, "s3", "gone-bucket", "https://b", "public", "x")
        db.upsert_code_exposure(gone, kind="reference", target="www.gone.com", repo="a/b",
                                path="p", commit="c", url="u")
        for target_type, target in [("domain", "gone.com"), ("collect", "gone.com"),
                                    ("hostname", "www.gone.com"), ("hostname", "www.kept.com")]:
            db.finish_source_call(db.begin_source_call("x", target_type, target, "2026-01-01"), ok=True)
        return gone, kept, own_ip, shared_ip

    def test_removes_the_domain_and_its_data_but_keeps_shared_ips(self, db):
        gone, kept, own_ip, shared_ip = self._seed(db)
        db.delete_domain(gone)

        assert [d["name"] for d in db.list_domains()] == ["kept.com"]
        assert db.get_hostname_by_name("www.gone.com") is None
        assert db.get_ip_by_address("192.0.2.1") is None
        assert db.get_ip_by_address("192.0.2.2") is not None
        assert db.list_results_for_target("ip", shared_ip)
        assert db.list_results_for_target("domain", gone) == []
        for table in ("results", "services", "candidate_domains", "cloud_assets", "code_exposures"):
            n = db.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            assert n == (1 if table == "results" else 0), table
        assert db.get_hostname_by_name("www.kept.com") is not None

    def test_deleted_targets_are_no_longer_fresh_but_still_counted(self, db):
        gone, *_ = self._seed(db)
        db.delete_domain(gone)
        assert db.last_successful_source_call("x", "domain", "gone.com") is None
        assert db.last_successful_source_call("x", "collect", "gone.com") is None
        assert db.last_successful_source_call("x", "hostname", "www.gone.com") is None
        assert db.last_successful_source_call("x", "hostname", "www.kept.com") is not None
        assert db.count_source_calls_since("x", "2000-01-01") == 4

    def test_unknown_id_is_a_no_op(self, db):
        db.delete_domain(999)
