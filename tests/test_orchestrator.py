import json
import time
import weakref
from unittest.mock import patch

import pytest

from posint_scanner.db import Database
from posint_scanner.models import DiscoveredHostname, EnrichmentResult, ServiceInfo
from posint_scanner.orchestrator import (
    ScanControl,
    _fallback_24s,
    _persist_discovered_hostnames,
    infer_parent_hostname,
    run_scan,
)
from posint_scanner.sources.base import ScrapeParseError, Source, SourceUnavailableError


@pytest.fixture
def db():
    database = Database(":memory:")
    database.init_schema()
    yield database
    database.close()


@pytest.fixture(autouse=True)
def no_live_netblock_sweep():
    """The netblock sweep stage does real DNS/HTTP lookups (ASN lookup via
    Cymru, prefix listing via RIPEstat, PTR sweep, target-nameserver lookup)
    by default - autouse-mock all of it to a no-op everywhere so a test that
    resolves a realistic-looking IP or uses a real domain like example.com
    doesn't silently trigger live network calls. Tests of the sweep itself
    override whichever of these they need."""
    with (
        patch("posint_scanner.orchestrator.sweep_netblocks", return_value=[]) as mock_sweep,
        patch("posint_scanner.orchestrator.lookup_asn", return_value=None) as mock_lookup_asn,
        patch("posint_scanner.orchestrator.lookup_asn_prefixes", return_value=[]) as mock_lookup_prefixes,
        patch(
            "posint_scanner.orchestrator.lookup_domain_nameserver_ip", return_value=None
        ) as mock_lookup_ns,
    ):
        yield {
            "sweep_netblocks": mock_sweep,
            "lookup_asn": mock_lookup_asn,
            "lookup_asn_prefixes": mock_lookup_prefixes,
            "lookup_domain_nameserver_ip": mock_lookup_ns,
        }


@pytest.fixture(autouse=True)
def no_live_fingerprint():
    """The fingerprint stage runs by default and makes real HTTP requests to
    every service found - autouse-mock it to "nothing fingerprinted"
    everywhere. Tests of the stage itself override this."""
    with patch(
        "posint_scanner.orchestrator.WebTechFingerprinter.scan_service", return_value=None
    ) as mock_scan:
        yield mock_scan


@pytest.fixture(autouse=True)
def no_live_nvd_lookup():
    """The vulnerability-lookup stage hits the real NVD API - autouse-mock
    NvdClient.lookup_cves to a no-op everywhere so a test with a service
    that happens to have both banner and version doesn't silently trigger a
    live (rate-limited) network call. Tests of the stage itself override
    this."""
    with patch("posint_scanner.orchestrator.NvdClient.lookup_cves", return_value=[]) as mock_lookup:
        yield mock_lookup


class TestFallback24s:
    def test_returns_containing_plus_above_and_below(self):
        import ipaddress

        result = set(_fallback_24s("1.2.3.4"))
        assert result == {
            ipaddress.IPv4Network("1.2.2.0/24"),
            ipaddress.IPv4Network("1.2.3.0/24"),
            ipaddress.IPv4Network("1.2.4.0/24"),
        }

    def test_handles_underflow_at_start_of_address_space(self):
        import ipaddress

        result = set(_fallback_24s("0.0.0.5"))
        # no valid "below" neighbor - just containing + above
        assert result == {
            ipaddress.IPv4Network("0.0.0.0/24"),
            ipaddress.IPv4Network("0.0.1.0/24"),
        }

    def test_handles_overflow_at_end_of_address_space(self):
        import ipaddress

        result = set(_fallback_24s("255.255.255.5"))
        # no valid "above" neighbor - just below + containing
        assert result == {
            ipaddress.IPv4Network("255.255.254.0/24"),
            ipaddress.IPv4Network("255.255.255.0/24"),
        }

    def test_invalid_ip_returns_empty_list(self):
        assert _fallback_24s("not-an-ip") == []


class TestInferParentHostname:
    def test_finds_known_parent(self):
        known = {"api.example.com", "example.com"}
        assert infer_parent_hostname("v2.api.example.com", "example.com", known) == "api.example.com"

    def test_returns_none_when_only_apex_matches(self):
        known = {"example.com"}
        assert infer_parent_hostname("api.example.com", "example.com", known) is None

    def test_returns_none_when_no_intermediate_known(self):
        known = {"v2.api.example.com", "example.com"}
        assert infer_parent_hostname("v2.api.example.com", "example.com", known) is None


class TestPersistDiscoveredHostnames:
    """Direct tests of the two-pass write, bypassing the thread pool
    entirely - proves the property that actually matters (given any order,
    the final persisted state is correct) without needing to coordinate a
    real thread race, which would be flaky by nature."""

    def test_links_parent_when_child_appears_before_parent_in_the_list(self, db):
        # this exact order is what a real ThreadPoolExecutor/as_completed
        # race could produce if the child's discovery source happened to
        # finish first - previously this silently left parent_hostname_id
        # as None even though the parent name was correctly inferable.
        domain_id = db.upsert_domain("example.com")
        all_discovered = [
            DiscoveredHostname(name="v2.api.example.com", source="test"),
            DiscoveredHostname(name="api.example.com", source="test"),
        ]
        known_hostnames = {"v2.api.example.com", "api.example.com"}

        _persist_discovered_hostnames(db, domain_id, "example.com", all_discovered, known_hostnames)

        api_row = db.get_hostname_by_name("api.example.com")
        v2_row = db.get_hostname_by_name("v2.api.example.com")
        assert v2_row["parent_hostname_id"] == api_row["id"]

    def test_links_parent_when_parent_appears_first_too(self, db):
        # order-independence cuts both ways - the previously-lucky order
        # must keep working.
        domain_id = db.upsert_domain("example.com")
        all_discovered = [
            DiscoveredHostname(name="api.example.com", source="test"),
            DiscoveredHostname(name="v2.api.example.com", source="test"),
        ]
        known_hostnames = {"v2.api.example.com", "api.example.com"}

        _persist_discovered_hostnames(db, domain_id, "example.com", all_discovered, known_hostnames)

        api_row = db.get_hostname_by_name("api.example.com")
        v2_row = db.get_hostname_by_name("v2.api.example.com")
        assert v2_row["parent_hostname_id"] == api_row["id"]

    def test_hostname_with_no_discoverable_parent_gets_none(self, db):
        domain_id = db.upsert_domain("example.com")
        all_discovered = [DiscoveredHostname(name="api.example.com", source="test")]
        known_hostnames = {"api.example.com"}

        _persist_discovered_hostnames(db, domain_id, "example.com", all_discovered, known_hostnames)

        assert db.get_hostname_by_name("api.example.com")["parent_hostname_id"] is None

    def test_result_data_is_persisted_regardless_of_parent_linkage(self, db):
        domain_id = db.upsert_domain("example.com")
        all_discovered = [
            DiscoveredHostname(name="v2.api.example.com", source="dnsrecon", data={"axfr_successful": True}),
            DiscoveredHostname(name="api.example.com", source="subfinder"),
        ]
        known_hostnames = {"v2.api.example.com", "api.example.com"}

        _persist_discovered_hostnames(db, domain_id, "example.com", all_discovered, known_hostnames)

        v2_row = db.get_hostname_by_name("v2.api.example.com")
        results = db.list_results_for_target("hostname", v2_row["id"])
        assert len(results) == 1
        assert results[0]["source"] == "dnsrecon"

    def test_one_items_failure_does_not_block_others(self):
        class FlakyForOneNameDatabase(Database):
            """Database whose upsert_hostname raises once for one specific
            name (simulating a transient write failure), then behaves
            normally - matches the FlakyResultDatabase pattern used
            elsewhere in this file, but targets upsert_hostname instead of
            insert_result."""

            def __init__(self, path):
                super().__init__(path)
                self._fail_for_name: str | None = "bad.example.com"

            def upsert_hostname(self, *args, **kwargs):
                name = args[1] if len(args) > 1 else kwargs.get("name")
                if name == self._fail_for_name:
                    self._fail_for_name = None
                    raise Exception("simulated: attempt to write a readonly database")
                return super().upsert_hostname(*args, **kwargs)

        flaky_db = FlakyForOneNameDatabase(":memory:")
        flaky_db.init_schema()
        domain_id = flaky_db.upsert_domain("example.com")
        all_discovered = [
            DiscoveredHostname(name="bad.example.com", source="test"),
            DiscoveredHostname(name="good.example.com", source="test"),
        ]
        known_hostnames = {"bad.example.com", "good.example.com"}

        _persist_discovered_hostnames(
            flaky_db, domain_id, "example.com", all_discovered, known_hostnames
        )

        assert flaky_db.get_hostname_by_name("good.example.com") is not None
        assert flaky_db.get_hostname_by_name("bad.example.com") is None
        flaky_db.close()


class FakeDiscoverySource(Source):
    name = "fake-discovery"

    def discover(self, domain):
        return [
            DiscoveredHostname(name=f"api.{domain}", source=self.name),
            DiscoveredHostname(name=f"www.{domain}", source=self.name),
        ]


class FailingDiscoverySource(Source):
    name = "fake-failing"

    def discover(self, domain):
        raise SourceUnavailableError("binary not found")


class FakeIpEnrichSource(Source):
    name = "fake-ip-enrich"

    def enrich(self, target, hostnames):
        return EnrichmentResult(
            source=self.name,
            target_type="ip",
            target=target,
            data={"seen_hostnames": hostnames},
            services=[ServiceInfo(port=443, protocol="tcp", banner="nginx")],
        )


class FakeHostnameEnrichSource(Source):
    name = "fake-hostname-enrich"
    enrich_target_kind = "hostname"

    def enrich(self, target, hostnames):
        return EnrichmentResult(
            source=self.name, target_type="hostname", target=target, data={"grade": "A"}
        )


class _Payload:
    """Stands in for the requests.Response (and its socket) a real HTTPError carries."""


class LeakProbeError(Exception):
    def __init__(self, payload):
        super().__init__("upstream said 429")
        self.payload = payload


class FailingHostnameEnrichSource(Source):
    name = "fake-failing-hostname-enrich"
    enrich_target_kind = "hostname"

    def __init__(self):
        self.payload_refs = []

    def enrich(self, target, hostnames):
        payload = _Payload()
        self.payload_refs.append(weakref.ref(payload))
        raise LeakProbeError(payload)


class WaitForReleaseIpSource(Source):
    """Runs after the failures and waits for their payloads to be freed -
    i.e. checks they're released mid-stage, not only when the stage ends."""

    name = "fake-wait-for-release"

    def __init__(self, failing):
        self.failing = failing
        self.released = None

    def enrich(self, target, hostnames):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            refs = self.failing.payload_refs
            # The loop variable still holds the latest finished future; every
            # earlier one must already be gone.
            if len(refs) == 2 and sum(ref() is not None for ref in refs) <= 1:
                self.released = True
                break
            time.sleep(0.01)
        else:
            self.released = False
        return EnrichmentResult(source=self.name, target_type="ip", target=target, data={})


class TestRunScan:
    def test_failed_enrichment_releases_its_exception_mid_stage(self, db):
        # Regression: every finished future stayed referenced until the whole
        # enrichment stage ended, and a failed one pins its exception - with a
        # real HTTPError, the Response and its open socket. On a big domain
        # that exhausted file descriptors (EMFILE) and took SQLite down.
        failing = FailingHostnameEnrichSource()
        waiter = WaitForReleaseIpSource(failing)
        with (
            patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]),
            # caplog-style handlers keep exc_info alive; not what's under test.
            patch("posint_scanner.orchestrator.logger"),
        ):
            run_scan(db, ["example.com"], [FakeDiscoverySource(), failing, waiter])

        assert waiter.released is True

    def test_cycle_held_failures_are_released_by_the_end_of_the_scan(self, db):
        # A real HTTPError is often kept in a reference cycle (tenacity's retry
        # state) holding its Response and socket; only the cycle collector
        # frees it. Stage boundaries collect, so nothing outlives the scan.
        import gc

        refs = []

        class CyclicFailure(Source):
            name = "fake-cyclic-failure"
            enrich_target_kind = "hostname"

            def enrich(self, target, hostnames):
                payload = _Payload()
                refs.append(weakref.ref(payload))
                exc = LeakProbeError(payload)
                payload.cycle = exc  # payload <-> exception
                raise exc

        gc.disable()
        try:
            with (
                patch("posint_scanner.orchestrator.resolve_hostname", return_value=[]),
                patch("posint_scanner.orchestrator.logger"),
            ):
                run_scan(db, ["example.com"], [FakeDiscoverySource(), CyclicFailure()])
            assert refs and all(ref() is None for ref in refs)
        finally:
            gc.enable()

    def test_full_pipeline_populates_db(self, db):
        sources = [FakeDiscoverySource(), FakeIpEnrichSource(), FakeHostnameEnrichSource()]
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
            run_scan(db, ["example.com"], sources)

        domain_row = db.get_domain_by_name("example.com")
        assert domain_row is not None

        hostnames = {row["name"] for row in db.list_hostnames_for_domain(domain_row["id"])}
        assert hostnames == {"api.example.com", "www.example.com"}

        ip_row = db.get_ip_by_address("1.2.3.4")
        assert ip_row is not None

        services = db.list_services_for_ip(ip_row["id"])
        assert len(services) == 1
        assert services[0]["port"] == 443

        ip_results = db.list_results_for_target("ip", ip_row["id"])
        assert any(r["source"] == "fake-ip-enrich" for r in ip_results)

        api_hostname = db.get_hostname_by_name("api.example.com")
        hostname_results = db.list_results_for_target("hostname", api_hostname["id"])
        assert any(r["source"] == "fake-hostname-enrich" for r in hostname_results)

    def test_unavailable_source_is_skipped_without_raising(self, db):
        sources = [FakeDiscoverySource(), FailingDiscoverySource()]
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=[]):
            run_scan(db, ["example.com"], sources)

        domain_row = db.get_domain_by_name("example.com")
        hostnames = {row["name"] for row in db.list_hostnames_for_domain(domain_row["id"])}
        assert hostnames == {"api.example.com", "www.example.com"}

    def test_source_filter_restricts_active_sources(self, db):
        sources = [FakeDiscoverySource(), FakeIpEnrichSource()]
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=[]):
            run_scan(db, ["example.com"], sources, source_filter=["fake-discovery"])

        domain_row = db.get_domain_by_name("example.com")
        hostnames = db.list_hostnames_for_domain(domain_row["id"])
        assert len(hostnames) == 2
        # enrichment source was filtered out, so no ip/services should exist
        assert db.list_all_ips() == []

    def test_parent_inferred_for_nested_discovered_hostname(self, db):
        class NestedDiscoverySource(Source):
            name = "nested"

            def discover(self, domain):
                return [
                    DiscoveredHostname(name=f"api.{domain}", source=self.name),
                    DiscoveredHostname(name=f"v2.api.{domain}", source=self.name),
                ]

        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=[]):
            run_scan(db, ["example.com"], [NestedDiscoverySource()])

        api_row = db.get_hostname_by_name("api.example.com")
        v2_row = db.get_hostname_by_name("v2.api.example.com")
        assert v2_row["parent_hostname_id"] == api_row["id"]

    def test_parent_linked_through_real_thread_race_child_source_finishes_first(self, db):
        # belt-and-suspenders: TestPersistDiscoveredHostnames proves the
        # property deterministically; this proves the real
        # ThreadPoolExecutor/as_completed path in _run_discovery_for_domain
        # doesn't regress. Two separate sources (not one source returning
        # both names) so `all_discovered`'s order genuinely depends on
        # thread completion, not just list construction order - the
        # parent's source sleeps so the child's source's future is the one
        # as_completed() yields first.
        import time

        class ParentSource(Source):
            name = "parent-source"

            def discover(self, domain):
                time.sleep(0.2)
                return [DiscoveredHostname(name=f"api.{domain}", source=self.name)]

        class ChildSource(Source):
            name = "child-source"

            def discover(self, domain):
                return [DiscoveredHostname(name=f"v2.api.{domain}", source=self.name)]

        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=[]):
            run_scan(db, ["example.com"], [ParentSource(), ChildSource()], netblock_sweep=False)

        api_row = db.get_hostname_by_name("api.example.com")
        v2_row = db.get_hostname_by_name("v2.api.example.com")
        assert v2_row["parent_hostname_id"] == api_row["id"]


class FlakyResultDatabase(Database):
    """Database whose insert_result raises once (simulating a transient
    write failure like a locked/readonly file) then behaves normally."""

    def __init__(self, path):
        super().__init__(path)
        self._insert_result_failures_left = 1

    def insert_result(self, *args, **kwargs):
        if self._insert_result_failures_left > 0:
            self._insert_result_failures_left -= 1
            raise Exception("simulated: attempt to write a readonly database")
        return super().insert_result(*args, **kwargs)


class TestDbWriteResilience:
    @pytest.fixture
    def flaky_db(self):
        database = FlakyResultDatabase(":memory:")
        database.init_schema()
        yield database
        database.close()

    def test_enrichment_write_failure_does_not_abort_remaining_results(self, flaky_db):
        class TwoHostDiscovery(Source):
            name = "two-host"

            def discover(self, domain):
                return [
                    DiscoveredHostname(name=f"a.{domain}", source=self.name),
                    DiscoveredHostname(name=f"b.{domain}", source=self.name),
                ]

        sources = [TwoHostDiscovery(), FakeHostnameEnrichSource()]
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=[]):
            run_scan(flaky_db, ["example.com"], sources)

        a_row = flaky_db.get_hostname_by_name("a.example.com")
        b_row = flaky_db.get_hostname_by_name("b.example.com")
        results_a = flaky_db.list_results_for_target("hostname", a_row["id"])
        results_b = flaky_db.list_results_for_target("hostname", b_row["id"])
        # exactly one of the two writes was the simulated failure; the other
        # must have gone through, and run_scan must not have raised.
        assert len(results_a) + len(results_b) == 1

    def test_discovery_write_failure_does_not_abort_scan(self, flaky_db):
        # both discovered hostnames carry `data`, so insert_result runs during
        # discovery too (not just enrichment) - the flaky failure hits the
        # first one, and the second must still get persisted.
        class TwoHostDiscoveryWithData(Source):
            name = "two-host-data"

            def discover(self, domain):
                return [
                    DiscoveredHostname(name=f"a.{domain}", source=self.name, data={"n": 1}),
                    DiscoveredHostname(name=f"b.{domain}", source=self.name, data={"n": 2}),
                ]

        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=[]):
            run_scan(flaky_db, ["example.com"], [TwoHostDiscoveryWithData()])

        domain_row = flaky_db.get_domain_by_name("example.com")
        hostnames = {row["name"] for row in flaky_db.list_hostnames_for_domain(domain_row["id"])}
        # both hostnames persist even though one's insert_result call failed -
        # upsert_hostname and insert_result are independent try/except scopes
        assert hostnames == {"a.example.com", "b.example.com"}


class TestNetblockSweepIntegration:
    def test_sweep_result_is_persisted(self, db, no_live_netblock_sweep):
        no_live_netblock_sweep["sweep_netblocks"].return_value = [
            DiscoveredHostname(
                name="db.example.com",
                source="dnsrecon",
                data={"discovered_via": "netblock_sweep", "ip": "1.2.3.5", "resolver": "1.1.1.1"},
            )
        ]
        sources = [FakeDiscoverySource()]
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
            run_scan(db, ["example.com"], sources)

        swept_row = db.get_hostname_by_name("db.example.com")
        assert swept_row is not None
        ip_row = db.get_ip_by_address("1.2.3.5")
        assert ip_row is not None
        ips_for_swept = {row["address"] for row in db.list_ips_for_hostname(swept_row["id"])}
        assert "1.2.3.5" in ips_for_swept

    def test_falls_back_to_24_and_neighbors_when_asn_lookup_fails(self, db, no_live_netblock_sweep):
        import ipaddress

        # fixture default: lookup_asn returns None
        sources = [FakeDiscoverySource()]
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
            run_scan(db, ["example.com"], sources)

        mock_sweep = no_live_netblock_sweep["sweep_netblocks"]
        mock_sweep.assert_called_once()
        networks_arg, domain_arg, resolvers_arg = mock_sweep.call_args[0]
        assert set(networks_arg) == {
            ipaddress.IPv4Network("1.2.2.0/24"),  # below
            ipaddress.IPv4Network("1.2.3.0/24"),  # containing
            ipaddress.IPv4Network("1.2.4.0/24"),  # above
        }
        assert domain_arg == "example.com"
        assert resolvers_arg == ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

    def test_uses_asn_prefixes_when_asn_lookup_succeeds(self, db, no_live_netblock_sweep):
        import ipaddress

        no_live_netblock_sweep["lookup_asn"].return_value = 15366
        no_live_netblock_sweep["lookup_asn_prefixes"].return_value = [
            ipaddress.IPv4Network("212.86.32.0/24"),  # contains 212.86.33.249? no - .32.0/24 covers .32.x
            ipaddress.IPv4Network("212.86.33.0/24"),  # this one actually contains it
            ipaddress.IPv4Network("178.20.88.0/24"),  # unrelated - bonus
        ]
        sources = [FakeDiscoverySource()]
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["212.86.33.249"]):
            run_scan(db, ["example.com"], sources)

        mock_sweep = no_live_netblock_sweep["sweep_netblocks"]
        networks_arg = mock_sweep.call_args[0][0]
        assert set(networks_arg) == {
            ipaddress.IPv4Network("212.86.33.0/24"),  # confirmed - contains the known IP
            ipaddress.IPv4Network("212.86.32.0/24"),  # bonus - fits under the cap
            ipaddress.IPv4Network("178.20.88.0/24"),  # bonus - fits under the cap
        }
        no_live_netblock_sweep["lookup_asn"].assert_called_once_with("212.86.33.249")
        no_live_netblock_sweep["lookup_asn_prefixes"].assert_called_once_with(15366)

    def test_includes_target_nameserver_as_second_resolver_when_found(
        self, db, no_live_netblock_sweep
    ):
        no_live_netblock_sweep["lookup_domain_nameserver_ip"].return_value = "9.9.9.9.9"  # distinct from defaults
        sources = [FakeDiscoverySource()]
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
            run_scan(db, ["example.com"], sources)

        mock_sweep = no_live_netblock_sweep["sweep_netblocks"]
        resolvers_arg = mock_sweep.call_args[0][2]
        assert resolvers_arg == ["1.1.1.1", "8.8.8.8", "9.9.9.9", "9.9.9.9.9"]

    def test_oversized_confirmed_prefix_falls_back_to_24_and_neighbors(
        self, db, no_live_netblock_sweep
    ):
        import ipaddress

        # the known IP (1.2.3.4) is INSIDE this /16 (65536 addresses) - way
        # over the cap. A prefix that large is almost certainly shared/
        # third-party infrastructure (a CDN, cloud provider, big transit
        # ASN), not something the target owns outright, so sweeping the
        # whole thing would defeat the point of the cap (this is exactly
        # what happened for real against dns-net.de: one IP's ASN prefix
        # was 3.5 million addresses). Only the IP's own /24 + neighbors
        # should get swept instead.
        no_live_netblock_sweep["lookup_asn"].return_value = 12345
        no_live_netblock_sweep["lookup_asn_prefixes"].return_value = [
            ipaddress.IPv4Network("1.2.0.0/16"),
            ipaddress.IPv4Network("172.16.0.0/16"),  # bonus, doesn't contain 1.2.3.4
        ]
        sources = [FakeDiscoverySource()]
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
            run_scan(db, ["example.com"], sources, netblock_sweep_max_addresses=20_000)

        mock_sweep = no_live_netblock_sweep["sweep_netblocks"]
        networks_arg = set(mock_sweep.call_args[0][0])
        assert ipaddress.IPv4Network("1.2.0.0/16") not in networks_arg
        assert networks_arg >= {
            ipaddress.IPv4Network("1.2.2.0/24"),
            ipaddress.IPv4Network("1.2.3.0/24"),
            ipaddress.IPv4Network("1.2.4.0/24"),
        }
        assert ipaddress.IPv4Network("172.16.0.0/16") not in networks_arg  # too big to fit as bonus either

    def test_bonus_prefix_swept_only_if_it_fits_remaining_budget(self, db, no_live_netblock_sweep):
        import ipaddress

        # known IP (1.2.3.4) confirms a small /24; a small bonus /24 from
        # the same ASN has plenty of budget left and should also get swept.
        no_live_netblock_sweep["lookup_asn"].return_value = 12345
        no_live_netblock_sweep["lookup_asn_prefixes"].return_value = [
            ipaddress.IPv4Network("1.2.3.0/24"),
            ipaddress.IPv4Network("172.16.5.0/24"),
        ]
        sources = [FakeDiscoverySource()]
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
            run_scan(db, ["example.com"], sources, netblock_sweep_max_addresses=20_000)

        mock_sweep = no_live_netblock_sweep["sweep_netblocks"]
        networks_arg = set(mock_sweep.call_args[0][0])
        assert networks_arg == {
            ipaddress.IPv4Network("1.2.3.0/24"),
            ipaddress.IPv4Network("172.16.5.0/24"),
        }

    def test_sweep_worker_count_is_configurable(self, db, no_live_netblock_sweep):
        sources = [FakeDiscoverySource()]
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
            run_scan(db, ["example.com"], sources, netblock_sweep_workers=42)

        mock_sweep = no_live_netblock_sweep["sweep_netblocks"]
        assert mock_sweep.call_args[1]["workers"] == 42

    def test_sweep_resolvers_are_configurable(self, db, no_live_netblock_sweep):
        sources = [FakeDiscoverySource()]
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
            run_scan(db, ["example.com"], sources, netblock_sweep_resolvers=["4.4.4.4"])

        mock_sweep = no_live_netblock_sweep["sweep_netblocks"]
        resolvers_arg = mock_sweep.call_args[0][2]
        assert resolvers_arg == ["4.4.4.4"]

    def test_sweep_disabled_via_flag(self, db, no_live_netblock_sweep):
        sources = [FakeDiscoverySource()]
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
            run_scan(db, ["example.com"], sources, netblock_sweep=False)

        no_live_netblock_sweep["sweep_netblocks"].assert_not_called()

    def test_no_known_ips_means_no_sweep_call(self, db, no_live_netblock_sweep):
        sources = [FakeDiscoverySource()]
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=[]):
            run_scan(db, ["example.com"], sources)

        no_live_netblock_sweep["sweep_netblocks"].assert_not_called()

    def test_ipv6_known_ip_is_skipped_without_raising(self, db, no_live_netblock_sweep):
        sources = [FakeDiscoverySource()]
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["::1"]):
            run_scan(db, ["example.com"], sources)

        no_live_netblock_sweep["sweep_netblocks"].assert_not_called()
        no_live_netblock_sweep["lookup_asn"].assert_not_called()


class TestVulnerabilityLookupIntegration:
    def test_uses_real_cpe_when_service_has_one(self, db, no_live_nvd_lookup):
        class CpeEnrichSource(Source):
            name = "cpe-enrich"

            def enrich(self, target, hostnames):
                return EnrichmentResult(
                    source=self.name,
                    target_type="ip",
                    target=target,
                    services=[
                        ServiceInfo(
                            port=443,
                            banner="nginx",
                            version="1.18.0",
                            cpe="cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
                        )
                    ],
                )

        no_live_nvd_lookup.return_value = [{"cve_id": "CVE-2021-23017", "cvss_score": 7.7}]
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
            run_scan(db, ["example.com"], [FakeDiscoverySource(), CpeEnrichSource()], netblock_sweep=False)

        no_live_nvd_lookup.assert_called_once_with("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*")

        ip_row = db.get_ip_by_address("1.2.3.4")
        results = db.list_results_for_target("ip", ip_row["id"])
        nvd_results = [r for r in results if r["source"] == "nvd"]
        assert len(nvd_results) == 1

    def test_cves_are_annotated_with_exploits_from_searchsploit(self, db, no_live_nvd_lookup):
        class CpeEnrichSource(Source):
            name = "cpe-enrich"

            def enrich(self, target, hostnames):
                return EnrichmentResult(
                    source=self.name, target_type="ip", target=target,
                    services=[ServiceInfo(port=445, banner="smb", version="1.0",
                                          cpe="cpe:2.3:a:microsoft:smb:1.0:*:*:*:*:*:*:*")],
                )

        no_live_nvd_lookup.return_value = [{"cve_id": "CVE-2017-0144", "cvss_score": 9.3}]
        exploits = [{"title": "EternalBlue", "edb_id": "42315",
                     "url": "https://www.exploit-db.com/exploits/42315"}]
        with (
            patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]),
            patch("posint_scanner.exploitdb.SearchSploitClient.lookup_cve", return_value=exploits),
        ):
            run_scan(db, ["example.com"], [FakeDiscoverySource(), CpeEnrichSource()],
                     netblock_sweep=False)

        ip_row = db.get_ip_by_address("1.2.3.4")
        nvd = [json.loads(r["data"]) for r in db.list_results_for_target("ip", ip_row["id"])
               if r["source"] == "nvd"]
        assert nvd[0]["cves"][0]["exploits"] == exploits

    def test_versionless_cpe_is_not_looked_up(self, db, no_live_nvd_lookup):
        # a wildcard-version CPE (common from Shodan, e.g. drupal:drupal:*)
        # would otherwise match every CVE ever filed for the product
        class VersionlessCpeSource(Source):
            name = "versionless-cpe"

            def enrich(self, target, hostnames):
                return EnrichmentResult(
                    source=self.name,
                    target_type="ip",
                    target=target,
                    services=[ServiceInfo(port=80, cpe="cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*")],
                )

        no_live_nvd_lookup.return_value = [{"cve_id": "CVE-2009-9999", "cvss_score": 7.5}]
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
            run_scan(db, ["example.com"], [FakeDiscoverySource(), VersionlessCpeSource()],
                     netblock_sweep=False)
        no_live_nvd_lookup.assert_not_called()
        ip_row = db.get_ip_by_address("1.2.3.4")
        assert not any(
            r["source"] == "nvd" for r in db.list_results_for_target("ip", ip_row["id"])
        )

    def test_stale_versionless_nvd_rows_are_purged(self, db, no_live_nvd_lookup):
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
            run_scan(db, ["example.com"], [FakeDiscoverySource()], netblock_sweep=False)
        ip_id = db.get_ip_by_address("1.2.3.4")["id"]
        stale = {"port": 80, "cpe": "cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*",
                 "cves": [{"cve_id": "CVE-2009-9999"}]}
        kept = {"port": 22, "cpe": "cpe:2.3:a:openssh:openssh:9.0:*:*:*:*:*:*:*",
                "cves": [{"cve_id": "CVE-2023-0001"}]}
        db.insert_result("nvd", "ip", ip_id, stale)
        db.insert_result("nvd", "ip", ip_id, kept)
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
            run_scan(db, ["example.com"], [FakeDiscoverySource()], netblock_sweep=False)
        cpes = [json.loads(r["data"])["cpe"] for r in db.list_results_for_target("ip", ip_id)
                if r["source"] == "nvd"]
        assert cpes == [kept["cpe"]]

    def test_falls_back_to_guessed_cpe_when_none_provided(self, db, no_live_nvd_lookup):
        no_live_nvd_lookup.return_value = [{"cve_id": "CVE-2021-23017", "cvss_score": 7.7}]
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
            run_scan(db, ["example.com"], [FakeDiscoverySource(), FakeIpEnrichSource()], netblock_sweep=False)

        # FakeIpEnrichSource sets banner="nginx" but no version - so no cpe
        # can be built at all, and NVD should never be called.
        no_live_nvd_lookup.assert_not_called()

    def test_skips_services_with_no_banner_or_cpe(self, db, no_live_nvd_lookup):
        class BareServiceSource(Source):
            name = "bare"

            def enrich(self, target, hostnames):
                return EnrichmentResult(
                    source=self.name, target_type="ip", target=target, services=[ServiceInfo(port=22)]
                )

        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
            run_scan(db, ["example.com"], [FakeDiscoverySource(), BareServiceSource()], netblock_sweep=False)

        no_live_nvd_lookup.assert_not_called()

    def test_no_cves_found_means_no_result_persisted(self, db, no_live_nvd_lookup):
        class CpeEnrichSource(Source):
            name = "cpe-enrich"

            def enrich(self, target, hostnames):
                return EnrichmentResult(
                    source=self.name,
                    target_type="ip",
                    target=target,
                    services=[ServiceInfo(port=443, cpe="cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*")],
                )

        no_live_nvd_lookup.return_value = []
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
            run_scan(db, ["example.com"], [FakeDiscoverySource(), CpeEnrichSource()], netblock_sweep=False)

        ip_row = db.get_ip_by_address("1.2.3.4")
        results = db.list_results_for_target("ip", ip_row["id"])
        assert not any(r["source"] == "nvd" for r in results)

    def test_dedupes_lookups_for_the_same_cpe_across_ips(self, db, no_live_nvd_lookup):
        class TwoHostCpeSource(Source):
            name = "two-host-cpe"

            def discover(self, domain):
                return [
                    DiscoveredHostname(name=f"a.{domain}", source=self.name),
                    DiscoveredHostname(name=f"b.{domain}", source=self.name),
                ]

            def enrich(self, target, hostnames):
                return EnrichmentResult(
                    source=self.name,
                    target_type="ip",
                    target=target,
                    services=[ServiceInfo(port=443, cpe="cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*")],
                )

        no_live_nvd_lookup.return_value = [{"cve_id": "CVE-2021-23017", "cvss_score": 7.7}]

        def fake_resolve(hostname):
            return ["1.2.3.4"] if hostname == "a.example.com" else ["5.6.7.8"]

        with patch("posint_scanner.orchestrator.resolve_hostname", side_effect=fake_resolve):
            run_scan(db, ["example.com"], [TwoHostCpeSource()], netblock_sweep=False)

        no_live_nvd_lookup.assert_called_once()  # same CPE on both IPs - only looked up once

    def test_disabled_via_flag(self, db, no_live_nvd_lookup):
        class CpeEnrichSource(Source):
            name = "cpe-enrich"

            def enrich(self, target, hostnames):
                return EnrichmentResult(
                    source=self.name,
                    target_type="ip",
                    target=target,
                    services=[ServiceInfo(port=443, cpe="cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*")],
                )

        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
            run_scan(
                db,
                ["example.com"],
                [FakeDiscoverySource(), CpeEnrichSource()],
                netblock_sweep=False,
                vuln_lookup=False,
            )

        no_live_nvd_lookup.assert_not_called()


class TestNucleiStage:
    def _fp_source(self):
        class FpEnrich(Source):
            name = "fp-enrich"

            def enrich(self, target, hostnames):
                return EnrichmentResult(
                    source=self.name, target_type="ip", target=target,
                    services=[ServiceInfo(port=8080, protocol="tcp", banner="jetty")],
                )
        return FpEnrich()

    def test_off_by_default(self, db):
        with (
            patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]),
            patch("posint_scanner.nuclei.NucleiScanner.scan") as scan,
        ):
            run_scan(db, ["example.com"], [FakeDiscoverySource(), self._fp_source()],
                     netblock_sweep=False, vuln_lookup=False)
        scan.assert_not_called()

    def test_scans_fingerprinted_urls_and_persists_findings(self, db, no_live_fingerprint):
        # fingerprint stage yields a webtech result with a URL; nuclei scans it
        no_live_fingerprint.return_value = {
            "url": "http://1.2.3.4:8080/geoserver/web/", "status": 200,
            "technologies": {"GeoServer": "2.23.1"}, "categories": {},
            "cpes": {}, "server_product": None, "server_version": None,
        }
        finding = {"template_id": "CVE-2024-36401", "name": "GeoServer RCE",
                   "severity": "critical", "matched_at": "http://1.2.3.4:8080/geoserver/ows",
                   "type": "http", "cves": ["CVE-2024-36401"], "cvss_score": 9.8,
                   "tags": ["rce"], "reference": []}
        with (
            patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]),
            patch("posint_scanner.nuclei.NucleiScanner.available", True),
            patch("posint_scanner.nuclei.NucleiScanner.scan", return_value=[finding]) as scan,
        ):
            run_scan(db, ["example.com"], [FakeDiscoverySource(), self._fp_source()],
                     netblock_sweep=False, vuln_lookup=False, nuclei_scan=True)

        scan.assert_called_once_with(["http://1.2.3.4:8080/geoserver/web/"])
        ip_id = db.get_ip_by_address("1.2.3.4")["id"]
        nuclei = [json.loads(r["data"]) for r in db.list_results_for_target("ip", ip_id)
                  if r["source"] == "nuclei"]
        assert nuclei == [finding]

    def test_no_targets_when_fingerprint_found_no_web_service(self, db):
        # fingerprint (autouse-mocked to None) => no webtech URLs => nuclei skips
        with (
            patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]),
            patch("posint_scanner.nuclei.NucleiScanner.available", True),
            patch("posint_scanner.nuclei.NucleiScanner.scan", return_value=[]) as scan,
        ):
            run_scan(db, ["example.com"], [FakeDiscoverySource(), self._fp_source()],
                     netblock_sweep=False, vuln_lookup=False, nuclei_scan=True)
        scan.assert_not_called()


class TestWebAppScanStage:
    """Active web-app scanning (--nikto / --wpscan) against resolved services."""

    def _svc_source(self):
        class SvcEnrich(Source):
            name = "svc-enrich"

            def enrich(self, target, hostnames):
                return EnrichmentResult(
                    source=self.name, target_type="ip", target=target,
                    services=[ServiceInfo(port=8080, protocol="tcp", banner="jetty")],
                )
        return SvcEnrich()

    def test_off_by_default(self, db):
        with (
            patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]),
            patch("posint_scanner.webscan.NiktoScanner.scan") as nikto,
            patch("posint_scanner.webscan.WpscanScanner.scan") as wpscan,
        ):
            run_scan(db, ["example.com"], [FakeDiscoverySource(), self._svc_source()],
                     netblock_sweep=False, vuln_lookup=False)
        nikto.assert_not_called()
        wpscan.assert_not_called()

    def test_scans_resolved_services_and_persists_findings(self, db):
        finding = {"tool": "nikto", "kind": "web", "severity": "medium",
                   "id": "600123", "title": "Shellshock", "resource": "/cgi-bin",
                   "url": "http://x/", "target": "http://x/", "cves": ["CVE-2014-6271"],
                   "reference": None, "location": "GET /cgi-bin"}
        with (
            patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]),
            patch("posint_scanner.webscan.NiktoScanner.available", True),
            patch("posint_scanner.webscan.NiktoScanner.scan", return_value=[finding]) as nikto,
        ):
            run_scan(db, ["example.com"], [FakeDiscoverySource(), self._svc_source()],
                     netblock_sweep=False, vuln_lookup=False, nikto_scan=True)
        # scanned the resolved service URL (built from the open port, not from a
        # fingerprint confirmation)
        called_urls = nikto.call_args[0][0]
        assert called_urls and all(u.endswith(":8080/") and u.startswith("http://") for u in called_urls)
        ip_id = db.get_ip_by_address("1.2.3.4")["id"]
        persisted = [json.loads(r["data"]) for r in db.list_results_for_target("ip", ip_id)
                     if r["source"] == "nikto"]
        assert persisted == [finding]

    def test_no_services_means_no_run(self, db):
        # discovery + resolution but no service-yielding source => no web targets
        with (
            patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]),
            patch("posint_scanner.webscan.WpscanScanner.available", True),
            patch("posint_scanner.webscan.WpscanScanner.scan", return_value=[]) as wpscan,
        ):
            run_scan(db, ["example.com"], [FakeDiscoverySource()],
                     netblock_sweep=False, vuln_lookup=False, wpscan_scan=True)
        wpscan.assert_not_called()


class TestTakeoverStage:
    """Subdomain-takeover scanning (--takeover) over discovered hostnames."""

    def test_off_by_default(self, db):
        with (
            patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]),
            patch("posint_scanner.webscan.TakeoverScanner.scan") as scan,
        ):
            run_scan(db, ["example.com"], [FakeDiscoverySource()],
                     netblock_sweep=False, vuln_lookup=False)
        scan.assert_not_called()

    def test_scans_hostnames_and_persists_on_hostname(self, db):
        finding = {"tool": "takeover", "kind": "takeover", "severity": "high",
                   "id": "github", "title": "Potential subdomain takeover (github)",
                   "resource": "api.example.com", "url": "api.example.com",
                   "target": "api.example.com", "cves": [], "reference": None,
                   "location": "example.github.io"}
        with (
            patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]),
            patch("posint_scanner.webscan.TakeoverScanner.available", True),
            patch("posint_scanner.webscan.TakeoverScanner.scan", return_value=[finding]) as scan,
        ):
            run_scan(db, ["example.com"], [FakeDiscoverySource()],
                     netblock_sweep=False, vuln_lookup=False, takeover_scan=True)
        assert set(scan.call_args[0][0]) == {"api.example.com", "www.example.com"}
        hid = db.get_hostname_by_name("api.example.com")["id"]
        persisted = [json.loads(r["data"]) for r in db.list_results_for_target("hostname", hid)
                     if r["source"] == "takeover"]
        assert persisted == [finding]


class TestCloudScanStage:
    """Artifact scanning (--cloud-scan): Trivy on images/repos + Checkov on repos."""

    IMG_FINDING = {
        "tool": "trivy", "kind": "vulnerability", "severity": "high",
        "id": "CVE-2021-23337", "title": "lodash", "resource": "lodash 4.17.11",
        "target": "acme/api:latest", "cves": ["CVE-2021-23337"],
        "reference": None, "location": None,
    }

    def test_off_by_default(self, db):
        from posint_scanner.config import CloudScanConfig
        with (
            patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]),
            patch("posint_scanner.cloudscan.TrivyScanner.scan_image") as img,
            patch("posint_scanner.cloudscan.CheckovScanner.scan_dir") as ckv,
        ):
            run_scan(db, ["example.com"], [FakeDiscoverySource()], netblock_sweep=False,
                     vuln_lookup=False,
                     cloudscan_config=CloudScanConfig(images=["acme/api:latest"]))
        img.assert_not_called()
        ckv.assert_not_called()

    def test_scans_configured_image_and_persists_trivy_result(self, db):
        from posint_scanner.config import CloudScanConfig
        with (
            patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]),
            patch("posint_scanner.cloudscan.TrivyScanner.available", True),
            patch("posint_scanner.cloudscan.TrivyScanner.scan_image",
                  return_value=[self.IMG_FINDING]) as img,
        ):
            run_scan(db, ["example.com"], [FakeDiscoverySource()], netblock_sweep=False,
                     vuln_lookup=False, cloud_scan=True,
                     cloudscan_config=CloudScanConfig(images=["acme/api:latest"]))
        img.assert_called_once_with("acme/api:latest")
        domain_id = db.get_domain_by_name("example.com")["id"]
        results = [json.loads(r["data"]) for r in db.list_results_for_target("domain", domain_id)
                   if r["source"] == "trivy"]
        assert len(results) == 1
        assert results[0]["target"] == "acme/api:latest"
        assert results[0]["counts"] == {"high": 1}
        assert results[0]["findings"] == [self.IMG_FINDING]

    def test_scans_configured_repo_with_checkov_and_trivy_fs(self, db):
        from posint_scanner.config import CloudScanConfig
        ckv_finding = {"tool": "checkov", "kind": "misconfig", "severity": "high",
                       "id": "CKV_AWS_20", "title": "S3 public", "resource": "aws_s3_bucket.x",
                       "target": "https://github.com/acme/iac.git", "cves": [],
                       "reference": None, "location": None}
        with (
            patch("posint_scanner.orchestrator.resolve_hostname", return_value=[]),
            patch("posint_scanner.orchestrator.clone_repo", return_value=True) as clone,
            patch("posint_scanner.cloudscan.TrivyScanner.available", True),
            patch("posint_scanner.cloudscan.CheckovScanner.available", True),
            patch("posint_scanner.cloudscan.TrivyScanner.scan_fs", return_value=[]),
            patch("posint_scanner.cloudscan.CheckovScanner.scan_dir",
                  return_value=[ckv_finding]) as ckv,
        ):
            run_scan(db, ["example.com"], [FakeDiscoverySource()], netblock_sweep=False,
                     vuln_lookup=False, cloud_scan=True,
                     cloudscan_config=CloudScanConfig(repos=["https://github.com/acme/iac.git"]))
        clone.assert_called_once()
        ckv.assert_called_once()
        domain_id = db.get_domain_by_name("example.com")["id"]
        checkov = [json.loads(r["data"]) for r in db.list_results_for_target("domain", domain_id)
                   if r["source"] == "checkov"]
        assert checkov[0]["findings"] == [ckv_finding]

    def test_scans_images_discovered_by_container_exposure(self, db):
        from posint_scanner.config import CloudScanConfig

        class ExposureSource(Source):
            name = "container_exposure"
            category = "active"

            def enrich(self, target, hostnames):
                return EnrichmentResult(
                    source=self.name, target_type="ip", target=target,
                    data={"exposures": [], "images": ["1.2.3.4:5000/api:latest"]},
                )

        with (
            patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]),
            patch("posint_scanner.cloudscan.TrivyScanner.available", True),
            patch("posint_scanner.cloudscan.TrivyScanner.scan_image", return_value=[]) as img,
        ):
            run_scan(db, ["example.com"], [FakeDiscoverySource(), ExposureSource()],
                     netblock_sweep=False, vuln_lookup=False, cloud_scan=True,
                     cloudscan_config=CloudScanConfig())
        img.assert_called_once_with("1.2.3.4:5000/api:latest")


class TestCloudAuditStage:
    """Authenticated cloud auditing (--cloud-audit): Prowler + ScoutSuite."""

    def test_off_by_default(self, db):
        with (
            patch("posint_scanner.orchestrator.resolve_hostname", return_value=[]),
            patch("posint_scanner.cloudscan.ProwlerScanner.scan") as pro,
            patch("posint_scanner.cloudscan.ScoutSuiteScanner.scan") as sco,
        ):
            run_scan(db, ["example.com"], [FakeDiscoverySource()], netblock_sweep=False,
                     vuln_lookup=False)
        pro.assert_not_called()
        sco.assert_not_called()

    def test_runs_prowler_per_provider_and_persists(self, db):
        from posint_scanner.config import CloudScanConfig
        finding = {"tool": "prowler", "kind": "misconfig", "severity": "critical",
                   "id": "iam_root_mfa", "title": "root mfa", "resource": "root",
                   "target": "aws", "cves": [], "reference": None, "location": "us-east-1"}
        with (
            patch("posint_scanner.orchestrator.resolve_hostname", return_value=[]),
            patch("posint_scanner.cloudscan.ProwlerScanner.available", True),
            patch("posint_scanner.cloudscan.ScoutSuiteScanner.available", False),
            patch("posint_scanner.cloudscan.ProwlerScanner.scan",
                  return_value=[finding]) as pro,
        ):
            run_scan(db, ["example.com"], [FakeDiscoverySource()], netblock_sweep=False,
                     vuln_lookup=False, cloud_audit=True,
                     cloudscan_config=CloudScanConfig(providers=["aws"]))
        pro.assert_called_once_with("aws")
        domain_id = db.get_domain_by_name("example.com")["id"]
        results = [json.loads(r["data"]) for r in db.list_results_for_target("domain", domain_id)
                   if r["source"] == "prowler"]
        assert results[0]["target"] == "aws"
        assert results[0]["counts"] == {"critical": 1}


class TestCrossDomainConcurrency:
    def test_domains_run_concurrently_not_sequentially(self, db):
        import time

        class SlowDiscoverySource(Source):
            name = "slow"

            def discover(self, domain):
                time.sleep(0.3)
                return [DiscoveredHostname(name=f"host.{domain}", source=self.name)]

        domains = ["a.example.com", "b.example.com", "c.example.com"]
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=[]):
            start = time.monotonic()
            run_scan(db, domains, [SlowDiscoverySource()], netblock_sweep=False, vuln_lookup=False)
            elapsed = time.monotonic() - start

        # sequential would take ~0.9s (3 x 0.3s); concurrent should be much
        # closer to a single domain's ~0.3s. Generous margin for CI jitter.
        assert elapsed < 0.7, f"took {elapsed:.2f}s - looks sequential, not concurrent"
        for domain in domains:
            assert db.get_domain_by_name(domain) is not None

    def test_one_domain_failure_does_not_abort_the_rest_of_the_batch(self, db):
        class FailsForOneDomain(Source):
            name = "flaky"

            def discover(self, domain):
                if domain == "bad.example.com":
                    raise RuntimeError("simulated unexpected failure")
                return [DiscoveredHostname(name=f"host.{domain}", source=self.name)]

        domains = ["good1.example.com", "bad.example.com", "good2.example.com"]
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=[]):
            # must not raise, despite one domain's pipeline failing outright
            run_scan(db, domains, [FailsForOneDomain()], netblock_sweep=False, vuln_lookup=False)

        assert db.get_domain_by_name("good1.example.com") is not None
        assert db.get_domain_by_name("good2.example.com") is not None
        good1_id = db.get_domain_by_name("good1.example.com")["id"]
        good2_id = db.get_domain_by_name("good2.example.com")["id"]
        assert db.get_hostname_by_name("host.good1.example.com")["domain_id"] == good1_id
        assert db.get_hostname_by_name("host.good2.example.com")["domain_id"] == good2_id

    def test_max_concurrent_domains_is_respected(self, db):
        import threading
        import time

        concurrent_count = {"current": 0, "max": 0}
        lock = threading.Lock()

        class TrackingSource(Source):
            name = "tracking"

            def discover(self, domain):
                with lock:
                    concurrent_count["current"] += 1
                    concurrent_count["max"] = max(concurrent_count["max"], concurrent_count["current"])
                time.sleep(0.1)
                with lock:
                    concurrent_count["current"] -= 1
                return []

        domains = [f"d{i}.example.com" for i in range(6)]
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=[]):
            run_scan(
                db,
                domains,
                [TrackingSource()],
                netblock_sweep=False,
                vuln_lookup=False,
                max_concurrent_domains=2,
            )

        assert concurrent_count["max"] <= 2

    def test_nvd_client_constructed_once_regardless_of_domain_count(self, db):
        import posint_scanner.orchestrator as orchestrator_module

        instantiations = []
        real_nvd_client = orchestrator_module.NvdClient

        class CountingNvdClient(real_nvd_client):
            def __init__(self, *args, **kwargs):
                instantiations.append(1)
                super().__init__(*args, **kwargs)

        domains = ["a.example.com", "b.example.com", "c.example.com"]
        with patch("posint_scanner.orchestrator.NvdClient", CountingNvdClient):
            with patch.object(real_nvd_client, "lookup_cves", return_value=[]):
                with patch("posint_scanner.orchestrator.resolve_hostname", return_value=[]):
                    run_scan(db, domains, [FakeDiscoverySource()], netblock_sweep=False)

        assert len(instantiations) == 1


class TestTechFingerprintIntegration:
    """The fingerprint stage is on by default (opt-out) and active, so
    scan_service is patched everywhere here - never a live HTTP fetch."""

    def test_runs_by_default(self, db, no_live_fingerprint):
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
            run_scan(
                db,
                ["example.com"],
                [FakeDiscoverySource(), FakeIpEnrichSource()],
                netblock_sweep=False,
                vuln_lookup=False,
            )
        no_live_fingerprint.assert_called()

    def test_opt_out_makes_no_fetch(self, db, no_live_fingerprint):
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
            run_scan(
                db,
                ["example.com"],
                [FakeDiscoverySource(), FakeIpEnrichSource()],
                netblock_sweep=False,
                tech_fingerprint=False,
                vuln_lookup=False,
            )
        no_live_fingerprint.assert_not_called()

    def test_persists_webtech_result_and_backfills_service_version(self, db):
        # FakeIpEnrichSource reports 443/nginx with NO version; the
        # fingerprinter supplies the version, which must land on the service.
        fake_result = {
            "url": "https://api.example.com:443/",
            "status": 200,
            "technologies": {"nginx": "1.25.3", "PHP": "8.2.4"},
            "categories": {"nginx": ["web-server"], "PHP": ["programming-language"]},
            "server_product": "nginx",
            "server_version": "1.25.3",
        }
        with patch(
            "posint_scanner.orchestrator.WebTechFingerprinter.scan_service",
            return_value=fake_result,
        ):
            with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
                run_scan(
                    db,
                    ["example.com"],
                    [FakeDiscoverySource(), FakeIpEnrichSource()],
                    netblock_sweep=False,
                    tech_fingerprint=True,
                    vuln_lookup=False,
                )

        ip_row = db.get_ip_by_address("1.2.3.4")
        results = db.list_results_for_target("ip", ip_row["id"])
        webtech = [r for r in results if r["source"] == "webtech"]
        assert len(webtech) == 1

        service = next(s for s in db.list_services_for_ip(ip_row["id"]) if s["port"] == 443)
        assert service["version"] == "1.25.3"  # backfilled from the fingerprint

    def test_fingerprinted_version_feeds_cve_lookup(self, db, no_live_nvd_lookup):
        # end-to-end: a service with no version gets one from the fingerprint,
        # which then lets the NVD stage build a CPE and find CVEs.
        no_live_nvd_lookup.return_value = [{"cve_id": "CVE-2021-23017", "cvss_score": 7.7}]
        fake_result = {
            "url": "https://api.example.com:443/",
            "status": 200,
            "technologies": {"nginx": "1.18.0"},
            "categories": {"nginx": ["web-server"]},
            "server_product": "nginx",
            "server_version": "1.18.0",
        }
        with patch(
            "posint_scanner.orchestrator.WebTechFingerprinter.scan_service",
            return_value=fake_result,
        ):
            with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
                run_scan(
                    db,
                    ["example.com"],
                    [FakeDiscoverySource(), FakeIpEnrichSource()],
                    netblock_sweep=False,
                    tech_fingerprint=True,
                )

        no_live_nvd_lookup.assert_called_once_with("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*")

    def test_no_web_server_product_leaves_service_untouched_but_records_result(self, db):
        fake_result = {
            "url": "http://api.example.com:443/",
            "status": 200,
            "technologies": {"jQuery": "3.6.0"},
            "categories": {"jQuery": ["javascript-library"]},
            "server_product": None,
            "server_version": None,
        }
        with patch(
            "posint_scanner.orchestrator.WebTechFingerprinter.scan_service",
            return_value=fake_result,
        ):
            with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
                run_scan(
                    db,
                    ["example.com"],
                    [FakeDiscoverySource(), FakeIpEnrichSource()],
                    netblock_sweep=False,
                    tech_fingerprint=True,
                    vuln_lookup=False,
                )

        ip_row = db.get_ip_by_address("1.2.3.4")
        service = next(s for s in db.list_services_for_ip(ip_row["id"]) if s["port"] == 443)
        assert service["banner"] == "nginx"  # unchanged from the enrich source
        assert service["version"] is None
        webtech = [r for r in db.list_results_for_target("ip", ip_row["id"]) if r["source"] == "webtech"]
        assert len(webtech) == 1

    def test_every_versioned_technology_is_cve_checked(self, db, no_live_nvd_lookup):
        fake_result = {
            "url": "https://api.example.com:443/",
            "status": 200,
            "technologies": {"nginx": "1.18.0", "jQuery": "3.4.1", "WordPress": None},
            "categories": {},
            "cpes": {
                "nginx": [
                    "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*",
                    "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
                ],
                "jQuery": ["cpe:2.3:a:jquery:jquery:3.4.1:*:*:*:*:*:*:*"],
            },
            "server_product": "nginx",
            "server_version": "1.18.0",
        }

        def fake_lookup(cpe):
            return {
                "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*": [{"cve_id": "CVE-2021-23017"}],
                "cpe:2.3:a:jquery:jquery:3.4.1:*:*:*:*:*:*:*": [{"cve_id": "CVE-2020-11022"}],
            }.get(cpe, [])

        no_live_nvd_lookup.side_effect = fake_lookup
        with patch(
            "posint_scanner.orchestrator.WebTechFingerprinter.scan_service",
            return_value=fake_result,
        ):
            with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
                run_scan(
                    db,
                    ["example.com"],
                    [FakeDiscoverySource(), FakeIpEnrichSource()],
                    netblock_sweep=False,
                    tech_fingerprint=True,
                )

        looked_up = [call.args[0] for call in no_live_nvd_lookup.call_args_list]
        # each CPE checked exactly once: the service row's guessed nginx CPE is
        # skipped in favour of the fingerprint's accurate mapping, not doubled
        assert sorted(looked_up) == sorted(
            [
                "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*",
                "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
                "cpe:2.3:a:jquery:jquery:3.4.1:*:*:*:*:*:*:*",
            ]
        )

        ip_row = db.get_ip_by_address("1.2.3.4")
        nvd = [
            json.loads(r["data"])
            for r in db.list_results_for_target("ip", ip_row["id"])
            if r["source"] == "nvd"
        ]
        by_tech = {entry["technology"]: entry for entry in nvd}
        assert set(by_tech) == {"nginx", "jQuery"}
        assert by_tech["jQuery"]["cves"] == [{"cve_id": "CVE-2020-11022"}]
        assert by_tech["nginx"]["cpe"] == "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"
        assert by_tech["nginx"]["port"] == 443


class TestAutomaticContinuation:
    """Continuation is automatic: re-scanning a domain already in the DB
    revalidates and prunes stale results; a first-ever scan does not."""

    def _seed_prior_scan(self, db):
        # a prior scan: a.example.com -> 1.1.1.1 (still valid) and
        # -> 9.9.9.9 (will become stale); 9.9.9.9 carries a service.
        domain_id = db.upsert_domain("example.com")
        hid = db.upsert_hostname(domain_id, "a.example.com")
        old = db.upsert_ip("1.1.1.1")
        gone = db.upsert_ip("9.9.9.9")
        db.upsert_resolution(hid, old, now="2020-01-01T00:00:00+00:00")
        db.upsert_resolution(hid, gone, now="2020-01-01T00:00:00+00:00")
        db.upsert_service(gone, 445, "tcp", "SMB")
        db.insert_result("shodan_web", "ip", gone, {"stale": True})
        return domain_id

    class _StableDiscovery(Source):
        name = "stable-disco"

        def discover(self, domain):
            return [DiscoveredHostname(name="a.example.com", source=self.name)]

    def test_rescan_of_known_domain_prunes_stale_mapping_and_orphan_ip(self, db):
        self._seed_prior_scan(db)  # domain already exists -> auto-resume
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.1.1.1"]):
            run_scan(db, ["example.com"], [self._StableDiscovery()],
                     netblock_sweep=False, vuln_lookup=False, tech_fingerprint=False)

        assert db.get_ip_by_address("1.1.1.1") is not None
        assert db.get_ip_by_address("9.9.9.9") is None  # orphaned + pruned
        hid = db.get_hostname_by_name("a.example.com")["id"]
        assert [r["address"] for r in db.list_ips_for_hostname(hid)] == ["1.1.1.1"]

    def test_revalidate_runs_for_known_domain(self, db):
        self._seed_prior_scan(db)
        with (
            patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.1.1.1"]),
            patch("posint_scanner.orchestrator._revalidate") as mock_reval,
        ):
            run_scan(db, ["example.com"], [self._StableDiscovery()],
                     netblock_sweep=False, vuln_lookup=False, tech_fingerprint=False)
        mock_reval.assert_called_once()

    def test_first_scan_of_new_domain_does_not_revalidate(self, db):
        with (
            patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.1.1.1"]),
            patch("posint_scanner.orchestrator._revalidate") as mock_reval,
        ):
            run_scan(db, ["brand-new.example.com"], [FakeDiscoverySource()],
                     netblock_sweep=False, vuln_lookup=False, tech_fingerprint=False)
        mock_reval.assert_not_called()


class CountingIpEnrichSource(FakeIpEnrichSource):
    name = "counting-ip-enrich"

    def __init__(self, **governance):
        self.calls: list[str] = []
        for key, value in governance.items():
            setattr(self, key, value)

    def enrich(self, target, hostnames):
        self.calls.append(target)
        return super().enrich(target, hostnames)


class CountingDiscoverySource(FakeDiscoverySource):
    name = "counting-discovery"

    def __init__(self, **governance):
        self.calls: list[str] = []
        for key, value in governance.items():
            setattr(self, key, value)

    def discover(self, domain):
        self.calls.append(domain)
        return super().discover(domain)


class TestGovernance:
    """Every source call goes through the governor (see governor.py)."""

    def test_enrichment_within_ttl_is_not_repeated_on_rescan(self, db):
        source = CountingIpEnrichSource(ttl_days=7)
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
            run_scan(db, ["example.com"], [FakeDiscoverySource(), source])
            run_scan(db, ["example.com"], [FakeDiscoverySource(), source])
        assert source.calls == ["1.2.3.4"]
        # the earlier result stays attached to the surviving IP
        ip_row = db.get_ip_by_address("1.2.3.4")
        assert any(
            r["source"] == source.name for r in db.list_results_for_target("ip", ip_row["id"])
        )

    def test_fresh_bypasses_ttl(self, db):
        source = CountingIpEnrichSource(ttl_days=7)
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
            run_scan(db, ["example.com"], [FakeDiscoverySource(), source])
            run_scan(db, ["example.com"], [FakeDiscoverySource(), source], fresh=True)
        assert source.calls == ["1.2.3.4", "1.2.3.4"]

    def test_discovery_within_ttl_is_not_repeated(self, db):
        source = CountingDiscoverySource(ttl_days=7)
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=[]):
            run_scan(db, ["example.com"], [source])
            run_scan(db, ["example.com"], [source])
        assert source.calls == ["example.com"]

    def test_budget_caps_calls_across_targets(self, db):
        source = CountingIpEnrichSource(daily_budget=1)

        def resolve(name):
            return ["1.1.1.1"] if name.startswith("api.") else ["2.2.2.2"]

        with patch("posint_scanner.orchestrator.resolve_hostname", side_effect=resolve):
            run_scan(db, ["example.com"], [FakeDiscoverySource(), source])
        assert len(source.calls) == 1


class DriftedScraperEnrich(Source):
    name = "drifted-scraper"
    category = "scrape"

    def enrich(self, target, hostnames):
        raise ScrapeParseError("host page returned 200 but no known fields")


class DriftedScraperDiscovery(Source):
    name = "drifted-disco"
    category = "scrape"
    ttl_days = 7

    def __init__(self):
        self.calls = 0

    def discover(self, domain):
        self.calls += 1
        raise ScrapeParseError("no results table")


class TestScraperParseWarnings:
    """A scraper whose page parsed to nothing raises ScrapeParseError, so
    markup drift shows up in the scan rather than looking like "no data"."""

    def test_enrichment_parse_warning_is_recorded_on_the_target(self, db):
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
            run_scan(db, ["example.com"], [FakeDiscoverySource(), DriftedScraperEnrich()])
        ip_row = db.get_ip_by_address("1.2.3.4")
        rows = [
            json.loads(r["data"])
            for r in db.list_results_for_target("ip", ip_row["id"])
            if r["source"] == "drifted-scraper"
        ]
        assert rows == [{"parse_warning": "host page returned 200 but no known fields"}]

    def test_parse_failure_is_not_cached_as_fresh(self, db):
        source = DriftedScraperDiscovery()
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=[]):
            run_scan(db, ["example.com"], [source])
            run_scan(db, ["example.com"], [source])
        assert source.calls == 2


class UnconfiguredEnrich(CountingIpEnrichSource):
    name = "unconfigured-enrich"

    @property
    def is_configured(self):
        return False


class TestUnconfiguredSources:
    def test_unconfigured_source_is_skipped_once_not_called_per_target(self, db, caplog):
        source = UnconfiguredEnrich()
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
            run_scan(db, ["example.com"], [FakeDiscoverySource(), source])
        assert source.calls == []
        warnings = [r for r in caplog.records if "unconfigured-enrich" in r.getMessage()]
        assert len(warnings) == 1


class ReverseIpSource(Source):
    """Reports other hostnames it has seen on each IP (like a reverse-IP API)."""

    name = "reverse-ip"

    def __init__(self, related_by_ip):
        self.related_by_ip = related_by_ip
        self.calls: list[str] = []

    def enrich(self, target, hostnames):
        self.calls.append(target)
        return EnrichmentResult(
            source=self.name,
            target_type="ip",
            target=target,
            related_hostnames=self.related_by_ip.get(target, []),
        )


def resolver(mapping, default=None):
    def resolve(name):
        return mapping.get(name, default or [])

    return resolve


class TestFeedbackLoop:
    """Hostnames an enrichment source relates to a target feed back into the
    pipeline when they're under the scanned domain; anything else becomes a
    candidate domain, never scanned automatically."""

    def test_in_scope_related_hostname_is_resolved_and_enriched(self, db):
        source = ReverseIpSource({"1.1.1.1": ["new.example.com"]})
        mapping = {"api.example.com": ["1.1.1.1"], "www.example.com": ["1.1.1.1"],
                   "new.example.com": ["2.2.2.2"]}
        with patch("posint_scanner.orchestrator.resolve_hostname", side_effect=resolver(mapping)):
            run_scan(db, ["example.com"], [FakeDiscoverySource(), source])

        assert db.get_hostname_by_name("new.example.com") is not None
        assert sorted(source.calls) == ["1.1.1.1", "2.2.2.2"]
        new_ip = db.get_ip_by_address("2.2.2.2")
        assert new_ip is not None
        assert [h["name"] for h in db.list_hostnames_for_ip(new_ip["id"])] == ["new.example.com"]

    def test_out_of_scope_related_hostname_becomes_candidate_domain(self, db):
        source = ReverseIpSource({"1.1.1.1": ["shop.other-brand.co.uk", "www.other-brand.co.uk"]})
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.1.1.1"]):
            run_scan(db, ["example.com"], [FakeDiscoverySource(), source])

        domain_id = db.get_domain_by_name("example.com")["id"]
        candidates = db.list_candidate_domains(domain_id)
        assert [c["name"] for c in candidates] == ["other-brand.co.uk"]
        assert candidates[0]["source"] == "reverse-ip"
        assert "1.1.1.1" in candidates[0]["via"]
        # never scanned: not a domain, and none of its hostnames stored
        assert db.get_domain_by_name("other-brand.co.uk") is None
        assert db.get_hostname_by_name("shop.other-brand.co.uk") is None

    def test_shared_hosting_ip_yields_no_candidates(self, db):
        crowd = [f"site{i}.example-{i}.net" for i in range(40)]
        source = ReverseIpSource({"1.1.1.1": crowd})
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.1.1.1"]):
            run_scan(db, ["example.com"], [FakeDiscoverySource(), source])
        domain_id = db.get_domain_by_name("example.com")["id"]
        assert db.list_candidate_domains(domain_id) == []

    def test_loop_is_bounded(self, db):
        class Chain(ReverseIpSource):
            """Every IP points at yet another new in-scope hostname."""

            def enrich(self, target, hostnames):
                self.calls.append(target)
                n = len(self.calls)
                return EnrichmentResult(
                    source=self.name, target_type="ip", target=target,
                    related_hostnames=[f"gen{n}.example.com"],
                )

        ips: dict[str, str] = {}

        def resolve(name):
            return [ips.setdefault(name, f"10.0.0.{len(ips) + 1}")]

        source = Chain({})
        with patch("posint_scanner.orchestrator.resolve_hostname", side_effect=resolve):
            run_scan(db, ["example.com"], [FakeDiscoverySource(), source])
        # pass 1 enriches api/www's IPs (-> gen1, gen2), pass 2 only the new
        # hosts' IPs (-> gen3, gen4); those are stored but not chased further
        assert len(source.calls) == 4
        assert db.get_hostname_by_name("gen4.example.com") is not None
        assert "gen3.example.com" not in ips

    def test_ip_addresses_are_not_candidates(self, db):
        source = ReverseIpSource({"1.1.1.1": ["9.9.9.9", "localhost"]})
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.1.1.1"]):
            run_scan(db, ["example.com"], [FakeDiscoverySource(), source])
        domain_id = db.get_domain_by_name("example.com")["id"]
        assert db.list_candidate_domains(domain_id) == []


class FakeCollectSource(Source):
    name = "fake-collect"

    def __init__(self, ttl_days=0.0):
        self.ttl_days = ttl_days
        self.calls: list[str] = []

    def collect(self, domain):
        self.calls.append(domain)
        return EnrichmentResult(
            source=self.name,
            target_type="domain",
            target=domain,
            data={"registrar": "Example Registrar"},
            related_hostnames=[f"ns1.{domain}", "ns.dns-provider.net"],
        )


class TestCollection:
    def test_domain_result_is_stored_and_related_hostnames_resolved(self, db):
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.1.1.1"]):
            run_scan(db, ["example.com"], [FakeDiscoverySource(), FakeCollectSource()])
        domain_id = db.get_domain_by_name("example.com")["id"]
        rows = db.list_results_for_target("domain", domain_id)
        assert [json.loads(r["data"]) for r in rows] == [{"registrar": "Example Registrar"}]
        ns = db.get_hostname_by_name("ns1.example.com")
        assert ns is not None
        assert [ip["address"] for ip in db.list_ips_for_hostname(ns["id"])] == ["1.1.1.1"]
        assert [c["name"] for c in db.list_candidate_domains(domain_id)] == ["dns-provider.net"]

    def test_collection_honours_ttl_independently_of_discovery(self, db):
        source = FakeCollectSource(ttl_days=7)
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=[]):
            run_scan(db, ["example.com"], [source])
            run_scan(db, ["example.com"], [source])
        assert source.calls == ["example.com"]


class SiblingCollectSource(Source):
    """Relates example.com to its .net sibling (and .net back to .com and on
    to .org), plus an unrelated domain."""

    name = "fake-sibling-collect"

    def __init__(self):
        self.calls: list[str] = []

    def collect(self, domain):
        self.calls.append(domain)
        related = {
            "example.com": ["www.example.net", "other.net"],
            "example.net": ["example.com", "example.org"],
        }.get(domain, [])
        return EnrichmentResult(
            source=self.name, target_type="domain", target=domain, data={},
            related_hostnames=related,
        )


class TestTldSiblings:
    def test_sibling_is_scanned_in_the_same_run_not_made_a_candidate(self, db):
        source = SiblingCollectSource()
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=[]):
            run_scan(db, ["example.com"], [source])

        # Each once, including the sibling's own sibling; never re-queued.
        assert sorted(source.calls) == ["example.com", "example.net", "example.org"]
        assert {d["name"] for d in db.list_domains()} == {
            "example.com", "example.net", "example.org"
        }
        com_id = db.get_domain_by_name("example.com")["id"]
        assert [c["name"] for c in db.list_candidate_domains(com_id)] == ["other.net"]

    def test_cancelled_scan_does_not_start_siblings(self, db):
        source = SiblingCollectSource()
        control = ScanControl()
        original = source.collect

        def collect_then_cancel(domain):
            result = original(domain)
            control.cancel()
            return result

        source.collect = collect_then_cancel
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=[]):
            run_scan(db, ["example.com"], [source], control=control)
        assert source.calls == ["example.com"]


class BucketCollectSource(Source):
    name = "fake-buckets"

    def collect(self, domain):
        from posint_scanner.models import CloudAsset

        return EnrichmentResult(
            source=self.name,
            target_type="domain",
            target=domain,
            data={"public": 1},
            cloud_assets=[
                CloudAsset(provider="s3", name="acme-data",
                           url="https://acme-data.s3.amazonaws.com/", exposure="public")
            ],
        )


class TestCloudAssetPersistence:
    def test_collect_cloud_assets_are_stored(self, db):
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=[]):
            run_scan(db, ["example.com"], [FakeDiscoverySource(), BucketCollectSource()])
        domain_id = db.get_domain_by_name("example.com")["id"]
        assets = db.list_cloud_assets(domain_id)
        assert len(assets) == 1
        assert assets[0]["name"] == "acme-data"
        assert assets[0]["exposure"] == "public"


class TestProgressAndCancel:
    def test_progress_events_report_each_stage(self, db):
        stages = []
        control = ScanControl(on_progress=lambda stage, detail: stages.append(stage))
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
            run_scan(
                db, ["example.com"], [FakeDiscoverySource(), FakeIpEnrichSource()], control=control
            )
        assert "discovery" in stages
        assert "enrichment" in stages

    def test_cancel_stops_before_later_stages_run(self, db):
        enrich = CountingIpEnrichSource()
        control = ScanControl()
        # cancel the moment discovery reports, before enrichment
        control.on_progress = lambda stage, detail: (
            control.cancel() if stage == "discovery" else None
        )
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
            run_scan(db, ["example.com"], [FakeDiscoverySource(), enrich], control=control)
        # discovery persisted its hostnames, but enrichment never ran
        domain_id = db.get_domain_by_name("example.com")["id"]
        assert db.list_hostnames_for_domain(domain_id)
        assert enrich.calls == []
        assert control.cancelled()

    def test_uncancelled_scan_completes_normally(self, db):
        enrich = CountingIpEnrichSource()
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
            run_scan(db, ["example.com"], [FakeDiscoverySource(), enrich], control=ScanControl())
        assert enrich.calls == ["1.2.3.4"]


class ExposureCollectSource(Source):
    name = "fake-gh-collect"

    def collect(self, domain):
        from posint_scanner.models import CodeExposure
        return EnrichmentResult(
            source=self.name, target_type="domain", target=domain,
            data={"total_hits": 2},
            code_exposures=[
                CodeExposure(kind="reference", target=f"api.{domain}", repo="acme/infra",
                             path="nginx.conf", commit="a" * 40,
                             url="https://github.com/acme/infra/blob/x/nginx.conf#L3", line=3),
                CodeExposure(kind="secret", target=f"api.{domain}", repo="acme/app",
                             path=".env", commit="b" * 40, url="https://github.com/acme/app/blob/y/.env#L1",
                             line=1, rule="aws_access_key_id", secret="AKIA1234"),
            ],
        )


class ExposureIpEnrichSource(Source):
    name = "fake-gh-ip"

    def enrich(self, target, hostnames):
        from posint_scanner.models import CodeExposure
        return EnrichmentResult(
            source=self.name, target_type="ip", target=target, data={},
            code_exposures=[
                CodeExposure(kind="reference", target=target, repo="acme/ops",
                             path="hosts.yml", commit="c" * 40,
                             url="https://github.com/acme/ops/blob/z/hosts.yml#L9", line=9),
            ],
        )


class TestCodeExposurePersistence:
    def test_collect_exposures_are_stored(self, db):
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=[]):
            run_scan(db, ["example.com"], [FakeDiscoverySource(), ExposureCollectSource()])
        domain_id = db.get_domain_by_name("example.com")["id"]
        rows = db.list_code_exposures(domain_id)
        assert {r["kind"] for r in rows} == {"reference", "secret"}
        assert db.list_code_exposures(domain_id)[0]["kind"] == "secret"  # secrets first

    def test_ip_enrichment_exposures_are_stored(self, db):
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
            run_scan(db, ["example.com"], [FakeDiscoverySource(), ExposureIpEnrichSource()])
        domain_id = db.get_domain_by_name("example.com")["id"]
        rows = db.list_code_exposures(domain_id, target="1.2.3.4")
        assert len(rows) == 1
        assert rows[0]["repo"] == "acme/ops"
        assert rows[0]["line"] == 9
