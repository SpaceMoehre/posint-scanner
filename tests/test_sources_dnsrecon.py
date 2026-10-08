import ipaddress
from unittest.mock import Mock, patch

import dns.resolver

from posint_scanner.sources.dnsrecon import (
    DnsReconSource,
    belongs_to_domain,
    hostname_from_zone_label,
    lookup_records,
    reverse_lookup,
    sweep_netblocks,
)


class TestHostnameFromZoneLabel:
    def test_apex_label_returns_domain_itself(self):
        assert hostname_from_zone_label("@", "example.com") == "example.com"

    def test_subdomain_label_is_joined_to_domain(self):
        assert hostname_from_zone_label("api", "example.com") == "api.example.com"

    def test_lowercases_result(self):
        assert hostname_from_zone_label("API", "Example.com") == "api.example.com"


class TestReverseLookup:
    def test_returns_ptr_names(self):
        answer = [Mock(target=Mock(__str__=lambda self: "host.example.com."))]
        with patch("dns.resolver.resolve_address", return_value=answer):
            result = reverse_lookup("1.2.3.4")
        assert result == ["host.example.com"]

    def test_returns_empty_list_on_no_ptr_record(self):
        with patch("dns.resolver.resolve_address", side_effect=dns.resolver.NXDOMAIN()):
            result = reverse_lookup("1.2.3.4")
        assert result == []


class TestBelongsToDomain:
    def test_exact_match(self):
        assert belongs_to_domain("example.com", "example.com") is True

    def test_subdomain_match(self):
        assert belongs_to_domain("host.example.com", "example.com") is True

    def test_unrelated_domain_does_not_match(self):
        assert belongs_to_domain("host.evil.com", "example.com") is False

    def test_suffix_without_dot_boundary_does_not_match(self):
        # "notexample.com" ends with "example.com" as a raw string but isn't
        # a subdomain of it - must not false-positive on this.
        assert belongs_to_domain("notexample.com", "example.com") is False

    def test_case_insensitive(self):
        assert belongs_to_domain("Host.Example.COM", "example.com") is True

    def test_ignores_trailing_dots(self):
        assert belongs_to_domain("host.example.com.", "example.com") is True


class TestSweepNetblocks:
    def test_finds_matching_hostname_in_range(self):
        network = ipaddress.ip_network("192.0.2.0/30")  # .1, .2 are the usable hosts

        def fake_reverse_lookup(ip, resolver=None):
            if ip == "192.0.2.1":
                return ["db.example.com"]
            return []

        with patch("posint_scanner.sources.dnsrecon.reverse_lookup", side_effect=fake_reverse_lookup):
            result = sweep_netblocks([network], "example.com", ["1.1.1.1"])

        assert len(result) == 1
        assert result[0].name == "db.example.com"
        assert result[0].source == "dnsrecon"
        assert result[0].data["discovered_via"] == "netblock_sweep"
        assert result[0].data["ip"] == "192.0.2.1"
        assert result[0].data["resolver"] == "1.1.1.1"

    def test_filters_out_ptr_hits_for_unrelated_domains(self):
        network = ipaddress.ip_network("192.0.2.0/30")

        def fake_reverse_lookup(ip, resolver=None):
            return ["somethingelse.other.org"]

        with patch("posint_scanner.sources.dnsrecon.reverse_lookup", side_effect=fake_reverse_lookup):
            result = sweep_netblocks([network], "example.com", ["1.1.1.1"])

        assert result == []

    def test_no_ptr_records_yields_nothing(self):
        network = ipaddress.ip_network("192.0.2.0/30")
        with patch("posint_scanner.sources.dnsrecon.reverse_lookup", return_value=[]):
            result = sweep_netblocks([network], "example.com", ["1.1.1.1"])
        assert result == []

    def test_queries_every_resolver_for_each_address(self):
        network = ipaddress.ip_network("192.0.2.0/30")
        calls = []

        def fake_reverse_lookup(ip, resolver=None):
            calls.append((ip, resolver.nameservers[0]))
            return []

        with patch("posint_scanner.sources.dnsrecon.reverse_lookup", side_effect=fake_reverse_lookup):
            sweep_netblocks([network], "example.com", ["1.1.1.1", "9.9.9.9"])

        resolvers_used = {resolver for _ip, resolver in calls}
        assert resolvers_used == {"1.1.1.1", "9.9.9.9"}
        # 2 usable addresses (.1, .2) x 2 resolvers
        assert len(calls) == 4

    def test_a_hit_from_either_resolver_counts(self):
        network = ipaddress.ip_network("192.0.2.0/30")

        def fake_reverse_lookup(ip, resolver=None):
            if ip == "192.0.2.1" and resolver.nameservers[0] == "9.9.9.9":
                return ["only-on-target-ns.example.com"]
            return []

        with patch("posint_scanner.sources.dnsrecon.reverse_lookup", side_effect=fake_reverse_lookup):
            result = sweep_netblocks([network], "example.com", ["1.1.1.1", "9.9.9.9"])

        assert len(result) == 1
        assert result[0].name == "only-on-target-ns.example.com"
        assert result[0].data["resolver"] == "9.9.9.9"

    def test_sweeps_multiple_networks_in_one_call(self):
        network_a = ipaddress.ip_network("192.0.2.0/30")
        network_b = ipaddress.ip_network("198.51.100.0/30")

        def fake_reverse_lookup(ip, resolver=None):
            if ip == "192.0.2.1":
                return ["a.example.com"]
            if ip == "198.51.100.1":
                return ["b.example.com"]
            return []

        with patch("posint_scanner.sources.dnsrecon.reverse_lookup", side_effect=fake_reverse_lookup):
            result = sweep_netblocks([network_a, network_b], "example.com", ["1.1.1.1"])

        names = {h.name for h in result}
        assert names == {"a.example.com", "b.example.com"}

    def test_worker_count_is_configurable(self):
        network = ipaddress.ip_network("192.0.2.0/30")
        seen_max_workers = {}

        class FakeExecutor:
            def __init__(self, max_workers=None):
                seen_max_workers["value"] = max_workers

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def submit(self, fn, *args):
                future = Mock()
                future.result.return_value = []
                return future

        with patch("posint_scanner.sources.dnsrecon.ThreadPoolExecutor", FakeExecutor):
            with patch("posint_scanner.sources.dnsrecon.as_completed", return_value=[]):
                sweep_netblocks([network], "example.com", ["1.1.1.1"], workers=7)

        assert seen_max_workers["value"] == 7


class TestLookupRecords:
    def test_collects_each_record_type(self):
        def fake_resolve(name, rtype):
            if rtype == "MX":
                return [Mock(__str__=lambda self: "10 mail.example.com.")]
            raise dns.resolver.NoAnswer()

        with patch("dns.resolver.resolve", side_effect=fake_resolve):
            result = lookup_records("example.com")

        assert result["MX"] == ["10 mail.example.com."]
        assert result["NS"] == []
        assert result["TXT"] == []
        assert result["SOA"] == []

    def test_handles_nxdomain_for_all_types(self):
        with patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
            result = lookup_records("nonexistent.example.com")
        assert all(v == [] for v in result.values())


class TestDnsReconSourceEnrich:
    def test_enrich_includes_ptr_and_records(self):
        source = DnsReconSource()
        with patch("posint_scanner.sources.dnsrecon.reverse_lookup", return_value=["host.example.com"]):
            with patch(
                "posint_scanner.sources.dnsrecon.lookup_records",
                return_value={"NS": [], "MX": [], "TXT": [], "SOA": []},
            ):
                result = source.enrich("1.2.3.4", ["api.example.com"])

        assert result.data["ptr"] == ["host.example.com"]
        assert result.data["records"]["api.example.com"]["MX"] == []
        assert result.source == "dnsrecon"
        assert result.target_type == "ip"


class TestDnsReconSourceDiscover:
    def test_returns_empty_when_no_ns_records(self):
        source = DnsReconSource()
        with patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
            result = source.discover("example.com")
        assert result == []

    @staticmethod
    def _fake_ns_and_a_resolve(ns_answer):
        """dns.resolver.resolve is called twice during a zone-transfer attempt:
        once for the domain's NS records, once for the nameserver's own A
        record (xfr needs an IP, not a hostname) - route each rtype accordingly."""

        def fake_resolve(name, rtype):
            if rtype == "NS":
                return ns_answer
            if rtype == "A":
                return [Mock(__str__=lambda self: "192.0.2.1")]
            raise dns.resolver.NoAnswer()

        return fake_resolve

    def test_zone_transfer_success_yields_discovered_hostnames(self):
        source = DnsReconSource()
        ns_answer = [Mock(target=Mock(__str__=lambda self: "ns1.example.com."))]

        fake_zone = Mock()
        fake_zone.nodes = {
            Mock(__str__=lambda self: "@"): Mock(),
            Mock(__str__=lambda self: "api"): Mock(),
        }

        with patch("dns.resolver.resolve", side_effect=self._fake_ns_and_a_resolve(ns_answer)):
            with patch("dns.query.xfr", return_value=iter([])):
                with patch("dns.zone.from_xfr", return_value=fake_zone):
                    result = source.discover("example.com")

        names = {h.name for h in result}
        assert names == {"example.com", "api.example.com"}
        assert result[0].source == "dnsrecon"
        assert result[0].data.get("axfr_successful") is True

    def test_zone_transfer_queries_nameserver_ip_not_hostname(self):
        source = DnsReconSource()
        ns_answer = [Mock(target=Mock(__str__=lambda self: "ns1.example.com."))]

        with patch("dns.resolver.resolve", side_effect=self._fake_ns_and_a_resolve(ns_answer)):
            with patch("dns.query.xfr", return_value=iter([])) as mock_xfr:
                with patch("dns.zone.from_xfr", return_value=Mock(nodes={})):
                    source.discover("example.com")

        called_where = mock_xfr.call_args[0][0]
        assert called_where == "192.0.2.1"

    def test_zone_transfer_refused_yields_nothing(self):
        source = DnsReconSource()
        ns_answer = [Mock(target=Mock(__str__=lambda self: "ns1.example.com."))]
        with patch("dns.resolver.resolve", side_effect=self._fake_ns_and_a_resolve(ns_answer)):
            with patch("dns.query.xfr", side_effect=OSError("refused")):
                result = source.discover("example.com")
        assert result == []

    def test_nameserver_with_no_a_record_is_skipped_without_calling_xfr(self):
        source = DnsReconSource()
        ns_answer = [Mock(target=Mock(__str__=lambda self: "ns1.example.com."))]

        def fake_resolve(name, rtype):
            if rtype == "NS":
                return ns_answer
            raise dns.resolver.NXDOMAIN()

        with patch("dns.resolver.resolve", side_effect=fake_resolve):
            with patch("dns.query.xfr") as mock_xfr:
                result = source.discover("example.com")

        mock_xfr.assert_not_called()
        assert result == []
