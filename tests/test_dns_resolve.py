from unittest.mock import Mock, patch

import dns.resolver

from posint_scanner.dns_resolve import lookup_domain_nameserver_ip, resolve_hostname


class TestResolveHostname:
    def test_collects_a_and_aaaa_records(self):
        def fake_resolve(name, rtype):
            if rtype == "A":
                return [Mock(__str__=lambda self: "1.2.3.4")]
            if rtype == "AAAA":
                return [Mock(__str__=lambda self: "::1")]
            raise dns.resolver.NoAnswer()

        with patch("dns.resolver.resolve", side_effect=fake_resolve):
            result = resolve_hostname("example.com")

        assert result == ["1.2.3.4", "::1"]

    def test_returns_empty_list_on_nxdomain(self):
        with patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
            result = resolve_hostname("nonexistent.example.com")
        assert result == []

    def test_returns_a_only_when_no_aaaa(self):
        def fake_resolve(name, rtype):
            if rtype == "A":
                return [Mock(__str__=lambda self: "1.2.3.4")]
            raise dns.resolver.NoAnswer()

        with patch("dns.resolver.resolve", side_effect=fake_resolve):
            result = resolve_hostname("example.com")
        assert result == ["1.2.3.4"]


class TestLookupDomainNameserverIp:
    def test_resolves_first_ns_hostname_to_ip(self):
        def fake_resolve(name, rtype):
            if name == "example.com" and rtype == "NS":
                return [Mock(__str__=lambda self: "ns1.example.com.")]
            if name == "ns1.example.com" and rtype == "A":
                return [Mock(__str__=lambda self: "9.9.9.9")]
            raise dns.resolver.NoAnswer()

        with patch("dns.resolver.resolve", side_effect=fake_resolve):
            assert lookup_domain_nameserver_ip("example.com") == "9.9.9.9"

    def test_returns_none_when_no_ns_records(self):
        with patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
            assert lookup_domain_nameserver_ip("example.com") is None

    def test_falls_through_to_second_ns_if_first_has_no_a_record(self):
        def fake_resolve(name, rtype):
            if name == "example.com" and rtype == "NS":
                return [
                    Mock(__str__=lambda self: "ns1.example.com."),
                    Mock(__str__=lambda self: "ns2.example.com."),
                ]
            if name == "ns1.example.com" and rtype == "A":
                raise dns.resolver.NoAnswer()
            if name == "ns2.example.com" and rtype == "A":
                return [Mock(__str__=lambda self: "9.9.9.9")]
            raise dns.resolver.NoAnswer()

        with patch("dns.resolver.resolve", side_effect=fake_resolve):
            assert lookup_domain_nameserver_ip("example.com") == "9.9.9.9"
