import ipaddress

import pytest

from posint_scanner.sources import origin_ip
from posint_scanner.sources.origin_ip import OriginIpSource, cdn_of, spf_hosts_and_ips


class TestCdnOf:
    def test_cloudflare_ip_is_detected(self):
        # 104.16.0.0/13 is a published Cloudflare range
        assert cdn_of("104.16.5.5") == "cloudflare"

    def test_non_cdn_ip_is_none(self):
        assert cdn_of("212.86.33.249") is None

    def test_garbage_is_none(self):
        assert cdn_of("not-an-ip") is None


class TestSpfParsing:
    def test_extracts_ip_literals_and_a_hosts_only(self):
        txt = [
            'v=spf1 ip4:198.51.100.7 ip4:203.0.113.0/24 a:mail.example.com '
            'include:sendgrid.net mx:_spf.google.com -all',
            'some other txt',
        ]
        ips, hosts = spf_hosts_and_ips(txt)
        assert "198.51.100.7" in ips
        assert "203.0.113.0/24" in ips
        assert hosts == ["mail.example.com"]
        # third-party delegation mechanisms are NOT origin hints
        assert "sendgrid.net" not in hosts
        assert "_spf.google.com" not in hosts


class TestOriginIpSource:
    def _patch_dns(self, monkeypatch, a_records, mx=None, txt=None):
        mx = mx or {}
        txt = txt or {}

        def fake_query(name, rtype):
            if rtype == "MX":
                return mx.get(name, [])
            if rtype == "TXT":
                return txt.get(name, [])
            return []

        def fake_resolve(name):
            return a_records.get(name, [])

        monkeypatch.setattr(origin_ip, "query_record_type", fake_query)
        monkeypatch.setattr(origin_ip, "resolve_hostname", fake_resolve)

    def test_reports_cdn_and_non_cdn_origin_candidate(self, monkeypatch):
        # apex sits on Cloudflare; a "direct" subdomain leaks a real origin IP
        self._patch_dns(
            monkeypatch,
            a_records={
                "example.com": ["104.16.5.5"],
                "direct.example.com": ["203.0.113.10"],
                "mail.example.com": ["203.0.113.10"],
            },
            mx={"example.com": ["10 mail.example.com."]},
        )
        result = OriginIpSource(subdomains=["direct"]).collect("example.com")
        assert result.target_type == "domain"
        assert result.data["cdn"] == "cloudflare"
        assert result.data["behind_cdn"] is True
        candidates = {c["ip"]: c for c in result.data["origin_candidates"]}
        assert "203.0.113.10" in candidates
        # the leaked IP came via two hints; both recorded
        assert set(candidates["203.0.113.10"]["via"]) == {"subdomain:direct.example.com", "mx:mail.example.com"}

    def test_cdn_frontend_ips_are_not_reported_as_origin(self, monkeypatch):
        self._patch_dns(
            monkeypatch,
            a_records={"example.com": ["104.16.5.5"], "www.example.com": ["104.16.5.6"]},
        )
        result = OriginIpSource(subdomains=["www"]).collect("example.com")
        # both are Cloudflare - nothing to de-cloak
        assert result.data["origin_candidates"] == []

    def test_spf_ip_literal_becomes_a_candidate(self, monkeypatch):
        self._patch_dns(
            monkeypatch,
            a_records={"example.com": ["104.16.5.5"]},
            txt={"example.com": ['v=spf1 ip4:198.51.100.7 -all']},
        )
        result = OriginIpSource(subdomains=[]).collect("example.com")
        vias = {c["ip"]: c["via"] for c in result.data["origin_candidates"]}
        assert vias["198.51.100.7"] == ["spf"]

    def test_spf_include_provider_is_not_reported_as_origin(self, monkeypatch):
        # include: delegates to a third-party mail provider - its IPs must
        # never surface as candidate origins even though they resolve.
        self._patch_dns(
            monkeypatch,
            a_records={"example.com": ["104.16.5.5"], "sendgrid.net": ["167.89.1.1"]},
            txt={"example.com": ['v=spf1 include:sendgrid.net -all']},
        )
        result = OriginIpSource(subdomains=[]).collect("example.com")
        assert result.data["origin_candidates"] == []

    def test_not_behind_cdn_still_reports_but_flags_false(self, monkeypatch):
        self._patch_dns(monkeypatch, a_records={"example.com": ["203.0.113.5"]})
        result = OriginIpSource(subdomains=[]).collect("example.com")
        assert result.data["behind_cdn"] is False
        assert result.data["cdn"] is None

    def test_origin_candidates_feed_back_only_when_behind_cdn(self, monkeypatch):
        # behind a CDN, a leaked origin IP is worth enriching -> related.
        self._patch_dns(
            monkeypatch,
            a_records={"example.com": ["104.16.5.5"], "direct.example.com": ["203.0.113.10"]},
        )
        result = OriginIpSource(subdomains=["direct"]).collect("example.com")
        assert "203.0.113.10" in result.data["origin_candidates"][0]["ip"]
        # related_hostnames are hostnames, not IPs - so origin IPs must NOT be
        # jammed in there (they'd be treated as candidate domains). Kept in data.
        assert result.related_hostnames == []

    def test_category_passive(self):
        assert OriginIpSource.category == "passive"
