import pytest

from posint_scanner.config import CategoryDefaults, Config
from posint_scanner.registry import (
    SourceSelection,
    build_sources,
    describe_sources,
    discovery_sources,
    enrichment_sources,
    filter_by_name,
)
from posint_scanner.sources.base import DEFAULT_TTL_DAYS


def names(sources):
    return {s.name for s in sources}


def config(**sources):
    return Config(sources=sources)


class TestDefaultEnablement:
    def test_includes_expected_default_sources(self):
        assert names(build_sources(Config())) == {
            "subfinder",
            "dnsrecon",
            "crtsh",
            "wayback",
            "commoncrawl",
            "hackertarget",
            "otx",
            "virustotal",
            "securitytrails",
            "fullhunt",
            "netlas",
            "urlscan",
            "greynoise",
            "ipinfo",
            "abuseipdb",
            "rdap",
            "entra_id",
            "origin_ip",
            "github",
            "theharvester",
            "hunter",
            "tomba",
            "pgp_keyserver",
            "shodan",
            "censys",
            "qualys_ssllabs",
            "qualys_vmdr",
            "ping",
            "portscan",
        }

    def test_stub_source_not_included_by_default(self):
        # subdomainsfinder has no documented API and always raises - running it
        # by default would error on every domain, every scan.
        assert "subdomainsfinder" not in names(build_sources(Config()))

    def test_scrapers_off_by_default(self):
        # shodan_web scrapes shodan.io's HTML, and its domain-page lookup runs
        # against a robots.txt disallow.
        found = names(build_sources(Config()))
        assert "shodan_web" not in found
        assert "rapiddns" not in found
        assert "fullhunt_web" not in found

    def test_category_default_can_turn_scrapers_on(self):
        cfg = Config(defaults=CategoryDefaults(scrape=True))
        assert "shodan_web" in names(build_sources(cfg))

    def test_category_default_can_turn_active_off(self):
        cfg = Config(defaults=CategoryDefaults(active=False))
        found = names(build_sources(cfg))
        assert "ping" not in found
        assert "portscan" not in found
        assert "shodan" in found

    def test_config_enabled_overrides_category_default(self):
        cfg = config(portscan={"enabled": False}, shodan_web={"enabled": True})
        found = names(build_sources(cfg))
        assert "portscan" not in found
        assert "shodan_web" in found

    def test_config_enabled_overrides_class_default(self):
        assert "subdomainsfinder" in names(build_sources(config(subdomainsfinder={"enabled": True})))


class TestSelection:
    def test_cli_disable_wins_over_config(self):
        cfg = config(ping={"enabled": True})
        assert "ping" not in names(build_sources(cfg, SourceSelection(disable={"ping"})))

    def test_cli_enable_wins_over_config(self):
        cfg = config(shodan_web={"enabled": False})
        assert "shodan_web" in names(build_sources(cfg, SourceSelection(enable={"shodan_web"})))

    def test_cli_category_override_wins_over_config(self):
        cfg = config(portscan={"enabled": True})
        found = names(build_sources(cfg, SourceSelection(categories={"active": False})))
        assert "portscan" not in found

    def test_explicit_source_wins_over_cli_category(self):
        selection = SourceSelection(enable={"ping"}, categories={"active": False})
        found = names(build_sources(Config(), selection))
        assert "ping" in found
        assert "portscan" not in found

    def test_unknown_source_name_rejected(self):
        with pytest.raises(ValueError, match="nope"):
            build_sources(Config(), SourceSelection(enable={"nope"}))


class TestFallback:
    def test_fullhunt_web_stands_in_for_unkeyed_fullhunt(self):
        cfg = config(fullhunt_web={"enabled": True})
        assert "fullhunt_web" in names(build_sources(cfg))
        cfg = config(fullhunt={"api_key": "k"}, fullhunt_web={"enabled": True})
        assert "fullhunt_web" not in names(build_sources(cfg))

    def test_web_fallback_skipped_when_api_sibling_configured(self):
        cfg = config(shodan={"api_key": "k"}, shodan_web={"enabled": True})
        assert "shodan_web" not in names(build_sources(cfg))

    def test_web_fallback_runs_when_api_sibling_unconfigured(self):
        cfg = config(shodan_web={"enabled": True})
        assert "shodan_web" in names(build_sources(cfg))

    def test_web_fallback_runs_when_api_sibling_disabled(self):
        cfg = config(shodan={"api_key": "k", "enabled": False}, shodan_web={"enabled": True})
        assert "shodan_web" in names(build_sources(cfg))

    def test_config_force_runs_both(self):
        cfg = config(shodan={"api_key": "k"}, shodan_web={"enabled": True, "force": True})
        assert {"shodan", "shodan_web"} <= names(build_sources(cfg))

    def test_explicit_cli_enable_forces_fallback(self):
        cfg = config(shodan={"api_key": "k"})
        found = names(build_sources(cfg, SourceSelection(enable={"shodan_web"})))
        assert {"shodan", "shodan_web"} <= found


class TestSettingsFlowIntoSources:
    def test_api_key_reaches_source(self):
        shodan = next(s for s in build_sources(config(shodan={"api_key": "k"})) if s.name == "shodan")
        assert shodan.api_key == "k"
        assert shodan.is_configured

    def test_unconfigured_keyed_source_still_built(self):
        # skipped at scan time with a warning, not dropped at build time
        shodan = next(s for s in build_sources(Config()) if s.name == "shodan")
        assert not shodan.is_configured

    def test_setting_overrides_flow_to_source(self):
        sources = build_sources(Config(), overrides={"qualys_vmdr": {"authorize_scans": True}})
        vmdr = next(s for s in sources if s.name == "qualys_vmdr")
        assert vmdr.authorize_scans is True

    def test_authorize_scans_defaults_false(self):
        vmdr = next(s for s in build_sources(Config()) if s.name == "qualys_vmdr")
        assert vmdr.authorize_scans is False

    def test_metered_source_has_default_ttl(self):
        shodan = next(s for s in build_sources(Config()) if s.name == "shodan")
        assert shodan.ttl_days == DEFAULT_TTL_DAYS

    def test_governance_overrides_from_config(self):
        cfg = config(shodan={"ttl_days": 0, "daily_budget": 10, "requests_per_minute": 30})
        shodan = next(s for s in build_sources(cfg) if s.name == "shodan")
        assert shodan.ttl_days == 0
        assert shodan.daily_budget == 10
        assert shodan.requests_per_minute == 30


class TestDescribeSources:
    def test_lists_every_registered_source_with_resolved_state(self):
        info = {i.name: i for i in describe_sources(config(shodan_web={"enabled": True}))}
        assert info["shodan_web"].category == "scrape"
        assert info["shodan_web"].enabled is True
        assert info["ping"].category == "active"
        assert info["subdomainsfinder"].enabled is False
        assert info["shodan"].configured is False


class TestDiscoveryAndEnrichmentSplit:
    def test_discovery_sources_only_include_discover_capable(self):
        found = names(discovery_sources(build_sources(Config())))
        assert {"subfinder", "dnsrecon", "crtsh"} <= found
        assert "shodan" not in found
        assert "qualys_ssllabs" not in found

    def test_enrichment_sources_only_include_enrich_capable(self):
        found = names(enrichment_sources(build_sources(Config())))
        assert {"shodan", "censys", "qualys_ssllabs", "qualys_vmdr", "dnsrecon"} <= found
        assert "subfinder" not in found


class TestFilterByName:
    def test_no_filter_returns_all(self):
        sources = build_sources(Config())
        assert filter_by_name(sources, None) == sources

    def test_filters_to_named_subset(self):
        filtered = filter_by_name(build_sources(Config()), ["subfinder", "shodan"])
        assert names(filtered) == {"subfinder", "shodan"}


class TestGitHubSource:
    def test_github_unconfigured_without_token(self):
        info = {i.name: i for i in describe_sources(config())}
        assert info["github"].category == "passive"
        assert info["github"].configured is False

    def test_github_configured_with_token(self):
        gh = next(s for s in build_sources(config(github={"token": "ghp_x"})) if s.name == "github")
        assert gh.is_configured
        assert gh.can_collect and gh.can_enrich
