"""Lightweight source registry.

Adding a new source: subclass Source in sources/ (declaring its `category`,
and a `settings_model` + `from_settings` if it takes keys/options), then add
the class to SOURCE_CLASSES below. Config (config.yaml `sources:` map and
`OSINT_<SOURCE>_<FIELD>` env vars) and the CLI/web-UI toggles pick it up
without further wiring. No dynamic plugin discovery / entry points -
deliberately simple.

Whether a source runs is decided per source, most specific first:

  1. CLI `--source X` / `--no-source X` (SourceSelection.enable/disable)
  2. CLI category switch, e.g. `--no-active` (SourceSelection.categories)
  3. config `sources: {X: {enabled: ...}}`
  4. the class's own `default_enabled` (e.g. False for a stub)
  5. config `defaults: {passive, scrape, active}` for the source's category

Categories: "passive" sources query resolvers/third-party APIs; "scrape"
sources parse a service's public HTML pages instead of a documented API
(policy-sensitive, off by default); "active" sources (ping, portscan) send
packets straight to the target (on by default, turn off with `--no-active`).
Qualys VMDR's active scan-triggering stays separately opt-in via its
`authorize_scans` setting (the `--authorize-scans` flag).

A `*_web` scraper declaring `fallback_for = "<api source>"` is a keyless
stand-in: it's dropped when its API sibling is enabled *and* configured,
unless forced (`force: true` in its config, or named via `--source`) - web
pages sometimes show data an API tier hides (e.g. Shodan's domain page), so
running both stays possible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from posint_scanner.config import Config
from posint_scanner.sources.base import Source, SourceSettings
from posint_scanner.sources.abuseipdb import AbuseIpDbSource
from posint_scanner.sources.bucketsearch import BucketSearchSource
from posint_scanner.sources.censys_source import CensysSource
from posint_scanner.sources.commoncrawl import CommonCrawlSource
from posint_scanner.sources.container_exposure import ContainerExposureSource
from posint_scanner.sources.crtsh import CrtShSource
from posint_scanner.sources.dnsbrute import DnsBruteSource
from posint_scanner.sources.dnsrecon import DnsReconSource
from posint_scanner.sources.entra_id import EntraIdSource
from posint_scanner.sources.fullhunt import FullHuntSource
from posint_scanner.sources.fullhunt_web import FullHuntWebSource
from posint_scanner.sources.github import GitHubSource
from posint_scanner.sources.greynoise import GreyNoiseSource
from posint_scanner.sources.hunter import HunterSource
from posint_scanner.sources.hackertarget import HackerTargetSource
from posint_scanner.sources.ipinfo import IpInfoSource
from posint_scanner.sources.lookalike import LookalikeSource
from posint_scanner.sources.netlas import NetlasSource
from posint_scanner.sources.origin_ip import OriginIpSource
from posint_scanner.sources.otx import OtxSource
from posint_scanner.sources.pgp_keyserver import PgpKeyserverSource
from posint_scanner.sources.ping import PingSource
from posint_scanner.sources.portscan import PortScanSource
from posint_scanner.sources.qualys_vmdr import QualysVmdrSource
from posint_scanner.sources.rapiddns import RapidDnsSource
from posint_scanner.sources.rdap import RdapSource
from posint_scanner.sources.securitytrails import SecurityTrailsSource
from posint_scanner.sources.shodan_source import ShodanSource
from posint_scanner.sources.shodan_web import ShodanWebSource
from posint_scanner.sources.ssllabs import SslLabsSource
from posint_scanner.sources.subdomainsfinder import SubdomainsFinderSource
from posint_scanner.sources.subfinder import SubfinderSource
from posint_scanner.sources.theharvester import TheHarvesterSource
from posint_scanner.sources.tomba import TombaSource
from posint_scanner.sources.urlscan import UrlScanSource
from posint_scanner.sources.virustotal import VirusTotalSource
from posint_scanner.sources.wayback import WaybackSource

SOURCE_CLASSES: list[type[Source]] = [
    # discovery
    SubfinderSource,
    DnsReconSource,
    CrtShSource,
    WaybackSource,
    CommonCrawlSource,
    HackerTargetSource,
    DnsBruteSource,
    OtxSource,
    VirusTotalSource,
    SecurityTrailsSource,
    FullHuntSource,
    NetlasSource,
    UrlScanSource,
    RapidDnsSource,
    FullHuntWebSource,
    # enrichment (several discovery sources above also enrich: reverse IP)
    ShodanSource,
    CensysSource,
    SslLabsSource,
    QualysVmdrSource,
    GreyNoiseSource,
    IpInfoSource,
    AbuseIpDbSource,
    PingSource,
    PortScanSource,
    ContainerExposureSource,
    ShodanWebSource,
    SubdomainsFinderSource,
    # collection (domain-level)
    RdapSource,
    EntraIdSource,
    LookalikeSource,
    OriginIpSource,
    BucketSearchSource,
    GitHubSource,
    # collection: email addresses
    TheHarvesterSource,
    HunterSource,
    TombaSource,
    PgpKeyserverSource,
]

CATEGORIES = ("passive", "scrape", "active")


@dataclass
class SourceSelection:
    """Run-time (CLI / web UI) choices, which win over config."""

    enable: set[str] = field(default_factory=set)
    disable: set[str] = field(default_factory=set)
    categories: dict[str, bool] = field(default_factory=dict)


@dataclass
class SourceInfo:
    """What the UI needs to render a toggle for one source."""

    name: str
    category: str
    enabled: bool
    configured: bool
    fallback_for: str | None


def _validate(selection: SourceSelection) -> None:
    known = {cls.name for cls in SOURCE_CLASSES}
    unknown = (selection.enable | selection.disable) - known
    if unknown:
        raise ValueError(
            f"unknown source(s): {', '.join(sorted(unknown))} "
            f"(known: {', '.join(sorted(known))})"
        )
    bad_categories = set(selection.categories) - set(CATEGORIES)
    if bad_categories:
        raise ValueError(f"unknown source categories: {', '.join(sorted(bad_categories))}")


def _is_enabled(
    cls: type[Source], settings: SourceSettings, config: Config, selection: SourceSelection
) -> bool:
    if cls.name in selection.enable:
        return True
    if cls.name in selection.disable:
        return False
    if cls.category in selection.categories:
        return selection.categories[cls.category]
    if settings.enabled is not None:
        return settings.enabled
    if cls.default_enabled is not None:
        return cls.default_enabled
    return bool(getattr(config.defaults, cls.category))


def _resolve(
    config: Config,
    selection: SourceSelection,
    overrides: dict[str, dict[str, Any]],
) -> list[tuple[Source, SourceSettings, bool]]:
    """Every registered source built from its settings, with whether it would
    run before fallback pruning."""
    _validate(selection)
    resolved = []
    for cls in SOURCE_CLASSES:
        settings = config.source_settings(cls.name, cls.settings_model)
        if cls.name in overrides:
            settings = settings.model_copy(update=overrides[cls.name])
        source = cls.from_settings(settings)
        source.configure(settings)
        resolved.append((source, settings, _is_enabled(cls, settings, config, selection)))
    return resolved


def _drop_superseded_fallbacks(
    resolved: list[tuple[Source, SourceSettings, bool]], selection: SourceSelection
) -> list[Source]:
    live_and_configured = {
        source.name for source, _, enabled in resolved if enabled and source.is_configured
    }
    kept = []
    for source, settings, enabled in resolved:
        if not enabled:
            continue
        forced = settings.force or source.name in selection.enable
        if source.fallback_for in live_and_configured and not forced:
            continue
        kept.append(source)
    return kept


def build_sources(
    config: Config,
    selection: SourceSelection | None = None,
    overrides: dict[str, dict[str, Any]] | None = None,
) -> list[Source]:
    """The sources that should run for this scan. `overrides` sets settings
    fields per source from run-time flags (e.g. qualys_vmdr authorize_scans).
    Raises ValueError for an unknown source/category name in `selection`."""
    selection = selection or SourceSelection()
    resolved = _resolve(config, selection, overrides or {})
    return _drop_superseded_fallbacks(resolved, selection)


def describe_sources(config: Config) -> list[SourceInfo]:
    """Every registered source and whether it runs by default under this
    config (before any run-time selection) - for rendering UI toggles."""
    selection = SourceSelection()
    resolved = _resolve(config, selection, {})
    running = {source.name for source in _drop_superseded_fallbacks(resolved, selection)}
    return [
        SourceInfo(
            name=source.name,
            category=source.category,
            enabled=source.name in running,
            configured=source.is_configured,
            fallback_for=source.fallback_for,
        )
        for source, _, _ in resolved
    ]


def discovery_sources(sources: list[Source]) -> list[Source]:
    return [source for source in sources if source.can_discover]


def enrichment_sources(sources: list[Source]) -> list[Source]:
    return [source for source in sources if source.can_enrich]


def collection_sources(sources: list[Source]) -> list[Source]:
    return [source for source in sources if source.can_collect]


def filter_by_name(sources: list[Source], names: list[str] | None) -> list[Source]:
    if not names:
        return sources
    wanted = set(names)
    return [source for source in sources if source.name in wanted]
