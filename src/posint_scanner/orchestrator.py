"""Scan pipeline: normalize domains -> discovery -> DNS resolution -> enrichment.

Each stage tolerates individual source failures (missing binary/API key,
transient errors after retries exhaust, unexpected exceptions) by logging
and skipping just that source - a bad source never aborts the whole scan.
The same applies to persisting a single item's result: a DB write failure
(e.g. a transient filesystem issue) is logged and skipped rather than
propagating up and killing the whole scan, since that would otherwise
discard everything already fetched from other sources/hosts in the batch.
"""

from __future__ import annotations

import functools
import gc
import ipaddress
import json
import logging
import os
import tempfile
import threading
import time
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait
from datetime import datetime, timezone

from posint_scanner.asn import lookup_asn, lookup_asn_prefixes
from posint_scanner.cloudscan import (
    CheckovScanner,
    ProwlerScanner,
    ScoutSuiteScanner,
    TrivyScanner,
    clone_repo,
    count_by_severity,
)
from posint_scanner.config import CloudScanConfig, WebScanConfig
from posint_scanner.db import Database
from posint_scanner.dns_resolve import lookup_domain_nameserver_ip, resolve_hostname
from posint_scanner.exploitdb import SearchSploitClient
from posint_scanner.governor import SourceGovernor
from posint_scanner.models import DiscoveredHostname, EnrichmentResult
from posint_scanner.normalize import InvalidDomainError, dedup_domains, normalize_domain
from posint_scanner.nuclei import NucleiScanner
from posint_scanner.nvd import NvdClient, build_cpe, cpe_version
from posint_scanner.webscan import NiktoScanner, TakeoverScanner, WpscanScanner
from posint_scanner.registry import (
    collection_sources,
    discovery_sources,
    enrichment_sources,
    filter_by_name,
)
from posint_scanner.scope import is_tld_sibling, split_related
from posint_scanner.settings import apply_settings
from posint_scanner.sources.base import ScrapeParseError, Source, SourceUnavailableError
from posint_scanner.sources.dnsrecon import SWEEP_WORKERS, sweep_netblocks
from posint_scanner.sources.portscan import TLS_PORTS
from posint_scanner.sources.webtech import WebTechFingerprinter

logger = logging.getLogger(__name__)


class ScanCancelled(Exception):
    """Raised inside the pipeline when the scan was asked to stop. It aborts
    the current domain's remaining stages; data already persisted stays."""


class ScanControl:
    """Progress reporting + cooperative cancellation for one run_scan call.

    `progress(stage, detail)` is emitted at each pipeline stage so a caller
    (the web UI's job tracker) can show what a running scan is doing.
    `cancel()` asks the scan to stop; stages call `check()` between units of
    work and raise ScanCancelled promptly. One instance is shared across a
    run's domain/stage thread pools, so both are thread-safe."""

    def __init__(self, on_progress: Callable[[str, str], None] | None = None) -> None:
        self.on_progress = on_progress
        self._cancel = threading.Event()

    def progress(self, stage: str, detail: str = "") -> None:
        logger.info("scan stage: %s%s", stage, f" ({detail})" if detail else "")
        if self.on_progress is not None:
            try:
                self.on_progress(stage, detail)
            except Exception:
                logger.exception("scan progress callback failed - continuing")

    def cancel(self) -> None:
        self._cancel.set()

    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def check(self) -> None:
        if self._cancel.is_set():
            raise ScanCancelled()

# Discovery/resolution/enrichment thread pool size (per domain). Adjustable
# via --workers. Kept modest by default because discovery/enrichment call
# external rate-limited APIs (Shodan, Censys) where more concurrency doesn't
# help and can hurt - raise it if your API plans support more throughput.
DEFAULT_WORKERS = 5

# How many domains run concurrently in a --domains-file batch. Each domain's
# full pipeline (discovery/resolution/netblock sweep/enrichment/vuln lookup)
# is otherwise independent, so this is a real speed lever for a batch - but
# every per-domain stage already opens its own thread pool, so concurrent
# domains multiply those pools together. Kept modest by default.
DEFAULT_MAX_CONCURRENT_DOMAINS = 4

# Netblock sweep: for every already-known IP, look up the ASN announcing it
# and sweep every prefix that ASN announces (not just a /24) for PTR records
# matching the domain - catches hosts with no public cert and no naming
# link to anything else discovered, anywhere in the target's own address
# space. If ASN lookup fails for an IP, fall back to its /24 (and
# neighbors) rather than skipping it. Queried against a baseline list of
# public resolvers, plus the target's own nameserver if one was discovered
# (it may be authoritative for its own reverse-DNS zone and see records a
# public resolver doesn't).
NETBLOCK_SWEEP_FALLBACK_PREFIX = 24
DEFAULT_NETBLOCK_SWEEP_MAX_ADDRESSES = 20_000
# Single source of truth for the default lives in dnsrecon.py (the module
# sweep_netblocks() itself defaults to) - reused here rather than
# duplicated, so the two can never drift out of sync again.
DEFAULT_NETBLOCK_SWEEP_WORKERS = SWEEP_WORKERS
DEFAULT_SWEEP_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

# Feedback loop: in-scope hostnames enrichment sources relate to a target
# (reverse-IP, PTR) are resolved and enriched too - for this many enrichment
# passes in total, so a chain of "new host -> new IP -> new host" can't run
# away. Names the last pass surfaces are stored but not chased.
MAX_ENRICHMENT_PASSES = 2
# A target related to more distinct out-of-scope domains than this is shared
# hosting (a CDN edge, a big web host) - its neighbours say nothing about the
# target's owner, so none of them become candidate domains.
SHARED_HOSTING_THRESHOLD = 25

# (source name, target label, related hostnames) from one collection or
# enrichment result.
Related = tuple[str, str, list[str]]


class ScanTargets:
    """The domains one run_scan call covers. Starts as the requested domains;
    a TLD sibling of one (see scope.is_tld_sibling) found mid-run is added
    and queued so run_scan schedules its own pipeline. Shared across the
    run's domain threads, so it's locked."""

    def __init__(self, domains: list[str]) -> None:
        self._lock = threading.Lock()
        self._known = set(domains)
        self._queued: list[str] = []

    def add(self, domain: str) -> bool:
        """Queue `domain` unless this run already covers it."""
        with self._lock:
            if domain in self._known:
                return False
            self._known.add(domain)
            self._queued.append(domain)
            return True

    def take_queued(self) -> list[str]:
        with self._lock:
            queued, self._queued = self._queued, []
            return queued


def normalize_input_domains(raw_domains: list[str]) -> list[str]:
    normalized = []
    for raw in raw_domains:
        try:
            normalized.append(normalize_domain(raw))
        except InvalidDomainError as exc:
            logger.error("skipping invalid domain %r: %s", raw, exc)
    return dedup_domains(normalized)


def infer_parent_hostname(hostname: str, domain: str, known_hostnames: set[str]) -> str | None:
    """Best-effort DNS-hierarchy parent: the closest known hostname that is a
    suffix of `hostname`, excluding the apex domain itself."""
    labels = hostname.split(".")
    for start in range(1, len(labels) - 1):
        candidate = ".".join(labels[start:])
        if candidate == domain:
            continue
        if candidate in known_hostnames:
            return candidate
    return None


def _persist_discovered_hostnames(
    db: Database,
    domain_id: int,
    domain: str,
    all_discovered: list[DiscoveredHostname],
    known_hostnames: set[str],
) -> None:
    """Two-pass write, deliberately split so correctness doesn't depend on
    `all_discovered`'s order. `infer_parent_hostname` (pure) always computes
    the right parent *name* from `known_hostnames`, since that set is fully
    built before this runs - but linking requires the parent's *row* to
    already be written. A single pass that both inserts and links as it
    goes made that an emergent, untestable property of whatever order
    `all_discovered` happens to be in (itself downstream of
    ThreadPoolExecutor/as_completed scheduling across discovery sources): a
    child processed before its parent would silently end up with no
    parent link even though the name was correctly inferred.

    Pass 1 inserts every item with no parent link. Pass 2 links each item
    to its parent, which is now guaranteed to exist if it was discovered
    in this same batch. A parent discovered in a previous run is already
    in the database and links correctly too; a parent not discovered at
    all (this run or before) correctly leaves parent_hostname_id as None.
    This intentionally doesn't retroactively re-link hostnames from past
    runs whose parent is only newly discovered now - that's a distinct,
    separate capability, not part of this fix."""
    for item in all_discovered:
        try:
            hostname_id = db.upsert_hostname(domain_id, item.name)
            if item.data:
                db.insert_result(item.source, "hostname", hostname_id, item.data)
        except Exception:
            logger.exception("failed to persist discovered hostname %s - continuing", item.name)

    for item in all_discovered:
        try:
            parent_name = infer_parent_hostname(item.name, domain, known_hostnames)
            if not parent_name:
                continue
            parent_row = db.get_hostname_by_name(parent_name)
            if parent_row is None:
                continue
            db.upsert_hostname(domain_id, item.name, parent_hostname_id=parent_row["id"])
        except Exception:
            logger.exception("failed to link parent hostname for %s - continuing", item.name)


def _run_discovery_for_domain(
    db: Database, sources: list[Source], domain: str, workers: int, governor: SourceGovernor
) -> int:
    domain_id = db.upsert_domain(domain)
    known_hostnames = {row["name"] for row in db.list_hostnames_for_domain(domain_id)}

    all_discovered: list[DiscoveredHostname] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                governor.run, source, "domain", domain, functools.partial(source.discover, domain)
            ): source
            for source in sources
        }
        for future in as_completed(futures):
            source = futures.pop(future)
            try:
                all_discovered.extend(future.result() or [])
            except SourceUnavailableError as exc:
                logger.warning("%s skipped for %s: %s", source.name, domain, exc)
            except ScrapeParseError as exc:
                logger.warning(
                    "%s: page for %s parsed to nothing - site markup may have changed: %s",
                    source.name,
                    domain,
                    exc,
                )
            except Exception:
                logger.exception("%s discovery failed for %s", source.name, domain)

    known_hostnames.update(item.name for item in all_discovered)
    _persist_discovered_hostnames(db, domain_id, domain, all_discovered, known_hostnames)

    logger.info("discovery for %s: %d hostnames found", domain, len(all_discovered))
    return domain_id


def _run_collection(
    db: Database,
    sources: list[Source],
    domain: str,
    domain_id: int,
    workers: int,
    governor: SourceGovernor,
    targets: ScanTargets | None = None,
) -> None:
    """Domain-level data (registration records etc.), stored as results on
    the domain. Runs right after discovery so any in-scope hostnames it
    relates (e.g. the domain's own nameservers) go through resolution and
    enrichment like discovered ones. Its ledger key is "collect", separate
    from discovery's "domain", so a source doing both has independent TTLs."""
    related: list[Related] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                governor.run, source, "collect", domain, functools.partial(source.collect, domain)
            ): source
            for source in sources
        }
        for future in as_completed(futures):
            source = futures.pop(future)
            try:
                result = future.result()
            except SourceUnavailableError as exc:
                logger.warning("%s skipped for %s: %s", source.name, domain, exc)
                continue
            except Exception:
                logger.exception("%s collection failed for %s", source.name, domain)
                continue
            if result is None:
                continue  # declined by the governor
            try:
                db.insert_result(result.source, "domain", domain_id, result.data)
                for asset in result.cloud_assets:
                    db.upsert_cloud_asset(
                        domain_id, asset.provider, asset.name, asset.url, asset.exposure, result.source
                    )
                for email in result.email_addresses:
                    db.upsert_email_address(
                        domain_id, email.address, result.source, email.name, email.position,
                        email.confidence, email.url,
                    )
                _persist_code_exposures(db, domain_id, result)
            except Exception:
                logger.exception("failed to persist %s result for %s", source.name, domain)
            if result.related_hostnames:
                related.append((source.name, domain, result.related_hostnames))
    _absorb_related(db, domain_id, domain, related, targets)


def _run_resolution(
    db: Database, domain_id: int, workers: int, hostname_ids: set[int] | None = None
) -> None:
    hostname_rows = [
        row
        for row in db.list_hostnames_for_domain(domain_id)
        if hostname_ids is None or row["id"] in hostname_ids
    ]
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(resolve_hostname, row["name"]): row for row in hostname_rows
        }
        for future in as_completed(futures):
            hostname_row = futures.pop(future)
            try:
                addresses = future.result()
            except Exception:
                logger.exception("resolution failed for %s - continuing", hostname_row["name"])
                continue

            for address in addresses:
                try:
                    ip_id = db.upsert_ip(address)
                    db.upsert_resolution(hostname_row["id"], ip_id)
                except Exception:
                    logger.exception(
                        "failed to persist resolution %s -> %s - continuing",
                        hostname_row["name"],
                        address,
                    )


def _fallback_24s(ip: str) -> list[ipaddress.IPv4Network]:
    """The /24 containing `ip`, plus its immediate neighbors above and
    below in address space. Allocators commonly assign contiguous /24s to
    the same organization, so checking next door catches more without the
    cost of sweeping a whole larger block."""
    try:
        containing = ipaddress.IPv4Network(f"{ip}/{NETBLOCK_SWEEP_FALLBACK_PREFIX}", strict=False)
    except ValueError:
        return []

    networks = [containing]
    block_size = containing.num_addresses
    base = int(containing.network_address)
    for offset in (-block_size, block_size):
        try:
            neighbor_address = ipaddress.IPv4Address(base + offset)
            networks.append(
                ipaddress.IPv4Network(f"{neighbor_address}/{NETBLOCK_SWEEP_FALLBACK_PREFIX}")
            )
        except ValueError:
            continue  # out of valid IPv4 range - skip that neighbor
    return networks


def _networks_to_sweep(
    known_ips: set[str], max_addresses: int
) -> tuple[set[ipaddress.IPv4Network], set[ipaddress.IPv4Network]]:
    """Split the ASN prefixes to sweep into `confirmed` (directly contains a
    known IP, or is the /24 fallback for one - proven relevant) and `bonus`
    (another prefix from the same ASN, not yet confirmed to host anything of
    the target's). The cap below always sweeps `confirmed` in full and only
    applies to `bonus`, so a large-but-proven-relevant prefix (like a /19
    the target's IP actually lives in) never gets silently dropped in favor
    of smaller, unconfirmed ones just because it sorts worse by size.

    A confirmed prefix bigger than `max_addresses` is treated as a signal
    it's shared/third-party infrastructure (a CDN, cloud provider, or a big
    transit ASN) rather than something the target owns outright - sweeping
    it in full would defeat the whole point of the cap (observed for real:
    one IP's ASN prefix was 3.5 million addresses). In that case the known
    IP's own /24 and its immediate neighbors are swept instead of the
    oversized prefix."""
    confirmed: set[ipaddress.IPv4Network] = set()
    bonus: set[ipaddress.IPv4Network] = set()

    for ip in known_ips:
        try:
            ip_addr = ipaddress.IPv4Address(ip)
        except ValueError:
            continue  # IPv6 - the sweep only supports IPv4 for now

        asn = lookup_asn(ip)
        prefixes = lookup_asn_prefixes(asn) if asn is not None else []
        matched = False
        for prefix in prefixes:
            if ip_addr not in prefix:
                bonus.add(prefix)
                continue
            matched = True
            if prefix.num_addresses <= max_addresses:
                confirmed.add(prefix)
            else:
                logger.warning(
                    "netblock sweep: %s's ASN prefix %s is %d addresses - too large to be "
                    "a dedicated block, likely shared/third-party infrastructure - sweeping "
                    "just %s/%d and its neighbors instead",
                    ip,
                    prefix,
                    prefix.num_addresses,
                    ip,
                    NETBLOCK_SWEEP_FALLBACK_PREFIX,
                )
                confirmed.update(_fallback_24s(ip))

        if not matched:
            # ASN lookup failed, returned nothing, or (rare) returned no
            # prefix that actually contains this IP - fall back to this
            # IP's own /24 and its neighbors rather than skipping it
            # entirely.
            confirmed.update(_fallback_24s(ip))

    bonus -= confirmed
    return confirmed, bonus


def _cap_networks_to_sweep(
    confirmed: set[ipaddress.IPv4Network],
    bonus: set[ipaddress.IPv4Network],
    domain: str,
    max_addresses: int,
) -> list[ipaddress.IPv4Network]:
    swept = list(confirmed)
    running_total = sum(network.num_addresses for network in confirmed)

    if running_total > max_addresses:
        logger.warning(
            "netblock sweep for %s: the prefix(es) known to contain target IPs alone total "
            "%d addresses, already over the %d-address cap - sweeping them anyway since "
            "they're confirmed relevant; no budget left for other same-ASN prefixes",
            domain,
            running_total,
            max_addresses,
        )
        return swept

    remaining_budget = max_addresses - running_total
    skipped_any = False
    for network in sorted(bonus, key=lambda n: n.num_addresses):
        if network.num_addresses > remaining_budget:
            skipped_any = True
            continue
        swept.append(network)
        remaining_budget -= network.num_addresses

    if skipped_any:
        logger.warning(
            "netblock sweep for %s: %d-address cap reached - not every other prefix from "
            "the same ASN(s) was swept; raise with --netblock-sweep-max-addresses to cover more",
            domain,
            max_addresses,
        )
    return swept


def _run_netblock_sweep(
    db: Database,
    domain: str,
    domain_id: int,
    enabled: bool,
    max_addresses: int,
    resolvers: list[str],
    sweep_workers: int,
) -> None:
    if not enabled:
        return

    known_ips: set[str] = set()
    for hostname_row in db.list_hostnames_for_domain(domain_id):
        for ip_row in db.list_ips_for_hostname(hostname_row["id"]):
            known_ips.add(ip_row["address"])

    confirmed, bonus = _networks_to_sweep(known_ips, max_addresses)
    if not confirmed and not bonus:
        return

    swept_networks = _cap_networks_to_sweep(confirmed, bonus, domain, max_addresses)

    resolver_ips = list(resolvers)
    target_ns_ip = lookup_domain_nameserver_ip(domain)
    if target_ns_ip and target_ns_ip not in resolver_ips:
        resolver_ips.append(target_ns_ip)

    discovered = sweep_netblocks(swept_networks, domain, resolver_ips, workers=sweep_workers)
    logger.info(
        "netblock sweep of %d network(s) for %s (resolvers: %s): %d additional hostname(s) found",
        len(swept_networks),
        domain,
        ", ".join(resolver_ips),
        len(discovered),
    )
    for item in discovered:
        try:
            hostname_id = db.upsert_hostname(domain_id, item.name)
            ip_id = db.upsert_ip(item.data["ip"])
            db.upsert_resolution(hostname_id, ip_id)
            db.insert_result(item.source, "hostname", hostname_id, item.data)
        except Exception:
            logger.exception(
                "failed to persist netblock-swept hostname %s - continuing", item.name
            )


def _persist_code_exposures(db: Database, domain_id: int, result: EnrichmentResult) -> None:
    """Store a result's GitHub code exposures (references + secrets) against
    the domain (see db.upsert_code_exposure)."""
    for exposure in result.code_exposures:
        db.upsert_code_exposure(
            domain_id,
            kind=exposure.kind,
            target=exposure.target,
            repo=exposure.repo,
            path=exposure.path,
            commit=exposure.commit,
            url=exposure.url,
            line=exposure.line,
            snippet=exposure.snippet,
            rule=exposure.rule,
            secret=exposure.secret,
        )


def _run_enrichment(
    db: Database,
    sources: list[Source],
    domain_id: int,
    workers: int,
    governor: SourceGovernor,
    hostname_ids: set[int] | None = None,
    skip_ip_ids: set[int] | None = None,
) -> tuple[list[Related], set[int]]:
    """Enrich the domain's hostnames (or just `hostname_ids`) and the IPs
    they resolve to (minus `skip_ip_ids`, already enriched this run).
    Returns every result's related hostnames, and the IP ids enriched."""
    hostname_kind_sources = [s for s in sources if s.enrich_target_kind == "hostname"]
    ip_kind_sources = [s for s in sources if s.enrich_target_kind == "ip"]
    related: list[Related] = []
    seen_ip_ids: set[int] = set(skip_ip_ids or ())
    enriched_ip_ids: set[int] = set()
    if not hostname_kind_sources and not ip_kind_sources:
        return related, enriched_ip_ids

    hostname_rows = [
        row
        for row in db.list_hostnames_for_domain(domain_id)
        if hostname_ids is None or row["id"] in hostname_ids
    ]
    futures: dict = {}
    with ThreadPoolExecutor(max_workers=workers) as executor:
        for hostname_row in hostname_rows:
            for source in hostname_kind_sources:
                future = executor.submit(
                    governor.run,
                    source,
                    "hostname",
                    hostname_row["name"],
                    functools.partial(source.enrich, hostname_row["name"], [hostname_row["name"]]),
                )
                futures[future] = (source, "hostname", hostname_row["id"], hostname_row["name"])

        for hostname_row in hostname_rows:
            for ip_row in db.list_ips_for_hostname(hostname_row["id"]):
                if ip_row["id"] in seen_ip_ids:
                    continue
                seen_ip_ids.add(ip_row["id"])
                enriched_ip_ids.add(ip_row["id"])
                hostnames_for_ip = [h["name"] for h in db.list_hostnames_for_ip(ip_row["id"])]
                for source in ip_kind_sources:
                    future = executor.submit(
                        governor.run,
                        source,
                        "ip",
                        ip_row["address"],
                        functools.partial(source.enrich, ip_row["address"], hostnames_for_ip),
                    )
                    futures[future] = (source, "ip", ip_row["id"], ip_row["address"])

        # pop, not index: a failed future holds its exception, whose
        # requests.Response keeps its socket open. Holding every future until
        # the (long) stage ends leaked one socket per failed call - enough to
        # hit EMFILE on big domains, after which SQLite can't open its files.
        for future in as_completed(futures):
            source, target_type, target_id, target_label = futures.pop(future)
            try:
                result = future.result()
            except SourceUnavailableError as exc:
                logger.warning("%s skipped for %s: %s", source.name, target_label, exc)
                continue
            except ScrapeParseError as exc:
                logger.warning(
                    "%s: page for %s parsed to nothing - site markup may have changed: %s",
                    source.name,
                    target_label,
                    exc,
                )
                try:
                    db.insert_result(source.name, target_type, target_id, {"parse_warning": str(exc)})
                except Exception:
                    logger.exception("failed to persist %s parse warning - continuing", source.name)
                continue
            except Exception:
                logger.exception("%s enrichment failed for %s", source.name, target_label)
                continue
            if result is None:
                continue  # declined by the governor (fresh result / budget spent)
            if result.related_hostnames:
                related.append((source.name, target_label, result.related_hostnames))

            try:
                db.insert_result(result.source, target_type, target_id, result.data)
                _persist_code_exposures(db, domain_id, result)
                if target_type == "ip":
                    for service in result.services:
                        db.upsert_service(
                            target_id,
                            service.port,
                            service.protocol,
                            service.banner,
                            service.version,
                            service.cpe,
                        )
            except Exception:
                logger.exception(
                    "failed to persist %s result for %s - continuing", source.name, target_label
                )
    return related, enriched_ip_ids


def _absorb_related(
    db: Database,
    domain_id: int,
    domain: str,
    related: list[Related],
    targets: ScanTargets | None = None,
) -> set[int]:
    """Store what enrichment related to its targets: new in-scope hostnames
    (returned, for the next pass to resolve and enrich) and out-of-scope
    registrable domains as candidate domains - unless the target looks like
    shared hosting (see SHARED_HOSTING_THRESHOLD). TLD siblings of `domain`
    are in scope: they go to `targets` to be scanned, not to candidates."""
    new_ids: set[int] = set()
    for source_name, target_label, names in related:
        hostnames, candidates = split_related(domain, names)
        if targets is not None:
            # Checked before the shared-hosting cut: a sibling is in scope by
            # its name, whatever else the result related.
            siblings = [c for c in candidates if is_tld_sibling(c, domain)]
            candidates = [c for c in candidates if c not in siblings]
            for sibling in siblings:
                if targets.add(sibling):
                    logger.info(
                        "%s: %s is a TLD sibling of %s (via %s) - in scope, queued for scanning",
                        source_name, sibling, domain, target_label,
                    )
        for name in hostnames:
            try:
                if db.get_hostname_by_name(name) is not None:
                    continue
                hostname_id = db.upsert_hostname(domain_id, name)
                db.insert_result(source_name, "hostname", hostname_id, {"related_to": target_label})
                new_ids.add(hostname_id)
            except Exception:
                logger.exception("failed to persist related hostname %s - continuing", name)
        if len(candidates) > SHARED_HOSTING_THRESHOLD:
            logger.info(
                "%s relates %s to %d other domains - shared hosting, not recording candidates",
                source_name,
                target_label,
                len(candidates),
            )
            continue
        for candidate in candidates:
            try:
                db.upsert_candidate_domain(domain_id, candidate, source_name, target_label)
            except Exception:
                logger.exception("failed to persist candidate domain %s - continuing", candidate)
    if new_ids:
        logger.info("feedback for %s: %d new related hostname(s)", domain, len(new_ids))
    return new_ids


def _run_enrichment_with_feedback(
    db: Database,
    sources: list[Source],
    domain: str,
    domain_id: int,
    workers: int,
    governor: SourceGovernor,
    targets: ScanTargets | None = None,
) -> None:
    """Enrichment, then up to MAX_ENRICHMENT_PASSES - 1 follow-up passes over
    only the in-scope hostnames the previous pass surfaced (and their new
    IPs). Names surfaced by the last pass are stored but not chased."""
    related, enriched_ip_ids = _run_enrichment(db, sources, domain_id, workers, governor)
    for _ in range(MAX_ENRICHMENT_PASSES - 1):
        new_ids = _absorb_related(db, domain_id, domain, related, targets)
        if not new_ids:
            return
        _run_resolution(db, domain_id, workers, hostname_ids=new_ids)
        related, more_ip_ids = _run_enrichment(
            db, sources, domain_id, workers, governor, hostname_ids=new_ids,
            skip_ip_ids=enriched_ip_ids,
        )
        enriched_ip_ids |= more_ip_ids
    _absorb_related(db, domain_id, domain, related, targets)


def _run_tech_fingerprint(
    db: Database,
    domain_id: int,
    enabled: bool,
    fingerprinter: WebTechFingerprinter,
    workers: int,
) -> None:
    """Active stage: visit every open service other stages found and
    fingerprint the web technologies/versions running on it (see
    sources/webtech.py). Runs after enrichment (it depends on services
    already being persisted) but *before* the vuln lookup, so any web-server
    product/version it identifies is written onto the service row in time for
    the NVD CVE lookup to use it - the same product/version-in, CVEs-out path
    Shodan/Censys/portscan feed.

    Fetches are network-bound and each hits a different target host, so they
    run in a thread pool. The fingerprinter is stateless/read-only and the
    Database is internally locked, so sharing both across the pool is safe."""
    if not enabled:
        return

    # (ip_id, address, hostnames, service_row) work items, deduped by IP the
    # same way enrichment/vuln lookup are - one IP is scanned once even when
    # many hostnames resolve to it.
    jobs: list[tuple[int, str, list[str], dict]] = []
    seen_ip_ids: set[int] = set()
    for hostname_row in db.list_hostnames_for_domain(domain_id):
        for ip_row in db.list_ips_for_hostname(hostname_row["id"]):
            if ip_row["id"] in seen_ip_ids:
                continue
            seen_ip_ids.add(ip_row["id"])
            hostnames = [h["name"] for h in db.list_hostnames_for_ip(ip_row["id"])]
            for service in db.list_services_for_ip(ip_row["id"]):
                jobs.append((ip_row["id"], ip_row["address"], hostnames, dict(service)))

    if not jobs:
        return

    def _scan(job: tuple[int, str, list[str], dict]) -> tuple[int, dict, dict | None]:
        ip_id, address, hostnames, service = job
        result = fingerprinter.scan_service(
            address, service["port"], service["protocol"], hostnames
        )
        return ip_id, service, result

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_scan, job): job for job in jobs}
        for future in as_completed(futures):
            ip_id, service, result = future.result()  # _scan never raises
            if result is None:
                continue
            try:
                db.insert_result(
                    "webtech",
                    "ip",
                    ip_id,
                    {"port": service["port"], **result},
                )
                # Write the fingerprinted web-server product/version back onto
                # the service. upsert_service COALESCEs, so this only fills
                # gaps (a version Shodan didn't have) - it never overwrites a
                # product another source already attributed.
                if result["server_product"]:
                    db.upsert_service(
                        ip_id,
                        service["port"],
                        service["protocol"],
                        result["server_product"],
                        result["server_version"],
                    )
            except Exception:
                logger.exception(
                    "failed to persist webtech result for %s port %s - continuing",
                    ip_id,
                    service["port"],
                )


def _webtech_cpe_checks(db: Database, ip_id: int) -> list[tuple[int, str, str | None, list[str]]]:
    """(port, technology, version, candidate CPEs) for every versioned
    technology the fingerprint stage identified on this IP - read back from
    its persisted `webtech` results."""
    checks = []
    for row in db.list_results_for_target("ip", ip_id):
        if row["source"] != "webtech":
            continue
        data = json.loads(row["data"])
        technologies = data.get("technologies", {})
        for technology, cpes in data.get("cpes", {}).items():
            checks.append((data["port"], technology, technologies.get(technology), cpes))
    return checks


def _run_vulnerability_lookup(
    db: Database,
    domain_id: int,
    enabled: bool,
    client: NvdClient,
    exploit_client: SearchSploitClient,
) -> None:
    """Given whatever product/version/CPE the enrichment sources (Shodan,
    Censys, the port scanner) already found, look up matching CVEs via NVD.
    Runs after enrichment since it depends on service data already being
    persisted - the same reasoning as the netblock sweep's ASN lookup for
    depending on already-resolved IPs.

    Also checks every versioned technology the fingerprint stage identified
    (web server, language, framework, CMS, JS library - not just the one
    product on the service row), each via its known NVD vendor:product
    mapping rather than a vendor==product guess. A product already covered by
    a fingerprint mapping skips the guessed-CPE path for its service, and no
    CPE is looked up twice for the same IP+port, so the two paths never
    produce duplicate results.

    A CVE is only looked up (and persisted) when the service's CPE carries a
    concrete version: a versionless/wildcard CPE matched against NVD returns
    every CVE ever filed for the product regardless of the running version, so
    those are skipped rather than flagged.

    `client` is one shared NvdClient reused across every concurrently-
    running domain (not one per domain) - NvdClient is internally
    lock-protected for exactly this, since NVD's rate limit is enforced
    against this machine's IP regardless of how many client objects exist
    in our process."""
    if not enabled:
        return

    cve_cache: dict[str, list[dict]] = {}

    def lookup(cpe: str) -> list[dict]:
        if cpe not in cve_cache:
            try:
                cves = client.lookup_cves(cpe)
            except Exception:
                logger.exception("nvd lookup failed for %s - continuing", cpe)
                cves = []
            # Annotate each CVE with any public exploit from the local
            # Exploit-DB (no-op when searchsploit isn't installed). Cached
            # with the CVEs, so a CVE seen on several services is looked up
            # once. Failure here must never lose the CVE itself.
            for cve in cves:
                cve_id = cve.get("cve_id")
                if not cve_id:
                    continue
                try:
                    exploits = exploit_client.lookup_cve(cve_id)
                except Exception:
                    logger.exception("searchsploit lookup failed for %s - continuing", cve_id)
                    continue
                if exploits:  # keep CVE dicts clean when there's nothing to add
                    cve["exploits"] = exploits
            cve_cache[cpe] = cves
        return cve_cache[cpe]

    def persist(ip_id: int, port: int, data: dict) -> None:
        try:
            db.insert_result("nvd", "ip", ip_id, {"port": port, **data})
        except Exception:
            logger.exception(
                "failed to persist nvd result for %s port %s - continuing", data.get("cpe"), port
            )

    seen_ip_ids: set[int] = set()
    for hostname_row in db.list_hostnames_for_domain(domain_id):
        for ip_row in db.list_ips_for_hostname(hostname_row["id"]):
            if ip_row["id"] in seen_ip_ids:
                continue
            seen_ip_ids.add(ip_row["id"])

            webtech_checks = _webtech_cpe_checks(db, ip_row["id"])
            fingerprinted = {
                (port, technology.lower(), version)
                for port, technology, version, _ in webtech_checks
            }
            looked_up: set[tuple[int, str]] = set()

            for service in db.list_services_for_ip(ip_row["id"]):
                cpe = service["cpe"]
                guessed = False
                if not cpe and service["banner"] and service["version"]:
                    key = (service["port"], service["banner"].lower(), service["version"])
                    if key in fingerprinted:
                        continue  # checked below via its accurate CPE mapping
                    cpe = build_cpe(service["banner"], service["version"])
                    guessed = True
                if not cpe or cpe_version(cpe) is None:
                    # Without a concrete version an NVD cpeName match returns
                    # every CVE ever filed for the product (e.g. a 15-year-old
                    # Drupal CVE on a host whose version we never determined).
                    continue

                looked_up.add((service["port"], cpe))
                cves = lookup(cpe)
                if cves:
                    persist(
                        ip_row["id"],
                        service["port"],
                        {"cpe": cpe, "cpe_guessed": guessed, "cves": cves},
                    )

            for port, technology, version, cpes in webtech_checks:
                cves_by_id: dict[str, dict] = {}
                matched_cpes = []
                for cpe in cpes:
                    if (port, cpe) in looked_up or cpe_version(cpe) is None:
                        continue
                    looked_up.add((port, cpe))
                    found = lookup(cpe)
                    if found:
                        matched_cpes.append(cpe)
                    for cve in found:
                        cves_by_id.setdefault(cve["cve_id"], cve)
                if not cves_by_id:
                    continue
                persist(
                    ip_row["id"],
                    port,
                    {
                        "cpe": matched_cpes[0] if len(matched_cpes) == 1 else matched_cpes,
                        "cpe_guessed": False,
                        "technology": technology,
                        "version": version,
                        "cves": list(cves_by_id.values()),
                    },
                )


def _nuclei_targets_for_ip(db: Database, ip_id: int) -> list[str]:
    """Web-service URLs to point Nuclei at for one IP: the exact URLs the
    fingerprint stage confirmed (redirect-resolved), read back from its
    persisted `webtech` results. Empty when nothing web-serving was found -
    Nuclei then has nothing to scan for this IP."""
    urls = []
    for row in db.list_results_for_target("ip", ip_id):
        if row["source"] != "webtech":
            continue
        url = json.loads(row["data"]).get("url")
        if url and url not in urls:
            urls.append(url)
    return urls


def _run_nuclei(
    db: Database, domain_id: int, enabled: bool, scanner: NucleiScanner
) -> None:
    """Active template scan (opt-in). For every IP, run Nuclei against the web
    services the fingerprint stage confirmed and persist each finding as a
    `nuclei` result on that IP. No-op when disabled, when the binary is
    absent, or when nothing web-serving was found (so it depends on the
    fingerprint stage having run). Failure for one IP never aborts the rest."""
    if not enabled or not scanner.available:
        return
    seen_ip_ids: set[int] = set()
    for hostname_row in db.list_hostnames_for_domain(domain_id):
        for ip_row in db.list_ips_for_hostname(hostname_row["id"]):
            if ip_row["id"] in seen_ip_ids:
                continue
            seen_ip_ids.add(ip_row["id"])
            targets = _nuclei_targets_for_ip(db, ip_row["id"])
            if not targets:
                continue
            try:
                findings = scanner.scan(targets)
            except Exception:
                logger.exception("nuclei scan failed for %s - continuing", ip_row["address"])
                continue
            for finding in findings:
                try:
                    db.insert_result("nuclei", "ip", ip_row["id"], finding)
                except Exception:
                    logger.exception(
                        "failed to persist nuclei finding %s for %s - continuing",
                        finding.get("template_id"), ip_row["address"],
                    )
            if findings:
                logger.info(
                    "nuclei: %d finding(s) on %s", len(findings), ip_row["address"]
                )


def _web_targets_for_ip(db: Database, address: str, ip_id: int) -> list[str]:
    """Web-service URLs to point Nikto/WPScan at for one IP. Unlike Nuclei
    (which scans only the fingerprint-*confirmed* URLs), these scan every
    resolved TCP service the enrichment stages found, regardless of whether the
    fingerprint stage identified a web app there - one `scheme://host:port/` per
    open service, scheme guessed from the port. Prefers a hostname (so
    name-based virtual hosts serve the right site), falling back to the IP."""
    hostnames = [row["name"] for row in db.list_hostnames_for_ip(ip_id)]
    host = hostnames[0] if hostnames else address
    urls: list[str] = []
    for service in db.list_services_for_ip(ip_id):
        if service["protocol"] != "tcp":
            continue
        port = service["port"]
        scheme = "https" if port in TLS_PORTS else "http"
        url = f"{scheme}://{host}:{port}/"
        if url not in urls:
            urls.append(url)
    return urls


def _run_web_app_scan(
    db: Database,
    domain_id: int,
    nikto_enabled: bool,
    wpscan_enabled: bool,
    nikto: NiktoScanner,
    wpscan: WpscanScanner,
) -> None:
    """Active web-application scan (opt-in). For every IP, run each enabled
    scanner (Nikto, WPScan) against its resolved web services and persist each
    finding as a `nikto` / `wpscan` result on that IP. No-op when both are
    disabled or their binaries are absent, or when nothing web-serving was
    found. Failure for one IP/tool never aborts the rest."""
    runs = [
        (name, scanner)
        for name, enabled, scanner in (
            ("nikto", nikto_enabled, nikto),
            ("wpscan", wpscan_enabled, wpscan),
        )
        if enabled and scanner.available
    ]
    if not runs:
        return
    seen_ip_ids: set[int] = set()
    for hostname_row in db.list_hostnames_for_domain(domain_id):
        for ip_row in db.list_ips_for_hostname(hostname_row["id"]):
            if ip_row["id"] in seen_ip_ids:
                continue
            seen_ip_ids.add(ip_row["id"])
            targets = _web_targets_for_ip(db, ip_row["address"], ip_row["id"])
            if not targets:
                continue
            for name, scanner in runs:
                try:
                    findings = scanner.scan(targets)
                except Exception:
                    logger.exception("%s scan failed for %s - continuing", name, ip_row["address"])
                    continue
                for finding in findings:
                    try:
                        db.insert_result(name, "ip", ip_row["id"], finding)
                    except Exception:
                        logger.exception(
                            "failed to persist %s finding for %s - continuing",
                            name, ip_row["address"],
                        )
                if findings:
                    logger.info(
                        "%s: %d finding(s) on %s", name, len(findings), ip_row["address"]
                    )


def _run_takeover(
    db: Database, domain_id: int, enabled: bool, scanner: TakeoverScanner
) -> None:
    """Active subdomain-takeover scan (opt-in). Run `takeover` over every
    discovered hostname for the domain in one pass and persist each claimable
    host as a `takeover` result on that hostname. No-op when disabled or the
    binary is absent. A finding whose host doesn't map back to a known hostname
    is attached to the domain instead, so nothing is dropped."""
    if not enabled or not scanner.available:
        return
    hostname_ids = {row["name"]: row["id"] for row in db.list_hostnames_for_domain(domain_id)}
    if not hostname_ids:
        return
    try:
        findings = scanner.scan(list(hostname_ids))
    except Exception:
        logger.exception("takeover scan failed for domain %s - continuing", domain_id)
        return
    for finding in findings:
        host = finding.get("resource") or ""
        target_type, target_id = ("hostname", hostname_ids.get(host)) if host in hostname_ids else (
            "domain", domain_id
        )
        try:
            db.insert_result("takeover", target_type, target_id, finding)
        except Exception:
            logger.exception("failed to persist takeover finding for %s - continuing", host)
    if findings:
        logger.info("takeover: %d potential takeover(s) for domain %s", len(findings), domain_id)


def _repo_urls_to_scan(
    db: Database, domain_id: int, extra_repos: list[str], max_repos: int
) -> list[str]:
    """Git URLs for the artifact scan: the public GitHub repos the code-
    exposure stage already found naming this domain, plus any explicitly
    configured, deduped and capped."""
    urls: list[str] = []
    seen: set[str] = set()
    for row in db.list_code_exposures(domain_id):
        repo = row["repo"]
        if not repo:
            continue
        url = f"https://github.com/{repo}.git"
        if url not in seen:
            seen.add(url)
            urls.append(url)
    for url in extra_repos:
        if url and url not in seen:
            seen.add(url)
            urls.append(url)
    return urls[:max_repos]


def _image_refs_to_scan(
    db: Database, domain_id: int, domain: str, cfg: CloudScanConfig
) -> list[str]:
    """Container image references for the artifact scan: images an exposed
    registry listed (via the container_exposure source), any explicitly
    configured, and names guessed from the domain label under configured
    orgs. Deduped and capped."""
    refs: list[str] = []
    seen: set[str] = set()

    def add(ref: str) -> None:
        if ref and ref not in seen:
            seen.add(ref)
            refs.append(ref)

    for hostname_row in db.list_hostnames_for_domain(domain_id):
        for ip_row in db.list_ips_for_hostname(hostname_row["id"]):
            for result_row in db.list_results_for_target("ip", ip_row["id"]):
                if result_row["source"] != "container_exposure":
                    continue
                for ref in json.loads(result_row["data"]).get("images") or []:
                    add(ref)
    for ref in cfg.images:
        add(ref)
    label = domain.split(".")[0]
    for org in cfg.guess_image_orgs:
        add(f"{org}/{label}")
        add(f"ghcr.io/{org}/{label}")
    return refs[: cfg.max_images]


def _persist_cloud_findings(
    db: Database, domain_id: int, source: str, target: str, target_kind: str, findings: list[dict]
) -> None:
    if not findings:
        return
    try:
        db.insert_result(
            source,
            "domain",
            domain_id,
            {
                "target": target,
                "target_kind": target_kind,
                "findings": findings,
                "counts": count_by_severity(findings),
            },
        )
    except Exception:
        logger.exception("failed to persist %s findings for %s - continuing", source, target)


def _run_artifact_scan(
    db: Database,
    domain: str,
    domain_id: int,
    enabled: bool,
    trivy: TrivyScanner,
    checkov: CheckovScanner,
    cfg: CloudScanConfig,
) -> None:
    """Credential-free artifact scanning (opt-in via --cloud-scan): clone the
    public repos this domain's code-exposure stage found and run Checkov (IaC
    misconfig) + `trivy fs` (vulnerable deps/secrets/misconfig) on each, and
    run `trivy image` on container images an exposed registry listed or that
    config supplies. No-op when both binaries are absent or nothing to scan.
    Findings persist as `checkov`/`trivy` results on the domain."""
    if not enabled or (not trivy.available and not checkov.available):
        return

    if trivy.available:
        for ref in _image_refs_to_scan(db, domain_id, domain, cfg):
            try:
                findings = trivy.scan_image(ref)
            except Exception:
                logger.exception("trivy image scan failed for %s - continuing", ref)
                continue
            _persist_cloud_findings(db, domain_id, "trivy", ref, "image", findings)
            if findings:
                logger.info("trivy: %d finding(s) in image %s", len(findings), ref)

    repo_urls = _repo_urls_to_scan(db, domain_id, cfg.repos, cfg.max_repos)
    if not repo_urls or not (trivy.available or checkov.available):
        return
    with tempfile.TemporaryDirectory(prefix="posint-repos-") as tmp:
        for index, url in enumerate(repo_urls):
            dest = os.path.join(tmp, f"repo{index}")
            if not clone_repo(url, dest, timeout=cfg.clone_timeout_seconds):
                continue
            if checkov.available:
                try:
                    findings = checkov.scan_dir(dest)
                except Exception:
                    logger.exception("checkov scan failed for %s - continuing", url)
                    findings = []
                _persist_cloud_findings(db, domain_id, "checkov", url, "repo", findings)
                if findings:
                    logger.info("checkov: %d finding(s) in %s", len(findings), url)
            if trivy.available:
                try:
                    findings = trivy.scan_fs(dest)
                except Exception:
                    logger.exception("trivy fs scan failed for %s - continuing", url)
                    findings = []
                _persist_cloud_findings(db, domain_id, "trivy", url, "repo", findings)
                if findings:
                    logger.info("trivy fs: %d finding(s) in %s", len(findings), url)


def _run_cloud_audit(
    db: Database,
    domain: str,
    domain_id: int,
    enabled: bool,
    prowler: ProwlerScanner,
    scoutsuite: ScoutSuiteScanner,
    providers: list[str],
) -> None:
    """Authenticated cloud-account auditing (opt-in via --cloud-audit): run
    Prowler and ScoutSuite against each configured provider, using credentials
    from the ambient environment (the vendor CLIs read them; we never handle
    secrets). Only for accounts you're authorized to audit. Findings persist as
    `prowler`/`scoutsuite` results on the domain. No-op when both binaries are
    absent."""
    if not enabled or (not prowler.available and not scoutsuite.available):
        return
    for provider in providers:
        for scanner, source in ((prowler, "prowler"), (scoutsuite, "scoutsuite")):
            if not scanner.available:
                continue
            try:
                findings = scanner.scan(provider)
            except Exception:
                logger.exception("%s audit of %s failed - continuing", source, provider)
                continue
            _persist_cloud_findings(db, domain_id, source, provider, "cloud-account", findings)
            logger.info("%s: %d finding(s) for %s", source, len(findings), provider)


def _revalidate(db: Database, domain_id: int, domain: str, run_started_at: str) -> None:
    """Continuation pruning for a resumed scan of an already-scanned domain.

    Runs after this run's resolution has refreshed last_seen on every still-
    valid hostname->IP mapping, so it can tell live data from stale by
    timestamp alone - no re-resolving. It deletes:

      1. stale DNS mappings - edges not re-observed this run, but only for
         hostnames that did resolve this run (delete_stale_resolutions guards
         against a transient resolver failure wiping valid edges); and
      2. orphaned IPs - any IP no longer pointed to by any hostname, together
         with its now-dangling services and results.

    Hostnames are deliberately kept even when they resolve to nothing now: a
    hostname's absence from a discovery source this run (a CLI tool that
    wasn't installed, an API that was down) isn't proof it's gone, so dropping
    hostnames would risk erasing valid history. Only concretely-invalid things
    (a mapping DNS retracted, an IP nothing points to) are removed."""
    stale_edges = db.delete_stale_resolutions(domain_id, run_started_at)
    orphan_ips = db.delete_orphan_ips()
    logger.info(
        "revalidation for %s: pruned %d stale DNS mapping(s) and %d orphaned IP(s)",
        domain,
        stale_edges,
        orphan_ips,
    )


# At most one stage-boundary cycle collection per this many seconds, process
# wide: a full collection is cheap once, not once per stage per domain.
RELEASE_CYCLES_INTERVAL_SECONDS = 30
_release_lock = threading.Lock()
_last_release = time.monotonic()


def _release_cycles(force: bool = False) -> None:
    """Collect reference cycles now rather than whenever the collector gets
    round to it. A failed HTTP call's exception often ends up in a cycle with
    its traceback (tenacity's retry state is one source), keeping its
    requests.Response - and, since urllib3 2.8 only closes a pool's sockets
    when the pool is garbage-collected, its open socket - alive. In a
    long-running web UI process those piled up across scans until EMFILE."""
    global _last_release
    with _release_lock:
        now = time.monotonic()
        if not force and now - _last_release < RELEASE_CYCLES_INTERVAL_SECONDS:
            return
        _last_release = now
    gc.collect()


def _end_stage(control: ScanControl) -> None:
    _release_cycles()
    control.check()


def _run_domain_pipeline(
    db: Database,
    domain: str,
    disco_sources: list[Source],
    enrich_sources: list[Source],
    collect_sources: list[Source],
    workers: int,
    netblock_sweep: bool,
    netblock_sweep_max_addresses: int,
    netblock_sweep_resolvers: list[str],
    netblock_sweep_workers: int,
    tech_fingerprint: bool,
    fingerprinter: WebTechFingerprinter,
    vuln_lookup: bool,
    nvd_client: NvdClient,
    exploit_client: SearchSploitClient,
    nuclei_scan: bool,
    nuclei_scanner: NucleiScanner,
    nikto_scan: bool,
    wpscan_scan: bool,
    takeover_scan: bool,
    nikto_scanner: NiktoScanner,
    wpscan_scanner: WpscanScanner,
    takeover_scanner: TakeoverScanner,
    cloud_scan: bool,
    cloud_audit: bool,
    trivy: TrivyScanner,
    checkov: CheckovScanner,
    prowler: ProwlerScanner,
    scoutsuite: ScoutSuiteScanner,
    cloudscan_config: CloudScanConfig,
    governor: SourceGovernor,
    control: ScanControl,
    targets: ScanTargets | None = None,
) -> None:
    """One domain's full pipeline. Wrapped in a try/except so an unexpected
    failure in any stage costs only this domain, not the rest of a
    multi-domain batch - domains run as independent tasks (see run_scan),
    so this is the same "one failure never aborts the whole scan" principle
    already applied to individual sources and DB writes, just at the scope
    that actually matches how domains are now scheduled."""
    try:
        logger.info("scanning %s", domain)
        control.progress("starting", domain)
        # Captured before any resolution writes so that, when continuing a
        # prior scan, every mapping this run re-observes sorts after it and
        # only genuinely stale mappings fall before it.
        run_started_at = datetime.now(timezone.utc).isoformat()
        # Continuation is automatic: if this domain is already in the DB, this
        # is a re-scan, so revalidate and prune afterwards. A domain never seen
        # before has nothing to prune. Checked before discovery upserts it.
        resume = db.get_domain_by_name(domain) is not None
        if resume:
            logger.info("%s already scanned - will revalidate and prune stale results", domain)
        control.progress("discovery", domain)
        domain_id = _run_discovery_for_domain(db, disco_sources, domain, workers, governor)
        _end_stage(control)
        control.progress("collection", domain)
        _run_collection(db, collect_sources, domain, domain_id, workers, governor, targets)
        _end_stage(control)
        control.progress("resolution", domain)
        _run_resolution(db, domain_id, workers)
        _end_stage(control)
        control.progress("netblock sweep", domain)
        _run_netblock_sweep(
            db,
            domain,
            domain_id,
            netblock_sweep,
            netblock_sweep_max_addresses,
            netblock_sweep_resolvers,
            netblock_sweep_workers,
        )
        _run_resolution(db, domain_id, workers)  # forward-resolve any netblock-swept hostnames too
        # Prune before enrichment so stages don't waste work on IPs that DNS
        # no longer points to (and that revalidation is about to remove).
        if resume:
            _revalidate(db, domain_id, domain, run_started_at)
        _end_stage(control)
        control.progress("enrichment", domain)
        _run_enrichment_with_feedback(
            db, enrich_sources, domain, domain_id, workers, governor, targets
        )
        _end_stage(control)
        control.progress("fingerprint", domain)
        _run_tech_fingerprint(db, domain_id, tech_fingerprint, fingerprinter, workers)
        _end_stage(control)
        control.progress("vulnerability lookup", domain)
        _run_vulnerability_lookup(db, domain_id, vuln_lookup, nvd_client, exploit_client)
        _end_stage(control)
        control.progress("nuclei", domain)
        _run_nuclei(db, domain_id, nuclei_scan, nuclei_scanner)
        _end_stage(control)
        control.progress("web app scan", domain)
        _run_web_app_scan(
            db, domain_id, nikto_scan, wpscan_scan, nikto_scanner, wpscan_scanner
        )
        _end_stage(control)
        control.progress("subdomain takeover", domain)
        _run_takeover(db, domain_id, takeover_scan, takeover_scanner)
        _end_stage(control)
        control.progress("cloud scan", domain)
        _run_artifact_scan(db, domain, domain_id, cloud_scan, trivy, checkov, cloudscan_config)
        _end_stage(control)
        control.progress("cloud audit", domain)
        _run_cloud_audit(
            db, domain, domain_id, cloud_audit, prowler, scoutsuite, cloudscan_config.providers
        )
        control.progress("done", domain)
    except ScanCancelled:
        logger.info("scan of %s cancelled", domain)
        raise
    except Exception:
        logger.exception("scan of %s failed - continuing with other domains", domain)


def run_scan(
    db: Database,
    domains: list[str],
    sources: list[Source],
    source_filter: list[str] | None = None,
    netblock_sweep: bool = True,
    netblock_sweep_max_addresses: int = DEFAULT_NETBLOCK_SWEEP_MAX_ADDRESSES,
    netblock_sweep_resolvers: list[str] | None = None,
    netblock_sweep_workers: int = DEFAULT_NETBLOCK_SWEEP_WORKERS,
    tech_fingerprint: bool = True,
    vuln_lookup: bool = True,
    nuclei_scan: bool = False,
    nuclei_templates_dir: str | None = None,
    nikto_scan: bool = False,
    wpscan_scan: bool = False,
    takeover_scan: bool = False,
    webscan_config: WebScanConfig | None = None,
    cloud_scan: bool = False,
    cloud_audit: bool = False,
    cloudscan_config: CloudScanConfig | None = None,
    nvd_api_key: str | None = None,
    workers: int = DEFAULT_WORKERS,
    max_concurrent_domains: int = DEFAULT_MAX_CONCURRENT_DOMAINS,
    fresh: bool = False,
    control: ScanControl | None = None,
) -> None:
    """`fresh` ignores every source's TTL and re-queries targets it answered
    for recently (budgets still apply) - see governor.py."""
    # Global proxy from the Settings page; raises before anything is sent if
    # a configured proxy is unreachable.
    apply_settings(db)
    active_sources = []
    for source in filter_by_name(sources, source_filter):
        if source.is_configured:
            active_sources.append(source)
        else:
            logger.warning("%s skipped: not configured (no API key)", source.name)
    disco_sources = discovery_sources(active_sources)
    enrich_sources = enrichment_sources(active_sources)
    collect_sources = collection_sources(active_sources)
    resolvers = netblock_sweep_resolvers if netblock_sweep_resolvers is not None else list(
        DEFAULT_SWEEP_RESOLVERS
    )

    # One shared, lock-protected NvdClient for every domain in this batch -
    # not one per domain - since NVD's rate limit is external and global to
    # this machine regardless of how many client objects exist here.
    nvd_client = NvdClient(api_key=nvd_api_key)
    # Local Exploit-DB (searchsploit); a no-op when the binary isn't present.
    exploit_client = SearchSploitClient()
    # Nuclei active scanner; a no-op when disabled or the binary isn't present.
    nuclei_scanner = NucleiScanner(templates_dir=nuclei_templates_dir)
    # Web-app / subdomain-takeover scanners; each a no-op when its stage is
    # disabled or its binary isn't present. Built once and shared across the
    # batch, like the cloud scanners below.
    webscan_config = webscan_config or WebScanConfig()
    nikto_scanner = NiktoScanner(extra_args=webscan_config.nikto_extra_args)
    wpscan_scanner = WpscanScanner(
        api_token=webscan_config.wpscan_api_token, extra_args=webscan_config.wpscan_extra_args
    )
    takeover_scanner = TakeoverScanner(extra_args=webscan_config.takeover_extra_args)
    # Cloud/container/IaC scanners; each a no-op when its stage is disabled or
    # its binary isn't present. Built once and shared across the batch.
    cloudscan_config = cloudscan_config or CloudScanConfig()
    trivy = TrivyScanner(extra_args=cloudscan_config.trivy_extra_args)
    checkov = CheckovScanner(extra_args=cloudscan_config.checkov_extra_args)
    prowler = ProwlerScanner(extra_args=cloudscan_config.prowler_extra_args)
    scoutsuite = ScoutSuiteScanner(extra_args=cloudscan_config.scoutsuite_extra_args)
    # One shared, stateless fingerprinter for the whole batch (see its class
    # docstring) - built unconditionally; the stage no-ops when disabled.
    fingerprinter = WebTechFingerprinter()
    governor = SourceGovernor(db, fresh=fresh)
    control = control or ScanControl()

    normalized_domains = normalize_input_domains(domains)
    targets = ScanTargets(normalized_domains)
    with ThreadPoolExecutor(max_workers=max_concurrent_domains) as executor:

        def submit(domain: str):
            return executor.submit(
                _run_domain_pipeline,
                db,
                domain,
                disco_sources,
                enrich_sources,
                collect_sources,
                workers,
                netblock_sweep,
                netblock_sweep_max_addresses,
                resolvers,
                netblock_sweep_workers,
                tech_fingerprint,
                fingerprinter,
                vuln_lookup,
                nvd_client,
                exploit_client,
                nuclei_scan,
                nuclei_scanner,
                nikto_scan,
                wpscan_scan,
                takeover_scan,
                nikto_scanner,
                wpscan_scanner,
                takeover_scanner,
                cloud_scan,
                cloud_audit,
                trivy,
                checkov,
                prowler,
                scoutsuite,
                cloudscan_config,
                governor,
                control,
                targets,
            )

        pending = {submit(domain) for domain in normalized_domains}
        while pending:
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                try:
                    future.result()  # _run_domain_pipeline catches its own errors
                except ScanCancelled:
                    pass  # shared control: the other domains stop themselves too
            # TLD siblings the finished (or still-running) pipelines found.
            if not control.cancelled():
                pending |= {submit(domain) for domain in targets.take_queued()}
    _release_cycles(force=True)
