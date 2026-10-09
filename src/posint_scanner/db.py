"""SQLite persistence layer.

Schema (documented in detail in SCHEMA.md):

    domains        - apex domains fed into a scan
    hostnames      - discovered DNS names, tracking a parent hostname to
                      express DNS-hierarchy relationships (e.g. v2.api is a
                      child of api)
    ip_addresses   - unique IPs, independent of any one hostname since a
                      single IP can answer for many hostnames
    resolutions    - many-to-many join between hostnames and ip_addresses
    services       - open services observed on an IP
    results        - generic bucket for whatever a source returns about a
                      target (ip or hostname), keyed by source name so new
                      sources never require a schema migration
    source_calls   - one row per source call, for TTL skipping and quota
                      budgets (see governor.py)
    candidate_domains - out-of-scope registrable domains a scan's sources
                      related to its targets, for review (never auto-scanned)
    cloud_assets   - cloud storage buckets (S3/GCS/Azure) a scan found for a
                      domain, with their public/private exposure
    settings       - key/value app settings edited in the web UI (see
                      settings.py)
"""

from __future__ import annotations

import functools
import json
import sqlite3
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypeVar

F = TypeVar("F", bound=Callable[..., Any])


def _locked(method: F) -> F:
    """Serialize every call through the instance's lock. Applied to every
    Database method that touches self.conn (reads included) - sqlite3
    connections aren't safe for concurrent use from multiple threads, and
    this is what makes it safe to share one Database across the
    thread-pooled, cross-domain-parallel scan pipeline.

    Uses an RLock (not a plain Lock) because some locked methods call other
    locked methods internally (upsert_domain calls get_domain_by_name,
    etc.) - a plain Lock would deadlock a thread against itself there."""

    @functools.wraps(method)
    def wrapper(self: Database, *args: Any, **kwargs: Any) -> Any:
        with self._lock:
            return method(self, *args, **kwargs)

    return wrapper  # type: ignore[return-value]

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    added_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hostnames (
    id INTEGER PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id),
    name TEXT NOT NULL UNIQUE,
    parent_hostname_id INTEGER REFERENCES hostnames(id),
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hostnames_domain ON hostnames(domain_id);
CREATE INDEX IF NOT EXISTS idx_hostnames_parent ON hostnames(parent_hostname_id);

CREATE TABLE IF NOT EXISTS ip_addresses (
    id INTEGER PRIMARY KEY,
    address TEXT NOT NULL UNIQUE,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS resolutions (
    hostname_id INTEGER NOT NULL REFERENCES hostnames(id),
    ip_id INTEGER NOT NULL REFERENCES ip_addresses(id),
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (hostname_id, ip_id)
);
CREATE INDEX IF NOT EXISTS idx_resolutions_ip ON resolutions(ip_id);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY,
    ip_id INTEGER NOT NULL REFERENCES ip_addresses(id),
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    banner TEXT,
    version TEXT,
    cpe TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE (ip_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY,
    source TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id INTEGER NOT NULL,
    data TEXT NOT NULL,
    fetched_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_results_target ON results(target_type, target_id);

CREATE TABLE IF NOT EXISTS source_calls (
    id INTEGER PRIMARY KEY,
    source TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target TEXT NOT NULL,
    called_at TEXT NOT NULL,
    ok INTEGER
);
CREATE INDEX IF NOT EXISTS idx_source_calls_source ON source_calls(source, called_at);
CREATE INDEX IF NOT EXISTS idx_source_calls_target ON source_calls(source, target_type, target);

CREATE TABLE IF NOT EXISTS candidate_domains (
    id INTEGER PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id),
    name TEXT NOT NULL,
    source TEXT NOT NULL,
    via TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE (domain_id, name)
);

CREATE TABLE IF NOT EXISTS cloud_assets (
    id INTEGER PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id),
    provider TEXT NOT NULL,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    exposure TEXT NOT NULL,
    source TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE (domain_id, provider, name)
);
CREATE INDEX IF NOT EXISTS idx_cloud_assets_domain ON cloud_assets(domain_id);

CREATE TABLE IF NOT EXISTS email_addresses (
    id INTEGER PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id),
    address TEXT NOT NULL,
    source TEXT NOT NULL,
    name TEXT,
    position TEXT,
    confidence INTEGER,
    url TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE (domain_id, address, source)
);
CREATE INDEX IF NOT EXISTS idx_email_addresses_domain ON email_addresses(domain_id);

CREATE TABLE IF NOT EXISTS code_exposures (
    id INTEGER PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id),
    kind TEXT NOT NULL,            -- 'reference' | 'secret'
    target TEXT NOT NULL,          -- hostname/IP named (secret: the one searched)
    repo TEXT NOT NULL,            -- owner/name
    path TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    url TEXT NOT NULL,
    line INTEGER,
    snippet TEXT,
    rule TEXT,                     -- secrets: which rule matched
    secret TEXT,                   -- secrets: the full value
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_code_exposures_domain ON code_exposures(domain_id);
-- One row per (file, target, kind, rule, secret): the commit_sha and line
-- change as the file is edited, so they're not part of identity. rule/secret
-- are NULL for references, and SQLite treats NULLs as distinct in a plain
-- UNIQUE, so COALESCE them to '' in the index (and in the matching ON CONFLICT
-- target) - otherwise reference rows would never conflict and would duplicate
-- on every re-scan.
CREATE UNIQUE INDEX IF NOT EXISTS idx_code_exposures_identity ON code_exposures(
    domain_id, repo, path, target, kind, COALESCE(rule, ''), COALESCE(secret, '')
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    """Thin wrapper around sqlite3 with upsert semantics for the scan data model."""

    # How long a statement waits for a competing lock before raising
    # "database is locked". Needed because more than one connection can hit
    # the same file at once: the web UI keeps a read connection open while a
    # scan writes through its own connection on a background thread. Without a
    # busy timeout that reader raises OperationalError (a 500 in the UI) the
    # instant the writer holds the lock.
    BUSY_TIMEOUT_MS = 10_000

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        # WAL lets readers proceed while a writer is active (rollback-journal
        # mode blocks them), so the dashboard stays responsive mid-scan; the
        # busy timeout absorbs the brief remaining write-lock windows (e.g. the
        # WAL checkpoint) instead of erroring. journal_mode is a persistent
        # property of the file, but setting it every open is harmless and
        # covers a DB created before this was added. :memory: doesn't support
        # WAL and has no cross-connection sharing anyway, so skip it there.
        if self.path != ":memory:":
            self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.execute(f"PRAGMA busy_timeout = {self.BUSY_TIMEOUT_MS}")

    def __enter__(self) -> Database:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    @_locked
    def close(self) -> None:
        self.conn.close()

    @_locked
    def init_schema(self) -> None:
        self.conn.executescript(SCHEMA_SQL)
        self._upgrade_schema()
        self.conn.commit()

    def _upgrade_schema(self) -> None:
        """In-place upgrades for columns added after a database was first
        created. No versioned migration system - this project is young
        enough that a plain "add the column if it's missing" check is all
        that's needed; ALTER TABLE ADD COLUMN never loses existing data."""
        existing_columns = {
            row["name"] for row in self.conn.execute("PRAGMA table_info(services)")
        }
        if "version" not in existing_columns:
            self.conn.execute("ALTER TABLE services ADD COLUMN version TEXT")
        if "cpe" not in existing_columns:
            self.conn.execute("ALTER TABLE services ADD COLUMN cpe TEXT")

    # -- domains ----------------------------------------------------------

    @_locked
    def upsert_domain(self, name: str, now: str | None = None) -> int:
        timestamp = now or _now()
        self.conn.execute(
            "INSERT INTO domains (name, added_at) VALUES (?, ?) "
            "ON CONFLICT(name) DO NOTHING",
            (name, timestamp),
        )
        self.conn.commit()
        row = self.get_domain_by_name(name)
        assert row is not None
        return int(row["id"])

    @_locked
    def get_domain_by_name(self, name: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM domains WHERE name = ?", (name,)
        ).fetchone()

    @_locked
    def list_domains(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM domains ORDER BY name").fetchall()

    # -- hostnames ----------------------------------------------------------

    @_locked
    def upsert_hostname(
        self,
        domain_id: int,
        name: str,
        parent_hostname_id: int | None = None,
        now: str | None = None,
    ) -> int:
        """Note: `domain_id` is deliberately absent from the ON CONFLICT
        clause below - whichever call first inserts a given hostname keeps
        that attribution forever; a later upsert_hostname for the same name
        under a *different* domain_id only touches last_seen/parent, not
        domain_id. This only matters if the same literal hostname is ever
        discovered while scanning two different top-level domains in one
        batch (e.g. domains.txt lists both "example.com" and
        "sub.example.com" and each turns up the same subdomain) - which of
        the two "wins" was already somewhat arbitrary (Python's
        first-come-first-served list order), and cross-domain parallelism
        (run_scan's ThreadPoolExecutor) makes that "first" a matter of
        thread scheduling instead of input order, rather than introducing
        any actual data corruption or flip-flopping."""
        timestamp = now or _now()
        self.conn.execute(
            """
            INSERT INTO hostnames (domain_id, name, parent_hostname_id, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                last_seen = excluded.last_seen,
                parent_hostname_id = COALESCE(excluded.parent_hostname_id, hostnames.parent_hostname_id)
            """,
            (domain_id, name, parent_hostname_id, timestamp, timestamp),
        )
        self.conn.commit()
        row = self.get_hostname_by_name(name)
        assert row is not None
        return int(row["id"])

    @_locked
    def get_hostname_by_name(self, name: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM hostnames WHERE name = ?", (name,)
        ).fetchone()

    @_locked
    def list_hostnames_for_domain(self, domain_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM hostnames WHERE domain_id = ? ORDER BY name", (domain_id,)
        ).fetchall()

    @_locked
    def list_child_hostnames(self, parent_hostname_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM hostnames WHERE parent_hostname_id = ? ORDER BY name",
            (parent_hostname_id,),
        ).fetchall()

    # -- ip addresses ---------------------------------------------------

    @_locked
    def upsert_ip(self, address: str, now: str | None = None) -> int:
        timestamp = now or _now()
        self.conn.execute(
            """
            INSERT INTO ip_addresses (address, first_seen, last_seen)
            VALUES (?, ?, ?)
            ON CONFLICT(address) DO UPDATE SET last_seen = excluded.last_seen
            """,
            (address, timestamp, timestamp),
        )
        self.conn.commit()
        row = self.get_ip_by_address(address)
        assert row is not None
        return int(row["id"])

    @_locked
    def get_ip_by_address(self, address: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM ip_addresses WHERE address = ?", (address,)
        ).fetchone()

    @_locked
    def list_all_ips(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM ip_addresses ORDER BY address").fetchall()

    # -- resolutions ------------------------------------------------------

    @_locked
    def upsert_resolution(self, hostname_id: int, ip_id: int, now: str | None = None) -> None:
        timestamp = now or _now()
        self.conn.execute(
            """
            INSERT INTO resolutions (hostname_id, ip_id, first_seen, last_seen)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(hostname_id, ip_id) DO UPDATE SET last_seen = excluded.last_seen
            """,
            (hostname_id, ip_id, timestamp, timestamp),
        )
        self.conn.commit()

    @_locked
    def list_ips_for_hostname(self, hostname_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            """
            SELECT ip_addresses.* FROM ip_addresses
            JOIN resolutions ON resolutions.ip_id = ip_addresses.id
            WHERE resolutions.hostname_id = ?
            ORDER BY ip_addresses.address
            """,
            (hostname_id,),
        ).fetchall()

    @_locked
    def list_hostnames_for_ip(self, ip_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            """
            SELECT hostnames.* FROM hostnames
            JOIN resolutions ON resolutions.hostname_id = hostnames.id
            WHERE resolutions.ip_id = ?
            ORDER BY hostnames.name
            """,
            (ip_id,),
        ).fetchall()

    # -- services -----------------------------------------------------------

    @_locked
    def upsert_service(
        self,
        ip_id: int,
        port: int,
        protocol: str = "tcp",
        banner: str | None = None,
        version: str | None = None,
        cpe: str | None = None,
        now: str | None = None,
    ) -> int:
        timestamp = now or _now()
        self.conn.execute(
            """
            INSERT INTO services (ip_id, port, protocol, banner, version, cpe, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip_id, port, protocol) DO UPDATE SET
                banner = COALESCE(excluded.banner, services.banner),
                version = COALESCE(excluded.version, services.version),
                cpe = COALESCE(excluded.cpe, services.cpe),
                last_seen = excluded.last_seen
            """,
            (ip_id, port, protocol, banner, version, cpe, timestamp, timestamp),
        )
        self.conn.commit()
        row = self.conn.execute(
            "SELECT id FROM services WHERE ip_id = ? AND port = ? AND protocol = ?",
            (ip_id, port, protocol),
        ).fetchone()
        assert row is not None
        return int(row["id"])

    @_locked
    def list_services_for_ip(self, ip_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM services WHERE ip_id = ? ORDER BY port, protocol", (ip_id,)
        ).fetchall()

    # -- results --------------------------------------------------------

    @_locked
    def insert_result(
        self, source: str, target_type: str, target_id: int, data: dict, now: str | None = None
    ) -> int:
        timestamp = now or _now()
        cursor = self.conn.execute(
            "INSERT INTO results (source, target_type, target_id, data, fetched_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (source, target_type, target_id, json.dumps(data), timestamp),
        )
        self.conn.commit()
        assert cursor.lastrowid is not None
        return cursor.lastrowid

    @_locked
    def list_results_for_target(self, target_type: str, target_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM results WHERE target_type = ? AND target_id = ? ORDER BY fetched_at",
            (target_type, target_id),
        ).fetchall()

    @_locked
    def delete_result(self, result_id: int) -> None:
        self.conn.execute("DELETE FROM results WHERE id = ?", (result_id,))
        self.conn.commit()

    # -- continuation / revalidation --------------------------------------
    # Used by a resumed scan to prune data that's no longer valid, driven by
    # last_seen: every still-valid hostname->IP mapping gets its last_seen
    # refreshed by the resolution stage this run, so an edge left with an old
    # timestamp is one DNS no longer returns. See orchestrator._revalidate.

    @_locked
    def delete_stale_resolutions(self, domain_id: int, cutoff: str) -> int:
        """Delete this domain's hostname->IP edges not refreshed since
        `cutoff` (the run's start), returning how many were removed.

        Guarded so a transient DNS failure can't wipe valid data: an edge is
        only deleted when its hostname resolved to *something* this run (has
        at least one edge with last_seen >= cutoff). A hostname that resolved
        to nothing this run - whether it's genuinely gone or the resolver just
        hiccuped - keeps all its edges untouched."""
        cursor = self.conn.execute(
            """
            DELETE FROM resolutions
            WHERE last_seen < ?
              AND hostname_id IN (SELECT id FROM hostnames WHERE domain_id = ?)
              AND hostname_id IN (SELECT hostname_id FROM resolutions WHERE last_seen >= ?)
            """,
            (cutoff, domain_id, cutoff),
        )
        self.conn.commit()
        return cursor.rowcount

    @_locked
    def delete_orphan_ips(self) -> int:
        """Delete IPs no longer referenced by any hostname's resolution (in
        any domain), along with their services and IP-scoped results, and
        return how many IPs were removed. An IP only ever enters the DB via a
        resolution or the netblock sweep (which also writes one), so a
        reference count of zero means it's been fully abandoned - e.g. a host
        whose DNS now points elsewhere, whose stale edge this run just pruned."""
        orphan_ids = [
            row["id"]
            for row in self.conn.execute(
                "SELECT id FROM ip_addresses WHERE id NOT IN (SELECT ip_id FROM resolutions)"
            )
        ]
        if not orphan_ids:
            return 0
        placeholders = ",".join("?" for _ in orphan_ids)
        self.conn.execute(
            f"DELETE FROM services WHERE ip_id IN ({placeholders})", orphan_ids
        )
        self.conn.execute(
            f"DELETE FROM results WHERE target_type = 'ip' AND target_id IN ({placeholders})",
            orphan_ids,
        )
        # Their results are gone, so a TTL must not treat them as fresh if
        # they come back; the calls still count toward budgets.
        self.conn.execute(
            f"UPDATE source_calls SET ok = 0 WHERE target_type = 'ip' AND target IN "
            f"(SELECT address FROM ip_addresses WHERE id IN ({placeholders}))",
            orphan_ids,
        )
        self.conn.execute(
            f"DELETE FROM ip_addresses WHERE id IN ({placeholders})", orphan_ids
        )
        self.conn.commit()
        return len(orphan_ids)

    @_locked
    def delete_domain(self, domain_id: int) -> None:
        """Delete a domain and everything scanned for it: its hostnames,
        their DNS mappings and results, the domain's own results, candidates,
        cloud assets, code exposures and email addresses. IPs go only once no other domain
        resolves to them (delete_orphan_ips). All in one transaction."""
        row = self.conn.execute("SELECT name FROM domains WHERE id = ?", (domain_id,)).fetchone()
        if row is None:
            return
        hostname_ids = "SELECT id FROM hostnames WHERE domain_id = ?"
        try:
            # As in delete_orphan_ips: results are gone, so a TTL must not
            # treat these targets as fresh on a re-scan; the calls still
            # count toward budgets.
            self.conn.execute(
                "UPDATE source_calls SET ok = 0 WHERE target_type IN ('domain', 'collect') "
                "AND target = ?",
                (row["name"],),
            )
            self.conn.execute(
                "UPDATE source_calls SET ok = 0 WHERE target_type = 'hostname' AND target IN "
                "(SELECT name FROM hostnames WHERE domain_id = ?)",
                (domain_id,),
            )
            self.conn.execute(
                f"DELETE FROM results WHERE target_type = 'hostname' AND target_id IN ({hostname_ids})",
                (domain_id,),
            )
            self.conn.execute(
                "DELETE FROM results WHERE target_type = 'domain' AND target_id = ?", (domain_id,)
            )
            self.conn.execute(
                f"DELETE FROM resolutions WHERE hostname_id IN ({hostname_ids})", (domain_id,)
            )
            self.conn.execute("DELETE FROM hostnames WHERE domain_id = ?", (domain_id,))
            for table in ("candidate_domains", "cloud_assets", "code_exposures", "email_addresses"):
                self.conn.execute(f"DELETE FROM {table} WHERE domain_id = ?", (domain_id,))
            self.conn.execute("DELETE FROM domains WHERE id = ?", (domain_id,))
        except Exception:
            self.conn.rollback()
            raise
        self.conn.commit()
        self.delete_orphan_ips()

    @_locked
    def backup_to(self, path: str | Path) -> None:
        """Consistent copy of the whole database (SQLite online backup)."""
        target = sqlite3.connect(str(path))
        try:
            self.conn.backup(target)
        finally:
            target.close()

    # -- source calls -----------------------------------------------------
    # Usage ledger for governor.py: every call a source makes is recorded
    # (ok NULL while in flight, then 1/0), so quota budgets and TTL skipping
    # hold across runs and processes, not just within one scan.

    @_locked
    def begin_source_call(self, source: str, target_type: str, target: str, now: str) -> int:
        cursor = self.conn.execute(
            "INSERT INTO source_calls (source, target_type, target, called_at) VALUES (?, ?, ?, ?)",
            (source, target_type, target, now),
        )
        self.conn.commit()
        assert cursor.lastrowid is not None
        return cursor.lastrowid

    @_locked
    def finish_source_call(self, call_id: int, ok: bool) -> None:
        self.conn.execute("UPDATE source_calls SET ok = ? WHERE id = ?", (int(ok), call_id))
        self.conn.commit()

    @_locked
    def cancel_source_call(self, call_id: int) -> None:
        self.conn.execute("DELETE FROM source_calls WHERE id = ?", (call_id,))
        self.conn.commit()

    @_locked
    def count_source_calls_since(self, source: str, since: str) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) AS n FROM source_calls WHERE source = ? AND called_at >= ?",
            (source, since),
        ).fetchone()
        return int(row["n"])

    @_locked
    def last_successful_source_call(
        self, source: str, target_type: str, target: str
    ) -> str | None:
        row = self.conn.execute(
            "SELECT MAX(called_at) AS at FROM source_calls "
            "WHERE source = ? AND target_type = ? AND target = ? AND ok = 1",
            (source, target_type, target),
        ).fetchone()
        return row["at"] if row else None

    # -- candidate domains ------------------------------------------------

    @_locked
    def upsert_candidate_domain(
        self, domain_id: int, name: str, source: str, via: str, now: str | None = None
    ) -> None:
        """First sighting's source/via are kept; later ones bump last_seen."""
        timestamp = now or _now()
        self.conn.execute(
            """
            INSERT INTO candidate_domains (domain_id, name, source, via, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(domain_id, name) DO UPDATE SET last_seen = excluded.last_seen
            """,
            (domain_id, name, source, via, timestamp, timestamp),
        )
        self.conn.commit()

    @_locked
    def list_candidate_domains(self, domain_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM candidate_domains WHERE domain_id = ? ORDER BY name", (domain_id,)
        ).fetchall()

    # -- cloud assets -----------------------------------------------------

    @_locked
    def upsert_cloud_asset(
        self,
        domain_id: int,
        provider: str,
        name: str,
        url: str,
        exposure: str,
        source: str,
        now: str | None = None,
    ) -> None:
        """Latest exposure/url/source win; first_seen is preserved."""
        timestamp = now or _now()
        self.conn.execute(
            """
            INSERT INTO cloud_assets
                (domain_id, provider, name, url, exposure, source, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(domain_id, provider, name) DO UPDATE SET
                url = excluded.url,
                exposure = excluded.exposure,
                source = excluded.source,
                last_seen = excluded.last_seen
            """,
            (domain_id, provider, name, url, exposure, source, timestamp, timestamp),
        )
        self.conn.commit()

    @_locked
    def list_cloud_assets(self, domain_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM cloud_assets WHERE domain_id = ? ORDER BY provider, name", (domain_id,)
        ).fetchall()

    # -- email addresses -------------------------------------------------

    @_locked
    def upsert_email_address(
        self,
        domain_id: int,
        address: str,
        source: str,
        name: str | None = None,
        position: str | None = None,
        confidence: int | None = None,
        url: str | None = None,
        now: str | None = None,
    ) -> None:
        """One row per (address, source); a re-sighting bumps last_seen and
        fills in details the source now knows, first_seen kept."""
        timestamp = now or _now()
        self.conn.execute(
            """
            INSERT INTO email_addresses
                (domain_id, address, source, name, position, confidence, url, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(domain_id, address, source) DO UPDATE SET
                name = COALESCE(excluded.name, name),
                position = COALESCE(excluded.position, position),
                confidence = COALESCE(excluded.confidence, confidence),
                url = COALESCE(excluded.url, url),
                last_seen = excluded.last_seen
            """,
            (domain_id, address, source, name, position, confidence, url, timestamp, timestamp),
        )
        self.conn.commit()

    @_locked
    def list_email_addresses(self, domain_id: int) -> list[sqlite3.Row]:
        """One row per address, its sources comma-joined and the details any
        source knew merged in."""
        return self.conn.execute(
            """
            SELECT address,
                   GROUP_CONCAT(source, ', ') AS sources,
                   MAX(name) AS name,
                   MAX(position) AS position,
                   MAX(confidence) AS confidence,
                   MAX(url) AS url,
                   MIN(first_seen) AS first_seen,
                   MAX(last_seen) AS last_seen
            FROM (SELECT * FROM email_addresses WHERE domain_id = ? ORDER BY source)
            GROUP BY address
            ORDER BY address
            """,
            (domain_id,),
        ).fetchall()

    # -- code exposures ---------------------------------------------------

    @_locked
    def upsert_code_exposure(
        self,
        domain_id: int,
        kind: str,
        target: str,
        repo: str,
        path: str,
        commit: str,
        url: str,
        line: int | None = None,
        snippet: str | None = None,
        rule: str | None = None,
        secret: str | None = None,
        now: str | None = None,
    ) -> None:
        """One row per (repo, path, target, kind, rule, secret); a re-sighting
        bumps last_seen and refreshes the commit/url/line, first_seen kept."""
        timestamp = now or _now()
        self.conn.execute(
            """
            INSERT INTO code_exposures
                (domain_id, kind, target, repo, path, commit_sha, url, line, snippet,
                 rule, secret, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(domain_id, repo, path, target, kind, COALESCE(rule, ''), COALESCE(secret, ''))
            DO UPDATE SET
                commit_sha = excluded.commit_sha,
                url = excluded.url,
                line = excluded.line,
                snippet = excluded.snippet,
                last_seen = excluded.last_seen
            """,
            (domain_id, kind, target, repo, path, commit, url, line, snippet,
             rule, secret, timestamp, timestamp),
        )
        self.conn.commit()

    @_locked
    def list_code_exposures(
        self, domain_id: int, target: str | None = None
    ) -> list[sqlite3.Row]:
        """Secrets first, then references; optionally only for one target."""
        sql = (
            'SELECT *, commit_sha AS "commit" FROM code_exposures WHERE domain_id = ?'
        )
        params: list[Any] = [domain_id]
        if target is not None:
            sql += " AND target = ?"
            params.append(target)
        sql += " ORDER BY CASE kind WHEN 'secret' THEN 0 ELSE 1 END, repo, path"
        return self.conn.execute(sql, params).fetchall()

    @_locked
    def count_secret_exposures(self, domain_id: int) -> int:
        """How many secret exposures a domain has - for the dashboard, without
        materializing (and loading the secret values of) every row."""
        return self.conn.execute(
            "SELECT COUNT(*) FROM code_exposures WHERE domain_id = ? AND kind = 'secret'",
            (domain_id,),
        ).fetchone()[0]

    @_locked
    def list_code_exposures_for_target(self, target: str) -> list[sqlite3.Row]:
        """Exposures naming `target` (hostname/IP) across every domain - for
        the host/IP pages, where an IP may belong to more than one domain.
        The same file/target/secret stored under two domains is collapsed to
        one row (latest last_seen) so the page doesn't show it twice."""
        return self.conn.execute(
            'SELECT *, commit_sha AS "commit", MAX(last_seen) AS last_seen '
            "FROM code_exposures WHERE target = ? "
            "GROUP BY repo, path, target, kind, COALESCE(rule, ''), COALESCE(secret, '') "
            "ORDER BY CASE kind WHEN 'secret' THEN 0 ELSE 1 END, repo, path",
            (target,),
        ).fetchall()

    # -- settings -----------------------------------------------------------

    @_locked
    def get_settings(self) -> dict[str, str]:
        return {row["key"]: row["value"] for row in self.conn.execute("SELECT key, value FROM settings")}

    @_locked
    def set_setting(self, key: str, value: str | None) -> None:
        """Store `value` under `key`; None/empty deletes it."""
        if value:
            self.conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
        else:
            self.conn.execute("DELETE FROM settings WHERE key = ?", (key,))
        self.conn.commit()
