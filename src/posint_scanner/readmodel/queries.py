"""Set-based reads behind every page: a page loads what it shows in a fixed
number of queries, however many IPs and hostnames the DB holds.

The per-row Database methods (list_services_for_ip, ...) suit the scan
pipeline, which works one target at a time. A page built from them issues
one query per IP or hostname - thousands on a real scan DB, each waiting its
turn while scans run. These load a whole scope at once instead.

A scope is a set of IPs, given as a subquery of ip ids (see Scope).
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Collection, Iterable
from dataclasses import dataclass

from posint_scanner.db import Database


@dataclass(frozen=True)
class Scope:
    """Which IPs a query covers: `sql` selects their ids (None: every IP)."""

    sql: str | None = None
    params: tuple = ()

    @classmethod
    def everything(cls) -> Scope:
        return cls()

    @classmethod
    def domains(cls, domain_ids: Collection[int]) -> Scope:
        """The IPs some hostname of these domains resolves to."""
        marks = ", ".join("?" * len(domain_ids))
        return cls(
            "SELECT r.ip_id FROM resolutions r JOIN hostnames h ON h.id = r.hostname_id "
            f"WHERE h.domain_id IN ({marks})" if domain_ids else "SELECT NULL WHERE 0",
            tuple(domain_ids),
        )

    @classmethod
    def ip(cls, ip_id: int) -> Scope:
        return cls("SELECT ?", (ip_id,))

    def where(self, column: str) -> tuple[str, tuple]:
        """A WHERE clause limiting `column` (an ip id) to this scope."""
        if self.sql is None:
            return "1", ()
        return f"{column} IN ({self.sql})", self.params


def _sources_clause(sources: Collection[str] | None, column: str = "source"
                    ) -> tuple[str, tuple]:
    if sources is None:
        return "1", ()
    return f"{column} IN ({', '.join('?' * len(sources))})", tuple(sources)


def _result(row) -> dict:
    return {"source": row["source"], "data": json.loads(row["data"]), "fetched_at": row["fetched_at"]}


def _group(rows: Iterable, key: str, value=dict) -> dict[int, list]:
    grouped: dict[int, list] = defaultdict(list)
    for row in rows:
        grouped[row[key]].append(value(row))
    return grouped


def ip_results(db: Database, scope: Scope, sources: Collection[str] | None = None
               ) -> dict[int, list[dict]]:
    """ip id -> its results (parsed, oldest first), only `sources` if given."""
    where, params = scope.where("target_id")
    only, more = _sources_clause(sources)
    rows = db.query(
        f"SELECT target_id, source, data, fetched_at FROM results "
        f"WHERE target_type = 'ip' AND {where} AND {only} ORDER BY fetched_at, id",
        params + more,
    )
    return _group(rows, "target_id", _result)


def hostname_results(db: Database, hostname_sql: str, params: tuple = (),
                     sources: Collection[str] | None = None) -> dict[int, list[dict]]:
    """hostname id -> its results, for the hostnames `hostname_sql` selects."""
    only, more = _sources_clause(sources)
    rows = db.query(
        f"SELECT target_id, source, data, fetched_at FROM results "
        f"WHERE target_type = 'hostname' AND target_id IN ({hostname_sql}) AND {only} "
        f"ORDER BY fetched_at, id",
        params + more,
    )
    return _group(rows, "target_id", _result)


def hostname_results_by_domain(db: Database, domain_ids: Collection[int],
                               sources: Collection[str] | None = None) -> dict[int, list[dict]]:
    """domain id -> the results on its hostnames (e.g. their takeovers)."""
    if not domain_ids:
        return {}
    only, more = _sources_clause(sources, "r.source")
    rows = db.query(
        "SELECT h.domain_id, r.source, r.data, r.fetched_at FROM results r "
        "JOIN hostnames h ON h.id = r.target_id "
        f"WHERE r.target_type = 'hostname' AND h.domain_id IN ({', '.join('?' * len(domain_ids))}) "
        f"AND {only} ORDER BY h.name, r.fetched_at, r.id",
        tuple(domain_ids) + more,
    )
    return _group(rows, "domain_id", _result)


def domain_results(db: Database, domain_ids: Collection[int],
                   sources: Collection[str] | None = None) -> dict[int, list[dict]]:
    """domain id -> its domain-level results."""
    if not domain_ids:
        return {}
    only, more = _sources_clause(sources)
    rows = db.query(
        f"SELECT target_id, source, data, fetched_at FROM results "
        f"WHERE target_type = 'domain' AND target_id IN ({', '.join('?' * len(domain_ids))}) "
        f"AND {only} ORDER BY fetched_at, id",
        tuple(domain_ids) + more,
    )
    return _group(rows, "target_id", _result)


def services(db: Database, scope: Scope) -> dict[int, list[dict]]:
    """ip id -> its services, by port."""
    where, params = scope.where("ip_id")
    rows = db.query(f"SELECT * FROM services WHERE {where} ORDER BY port, protocol", params)
    return _group(rows, "ip_id")


def hostnames_on_ips(db: Database, scope: Scope) -> dict[int, list[dict]]:
    """ip id -> the hostnames resolving to it (with their apex `domain`)."""
    where, params = scope.where("r.ip_id")
    rows = db.query(
        "SELECT r.ip_id, h.*, d.name AS domain FROM resolutions r "
        "JOIN hostnames h ON h.id = r.hostname_id JOIN domains d ON d.id = h.domain_id "
        f"WHERE {where} ORDER BY h.name",
        params,
    )
    return _group(rows, "ip_id")


def ips(db: Database, scope: Scope) -> list[dict]:
    where, params = scope.where("id")
    return [dict(r) for r in db.query(
        f"SELECT * FROM ip_addresses WHERE {where} ORDER BY address", params)]


def hosts(db: Database, scope: Scope, sources: Collection[str] | None = None) -> list[dict]:
    """Every IP in `scope` with what the pages and reports group by: its
    `hostnames` and apex `domains` (none for e.g. netblock-sweep hits),
    `services`, and `results` (only `sources` if given). Four queries."""
    found = ips(db, scope)
    names = hostnames_on_ips(db, scope)
    ports = services(db, scope)
    results = ip_results(db, scope, sources)
    return [
        {
            "id": ip["id"],
            "address": ip["address"],
            "first_seen": ip["first_seen"],
            "last_seen": ip["last_seen"],
            "hostnames": [h["name"] for h in names.get(ip["id"], [])],
            "domains": sorted({h["domain"] for h in names.get(ip["id"], [])}),
            "services": ports.get(ip["id"], []),
            "results": results.get(ip["id"], []),
        }
        for ip in found
    ]


def domain_ids(db: Database, names: Collection[str] | None = None) -> dict[str, int]:
    """name -> id of the domains named (every domain if None)."""
    if names is None:
        rows = db.query("SELECT id, name FROM domains ORDER BY name")
    else:
        names = list(names)
        rows = db.query(
            f"SELECT id, name FROM domains WHERE name IN ({', '.join('?' * len(names))}) "
            "ORDER BY name", names) if names else []
    return {r["name"]: r["id"] for r in rows}


def secret_exposures(db: Database, domain_ids: Collection[int]) -> dict[int, list[dict]]:
    """domain id -> its leaked secrets found in public code."""
    if not domain_ids:
        return {}
    rows = db.query(
        "SELECT * FROM code_exposures WHERE kind = 'secret' "
        f"AND domain_id IN ({', '.join('?' * len(domain_ids))}) ORDER BY repo, path",
        tuple(domain_ids),
    )
    return _group(rows, "domain_id")


def other_domains(db: Database, domain: str | None = None) -> list[dict]:
    """The candidate domains not scanned yet (of `domain`'s scans, or all),
    one row per name: which scanned domains led to it (`found_for`), which
    sources or tools named it, one place it was seen and when last."""
    only = "AND d.name = ?" if domain else ""
    rows = db.query(
        "SELECT c.name, group_concat(DISTINCT d.name) AS found_for, "
        "group_concat(DISTINCT c.source) AS sources, MIN(c.via) AS via, "
        "MAX(c.last_seen) AS last_seen FROM candidate_domains c "
        "JOIN domains d ON d.id = c.domain_id "
        f"WHERE c.name NOT IN (SELECT name FROM domains) {only} "
        "GROUP BY c.name ORDER BY c.name",
        (domain,) if domain else (),
    )
    return [
        {**dict(r), "found_for": sorted(r["found_for"].split(",")),
         "sources": sorted(r["sources"].split(","))}
        for r in rows
    ]


def count_by_domain(db: Database, table: str, extra: str = "") -> dict[int, int]:
    """domain id -> rows of `table` (hostnames, code_exposures, ...) it owns."""
    rows = db.query(
        f"SELECT domain_id, COUNT(*) AS n FROM {table} WHERE 1 {extra} GROUP BY domain_id")
    return {r["domain_id"]: r["n"] for r in rows}
