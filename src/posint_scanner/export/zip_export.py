"""Everything in one archive: JSON + CSV exports, the Obsidian vault and a
copy of the SQLite database itself."""

from __future__ import annotations

import tempfile
import zipfile
from collections.abc import Collection
from pathlib import Path

from posint_scanner.db import Database
from posint_scanner.export.csv_export import write_csv
from posint_scanner.export.json_export import write_json
from posint_scanner.export.obsidian_export import export_obsidian


def write_zip(
    db: Database, output_path: str | Path, domains: Collection[str] | None = None
) -> None:
    """`domains`: limit the archive to these domain names (None = all)."""
    if domains is None:
        _write_zip(db, output_path)
        return
    with tempfile.TemporaryDirectory() as scratch:
        subset = _subset(db, set(domains), Path(scratch) / "subset.db")
        try:
            _write_zip(subset, output_path)
        finally:
            subset.close()


def _write_zip(db: Database, output_path: str | Path) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        staging = Path(tmp)
        write_json(db, staging / "results.json")
        write_csv(db, staging / "services.csv")
        export_obsidian(db, staging / "vault")
        db.backup_to(staging / "posint.db")
        with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(staging.rglob("*")):
                if path.is_file():
                    archive.write(path, path.relative_to(staging).as_posix())


def _subset(db: Database, keep: set[str], path: Path) -> Database:
    """Copy of `db` holding only the `keep` domains (and what they own)."""
    db.backup_to(path)
    copy = Database(path)
    for row in copy.list_domains():
        if row["name"] not in keep:
            copy.delete_domain(row["id"])
    return copy
