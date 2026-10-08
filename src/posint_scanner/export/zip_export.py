"""Everything in one archive: JSON + CSV exports, the Obsidian vault and a
copy of the SQLite database itself."""

from __future__ import annotations

import tempfile
import zipfile
from pathlib import Path

from posint_scanner.db import Database
from posint_scanner.export.csv_export import write_csv
from posint_scanner.export.json_export import write_json
from posint_scanner.export.obsidian_export import export_obsidian


def write_zip(db: Database, output_path: str | Path) -> None:
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
