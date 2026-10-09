"""Background scan runner for the web UI.

A scan is long-running (discovery + netblock sweep + enrichment + fingerprint
+ CVE lookup can take many minutes), so the HTTP handler can't block on it.
This runs each scan on its own thread and tracks status in an in-memory
registry the UI polls. State is process-local and lost on restart - the
durable record of a scan is the SQLite DB it writes, not this registry.

The worker opens its own Database on its own thread rather than sharing the
web app's connection: a scan holds the DB busy for minutes, and keeping that
off the connection the UI reads from means the dashboard stays responsive
while a scan runs.
"""

from __future__ import annotations

import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from posint_scanner.config import load_config
from posint_scanner.db import Database
from posint_scanner.orchestrator import ScanControl, run_scan
from posint_scanner.registry import SOURCE_CLASSES, SourceSelection, build_sources

logger = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ScanOptions:
    """Which stages/sources to run. Mirrors the `scan` CLI flags.

    `sources` is the exact set of source names to run (the dashboard renders
    one checkbox per registered source, pre-checked from config); None means
    "whatever config enables", as a CLI scan with no source flags would."""

    sources: set[str] | None = None
    authorize_scans: bool = False
    fingerprint: bool = True
    netblock_sweep: bool = True
    vuln_lookup: bool = True
    nuclei: bool = False
    nikto: bool = False
    wpscan: bool = False
    takeover: bool = False
    cloud_scan: bool = False
    cloud_audit: bool = False
    fresh: bool = False

    def selection(self) -> SourceSelection:
        if self.sources is None:
            return SourceSelection()
        every = {cls.name for cls in SOURCE_CLASSES}
        return SourceSelection(enable=set(self.sources), disable=every - self.sources)


@dataclass
class ScanJob:
    id: str
    domain: str
    options: ScanOptions
    status: str = "pending"  # pending | running | completed | cancelled | failed
    stage: str = ""  # what the running scan is currently doing
    detail: str = ""
    error: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    created_at: str = field(default_factory=_now)
    # Set when the job starts running; the cancel endpoint calls control.cancel().
    control: ScanControl | None = None

    def cancel(self) -> None:
        if self.control is not None:
            self.control.cancel()
        if self.status in ("pending", "running"):
            self.status = "cancelling"

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "domain": self.domain,
            "status": self.status,
            "stage": self.stage,
            "detail": self.detail,
            "error": self.error,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


class ScanManager:
    """Thread-safe registry of scan jobs. One instance lives on the app."""

    def __init__(self, db_path: str, config_path: str, vault_dir: str) -> None:
        self.db_path = db_path
        self.config_path = config_path
        self.vault_dir = vault_dir
        self._jobs: dict[str, ScanJob] = {}
        self._lock = threading.Lock()

    def start(self, domain: str, options: ScanOptions) -> ScanJob:
        job = ScanJob(id=uuid.uuid4().hex[:12], domain=domain, options=options)
        with self._lock:
            self._jobs[job.id] = job
        thread = threading.Thread(target=self._run, args=(job,), daemon=True)
        thread.start()
        return job

    def get(self, job_id: str) -> ScanJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def cancel(self, job_id: str) -> ScanJob | None:
        job = self.get(job_id)
        if job is not None:
            job.cancel()
        return job

    def busy(self) -> bool:
        """Whether any scan is still running (deleting data under a running
        scan would have it write back half a domain)."""
        with self._lock:
            return any(
                j.status in ("pending", "running", "cancelling") for j in self._jobs.values()
            )

    def list(self) -> list[ScanJob]:
        with self._lock:
            return sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)

    def _run(self, job: ScanJob) -> None:
        job.status = "running"
        job.started_at = _now()

        def on_progress(stage: str, detail: str) -> None:
            job.stage = stage
            job.detail = detail

        job.control = ScanControl(on_progress=on_progress)
        try:
            config = load_config(self.config_path)
            opts = job.options
            sources = build_sources(
                config,
                opts.selection(),
                overrides=(
                    {"qualys_vmdr": {"authorize_scans": True}} if opts.authorize_scans else None
                ),
            )
            # The worker's own connection (see module docstring). check_same_thread
            # is already off in Database, but a fresh one keeps the scan's long
            # write lock off the connection the UI reads from.
            with Database(self.db_path) as db:
                db.init_schema()
                run_scan(
                    db,
                    [job.domain],
                    sources,
                    netblock_sweep=opts.netblock_sweep,
                    tech_fingerprint=opts.fingerprint,
                    vuln_lookup=opts.vuln_lookup,
                    nuclei_scan=opts.nuclei,
                    nuclei_templates_dir=config.nuclei.templates_dir,
                    nikto_scan=opts.nikto,
                    wpscan_scan=opts.wpscan,
                    takeover_scan=opts.takeover,
                    webscan_config=config.webscan,
                    cloud_scan=opts.cloud_scan,
                    cloud_audit=opts.cloud_audit,
                    cloudscan_config=config.cloudscan,
                    nvd_api_key=config.nvd.api_key,
                    fresh=opts.fresh,
                    control=job.control,
                )
            job.status = "cancelled" if job.control.cancelled() else "completed"
        except Exception as exc:  # noqa: BLE001 - surface any failure to the UI
            logger.exception("scan job %s for %s failed", job.id, job.domain)
            job.status = "failed"
            job.error = f"{type(exc).__name__}: {exc}"
        finally:
            job.finished_at = _now()
