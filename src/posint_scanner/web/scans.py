"""Background scan runner for the web UI.

A scan is long-running (discovery + netblock sweep + enrichment + fingerprint
+ CVE lookup can take many minutes), so the HTTP handler can't block on it.
This runs each scan on its own thread and tracks status in a registry the UI
polls.

Jobs are also stored in the DB (`scan_jobs`), with the work each has finished
(`scan_checkpoints`, see orchestrator.Checkpoints). A job still marked
running when the process starts was cut off - the container stopped, the
process was killed - and is marked "interrupted". Resuming it (automatically
on startup, or from the UI) runs it again under the same id, skipping what it
already finished. Cancelled and failed jobs can be resumed the same way.

The worker opens its own Database on its own thread rather than sharing the
web app's connection: a scan holds the DB busy for minutes, and keeping that
off the connection the UI reads from means the dashboard stays responsive
while a scan runs.
"""

from __future__ import annotations

import json
import logging
import threading
import uuid
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone

from posint_scanner import toolrun
from posint_scanner.config import load_config
from posint_scanner.db import Database
from posint_scanner.orchestrator import Checkpoints, ScanControl, run_scan
from posint_scanner.registry import SOURCE_CLASSES, SourceSelection, build_sources
from posint_scanner.settings import apply_source_secrets

logger = logging.getLogger(__name__)

ACTIVE_STATES = ("pending", "running", "cancelling")
RESUMABLE_STATES = ("interrupted", "cancelled", "failed")
# How many past jobs the dashboard lists after a restart.
RECOVERED_JOBS = 50


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
    verify_ports: bool = True
    fingerprint: bool = True
    netblock_sweep: bool = True
    vuln_lookup: bool = True
    nuclei: bool = False
    nikto: bool = False
    wpscan: bool = False
    takeover: bool = False
    php2shell: bool = True
    cloud_scan: bool = False
    cloud_audit: bool = False
    fresh: bool = False

    def selection(self) -> SourceSelection:
        if self.sources is None:
            return SourceSelection()
        every = {cls.name for cls in SOURCE_CLASSES}
        return SourceSelection(enable=set(self.sources), disable=every - self.sources)

    def to_json(self) -> str:
        data = asdict(self)
        data["sources"] = sorted(self.sources) if self.sources is not None else None
        return json.dumps(data)

    @classmethod
    def from_json(cls, text: str) -> ScanOptions:
        """Options stored by to_json; fields added or dropped since keep
        their defaults / are ignored."""
        data = json.loads(text)
        known = {f.name for f in fields(cls)}
        options = cls(**{k: v for k, v in data.items() if k in known})
        if options.sources is not None:
            options.sources = set(options.sources)
        return options


@dataclass
class ScanJob:
    id: str
    domain: str
    options: ScanOptions
    # pending | running | completed | cancelling | cancelled | failed | interrupted
    status: str = "pending"
    stage: str = ""  # what the running scan is currently doing
    detail: str = ""
    error: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    created_at: str = field(default_factory=_now)
    resumes: int = 0
    # Set when the job starts running; the cancel endpoint calls control.cancel().
    control: ScanControl | None = None

    def cancel(self) -> None:
        if self.control is not None:
            self.control.cancel()
        if self.status in ("pending", "running"):
            self.status = "cancelling"

    @property
    def resumable(self) -> bool:
        return self.status in RESUMABLE_STATES

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
            "resumes": self.resumes,
            "resumable": self.resumable,
        }

    @classmethod
    def from_row(cls, row) -> ScanJob:
        return cls(
            id=row["id"],
            domain=row["domain"],
            options=ScanOptions.from_json(row["options"]),
            status=row["status"],
            stage=row["stage"],
            detail=row["detail"],
            error=row["error"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            created_at=row["created_at"],
            resumes=row["resumes"],
        )


class ScanManager:
    """Thread-safe registry of scan jobs. One instance lives on the app."""

    def __init__(self, db_path: str, config_path: str, resume_interrupted: bool = False) -> None:
        self.db_path = db_path
        self.config_path = config_path
        self._jobs: dict[str, ScanJob] = {}
        self._lock = threading.Lock()
        # Job bookkeeping only; scans write through their own connection.
        self._db = Database(db_path)
        self._db.init_schema()
        self._recover(resume_interrupted)

    def _save(self, job: ScanJob, *names: str) -> None:
        try:
            self._db.update_scan_job(job.id, **{name: getattr(job, name) for name in names})
        except Exception:
            logger.exception("failed to store scan job %s - continuing", job.id)

    def _recover(self, resume_interrupted: bool) -> None:
        """Load past jobs; any still marked active was cut off by the process
        ending - mark it interrupted and, if asked, resume it."""
        interrupted = []
        for row in self._db.list_scan_jobs(RECOVERED_JOBS):
            job = ScanJob.from_row(row)
            if job.status in ACTIVE_STATES:
                job.status = "interrupted"
                self._save(job, "status")
                interrupted.append(job)
                logger.warning("scan job %s for %s was interrupted (stage: %s)",
                               job.id, job.domain, job.stage or "-")
            self._jobs[job.id] = job
        if resume_interrupted:
            for job in interrupted:
                logger.info("resuming interrupted scan job %s for %s", job.id, job.domain)
                self.resume(job.id)

    def start(self, domain: str, options: ScanOptions) -> ScanJob:
        job = ScanJob(id=uuid.uuid4().hex[:12], domain=domain, options=options)
        self._db.create_scan_job(
            job.id, job.domain, options.to_json(), job.status, job.created_at
        )
        with self._lock:
            self._jobs[job.id] = job
        threading.Thread(target=self._run, args=(job,), daemon=True).start()
        return job

    def resume(self, job_id: str) -> ScanJob | None:
        """Run an interrupted/cancelled/failed job again, continuing where it
        stopped. None if there's no such job or it can't be resumed now."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or not job.resumable:
                return None
            job.status = "pending"
            job.error = None
            job.finished_at = None
            job.control = None
            job.resumes += 1
        self._save(job, "status", "error", "finished_at", "resumes")
        threading.Thread(target=self._run, args=(job,), daemon=True).start()
        return job

    def get(self, job_id: str) -> ScanJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def cancel(self, job_id: str) -> ScanJob | None:
        job = self.get(job_id)
        if job is not None:
            job.cancel()
            self._save(job, "status")
        return job

    def busy(self) -> bool:
        """Whether any scan is still running (deleting data under a running
        scan would have it write back half a domain)."""
        with self._lock:
            return any(j.status in ACTIVE_STATES for j in self._jobs.values())

    def list(self) -> list[ScanJob]:
        with self._lock:
            return sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)

    def _run(self, job: ScanJob) -> None:
        job.status = "running"
        # The first start, kept across resumes: source calls the job made
        # since then aren't repeated (see orchestrator.Checkpoints).
        job.started_at = job.started_at or _now()
        self._save(job, "status", "started_at")

        def on_progress(stage: str, detail: str) -> None:
            job.stage = stage
            job.detail = detail
            self._save(job, "stage", "detail")

        job.control = ScanControl(on_progress=on_progress)
        try:
            config = load_config(self.config_path)
            toolrun.set_limits(config.sandbox.size_mb, config.sandbox.max_inodes)
            opts = job.options
            # The worker's own connection (see module docstring). check_same_thread
            # is already off in Database, but a fresh one keeps the scan's long
            # write lock off the connection the UI reads from.
            with Database(self.db_path) as db:
                db.init_schema()
                apply_source_secrets(config, db)  # web-UI API keys, if any
                sources = build_sources(
                    config,
                    opts.selection(),
                    overrides=(
                        {"qualys_vmdr": {"authorize_scans": True}} if opts.authorize_scans else None
                    ),
                )
                run_scan(
                    db,
                    [job.domain],
                    sources,
                    netblock_sweep=opts.netblock_sweep,
                    verify_ports=opts.verify_ports,
                    tech_fingerprint=opts.fingerprint,
                    vuln_lookup=opts.vuln_lookup,
                    nuclei_scan=opts.nuclei,
                    nuclei_templates_dir=config.nuclei.templates_dir,
                    nikto_scan=opts.nikto,
                    wpscan_scan=opts.wpscan,
                    takeover_scan=opts.takeover,
                    php2shell_scan=opts.php2shell,
                    webscan_config=config.webscan,
                    cloud_scan=opts.cloud_scan,
                    cloud_audit=opts.cloud_audit,
                    cloudscan_config=config.cloudscan,
                    nvd_api_key=config.nvd.api_key,
                    fresh=opts.fresh,
                    control=job.control,
                    checkpoints=Checkpoints(db, job.id, since=job.started_at),
                )
                if not job.control.cancelled():
                    db.delete_scan_checkpoints(job.id)  # nothing left to resume
            job.status = "cancelled" if job.control.cancelled() else "completed"
        except Exception as exc:  # noqa: BLE001 - surface any failure to the UI
            logger.exception("scan job %s for %s failed", job.id, job.domain)
            job.status = "failed"
            job.error = f"{type(exc).__name__}: {exc}"
        finally:
            job.finished_at = _now()
            self._save(job, "status", "error", "finished_at")
