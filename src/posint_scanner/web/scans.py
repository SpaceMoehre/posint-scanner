"""Background scan jobs for the web UI.

A scan is long-running (discovery + netblock sweep + enrichment + fingerprint
+ CVE lookup can take many minutes), so the HTTP handler can't block on it.
Each job runs in its own process (ProcessRunner): a scan keeps a hundred
threads busy parsing, fingerprinting and storing, and in the server's
process they would hold the GIL against every page request. At most
`web.max_parallel_scans` (config.yaml) run at once; later jobs wait as
pending.

The `scan_jobs` table is the one record of a job: the process running it
writes its status and progress there, and the UI reads them from there.
Finished work is recorded in `scan_checkpoints` (see
orchestrator.Checkpoints). A job still marked active when the server starts
was cut off - the container stopped, the process was killed - and is marked
"interrupted". Resuming it (automatically on startup, or from the UI) runs
it again under the same id, skipping what it already finished. Cancelled and
failed jobs can be resumed the same way.

Cancelling sets the job's cancel event, which the scan checks between units
of work; a scan that hasn't stopped CANCEL_GRACE_SECONDS later is killed
(its tool sandboxes die with it, and checkpoints keep it resumable).
"""

from __future__ import annotations

import ctypes
import json
import logging
import logging.handlers
import atexit
import multiprocessing
import multiprocessing.process
import os
import signal
import threading
import uuid
from collections import deque
from collections.abc import Callable
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone

from posint_scanner import toolrun
from posint_scanner.config import WebConfig, load_config
from posint_scanner.db import Database
from posint_scanner.orchestrator import Checkpoints, ScanControl, run_scan
from posint_scanner.registry import SOURCE_CLASSES, SourceSelection, build_sources
from posint_scanner.settings import apply_source_secrets

logger = logging.getLogger(__name__)

ACTIVE_STATES = ("pending", "running", "cancelling")
RESUMABLE_STATES = ("interrupted", "cancelled", "failed")
# How many past jobs the dashboard lists.
LISTED_JOBS = 50
# How long a cancelled scan may take to stop on its own before it's killed.
CANCEL_GRACE_SECONDS = 30.0


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


# Settings key of the last scan's options, which pre-fill the scan forms.
LAST_OPTIONS = "scan.last_options"
# The scan forms' stage toggles (ScanOptions fields), in form order.
STAGES = ("verify_ports", "fingerprint", "netblock_sweep", "vuln_lookup", "nuclei", "nikto",
          "wpscan", "takeover", "php2shell", "cloud_scan", "cloud_audit", "fresh",
          "authorize_scans")


def remember_options(db: Database, options: ScanOptions, known_sources: list[str]) -> None:
    """Keep `options` to pre-fill the next scan form (see form_state).
    `known_sources` are the sources the form offered, so one added later
    starts at its config default instead of off."""
    db.set_setting(LAST_OPTIONS, json.dumps(
        {"options": json.loads(options.to_json()), "known_sources": known_sources}))


def form_state(db: Database, sources: list, active_default: bool) -> dict:
    """What the scan forms start with: the last scan's options (every
    toggle, the intrusive ones included), else the config defaults.
    `sources` are registry.describe_sources' rows. Returns the ticked
    `sources` names and each STAGES toggle."""
    state: dict = {
        "sources": {s.name for s in sources if s.enabled},
        **{stage: False for stage in STAGES},
        "verify_ports": active_default, "fingerprint": active_default,
        "php2shell": active_default, "netblock_sweep": True, "vuln_lookup": True,
    }
    try:
        stored = json.loads(db.get_settings().get(LAST_OPTIONS) or "null")
        if not stored:
            return state
        options = ScanOptions.from_json(json.dumps(stored["options"]))
        known = set(stored.get("known_sources") or [])
    except (ValueError, KeyError, TypeError):
        logger.warning("stored scan options unreadable - using the defaults")
        return state
    state.update({stage: getattr(options, stage) for stage in STAGES})
    if options.sources is not None:
        state["sources"] = {
            s.name for s in sources
            if (s.name in options.sources if s.name in known else s.enabled)
        }
    return state


def run_job(db_path: str, config_path: str, job_id: str, control: ScanControl) -> None:
    """Run the stored job `job_id` to its end, recording its status and
    progress in `scan_jobs`. Runs in the job's own process (ProcessRunner)."""
    with Database(db_path) as db:
        row = db.get_scan_job(job_id)
        if row is None:
            logger.error("scan job %s is gone - not running it", job_id)
            return
        job = ScanJob.from_row(row)
        # The first start, kept across resumes: source calls the job made
        # since then aren't repeated (see orchestrator.Checkpoints).
        job.started_at = job.started_at or _now()
        db.update_scan_job(job_id, started_at=job.started_at)
        # Unless it was cancelled meanwhile - then it shows as cancelling.
        db.update_scan_job(job_id, only_if_status=("pending",), status="running")

        def on_progress(stage: str, detail: str) -> None:
            db.update_scan_job(job_id, stage=stage, detail=detail)

        control.on_progress = on_progress
        error = None
        try:
            config = load_config(config_path)
            toolrun.set_limits(config.sandbox.size_mb, config.sandbox.max_inodes)
            opts = job.options
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
                control=control,
                checkpoints=Checkpoints(db, job.id, since=job.started_at),
            )
            if not control.cancelled():
                db.delete_scan_checkpoints(job.id)  # nothing left to resume
            status = "cancelled" if control.cancelled() else "completed"
        except Exception as exc:  # noqa: BLE001 - surface any failure to the UI
            logger.exception("scan job %s for %s failed", job.id, job.domain)
            status = "failed"
            error = f"{type(exc).__name__}: {exc}"
        db.update_scan_job(job_id, status=status, error=error, finished_at=_now())


# Called with (job id, exit code) once a runner's job has ended.
OnExit = Callable[[str, int], None]


class ProcessRunner:
    """Runs each job in a spawned child process (fork is unsafe in a
    process that already runs threads). The child's log records come back
    over a queue and go through this process's logging setup, so one
    process writes the log file.

    Children are started from one long-lived launcher thread: the kernel's
    parent-death signal (see _child_main) fires when the *thread* that
    started a child exits, and request-handler threads come and go."""

    def __init__(self, db_path: str, config_path: str, on_exit: OnExit,
                 target: Callable[..., None] | None = None) -> None:
        """`target` replaces the child's entry point (_child_main), for tests."""
        self.db_path = db_path
        self.config_path = config_path
        self.on_exit = on_exit
        self._target = target or _child_main
        self._ctx = multiprocessing.get_context("spawn")
        self._lock = threading.Lock()
        self._cancel: dict[str, object] = {}  # job id -> its multiprocessing Event
        self._procs: dict[str, multiprocessing.process.BaseProcess] = {}
        self._launches: deque[str] = deque()
        self._wake = threading.Condition(self._lock)
        self._logs = self._ctx.Queue()
        self._listener = logging.handlers.QueueListener(self._logs, _Forward())
        self._listener.start()
        # At exit multiprocessing terminates the children; their jobs then
        # stay active, to show as interrupted (and resume) on the next start.
        # Registered after multiprocessing's own exit hook, so it runs first.
        self._exiting = False
        atexit.register(self._at_exit)
        threading.Thread(target=self._launcher, name="scan-launcher", daemon=True).start()

    def _at_exit(self) -> None:
        self._exiting = True

    def start(self, job_id: str) -> None:
        with self._lock:
            # Registered now, so a cancel before the launch still reaches it.
            self._cancel[job_id] = self._ctx.Event()
            self._launches.append(job_id)
            self._wake.notify()

    def cancel(self, job_id: str) -> None:
        with self._lock:
            event = self._cancel.get(job_id)
            proc = self._procs.get(job_id)
        if event is None:
            return
        event.set()  # type: ignore[attr-defined]
        if proc is not None:
            _kill_later(job_id, proc)

    def _launcher(self) -> None:
        while True:
            with self._lock:
                while not self._launches:
                    self._wake.wait()
                job_id = self._launches.popleft()
                event = self._cancel[job_id]
            proc = self._ctx.Process(
                target=_child_bootstrap,
                args=(self._target, self.db_path, self.config_path, job_id, event, self._logs,
                      logging.getLogger().getEffectiveLevel(), os.getpid()),
                name=f"scan-{job_id}",
                daemon=True,
            )
            try:
                proc.start()
            except Exception:
                logger.exception("could not start a process for scan job %s", job_id)
                with self._lock:
                    self._cancel.pop(job_id, None)
                self.on_exit(job_id, 1)
                continue
            with self._lock:
                self._procs[job_id] = proc
            if event.is_set():  # type: ignore[attr-defined]
                _kill_later(job_id, proc)  # cancelled before it launched
            threading.Thread(target=self._reap, args=(job_id, proc), daemon=True).start()

    def _reap(self, job_id: str, proc: multiprocessing.process.BaseProcess) -> None:
        proc.join()
        with self._lock:
            self._procs.pop(job_id, None)
            self._cancel.pop(job_id, None)
        if not self._exiting:
            self.on_exit(job_id, proc.exitcode or 0)


class ThreadRunner:
    """Runs each job on a thread of this process. The tests use it: they
    patch run_scan, which a child process wouldn't see."""

    def __init__(self, db_path: str, config_path: str, on_exit: OnExit) -> None:
        self.db_path = db_path
        self.config_path = config_path
        self.on_exit = on_exit
        self._lock = threading.Lock()
        self._cancel: dict[str, threading.Event] = {}

    def start(self, job_id: str) -> None:
        event = threading.Event()
        with self._lock:
            self._cancel[job_id] = event

        def target() -> None:
            exitcode = 1
            try:
                run_job(self.db_path, self.config_path, job_id, ScanControl(cancel_event=event))
                exitcode = 0
            finally:
                with self._lock:
                    self._cancel.pop(job_id, None)
                self.on_exit(job_id, exitcode)

        threading.Thread(target=target, name=f"scan-{job_id}", daemon=True).start()

    def cancel(self, job_id: str) -> None:
        with self._lock:
            event = self._cancel.get(job_id)
        if event is not None:
            event.set()


# The runner ScanManager uses unless given one (the tests swap it).
RUNNER: Callable[[str, str, OnExit], ProcessRunner | ThreadRunner] = ProcessRunner


class _Forward(logging.Handler):
    """Hands a child's log record to this process's logger of the same name."""

    def emit(self, record: logging.LogRecord) -> None:
        logging.getLogger(record.name).handle(record)


def _kill_later(job_id: str, proc: multiprocessing.process.BaseProcess) -> None:
    timer = threading.Timer(CANCEL_GRACE_SECONDS, _kill, args=(job_id, proc))
    timer.daemon = True
    timer.start()


def _kill(job_id: str, proc: multiprocessing.process.BaseProcess) -> None:
    if proc.is_alive():
        logger.warning("scan job %s did not stop within %ds of its cancel - killing it",
                       job_id, CANCEL_GRACE_SECONDS)
        proc.kill()


PR_SET_PDEATHSIG = 1


def _child_bootstrap(target: Callable[..., None], db_path: str, config_path: str,
                     job_id: str, cancel_event, log_queue, log_level: int,
                     parent_pid: int) -> None:
    """A scan process's entry point: set the process up, then run `target`."""
    # Die with the server, as a thread would: a scan outliving it would be
    # marked interrupted and resumed next to itself. Ctrl+C is the server's
    # to handle - the scan ends with it.
    try:
        ctypes.CDLL(None, use_errno=True).prctl(PR_SET_PDEATHSIG, int(signal.SIGKILL))
    except (OSError, AttributeError):
        pass  # not Linux: the parent's exit still terminates daemon children
    if os.getppid() != parent_pid:
        os._exit(1)  # the server is already gone
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    root = logging.getLogger()
    root.handlers[:] = [logging.handlers.QueueHandler(log_queue)]
    root.setLevel(log_level)
    target(db_path, config_path, job_id, cancel_event)


def _child_main(db_path: str, config_path: str, job_id: str, cancel_event) -> None:
    run_job(db_path, config_path, job_id, ScanControl(cancel_event=cancel_event))


class ScanManager:
    """Starts, queues, cancels and lists the web UI's scan jobs. One
    instance lives on the app."""

    def __init__(
        self,
        db_path: str,
        config_path: str,
        resume_interrupted: bool = False,
        runner: Callable[[str, str, OnExit], ProcessRunner | ThreadRunner] | None = None,
    ) -> None:
        self.db_path = db_path
        self.config_path = config_path
        self._db = Database(db_path)
        self._db.init_schema()
        self._lock = threading.Lock()
        self._queue: deque[str] = deque()  # pending jobs, oldest first
        self._running: set[str] = set()
        self._runner = (runner or RUNNER)(db_path, config_path, self._exited)
        self._recover(resume_interrupted)

    def _recover(self, resume_interrupted: bool) -> None:
        """A job still marked active was cut off by the last server ending -
        mark it interrupted and, if asked, resume it."""
        marks = ", ".join("?" * len(ACTIVE_STATES))
        for row in self._db.query(
            f"SELECT * FROM scan_jobs WHERE status IN ({marks}) ORDER BY created_at",
            ACTIVE_STATES,
        ):
            self._db.update_scan_job(row["id"], status="interrupted")
            logger.warning("scan job %s for %s was interrupted (stage: %s)",
                           row["id"], row["domain"], row["stage"] or "-")
            if resume_interrupted:
                logger.info("resuming interrupted scan job %s for %s", row["id"], row["domain"])
                self.resume(row["id"])

    def _max_parallel(self) -> int:
        try:
            return load_config(self.config_path).web.max_parallel_scans
        except Exception:  # noqa: BLE001 - a broken config fails the job itself, visibly
            return WebConfig().max_parallel_scans

    def _dispatch(self) -> None:
        limit = self._max_parallel()
        with self._lock:
            while self._queue and len(self._running) < limit:
                job_id = self._queue.popleft()
                self._running.add(job_id)
                self._runner.start(job_id)

    def _exited(self, job_id: str, exitcode: int) -> None:
        """A job's runner ended. A process that died without recording an
        end (killed after a cancel, crashed) is marked here."""
        try:
            if exitcode:
                how = f"signal {-exitcode}" if exitcode < 0 else f"code {exitcode}"
                if not self._db.update_scan_job(
                    job_id, only_if_status=("cancelling",), status="cancelled", finished_at=_now()
                ):
                    self._db.update_scan_job(
                        job_id, only_if_status=ACTIVE_STATES, status="failed",
                        error=f"the scan process exited with {how}", finished_at=_now(),
                    )
        except Exception:
            logger.exception("could not record the end of scan job %s", job_id)
        finally:
            with self._lock:
                self._running.discard(job_id)
            self._dispatch()

    def start(self, domain: str, options: ScanOptions) -> ScanJob:
        job = ScanJob(id=uuid.uuid4().hex[:12], domain=domain, options=options)
        self._db.create_scan_job(job.id, job.domain, options.to_json(), job.status, job.created_at)
        with self._lock:
            self._queue.append(job.id)
        self._dispatch()
        return self.get(job.id) or job

    def resume(self, job_id: str) -> ScanJob | None:
        """Run an interrupted/cancelled/failed job again, continuing where it
        stopped. None if there's no such job or it can't be resumed now."""
        job = self.get(job_id)
        with self._lock:
            # Its last run may have recorded its end but not exited yet.
            still_running = job_id in self._running or job_id in self._queue
        if job is None or still_running or not self._db.update_scan_job(
            job_id, only_if_status=RESUMABLE_STATES, status="pending", error=None,
            finished_at=None, resumes=job.resumes + 1,
        ):
            return None
        with self._lock:
            self._queue.append(job_id)
        self._dispatch()
        return self.get(job_id)

    def get(self, job_id: str) -> ScanJob | None:
        row = self._db.get_scan_job(job_id)
        return ScanJob.from_row(row) if row is not None else None

    def cancel(self, job_id: str) -> ScanJob | None:
        if self.get(job_id) is None:
            return None
        with self._lock:
            queued = job_id in self._queue
            if queued:
                self._queue.remove(job_id)
        if queued:
            self._db.update_scan_job(job_id, only_if_status=("pending",),
                                     status="cancelled", finished_at=_now())
        elif self._db.update_scan_job(job_id, only_if_status=("pending", "running"),
                                      status="cancelling"):
            self._runner.cancel(job_id)
        return self.get(job_id)

    def busy(self) -> bool:
        """Whether any scan is still running or waiting (deleting data under
        a running scan would have it write back half a domain)."""
        marks = ", ".join("?" * len(ACTIVE_STATES))
        return bool(self._db.query(
            f"SELECT 1 FROM scan_jobs WHERE status IN ({marks}) LIMIT 1", ACTIVE_STATES))

    def list(self) -> list[ScanJob]:
        return [ScanJob.from_row(row) for row in self._db.list_scan_jobs(LISTED_JOBS)]
