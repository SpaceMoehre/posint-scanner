"""Running external tools without leaving files behind.

During a scan the database is the only thing that may grow. External tools
(nikto, trivy, theHarvester, ...) still need somewhere to write their input
lists and reports, so each run gets a private workspace under one scratch root
next to the database:

    <db dir>/.posint-scratch/run-<pid>/<tool>-<random>/

The run's report is lzma-compressed into the `tool_outputs` table and the
workspace is deleted as soon as the tool exits - in a `finally`, so a failing
tool cleans up too. What a `finally` can't cover (the process killed outright)
is swept up later: every scan, and the web server on startup, removes the
`run-<pid>` dirs of processes that are no longer alive. Live processes' dirs
are never touched, so a CLI scan and the web UI can share one data dir.

Tools run in their own process group, and the whole group is killed on a
timeout - and after a normal exit, in case the tool left children behind -
so nothing keeps writing into a workspace after it's gone. `TMPDIR` points at
the workspace, so a tool's own temp files are wiped with it.

Tool databases that are too big to re-download per scan (trivy's vulnerability
DB, wpscan's) live in a read-only cache dir, filled only by `posint-scanner
update-dbs` (or baked into the Docker image) - never during a scan.
"""

from __future__ import annotations

import atexit
import contextlib
import logging
import lzma
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

from posint_scanner.models import Report

logger = logging.getLogger(__name__)

SCRATCH_DIRNAME = ".posint-scratch"
CACHE_DIRNAME = ".posint-cache"
CACHE_DIR_ENV = "POSINT_CACHE_DIR"

# Highest stdlib ratio; slow, but it runs once per report after the tool is
# done, which is nothing next to the tools' own runtimes.
LZMA_PRESET = 9 | lzma.PRESET_EXTREME
CHUNK_BYTES = 1 << 20

# How often a running tool is checked against its deadline and size limit,
# and how long its process group gets between SIGTERM and SIGKILL.
POLL_SECONDS = 1.0
KILL_GRACE_SECONDS = 5.0

# -- compression ------------------------------------------------------------


def compress_file(path: str | Path) -> Report | None:
    """`path` compressed, streamed in chunks so a huge report never sits in
    memory uncompressed; None if the tool didn't write it."""
    compressor = lzma.LZMACompressor(preset=LZMA_PRESET)
    parts: list[bytes] = []
    raw_size = 0
    try:
        with open(path, "rb") as handle:
            while chunk := handle.read(CHUNK_BYTES):
                raw_size += len(chunk)
                parts.append(compressor.compress(chunk))
    except OSError:
        return None
    parts.append(compressor.flush())
    return Report(data=b"".join(parts), raw_size=raw_size)


def compress_text(text: str) -> Report:
    raw = text.encode("utf-8", errors="surrogatepass")
    return Report(data=lzma.compress(raw, preset=LZMA_PRESET), raw_size=len(raw))


# Receives (target, compressed report) per tool run; None means the run found
# nothing, so any stored report for that target should go.
ReportSink = Callable[[str, Report | None], None]


def emit(
    sink: ReportSink | None,
    target: str,
    findings: Sequence[object],
    *,
    text: str | None = None,
    path: str | Path | None = None,
) -> None:
    """Hand a run's raw report (the file at `path`, else `text`) to `sink`,
    compressed - or None when the run found nothing. Call it before the
    workspace holding `path` is left."""
    if sink is None:
        return
    if not findings:
        sink(target, None)
        return
    report = compress_file(path) if path is not None else None
    sink(target, report or compress_text(text or ""))


def decompress_chunks(data: bytes) -> Iterator[bytes]:
    """A stored report decompressed piece by piece (for streaming downloads)."""
    decompressor = lzma.LZMADecompressor()
    for start in range(0, len(data), CHUNK_BYTES):
        out = decompressor.decompress(data[start:start + CHUNK_BYTES])
        if out:
            yield out


def decompress(data: bytes) -> bytes:
    return lzma.decompress(data)


# -- scratch and cache dirs -------------------------------------------------

_lock = threading.Lock()
_scratch_root: Path | None = None
_cache_root: Path | None = None
_active = 0


def configure(db_path: str | Path) -> None:
    """Point the scratch and cache roots next to the database at `db_path`
    (the cache root can be overridden with $POSINT_CACHE_DIR), and sweep
    leftovers of dead processes. Called at every scan start and on server
    startup."""
    global _scratch_root, _cache_root
    if str(db_path) != ":memory:":  # an in-memory DB has no data dir to use
        base = Path(db_path).resolve().parent
        with _lock:
            _scratch_root = base / SCRATCH_DIRNAME
            _cache_root = Path(os.environ.get(CACHE_DIR_ENV) or base / CACHE_DIRNAME)
    sweep()


def scratch_root() -> Path:
    with _lock:
        return _scratch_root or Path(tempfile.gettempdir()) / SCRATCH_DIRNAME


def cache_dir(tool: str) -> Path:
    """Where `tool`'s downloaded database lives. Read-only during scans."""
    with _lock:
        root = _cache_root or Path(tempfile.gettempdir()) / CACHE_DIRNAME
    return root / tool


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, owned by someone else
    return True


def sweep() -> int:
    """Remove the scratch dirs of processes that are gone (killed before their
    own cleanup ran). Returns how many were removed."""
    root = scratch_root()
    removed = 0
    try:
        entries = list(root.iterdir())
    except OSError:
        return 0
    for entry in entries:
        pid_text = entry.name.removeprefix("run-")
        if entry.name == pid_text or not pid_text.isdigit():
            continue
        if int(pid_text) == os.getpid() or _pid_alive(int(pid_text)):
            continue
        shutil.rmtree(entry, ignore_errors=True)
        removed += 1
    if removed:
        logger.info("removed %d leftover scratch dir(s) under %s", removed, root)
    return removed


def _run_dir() -> Path:
    return scratch_root() / f"run-{os.getpid()}"


@contextlib.contextmanager
def workspace(tool: str) -> Iterator[Path]:
    """A fresh, private dir for one tool run, deleted on exit."""
    global _active
    path = _run_dir() / f"{tool}-{uuid.uuid4().hex[:12]}"
    path.mkdir(parents=True)
    with _lock:
        _active += 1
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)
        with _lock:
            _active -= 1


def release() -> None:
    """Remove this process's scratch dir once no tool is running (end of a
    scan). A concurrent scan in the same process keeps it alive."""
    run_dir = _run_dir()
    with _lock:
        if _active:
            return
    shutil.rmtree(run_dir, ignore_errors=True)


def _remove_run_dir_at_exit() -> None:
    shutil.rmtree(_run_dir(), ignore_errors=True)


atexit.register(_remove_run_dir_at_exit)


# -- running ----------------------------------------------------------------


@dataclass(frozen=True)
class ToolResult:
    returncode: int
    stdout: str
    stderr: str


def tree_size(path: str | Path) -> int:
    total = 0
    for dirpath, _dirnames, filenames in os.walk(path):
        for name in filenames:
            try:
                total += os.lstat(os.path.join(dirpath, name)).st_size
            except OSError:
                pass
    return total


def _kill_group(proc: subprocess.Popen) -> None:
    """SIGTERM the tool's whole process group, SIGKILL whatever is left after
    a grace period. A no-op when the group is already gone."""
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    deadline = time.monotonic() + KILL_GRACE_SECONDS
    while time.monotonic() < deadline:
        proc.poll()  # reap the leader, or its zombie keeps the group "alive"
        try:
            os.killpg(proc.pid, 0)
        except (ProcessLookupError, PermissionError):
            return
        time.sleep(0.1)
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(proc.pid, signal.SIGKILL)


def run_tool(
    cmd: Sequence[str],
    *,
    timeout: float,
    cwd: str | Path,
    env: dict[str, str] | None = None,
    input: str | None = None,
    size_limit: tuple[str | Path, int] | None = None,
) -> ToolResult | None:
    """Run `cmd` in its own process group with `cwd` (a workspace) as its
    working and temp dir; `env` adds to the inherited environment. Returns
    its output, or None (logged) when it couldn't start, ran past `timeout`,
    or grew `size_limit`'s dir beyond its byte cap - the group is killed then.
    Never raises for a failing tool."""
    name = Path(cmd[0]).name
    full_env = {**os.environ, "TMPDIR": str(cwd), **(env or {})}
    try:
        proc = subprocess.Popen(
            list(cmd),
            stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=full_env,
            text=True,
            encoding="utf-8",
            errors="replace",
            start_new_session=True,
        )
    except (OSError, ValueError) as exc:
        logger.warning("%s could not be started: %s", name, exc)
        return None
    deadline = time.monotonic() + timeout
    pending_input = input
    while True:
        try:
            stdout, stderr = proc.communicate(input=pending_input, timeout=POLL_SECONDS)
            break
        except subprocess.TimeoutExpired:
            pending_input = None  # sent on the first call; retries may not resend
            reason = None
            if time.monotonic() >= deadline:
                reason = f"timed out after {timeout:.0f}s"
            elif size_limit and tree_size(size_limit[0]) > size_limit[1]:
                reason = f"exceeded {size_limit[1] // (1024 * 1024)} MB on disk"
            if reason:
                _kill_group(proc)
                proc.communicate()
                logger.warning("%s %s - killed", name, reason)
                return None
    _kill_group(proc)  # children it left running
    return ToolResult(proc.returncode, stdout or "", stderr or "")
