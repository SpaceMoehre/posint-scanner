"""Running external tools so they can't leave anything behind.

During a scan the database is the only thing that may grow. Every external
tool (nikto, trivy, theHarvester, ping, ...) therefore runs in a throwaway
bubblewrap sandbox:

- `/` is mounted read-only, so the tool can't write anywhere on disk;
- `/tmp` is a fresh tmpfs holding the workspaces (`/tmp/work/...`), HOME
  (`/tmp/home`) and TMPDIR - everything a tool writes lands there;
- the sandbox has its own PID namespace: when it ends, the kernel kills every
  process still in it and frees the tmpfs, files left open included. Nothing
  depends on a `finally` running - `--die-with-parent` ends the sandbox even
  when this process is killed outright.

`workspace()` is a sandbox's lifetime. Inside it an agent process
(sandbox_agent.py) runs the tools `run_tool()` sends it, and this process
reads and writes the sandbox's files through an fd the agent hands over -
the `Path` a workspace yields is `/proc/self/fd/<n>/work/<tool>-<id>`, so
callers parse reports in place, before the sandbox is gone. Paths under it
in a tool's arguments, cwd and env are translated to the sandbox's view
(`/tmp/work/...`). A `workspace()` nested in another on the same thread
shares the outer sandbox, so a clone can be scanned by several tools.

At most HEAVY_SLOTS sandboxes exist at once across every process sharing a
data dir (CLI scans, the web server): each holds an flock on one of the slot
files in `<db dir>/.posint-slots`, released by the kernel if the holder
dies. Each sandbox's tmpfs is capped (`sandbox:` in config.yaml): a tool
pushing it past `size_mb` or `max_inodes` is killed.

Small one-shot tools (ping, searchsploit, subfinder) use `run_light()`: a
sandbox of their own around a single command, with a small tmpfs, not
counted against the slots.

Without a working bwrap there is no fallback: `which()` reports every tool
missing, so each stage skips as if its binary weren't installed, and
`sandbox_error()` says why (logged once, shown in the web UI).
`posint-scanner sandbox-check` tests the sandbox where it will run.

Tool databases that are too big to re-download per scan (trivy's vulnerability
DB, wpscan's) live in a read-only cache dir, filled only by `posint-scanner
update-dbs` (which the Docker image runs on first start) - never during a
scan.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import logging
import lzma
import os
import re
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

from posint_scanner.models import Report

logger = logging.getLogger(__name__)

CACHE_DIRNAME = ".posint-cache"
CACHE_DIR_ENV = "POSINT_CACHE_DIR"
SLOTS_DIRNAME = ".posint-slots"
# Where versions before the sandbox put tool workspaces; removed on sight.
LEGACY_SCRATCH_DIRNAME = ".posint-scratch"

# The sandbox's tmpfs, as seen inside it.
SANDBOX_BASE = "/tmp"
AGENT = Path(__file__).with_name("sandbox_agent.py")

# How many workspace sandboxes may exist at once, across processes.
HEAVY_SLOTS = 4
SLOT_WAIT_SECONDS = 0.5
DEFAULT_SIZE_MB = 1024
DEFAULT_MAX_INODES = 200_000
# run_light()'s tmpfs. Without an agent only the byte cap applies (bwrap's
# --size); its tools write next to nothing and run under short timeouts.
LIGHT_SIZE_MB = 16
# The agent's start, and how long past a run's own timeout (plus the kill
# grace) its answer may take before the sandbox counts as hung.
START_TIMEOUT_SECONDS = 30
REPLY_GRACE_SECONDS = 60

# Highest stdlib ratio; slow, but it runs once per report after the tool is
# done, which is nothing next to the tools' own runtimes.
LZMA_PRESET = 9 | lzma.PRESET_EXTREME
CHUNK_BYTES = 1 << 20

# How long a light tool's process group gets between SIGTERM and SIGKILL
# (the agent uses the same grace for workspace tools).
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


# -- configuration ----------------------------------------------------------

_lock = threading.Lock()
_cache_root: Path | None = None
_slots_dir: Path | None = None
_limits = (DEFAULT_SIZE_MB * 1024 * 1024, DEFAULT_MAX_INODES)
# Tests only: sandboxes become plain dirs under this root and tools run
# without bwrap - no isolation, but the same agent and plumbing.
_test_root: Path | None = None


def configure(db_path: str | Path) -> None:
    """Point the cache dir (overridable with $POSINT_CACHE_DIR) and the slot
    files next to the database at `db_path`, and remove an older version's
    scratch dir. Called at every scan start and on server startup."""
    global _cache_root, _slots_dir
    if str(db_path) == ":memory:":  # an in-memory DB has no data dir to use
        return
    base = Path(db_path).resolve().parent
    with _lock:
        _cache_root = Path(os.environ.get(CACHE_DIR_ENV) or base / CACHE_DIRNAME)
        _slots_dir = base / SLOTS_DIRNAME
    legacy = base / LEGACY_SCRATCH_DIRNAME
    if legacy.is_dir():
        shutil.rmtree(legacy, ignore_errors=True)
        logger.info("removed %s (an older version's tool scratch dir)", legacy)


def set_limits(size_mb: int, max_inodes: int) -> None:
    """Cap each workspace sandbox's tmpfs (config.yaml `sandbox:`)."""
    global _limits
    with _lock:
        _limits = (size_mb * 1024 * 1024, max_inodes)


def cache_dir(tool: str) -> Path:
    """Where `tool`'s downloaded database lives. Read-only during scans."""
    with _lock:
        root = _cache_root or Path(tempfile.gettempdir()) / CACHE_DIRNAME
    return root / tool


# -- the sandbox ------------------------------------------------------------


class SandboxUnavailable(RuntimeError):
    """bwrap can't create a sandbox here; no tool may run."""


@dataclass(frozen=True)
class ToolResult:
    returncode: int
    stdout: str
    stderr: str


_bwrap_size_flag: bool | None = None


def _bwrap_argv(max_bytes: int, writable: Sequence[str | Path] = ()) -> list[str]:
    """bwrap up to the `--` before the command: read-only `/`, a tmpfs on
    /tmp (capped where bwrap supports --size), own PID/IPC namespaces, no
    capabilities, gone with this process. `writable` paths stay writable."""
    global _bwrap_size_flag
    bwrap = shutil.which("bwrap") or "bwrap"
    if _bwrap_size_flag is None:
        try:
            help_text = subprocess.run([bwrap, "--help"], capture_output=True, text=True).stdout
        except OSError:
            help_text = ""
        _bwrap_size_flag = "--size" in help_text
    argv = [
        bwrap,
        # A user namespace where possible; when bwrap may not create one but
        # runs with CAP_SYS_ADMIN (a privileged container) it does without.
        "--unshare-user-try",
        "--unshare-pid",
        "--unshare-ipc",
        "--die-with-parent",
        "--new-session",
        # uid 0 inside would keep every capability - enough to remount `/`
        # writable. Tools get none.
        "--cap-drop", "ALL",
        "--ro-bind", "/", "/",
        "--dev", "/dev",
        "--proc", "/proc",
    ]
    if _bwrap_size_flag:
        argv += ["--size", str(max_bytes)]
    argv += ["--tmpfs", SANDBOX_BASE]
    for path in writable:
        argv += ["--bind", str(path), str(path)]
    return [*argv, "--chdir", SANDBOX_BASE, "--"]


def _tool_env(base: str, env: dict[str, str] | None) -> dict[str, str]:
    return {
        **os.environ,
        "TMPDIR": base,
        "HOME": f"{base}/home",
        "XDG_CONFIG_HOME": f"{base}/home/.config",
        "XDG_CACHE_HOME": f"{base}/home/.cache",
        "XDG_DATA_HOME": f"{base}/home/.local/share",
        **(env or {}),
    }


def _read_output(path: Path) -> str:
    # As subprocess's text mode would have decoded it.
    try:
        raw = path.read_bytes()
    except OSError:
        return ""
    return raw.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")


class _Box:
    """One sandbox with its agent. `host_base` is the sandbox's tmpfs as this
    process sees it, `inside_base` as tools see it."""

    def __init__(self, max_bytes: int, max_inodes: int, writable: Sequence[str | Path] = ()) -> None:
        self.max_bytes = max_bytes
        self.max_inodes = max_inodes
        self._broken = False
        self._scratch: Path | None = None
        ours, theirs = socket.socketpair()
        fd = theirs.fileno()
        agent = [sys.executable, "-I", str(AGENT)]
        if _test_root is None:
            self.inside_base = SANDBOX_BASE
            argv = [*_bwrap_argv(max_bytes, writable), *agent,
                    SANDBOX_BASE, str(fd), "statvfs", "--pidns"]
        else:
            _test_root.mkdir(parents=True, exist_ok=True)
            self._scratch = Path(tempfile.mkdtemp(prefix="box-", dir=_test_root))
            self.inside_base = str(self._scratch)
            argv = [*agent, self.inside_base, str(fd), "walk"]
        try:
            self._proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                pass_fds=(fd,),
                start_new_session=True,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
        except OSError as exc:
            ours.close()
            self._remove_scratch()
            raise SandboxUnavailable(f"bwrap could not be started: {exc}") from exc
        finally:
            theirs.close()
        assert self._proc.stdin and self._proc.stdout and self._proc.stderr
        self._stdin, self._stdout, self._stderr = (
            self._proc.stdin, self._proc.stdout, self._proc.stderr
        )
        # The agent's first act is handing over its tmpfs; an empty read
        # means it (or bwrap) died first.
        fds: list[int] = []
        try:
            ours.settimeout(START_TIMEOUT_SECONDS)
            _msg, fds, _flags, _addr = socket.recv_fds(ours, 16, 1)
        except OSError:
            pass
        finally:
            ours.close()
        if not fds:
            self._kill()
            detail = self._stderr.read().decode("utf-8", errors="replace").strip()
            for pipe in (self._stdin, self._stdout, self._stderr):
                pipe.close()
            self._remove_scratch()
            raise SandboxUnavailable(f"sandbox did not start: {detail[-300:] or 'no output'}")
        self._root_fd = fds[0]
        self.host_base = Path(f"/proc/self/fd/{self._root_fd}")
        self._host_prefix = re.compile(re.escape(str(self.host_base)) + r"(?=/|$)")

    def inside(self, value: str) -> str:
        """`value` with host-side paths into the sandbox in the tools' view."""
        return self._host_prefix.sub(self.inside_base, value)

    def new_dir(self, tool: str) -> Path:
        path = self.host_base / "work" / f"{tool}-{uuid.uuid4().hex[:12]}"
        path.mkdir()
        return path

    def run(
        self,
        cmd: Sequence[str],
        *,
        timeout: float,
        cwd: str | Path,
        env: dict[str, str] | None,
        input: str | None,
        size_limit: tuple[str | Path, int] | None,
    ) -> ToolResult | None:
        name = Path(cmd[0]).name
        if self._broken:
            logger.warning("%s not run: its sandbox stopped responding earlier", name)
            return None
        request = {
            "cmd": [self.inside(str(arg)) for arg in cmd],
            "cwd": self.inside(str(cwd)),
            "env": {k: self.inside(v) for k, v in _tool_env(self.inside_base, env).items()},
            "input": input,
            "timeout": timeout,
            "max_bytes": self.max_bytes,
            "max_inodes": self.max_inodes,
            "size_limit": (
                [self.inside(str(size_limit[0])), size_limit[1]] if size_limit else None
            ),
        }
        try:
            self._stdin.write((json.dumps(request) + "\n").encode())
            self._stdin.flush()
            line = self._read_line(timeout + 3 * KILL_GRACE_SECONDS + REPLY_GRACE_SECONDS)
        except (OSError, ValueError):
            line = None
        if line is None:
            self._broken = True
            self._kill()
            logger.warning("%s: its sandbox stopped responding - killed", name)
            return None
        reply = json.loads(line)
        agent_dir = self.host_base / ".agent"
        stdout = _read_output(agent_dir / "stdout")
        stderr = _read_output(agent_dir / "stderr")
        for leftover in ("stdout", "stderr"):
            (agent_dir / leftover).unlink(missing_ok=True)
        if "error" in reply:
            killed = not reply["error"].startswith("could not be started")
            logger.warning("%s %s%s", name, reply["error"], " - killed" if killed else "")
            return None
        return ToolResult(reply["returncode"], stdout, stderr)

    def _read_line(self, timeout: float) -> str | None:
        fd = self._stdout.fileno()
        buf = b""
        deadline = time.monotonic() + timeout
        while not buf.endswith(b"\n"):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
                return None
            chunk = os.read(fd, 65536)
            if not chunk:
                return None
            buf += chunk
        return buf.decode()

    def close(self) -> None:
        """End the sandbox: the agent kills what's left in it and exits, and
        the kernel drops the tmpfs."""
        with contextlib.suppress(OSError):
            self._stdin.close()
        try:
            self._proc.wait(timeout=3 * KILL_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            self._kill()
        os.close(self._root_fd)
        for pipe in (self._stdout, self._stderr):
            pipe.close()
        self._remove_scratch()

    def _kill(self) -> None:
        # bwrap's own process; --die-with-parent takes the sandbox with it.
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(self._proc.pid, signal.SIGKILL)
        self._proc.wait()

    def _remove_scratch(self) -> None:
        if self._scratch is not None:
            shutil.rmtree(self._scratch, ignore_errors=True)


_probe_lock = threading.Lock()
_probed = False
_probe_error: str | None = None


def _probe() -> str | None:
    if _test_root is None and shutil.which("bwrap") is None:
        return "bwrap (bubblewrap) is not installed"
    try:
        box = _Box(LIGHT_SIZE_MB * 1024 * 1024, 1000)
    except SandboxUnavailable as exc:
        return str(exc)
    try:
        (box.host_base / "work" / "probe").write_text("ok")
        result = box.run(
            [shutil.which("cat") or "/bin/cat", "probe"], timeout=30,
            cwd=box.host_base / "work", env=None, input=None, size_limit=None,
        )
        if result is None or result.stdout != "ok":
            return "a test command in the sandbox failed"
    except OSError as exc:
        return f"the sandbox's files are not reachable: {exc}"
    finally:
        box.close()
    return None


def sandbox_error() -> str | None:
    """Why no tool can run (bwrap missing or blocked), or None. Probed once
    per process, by actually starting a sandbox."""
    global _probed, _probe_error
    if _test_root is not None:
        return None
    with _probe_lock:
        if not _probed:
            _probe_error = _probe()
            _probed = True
            if _probe_error:
                logger.error(
                    "tool sandbox unavailable (%s) - every external tool is skipped. "
                    "Run `posint-scanner sandbox-check`; see the README's \"Tool sandbox\"",
                    _probe_error,
                )
        return _probe_error


def which(binary: str) -> str | None:
    """`binary`'s path - or None, as if it weren't installed, when tools
    can't be sandboxed."""
    path = shutil.which(binary)
    if path is None or sandbox_error() is not None:
        return None
    return path


@contextlib.contextmanager
def _slot() -> Iterator[None]:
    """Hold one of the HEAVY_SLOTS slot files (waiting for a free one)."""
    with _lock:
        slots = _slots_dir or Path(tempfile.gettempdir()) / SLOTS_DIRNAME
    slots.mkdir(parents=True, exist_ok=True)
    waiting = False
    while True:
        for index in range(HEAVY_SLOTS):
            handle = open(slots / f"slot-{index}", "a")
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                handle.close()
                continue
            try:
                yield
            finally:
                handle.close()  # releases the lock
            return
        if not waiting:
            waiting = True
            logger.info("all %d tool sandboxes busy - waiting for one", HEAVY_SLOTS)
        time.sleep(SLOT_WAIT_SECONDS)


_local = threading.local()


@contextlib.contextmanager
def workspace(
    tool: str, *, writable: Sequence[str | Path] = (), size_mb: int | None = None
) -> Iterator[Path]:
    """A fresh dir for `tool` in a sandbox that lives as long as this block;
    `run_tool()` runs commands in it. Nested in another workspace on the same
    thread, it's a new dir in the same sandbox. `writable` (host paths that
    stay writable) and `size_mb` (overriding the configured cap) apply to an
    outermost workspace only. Raises SandboxUnavailable without a sandbox -
    callers find their binary with `which()` first, which then says none."""
    box: _Box | None = getattr(_local, "box", None)
    if box is not None:
        if writable or size_mb:
            raise ValueError("writable/size_mb need an outermost workspace")
        path = box.new_dir(tool)
        try:
            yield path
        finally:
            shutil.rmtree(path, ignore_errors=True)
        return
    if (error := sandbox_error()) is not None:
        raise SandboxUnavailable(error)
    with _lock:
        max_bytes, max_inodes = _limits
    if size_mb:
        max_bytes = size_mb * 1024 * 1024
    with _slot():
        box = _Box(max_bytes, max_inodes, writable)
        _local.box = box
        try:
            yield box.new_dir(tool)
        finally:
            _local.box = None
            box.close()


def run_tool(
    cmd: Sequence[str],
    *,
    timeout: float,
    cwd: str | Path,
    env: dict[str, str] | None = None,
    input: str | None = None,
    size_limit: tuple[str | Path, int] | None = None,
) -> ToolResult | None:
    """Run `cmd` in this thread's workspace sandbox, in `cwd` (a workspace),
    in its own process group; `env` adds to the inherited environment (whose
    HOME and TMPDIR point into the sandbox). Returns its output, or None
    (logged) when it couldn't start, ran past `timeout`, grew `size_limit`'s
    dir beyond its byte cap or the sandbox beyond its caps - the group is
    killed then. Never raises for a failing tool."""
    return _box().run(cmd, timeout=timeout, cwd=cwd, env=env, input=input, size_limit=size_limit)


def run_light(
    cmd: Sequence[str], *, timeout: float, env: dict[str, str] | None = None
) -> ToolResult | None:
    """Run one small command in a sandbox of its own (small tmpfs, no slot),
    gone when it exits. Returns its output, or None (logged) when no sandbox
    is available, it couldn't start or ran past `timeout`."""
    if (error := sandbox_error()) is not None:
        logger.warning("%s not run: %s", Path(cmd[0]).name, error)
        return None
    if _test_root is not None:
        _test_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=_test_root) as base:
            return _run_process(list(cmd), Path(cmd[0]).name, timeout, base, _tool_env(base, env))
    argv = [*_bwrap_argv(LIGHT_SIZE_MB * 1024 * 1024), *cmd]
    return _run_process(argv, Path(cmd[0]).name, timeout, None, _tool_env(SANDBOX_BASE, env))


def _kill_group(proc: subprocess.Popen) -> None:
    """SIGTERM the process group, SIGKILL whatever is left after a grace
    period. A no-op when the group is already gone."""
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


def _run_process(
    argv: list[str], name: str, timeout: float, cwd: str | None, env: dict[str, str]
) -> ToolResult | None:
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=env,
            text=True,
            encoding="utf-8",
            errors="replace",
            start_new_session=True,
        )
    except (OSError, ValueError) as exc:
        logger.warning("%s could not be started: %s", name, exc)
        return None
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        proc.communicate()
        logger.warning("%s timed out after %.0fs - killed", name, timeout)
        return None
    _kill_group(proc)  # children it left running
    return ToolResult(proc.returncode, stdout or "", stderr or "")


# -- self-check -------------------------------------------------------------


def self_check() -> list[tuple[str, bool, str]]:
    """Exercise the sandbox where it runs (`posint-scanner sandbox-check`):
    (check, passed, detail) per guarantee the module docstring makes."""
    if (error := sandbox_error()) is not None:
        return [("sandbox starts", False, error)]
    results: list[tuple[str, bool, str]] = [("sandbox starts", True, "")]

    def check(name: str, passed: bool, detail: str = "") -> None:
        results.append((name, passed, "" if passed else detail))

    def sh(script: str, cwd: Path, timeout: float = 20) -> ToolResult | None:
        return run_tool(["sh", "-c", script], timeout=timeout, cwd=cwd)

    with _lock:
        data_dir = _slots_dir.parent if _slots_dir else None
    with workspace("check") as ws:
        (ws / "in.txt").write_text("hello")
        result = sh("cat in.txt > out.txt", ws)
        out = ws / "out.txt"
        check("tools and the scanner share the workspace",
              result is not None and out.exists() and out.read_text() == "hello",
              f"result {result}")

        targets = ["/"] + ([str(data_dir)] if data_dir else [])
        for target in targets:
            probe = Path(target) / f".posint-sandbox-check-{uuid.uuid4().hex[:8]}"
            result = sh(f'echo x > "{probe}"', ws)
            leaked = probe.exists()
            probe.unlink(missing_ok=True)
            check(f"{target} is read-only to tools",
                  result is not None and result.returncode != 0 and not leaked,
                  f"a tool wrote {probe}")

        result = sh('touch "$HOME/h" "$TMPDIR/t" && echo ok', ws)
        home = _box().host_base
        check("HOME and TMPDIR are in the sandbox's tmpfs",
              result is not None and result.stdout.strip() == "ok"
              and (home / "home" / "h").exists() and (home / "t").exists(),
              f"result {result}")

        # A child in a session of its own escapes the tool's process group;
        # the PID namespace must catch it.
        result = sh("setsid sleep 300 >/dev/null 2>&1 < /dev/null & echo $!; sleep 1", ws)
        pid = result.stdout.strip() if result else ""
        result = sh(f"test -e /proc/{pid} && echo alive || echo gone", ws) if pid.isdigit() else None
        check("processes a tool leaves behind are killed after its run",
              result is not None and result.stdout.strip() == "gone",
              f"a detached `sleep` (pid {pid or '?'}) survived")

    proc_ok = True
    with _slot():
        box = _Box(LIGHT_SIZE_MB * 1024 * 1024, 200)
        try:
            killed = box.run(
                ["sh", "-c", "i=0; while [ $i -lt 2000 ]; do : > f$i; i=$((i+1)); done; sleep 30"],
                timeout=25, cwd=box.host_base / "work", env=None, input=None, size_limit=None,
            ) is None
        finally:
            box.close()
            proc_ok = box._proc.poll() is not None
    check("a tool past the inode cap is killed", killed, "it ran on")
    check("the sandbox's processes are gone after it closes", proc_ok, "bwrap still running")

    result = run_light(["sh", "-c", "echo ok"], timeout=20)
    check("one-shot sandboxes run", result is not None and result.stdout.strip() == "ok",
          f"result {result}")
    if ping := shutil.which("ping"):
        result = run_light([ping, "-c", "1", "-W", "2", "127.0.0.1"], timeout=10)
        check("ping works in a sandbox (the ping source needs it)",
              result is not None and result.returncode == 0,
              (result.stderr or result.stdout).strip()[-200:] if result else "did not finish")
    return results


def _box() -> _Box:
    box: _Box | None = getattr(_local, "box", None)
    if box is None:
        raise RuntimeError("no toolrun.workspace() on this thread")
    return box
