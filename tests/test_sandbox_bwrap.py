"""The guarantees bwrap itself makes, with a real bwrap - everywhere else
tests run sandboxes as plain dirs (conftest.py). Skipped where bwrap can't
start a sandbox (e.g. a container without user namespaces); CI sets
POSINT_REQUIRE_BWRAP=1 so that fails instead."""

import os
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import pytest

import posint_scanner
from posint_scanner import toolrun

pytestmark = pytest.mark.bwrap


@pytest.fixture(autouse=True)
def real_bwrap(monkeypatch, tmp_path):
    monkeypatch.setattr(toolrun, "_test_root", None)
    monkeypatch.setattr(toolrun, "_probed", False)
    monkeypatch.setattr(toolrun, "_probe_error", None)
    monkeypatch.setattr(toolrun, "_bwrap_size_flag", None)
    data = tmp_path / "data"
    data.mkdir()
    toolrun.configure(data / "posint.db")
    if (error := toolrun.sandbox_error()) is not None:
        if os.environ.get("POSINT_REQUIRE_BWRAP"):
            pytest.fail(f"bwrap sandbox unavailable: {error}")
        pytest.skip(f"bwrap sandbox unavailable: {error}")
    return data


def _sleep_arg() -> str:
    # A sleep duration no other process has, to find it in the host's /proc.
    return f"3600.{uuid.uuid4().int % 10**9:09d}"


def _host_pids(arg: str) -> list[int]:
    pids = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            cmdline = (entry / "cmdline").read_bytes().split(b"\0")
            state = (entry / "stat").read_text().rsplit(")", 1)[1].split()[0]
        except OSError:
            continue
        if arg.encode() in cmdline and state != "Z":
            pids.append(int(entry.name))
    return pids


def _wait(condition, seconds: float = 10.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.05)
    return False


def test_self_check_passes():
    failed = [f"{name}: {detail}" for name, passed, detail in toolrun.self_check() if not passed]
    assert failed == []


def test_nothing_a_tool_writes_reaches_the_host(real_bwrap):
    marker = f"posint-leak-{uuid.uuid4().hex}"
    def data_files():  # the slot files are the scanner's own
        return {p for p in real_bwrap.rglob("*") if toolrun.SLOTS_DIRNAME not in p.parts}

    before = data_files()
    with toolrun.workspace("t") as ws:
        result = toolrun.run_tool(
            ["sh", "-c", f'touch "/tmp/{marker}" "$HOME/{marker}" "$TMPDIR/{marker}" {marker}'
                         f'; touch "{real_bwrap}/{marker}" "{Path.home()}/{marker}" || true'],
            timeout=20, cwd=ws,
        )
        assert result is not None and result.returncode == 0
        assert (ws / marker).exists()  # the scanner sees the workspace
    for where in (Path("/tmp"), Path(tempfile.gettempdir()), Path.home(), real_bwrap):
        assert not (where / marker).exists()
    assert data_files() == before


def test_a_detached_process_is_killed_with_its_run():
    arg = _sleep_arg()
    with toolrun.workspace("t") as ws:
        result = toolrun.run_tool(
            ["sh", "-c", f"setsid sleep {arg} >/dev/null 2>&1 < /dev/null & sleep 1"],
            timeout=20, cwd=ws,
        )
        assert result is not None
        assert _wait(lambda: not _host_pids(arg))


def test_killing_the_scanner_kills_its_sandbox(tmp_path):
    arg = _sleep_arg()
    script = (
        "from posint_scanner import toolrun\n"
        f"toolrun.configure({str(tmp_path / 'child' / 'posint.db')!r})\n"
        "with toolrun.workspace('t') as ws:\n"
        f"    toolrun.run_tool(['sleep', {arg!r}], timeout=600, cwd=ws)\n"
    )
    env = {**os.environ, "PYTHONPATH": str(Path(posint_scanner.__file__).parents[1])}
    (tmp_path / "child").mkdir()
    scanner = subprocess.Popen([sys.executable, "-c", script], env=env)
    try:
        assert _wait(lambda: bool(_host_pids(arg)), 30), "the tool never started"
        scanner.send_signal(signal.SIGKILL)
        scanner.wait()
        assert _wait(lambda: not _host_pids(arg)), "the tool outlived the scanner"
    finally:
        scanner.kill()
        for pid in _host_pids(arg):
            os.kill(pid, signal.SIGKILL)


def test_a_tool_past_the_byte_cap_is_killed():
    toolrun.set_limits(1, 10_000)
    with toolrun.workspace("t") as ws:
        result = toolrun.run_tool(
            ["sh", "-c", "head -c 3000000 /dev/zero > big; sleep 30"], timeout=20, cwd=ws
        )
        assert result is None
        assert toolrun.run_tool(["true"], timeout=10, cwd=ws).returncode == 0
