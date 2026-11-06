"""Web scan jobs run in child processes (web/scans.py ProcessRunner), so a
scan's threads never compete with page requests for the GIL."""

from __future__ import annotations

import functools
import logging
import subprocess
import sys
import time

import pytest

import scan_children
from posint_scanner.db import Database
from posint_scanner.web import scans
from posint_scanner.web.scans import ProcessRunner, ScanManager, ScanOptions

NOTHING = ScanOptions(sources=set(), verify_ports=False, fingerprint=False, netblock_sweep=False,
                      vuln_lookup=False, php2shell=False)


def _manager(tmp_path, target=None, config: str = "") -> ScanManager:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(config)
    runner = functools.partial(ProcessRunner, target=target) if target else ProcessRunner
    return ScanManager(str(tmp_path / "s.db"), str(config_path), runner=runner)


def _wait(manager, job_id, wanted, timeout=30.0) -> str:
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = manager.get(job_id).status
        if status in wanted:
            return status
        time.sleep(0.05)
    return manager.get(job_id).status


def test_a_scan_runs_to_completion_in_its_own_process(tmp_path):
    manager = _manager(tmp_path)
    job = manager.start("example.invalid", NOTHING)
    assert _wait(manager, job.id, {"completed", "failed"}) == "completed"
    assert manager.get(job.id).finished_at is not None
    assert not manager.busy()


def test_a_crashed_scan_process_is_marked_failed(tmp_path):
    manager = _manager(tmp_path, scan_children.crashes)
    job = manager.start("example.com", NOTHING)
    assert _wait(manager, job.id, {"failed"}) == "failed"
    assert "exited with code 3" in manager.get(job.id).error
    assert manager.get(job.id).resumable


def test_cancel_reaches_the_scan_process(tmp_path):
    manager = _manager(tmp_path, scan_children.waits)
    job = manager.start("example.com", NOTHING)
    _wait(manager, job.id, {"running"})
    manager.cancel(job.id)
    assert _wait(manager, job.id, {"cancelled"}, timeout=10) == "cancelled"


def test_a_job_cancelled_before_its_process_starts_ends_cancelled(tmp_path, monkeypatch):
    monkeypatch.setattr(scans, "CANCEL_GRACE_SECONDS", 0.2)
    manager = _manager(tmp_path, scan_children.ignores_cancel)
    job = manager.start("example.com", NOTHING)
    manager.cancel(job.id)
    assert _wait(manager, job.id, {"cancelled", "failed"}, timeout=10) == "cancelled"


def test_a_scan_ignoring_its_cancel_is_killed(tmp_path, monkeypatch):
    monkeypatch.setattr(scans, "CANCEL_GRACE_SECONDS", 0.2)
    manager = _manager(tmp_path, scan_children.ignores_cancel)
    job = manager.start("example.com", NOTHING)
    _wait(manager, job.id, {"running"})
    manager.cancel(job.id)
    assert _wait(manager, job.id, {"cancelled"}, timeout=10) == "cancelled"


def test_jobs_past_the_parallel_limit_wait_their_turn(tmp_path):
    manager = _manager(tmp_path, scan_children.waits, "web:\n  max_parallel_scans: 1\n")
    first = manager.start("one.example", NOTHING)
    second = manager.start("two.example", NOTHING)
    _wait(manager, first.id, {"running"})
    time.sleep(0.5)
    assert manager.get(second.id).status == "pending"
    manager.cancel(first.id)
    assert _wait(manager, second.id, {"running"}) == "running"
    manager.cancel(second.id)
    assert _wait(manager, second.id, {"cancelled"}) == "cancelled"


def test_a_queued_job_is_cancelled_without_running(tmp_path):
    manager = _manager(tmp_path, scan_children.waits, "web:\n  max_parallel_scans: 1\n")
    first = manager.start("one.example", NOTHING)
    second = manager.start("two.example", NOTHING)
    assert manager.cancel(second.id).status == "cancelled"
    manager.cancel(first.id)
    assert _wait(manager, first.id, {"cancelled"}) == "cancelled"
    time.sleep(0.5)
    assert manager.get(second.id).status == "cancelled"


def test_the_scan_process_logs_through_the_server(tmp_path, caplog):
    caplog.set_level(logging.INFO)
    manager = _manager(tmp_path, scan_children.logs)
    job = manager.start("example.com", NOTHING)
    _wait(manager, job.id, {"completed"})
    deadline = time.time() + 5
    while "hello from scan" not in caplog.text and time.time() < deadline:
        time.sleep(0.05)
    assert f"hello from scan {job.id}" in caplog.text


def _server(db_path: str, then: str) -> subprocess.Popen:
    """A process running a ScanManager with one stuck scan, which runs
    `then` once the scan is running."""
    return subprocess.Popen([sys.executable, "-c", f"""
import atexit, functools, sys, time
# Runs last at exit (hooks run in reverse), after multiprocessing has
# terminated the scan: time for anything reacting to that to write the DB.
atexit.register(time.sleep, 1)
sys.path[:0] = {sys.path!r}
import scan_children
from posint_scanner.db import Database
from posint_scanner.web.scans import ProcessRunner, ScanManager, ScanOptions
manager = ScanManager({db_path!r}, "none.yaml",
                      runner=functools.partial(ProcessRunner, target=scan_children.ignores_cancel))
job = manager.start("example.com", ScanOptions())
while manager.get(job.id).status != "running":
    time.sleep(0.05)
{then}
"""])


def _running_job(db_path: str) -> dict:
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            with Database(db_path) as db:
                rows = db.list_scan_jobs(1)
        except Exception:  # noqa: BLE001 - the server is still creating the DB
            rows = []
        if rows and rows[0]["status"] == "running":
            return dict(rows[0])
        time.sleep(0.1)
    raise AssertionError("the scan never started")


def test_a_scan_process_dies_with_the_server(tmp_path):
    db_path = str(tmp_path / "s.db")
    server = _server(db_path, "time.sleep(60)")
    try:
        scan_pid = int(_running_job(db_path)["stage"])
    finally:
        server.kill()
        server.wait()
    deadline = time.time() + 10
    while time.time() < deadline and _alive(scan_pid):
        time.sleep(0.05)
    assert not _alive(scan_pid)


def test_a_scan_cut_off_by_server_exit_is_resumable(tmp_path):
    db_path = str(tmp_path / "s.db")
    server = _server(db_path, "sys.exit(0)")
    assert server.wait(timeout=30) == 0
    with Database(db_path) as db:
        assert db.list_scan_jobs(1)[0]["status"] == "running"  # not failed
    manager = ScanManager(db_path, str(tmp_path / "none.yaml"))
    assert manager.list()[0].status == "interrupted"


def _alive(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] != "Z"
    except FileNotFoundError:
        return False


@pytest.fixture(autouse=True)
def _no_leftover_children():
    yield
    import multiprocessing

    for child in multiprocessing.active_children():
        child.kill()
