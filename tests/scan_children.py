"""Stand-in scan processes for test_scan_processes.py: entry points with
web.scans._child_main's signature that misbehave on purpose. A spawned
child imports them by module name (spawn hands it the test's sys.path)."""

from __future__ import annotations

import logging
import os
import time

from posint_scanner.db import Database


def _mark_running(db_path: str, job_id: str) -> None:
    """Running, with the process's pid as its stage."""
    with Database(db_path) as db:
        db.update_scan_job(job_id, stage=str(os.getpid()))
        db.update_scan_job(job_id, only_if_status=("pending",), status="running")


def ignores_cancel(db_path, config_path, job_id, cancel_event):
    _mark_running(db_path, job_id)
    time.sleep(60)


def crashes(db_path, config_path, job_id, cancel_event):
    _mark_running(db_path, job_id)
    os._exit(3)


def logs(db_path, config_path, job_id, cancel_event):
    logging.getLogger("posint_scanner.test_child").warning("hello from scan %s", job_id)
    with Database(db_path) as db:
        db.update_scan_job(job_id, status="completed")


def waits(db_path, config_path, job_id, cancel_event):
    """Runs until cancelled, as a well-behaved scan does."""
    _mark_running(db_path, job_id)
    cancel_event.wait(30)
    with Database(db_path) as db:
        db.update_scan_job(job_id, status="cancelled" if cancel_event.is_set() else "completed")
