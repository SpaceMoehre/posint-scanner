"""Page latency while scans run - the web UI must stay responsive under them.

    uv run python scripts/bench_web.py [--domains 30] [--ips 60] [--scans 3]

Seeds a synthetic DB (tests/scale_seed.py), then times the main pages with
no scan running, with stand-in scans on threads of the server process (how
scans used to run), and with them in their own processes (ProcessRunner).
A stand-in scan keeps 8 threads busy with pure-Python work, as a real scan's
parsing and fingerprinting does, until cancelled.
"""

from __future__ import annotations

import argparse
import functools
import json
import statistics
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from fastapi.testclient import TestClient  # noqa: E402

from posint_scanner.db import Database  # noqa: E402
from posint_scanner.web import scans  # noqa: E402
from posint_scanner.web.app import create_app  # noqa: E402
from posint_scanner.web.scans import ScanOptions  # noqa: E402
from scale_seed import seed  # noqa: E402

PAGES = ["/", "/overview", "/domains/example1.com", "/ips/10.0.1.1"]
BURN_THREADS = 8


def _burn(is_cancelled) -> None:
    data = {"ports": list(range(200)), "banner": "x" * 500}

    def work() -> None:
        while not is_cancelled():
            json.loads(json.dumps(data))

    threads = [threading.Thread(target=work) for _ in range(BURN_THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def _fake_run_scan(db, domains, sources, control=None, **kw) -> None:
    _burn(control.cancelled)


def burn_child(db_path, config_path, job_id, cancel_event):
    with Database(db_path) as db:
        db.update_scan_job(job_id, status="running")
    _burn(cancel_event.is_set)
    with Database(db_path) as db:
        db.update_scan_job(job_id, status="cancelled")


def _get(client: TestClient, path: str, cap: float) -> float:
    """Milliseconds to load `path`, or inf past `cap` seconds."""
    took: list[float] = []

    def get() -> None:
        start = time.perf_counter()
        assert client.get(path).status_code == 200, path
        took.append((time.perf_counter() - start) * 1000)

    thread = threading.Thread(target=get, daemon=True)
    thread.start()
    thread.join(cap)
    return took[0] if took else float("inf")


def _time_pages(client: TestClient, rounds: int, cap: float) -> dict[str, float]:
    times: dict[str, list[float]] = {p: [] for p in PAGES}
    for _ in range(rounds):
        for path in PAGES:
            times[path].append(_get(client, path, cap))
            if times[path][-1] == float("inf"):
                return {p: statistics.median(t) if t else float("inf") for p, t in times.items()}
    return {p: statistics.median(t) for p, t in times.items()}


def _run(mode: str, db_path: str, config_path: str, n_scans: int, rounds: int,
         cap: float) -> dict:
    runner = {
        "none": scans.ThreadRunner,
        "threads": scans.ThreadRunner,
        "processes": functools.partial(scans.ProcessRunner, target=burn_child),
    }[mode]
    with patch.object(scans, "RUNNER", runner), patch.object(scans, "run_scan", _fake_run_scan):
        client = TestClient(create_app(db_path=db_path, config_path=config_path))
        manager = client.app.state.manager
        jobs = [] if mode == "none" else [
            manager.start(f"scan{i}.example", ScanOptions()) for i in range(n_scans)]
        deadline = time.time() + 30
        while any(manager.get(j.id).status != "running" for j in jobs) and time.time() < deadline:
            time.sleep(0.05)
        time.sleep(0.5)
        try:
            return _time_pages(client, rounds, cap)
        finally:
            for job in jobs:
                manager.cancel(job.id)
            # A capped request still running holds up the scans' exit.
            while manager.busy() and time.time() < deadline + 600:
                time.sleep(0.05)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--domains", type=int, default=30)
    parser.add_argument("--ips", type=int, default=60, help="IPs per domain")
    parser.add_argument("--scans", type=int, default=3)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--cap", type=float, default=20.0, help="seconds before a page counts as timed out")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        db_path = str(Path(tmp) / "bench.db")
        config_path = Path(tmp) / "config.yaml"
        config_path.write_text(f"web:\n  max_parallel_scans: {args.scans}\n")
        with Database(db_path) as db:
            db.init_schema()
            seed(db, args.domains, args.ips, rescans=2)
        print(f"{args.domains} domains x {args.ips} IPs, {args.scans} stand-in scans; "
              f"median ms over {args.rounds} rounds (inf: over {args.cap:g}s)")
        print(f"{'page':28}" + "".join(f"{m:>12}" for m in ("no scan", "threads", "processes")))
        results = {m: _run(m, db_path, str(config_path), args.scans, args.rounds, args.cap)
                   for m in ("none", "threads", "processes")}
        for page in PAGES:
            print(f"{page:28}" + "".join(f"{results[m][page]:12.1f}" for m in results))


if __name__ == "__main__":
    main()
