"""A scan may only write to the database: external tools run in scratch
workspaces that are removed, their reports land compressed in tool_outputs,
and nothing they start outlives them."""

import json
import os
import stat
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from posint_scanner import toolrun
from posint_scanner.db import Database
from posint_scanner.models import DiscoveredHostname
from posint_scanner.orchestrator import run_scan
from posint_scanner.sources.base import Source

TAKEOVER_REPORT = {"domains": {"api.example.com": {"service": "github", "error": "gone"}}}


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # A zombie still answers kill(0); it isn't running any more.
    try:
        return Path(f"/proc/{pid}/stat").read_text().split()[2] != "Z"
    except OSError:
        return False


def _wait_dead(pid: int, seconds: float = 3.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not _alive(pid):
            return True
        time.sleep(0.05)
    return False


def _script(path: Path, body: str) -> Path:
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


def _tree(root: Path) -> set[str]:
    return {str(p.relative_to(root)) for p in root.rglob("*")}


class TestCompression:
    def test_file_round_trip(self, tmp_path):
        raw = json.dumps([{"id": i, "title": "finding"} for i in range(5000)]).encode()
        path = tmp_path / "report.json"
        path.write_bytes(raw)
        report = toolrun.compress_file(path)
        assert report.raw_size == len(raw)
        assert len(report.data) < len(raw) / 10  # repetitive JSON compresses hard
        assert toolrun.decompress(report.data) == raw
        assert b"".join(toolrun.decompress_chunks(report.data)) == raw

    def test_missing_file_is_none(self, tmp_path):
        assert toolrun.compress_file(tmp_path / "absent.json") is None

    def test_emit_sends_none_without_findings(self):
        seen = []
        toolrun.emit(lambda t, r: seen.append((t, r)), "x", [], text="noise")
        toolrun.emit(lambda t, r: seen.append((t, r)), "y", [1], text="report")
        assert seen[0] == ("x", None)
        assert toolrun.decompress(seen[1][1].data) == b"report"


class TestWorkspace:
    def test_removed_after_use_and_on_error(self):
        with toolrun.workspace("t") as first:
            (first / "file").write_text("x")
        assert not first.exists()
        with pytest.raises(RuntimeError), toolrun.workspace("t") as second:
            raise RuntimeError
        assert not second.exists()

    def test_sweep_removes_dead_runs_only(self):
        root = toolrun.scratch_root()
        dead = root / "run-999999999"
        own = root / f"run-{os.getpid()}"
        live = root / f"run-{os.getppid()}"
        for path in (dead, own, live):
            (path / "tool-x").mkdir(parents=True)
        assert toolrun.sweep() == 1
        assert not dead.exists()
        assert own.exists() and live.exists()

    def test_configure_points_next_to_the_db(self, tmp_path):
        toolrun.configure(tmp_path / "data" / "posint.db")
        assert toolrun.scratch_root() == (tmp_path / "data" / ".posint-scratch").resolve()
        assert toolrun.cache_dir("trivy") == (tmp_path / "data" / ".posint-cache" / "trivy").resolve()


class TestRunTool:
    def test_output_and_tmpdir(self, tmp_path):
        with toolrun.workspace("t") as ws:
            result = toolrun.run_tool(["sh", "-c", 'echo "$TMPDIR"; cat'], timeout=10, cwd=ws,
                                      input="in")
        assert result.returncode == 0
        assert result.stdout == f"{ws}\nin"

    def test_timeout_kills_the_whole_group(self, tmp_path):
        pidfile = tmp_path / "child.pid"
        with toolrun.workspace("t") as ws:
            result = toolrun.run_tool(
                ["sh", "-c", f"sleep 60 & echo $! > {pidfile}; wait"], timeout=1, cwd=ws
            )
        assert result is None
        assert _wait_dead(int(pidfile.read_text()))

    def test_children_left_behind_are_killed(self, tmp_path):
        pidfile = tmp_path / "child.pid"
        with toolrun.workspace("t") as ws:
            result = toolrun.run_tool(
                ["sh", "-c", f"sleep 60 >/dev/null 2>&1 & echo $! > {pidfile}"], timeout=10, cwd=ws
            )
        assert result is not None and result.returncode == 0
        assert _wait_dead(int(pidfile.read_text()))

    def test_size_limit_kills(self):
        with toolrun.workspace("t") as ws:
            result = toolrun.run_tool(
                ["sh", "-c", "head -c 3000000 /dev/zero > big; sleep 30"],
                timeout=20, cwd=ws, size_limit=(ws, 1_000_000),
            )
        assert result is None

    def test_missing_binary_is_none(self):
        with toolrun.workspace("t") as ws:
            assert toolrun.run_tool(["/nonexistent/tool"], timeout=5, cwd=ws) is None


class TestToolOutputs:
    @pytest.fixture
    def db(self):
        database = Database(":memory:")
        database.init_schema()
        yield database
        database.close()

    def test_rescan_overwrites_and_empty_run_deletes(self, db):
        domain_id = db.upsert_domain("example.com")
        db.save_tool_output(domain_id, "nikto", "https://a/", toolrun.compress_text("old"))
        db.save_tool_output(domain_id, "nikto", "https://a/", toolrun.compress_text("new"))
        rows = db.list_tool_outputs(domain_id)
        assert len(rows) == 1
        assert toolrun.decompress(db.get_tool_output(rows[0]["id"])["content"]) == b"new"
        db.save_tool_output(domain_id, "nikto", "https://a/", None)
        assert db.list_tool_outputs(domain_id) == []

    def test_domain_delete_removes_reports(self, db):
        domain_id = db.upsert_domain("example.com")
        db.save_tool_output(domain_id, "trivy", "img", toolrun.compress_text("x"))
        db.delete_domain(domain_id)
        assert db.conn.execute("SELECT COUNT(*) FROM tool_outputs").fetchone()[0] == 0


class Discovery(Source):
    name = "fake-discovery"

    def discover(self, domain):
        return [DiscoveredHostname(name=f"api.{domain}", source=self.name)]


class TestScanWritesOnlyTheDatabase:
    def test_tool_files_end_up_in_the_db_and_nowhere_else(self, tmp_path, monkeypatch):
        data = tmp_path / "data"
        data.mkdir()
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        pidfile = tmp_path / "child.pid"
        # A takeover that writes its report, litters $TMPDIR and leaves a
        # child running - everything a misbehaving tool might do.
        _script(bin_dir / "takeover", f"""
out=""
while [ $# -gt 0 ]; do [ "$1" = "-o" ] && out="$2"; shift; done
echo '{json.dumps(TAKEOVER_REPORT)}' > "$out"
echo junk > "$TMPDIR/junk"
sleep 60 >/dev/null 2>&1 &
echo $! > {pidfile}
""")
        monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
        # A run killed earlier left its scratch dir behind.
        stale = data / ".posint-scratch" / "run-999999999" / "nikto-x"
        stale.mkdir(parents=True)

        db = Database(data / "posint.db")
        db.init_schema()
        before = _tree(data)
        with patch("posint_scanner.orchestrator.resolve_hostname", return_value=["1.2.3.4"]):
            run_scan(db, ["example.com"], [Discovery()], netblock_sweep=False,
                     vuln_lookup=False, tech_fingerprint=False, takeover_scan=True)

        domain_id = db.get_domain_by_name("example.com")["id"]
        (row,) = db.list_tool_outputs(domain_id)
        assert (row["tool"], row["target"]) == ("takeover", "example.com")
        stored = toolrun.decompress(db.get_tool_output(row["id"])["content"])
        assert json.loads(stored) == TAKEOVER_REPORT
        db.close()

        assert _wait_dead(int(pidfile.read_text()))
        db_files = {"posint.db", "posint.db-wal", "posint.db-shm"}
        assert _tree(data) - db_files - {".posint-scratch"} == before - db_files - {
            ".posint-scratch", ".posint-scratch/run-999999999", ".posint-scratch/run-999999999/nikto-x"
        }
        assert list((data / ".posint-scratch").iterdir()) == []
