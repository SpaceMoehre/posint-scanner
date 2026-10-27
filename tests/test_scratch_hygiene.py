"""A scan may only write to the database: external tools run in sandboxes
that vanish with them (see toolrun.py), their reports land compressed in
tool_outputs, and nothing they start outlives them. Tests run sandboxes as
plain dirs without bwrap (conftest.py), so what bwrap itself guarantees is
covered by `posint-scanner sandbox-check` on the real host instead."""

import fcntl
import json
import os
import re
import shutil
import signal
import stat
import threading
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
        assert list(toolrun._test_root.iterdir()) == []

    def test_nested_workspace_shares_the_sandbox(self):
        with toolrun.workspace("outer") as outer:
            (outer / "repo").mkdir()
            with toolrun.workspace("inner") as inner:
                assert inner.parent == outer.parent
                result = toolrun.run_tool(["ls", str(outer)], timeout=10, cwd=inner)
                assert result.stdout.split() == ["repo"]
            assert not inner.exists() and outer.exists()

    def test_nested_workspace_cannot_widen_the_sandbox(self, tmp_path):
        with toolrun.workspace("outer"), pytest.raises(ValueError), \
                toolrun.workspace("inner", writable=[tmp_path]):
            pass

    def test_configure_points_next_to_the_db_and_drops_old_scratch(self, tmp_path):
        legacy = tmp_path / "data" / ".posint-scratch" / "run-1" / "nikto-x"
        legacy.mkdir(parents=True)
        toolrun.configure(tmp_path / "data" / "posint.db")
        assert toolrun.cache_dir("trivy") == (tmp_path / "data" / ".posint-cache" / "trivy").resolve()
        assert toolrun._slots_dir == (tmp_path / "data" / ".posint-slots").resolve()
        assert not (tmp_path / "data" / ".posint-scratch").exists()


class TestSlots:
    def test_at_most_four_sandboxes_at_once(self):
        lock = threading.Lock()
        active = peak = 0

        def stage():
            nonlocal active, peak
            with toolrun.workspace("t"):
                with lock:
                    active += 1
                    peak = max(peak, active)
                time.sleep(0.3)
                with lock:
                    active -= 1

        threads = [threading.Thread(target=stage) for _ in range(7)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert peak == toolrun.HEAVY_SLOTS

    def test_slots_held_elsewhere_are_waited_for(self, tmp_path):
        # Locks taken through other open files - as another process would.
        slots = toolrun._slots_dir
        slots.mkdir(parents=True)
        held = []
        for index in range(toolrun.HEAVY_SLOTS):
            handle = open(slots / f"slot-{index}", "a")
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            held.append(handle)
        entered = threading.Event()

        def stage():
            with toolrun.workspace("t"):
                entered.set()

        thread = threading.Thread(target=stage)
        thread.start()
        assert not entered.wait(1.5)
        held.pop().close()
        assert entered.wait(5)
        thread.join()
        for handle in held:
            handle.close()

    def test_light_runs_take_no_slot(self):
        slots = toolrun._slots_dir
        slots.mkdir(parents=True)
        held = [open(slots / f"slot-{i}", "a") for i in range(toolrun.HEAVY_SLOTS)]
        for handle in held:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = toolrun.run_light(["sh", "-c", "echo ok"], timeout=10)
        assert result.stdout == "ok\n"
        for handle in held:
            handle.close()


class TestRunTool:
    def test_output_input_and_env(self):
        with toolrun.workspace("t") as ws:
            result = toolrun.run_tool(
                ["sh", "-c", 'echo "$TMPDIR"; echo "$HOME"; pwd; cat; echo err >&2'],
                timeout=10, cwd=ws, input="in",
            )
            box = toolrun._box()
            base = box.inside_base
            assert result.returncode == 0
            assert result.stdout == f"{base}\n{base}/home\n{box.inside(str(ws))}\nin"
            assert result.stderr == "err\n"

    def test_paths_into_the_workspace_are_translated(self):
        with toolrun.workspace("t") as ws:
            (ws / "targets.txt").write_text("a\nb\n")
            result = toolrun.run_tool(
                ["sh", "-c", 'cat "$1" > "$OUT"', "sh", str(ws / "targets.txt")],
                timeout=10, cwd=ws, env={"OUT": f"{ws}/copy.txt"},
            )
            assert result.returncode == 0
            assert (ws / "copy.txt").read_text() == "a\nb\n"
            assert str(ws).startswith("/proc/self/fd/")
            assert not toolrun._box().inside(str(ws)).startswith("/proc/")

    def test_needs_a_workspace(self, tmp_path):
        with pytest.raises(RuntimeError):
            toolrun.run_tool(["true"], timeout=5, cwd=tmp_path)

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

    def test_sandbox_byte_cap_kills(self):
        toolrun.set_limits(1, 10_000)
        with toolrun.workspace("t") as ws:
            result = toolrun.run_tool(
                ["sh", "-c", "head -c 3000000 /dev/zero > big; sleep 30"], timeout=20, cwd=ws
            )
            assert result is None
            # the sandbox stays usable for the next tool
            assert toolrun.run_tool(["true"], timeout=10, cwd=ws).returncode == 0

    def test_sandbox_inode_cap_kills(self):
        toolrun.set_limits(1024, 100)
        with toolrun.workspace("t") as ws:
            result = toolrun.run_tool(
                ["sh", "-c", "i=0; while [ $i -lt 500 ]; do : > f$i; i=$((i+1)); done; sleep 30"],
                timeout=20, cwd=ws,
            )
        assert result is None

    def test_missing_binary_is_none(self):
        with toolrun.workspace("t") as ws:
            assert toolrun.run_tool(["/nonexistent/tool"], timeout=5, cwd=ws) is None

    def test_light_run(self):
        result = toolrun.run_light(["sh", "-c", 'echo "$HOME"; touch "$TMPDIR/x"'], timeout=10)
        assert result.returncode == 0
        assert toolrun.run_light(["sleep", "30"], timeout=1) is None
        assert list(toolrun._test_root.iterdir()) == []


class TestNoSandbox:
    @pytest.fixture
    def no_bwrap(self, monkeypatch):
        monkeypatch.setattr(toolrun, "_test_root", None)
        monkeypatch.setattr(toolrun, "_probed", False)
        monkeypatch.setattr(toolrun, "_probe_error", None)
        real_which = shutil.which
        monkeypatch.setattr(
            "shutil.which", lambda name: None if name == "bwrap" else real_which(name)
        )

    def test_every_tool_is_missing_and_nothing_runs(self, no_bwrap):
        assert "bwrap" in toolrun.sandbox_error()
        assert toolrun.which("sh") is None
        assert toolrun.run_light(["sh", "-c", "echo hi"], timeout=5) is None
        with pytest.raises(toolrun.SandboxUnavailable), toolrun.workspace("t"):
            pass

    def test_web_ui_shows_a_banner(self, no_bwrap, tmp_path):
        from fastapi.testclient import TestClient

        from posint_scanner.web.app import create_app

        app = create_app(db_path=str(tmp_path / "posint.db"), config_path=str(tmp_path / "none.yaml"))
        page = TestClient(app).get("/").text
        assert "Tool sandbox unavailable" in page

    def test_a_sandbox_that_fails_to_start_is_reported(self, monkeypatch, tmp_path):
        # A "bwrap" that dies at once, as a real one does when Docker blocks it.
        _script(tmp_path / "bwrap", "echo 'bwrap: No permissions to create new namespace' >&2; exit 1\n")
        monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")
        monkeypatch.setattr(toolrun, "_test_root", None)
        monkeypatch.setattr(toolrun, "_probed", False)
        monkeypatch.setattr(toolrun, "_probe_error", None)
        monkeypatch.setattr(toolrun, "_bwrap_size_flag", True)
        error = toolrun.sandbox_error()
        assert "No permissions to create new namespace" in error
        assert toolrun.which("sh") is None

    def test_agent_refuses_a_pid_namespace_it_does_not_own(self, monkeypatch, tmp_path):
        # A "bwrap" that just runs the command: the agent ends up in the
        # caller's PID namespace and must not sweep it.
        _script(tmp_path / "bwrap", 'while [ "$1" != "--" ]; do shift; done; shift; exec "$@"\n')
        monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")
        monkeypatch.setattr(toolrun, "_test_root", None)
        monkeypatch.setattr(toolrun, "_bwrap_size_flag", True)
        with pytest.raises(toolrun.SandboxUnavailable, match="refusing"):
            toolrun._Box(1 << 20, 100)


class TestBwrapArgv:
    def test_isolation_flags(self, monkeypatch, tmp_path):
        monkeypatch.setattr(toolrun, "_bwrap_size_flag", True)
        argv = toolrun._bwrap_argv(5 << 20, writable=[tmp_path])
        joined = " ".join(argv)
        for flag in ("--unshare-user-try", "--unshare-pid", "--die-with-parent",
                     "--new-session", "--cap-drop ALL", "--ro-bind / /", "--proc /proc",
                     f"--size {5 << 20} --tmpfs /tmp", f"--bind {tmp_path} {tmp_path}",
                     "--chdir /tmp"):
            assert flag in joined
        assert argv[-1] == "--"
        # later mounts go on top of the read-only root
        assert argv.index("--tmpfs") > argv.index("--ro-bind")
        assert argv.index("--bind") > argv.index("--tmpfs")

    def test_no_size_flag_on_old_bwrap(self, monkeypatch):
        monkeypatch.setattr(toolrun, "_bwrap_size_flag", False)
        assert "--size" not in toolrun._bwrap_argv(5 << 20)


class TestSelfCheck:
    def test_reports_what_test_mode_cannot_isolate(self, tmp_path):
        toolrun.configure(tmp_path / "data" / "posint.db")
        checks = toolrun.self_check()
        results = {name: passed for name, passed, _ in checks}
        details = {name: detail for name, _, detail in checks}
        assert results["sandbox starts"]
        assert results["tools and the scanner share the workspace"]
        assert results["a tool past the inode cap is killed"]
        assert results["one-shot sandboxes run"]
        # No bwrap in tests: the data dir is writable and a detached process
        # survives - the check must say so rather than pass.
        assert not results[f"{(tmp_path / 'data').resolve()} is read-only to tools"]
        leaked = "processes a tool leaves behind are killed after its run"
        assert not results[leaked]
        os.kill(int(re.search(r"pid (\d+)", details[leaked]).group(1)), signal.SIGKILL)


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
        # An older version left its scratch dir behind.
        (data / ".posint-scratch" / "run-999999999" / "nikto-x").mkdir(parents=True)

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
        slots = {".posint-slots"} | {f".posint-slots/slot-{i}" for i in range(toolrun.HEAVY_SLOTS)}
        stale = {".posint-scratch", ".posint-scratch/run-999999999",
                 ".posint-scratch/run-999999999/nikto-x"}
        assert _tree(data) - db_files - slots == before - db_files - stale
        assert list(toolrun._test_root.iterdir()) == []
