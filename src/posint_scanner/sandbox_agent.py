"""The process inside a tool sandbox (see toolrun.py): runs the tools sent to it.

toolrun starts this as the sandbox's only long-lived process, as a plain
script (`python -I sandbox_agent.py`), so it uses the standard library only.

    sandbox_agent.py <base> <sock fd> <statvfs|walk> [--pidns]

`<base>` is the sandbox's writable tree (in the sandbox: the tmpfs on /tmp):
`work/` holds the workspaces, `home/` is the tools' HOME, `.agent/` the
captured output of the current run. The agent first hands toolrun an O_PATH
fd of `<base>` over the socket `<sock fd>` - toolrun reads and writes the
sandbox's files through it - then answers one JSON request per stdin line
with one JSON line on stdout:

    {"cmd": [...], "cwd": ..., "env": {...}, "input": str|null, "timeout": s,
     "max_bytes": n, "max_inodes": n, "size_limit": [path, bytes]|null}
    -> {"returncode": n}  (output in .agent/stdout and .agent/stderr)
    -> {"error": "timed out after 60s"}

The tool runs in its own process group, killed on a timeout, when the
sandbox's tmpfs use passes `max_bytes`/`max_inodes` (`statvfs` measures the
tmpfs, `walk` counts `<base>`'s files - for tests, where `<base>` is a plain
dir), or when `size_limit`'s dir passes its byte cap. With `--pidns` the
agent is alone in its PID namespace apart from bwrap's init, so after every
run it kills whatever else is left - processes that left the tool's group
included. EOF on stdin ends the agent, and with it the sandbox.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from typing import IO

POLL_SECONDS = 1.0
KILL_GRACE_SECONDS = 5.0


def tree_usage(path: str) -> tuple[int, int]:
    """(bytes, entries) under `path`, not following symlinks."""
    size = entries = 0
    for dirpath, dirnames, filenames in os.walk(path):
        for name in dirnames + filenames:
            entries += 1
            if name in filenames:
                try:
                    size += os.lstat(os.path.join(dirpath, name)).st_size
                except OSError:
                    pass
    return size, entries


def usage(base: str, measure: str) -> tuple[int, int]:
    """(bytes, inodes) the sandbox's writable tree uses."""
    if measure == "statvfs":
        st = os.statvfs(base)
        return (st.f_blocks - st.f_bfree) * st.f_frsize, st.f_files - st.f_ffree
    return tree_usage(base)


def over_limit(base: str, measure: str, req: dict) -> str | None:
    used_bytes, used_inodes = usage(base, measure)
    if used_bytes > req["max_bytes"]:
        return f"exceeded the sandbox's {req['max_bytes'] // (1024 * 1024)} MB"
    if used_inodes > req["max_inodes"]:
        return f"exceeded the sandbox's {req['max_inodes']} inodes"
    if req.get("size_limit"):
        path, cap = req["size_limit"]
        if tree_usage(path)[0] > cap:
            return f"exceeded {cap // (1024 * 1024)} MB on disk"
    return None


def kill_group(proc: subprocess.Popen) -> None:
    """SIGTERM the tool's process group, SIGKILL whatever is left after a
    grace period. A no-op when the group is already gone."""
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
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _other_pids() -> list[int]:
    own = os.getpid()
    return [int(name) for name in os.listdir("/proc")
            if name.isdigit() and int(name) not in (1, own)]


def own_pid_namespace() -> bool:
    """Whether we're in a fresh bwrap PID namespace and /proc lists it - not
    a namespace we were started from, whose processes are none of ours to
    kill. bwrap's init is PID 1 there and forks us as PID 2."""
    try:
        with open("/proc/1/comm") as comm:
            init = comm.read().strip()
        return (init == "bwrap" and os.getpid() == 2
                and os.readlink("/proc/self") == "2")
    except OSError:
        return False


def kill_others() -> None:
    """Kill every process in the PID namespace but init and the agent."""
    if not own_pid_namespace():
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for pid in _other_pids():
            try:
                os.kill(pid, sig)
            except (ProcessLookupError, PermissionError):
                pass
        deadline = time.monotonic() + KILL_GRACE_SECONDS
        while _other_pids() and time.monotonic() < deadline:
            try:  # orphans are init's to reap; our own children are ours
                while os.waitpid(-1, os.WNOHANG)[0]:
                    pass
            except ChildProcessError:
                pass
            time.sleep(0.1)


def _feed(stdin: IO[bytes], text: str) -> None:
    try:
        stdin.write(text.encode("utf-8", errors="replace"))
        stdin.close()
    except OSError:
        pass  # the tool exited without reading it all


def run(req: dict, base: str, measure: str) -> dict:
    agent_dir = os.path.join(base, ".agent")
    with open(os.path.join(agent_dir, "stdout"), "wb") as out, \
            open(os.path.join(agent_dir, "stderr"), "wb") as err:
        try:
            proc = subprocess.Popen(
                req["cmd"],
                stdin=subprocess.PIPE if req.get("input") is not None else subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                cwd=req["cwd"],
                env=req["env"],
                start_new_session=True,
            )
        except (OSError, ValueError) as exc:
            return {"error": f"could not be started: {exc}"}
    if proc.stdin is not None:
        threading.Thread(target=_feed, args=(proc.stdin, req["input"]), daemon=True).start()
    deadline = time.monotonic() + req["timeout"]
    while True:
        try:
            proc.wait(timeout=POLL_SECONDS)
            break
        except subprocess.TimeoutExpired:
            reason = None
            if time.monotonic() >= deadline:
                reason = f"timed out after {req['timeout']:.0f}s"
            else:
                reason = over_limit(base, measure, req)
            if reason:
                kill_group(proc)
                proc.wait()
                return {"error": reason}
    kill_group(proc)  # children it left running
    return {"returncode": proc.returncode}


def main(argv: list[str]) -> int:
    base, sock_fd, measure = argv[1], int(argv[2]), argv[3]
    pidns = "--pidns" in argv[4:]
    if pidns and not own_pid_namespace():
        sys.exit("sandbox_agent: /proc is not this PID namespace's - refusing to run")
    for sub in ("work", "home", ".agent"):
        os.makedirs(os.path.join(base, sub), exist_ok=True)
    with socket.socket(fileno=sock_fd) as sock:
        root = os.open(base, os.O_PATH | os.O_DIRECTORY)
        socket.send_fds(sock, [b"ready"], [root])
        os.close(root)
    for line in sys.stdin:
        try:
            reply = run(json.loads(line), base, measure)
        finally:
            if pidns:
                kill_others()
        sys.stdout.write(json.dumps(reply) + "\n")
        sys.stdout.flush()
    if pidns:
        kill_others()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
