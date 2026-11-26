"""Latency added by undolayer per tool call: the same operation run directly vs through the gateway.

    python3 bench/overhead/overhead.py [--n 200]

Direct baselines run the same work in-process (a Python function, a sqlite3 statement, a
subprocess, a file write). Gateway numbers include the MCP round trip, classification,
policy, the write-ahead journal and staging.
"""
import argparse
import json
import os
import platform
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "sdk" / "python"))
os.environ.setdefault("UNDOLAYER_BIN", str(ROOT / "bin" / "undolayer"))
from undolayer import Undolayer  # noqa: E402


def timed(fn, n):
    fn()  # warm-up
    xs = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        xs.append((time.perf_counter() - t) * 1000)
    xs.sort()
    return {"median_ms": statistics.median(xs), "p95_ms": xs[int(0.95 * (len(xs) - 1))]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--out")
    a = ap.parse_args()
    d = Path(tempfile.mkdtemp(prefix="ul-overhead-"))
    (d / "ws").mkdir()
    db = d / "app.db"
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)")
    c.executemany("INSERT INTO t(v) VALUES (?)", [(str(i),) for i in range(10000)])
    c.commit()
    c.close()
    (d / "undolayer.toml").write_text(f'state_dir = "{d}/state"\n[workspace]\nroot = "ws"\n[sql]\ndsn = "app.db"\n')
    ul = Undolayer(config=str(d / "undolayer.toml"))

    @ul.tool(lane="read")
    def lookup(key: str) -> dict:
        """Read a record."""
        return {"key": key, "value": 1}

    @ul.tool(lane="deferrable", destinations=["to"])
    def notify(to: str, text: str) -> dict:
        """Send a message."""
        return {"ok": True}

    def lookup_direct():
        return lookup("k")

    # the gateway holds its staged transaction open on app.db, so the baseline uses an identical copy
    import shutil
    shutil.copy(db, d / "direct.db")
    direct = sqlite3.connect(d / "direct.db", isolation_level=None)
    rows = []
    with ul:
        s = ul.session("Look up k and notify ops@corp.example")
        n = a.n
        i = iter(range(10 ** 9))
        cases = [
            ("API read (registry tool)", lookup_direct, lambda: s.call("lookup", key="k")),
            ("API send, queued (deferrable)", lambda: notify("ops@corp.example", "x"),
             lambda: s.call("notify", to="ops@corp.example", text="x")),
            ("SQL read", lambda: direct.execute("SELECT v FROM t WHERE id = 42").fetchall(),
             lambda: s.builtin("sql_execute", sql="SELECT v FROM t WHERE id = 42")),
            ("SQL write, staged with row capture", lambda: direct.execute("UPDATE t SET v = 'x' WHERE id = ?", (next(i) % 9000 + 1,)),
             lambda: s.builtin("sql_execute", sql=f"UPDATE t SET v = 'y' WHERE id = {next(i) % 9000 + 1}")),
            ("file write, staged", lambda: (d / "ws" / "direct.txt").write_text("hello\n"),
             lambda: s.builtin("fs_write", path="notes.txt", content="hello\n")),
            ("shell command, sandboxed", lambda: subprocess.run(["sh", "-c", "echo hi"], capture_output=True),
             lambda: s.builtin("shell_run", command="echo hi")),
        ]
        for name, fd, fg in cases:
            k = n if "shell" not in name else max(20, n // 10)
            dr, gw = timed(fd, k), timed(fg, k)
            rows.append({"operation": name, "n": k, "direct": dr, "gateway": gw,
                         "added_median_ms": gw["median_ms"] - dr["median_ms"]})
        t = time.perf_counter()
        s.rollback()
        rollback_ms = (time.perf_counter() - t) * 1000
        rolled = sum(r["n"] + 1 for r in rows if r["operation"].startswith(("SQL write", "file", "API send")))
        # a realistic task: 20 row updates, 5 files, 1 message, committed as one unit
        s = ul.session("Fix the 20 rows, update the docs and tell ops@corp.example")
        for k in range(20):
            s.builtin("sql_execute", sql=f"UPDATE t SET v = 'fixed' WHERE id = {k + 1}")
        for k in range(5):
            s.builtin("fs_write", path=f"docs/page{k}.md", content="updated\n")
        s.call("notify", to="ops@corp.example", text="done")
        t = time.perf_counter()
        s.commit()
        commit_ms = (time.perf_counter() - t) * 1000
    env = {"os": platform.platform(), "machine": platform.machine(), "python": platform.python_version()}
    print(f"undolayer overhead per call ({env['os']}, {env['machine']})\n")
    print(f"{'operation':40} {'direct median':>14} {'gateway median':>15} {'gateway p95':>12} {'added':>9}")
    for r in rows:
        print(f"{r['operation']:40} {r['direct']['median_ms']:12.2f}ms {r['gateway']['median_ms']:13.2f}ms "
              f"{r['gateway']['p95_ms']:10.2f}ms {r['added_median_ms']:7.2f}ms")
    print(f"\ncommit of a task (20 row updates, 5 files, 1 message): {commit_ms:.0f} ms")
    print(f"rollback of the timing session ({rolled} staged writes and sends): {rollback_ms:.0f} ms")
    if a.out:
        Path(a.out).write_text(json.dumps({"env": env, "rows": rows, "commit_ms": commit_ms, "rollback_ms": rollback_ms,
                                           "rolled_back_actions": rolled}, indent=2))


if __name__ == "__main__":
    main()
