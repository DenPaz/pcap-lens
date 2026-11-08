"""Overlapping random requests against one backend, checking what comes back.

Usage::

    uv run python test/fixtures/generate.py --large 200000 test/fixtures/large-200k.pcap
    uv run python -u test/perf/stress.py --seeds 20 --steps 200 \\
        test/fixtures/mixed.pcapng test/fixtures/http.pcap test/fixtures/large-200k.pcap

Each seed starts ``python -m pcap_backend``, sends ``--steps`` random requests
without waiting for answers (open, streaming and plain filters, stop_filter,
sorted pages, cancel, close, find, the overview strip), then waits for every
answer. A problem is an internal error (-32603), a request that never
answers, a traceback on stderr, a backend that doesn't exit once stdin
closes, or a child process left behind. Seeds are reproducible (``--first``).

It found the work folder of an open still in progress removed by a close or
a newer open (fixed in service/base.py, ``_supersede_open``).
"""

from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
# Errors a request may answer with when others overlap it.
EXPECTED = {
    -32800,  # cancelled or superseded
    -32003,  # no capture open (closed meanwhile)
    -32010,  # invalid filter (some below are)
    -32012,  # still indexing or filtering
    -32602,  # invalid params (e.g. a stop for an old filter)
}
FILTERS = [
    "",
    "tcp",
    "udp",
    "ip.len > 100",
    "frame.number < 500",
    "dns || http",
    "tcp.flags.syn == 1",
    "nonexistent_field",
    "frame.len >",
    "!tcp",
]
SORTS = [
    None,
    {"field": "frame.number", "desc": True},
    {"field": "_ws.col.protocol"},
    {"field": "frame.time_relative", "desc": True},
    {"field": "_ws.col.info"},
]


class Client:
    """A backend and the answers and notifications it sent."""

    def __init__(self) -> None:
        env = {**os.environ, "PYTHONPATH": str(REPO / "backend")}
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "pcap_backend"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=REPO,
        )
        self.next_id = 0
        self.pending: dict[int, tuple[str, float]] = {}
        self.answers: dict[int, dict[str, Any]] = {}
        self.notes: list[dict[str, Any]] = []
        self.stderr: list[str] = []
        self.lock = threading.Lock()
        threading.Thread(target=self._read, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()

    def _read(self) -> None:
        assert self.proc.stdout is not None
        for raw in self.proc.stdout:
            msg = json.loads(raw)
            with self.lock:
                if msg.get("id") is not None:
                    self.answers[msg["id"]] = msg
                    self.pending.pop(msg["id"], None)
                else:
                    self.notes.append(msg)

    def _read_stderr(self) -> None:
        assert self.proc.stderr is not None
        self.stderr.extend(raw.decode("utf-8", "replace") for raw in self.proc.stderr)

    def send(self, method: str, params: dict[str, Any]) -> int:
        with self.lock:
            self.next_id += 1
            rid = self.next_id
            self.pending[rid] = (method, time.monotonic())
        data = json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        assert self.proc.stdin is not None
        self.proc.stdin.write(data.encode() + b"\n")
        self.proc.stdin.flush()
        return rid

    def call(self, method: str, params: dict[str, Any], timeout: float = 120) -> dict[str, Any]:
        rid = self.send(method, params)
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            with self.lock:
                if rid in self.answers:
                    return self.answers[rid]
            time.sleep(0.01)
        raise TimeoutError(method)


def descendants(pid: int) -> list[str]:
    """``"pid name"`` of every process below ``pid`` (POSIX ``ps``)."""
    out = subprocess.run(
        ["ps", "-o", "pid=,ppid=,comm=", "-A"], capture_output=True, text=True, check=True
    ).stdout
    rows = [line.split(None, 2) for line in out.splitlines()]
    found, below = {pid}, []
    changed = True
    while changed:
        changed = False
        for p, parent, name in rows:
            if int(parent) in found and int(p) not in found:
                found.add(int(p))
                below.append(f"{p} {name}")
                changed = True
    return below


def random_request(rnd: random.Random, c: Client, captures: list[str]) -> None:
    op = rnd.choices(
        ["open", "filter", "stop", "page", "cancel", "close", "find", "pause", "overview"],
        [2, 6, 2, 8, 3, 1, 2, 3, 1],
    )[0]
    if op == "open":
        c.send("open", {"path": rnd.choice(captures), "stream": rnd.random() < 0.8})
    elif op == "filter":
        c.send("set_filter", {"expr": rnd.choice(FILTERS), "stream": rnd.random() < 0.8})
    elif op == "stop":
        with c.lock:
            ids = [n["params"].get("filterId") for n in c.notes if n.get("method") == "filter"]
        c.send("stop_filter", {"filterId": ids[-1] if ids else rnd.randint(1, 20)})
    elif op == "page":
        params: dict[str, Any] = {"offset": rnd.randint(0, 2000), "limit": 100}
        sort = rnd.choice(SORTS)
        if sort is not None:
            params["sort"] = sort
        c.send("list_packets", params)
    elif op == "cancel":
        with c.lock:
            ids = list(c.pending)
        if ids:
            c.send("cancel", {"requestId": rnd.choice(ids)})
    elif op == "close":
        c.send("close", {})
    elif op == "find":
        c.send("find_packet", {"mode": "string", "value": "HTTP", "from": 0})
    elif op == "overview":
        c.send("view_overview", {"buckets": 100})
    else:
        time.sleep(rnd.random() * 0.5)


def run(seed: int, captures: list[str], steps: int) -> list[str]:
    """One seed's problems (empty when there were none)."""
    rnd = random.Random(seed)
    c = Client()
    problems: list[str] = []
    init = c.call("initialize", {})
    if "error" in init:
        return [f"initialize: {init['error']}"]
    for _ in range(steps):
        random_request(rnd, c, captures)
        time.sleep(rnd.random() * 0.05)
    end = time.monotonic() + 180
    while time.monotonic() < end:
        with c.lock:
            if not c.pending:
                break
        time.sleep(0.1)
    with c.lock:
        problems += [
            f"no answer to #{rid} {method} after {time.monotonic() - started:.0f} s"
            for rid, (method, started) in c.pending.items()
        ]
        for rid, msg in sorted(c.answers.items()):
            err = msg.get("error")
            if err and err["code"] not in EXPECTED:
                problems.append(f"#{rid}: {err['code']} {err['message'][:200]}")
    children = descendants(c.proc.pid)
    assert c.proc.stdin is not None
    c.proc.stdin.close()
    try:
        c.proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        problems.append("the backend did not exit 20 s after stdin closed")
        c.proc.kill()
        c.proc.wait()
    time.sleep(0.5)
    if left := [k for k in children if Path(f"/proc/{k.split()[0]}").exists()]:
        problems.append(f"children left after exit: {left}")
    stderr = "".join(c.stderr)
    if "Traceback" in stderr:
        problems.append("traceback on stderr:\n" + stderr[stderr.index("Traceback") :][:3000])
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("captures", nargs="+", help="captures to open (mix small and large ones)")
    ap.add_argument("--first", type=int, default=1, help="first seed")
    ap.add_argument("--seeds", type=int, default=10, help="how many seeds")
    ap.add_argument("--steps", type=int, default=200, help="requests per seed")
    args = ap.parse_args(argv)
    bad = 0
    for seed in range(args.first, args.first + args.seeds):
        start = time.monotonic()
        found = run(seed, args.captures, args.steps)
        print(
            f"seed {seed}: {'ok' if not found else 'PROBLEMS'} ({time.monotonic() - start:.0f} s)"
        )
        for problem in found:
            print("   ", problem)
        bad += bool(found)
    print(f"{bad} of {args.seeds} seeds had problems")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
