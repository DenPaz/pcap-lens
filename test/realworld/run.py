"""Run every backend feature over real captures and report what breaks.

Not part of CI (it downloads captures). The generated fixtures in
test/fixtures are small and tidy; real captures have truncated packets,
odd encapsulations, many link types and broken streams. This drives the
backend the way the extension does: one ``python -m pcap_backend`` server
per capture over JSON-RPC, a streaming open with the default coloring
rules and name resolution, then each feature in turn, and checks a few
invariants (packet counts agree, exports read back, pages are complete).

    uv run python test/realworld/run.py --fetch wireshark           # every feature
    uv run python test/realworld/run.py --fetch tcpdump --quick     # 600 odd captures
    uv run python test/realworld/run.py DIR_OR_FILE …              # your own
    … --only http -j 4 --out report.json

Wireshark's test captures (about 190 after skipping its synthetic Oracle
TNS and NVMe-MI series) come from GitLab, tcpdump's (about 600, many
fuzzed: out-of-bounds reads, odd link types) from its TESTLIST on GitHub.

Captures are kept in ~/.cache/pcap-lens-realworld (never in the repository:
they aren't ours to redistribute). Every result is listed as ok, expected
(an answer the viewer shows as a message, e.g. "no TCP stream here") or a
problem: an internal error, a tshark failure, a timeout, a broken
invariant, a traceback on the server's stderr. Exit status 1 when there
are problems.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import queue
import re
import selectors
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
CACHE = Path.home() / ".cache" / "pcap-lens-realworld"
WIRESHARK_TREE = (
    "https://gitlab.com/api/v4/projects/wireshark%2Fwireshark/repository/tree"
    "?path=test/captures&per_page=100&ref=master&page={page}"
)
WIRESHARK_RAW = "https://gitlab.com/api/v4/projects/wireshark%2Fwireshark/repository/files/{path}/raw?ref=master"
# Generator scripts, side files, and the hundreds of synthetic Oracle TNS and
# NVMe-MI captures (one dissector each: they add time, not variety).
SKIP = re.compile(r"^(_gen_|tns_|nvme-mi-)|\.(py|cbordiag|m|xml)$|keys\.txt$|text2pcap_hash_eol")

INTERNAL_ERROR = -32603
TSHARK_FAILED = -32002
TIMEOUT_CODE = 0
# Answers the viewer shows as a message (no such stream, still indexing…).
EXPECTED_CODES = {-32602, -32010, -32011, -32012}
SLOW_S = 30.0

with (ROOT / "package.json").open(encoding="utf-8") as fh:
    _PROPS: dict[str, Any] = {}
    _conf = json.load(fh)["contributes"]["configuration"]
    for _section in _conf if isinstance(_conf, list) else [_conf]:
        _PROPS.update(_section["properties"])
COLORING = [
    {"filter": r["filter"], "foreground": r["foreground"], "background": r["background"]}
    for r in _PROPS["pcapViewer.coloringRules"]["default"]
]
NAMES = {"mac": True, "network": False, "capturedDns": True, "transport": False, "external": False}


# --- fetching ---------------------------------------------------------------


def _get(url: str, timeout: float = 120) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "pcap-lens-realworld"})  # noqa: S310
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (https only)
        data: bytes = resp.read()
    return data


def fetch_wireshark(dest: Path) -> list[Path]:
    """Wireshark's own test captures (test/captures), downloaded once."""
    dest.mkdir(parents=True, exist_ok=True)
    names: list[str] = []
    for page in range(1, 20):
        entries = json.loads(_get(WIRESHARK_TREE.format(page=page)))
        if not entries:
            break
        names += [e["name"] for e in entries if e["type"] == "blob" and not SKIP.search(e["name"])]
    for name in names:
        target = dest / name
        if target.exists() and target.stat().st_size and not _is_html(target):
            continue
        path = urllib.parse.quote(f"test/captures/{name}", safe="")
        # One at a time: GitLab answers parallel raw requests with an HTML page.
        target.write_bytes(_get(WIRESHARK_RAW.format(path=path)))
        time.sleep(0.2)
        print(f"fetched {name}", file=sys.stderr)
    return sorted(dest / n for n in names)


TCPDUMP_TESTLIST = (
    "https://raw.githubusercontent.com/the-tcpdump-group/tcpdump/master/tests/TESTLIST"
)
TCPDUMP_RAW = "https://raw.githubusercontent.com/the-tcpdump-group/tcpdump/master/tests/{name}"


def fetch_tcpdump(dest: Path) -> list[Path]:
    """tcpdump's test captures (the files its TESTLIST reads), downloaded once."""
    dest.mkdir(parents=True, exist_ok=True)
    names = sorted(
        {
            cells[1]
            for line in _get(TCPDUMP_TESTLIST).decode().splitlines()
            if not line.startswith("#")
            and len(cells := line.split()) > 1
            and re.search(r"\.(pcap|pcapng|cap)$", cells[1])
        }
    )
    for name in names:
        target = dest / name
        if not (target.exists() and target.stat().st_size):
            target.write_bytes(_get(TCPDUMP_RAW.format(name=name)))
            print(f"fetched {name}", file=sys.stderr)
    return [dest / n for n in names]


def _is_html(path: Path) -> bool:
    with path.open("rb") as fh:
        return fh.read(15).lower().startswith((b"<!doctype", b"<html"))


# --- the server -------------------------------------------------------------


class RpcError(Exception):
    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


class Server:
    """``python -m pcap_backend`` with an empty home, as the tests run it."""

    def __init__(self, home: Path) -> None:
        env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("WIRESHARK_CONFIG_DIR", "WIRESHARK_PLUGIN_DIR")
        }
        env |= {
            "HOME": str(home),
            "APPDATA": str(home),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "PYTHONPATH": str(ROOT / "backend"),
        }
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "pcap_backend"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        self._next = 0
        self._replies: dict[int, queue.Queue[dict[str, Any]]] = {}
        self._lock = threading.Lock()
        self.notifications: queue.Queue[dict[str, Any]] = queue.Queue()
        self.stderr: list[str] = []
        self.bad_output: list[str] = []
        threading.Thread(target=self._read_out, daemon=True).start()
        threading.Thread(target=self._read_err, daemon=True).start()

    def _read_out(self) -> None:
        assert self.proc.stdout is not None
        for raw in self.proc.stdout:
            try:
                msg = json.loads(raw)
            except ValueError:
                self.bad_output.append(raw.decode("utf-8", "replace")[:200])
                continue
            if "id" in msg and ("result" in msg or "error" in msg):
                with self._lock:
                    box = self._replies.get(msg["id"])
                if box is not None:
                    box.put(msg)
            elif msg.get("method") != "progress":
                self.notifications.put(msg)

    def _read_err(self) -> None:
        assert self.proc.stderr is not None
        for raw in self.proc.stderr:
            self.stderr.append(raw.decode("utf-8", "replace").rstrip())

    def call(self, method: str, params: dict[str, Any], timeout: float) -> Any:
        with self._lock:
            self._next += 1
            rid = self._next
            box: queue.Queue[dict[str, Any]] = queue.Queue()
            self._replies[rid] = box
        line = json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        assert self.proc.stdin is not None
        self.proc.stdin.write(line.encode() + b"\n")
        self.proc.stdin.flush()
        try:
            msg = box.get(timeout=timeout)
        except queue.Empty:
            self.proc.stdin.write(
                json.dumps(
                    {"jsonrpc": "2.0", "method": "cancel", "params": {"requestId": rid}}
                ).encode()
                + b"\n"
            )
            self.proc.stdin.flush()
            raise RpcError(TIMEOUT_CODE, f"no answer in {timeout:.0f} s") from None
        finally:
            with self._lock:
                self._replies.pop(rid, None)
        if "error" in msg:
            err = msg["error"]
            raise RpcError(err.get("code", 0), err.get("message", ""), err.get("data"))
        return msg["result"]

    def wait_for(self, method: str, event: set[str], timeout: float) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while (left := deadline - time.monotonic()) > 0:
            try:
                msg = self.notifications.get(timeout=left)
            except queue.Empty:
                break
            params = msg.get("params") or {}
            if msg.get("method") == method and params.get("event") in event:
                return params
        raise RpcError(TIMEOUT_CODE, f"no {method} {'/'.join(sorted(event))} in {timeout:.0f} s")

    def close(self) -> None:
        assert self.proc.stdin is not None
        with contextlib.suppress(OSError):
            self.proc.stdin.close()
        try:
            self.proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
            self.stderr.append("(server did not exit within 30 s of closing stdin)")
        for stream in (self.proc.stdout, self.proc.stderr):
            if stream is not None:
                stream.close()


# --- one capture -------------------------------------------------------------


@dataclass
class Step:
    name: str
    status: str  # ok, expected, note (tshark's own oddity), problem
    seconds: float
    detail: str = ""


@dataclass
class Report:
    capture: str
    frames: int | None = None
    steps: list[Step] = field(default_factory=list)

    def problems(self) -> list[Step]:
        return [s for s in self.steps if s.status == "problem"]


class Run:
    def __init__(
        self, server: Server, report: Report, timeout: float, work: Path, quick: bool = False
    ) -> None:
        self.quick = quick
        self.server = server
        self.report = report
        self.timeout = timeout
        self.work = work

    def call(self, name: str, method: str, params: dict[str, Any] | None = None) -> Any:
        """One request, recorded; None when it failed."""
        start = time.monotonic()
        try:
            result = self.server.call(method, params or {}, self.timeout)
        except RpcError as exc:
            took = time.monotonic() - start
            status = "expected" if exc.code in EXPECTED_CODES else "problem"
            data = f" {json.dumps(exc.data)[:300]}" if exc.data else ""
            self.report.steps.append(Step(name, status, took, f"[{exc.code}] {exc.message}{data}"))
            return None
        took = time.monotonic() - start
        self.report.steps.append(
            Step(name, "problem" if took > SLOW_S else "ok", took, "slow" if took > SLOW_S else "")
        )
        return result

    def check(self, name: str, ok: bool, detail: str) -> None:
        self.report.steps.append(Step(name, "ok" if ok else "problem", 0.0, "" if ok else detail))

    def first_frame(self, flt: str) -> int | None:
        res = self.call(f"count {flt}", "count_matches", {"filter": flt, "limit": 1})
        frames = (res or {}).get("frames") or []
        return frames[0] if frames else None


def record_count(path: Path) -> int | None:
    """Records in a capture as tshark reads them (capinfos counts a Sysdig
    file's system-call events as 0 packets)."""
    try:
        out = subprocess.run(
            ["tshark", "-n", "-r", str(path), "-T", "fields", "-e", "frame.number"],  # noqa: S607
            capture_output=True,
            timeout=300,
            check=False,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    return len(out.split())


def exercise(path: Path, timeout: float, quick: bool = False) -> Report:
    report = Report(str(path))
    with tempfile.TemporaryDirectory(prefix="pcap-realworld-") as tmp:
        home = Path(tmp) / "home"
        work = Path(tmp) / "out"
        home.mkdir()
        work.mkdir()
        server = Server(home)
        run = Run(server, report, timeout, work, quick)
        try:
            _exercise(run, path, Path(tmp) / "cache")
        except Exception as exc:  # noqa: BLE001 (a harness bug is reported, not fatal)
            report.steps.append(Step("harness", "problem", 0.0, f"{type(exc).__name__}: {exc}"))
        finally:
            run.call("close", "close")
            server.close()
        tracebacks = [i for i, line in enumerate(server.stderr) if "Traceback" in line]
        for i in tracebacks:
            tail = " | ".join(server.stderr[max(0, i - 1) : i + 25][-6:])
            report.steps.append(Step("stderr traceback", "problem", 0.0, tail[:600]))
        for line in server.bad_output[:3]:
            report.steps.append(Step("stdout not JSON", "problem", 0.0, line))
    return report


def _exercise(run: Run, path: Path, cache: Path) -> None:
    if run.call("initialize", "initialize", {}) is None:
        return
    opened = run.call(
        "open",
        "open",
        {
            "path": str(path),
            "stream": True,
            "names": NAMES,
            "columns": [],
            "coloring": {"rules": COLORING},
            "cache": {"dir": str(cache), "maxBytes": 1 << 30},
        },
    )
    if opened is None:
        return
    if opened.get("indexing"):
        start = time.monotonic()
        try:
            done = run.server.wait_for("index", {"done", "failed"}, run.timeout)
        except RpcError as exc:
            run.check("index done", False, exc.message)
            return
        took = time.monotonic() - start
        if done.get("event") == "failed":
            run.report.steps.append(Step("index", "problem", took, json.dumps(done)[:400]))
            return
        run.report.steps.append(Step("index", "ok", took))
    info = run.call("capture_info", "capture_info") or {}
    frames = int(info.get("frames") or info.get("packets") or 0)
    run.report.frames = frames
    expected = record_count(path)
    if expected is not None:
        run.check("frames = tshark", frames == expected, f"viewer {frames}, tshark {expected}")

    if run.quick:
        _quick(run, frames)
    else:
        _packet_list(run, frames)
        if frames:
            _details(run, frames)
            _filters_and_find(run)
            _streams(run)
        _statistics(run)
        _other(run, frames)
        _exports(run, path, frames)
    if frames:
        _replay(run, path)
    # Reopening reads the saved index: same rows.
    again = run.call(
        "reopen (saved index)",
        "open",
        {
            "path": str(path),
            "stream": True,
            "names": NAMES,
            "columns": [],
            "coloring": {"rules": COLORING},
            "cache": {"dir": str(cache), "maxBytes": 1 << 30},
        },
    )
    if again is not None and not again.get("indexing"):
        page = run.call("list after reopen", "list_packets", {"offset": 0, "limit": 50}) or {}
        run.check(
            "reopen total",
            page.get("total") == frames,
            f"total {page.get('total')} after reopening, {frames} before",
        )


def _quick(run: Run, frames: int) -> None:
    """The parts most likely to meet a malformed capture, for big sets of
    small captures (tcpdump's tests): a page, a sort, the first and last
    details, one filter, the main statistics, triage and an export."""
    page = run.call("list first page", "list_packets", {"offset": 0, "limit": 200}) or {}
    run.check("list total", page.get("total") == frames, f"total {page.get('total')} vs {frames}")
    run.call(
        "sort info", "list_packets", {"offset": 0, "limit": 20, "sort": {"field": "_ws.col.info"}}
    )
    names: set[str] = set()
    for n in sorted({1, frames} - {0}):
        detail = run.call(f"detail {n}", "packet_detail", {"number": n})
        if detail:
            _collect_names(detail.get("tree") or [], names)
            _check_tree(run, n, detail)
    if names:
        run.call("field_types", "field_types", {"fields": sorted(names)[:500]})
    run.call("filter ip", "set_filter", {"expr": "ip || ipv6"})
    run.call("list ip", "list_packets", {"offset": 0, "limit": 50})
    run.call("filter clear", "set_filter", {"expr": ""})
    for params in ({"kind": "phs"}, {"kind": "conversations", "type": "ip"}, {"kind": "expert"}):
        run.call(f"stats {params['kind']}", "stats", params)
    tcp = run.first_frame("tcp") if frames else None
    if tcp is not None:
        run.call("follow tcp", "follow_stream", {"proto": "tcp", "frame": tcp})
    run.call("voip calls", "voip_calls", {})
    run.call("triage", "triage", {})
    run.call("capture profile", "capture_profile", {})
    run.call("comments", "packet_comments", {"frames": list(range(1, min(frames, 50) + 1))})
    dest = run.work / "all.pcapng"
    if run.call("export pcapng", "export", {"kind": "pcapng", "dest": str(dest), "filter": ""}):
        got = record_count(dest)
        run.check(
            "export pcapng count", got == frames, f"{got} packets written, {frames} in capture"
        )


def _packet_list(run: Run, frames: int) -> None:
    page = run.call("list first page", "list_packets", {"offset": 0, "limit": 200}) or {}
    rows = page.get("rows") or []
    run.check("list total", page.get("total") == frames, f"total {page.get('total')} vs {frames}")
    run.check(
        "first page rows",
        len(rows) == min(200, frames),
        f"{len(rows)} rows, expected {min(200, frames)}",
    )
    if frames > 200:
        last = run.call("list last page", "list_packets", {"offset": frames - 50, "limit": 50})
        got = len((last or {}).get("rows") or [])
        run.check("last page rows", got == 50, f"{got} rows on the last page")
    for field_name in (
        "frame.number",
        "_ws.col.def_src",
        "_ws.col.protocol",
        "frame.len",
        "_ws.col.info",
    ):
        for desc in (False, True):
            res = run.call(
                f"sort {field_name}{' desc' if desc else ''}",
                "list_packets",
                {"offset": 0, "limit": 20, "sort": {"field": field_name, "desc": desc}},
            )
            if res is not None and field_name == "frame.number" and frames:
                first = (res.get("rows") or [{}])[0]
                want = frames if desc else 1
                got = first.get("frame", first.get("number"))
                run.check("sort by number", got == want, f"first row {got}, expected {want}")
    for fmt in ("relative", "delta_displayed", "delta_captured", "absolute", "utc", "epoch"):
        run.call(f"time {fmt}", "list_packets", {"offset": 0, "limit": 50, "timeFormat": fmt})
    run.call(
        "sort by delta time",
        "list_packets",
        {
            "offset": 0,
            "limit": 20,
            "sort": {"field": "frame.time_relative"},
            "timeFormat": "delta_displayed",
        },
    )
    if frames:
        run.call(
            "overview",
            "view_overview",
            {"buckets": 400, "sort": None, "timeFormat": "relative"},
        )


def _details(run: Run, frames: int) -> None:
    picks = sorted({1, (frames + 1) // 2, frames})
    names: set[str] = set()
    for n in picks:
        detail = run.call(f"detail {n}", "packet_detail", {"number": n})
        if detail:
            _collect_names(detail.get("tree") or [], names)
            _check_tree(run, n, detail)
    if frames <= 10_000:
        run.call("detail two-pass", "packet_detail", {"number": picks[-1], "twoPass": True})
    run.call("detail quick", "packet_detail", {"number": frames, "mode": "quick", "window": 50})
    if names:
        run.call("field_types", "field_types", {"fields": sorted(names)[:500]})
    run.call(
        "bytes export", "export", {"kind": "bytes", "number": 1, "dest": str(run.work / "b.bin")}
    )


def _collect_names(nodes: list[dict[str, Any]], out: set[str]) -> None:
    for node in nodes:
        if node.get("name"):
            out.add(node["name"])
        _collect_names(node.get("children") or [], out)


def _check_tree(run: Run, n: int, detail: dict[str, Any]) -> None:
    """Each field must lie in its byte source, with its raw value there. A
    field that fits no source at all is tshark's own position (its Babel
    dissector reports offsets past the packet): a note, not our problem."""
    data = [bytes.fromhex(s.get("hex") or "") for s in detail.get("sources") or []]
    if not data:
        return
    wrong: list[str] = []
    upstream: list[str] = []

    def fits(i: int, pos: int, size: int, raw: str) -> bool:
        if pos + size > len(data[i]):
            return False
        return len(raw) != 2 * size or data[i][pos : pos + size].hex() == raw

    def walk(nodes: list[dict[str, Any]]) -> None:
        for node in nodes:
            pos, size, src = node.get("pos"), node.get("size"), node.get("src", 0)
            if isinstance(pos, int) and isinstance(size, int) and 0 <= src < len(data):
                raw = node.get("value") or ""
                if not fits(src, pos, size, raw):
                    what = f"{node.get('name') or node.get('label', '')[:30]} {pos}+{size} in {src}"
                    others = [i for i in range(len(data)) if i != src and fits(i, pos, size, raw)]
                    (wrong if others else upstream).append(
                        what + (f", fits {others}" if others else "")
                    )
            walk(node.get("children") or [])

    walk(detail.get("tree") or [])
    run.check(f"detail {n} byte sources", not wrong, "; ".join(wrong[:4]))
    if upstream:
        run.report.steps.append(
            Step(f"detail {n} tshark positions", "note", 0.0, "; ".join(upstream[:4]))
        )


def _filters_and_find(run: Run) -> None:
    for expr in ("ip || ipv6", "tcp", "udp", "frame.len > 100", "!(arp)"):
        res = run.call(f"filter {expr}", "set_filter", {"expr": expr})
        if res is None:
            continue
        count = run.call(f"count {expr}", "count_matches", {"filter": expr})
        shown = res.get("matchCount")
        if count is not None:
            run.check(
                f"filter {expr} count",
                count.get("count") == shown,
                f"set_filter {shown}, count_matches {count}",
            )
        run.call(f"list {expr}", "list_packets", {"offset": 0, "limit": 100})
    run.call("filter clear", "set_filter", {"expr": ""})
    for mode, value, where in (
        ("string", "a", "bytes"),
        ("string", "a", "list"),
        ("string", "a", "details"),
        ("regex", "[0-9]{3}", "details"),
        ("hex", "00", "bytes"),
        ("filter", "frame.len > 60", "bytes"),
    ):
        run.call(
            f"find {mode} in {where}", "find_packet", {"mode": mode, "value": value, "in": where}
        )
    run.call("mark", "mark_packets", {"frames": [1]})
    run.call("find marked", "find_packet", {"mode": "marked"})
    run.call("neighbor", "neighbor_frame", {"frame": 1, "direction": "next"})
    run.call("ignore", "ignore_packets", {"frames": [1]})
    run.call("expert with ignored", "expert_summary", {})
    run.call("unignore", "unignore_all", {})
    run.call("filter hints", "filter_hints", {"expr": 'http.host == "Example" && tcp.port == 1'})
    for fld in ("ip.src", "frame.len", "_ws.col.protocol", "eth.src"):
        run.call(f"values {fld}", "field_values", {"field": fld, "limit": 20})


def _streams(run: Run) -> None:
    for proto, flt in (
        ("tcp", "tcp"),
        ("udp", "udp"),
        ("tls", "tls"),
        ("http", "http"),
        ("http2", "http2"),
        ("quic", "quic"),
        ("websocket", "websocket"),
    ):
        frame = run.first_frame(flt)
        if frame is not None:
            res = run.call(f"follow {proto}", "follow_stream", {"proto": proto, "frame": frame})
            if res is not None and not res.get("hint"):
                segs = res.get("segments")
                run.check(
                    f"follow {proto} segments", isinstance(segs, list), f"segments {segs!r:.80}"
                )
    tcp = run.first_frame("tcp")
    if tcp is not None:
        run.call("tcp graph", "tcp_graph", {"frame": tcp})
    run.call("flow graph", "flow_graph", {"offset": 0, "limit": 200})
    voip = run.call("voip calls", "voip_calls", {})
    streams = (voip or {}).get("streams") or []
    if streams:
        key = streams[0].get("key", streams[0])
        run.call("rtp stream", "rtp_stream", {"stream": key})
        run.call(
            "rtp audio",
            "rtp_audio",
            {"stream": key, "dest": str(run.work / "a.wav"), "format": "wav"},
        )
    run.call("voip heuristic", "voip_calls", {"heuristic": True})


STATS: list[dict[str, Any]] = [
    {"kind": "phs"},
    *({"kind": "conversations", "type": t} for t in ("eth", "ip", "ipv6", "tcp", "udp")),
    *({"kind": "endpoints", "type": t} for t in ("eth", "ip", "ipv6", "tcp", "udp")),
    {"kind": "io"},
    {
        "kind": "io",
        "series": [{"metric": "packets", "filter": "tcp"}, {"metric": "sum", "field": "frame.len"}],
    },
    {"kind": "expert"},
    {"kind": "properties"},
    *({"kind": "http", "type": t} for t in ("packets", "requests", "load")),
    {"kind": "dns"},
    {"kind": "plen"},
    {"kind": "srt", "type": "auto"},
    {"kind": "sip"},
    {"kind": "credentials"},
    *({"kind": "ipv4", "type": t} for t in ("addresses", "srcdst", "ptype", "dests")),
    *({"kind": "ipv6", "type": t} for t in ("addresses", "srcdst", "ptype", "dests")),
    {"kind": "multicast"},
    {"kind": "hosts"},
    {"kind": "sctp"},
    {"kind": "conversations", "type": "tcp", "filter": "tcp.port == 80"},
]


def _statistics(run: Run) -> None:
    for params in STATS:
        label = " ".join(str(v) if not isinstance(v, list) else "series" for v in params.values())
        res = run.call(f"stats {label}", "stats", params)
        if res is not None:
            run.check(
                f"stats {label} shape",
                isinstance(res.get("rows"), list) and isinstance(res.get("columns"), list),
                f"keys {sorted(res)[:8]}",
            )
    run.call("expert summary", "expert_summary", {})


def _other(run: Run, frames: int) -> None:
    objects = run.call("export objects", "export_objects", {})
    for obj in ((objects or {}).get("objects") or [])[:2]:
        run.call(
            "save object",
            "save_objects",
            {"ids": [obj.get("id")], "dir": str(run.work)},
        )
    run.call("comments", "packet_comments", {"frames": list(range(1, min(frames, 50) + 1))})
    run.call("triage", "triage", {})
    run.call("capture profile", "capture_profile", {})
    run.call("scans", "scans", {})
    run.call("file format", "file_format", {})
    if frames:
        run.call("colors again", "set_coloring", {"rules": COLORING})


def _exports(run: Run, path: Path, frames: int) -> None:
    for kind in ("pcapng", "pcap"):
        dest = run.work / f"all.{kind}"
        if (
            run.call(f"export {kind}", "export", {"kind": kind, "dest": str(dest), "filter": ""})
            is None
        ):
            continue
        got = record_count(dest)
        # pcap can't hold every link type; a refusal is reported as an error above.
        run.check(
            f"export {kind} count", got == frames, f"{got} packets written, {frames} in capture"
        )
    for kind in ("csv", "json"):
        dest = run.work / f"list.{kind}"
        if run.call(f"export {kind}", "export", {"kind": kind, "dest": str(dest)}) is None:
            continue
        text = dest.read_text(encoding="utf-8")
        if kind == "json":
            try:
                rows = json.loads(text)
                run.check("export json rows", len(rows) == frames, f"{len(rows)} rows")
            except ValueError as exc:
                run.check("export json parses", False, str(exc))
        else:
            run.check("export csv rows", text.count("\n") >= frames, f"{text.count(chr(10))} lines")
    for fmt in ("text", "pdml", "json"):
        dest = run.work / f"diss.{fmt}"
        res = run.call(
            f"export dissections {fmt}",
            "export",
            {"kind": "dissections", "format": fmt, "dest": str(dest), "filter": "", "bytes": True},
        )
        if res is not None and fmt == "json" and frames:
            try:
                run.check(
                    "dissections json", len(json.loads(dest.read_text("utf-8"))) == frames, "count"
                )
            except ValueError as exc:
                run.check("dissections json parses", False, str(exc)[:200])
    run.call(
        "edit dedup", "edit_capture", {"operation": "dedup", "dest": str(run.work / "d.pcapng")}
    )
    if path.suffix != ".gz":
        run.call("probe file", "probe_file", {"path": str(path)})


# --- replay to service -------------------------------------------------------

# Streams a replay check sends: tshark's Follow runs once for each of them.
REPLAY_STREAMS = 30
REPLAY_SCOPE = f"tcp.stream < {REPLAY_STREAMS} || udp.stream < {REPLAY_STREAMS}"
# Follow's stand-in for bytes the capture lacks (a replay leaves them out).
MISSING = re.compile(rb"\[\d+ bytes missing in capture file\]\x00?")


class Sink:
    """A local TCP server and UDP socket keeping what each connection and
    datagram brought (the services a replay check sends to)."""

    def __init__(self) -> None:
        self.tcp = socket.create_server(("127.0.0.1", 0), backlog=1024)
        self.tcp.setblocking(False)
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
        self.udp.bind(("127.0.0.1", 0))
        self.udp.setblocking(False)
        self.connections: list[bytearray] = []
        self.reset: list[bool] = []
        self.datagrams: list[bytes] = []
        self._sel = selectors.DefaultSelector()
        self._sel.register(self.tcp, selectors.EVENT_READ)
        self._sel.register(self.udp, selectors.EVENT_READ)
        self._open = 0
        self._last = time.monotonic()
        self._stopping = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def port(self, proto: str) -> int:
        return int((self.tcp if proto == "tcp" else self.udp).getsockname()[1])

    def _loop(self) -> None:
        deadline = 0.0
        while True:
            now = time.monotonic()
            if self._stopping.is_set():
                deadline = deadline or now + 10
                if now > deadline or (not self._open and now - self._last > 0.5):
                    break
            for key, _ in self._sel.select(0.05):
                self._last = time.monotonic()
                sock = key.fileobj
                assert isinstance(sock, socket.socket)
                if sock is self.tcp:
                    with contextlib.suppress(BlockingIOError):
                        conn, _ = self.tcp.accept()
                        conn.setblocking(False)
                        self._sel.register(conn, selectors.EVENT_READ, len(self.connections))
                        self.connections.append(bytearray())
                        self.reset.append(False)
                        self._open += 1
                elif sock is self.udp:
                    with contextlib.suppress(BlockingIOError):
                        self.datagrams.append(self.udp.recv(65536))
                else:
                    self._read(sock, key.data)
        for key in list(self._sel.get_map().values()):
            self._sel.unregister(key.fileobj)
            key.fileobj.close()  # type: ignore[union-attr]
        self._sel.close()

    def _read(self, sock: socket.socket, i: int) -> None:
        try:
            chunk = sock.recv(1 << 16)
        except BlockingIOError:
            return
        except OSError:
            self.reset[i] = True
            chunk = b""
        if chunk:
            self.connections[i] += chunk
            return
        self._sel.unregister(sock)
        sock.close()
        self._open -= 1

    def close(self) -> None:
        """Wait for the connections to end (10 s at most), then close everything."""
        self._stopping.set()
        self._thread.join()


def follow_payloads(path: Path) -> tuple[list[bytes], list[bytes]]:
    """What tshark's Follow says each direction of the first REPLAY_STREAMS
    TCP streams carried, and every UDP datagram of the first UDP streams."""
    args = ["tshark", "-n", "-q", "-r", str(path)]
    for proto in ("tcp", "udp"):
        for i in range(REPLAY_STREAMS):
            args += ["-z", f"follow,{proto},raw,{i}"]
    try:
        out = subprocess.run(
            args, capture_output=True, timeout=600, check=False, text=True, errors="replace"
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return [], []
    udp: list[bytes] = []
    proto = ""
    sides: list[bytearray] = []
    tcp_sides: list[bytearray] = []
    for line in out.split("\n"):
        if line.startswith("Follow: "):
            proto = line.split()[1].split(",")[0]
            sides = [bytearray(), bytearray()]
            if proto == "tcp":
                tcp_sides.extend(sides)
        elif line.startswith(("=", "Filter:", "Node ")) or not line.strip():
            continue
        elif sides:
            with contextlib.suppress(ValueError):
                data = bytes.fromhex(line.strip())
                if MISSING.fullmatch(data):
                    continue
                if proto == "udp":
                    udp.append(data)
                else:
                    sides[1 if line.startswith("\t") else 0] += data
    return [bytes(t) for t in tcp_sides if t], udp


def segment_payloads(path: Path) -> list[bytes]:
    """Each direction of the first REPLAY_STREAMS TCP streams as its
    segments' payloads in sequence order, every byte once (the first copy)."""
    args = ["tshark", "-n", "-r", str(path), "-Y", f"tcp.stream < {REPLAY_STREAMS} && tcp.len > 0"]
    args += ["-T", "fields", "-E", "occurrence=l"]
    for name in ("tcp.stream", "ip.src", "ipv6.src", "tcp.srcport", "tcp.seq_raw", "tcp.payload"):
        args += ["-e", name]
    try:
        out = subprocess.run(
            args, capture_output=True, timeout=600, check=False, text=True, errors="replace"
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    sides: dict[tuple[str, ...], dict[int, bytes]] = {}
    for line in out.split("\n"):
        cells = line.split("\t")
        if len(cells) != 6 or not cells[4] or not cells[5]:
            continue
        with contextlib.suppress(ValueError):
            side = sides.setdefault((cells[0], cells[1] or cells[2], cells[3]), {})
            side.setdefault(int(cells[4]), bytes.fromhex(cells[5].replace(":", "")))
    result = []
    for segments in sides.values():
        data = bytearray()
        end: int | None = None
        for seq in sorted(segments):  # (no wrap-around: these are short test captures)
            payload = segments[seq]
            if end is None:
                end = seq
            if seq + len(payload) > end:
                data += payload[max(0, end - seq) :]
                end = seq + len(payload)
        result.append(bytes(data))
    return result


def _replay(run: Run, path: Path) -> None:
    """Replay the first streams' client side into local servers, at no
    pauses, and check what arrived against tshark's Follow."""
    known = run.call("replay targets", "replay_targets", {"filter": REPLAY_SCOPE})
    targets = (known or {}).get("targets") or []
    if not targets:
        return
    sink = Sink()
    try:
        res = run.call(
            "replay",
            "replay",
            {
                "filter": REPLAY_SCOPE,
                "speed": 0,
                "targets": {
                    t["key"]: {"ip": "127.0.0.1", "port": sink.port(t["proto"])} for t in targets
                },
            },
        )
    finally:
        sink.close()
    if res is None:
        return
    sent = {t["key"]: t for t in res.get("targets") or []}
    planned = sum(t["bytes"] for t in targets)
    run.check(
        "replay sent = planned",
        sum(t["bytes"] for t in sent.values()) == planned,
        f"{sum(t['bytes'] for t in sent.values())} bytes sent, {planned} planned",
    )
    errors = [f"{k}: {e}" for k, t in sent.items() for e in t.get("errors") or []]
    run.check("replay errors", not errors, "; ".join(errors)[:600])
    tcp_sent = sum(t["bytes"] - t["dropped"] for t in sent.values() if t["key"].startswith("tcp"))
    tcp_got = sum(len(c) for c in sink.connections)
    run.check(
        "replay tcp received",
        tcp_got == tcp_sent,
        f"{tcp_got} bytes arrived, {tcp_sent} sent",
    )
    tcp, udp = follow_payloads(path)

    def matches(i: int, sides: list[bytes]) -> bool:
        c = sink.connections[i]
        return any(f == c or (sink.reset[i] and f.startswith(c)) for f in sides)

    wrong = [i for i, c in enumerate(sink.connections) if c and not matches(i, tcp)]
    # Follow shows what a dissector hands its tap, which isn't always the
    # segments' payload (DTN's TCPCLv4 transfers): those count when they
    # equal the payloads put in sequence order.
    upstream = [i for i in wrong if matches(i, segment_payloads(path))] if wrong else []
    wrong = [i for i in wrong if i not in upstream]
    if upstream:
        run.report.steps.append(
            Step(
                "replay tcp = follow",
                "note",
                0.0,
                f"{len(upstream)} connections equal their segments' payloads, not Follow",
            )
        )
    first = bytes(sink.connections[wrong[0]]) if wrong else b""
    run.check(
        "replay tcp = segments",
        not wrong,
        f"{len(wrong)} of {len(sink.connections)} connections differ from every Follow direction"
        f" and the segments' payloads, e.g. {len(first)} bytes {first[:24].hex()}",
    )
    datagrams = sum(t["datagrams"] for t in sent.values())
    run.check(
        "replay udp received",
        len(sink.datagrams) == datagrams,
        f"{len(sink.datagrams)} datagrams arrived, {datagrams} sent",
    )
    pool = Counter(udp)
    pool.subtract(d for d in sink.datagrams if d)  # Follow shows no empty datagram
    extra = -sum(n for n in pool.values() if n < 0)
    run.check("replay udp = follow", not extra, f"{extra} datagrams Follow doesn't show")


# --- main --------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("paths", nargs="*", type=Path, help="captures or folders of captures")
    ap.add_argument(
        "--fetch",
        action="append",
        choices=["wireshark", "tcpdump"],
        default=[],
        help="download and run a source's test captures (repeatable)",
    )
    ap.add_argument("--only", help="only captures whose name contains this")
    ap.add_argument("--quick", action="store_true", help="fewer steps per capture")
    ap.add_argument("-j", "--jobs", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    ap.add_argument("--timeout", type=float, default=120.0, help="seconds per request")
    ap.add_argument("--out", type=Path, help="write the full report as JSON")
    args = ap.parse_args(argv)

    captures: list[Path] = []
    if "wireshark" in args.fetch:
        captures += fetch_wireshark(CACHE / "wireshark")
    if "tcpdump" in args.fetch:
        captures += fetch_tcpdump(CACHE / "tcpdump")
    for p in args.paths:
        captures += sorted(x for x in p.rglob("*") if x.is_file()) if p.is_dir() else [p]
    if args.only:
        captures = [c for c in captures if args.only in c.name]
    if not captures:
        ap.error("no captures: give paths or --fetch")

    reports: list[Report] = []
    with ThreadPoolExecutor(args.jobs) as pool:
        for report in pool.map(lambda c: exercise(c, args.timeout, args.quick), captures):
            reports.append(report)
            bad = report.problems()
            mark = "PROBLEM" if bad else "ok"
            print(f"{mark:8} {Path(report.capture).name} ({report.frames} packets)", flush=True)
            for step in bad:
                print(f"         {step.name}: {step.detail[:300]}", flush=True)

    kinds = Counter(
        (s.name.split(" ")[0], s.detail.split("]")[0] + "]" if s.detail.startswith("[") else s.name)
        for r in reports
        for s in r.problems()
    )
    print(f"\n{len(reports)} captures, {sum(1 for r in reports if r.problems())} with problems")
    for (name, what), n in kinds.most_common(40):
        print(f"{n:5}  {name}  {what}")
    if args.out:
        args.out.write_text(
            json.dumps(
                [
                    {
                        "capture": r.capture,
                        "frames": r.frames,
                        "steps": [s.__dict__ for s in r.steps],
                    }
                    for r in reports
                ],
                indent=1,
            ),
            encoding="utf-8",
        )
    return 1 if any(r.problems() for r in reports) else 0


if __name__ == "__main__":
    sys.exit(main())
