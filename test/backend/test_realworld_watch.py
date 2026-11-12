"""The real-capture harness (test/realworld/run.py): its memory watch, which
kills only Wireshark tools it started that grew past the cap, and the checks
that need no capture."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="the watch needs ps and SIGKILL")

RUN_PY = Path(__file__).resolve().parents[1] / "realworld" / "run.py"


@pytest.fixture(scope="module")
def harness() -> ModuleType:
    spec = importlib.util.spec_from_file_location("realworld_run", RUN_PY)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # (its dataclasses look their module up)
    spec.loader.exec_module(module)
    return module


def _sleeper() -> subprocess.Popen[bytes]:
    return subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])


def test_kills_a_tool_over_the_cap_at_any_depth(harness: ModuleType) -> None:
    child = _sleeper()
    try:
        watch = harness.MemoryWatch(100)
        # The harness (1) started a backend (2), which started the "tshark" (child).
        watch.check(
            [
                harness.Proc(2, 1, 50_000, 1.0, "S", "python3"),
                harness.Proc(child.pid, 2, 200 << 10, 99.0, "R", "tshark"),
            ],
            root=1,
        )
        assert child.wait(timeout=10) < 0  # (killed by a signal)
        assert watch.killed == [f"tshark (pid {child.pid}) at 200 MB"]
    finally:
        child.kill()
        child.wait()


def test_leaves_backends_small_tools_and_other_processes_alone(harness: ModuleType) -> None:
    children = [_sleeper() for _ in range(3)]
    try:
        backend, small, foreign = (c.pid for c in children)
        watch = harness.MemoryWatch(100)
        watch.check(
            [
                harness.Proc(
                    backend, 1, 900 << 10, 1.0, "S", "python3"
                ),  # ours, not a Wireshark tool
                harness.Proc(small, backend, 50 << 10, 1.0, "S", "tshark"),  # under the cap
                harness.Proc(foreign, 999, 900 << 10, 1.0, "S", "tshark"),  # not the harness's
            ],
            root=1,
        )
        assert watch.killed == []
        assert all(c.poll() is None for c in children)
    finally:
        for c in children:
            c.kill()
            c.wait()


def test_ps_lists_this_process(harness: ModuleType) -> None:
    rows = harness.processes()
    assert any(p.pid == os.getpid() and p.rss_kb > 0 and p.program for p in rows)


def test_ps_is_read_in_the_c_locale_and_with_a_decimal_comma(
    harness: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    # macOS's ps writes "0,0" in pt_BR: every row was dropped there.
    seen: dict[str, str] = {}

    def fake_ps(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        env = kwargs["env"]
        assert isinstance(env, dict)
        seen.update(env)
        out = "  10     1  2048   0,5 Ss   /usr/bin/python3\n  11    10  4096  97,3 R+   tshark\n"
        return subprocess.CompletedProcess(argv, 0, out, "")

    monkeypatch.setattr(harness.subprocess, "run", fake_ps)
    assert harness.processes() == [
        harness.Proc(10, 1, 2048, 0.5, "Ss", "python3"),
        harness.Proc(11, 10, 4096, 97.3, "R+", "tshark"),
    ]
    assert seen["LC_ALL"] == "C"


def test_a_busy_tshark_under_the_backend_is_named(
    harness: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    # (A request waiting on it is tshark's slowness: a note, not a problem.)
    procs = [
        harness.Proc(10, 1, 100_000, 2.0, "S", "python3"),  # the backend
        harness.Proc(11, 10, 150_000, 99.0, "R", "tshark"),  # looping
        harness.Proc(12, 10, 150_000, 3.0, "S+", "tshark"),  # waiting on its reader
        harness.Proc(14, 10, 150_000, 40.0, "R+", "tshark"),  # sharing a CPU
        harness.Proc(13, 99, 150_000, 99.0, "R", "tshark"),  # someone else's
    ]
    monkeypatch.setattr(harness, "processes", lambda: procs)
    monkeypatch.setattr(harness, "core_dumping", lambda pid: pid == 12)
    assert harness.busy_tools(10) == [
        "tshark at 99% CPU",
        "tshark crashed, its core still being dumped",
        "tshark at 40% CPU",
    ]
    assert harness.busy_tools(12) == []


def test_core_dumping_reads_the_process_status(harness: ModuleType) -> None:
    # (This process isn't being dumped; a pid that's gone isn't either.)
    if not Path("/proc/self/status").exists():
        pytest.skip("no /proc")
    assert harness.core_dumping(os.getpid()) is False
    assert harness.core_dumping(2**22 + 12345) is False


def test_a_count_tshark_could_not_finish_is_unknown(
    harness: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A tshark killed mid-count (MemoryWatch) printed nothing: not "0 packets".
    killed = subprocess.CompletedProcess(["tshark"], -9, b"", b"")
    monkeypatch.setattr(harness.subprocess, "run", lambda *_a, **_k: killed)
    assert harness.record_count(tmp_path / "x.pcap") is None
    done = subprocess.CompletedProcess(["tshark"], 0, b"1\n2\n3\n", b"")
    monkeypatch.setattr(harness.subprocess, "run", lambda *_a, **_k: done)
    assert harness.record_count(tmp_path / "x.pcap") == 3


def test_steps_waiting_on_a_busy_tshark_are_counted(harness: ModuleType) -> None:
    # (Notes, not problems; the count shows a slowdown of ours as a jump.)
    def report(capture: str, *steps: tuple[str, str]) -> object:
        r = harness.Report(capture)
        r.steps = [harness.Step("x", status, 1.0, detail) for status, detail in steps]
        return r

    busy = "(tshark's own dissection: tshark at 99% CPU)"
    reports = [
        report("a.pcap", ("note", f"slow {busy}"), ("note", f"[0] no answer in 120 s {busy}")),
        report("b.pcap", ("note", f"slow {busy}"), ("problem", "slow"), ("ok", "")),
        report("c.pcap", ("note", "tshark crashed (a segmentation fault)")),
    ]
    assert harness.busy_summary(reports) == (
        "2 steps slow and 1 timed out while tshark was busy (notes, in 2 captures)"
    )
    assert harness.busy_summary(reports[2:]) is None


def test_problems_are_listed_again_after_the_totals(
    harness: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    r = harness.Report("/cache/x.pcap")
    r.steps = [
        harness.Step("open", "ok", 1.0, ""),
        harness.Step("export pcap", "problem", 1.0, "[-32002] tshark failed:\n  line two"),
        harness.Step("triage", "note", 1.0, "slow"),
    ]
    assert harness.problem_lines([r]) == ["  x.pcap: export pcap: [-32002] tshark failed: line two"]
    monkeypatch.setattr(harness, "MAX_LISTED_PROBLEMS", 1)
    r.steps.append(harness.Step("stats", "problem", 1.0, "slow"))
    assert harness.problem_lines([r])[-1] == "  … and 1 more"


def test_segments_start_after_the_syn(
    harness: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # m3ua_coverage: the first data segment reuses the SYN's sequence number.
    # A receiver (and the replay planner) drops that byte; tshark 4.6's Follow
    # keeps it, so the segments must say what the replay should have sent.
    rows = [
        # stream, ip.src, ipv6.src, srcport, seq_raw, payload, udp.payload, syn
        ("0", "192.0.2.1", "", "40001", "1", "", "", "1"),
        ("0", "192.0.2.1", "", "40001", "1", "01000301", "", "0"),
        ("0", "192.0.2.1", "", "40001", "5", "aabb", "", "0"),
        ("0", "192.0.2.2", "", "2905", "7", "", "", "True"),  # the SYN-ACK
        ("0", "192.0.2.2", "", "2905", "8", "cc", "", "False"),
        ("1", "192.0.2.3", "", "40002", "100", "dd", "", "0"),  # no SYN captured
        ("", "", "", "", "", "", "ee", ""),
    ]
    out = "".join("\t".join(r) + "\n" for r in rows)
    done = subprocess.CompletedProcess(["tshark"], 0, out, "")
    monkeypatch.setattr(harness.subprocess, "run", lambda *_a, **_k: done)
    tcp, udp = harness.segment_payloads(tmp_path / "x.pcap")
    assert tcp == [bytes.fromhex("000301aabb"), b"\xcc", b"\xdd"]
    assert udp == [b"\xee"]


def test_overview_rows_against_their_filters(harness: ModuleType) -> None:
    status = harness.overview_row_status
    assert status("exact", "ip.addr == 10.0.0.1", 5, 5) == "ok"
    assert status("exact", "ip.addr == 10.0.0.1", 6, 5) == "problem"
    assert status("at least", "udp", 452, 427) == "ok"
    assert status("at least", "udp", 400, 427) == "problem"
    assert status("some", 'http.request.method == "GET"', 0, 3) == "problem"
    assert status("some", 'http.request.method == "GET"', 1, 3) == "ok"
    # tshark 4.6's hierarchy counts malformed layers its own filter misses: a note.
    assert status("at least", "_ws.malformed", 0, 3) == "note"
    assert status("exact", "_ws.malformed", 0, 3) == "problem"


def test_a_timeout_names_what_it_waited_on(harness: ModuleType) -> None:
    # (No busy tool: the states and any crash reporter say why next time.)
    procs = [
        harness.Proc(10, 1, 100_000, 2.0, "S", "python3"),  # the backend
        harness.Proc(11, 10, 900 * 1024, 0.0, "U", "tshark"),
        harness.Proc(12, 1, 50_000, 30.0, "S", "ReportCrash"),
        harness.Proc(13, 99, 150_000, 0.0, "S", "tshark"),  # someone else's
    ]
    assert harness.waiting_on(procs, 10) == ["tshark U 0% CPU 900 MB", "ReportCrash running"]
    assert harness.waiting_on(procs[:1], 10) == []


def test_a_part_takes_every_nth_capture(harness: ModuleType) -> None:
    items = list(range(1, 8))
    assert harness.part_of(items, "1/2") == [1, 3, 5, 7]
    assert harness.part_of(items, "2/2") == [2, 4, 6]
    assert harness.part_of(items, "1/1") == items
    for bad in ("0/2", "3/2", "2", "a/b", "1/0"):
        with pytest.raises(ValueError, match="K/N"):
            harness.part_of(items, bad)
