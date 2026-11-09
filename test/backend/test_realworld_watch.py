"""The real-capture harness's memory watch (test/realworld/run.py): it kills
only Wireshark tools it started that grew past the cap."""

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
    assert harness.busy_tools(10) == ["tshark at 99% CPU", "tshark at 40% CPU"]
    assert harness.busy_tools(12) == []


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
