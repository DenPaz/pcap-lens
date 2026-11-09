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
                (2, 1, 50_000, "python3"),
                (child.pid, 2, 200 << 10, "/usr/bin/tshark"),
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
                (backend, 1, 900 << 10, "python3"),  # ours, but not a Wireshark tool
                (small, backend, 50 << 10, "tshark"),  # under the cap
                (foreign, 999, 900 << 10, "tshark"),  # not started by the harness
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
    rows = harness.MemoryWatch._processes()
    assert any(pid == os.getpid() and rss > 0 for pid, _ppid, rss, _name in rows)
