"""A newer open, or a close, while an open is still in progress.

The open in progress has made its work folder but not yet attached its capture.
Found by a stress test of overlapping requests (a reload while a slow capture
opens): the close removed that folder, the first open then attached a capture
whose rows file was gone (every page an internal error), and the newer open
replaced it without closing it.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

import pytest

from pcap_backend import tshark as ts
from pcap_backend.cancellation import CancelledError, CancelToken
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import NotOpenError, RequestContext

pytestmark = [pytest.mark.tshark, pytest.mark.usefixtures("slow_index")]


def _open_in_background(
    service: PcapService, path: Path
) -> tuple[threading.Thread, dict[str, Any], Path]:
    """A non-streaming open (it waits for the whole, held, index pass); its work folder."""
    outcome: dict[str, Any] = {}
    token = CancelToken()

    def run() -> None:
        try:
            outcome["result"] = service.open({"path": str(path)}, RequestContext(token=token))
        except BaseException as exc:  # noqa: BLE001 - the test looks at it
            outcome["error"] = exc

    thread = threading.Thread(target=run)
    thread.start()
    end = time.monotonic() + 10
    while service._work_dir is None and time.monotonic() < end:
        time.sleep(0.01)
    time.sleep(0.2)  # (its work folder made, its pass held)
    work_dir = service._work_dir
    assert work_dir is not None and work_dir.is_dir()
    return thread, outcome, work_dir


def test_a_newer_open_supersedes_one_in_progress(
    service: PcapService, ctx: RequestContext, fixtures: Path
) -> None:
    thread, outcome, first_dir = _open_in_background(service, fixtures / "mixed.pcapng")
    result = service.open({"path": str(fixtures / "http.pcap"), "stream": True}, ctx)
    thread.join(timeout=30)
    assert isinstance(outcome.get("error"), CancelledError)
    assert result["path"].endswith("http.pcap")
    page = service.list_packets({"offset": 0, "limit": 3}, ctx)
    assert [row["number"] for row in page["rows"]] == [1, 2, 3]
    assert not first_dir.exists()
    assert service._work_dir is not None and service._work_dir.is_dir()


def test_a_close_supersedes_an_open_in_progress(
    service: PcapService, ctx: RequestContext, fixtures: Path
) -> None:
    thread, outcome, first_dir = _open_in_background(service, fixtures / "mixed.pcapng")
    service.close({}, ctx)
    thread.join(timeout=30)
    assert isinstance(outcome.get("error"), CancelledError)
    with pytest.raises(NotOpenError):
        service.list_packets({"offset": 0, "limit": 5}, ctx)
    assert not first_dir.exists()
    assert len(ts.PROCESSES) == 0
