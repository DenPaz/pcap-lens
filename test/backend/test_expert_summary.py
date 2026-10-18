"""expert_summary: expert items per severity for the viewer's status bar."""

from __future__ import annotations

import threading
from collections import Counter
from pathlib import Path

import pytest

from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import IndexingError, NotOpenError, RequestContext

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.mark.tshark
def test_counts_match_the_expert_statistics(service: PcapService, ctx: RequestContext) -> None:
    with pytest.raises(NotOpenError):
        service.expert_summary({}, ctx)
    service.open({"path": str(FIXTURES / "mixed.pcapng")}, ctx)
    counts = service.expert_summary({}, ctx)["counts"]
    table = service.stats({"kind": "expert"}, ctx)
    expected: Counter[str] = Counter()
    for row in table["rows"]:
        expected[row["cells"][0].lower()] += row["cells"][4]
    assert counts == {s: expected[s] for s in ("error", "warning", "note", "chat", "comment")}
    assert sum(counts.values()) > 0
    # Cached for the open capture.
    assert service.expert_summary({}, ctx)["counts"] is counts


@pytest.mark.tshark
def test_waits_for_indexing(
    service: PcapService, ctx: RequestContext, slow_index: threading.Event
) -> None:
    service.open({"path": str(FIXTURES / "http.pcap"), "stream": True}, ctx)
    with pytest.raises(IndexingError):
        service.expert_summary({}, ctx)
    slow_index.set()
