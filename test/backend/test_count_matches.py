"""count_matches: counting a display filter without touching the viewer's view."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from pcap_backend.pcap_service import MAX_MATCH_FRAMES, PcapService
from pcap_backend.protocol import (
    FilterError,
    IndexingError,
    InvalidParamsError,
    NotOpenError,
    RequestContext,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.mark.tshark
def test_counts_without_changing_the_view(service: PcapService, ctx: RequestContext) -> None:
    with pytest.raises(NotOpenError):
        service.count_matches({"filter": "dns"}, ctx)
    service.open({"path": str(FIXTURES / "mixed.pcapng")}, ctx)
    view = service.set_filter({"expr": "icmp"}, ctx)
    res = service.count_matches({"filter": "dns", "limit": 3}, ctx)
    assert res == {"filter": "dns", "count": 6, "total": 26, "frames": res["frames"]}
    assert len(res["frames"]) == 3 and res["frames"] == sorted(res["frames"])
    # offset + limit is a page: the next three, then what is left.
    rest = service.count_matches({"filter": "dns", "limit": 3, "offset": 3}, ctx)["frames"]
    assert len(rest) == 3 and rest[0] > res["frames"][-1]
    every = service.count_matches({"filter": "dns", "limit": 6}, ctx)["frames"]
    assert res["frames"] + rest == every
    last = service.count_matches({"filter": "dns", "limit": 3, "offset": 5}, ctx)["frames"]
    assert last == every[5:]
    page = service.count_matches({"filter": "", "limit": 3, "offset": 3}, ctx)["frames"]
    assert page == [4, 5, 6]
    # The view is still the viewer's icmp filter.
    page = service.list_packets({"limit": 50}, ctx)
    assert page["filterId"] == view["filterId"] and page["total"] == view["matchCount"]
    assert service.count_matches({"filter": ""}, ctx)["count"] == 26
    assert service.count_matches({"filter": "frame.number > 1000"}, ctx)["count"] == 0
    # Cached: applying the same filter afterwards needs no tshark pass either.
    assert service.set_filter({"expr": "dns"}, ctx)["matchCount"] == 6


@pytest.mark.tshark
def test_rejects_bad_input(service: PcapService, ctx: RequestContext) -> None:
    service.open({"path": str(FIXTURES / "mixed.pcapng")}, ctx)
    with pytest.raises(FilterError):
        service.count_matches({"filter": "dns.qry.name =="}, ctx)
    for limit in (-1, MAX_MATCH_FRAMES + 1):
        with pytest.raises(InvalidParamsError):
            service.count_matches({"filter": "dns", "limit": limit}, ctx)


@pytest.mark.tshark
def test_waits_for_indexing(
    service: PcapService, ctx: RequestContext, slow_index: threading.Event
) -> None:
    service.open({"path": str(FIXTURES / "http.pcap"), "stream": True}, ctx)
    with pytest.raises(IndexingError):
        service.count_matches({"filter": "tcp"}, ctx)
    slow_index.set()
