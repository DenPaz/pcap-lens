"""Two-pass packet detail (``twoPass``): the whole capture dissected twice, so
references to later packets appear, as in Wireshark."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import pytest

from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import RequestContext

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _values(tree: list[dict[str, Any]], name: str) -> list[str]:
    out: list[str] = []
    for node in tree:
        if node.get("name") == name:
            out.append(node["show"])
        out += _values(node.get("children", []), name)
    return out


@pytest.mark.tshark
def test_two_pass_shows_references_to_later_packets(
    opened: PcapService, ctx: RequestContext
) -> None:
    # http.pcap: the GET is frame 4, its response frame 7.
    one = opened.packet_detail({"number": 4}, ctx)
    assert _values(one["tree"], "http.response_in") == []
    assert "twoPass" not in one
    two = opened.packet_detail({"number": 4, "twoPass": True}, ctx)
    assert _values(two["tree"], "http.response_in") == ["7"]
    assert two["twoPass"] is True
    assert two["sources"] == one["sources"]
    # Each kind is cached on its own.
    assert opened.packet_detail({"number": 4}, ctx) is one
    assert opened.packet_detail({"number": 4, "twoPass": True}, ctx) is two
    # Backward references are there either way.
    response = opened.packet_detail({"number": 7, "twoPass": True}, ctx)
    assert _values(response["tree"], "http.request_in") == ["4"]


@pytest.mark.tshark
def test_one_pass_while_indexing(
    service: PcapService, ctx: RequestContext, slow_index: threading.Event
) -> None:
    service.open({"path": str(FIXTURES / "http.pcap"), "stream": True}, ctx)
    detail = service.packet_detail({"number": 2, "twoPass": True}, ctx)
    assert "twoPass" not in detail, "the file isn't complete yet"
    slow_index.set()
