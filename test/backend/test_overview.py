"""The capture overview (overview.py, the ``overview`` RPC)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from pcap_backend import overview
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import FilterError, RequestContext

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_timeline_merges_buckets_exactly() -> None:
    timeline = overview.Timeline(10)
    for i in range(100):
        timeline.add(i * 0.001, 10)
    assert timeline.interval == 0.01
    assert timeline.packets == [10] * 10 and timeline.bytes == [100] * 10
    timeline.add(5.0, 1)  # (needs 1 s buckets: 0.01 → 0.02 → 0.1 → 0.2 → 1)
    assert timeline.interval == 1
    assert timeline.packets == [100, 0, 0, 0, 0, 1]
    assert sum(timeline.bytes) == 1001


def test_every_interval_is_a_multiple_of_the_one_before() -> None:
    for small, big in zip(overview.INTERVALS, overview.INTERVALS[1:], strict=False):
        assert abs(big / small - round(big / small)) < 1e-9
    timeline = overview.Timeline(2)
    timeline.add(10 * 365 * 86400.0, 1)  # (past the last interval: it doubles)
    assert timeline.interval > overview.INTERVALS[-1] and len(timeline.packets) <= 2


def test_a_time_before_the_first_packet_counts_in_the_first_bucket() -> None:
    timeline = overview.Timeline(10)
    timeline.add(-0.5, 7)
    assert timeline.packets == [1] and timeline.bytes == [7]


def _row(**cells: str) -> list[str]:
    row = [""] * len(overview.FIELDS)
    for name, value in cells.items():
        row[overview.FIELDS.index(name.replace("__", "."))] = value
    return row


def test_lines_tshark_cut_short_are_skipped() -> None:
    summary = overview.Overview()
    summary.add_lines(["", "1\t0.0"])
    assert summary.packets == 0


def test_cards_from_lines() -> None:
    summary = overview.Overview()
    summary.add(_row(**{"frame.number": "1", "frame.time_relative": "0", "frame.len": "60"}))
    summary.add(
        _row(**{
            "frame.number": "2", "frame.time_relative": "0.5", "frame.len": "100",
            "ipv6.src": "2001:db8::1", "ipv6.dst": "2001:db8::2",
            "tcp.flags.syn": "True",
            "tcp.flags.ack": "False", "tcp.dstport": "443",
        })
    )  # fmt: skip
    result = summary.to_json()
    assert result["packets"] == 2 and result["bytes"] == 160 and result["duration"] == 0.5
    assert [i["filter"] for i in result["addresses"]["items"]] == [
        "ipv6.addr == 2001:db8::1",
        "ipv6.addr == 2001:db8::2",
    ]
    assert result["protocols"]["items"] == []  # (no hierarchy report)
    assert result["services"]["items"] == [
        {"label": "443/tcp", "count": 1, "filter": "tcp.port == 443"}
    ]


PHS = """
===================================================================
Protocol Hierarchy Statistics
Filter:

eth                                      frames:62 bytes:5154
  ip                                     frames:62 bytes:5154
    tcp                                  frames:53 bytes:4315
      http                               frames:11 bytes:1607
        data-text-lines                  frames:3 bytes:451
          http                           frames:1 bytes:191
      dns                                frames:2 bytes:200
    udp                                  frames:9 bytes:839
      dns                                frames:7 bytes:639
===================================================================
"""


def test_protocols_come_from_the_hierarchy_report() -> None:
    summary = overview.Overview()
    summary.add_lines(PHS.split("\n"))
    counts = {i["label"]: i["count"] for i in summary.to_json()["protocols"]["items"]}
    # (eth is plumbing; HTTP nested in itself counts once; DNS over TCP and UDP adds up.)
    assert counts == {"ip": 62, "tcp": 53, "http": 11, "dns": 9, "udp": 9, "data-text-lines": 3}


def test_a_quote_in_a_name_is_escaped() -> None:
    summary = overview.Overview()
    summary.add(_row(**{"frame.number": "1", "http.request.method": "GET", "http.host": 'a"b'}))
    hosts = summary.to_json()["http"]["hosts"]["items"]
    assert hosts == [{"label": 'a"b', "count": 1, "filter": 'http.host == "a\\"b"'}]


def _overview(service: PcapService, **params: Any) -> dict[str, Any]:
    return service.overview(params, RequestContext())


def _matches(service: PcapService, flt: str) -> int:
    return int(service.count_matches({"filter": flt}, RequestContext())["count"])


@pytest.mark.tshark
def test_overview_of_the_session_capture(service: PcapService) -> None:
    service.open({"path": str(FIXTURES / "sessions.pcap")}, RequestContext())
    result = _overview(service)
    info = service.capture_info({}, RequestContext())
    assert result["packets"] == info["frames"] == 62
    timeline = result["timeline"]
    assert sum(timeline["packets"]) == 62 and sum(timeline["bytes"]) == result["bytes"]
    assert timeline["interval"] == 0.1 and len(timeline["packets"]) == 31
    # Rows that count packets match their filters exactly.
    cards = [result["addresses"], result["protocols"]]
    cards += [result["dns"][k] for k in ("rcodes", "types", "names")]
    cards += [result["tls"][k] for k in ("versions", "servers")]
    for card in cards:
        assert card["items"]
        for item in card["items"]:
            assert _matches(service, item["filter"]) == item["count"], item
    assert result["addresses"]["items"][0]["label"] == "192.168.1.10"
    # HTTP counts messages: the pipelined pair shares one packet.
    http = result["http"]
    assert (http["requests"], http["responses"]) == (7, 6)
    assert {i["label"]: i["count"] for i in http["methods"]["items"]} == {"GET": 6, "POST": 1}
    assert {i["label"] for i in http["statuses"]["items"]} >= {"200", "404", "500"}
    assert http["contentTypes"]["items"][0]["label"] == "text/plain"
    dns = result["dns"]
    assert (dns["queries"], dns["responses"]) == (5, 4)
    assert {i["label"]: i["count"] for i in dns["rcodes"]["items"]} == {"NoError": 3, "NXDomain": 1}
    tls = result["tls"]
    assert (tls["clientHellos"], tls["serverHellos"]) == (3, 2)
    assert [i["label"] for i in tls["versions"]["items"]] == ["TLS 1.3", "TLS 1.2"]
    services = {i["label"]: i["count"] for i in result["services"]["items"]}
    assert services == {"443/tcp": 3, "80/tcp": 2, "8080/tcp": 1}  # (TCP connections)


@pytest.mark.tshark
def test_overview_limited_to_a_filter_and_without_ignored_packets(service: PcapService) -> None:
    service.open({"path": str(FIXTURES / "sessions.pcap")}, RequestContext())
    dns = _overview(service, filter="dns")
    assert dns["packets"] == 9 and dns["filter"] == "dns"
    assert dns["http"]["requests"] == 0 and dns["dns"]["queries"] == 5
    service.ignore_packets({"frames": [1, 2, 3], "ignore": True}, RequestContext())
    assert _overview(service)["packets"] == 59
    with pytest.raises(FilterError):
        _overview(service, filter="dns.nope ==")


@pytest.mark.tshark
def test_overview_buckets(service: PcapService) -> None:
    service.open({"path": str(FIXTURES / "sessions.pcap")}, RequestContext())
    timeline = _overview(service, buckets=4)["timeline"]
    assert timeline["interval"] == 1 and len(timeline["packets"]) == 4
    assert sum(timeline["packets"]) == 62
