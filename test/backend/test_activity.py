"""Conversations' and endpoints' activity over time (activity.py)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from pcap_backend import activity
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import InvalidParamsError, RequestContext
from pcap_backend.stats import Table, _col

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
S = 1_000_000_000


def test_grid_widens_every_key_at_once() -> None:
    grid = activity.Grid(buckets=4)
    grid.add(["a"], 0, 10)
    grid.add(["a", "b"], int(0.0015 * S), 5)  # (1 ms buckets: the second)
    assert grid.interval_ns == S // 1000
    assert grid.data == {"a": [10, 5], "b": [0, 5]}
    grid.add(["b"], int(0.0075 * S), 1)  # past 4 ms: 2 ms buckets, merged in pairs
    assert grid.interval_ns == 2 * S // 1000
    assert grid.data == {"a": [15], "b": [5, 0, 0, 1]}
    grid.add(["a"], int(0.009 * S), 2)  # past 8 ms: 10 ms buckets (5 of 2 ms)
    assert grid.interval_ns == 10 * S // 1000
    assert grid.data == {"a": [17], "b": [6]}
    assert grid.length() == 1


def _cells(**values: str) -> dict[str, str]:
    cells = dict.fromkeys(activity.FIELDS, "")
    cells.update({k.replace("_", "."): v for k, v in values.items()})
    return cells


def test_packet_keys_by_type() -> None:
    sep = activity.AGGREGATOR
    # GTP: outer IP/UDP 2152, inner IP/UDP. Each UDP header with its IP header.
    gtp = _cells(
        ip_src=f"10.0.0.1{sep}192.168.0.1",
        ip_dst=f"10.0.0.2{sep}192.168.0.2",
        udp_srcport=f"2152{sep}5000",
        udp_dstport=f"2152{sep}53",
    )
    assert activity.packet_keys(gtp, "udp", "conversations") == {
        (("10.0.0.1", "2152"), ("10.0.0.2", "2152")),
        (("192.168.0.1", "5000"), ("192.168.0.2", "53")),
    }
    assert activity.packet_keys(gtp, "ip", "endpoints") == {
        ("10.0.0.1", None),
        ("10.0.0.2", None),
        ("192.168.0.1", None),
        ("192.168.0.2", None),
    }
    # A conversation is the same key both ways.
    a = activity.packet_keys(_cells(eth_src="02:00", eth_dst="02:01"), "eth", "conversations")
    b = activity.packet_keys(_cells(eth_src="02:01", eth_dst="02:00"), "eth", "conversations")
    assert a == b and len(a) == 1
    v6 = _cells(ipv6_src="2001:db8::1", ipv6_dst="2001:db8::2", tcp_srcport="1", tcp_dstport="2")
    assert activity.packet_keys(v6, "tcp", "endpoints") == {
        ("2001:db8::1", "1"),
        ("2001:db8::2", "2"),
    }
    assert activity.packet_keys(v6, "udp", "conversations") == set()


def _conversations(rows: list[list[Any]]) -> Table:
    table = Table(
        "conversations",
        "TCP Conversations",
        [
            _col("a", "Address A"),
            _col("b", "Address B"),
            _col("packets", "Packets", True),
            _col("bytes", "Bytes", True),
            _col("start", "Rel Start", True),
            _col("duration", "Duration", True),
        ],
    )
    table.rows = [{"cells": cells} for cells in rows]
    return table


def test_attach_splits_rows_sharing_ends_by_time_and_scales_to_their_bytes() -> None:
    grid = activity.Grid(buckets=10)
    key = (("10.0.0.1", "5000"), ("10.0.0.2", "80"))
    for second, size in ((0, 100), (1, 100), (5, 300), (6, 300)):
        grid.add([key], second * S, size)
    # (Two connections reusing the port, one at 0-1 s, one at 5-6 s; tshark
    # counted 220 bytes in the first: its report leaves a quoted header out.)
    table = _conversations(
        [
            ["10.0.0.1:5000", "10.0.0.2:80", 2, 220, 0.0, 1.0],
            ["10.0.0.2:80", "10.0.0.1:5000", 2, 600, 5.0, 1.0],
            ["10.0.0.3:1", "10.0.0.4:2", 1, 10, 0.0, 0.0],  # (not in the pass)
        ]
    )
    activity.attach(table, "tcp", grid)
    assert table.extra["activity"] == {"interval": 1.0, "buckets": 7}
    assert table.rows[0]["activity"] == [110, 110, 0, 0, 0, 0, 0]
    assert table.rows[1]["activity"] == [0, 0, 0, 0, 0, 300, 300]
    assert "activity" not in table.rows[2]


def test_attach_charts_at_most_max_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(activity, "MAX_ROWS", 1)
    grid = activity.Grid()
    small, big = ("a", None), ("b", None)
    grid.add([tuple(sorted((small, ("x", None))))], 0, 1)
    grid.add([tuple(sorted((big, ("x", None))))], 0, 9)
    table = _conversations([["a", "x", 1, 1, 0.0, 0.0], ["b", "x", 1, 9, 0.0, 0.0]])
    activity.attach(table, "ip", grid)
    assert "activity" not in table.rows[0] and table.rows[1]["activity"] == [9]


def _charted(service: PcapService, **params: Any) -> dict[str, Any]:
    """A table as the panel gets it: the report, then its rows' activity."""
    table = service.stats(params, RequestContext())
    charts = service.stats_activity(params, RequestContext())
    assert len(charts["rows"]) == len(table["rows"]), "one chart (or None) per row, in order"
    for row, values in zip(table["rows"], charts["rows"], strict=True):
        if values is not None:
            row["activity"] = values
    table["activity"] = charts["activity"]
    return table


@pytest.mark.tshark
@pytest.mark.parametrize("kind", ["conversations", "endpoints"])
@pytest.mark.parametrize("typ", ["eth", "ip", "ipv6", "tcp", "udp"])
def test_every_chart_adds_up_to_its_row(service: PcapService, kind: str, typ: str) -> None:
    service.open({"path": str(FIXTURES / "network.pcap")}, RequestContext())
    table = _charted(service, kind=kind, type=typ)
    assert table["rows"], "network.pcap has every address type"
    bytes_at = [c["id"] for c in table["columns"]].index("bytes")
    for row in table["rows"]:
        values = row["activity"]
        assert len(values) == table["activity"]["buckets"]
        assert abs(sum(values) - row["cells"][bytes_at]) <= len(values), row["cells"][:2]


@pytest.mark.tshark
def test_activity_follows_the_display_filter_and_the_ignored_packets(
    service: PcapService,
) -> None:
    service.open({"path": str(FIXTURES / "network.pcap")}, RequestContext())
    table = _charted(service, kind="conversations", type="udp", filter="udp.port == 5000")
    [row] = table["rows"]
    assert row["cells"][:2] == ["10.1.1.5:4000", "239.1.1.1:5000"]
    # The burst at the start, then the steady stream.
    assert row["activity"][0] > 10 * max(row["activity"][1:])
    assert sum(row["activity"]) == row["cells"][3]
    # Charted once: asking again reads the table's.
    again = service.stats_activity(
        {"kind": "conversations", "type": "udp", "filter": "udp.port == 5000"}, RequestContext()
    )
    assert again["rows"] == [row["activity"]]
    # Ignoring packets is another table (and another pass).
    service.ignore_packets({"frames": [1]}, RequestContext())
    fewer = _charted(service, kind="conversations", type="udp", filter="udp.port == 5000")
    assert fewer["rows"][0]["cells"][2] == row["cells"][2] - 1


@pytest.mark.tshark
def test_activity_without_its_table_reads_the_report_first(service: PcapService) -> None:
    service.open({"path": str(FIXTURES / "mixed.pcapng")}, RequestContext())
    charts = service.stats_activity({"kind": "endpoints", "type": "ip"}, RequestContext())
    assert charts["activity"]["buckets"] >= 1 and all(charts["rows"])
    with pytest.raises(InvalidParamsError, match="conversations or endpoints"):
        service.stats_activity({"kind": "phs"}, RequestContext())
