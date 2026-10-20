"""IO graph series (stats {kind: "io", series}): tshark's io,stat functions."""

from __future__ import annotations

from pathlib import Path

import pytest

from pcap_backend import stats
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import FilterError, InvalidParamsError, RequestContext
from pcap_backend.tshark import ToolError

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"

# tshark 4.2's output for `io,stat,0.5,,SUM(frame.len)frame.len,udp.port==5060`.
SERIES_IO = """
=======================================================================
| IO Statistics                                                       |
|                                                                     |
| Col 1: Frames and bytes                                             |
|     2: SUM(frame.len)frame.len                                      |
|     3: udp.port==5060                                               |
|---------------------------------------------------------------------|
|            |1               |2    |3               |
| Interval   | Frames | Bytes | SUM | Frames | Bytes |
|---------------------------------------------------------------------|
| 0.0 <> 0.5 |      3 |  1012 | 1012 |      3 |  1012 |
| 0.5 <> 1.0 |      0 |     0 |    0 |      0 |     0 |
| 2.5 <> Dur |      4 |  1303 | 1303 |      4 |  1303 |
=======================================================================
"""


def test_series_columns_follow_the_frames_and_bytes() -> None:
    series = [
        stats.IoSeries("sum", field="frame.len"),
        stats.IoSeries("bits", "udp.port==5060"),
    ]
    table = stats.parse_io_stat(SERIES_IO, 0.5, series)
    assert [c["id"] for c in table.columns] == ["start", "end", "packets", "bytes", "s0", "s1"]
    assert [c["label"] for c in table.columns[4:]] == ["SUM(frame.len)", "Bits · udp.port==5060"]
    assert [r["cells"] for r in table.rows] == [
        [0, 0.5, 3, 1012, 1012, 8096],
        [0.5, 1, 0, 0, 0, 0],
        [2.5, 3, 4, 1303, 1303, 10424],
    ]
    assert table.to_json()["series"][1] == {
        "metric": "bits",
        "filter": "udp.port==5060",
        "field": "",
        "label": "Bits · udp.port==5060",
    }


def test_tap_arguments() -> None:
    assert stats.IoSeries("packets").tap_arg() == "frame"
    assert stats.IoSeries("packets", "tcp").tap_arg() == "tcp"
    assert stats.IoSeries("bytes", "tcp").tap_arg("!(frame.number == 2)") == (
        "(!(frame.number == 2)) && (tcp)"
    )
    # A function's field is its filter too (packets without it would count as 0).
    assert stats.IoSeries("avg", "tcp", "tcp.len").tap_arg() == "AVG(tcp.len)tcp.len && (tcp)"
    assert stats.IoSeries("max", field="frame.len").tap_arg("udp") == (
        "MAX(frame.len)frame.len && (udp)"
    )


def _column(table: dict, i: int) -> list:
    at = [c["id"] for c in table["columns"]].index(f"s{i}")
    return [r["cells"][at] for r in table["rows"]]


@pytest.mark.tshark
def test_series_from_tshark(service: PcapService, ctx: RequestContext) -> None:
    service.open({"path": str(FIXTURES / "voip.pcap")}, ctx)
    sip = service.count_matches({"filter": "sip"}, ctx)["count"]
    table = service.stats(
        {
            "kind": "io",
            "interval": 0.5,
            "series": [
                {"metric": "packets", "filter": "sip"},
                {"metric": "sum", "field": "frame.len"},
                {"metric": "count", "field": "frame.len", "filter": "udp"},
                {"metric": "max", "field": "frame.len"},
                {"metric": "bits"},
            ],
        },
        ctx,
    )
    packets = [r["cells"][2] for r in table["rows"]]
    size = [r["cells"][3] for r in table["rows"]]
    assert sum(_column(table, 0)) == sip
    assert _column(table, 1) == size, "SUM(frame.len) is the bytes column"
    assert sum(_column(table, 2)) == service.count_matches({"filter": "udp"}, ctx)["count"]
    assert all(m <= s for m, s in zip(_column(table, 3), size, strict=True))
    assert max(_column(table, 3)) > 0
    assert _column(table, 4) == [b * 8 for b in size]
    assert sum(packets) == service.capture_info({}, ctx)["frames"]


@pytest.mark.tshark
def test_series_limited_to_the_display_filter(opened: PcapService, ctx: RequestContext) -> None:
    table = opened.stats(
        {
            "kind": "io",
            "filter": "tcp.port == 80",
            "series": [{"metric": "packets", "filter": "http"}],
        },
        ctx,
    )
    assert sum(_column(table, 0)) == opened.count_matches({"filter": "http"}, ctx)["count"]
    limited = opened.stats(
        {
            "kind": "io",
            "filter": "tcp.len == 0",
            "series": [{"metric": "packets", "filter": "http"}],
        },
        ctx,
    )
    assert sum(_column(limited, 0)) == 0, "HTTP packets carry data: none within tcp.len == 0"


@pytest.mark.tshark
def test_series_errors(opened: PcapService, ctx: RequestContext) -> None:
    def io(*series: dict) -> dict:
        return opened.stats({"kind": "io", "series": list(series)}, ctx)

    with pytest.raises(FilterError) as bad:
        io({"metric": "packets"}, {"metric": "packets", "filter": "tcp.port =="})
    assert bad.value.data == {"expr": "tcp.port ==", "series": 1}
    with pytest.raises(FilterError) as comma:
        io({"metric": "packets", "filter": "frame.number in {1,2}"})
    assert "commas" in str(comma.value)
    with pytest.raises(FilterError) as unknown:
        io({"metric": "avg", "field": "no.such.field"})
    assert unknown.value.data["series"] == 0
    with pytest.raises(InvalidParamsError, match="needs a field"):
        io({"metric": "sum"})
    with pytest.raises(InvalidParamsError, match="metric must be one of"):
        io({"metric": "median", "field": "frame.len"})
    with pytest.raises(InvalidParamsError, match="at most"):
        io(*[{"metric": "packets"}] * (stats.MAX_IO_SERIES + 1))
    # tshark itself refuses SUM of addresses (and exits 0).
    with pytest.raises(ToolError, match="integral"):
        io({"metric": "sum", "field": "ip.src"})
