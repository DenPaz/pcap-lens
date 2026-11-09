"""The sequence check (stats kind "sequences") over sequences.pcap's GTP-U
tunnels: what it finds per TEID, and that its filters match its rows."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import InvalidParamsError, RequestContext
from pcap_backend.tshark import ToolError

pytestmark = pytest.mark.tshark

GTP = {"kind": "sequences", "key": ["gtp.teid"], "seq": "gtp.seq_number"}


@pytest.fixture
def gtp(service: PcapService, ctx: RequestContext, fixtures: Path) -> PcapService:
    service.open({"path": str(fixtures / "sequences.pcap")}, ctx)
    return service


def _cells(table: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    """A row's cells by column id, with its frame and filter."""
    named = dict(zip([c["id"] for c in table["columns"]], row["cells"], strict=True))
    return {**named, **{k: row[k] for k in ("frame", "filter", "depth") if k in row}}


def _streams(table: dict[str, Any]) -> dict[int, dict[str, Any]]:
    rows = [_cells(table, r) for r in table["rows"] if r["depth"] == 0]
    return {int(r["k0"], 16): r for r in rows}


def test_what_each_tunnel_shows(gtp: PcapService, ctx: RequestContext) -> None:
    table = gtp.stats({**GTP, "wrap": 65536, "reorder": 2}, ctx)
    rows = _streams(table)
    counts = {
        teid: (r["messages"], r["missing"], r["duplicates"], r["late"], r["restarts"])
        for teid, r in rows.items()
    }
    assert counts == {
        0x100: (6, 0, 0, 0, 0),
        0x200: (9, 2, 1, 1, 0),
        0x300: (6, 0, 0, 0, 0),  # 65535 → 0 is the counter wrapping
        0x400: (7, 0, 0, 0, 1),
    }
    assert rows[0x200]["result"] == "2 missing, 1 duplicate, 1 late"
    assert rows[0x100]["result"] == "OK"
    # Streams with problems come first.
    tops = [r["cells"][0] for r in table["rows"] if r["depth"] == 0]
    assert [int(k, 16) for k in tops[:2]] == [0x200, 0x400]
    # 0x200's problems, in capture order, under it.
    labels: list[str] = []
    after = False
    for r in table["rows"]:
        if r["depth"] == 0:
            after = int(r["cells"][0], 16) == 0x200
        elif after:
            labels.append(r["cells"][0])
    assert labels == [
        "Missing 4\N{EN DASH}5 (2)",
        "Reordered: 8 arrived late",
        "Late 8",
        "Duplicate 9",
    ]
    summary = table["summary"]
    assert (summary["streams"], summary["withProblems"], summary["missing"]) == (4, 2, 2)


def test_filters_match_the_rows(gtp: PcapService, ctx: RequestContext) -> None:
    table = gtp.stats({**GTP, "wrap": 65536, "reorder": 2}, ctx)
    for raw in table["rows"]:
        if "filter" not in raw:
            continue
        row = _cells(table, raw)
        res = gtp.count_matches({"filter": row["filter"], "limit": 100}, ctx)
        if row["depth"] == 0:
            assert res["count"] == row["messages"], row["filter"]
            assert res["frames"][0] == row["frame"]
        else:
            assert res["frames"] == [row["frame"]]


def test_without_the_wrap_and_with_a_wider_window(gtp: PcapService, ctx: RequestContext) -> None:
    rows = _streams(gtp.stats(GTP, ctx))
    # 65535 → 0 without a wrap is the numbering starting again.
    assert rows[0x300]["restarts"] == 1
    # 4 → 1 is within the default window (1000): late and duplicate, not a restart.
    assert (rows[0x400]["restarts"], rows[0x400]["duplicates"]) == (0, 3)


def test_limited_to_a_display_filter(gtp: PcapService, ctx: RequestContext) -> None:
    table = gtp.stats({**GTP, "filter": "gtp.teid == 0x200"}, ctx)
    assert list(_streams(table)) == [0x200]
    assert table["filter"] == "gtp.teid == 0x200"


def test_refused_parameters(gtp: PcapService, ctx: RequestContext) -> None:
    with pytest.raises(InvalidParamsError, match=r"no field 'gtp\.nope'") as raised:
        gtp.stats({**GTP, "seq": "gtp.nope"}, ctx)
    assert raised.value.data == {"field": "gtp.nope"}
    with pytest.raises(InvalidParamsError, match="name the field"):
        gtp.stats({**GTP, "seq": ""}, ctx)
    with pytest.raises(InvalidParamsError, match="once"):
        gtp.stats({**GTP, "key": ["gtp.seq_number"]}, ctx)
    with pytest.raises(InvalidParamsError, match="wrap"):
        gtp.stats({**GTP, "wrap": 100}, ctx)
    # No key: one stream of every message.
    table = gtp.stats({**GTP, "key": []}, ctx)
    assert [r["cells"][:2] for r in table["rows"] if r["depth"] == 0] == [["All messages", 28]]
    assert table["columns"][0]["label"] == "Stream"


def test_a_pass_cut_short_by_a_failure_is_an_error(
    gtp: PcapService, ctx: RequestContext, killed_after: Callable[[int], None]
) -> None:
    # The messages read before tshark died would pass for a whole check:
    # "OK", every stream complete (Codex review).
    killed_after(5)
    with pytest.raises(ToolError, match="signal 9"):
        gtp.stats(GTP, ctx)
