"""Ignored packets (Ctrl+D): flagged in the list, left out of statistics and exports."""

from __future__ import annotations

import csv
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

from pcap_backend import navigation
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import InvalidParamsError, RequestContext
from pcap_backend.tshark import find_tool


def test_exclusion_filter_has_no_commas() -> None:
    assert navigation.exclusion_filter([]) == ""
    assert navigation.exclusion_filter([7]) == "!(frame.number == 7)"
    assert navigation.exclusion_filter([5, 1, 2, 3]) == (
        "!((frame.number >= 1 && frame.number <= 3) || frame.number == 5)"
    )


def _frames(path: Path) -> list[int]:
    """The original frame numbers kept in an export (http.pcap's frames have
    distinct lengths, so they identify the packets)."""
    tshark = find_tool("tshark")
    out = subprocess.run(
        [str(tshark), "-r", str(path), "-T", "fields", "-e", "frame.len"],
        capture_output=True,
        check=True,
        text=True,
    ).stdout
    return [int(x) for x in out.split()]


@pytest.mark.tshark
def test_toggle_flags_rows_and_unignore_all(opened: PcapService, ctx: RequestContext) -> None:
    res = opened.ignore_packets({"frames": [2, 3]}, ctx)
    assert res == {"count": 2, "ignored": [2, 3], "unignored": []}
    # A toggle of a set that is partly ignored ignores all of it, then unignores.
    assert opened.ignore_packets({"frames": [3, 4]}, ctx)["count"] == 3
    assert opened.ignore_packets({"frames": [3, 4]}, ctx)["unignored"] == [3, 4]
    rows = opened.list_packets({"offset": 0, "limit": 11}, ctx)["rows"]
    assert [r["number"] for r in rows if r.get("ignored")] == [2]
    assert opened.ignore_packets({"frames": [9], "ignore": False}, ctx)["count"] == 1
    assert opened.unignore_all({}, ctx) == {"count": 0}
    rows = opened.list_packets({"offset": 0, "limit": 11}, ctx)["rows"]
    assert not any(r.get("ignored") for r in rows)


@pytest.mark.tshark
def test_statistics_leave_ignored_packets_out(opened: PcapService, ctx: RequestContext) -> None:
    def total(**params: object) -> int:
        table = opened.stats({"kind": "phs", **params}, ctx)
        return sum(r["cells"][2] for r in table["rows"] if r.get("depth", 0) == 0)

    counts_before = opened.expert_summary({}, ctx)["counts"]
    assert total() == 11
    opened.ignore_packets({"frames": [1, 2, 3, 11]}, ctx)
    assert total() == 7
    assert total(filter="tcp.port == 80") == 7
    # io,stat takes its filters as a comma-separated list: the exclusion has no commas.
    io = opened.stats({"kind": "io"}, ctx)
    packets = [c["id"] for c in io["columns"]].index("packets")
    assert sum(r["cells"][packets] for r in io["rows"]) == 7
    conv = opened.stats({"kind": "conversations", "type": "tcp"}, ctx)
    assert conv["rows"], "the rest of the conversation is still there"
    # The status bar's counts are recounted for the new set (http.pcap's notes
    # are the connection's FINs, frames 8-11).
    counts = opened.expert_summary({}, ctx)["counts"]
    assert sum(counts.values()) < sum(counts_before.values())
    opened.unignore_all({}, ctx)
    assert opened.expert_summary({}, ctx)["counts"] == counts_before


@pytest.mark.tshark
def test_exports_leave_ignored_packets_out(
    opened: PcapService, ctx: RequestContext, tmp_path: Path
) -> None:
    every = _frames(Path(opened._require_file().path))
    opened.ignore_packets({"frames": [2, 5]}, ctx)
    kept = [n for i, n in enumerate(every, 1) if i not in (2, 5)]

    res = opened.export({"kind": "pcapng", "dest": str(tmp_path / "all.pcapng")}, ctx)
    assert res["packets"] == 9 and res["filter"] == ""
    assert _frames(tmp_path / "all.pcapng") == kept

    opened.set_filter({"expr": "tcp"}, ctx)
    res = opened.export({"kind": "pcap", "dest": str(tmp_path / "tcp.pcap")}, ctx)
    assert res["filter"] == "tcp" and _frames(tmp_path / "tcp.pcap") == kept

    opened.mark_packets({"frames": [1, 2, 3]}, ctx)
    res = opened.export({"kind": "pcapng", "dest": str(tmp_path / "m.pcapng"), "marked": True}, ctx)
    assert res["packets"] == 2 and _frames(tmp_path / "m.pcapng") == [every[0], every[2]]
    with pytest.raises(InvalidParamsError, match="selected packets is ignored"):
        opened.export({"kind": "pcapng", "dest": str(tmp_path / "s.pcapng"), "frames": [5]}, ctx)

    dest = tmp_path / "list.csv"
    opened.export({"kind": "csv", "dest": str(dest)}, ctx)
    with dest.open(encoding="utf-8") as fh:
        numbers = [int(r[0]) for r in list(csv.reader(fh))[1:]]
    assert numbers == [1, 3, 4, 6, 7, 8, 9, 10, 11]

    dest = tmp_path / "d.txt"
    res = opened.export({"kind": "dissections", "dest": str(dest), "filter": ""}, ctx)
    assert res["packets"] == 9
    text = dest.read_text(encoding="utf-8")
    assert "Frame 2:" not in text and "Frame 3:" in text


@pytest.mark.tshark
def test_too_many_ranges_are_refused(
    opened: PcapService, ctx: RequestContext, patch_service: Callable[[str, object], None]
) -> None:
    patch_service("MAX_FILTER_ARG", 40)
    opened.ignore_packets({"frames": [1, 3, 5, 7]}, ctx)
    with pytest.raises(InvalidParamsError, match="unignore some"):
        opened.stats({"kind": "phs"}, ctx)
