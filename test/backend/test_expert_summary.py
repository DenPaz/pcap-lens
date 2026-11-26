"""expert_summary: expert items per severity for the viewer's status bar."""

from __future__ import annotations

import threading
from collections import Counter
from pathlib import Path

import pytest

from pcap_backend import stats
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import IndexingError, NotOpenError, RequestContext
from pcap_backend.tshark import run

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


@pytest.mark.tshark
@pytest.mark.parametrize("capture", ["network.pcap", "comments.pcapng", "mixed.pcapng"])
def test_every_expert_item_the_packets_show_is_listed_and_linked(
    service: PcapService, ctx: RequestContext, capture: str
) -> None:
    """The table and the status bar list what the packets' own expert items
    (the _ws.expert field, as Wireshark shows them) say: network.pcap's SCTP
    is "Malformed" only when tshark builds the protocol tree, which the
    report alone didn't, and comments.pcapng has a multi-line comment."""
    service.open({"path": str(FIXTURES / capture)}, ctx)
    f = service._require_file()
    argv = f.tshark.argv(
        "-n",
        "-Y",
        "_ws.expert",
        "-T",
        "fields",
        "-e",
        "_ws.expert",
        "-E",
        "aggregator=\x1e",
        capture=str(f.path),
    )
    shown = set()
    for line in stats._lines(run(argv).stdout.decode()):
        for item in filter(None, line.split("\x1e")):
            m = stats._EXPERT_FIELD.match(item)
            assert m, item
            sev = stats._EXPERT_SEVERITY_ALIAS.get(m["sev"], m["sev"])
            shown.add((sev, stats.expert_key(m["msg"])))
    table = service.stats({"kind": "expert"}, ctx)
    # (tshark 4.6's fields output doubles backslashes: stats.expert_key.)
    assert {(r["cells"][0], stats.expert_key(r["cells"][1])) for r in table["rows"]} == shown
    assert all(r.get("frames") for r in table["rows"])
    counts = service.expert_summary({}, ctx)["counts"]
    expected: Counter[str] = Counter()
    for row in table["rows"]:
        expected[row["cells"][0].lower()] += row["cells"][4]
    assert counts == {s: expected[s] for s in stats.EXPERT_SEVERITIES}
