"""Comparing captures: profiles, their diff, and the service methods."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from pcap_backend import compare
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import InvalidParamsError, RequestContext

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_flow_keys() -> None:
    # The server is the end with the lower port, whichever side tshark printed first.
    assert (
        compare.flow_key("tcp", "10.0.0.5:51000", "10.0.0.80:80") == "tcp 10.0.0.5 → 10.0.0.80:80"
    )
    assert (
        compare.flow_key("tcp", "10.0.0.80:80", "10.0.0.5:51000") == "tcp 10.0.0.5 → 10.0.0.80:80"
    )
    assert (
        compare.flow_key("udp", "2001:db8:1::10:51001", "2001:db8:10::1:123")
        == "udp 2001:db8:1::10 → [2001:db8:10::1]:123"
    )
    # Same port both ways (DNS between servers, NTP): ordered by address.
    assert compare.flow_key("udp", "10.0.0.9:53", "10.0.0.2:53") == "udp 10.0.0.9 → 10.0.0.2:53"
    assert compare.flow_key("sctp", "a", "b") == "sctp a ↔ b"


def _table(columns: list[str], rows: list[list[Any]], **extra: Any) -> dict[str, Any]:
    return {
        "columns": [{"id": c} for c in columns],
        "rows": [{"cells": r, **extra} for r in rows],
    }


def _profile(
    packets: int,
    conversations: list[list[Any]],
    checks: dict[str, int],
    expert: list[list[Any]] = (),  # type: ignore[assignment]
    two_pass: bool = True,
) -> dict[str, Any]:
    phs = {
        "columns": [{"id": c} for c in ("protocol", "packets", "bytes")],
        "rows": [
            {"cells": ["eth", packets, packets * 100], "depth": 0},
            {"cells": ["ip", packets, packets * 100], "depth": 1},
            {"cells": ["tcp", packets - 10, (packets - 10) * 100], "depth": 2},
        ],
    }
    conv = _table(["a", "b", "packets", "bytes"], conversations)
    hosts: dict[str, list[int]] = {}
    for a, b, p, size in conversations:
        for end in (a, b):
            host = end.rpartition(":")[0]
            hosts.setdefault(host, [0, 0])
            hosts[host][0] += p
            hosts[host][1] += size
    endpoints = _table(["address", "packets", "bytes"], [[h, *v] for h, v in hosts.items()])
    triage = {
        "twoPass": two_pass,
        "checks": [
            {"id": cid, "title": cid.replace("_", " "), "filter": cid, "count": n, "first": 1}
            for cid, n in checks.items()
        ],
    }
    expert_table = _table(["severity", "summary", "group", "protocol", "count"], list(expert))
    info = {"frames": packets, "startTime": 100.0, "endTime": 110.0, "linkType": "ether", "size": 9}
    return compare.profile(info, phs, [("tcp", conv)], [endpoints], triage, expert_table)


def test_profile_sums_flows_and_keeps_counts() -> None:
    p = _profile(
        100,
        [
            ["10.0.0.5:51000", "10.0.0.80:80", 10, 1000],
            ["10.0.0.5:51001", "10.0.0.80:80", 20, 3000],  # the same flow, another connection
            ["10.0.0.6:51000", "10.0.0.80:443", 5, 500],
        ],
        {"tcp_resets": 2},
        [["Warning", "HTTP/1.1 503 Service Unavailable\\r\\n", "Sequence", "HTTP", 3]],
    )
    assert p["packets"] == 100 and p["bytes"] == 10_000 and p["duration"] == 10.0
    assert p["flows"]["tcp 10.0.0.5 → 10.0.0.80:80"] == [2, 30, 4000]
    assert p["protocols"]["eth/ip/tcp"] == [90, 9000]
    assert p["checks"]["tcp_resets"]["count"] == 2
    assert p["expert"] == {"Warning|Sequence|HTTP|HTTP/1.1 503 Service Unavailable": 3}
    assert p["severities"] == {"Warning": 3}


def test_profile_keeps_the_largest_flows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(compare, "MAX_PROFILE_ITEMS", 2)
    p = _profile(
        100,
        [[f"10.0.0.{i}:50000", "10.0.0.80:80", 1, 100 * i] for i in range(1, 6)],
        {},
    )
    assert list(p["flows"]) == ["tcp 10.0.0.5 → 10.0.0.80:80", "tcp 10.0.0.4 → 10.0.0.80:80"]
    assert p["otherFlows"] == [3, 3, 600]


def test_diff_new_gone_changed_and_checks() -> None:
    before = _profile(
        1000,
        [
            ["10.0.0.5:51000", "10.0.0.80:80", 500, 50_000],
            ["10.0.0.7:51000", "10.0.0.80:21", 400, 40_000],
            ["10.0.0.8:51000", "10.0.0.80:22", 100, 10_000],
        ],
        {"tcp_resets": 0, "dns_errors": 10, "tcp_connection_attempts": 30, "http_server_errors": 0},
        [["Note", "Retransmission", "Sequence", "TCP", 4]],
    )
    after = _profile(
        2000,
        [
            ["10.0.0.5:52000", "10.0.0.80:80", 1800, 180_000],  # was 50 %, now 90 %
            ["10.0.0.66:60000", "10.0.0.80:3389", 100, 10_000],
            ["10.0.0.8:51000", "10.0.0.80:22", 100, 10_000],  # 10 % → 5 %
        ],
        {
            "tcp_resets": 50,
            "dns_errors": 10,
            "tcp_connection_attempts": 30,
            "http_server_errors": 4,
        },
        [["Warning", "Connection reset (RST)", "Sequence", "TCP", 50]],
    )
    d = compare.diff(before, after, ("monday.pcap", "tuesday.pcap"))
    assert d["before"]["name"] == "monday.pcap" and d["after"]["packetsPerSecond"] == 200.0
    # Counts that differ, most changed rate first; equal counts are only counted.
    assert [c["id"] for c in d["checks"]["changed"]] == ["tcp_resets", "http_server_errors"]
    resets = d["checks"]["changed"][0]
    assert (resets["before"], resets["after"], resets["afterPer1000"]) == (0, 50, 25.0)
    assert d["checks"]["unchangedNonZero"] == 2 and "notCompared" not in d["checks"]
    flows = d["flows"]
    assert [f["flow"] for f in flows["new"]] == ["tcp 10.0.0.66 → 10.0.0.80:3389"]
    assert [f["flow"] for f in flows["gone"]] == ["tcp 10.0.0.7 → 10.0.0.80:21"]
    assert [(f["flow"], f["shareChange"]) for f in flows["changed"]] == [
        ("tcp 10.0.0.5 → 10.0.0.80:80", 40.0),
        ("tcp 10.0.0.8 → 10.0.0.80:22", -5.0),
    ]
    assert [e["address"] for e in d["endpoints"]["new"]] == ["10.0.0.66"]
    assert d["expert"]["severities"] == {
        "Note": {"before": 4, "after": 0},
        "Warning": {"before": 0, "after": 50},
    }
    assert d["expert"]["new"][0]["summary"] == "Connection reset (RST)"
    assert d["expert"]["gone"][0]["summary"] == "Retransmission"
    assert "notes" not in d


def test_diff_limits_and_notes() -> None:
    conv = [[f"10.0.0.{i}:50000", "10.0.0.80:80", 10, 1000] for i in range(1, 6)]
    before = _profile(100, [], {"dns_unanswered": 0}, two_pass=False)
    before["checks"].pop("dns_unanswered")
    before["notCounted"] = {"dns_unanswered": "needs two passes"}
    before["missing"] = ["expert information"]
    after = _profile(100, conv, {"dns_unanswered": 1})
    d = compare.diff(before, after, limit=2)
    assert len(d["flows"]["new"]) == 2 and d["flows"]["more"] == {"new": 3}
    assert d["checks"]["notCompared"] == ["dns_unanswered"]
    assert any("two-pass" in n for n in d["notes"])
    assert "Not available for before: expert information." in d["notes"]
    # Expert lists keep the most severe messages when cut, and say how many more.
    chats = [["Chat", f"SYN to port {p}", "Sequence", "TCP", 9] for p in range(5)]
    noisy = _profile(100, conv, {}, expert=[*chats, ["Warning", "Reset", "Sequence", "TCP", 1]])
    e = compare.diff(before, noisy, limit=2)["expert"]
    assert [x["summary"] for x in e["new"]] == ["Reset", "SYN to port 0"]
    assert e["more"] == {"new": 4}
    with pytest.raises(ValueError, match="profile version"):
        compare.diff({**before, "version": 0}, after)


@pytest.mark.tshark
def test_office_before_and_after(ctx: RequestContext) -> None:
    services = []
    try:
        profiles = []
        for name in ("office-before.pcap", "office-after.pcap"):
            service = PcapService()
            services.append(service)
            service.initialize({}, ctx)
            service.open({"path": str(FIXTURES / name), "names": {}}, ctx)
            profiles.append(service.capture_profile({}, ctx))
        before, after = profiles
        assert before["missing"] == after["missing"] == []
        d = services[0].compare_profiles({"before": before, "after": after}, ctx)
        changed = {c["id"]: (c["before"], c["after"]) for c in d["checks"]["changed"]}
        assert changed["tcp_resets"] == (0, 5)
        assert changed["http_server_errors"] == (0, 4)
        assert changed["dns_errors"] == (0, 3)
        assert changed["dns_unanswered"] == (0, 1)
        assert changed["icmp_unanswered"] == (0, 3)
        assert changed["tcp_retransmissions"] == (0, 1)
        assert "dns_queries" not in changed, "5 queries in both"
        assert [e["address"] for e in d["endpoints"]["new"]] == ["10.0.0.66"]
        assert {f["flow"] for f in d["flows"]["new"]} == {
            f"tcp 10.0.0.66 → 10.0.0.80:{port}" for port in (22, 23, 445, 3389, 5900)
        }
        assert not d["flows"]["gone"] and not d["endpoints"]["gone"]
        summaries = {e["summary"] for e in d["expert"]["new"]}
        assert "Connection reset (RST)" in summaries
        # Every message only the after capture has is new (tshark versions word
        # and group them differently: 4.6 added chats such as Karn's ACK).
        wide = compare.diff(before, after, limit=1000)
        assert {
            "|".join((e["severity"], e["group"], e["protocol"], e["summary"]))
            for e in wide["expert"]["new"]
        } == set(after["expert"]) - set(before["expert"])
        # A capture against itself: nothing changed.
        same = services[0].compare_profiles({"before": before, "after": before}, ctx)
        assert not same["checks"]["changed"] and not same["flows"]["new"]
        assert not same["protocols"]["changed"] and not same["expert"]["new"]
        with pytest.raises(InvalidParamsError, match="profiles"):
            services[0].compare_profiles({"before": before}, ctx)
        with pytest.raises(InvalidParamsError, match="not a capture profile"):
            services[0].compare_profiles({"before": before, "after": {"version": 1}}, ctx)
    finally:
        for service in services:
            service.shutdown()
