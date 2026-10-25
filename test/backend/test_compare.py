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
    assert p["otherFlowIds"] == {
        "ids": sorted(compare.member_id(f"tcp 10.0.0.{i} → 10.0.0.80:80") for i in (1, 2, 3)),
        "complete": True,
    }


def test_flows_beyond_the_kept_ones_are_neither_new_nor_gone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Codex review: a flow ranked just inside the kept ones in one capture and
    # just outside in the other read as new (or gone).
    monkeypatch.setattr(compare, "MAX_PROFILE_ITEMS", 2)

    def conv(sizes: dict[int, int]) -> list[list[Any]]:
        return [[f"10.0.0.{i}:50000", "10.0.0.80:80", 1, n] for i, n in sizes.items()]

    before = _profile(100, conv({1: 500, 2: 400, 3: 300, 4: 200}), {})
    after = _profile(100, conv({1: 500, 3: 450, 2: 100, 5: 50}), {})
    d = compare.diff(before, after)
    # 10.0.0.3 moved into the kept ones and 10.0.0.2 out: in both, so neither.
    assert d["flows"]["new"] == [] and d["flows"]["gone"] == []
    assert "unsure" not in d["flows"]
    # Endpoints the same way (10.0.0.80 and the clients by bytes).
    assert d["endpoints"]["new"] == [] and d["endpoints"]["gone"] == []
    # Ids that stop short: a flow missing from the other side may be in it.
    monkeypatch.setattr(compare, "MAX_MEMBER_IDS", 1)
    before = _profile(100, conv({1: 500, 2: 400, 3: 300, 4: 200}), {})
    after = _profile(100, conv({1: 500, 6: 450, 2: 100}), {})
    d = compare.diff(before, after)
    # 10.0.0.6 isn't among before's ids (10.0.0.3 is the one kept), but they stop
    # short: unsure, not new.
    assert d["flows"]["new"] == [] and d["flows"]["unsure"] == {"new": 1}
    assert any("some flows are new or gone" in n for n in d["notes"])
    # 10.0.0.2 left the kept ones but after's ids are complete: in both.
    assert d["flows"]["gone"] == []
    assert compare.diff(after, before)["flows"]["new"] == []


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
    # Most changed rate first. Equal counts in a capture twice as long are half
    # the rate: changed too (Codex review: 10 in 100 packets vs 10 in 10,000
    # read as unchanged).
    assert [c["id"] for c in d["checks"]["changed"]] == [
        "tcp_resets",
        "tcp_connection_attempts",
        "dns_errors",
        "http_server_errors",
    ]
    resets = d["checks"]["changed"][0]
    assert (resets["before"], resets["after"], resets["afterPer1000"]) == (0, 50, 25.0)
    assert d["checks"]["unchangedNonZero"] == 0 and "notCompared" not in d["checks"]
    # Equal counts at close rates (1000 vs 1100 packets) stay unchanged.
    longer = {**after, "packets": 1100}
    same = compare.diff(before, longer)["checks"]
    assert [c["id"] for c in same["changed"]] == ["tcp_resets", "http_server_errors"]
    assert same["unchangedNonZero"] == 2
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


def test_reset_counts() -> None:
    lines = [
        "10.0.0.80\t\t22\t10.0.0.66\t\t50001",  # the server refusing the client
        # The scanner's own reset after an open port's SYN/ACK isn't the port's answer.
        "10.0.0.66\t\t50002\t10.0.0.80\t\t23",
        "10.0.0.80\t\t22\t10.0.0.66\t\t50003",
        "\t2001:db8::1\t443\t\t2001:db8::9\t50000\r",
        "garbage",
        "10.0.0.1\t\tx\t10.0.0.2\t\t80",
    ]
    assert compare.reset_counts(lines) == {
        "tcp 10.0.0.66 → 10.0.0.80:22": 2,
        "tcp 2001:db8::9 → [2001:db8::1]:443": 1,
    }


def test_scans() -> None:
    def flows(*keys: str, packets: float = 2) -> dict[str, list[float]]:
        return {k: [1, packets, 100 * packets] for k in keys}

    probes = flows(*(f"tcp 10.0.0.9 → 10.0.0.1:{p}" for p in (21, 22, 23, 25)))
    assert compare.scans(probes) == [
        {
            "kind": "port scan",
            "protocol": "tcp",
            "client": "10.0.0.9",
            "server": "10.0.0.1",
            "ports": [21, 22, 23, 25],
            "targets": 4,
            "packets": 8,
        }
    ]
    # With the resets per flow: how many of the targets answered with one.
    resets = {"tcp 10.0.0.9 → 10.0.0.1:21": 1, "tcp 10.0.0.9 → 10.0.0.1:23": 2}
    assert compare.scans(probes, resets)[0]["reset"] == 2
    assert compare.scans(probes, {})[0]["reset"] == 0
    # Three ports, or flows that carried data, are no scan.
    assert compare.scans(dict(list(probes.items())[:3])) == []
    assert compare.scans(flows(*probes, packets=40)) == []
    # A host sweep needs more servers: a client asking four DNS servers is normal.
    dns = flows(*(f"udp 10.0.0.9 → 10.0.0.{n}:53" for n in range(1, 5)))
    assert compare.scans(dns) == []
    sweep = flows(*(f"tcp 10.0.0.9 → [2001:db8::{n}]:445" for n in range(1, 9)))
    (found,) = compare.scans(sweep)
    assert found["kind"] == "host sweep" and found["port"] == 445
    assert found["servers"][0] == "2001:db8::1" and len(found["servers"]) == 8
    # A long scan lists MAX_SCAN_TARGETS ports and counts them all.
    wide = flows(*(f"tcp 10.0.0.9 → 10.0.0.1:{p}" for p in range(1, 101)))
    (big,) = compare.scans(wide)
    assert len(big["ports"]) == compare.MAX_SCAN_TARGETS and big["targets"] == 100
    # Flows without ports (ICMP) are skipped.
    assert compare.scans({"icmp 10.0.0.1 ↔ 10.0.0.2": [1, 2, 100]}) == []
    base = _profile(100, [], {})
    d = compare.diff(
        {**base, "scans": compare.scans(probes)}, {**base, "scans": compare.scans(sweep)}
    )
    assert [s["kind"] for s in d["scans"]["gone"]] == ["port scan"]
    assert [s["kind"] for s in d["scans"]["new"]] == ["host sweep"]


def test_scans_beyond_the_kept_ones_are_neither_new_nor_gone() -> None:
    # Codex review: twenty four-port scans and one five-port scan before; the
    # twenty grow to six ports after, pushing the five-port one out of the top
    # twenty kept. It is in both captures, so it isn't gone.
    def scan_flows(sizes: dict[int, int]) -> dict[str, list[float]]:
        return {
            f"tcp 10.0.1.{c} → 10.0.0.80:{port}": [1, 2, 200]
            for c, n in sizes.items()
            for port in range(1, n + 1)
        }

    before_flows = scan_flows({**dict.fromkeys(range(1, 21), 4), 99: 5})
    after_flows = scan_flows({**dict.fromkeys(range(1, 21), 6), 99: 5})
    base = _profile(100, [], {})
    before = {**base, **_scan_parts(before_flows)}
    after = {**base, **_scan_parts(after_flows)}
    assert len(after["scans"]) == compare.MAX_SCANS and len(after["scanKeys"]) == 21
    assert "10.0.1.99" not in {x["client"] for x in after["scans"]}
    d = compare.diff(before, after)
    assert d["scans"]["new"] == [] and d["scans"]["gone"] == []
    # A profile without scanKeys (an older one) still compares by its scans.
    old = {k: v for k, v in before.items() if k != "scanKeys"}
    assert [x["client"] for x in compare.diff(old, old)["scans"]["both"]][:1] == ["10.0.1.99"]


def _scan_parts(flows: dict[str, list[float]]) -> dict[str, Any]:
    found = compare.scans(flows, limit=None)
    return {
        "scans": found[: compare.MAX_SCANS],
        "scanKeys": sorted(compare.scan_key(x) for x in found),
    }


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
        # Every scanned port answered with a reset: the five resets are the scan's.
        assert d["scans"] == {
            "new": [
                {
                    "kind": "port scan",
                    "protocol": "tcp",
                    "client": "10.0.0.66",
                    "server": "10.0.0.80",
                    "ports": [22, 23, 445, 3389, 5900],
                    "targets": 5,
                    "packets": 10,
                    "reset": 5,
                }
            ],
            "gone": [],
            "both": [],
        }
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
        assert not same["scans"]["new"] and len(same["scans"]["both"]) == 0
        # The scans request (triage, the summary) finds the same in one capture.
        assert services[1].scans({}, ctx)["scans"] == after["scans"] == d["scans"]["new"]
        assert services[0].scans({}, ctx) == {"scans": []}
        with pytest.raises(InvalidParamsError, match="profiles"):
            services[0].compare_profiles({"before": before}, ctx)
        with pytest.raises(InvalidParamsError, match="not a capture profile"):
            services[0].compare_profiles({"before": before, "after": {"version": 1}}, ctx)
    finally:
        for service in services:
            service.shutdown()
