from __future__ import annotations

from pathlib import Path

import pytest

from pcap_backend import stats
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import InvalidParamsError, RequestContext

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
NETWORK = FIXTURES / "network.pcap"

_SCTP_HEAD = ["Source IP", "PortA", "Dest. IP", "PortB", "DATA", "SACK", "HBEAT", "HBEATACK",
              "INIT", "INITACK", "COOKIE", "COOKIACK", "ABORT", "ERROR"]  # fmt: skip
_RULE = "-" * 100
# tshark's sctp,stat layout: a "|"-separated table between rules (cells padded).
SCTP_STAT = "\n".join(
    [
        "-" * 40 + " SCTP Statistics " + "-" * 40,
        "|  Total packets RX/TX 12",
        _RULE,
        "|" + "|".join(f"{c:^8}" for c in _SCTP_HEAD) + "|",
        _RULE,
        "|"
        + "|".join(
            f"{c:>8}" for c in ["10.2.0.2", 2905, "10.2.0.1", 2905, 0, 3, 0, 1, 0, 1, 0, 1, 0, 0]
        )
        + "|",
        "|"
        + "|".join(
            f"{c:>12}" for c in ["2001:db8::1", 1, "2001:db8::2", 2, 5, 0, 0, 0, 1, 0, 1, 0, 0, 0]
        )
        + "|",
        _RULE,
    ]
)


def test_sctp_report() -> None:
    table = stats.parse_sctp_stat(SCTP_STAT)
    labels = [c["label"] for c in table.columns]
    assert labels[:6] == ["Source", "Port", "Destination", "Port", "DATA", "SACK"]
    assert "COOKIE ECHO" in labels and "HEARTBEAT ACK" in labels
    assert table.rows[0]["cells"][:6] == ["10.2.0.2", 2905, "10.2.0.1", 2905, 0, 3]
    assert table.rows[0]["filter"] == (
        "ip.src == 10.2.0.2 && sctp.srcport == 2905 && ip.dst == 10.2.0.1 && sctp.dstport == 2905"
    )
    assert table.rows[1]["filter"].startswith("ipv6.src == 2001:db8::1 && sctp.srcport == 1")


def test_hosts_report() -> None:
    text = (
        "# TShark hosts output\n#\n# Host data gathered from x.pcap\n\n"
        "93.184.216.35\twireshark.org\n93.184.216.34\texample.com\n2001:db8::1\tv6.example\n"
    )
    table = stats.parse_hosts(text)
    assert [r["cells"] for r in table.rows] == [
        ["93.184.216.34", "example.com"],
        ["2001:db8::1", "v6.example"],
        ["93.184.216.35", "wireshark.org"],
    ]
    assert table.rows[1]["filter"] == "ipv6.addr == 2001:db8::1"


def test_multicast_streams_bandwidth_and_bursts() -> None:
    # 60 packets of 100 bytes 1 ms apart (a burst over the 50-packet alarm),
    # then 10 more 100 ms apart; and a second stream of 3.
    first = "\t100\t10.0.0.1\t\t4000\t239.0.0.1\t\t5000"
    lines = [f"{1000 + i * 0.001:.6f}{first}" for i in range(60)]
    lines += [f"{1000.059 + i * 0.1:.6f}{first}" for i in range(1, 11)]
    lines += [f"{1000 + i:.6f}\t50\t\tfe80::1\t4001\t\tff02::fb\t5353" for i in range(3)]
    lines += ["garbage", ""]
    table = stats.multicast_streams(lines)
    first, second = (r["cells"] for r in table.rows)
    assert first[:5] == ["10.0.0.1", 4000, "239.0.0.1", 5000, 70]
    assert first[5] == round(70 / 1.059, 2)  # packets per second
    assert first[6] == round(7000 * 8 / 1.059)  # average bits per second
    assert first[7:] == [60 * 100 * 8 * 10, 60, 1]  # max BW, max burst, alarms
    assert second[:5] == ["fe80::1", 4001, "ff02::fb", 5353, 3]
    assert second[8:] == [1, 0]
    assert table.rows[1]["filter"] == (
        "ipv6.src == fe80::1 && udp.srcport == 4001 && ipv6.dst == ff02::fb && udp.dstport == 5353"
    )


@pytest.mark.tshark
@pytest.mark.parametrize(
    ("kind", "typ"),
    [(v, t) for v in ("ipv4", "ipv6") for t in stats.IP_STATS_TYPES],
)
def test_ip_statistics_rows_filter_their_packets(
    service: PcapService, ctx: RequestContext, kind: str, typ: str
) -> None:
    service.open({"path": str(NETWORK)}, ctx)
    table = service.stats({"kind": kind, "type": typ}, ctx)
    assert table["type"] == typ and table["rows"], table
    for row in table["rows"]:
        if "filter" in row:
            count = service.count_matches({"filter": row["filter"]}, ctx)["count"]
            assert count == row["cells"][1], (row, count)
    # Every address row and every port has a filter.
    assert sum("filter" in r for r in table["rows"]) == len(table["rows"])


@pytest.mark.tshark
def test_multicast_sctp_and_resolved_addresses(service: PcapService, ctx: RequestContext) -> None:
    service.open({"path": str(NETWORK)}, ctx)
    mc = service.stats({"kind": "multicast"}, ctx)
    assert [r["cells"][:5] for r in mc["rows"]] == [
        ["10.1.1.5", 4000, "239.1.1.1", 5000, 80],
        ["10.1.1.6", 4001, "239.2.2.2", 5001, 10],
    ]
    assert [r["cells"][8:] for r in mc["rows"]] == [[60, 1], [1, 0]]
    assert service.count_matches({"filter": mc["rows"][0]["filter"]}, ctx)["count"] == 80
    # Limited to a filter: only the second stream's packets.
    limited = service.stats({"kind": "multicast", "filter": "udp.dstport == 5001"}, ctx)
    assert [r["cells"][4] for r in limited["rows"]] == [10]

    sctp = service.stats({"kind": "sctp"}, ctx)
    assert sorted(r["cells"][4] for r in sctp["rows"]) == [0, 3]  # DATA chunks per direction
    for row in sctp["rows"]:
        assert service.count_matches({"filter": row["filter"]}, ctx)["count"] == 6

    hosts = service.stats({"kind": "hosts"}, ctx)
    assert [r["cells"] for r in hosts["rows"]] == [["10.1.1.5", "ntp.example.org"]]
    assert hosts["unfiltered"] is False
    assert service.stats({"kind": "hosts", "filter": "udp"}, ctx)["unfiltered"] is True

    with pytest.raises(InvalidParamsError, match="type must be one of"):
        service.stats({"kind": "ipv4", "type": "ttl"}, ctx)
