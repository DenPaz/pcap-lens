"""Triage checks: fixed display filters for the usual trouble (retransmissions,
resets, unanswered connection attempts, DNS and HTTP errors…), counted by
tshark in one ``-z io,stat`` pass with each check's first and last packet
(MIN/MAX of ``frame.number``). The host's AI triage turns the counts into
findings; the counts themselves are what tshark says.

io,stat separates its arguments with commas, so no filter here holds one.
A filter the installed tshark refuses (a field it doesn't know) is reported
as unavailable rather than failing the pass.

Checks marked ``two_pass`` look for requests without a response: tshark only
links requests to responses when it reads the capture twice (``-2``), so the
pass is two-pass up to ``TWO_PASS_LIMIT`` packets (about twice the time) and
those checks are skipped above it.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from pcap_backend.stats import IoSeries, Table

# Captures up to this many packets get the two-pass checks.
TWO_PASS_LIMIT = 200_000


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    filter: str
    two_pass: bool = False


CHECKS: tuple[Check, ...] = (
    Check(
        "tcp_retransmissions",
        "TCP retransmissions",
        "tcp.analysis.retransmission || tcp.analysis.fast_retransmission"
        " || tcp.analysis.spurious_retransmission",
    ),
    Check(
        "tcp_lost_segments",
        "TCP segments lost or not captured",
        "tcp.analysis.lost_segment || tcp.analysis.ack_lost_segment",
    ),
    Check("tcp_duplicate_acks", "TCP duplicate ACKs", "tcp.analysis.duplicate_ack"),
    Check("tcp_out_of_order", "TCP out-of-order segments", "tcp.analysis.out_of_order"),
    Check(
        "tcp_window_problems",
        "TCP zero or full windows",
        "tcp.analysis.zero_window || tcp.analysis.window_full",
    ),
    Check("tcp_resets", "TCP resets (RST)", "tcp.flags.reset == 1"),
    Check(
        "tcp_connection_attempts",
        "TCP connection attempts (SYN)",
        "tcp.flags.syn == 1 && tcp.flags.ack == 0",
    ),
    Check(
        "tcp_connection_accepts",
        "TCP connections accepted (SYN/ACK)",
        "tcp.flags.syn == 1 && tcp.flags.ack == 1",
    ),
    Check(
        "tcp_syn_retries",
        "Retransmitted TCP connection attempts",
        "tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.analysis.retransmission",
    ),
    Check(
        "icmp_unreachable",
        "ICMP destination unreachable",
        "icmp.type == 3 || icmpv6.type == 1",
    ),
    Check(
        "icmp_unanswered",
        "ICMP echo requests without a reply",
        "icmp.no_resp || icmpv6.no_resp",
        two_pass=True,
    ),
    Check("icmp_time_exceeded", "ICMP time exceeded", "icmp.type == 11 || icmpv6.type == 3"),
    Check("icmp_redirects", "ICMP redirects", "icmp.type == 5 || icmpv6.type == 137"),
    Check("dns_queries", "DNS queries", "dns.flags.response == 0"),
    Check("dns_responses", "DNS responses", "dns.flags.response == 1"),
    Check(
        "dns_errors",
        "DNS error responses (rcode not NoError)",
        "dns.flags.response == 1 && dns.flags.rcode != 0",
    ),
    Check(
        "dns_unanswered",
        "DNS queries without a response",
        "dns.flags.response == 0 && !dns.response_in",
        two_pass=True,
    ),
    Check("dns_retransmissions", "DNS retransmissions", "dns.retransmission"),
    Check(
        "http_client_errors",
        "HTTP 4xx responses",
        "http.response.code >= 400 && http.response.code < 500",
    ),
    Check("http_server_errors", "HTTP 5xx responses", "http.response.code >= 500"),
    Check(
        "http_unanswered",
        "HTTP requests without a response",
        "http.request && !http.response_in",
        two_pass=True,
    ),
    Check("tls_alerts", "TLS alerts", "tls.alert_message"),
    Check(
        "tls_old_versions",
        "TLS server hellos below TLS 1.2",
        "tls.handshake.type == 2 && tls.handshake.version < 0x0303",
    ),
    Check(
        "cleartext_credentials",
        "Credentials sent in clear text",
        'http.authbasic || ftp.request.command == "PASS" || pop.request.command == "PASS"'
        ' || imap.request.command == "LOGIN" || telnet',
    ),
    Check("sip_errors", "SIP error responses (4xx-6xx)", "sip.Status-Code >= 400"),
    Check("kerberos_errors", "Kerberos errors", "kerberos.error_code"),
    Check(
        "smb_auth_errors",
        "SMB2 access denied or logon failures",
        "smb2.nt_status == 0xc0000022 || smb2.nt_status == 0xc000006d",
    ),
    Check(
        "arp_duplicate_addresses",
        "ARP duplicate IP addresses",
        "arp.duplicate-address-detected || arp.duplicate-address-frame",
    ),
    Check("dhcp_naks", "DHCP NAKs", "dhcp.option.dhcp == 6"),
    Check("ip_fragments", "IP fragments", "ip.flags.mf == 1 || ip.frag_offset > 0"),
    Check(
        "ip_low_ttl",
        "Unicast IPv4 packets with TTL 1 or less",
        "ip.ttl <= 1 && !(ip.dst == 224.0.0.0/4)",
    ),
    Check("broadcasts", "Ethernet broadcasts", "eth.dst == ff:ff:ff:ff:ff:ff"),
    Check("malformed", "Malformed packets", "_ws.malformed"),
)


def series(checks: Sequence[Check]) -> list[IoSeries]:
    """io,stat graphs: per check, its packets, then MIN and MAX of
    ``frame.number`` (its first and last packet; 0 when none)."""
    out: list[IoSeries] = []
    for c in checks:
        out += [
            IoSeries("packets", c.filter),
            IoSeries("min", c.filter, "frame.number"),
            IoSeries("max", c.filter, "frame.number"),
        ]
    return out


def results(checks: Sequence[Check], table: Table) -> list[dict[str, object]]:
    """Each check's ``count``, ``first`` and ``last`` (null when it matched
    nothing) over the table's intervals (``parse_io_stat`` of ``series``)."""
    out: list[dict[str, object]] = []
    for i, c in enumerate(checks):
        col = 4 + 3 * i
        count = 0
        first: int | None = None
        last: int | None = None
        for row in table.rows:
            cells = row["cells"]
            count += int(cells[col])
            lo, hi = int(cells[col + 1]), int(cells[col + 2])
            if lo > 0:
                first = lo if first is None else min(first, lo)
            if hi > 0:
                last = hi if last is None else max(last, hi)
        out.append(
            {
                "id": c.id,
                "title": c.title,
                "filter": c.filter,
                "count": count,
                "first": first,
                "last": last,
            }
        )
    return out
