"""Generate the small synthetic capture files used by the test suites.

Usage (from the repository root)::

    uv run python test/fixtures/generate.py            # regenerate committed fixtures
    uv run python test/fixtures/generate.py --large 1000000 /tmp/big.pcap
    uv run python test/fixtures/generate.py --tls-keylog /tmp/tls.pcap /tmp/tls-keys.log

The committed fixtures are deterministic (fixed timestamps, addresses and
sequence numbers) so that tests can assert on exact values. ``formats/`` holds
the same packets in the other file types the viewer opens (compressed, snoop,
ERF, Bluetooth logs, generic extensions); those writers use only the standard
library, so their bytes never depend on a Wireshark version.
"""

from __future__ import annotations

import argparse
import gzip
import random
import shutil
import ssl
import struct
import sys
import zlib
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import h323  # test/fixtures/h323.py: H.225.0 and H.245 messages in aligned PER
import mmdb  # test/fixtures/mmdb.py: MaxMind databases for the GeoIP tests
import quic  # test/fixtures/quic.py: the hand-encrypted QUIC connection
from scapy.asn1.asn1 import ASN1_OID
from scapy.layers.dns import DNS, DNSQR, DNSRR, DNSRRMX
from scapy.layers.dot11 import Dot11
from scapy.layers.dot15d4 import Dot15d4Data, Dot15d4FCS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, LLC, SNAP, Ether
from scapy.layers.rtp import RTP
from scapy.layers.sctp import (
    SCTP,
    SCTPChunkCookieAck,
    SCTPChunkCookieEcho,
    SCTPChunkData,
    SCTPChunkHeartbeatAck,
    SCTPChunkHeartbeatReq,
    SCTPChunkInit,
    SCTPChunkInitAck,
    SCTPChunkParamStateCookie,
    SCTPChunkSACK,
)
from scapy.layers.sixlowpan import LoWPAN_IPHC
from scapy.layers.snmp import SNMP, SNMPget, SNMPnext, SNMPresponse, SNMPvarbind
from scapy.packet import Packet, Raw
from scapy.utils import wrpcap, wrpcapng

HERE = Path(__file__).resolve().parent
BASE_TS = 1_700_000_000.0  # 2023-11-14T22:13:20Z

CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"


def _stamp(packets: list[Packet], start: float = BASE_TS, step: float = 0.001) -> list[Packet]:
    for i, pkt in enumerate(packets):
        pkt.time = start + i * step
    return packets


class _TcpSession:
    """Minimal TCP conversation builder that keeps sequence numbers consistent."""

    def __init__(self, client: str, server: str, sport: int, dport: int) -> None:
        self.client, self.server, self.sport, self.dport = client, server, sport, dport
        self.cseq, self.sseq = 1000, 5000
        self.packets: list[Packet] = []

    def _c(self, flags: str, payload: bytes = b"") -> None:
        pkt = (
            Ether(src=CLIENT_MAC, dst=SERVER_MAC)
            / IP(src=self.client, dst=self.server, id=len(self.packets) + 1)
            / TCP(
                sport=self.sport,
                dport=self.dport,
                flags=flags,
                seq=self.cseq,
                ack=self.sseq if "A" in flags else 0,
            )
        )
        if payload:
            pkt = pkt / Raw(payload)
        self.packets.append(pkt)
        self.cseq += len(payload) + (1 if ("S" in flags or "F" in flags) else 0)

    def _s(self, flags: str, payload: bytes = b"") -> None:
        pkt = (
            Ether(src=SERVER_MAC, dst=CLIENT_MAC)
            / IP(src=self.server, dst=self.client, id=len(self.packets) + 1)
            / TCP(sport=self.dport, dport=self.sport, flags=flags, seq=self.sseq, ack=self.cseq)
        )
        if payload:
            pkt = pkt / Raw(payload)
        self.packets.append(pkt)
        self.sseq += len(payload) + (1 if ("S" in flags or "F" in flags) else 0)

    def handshake(self) -> None:
        self.cseq -= 1  # SYN consumes the initial sequence number
        self._c("S")
        self.sseq -= 1
        self._s("SA")
        self._c("A")

    def client_send(self, data: bytes) -> None:
        self._c("PA", data)
        self._s("A")

    def server_send(self, *chunks: bytes) -> None:
        for chunk in chunks:
            self._s("PA", chunk)
        self._c("A")

    def close(self) -> None:
        self._c("FA")
        self._s("FA")
        self._c("A")


def http_packets() -> list[Packet]:
    s = _TcpSession("192.168.1.10", "93.184.216.34", 50000, 80)
    s.handshake()
    s.client_send(
        b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: pcap-viewer-test\r\n"
        b"Accept: */*\r\n\r\n"
    )
    body = b"<html><body>" + b"Hello, PCAP Viewer! " * 20 + b"</body></html>"
    headers = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode()
    )
    response = headers + body
    # Split the response over two segments so tshark has to reassemble it.
    s.server_send(response[:200], response[200:])
    s.close()
    return _stamp(s.packets)


def credentials_packets() -> list[Packet]:
    """Logins in the clear, as tshark's credentials tap lists them: HTTP Basic,
    FTP, POP and IMAP (made-up accounts on documentation addresses)."""
    packets: list[Packet] = []
    http = _TcpSession("192.168.1.20", "198.51.100.80", 50100, 80)
    http.handshake()
    http.client_send(
        b"GET /admin HTTP/1.1\r\nHost: intranet.example\r\n"
        b"Authorization: Basic YWxpY2U6czNjcmV0\r\n\r\n"  # alice:s3cret
    )
    http.server_send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    http.close()
    packets += http.packets
    for port, dport, lines in (
        (50101, 21, [b"220 ready\r\n", b"USER bob\r\n", b"331 password?\r\n",
                     b"PASS hunter2\r\n", b"230 welcome\r\n"]),
        (50102, 110, [b"+OK POP3 ready\r\n", b"USER carol\r\n", b"+OK\r\n",
                      b"PASS pop-pass\r\n", b"+OK logged in\r\n"]),
        (50103, 143, [b"* OK IMAP ready\r\n", b"a1 LOGIN dave imap-pass\r\n",
                      b"a1 OK LOGIN completed\r\n"]),
    ):  # fmt: skip
        s = _TcpSession("192.168.1.20", f"198.51.100.{dport % 256}", port, dport)
        s.handshake()
        for i, line in enumerate(lines):
            # The server speaks first, then they take turns.
            if i % 2 == 0:
                s.server_send(line)
            else:
                s.client_send(line)
        s.close()
        packets += s.packets
    return _stamp(packets)


def _http_response(body: bytes, content_type: str, extra: bytes = b"") -> bytes:
    return (
        f"HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\n".encode()
        + extra
        + (b"" if b"chunked" in extra else f"Content-Length: {len(body)}\r\n".encode())
        + b"\r\n"
        + body
    )


def _chunked(data: bytes, size: int) -> bytes:
    out = b""
    for i in range(0, len(data), size):
        part = data[i : i + size]
        out += f"{len(part):x}\r\n".encode() + part + b"\r\n"
    return out + b"0\r\n\r\n"


# Bodies of objects.pcap, also used by the export-objects tests.
OBJECT_PNG = b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 3
OBJECT_REPORT = b"".join(f"report line {i}\n".encode() for i in range(60))
OBJECT_UPLOAD = b'{"name": "pcap-viewer", "size": 3}'
OBJECT_DUP = b"same body twice\n"
OBJECT_TFTP = bytes((i * 7) % 256 for i in range(612))
OBJECT_MAIL = (
    b"From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Test report\r\n\r\n"
    b"Hello Bob,\r\nthe report is attached.\r\n"
)


def objects_packets() -> list[Packet]:
    """HTTP, TFTP and SMTP (IMF) transfers for Export Objects."""
    web = _TcpSession("192.168.1.10", "93.184.216.34", 50100, 80)
    web.handshake()
    get = "GET {} HTTP/1.1\r\nHost: example.com\r\n\r\n"
    web.client_send(get.format("/images/logo.png").encode())
    web.server_send(_http_response(OBJECT_PNG, "image/png"))
    web.client_send(get.format("/report").encode())
    report = gzip.compress(OBJECT_REPORT, mtime=0)
    chunked = b"Transfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n"
    web.server_send(_http_response(_chunked(report, 200), "text/plain", chunked))
    web.client_send(
        b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n"
        + f"Content-Length: {len(OBJECT_UPLOAD)}\r\n\r\n".encode()
        + OBJECT_UPLOAD
    )
    web.server_send(b"HTTP/1.1 204 No Content\r\n\r\n")
    for _ in range(2):
        web.client_send(get.format("/files/dup.txt").encode())
        web.server_send(_http_response(OBJECT_DUP, "text/plain"))
    web.close()

    tftp: list[Packet] = []
    client, server = (
        ("02:00:00:00:00:01", "192.168.1.20", 40000),
        ("02:00:00:00:00:02", "192.168.1.1"),
    )

    def udp(src: tuple[str, str, int], dst: tuple[str, str, int], data: bytes) -> Packet:
        return (
            Ether(src=src[0], dst=dst[0])
            / IP(src=src[1], dst=dst[1])
            / UDP(sport=src[2], dport=dst[2])
            / Raw(data)
        )

    srv = (*server, 50001)
    tftp.append(udp(client, (*server, 69), b"\x00\x01boot/config.bin\x00octet\x00"))
    for block, i in enumerate(range(0, len(OBJECT_TFTP), 512), start=1):
        tftp.append(udp(srv, client, struct.pack("!HH", 3, block) + OBJECT_TFTP[i : i + 512]))
        tftp.append(udp(client, srv, struct.pack("!HH", 4, block)))

    mail = _TcpSession("192.168.1.10", "192.168.1.25", 50200, 25)
    mail.handshake()
    mail.server_send(b"220 mail.example.com ESMTP\r\n")
    for command, reply in (
        (b"HELO client\r\n", b"250 mail.example.com\r\n"),
        (b"MAIL FROM:<alice@example.com>\r\n", b"250 OK\r\n"),
        (b"RCPT TO:<bob@example.com>\r\n", b"250 OK\r\n"),
        (b"DATA\r\n", b"354 End data with <CR><LF>.<CR><LF>\r\n"),
        (OBJECT_MAIL + b".\r\n", b"250 OK: queued\r\n"),
        (b"QUIT\r\n", b"221 Bye\r\n"),
    ):
        mail.client_send(command)
        mail.server_send(reply)
    mail.close()
    return _stamp(web.packets + tftp + mail.packets)


def dns_packets() -> list[Packet]:
    pkts: list[Packet] = []
    names = ["example.com", "wireshark.org", "nonexistent.invalid"]
    for i, name in enumerate(names):
        qid = 0x1000 + i
        q = (
            Ether(src=CLIENT_MAC, dst=SERVER_MAC)
            / IP(src="192.168.1.10", dst="8.8.8.8")
            / UDP(sport=40000 + i, dport=53)
            / DNS(id=qid, rd=1, qd=DNSQR(qname=name, qtype="A"))
        )
        if name.endswith(".invalid"):
            answer = DNS(id=qid, qr=1, rd=1, ra=1, rcode=3, qd=DNSQR(qname=name, qtype="A"))
        else:
            answer = DNS(
                id=qid,
                qr=1,
                rd=1,
                ra=1,
                qd=DNSQR(qname=name, qtype="A"),
                an=DNSRR(rrname=name, type="A", ttl=300, rdata=f"93.184.216.{34 + i}"),
            )
        r = (
            Ether(src=SERVER_MAC, dst=CLIENT_MAC)
            / IP(src="8.8.8.8", dst="192.168.1.10")
            / UDP(sport=53, dport=40000 + i)
            / answer
        )
        pkts += [q, r]
    return _stamp(pkts, step=0.01)


def udp_custom_packets() -> list[Packet]:
    """UDP/9999 traffic decoded by backend/dissectors/example.lua."""
    pkts: list[Packet] = []
    for i in range(6):
        msg_type = 1 + (i % 3)
        payload = struct.pack("!BBH", 1, msg_type, i) + f"message-{i}".encode()
        pkts.append(
            Ether(src=CLIENT_MAC, dst=SERVER_MAC)
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=12345, dport=9999)
            / Raw(payload)
        )
    return _stamp(pkts, step=0.1)


def tls_packets() -> list[Packet]:
    """A TCP handshake followed by a hand-built TLS 1.2 ClientHello with SNI."""
    sni = b"secure.example.com"
    server_name = struct.pack("!BH", 0, len(sni)) + sni
    sni_ext = (
        struct.pack("!HH", 0x0000, len(server_name) + 2)
        + struct.pack("!H", len(server_name))
        + server_name
    )
    extensions = sni_ext
    body = (
        b"\x03\x03"  # client_version TLS 1.2
        + bytes(range(32))  # random
        + b"\x00"  # session id length
        + struct.pack("!H", 4)
        + b"\xc0\x2f\x00\x9c"  # cipher suites
        + b"\x01\x00"  # compression methods: null
        + struct.pack("!H", len(extensions))
        + extensions
    )
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
    s = _TcpSession("192.168.1.10", "93.184.216.34", 50443, 443)
    s.handshake()
    s.client_send(record)
    return _stamp(s.packets)


# ---------------------------------------------------------------------- VoIP

ALICE, BOB, CAROL = "10.0.0.1", "10.0.0.2", "10.0.0.3"
VOIP_START = BASE_TS + 100.0
RTP_PACKETS = 50  # per direction: one second of 20 ms G.711 frames
RTP_LOST = 20  # the caller's packet with this index is never sent
RTP_TONES = (440.0, 880.0)  # caller → callee, callee → caller


def ulaw_encode(sample: int) -> int:
    """G.711 µ-law byte of a 16-bit linear sample (ITU-T G.711, the usual
    segment encoder); the backend's decoder is the inverse."""
    bias, clip = 0x84, 32635
    sign = 0x80 if sample < 0 else 0
    magnitude = min(abs(sample), clip) + bias
    exponent = max(0, magnitude.bit_length() - 8)
    mantissa = (magnitude >> (exponent + 3)) & 0x0F
    return ~(sign | (exponent << 4) | mantissa) & 0xFF


def _tone(freq: float, start: int, count: int, rate: int = 8000) -> bytes:
    """``count`` µ-law samples of a sine wave from sample ``start`` on."""
    import math  # noqa: PLC0415 - only the VoIP fixture needs it

    return bytes(
        ulaw_encode(int(12000 * math.sin(2 * math.pi * freq * (start + i) / rate)))
        for i in range(count)
    )


def _sip(src: str, dst: str, text: str) -> Packet:
    body = text.replace("\n", "\r\n").encode()
    return Ether() / IP(src=src, dst=dst) / UDP(sport=5060, dport=5060) / Raw(body)


def _sdp(addr: str, port: int, formats: str, maps: str = "0 PCMU/8000") -> str:
    """An SDP offer or answer; ``maps`` = rtpmap lines ("8 PCMA/8000, 101 …")."""
    rtpmap = "".join(f"a=rtpmap:{m.strip()}\n" for m in maps.split(","))
    return (
        f"v=0\no=- 1 1 IN IP4 {addr}\ns=call\nc=IN IP4 {addr}\nt=0 0\n"
        f"m=audio {port} RTP/AVP {formats}\n{rtpmap}"
    )


def _sip_message(first: str, src: str, call_id: str, cseq: str, frm: str, to: str,
                 sdp: str = "", headers: str = "",
                 ctype: str = "application/sdp") -> str:  # fmt: skip
    """A SIP message; ``sdp`` is the body (of type ``ctype``), ``headers``
    extra header lines (each ending in a newline)."""
    content = f"Content-Type: {ctype}\n" if sdp else ""
    return (
        f"{first}\nVia: SIP/2.0/UDP {src}:5060;branch=z9hG4bK{sum(map(ord, call_id + cseq))}\n"
        f"From: <sip:{frm}>;tag=a1\nTo: <sip:{to}>\nCall-ID: {call_id}\nCSeq: {cseq}\n"
        f"Contact: <sip:{frm.partition('@')[0]}@{src}>\nMax-Forwards: 70\n{headers}{content}"
        f"Content-Length: {len(sdp.replace(chr(10), chr(13) + chr(10)))}\n\n{sdp}"
    )


def voip_packets() -> list[Packet]:
    """A SIP call from alice to bob with SDP and one second of G.711 µ-law
    audio each way (caller: a 440 Hz tone on port 40000, with packet
    RTP_LOST missing and some jitter; callee: 880 Hz on port 50000), then
    carol's call to bob, rejected with 486 Busy Here. Deterministic."""
    rng = random.Random(7)
    timed: list[tuple[float, Packet]] = []
    call, other = "call-1@10.0.0.1", "call-2@10.0.0.3"
    alice, bob, carol = "alice@10.0.0.1", "bob@10.0.0.2", "carol@10.0.0.3"

    def sip(at: float, src: str, dst: str, first: str, cid: str, cseq: str, frm: str,
            to: str, sdp: str = "") -> None:  # fmt: skip
        timed.append(
            (
                VOIP_START + at,
                _sip(src, dst, _sip_message(first, src, cid, cseq, frm, to, sdp)),
            )
        )

    sip(
        0.000,
        ALICE,
        BOB,
        f"INVITE sip:{bob} SIP/2.0",
        call,
        "1 INVITE",
        alice,
        bob,
        _sdp(ALICE, 40000, "0 8"),
    )
    sip(0.010, BOB, ALICE, "SIP/2.0 100 Trying", call, "1 INVITE", alice, bob)
    sip(0.050, BOB, ALICE, "SIP/2.0 180 Ringing", call, "1 INVITE", alice, bob)
    sip(1.000, BOB, ALICE, "SIP/2.0 200 OK", call, "1 INVITE", alice, bob, _sdp(BOB, 50000, "0"))
    sip(1.010, ALICE, BOB, f"ACK sip:{bob} SIP/2.0", call, "1 ACK", alice, bob)
    media = 1.020
    for direction, (src, dst, sport, dport, ssrc) in enumerate(
        ((ALICE, BOB, 40000, 50000, 0x11111111), (BOB, ALICE, 50000, 40000, 0x22222222))
    ):
        for i in range(RTP_PACKETS):
            if direction == 0 and i == RTP_LOST:
                continue
            jitter = rng.uniform(0, 0.004) if direction == 0 else 0.0
            payload = _tone(RTP_TONES[direction], i * 160, 160)
            pkt = (
                Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
                / RTP(version=2, payload_type=0, sequence=1000 * (direction + 1) + i,
                      timestamp=160 * i, sourcesync=ssrc, marker=int(i == 0))
                / Raw(payload)
            )  # fmt: skip
            timed.append((VOIP_START + media + 0.020 * i + direction * 0.001 + jitter, pkt))
    end = media + 0.020 * RTP_PACKETS + 0.05
    sip(end, ALICE, BOB, f"BYE sip:{bob} SIP/2.0", call, "2 BYE", alice, bob)
    sip(end + 0.010, BOB, ALICE, "SIP/2.0 200 OK", call, "2 BYE", alice, bob)
    sip(
        end + 0.500,
        CAROL,
        BOB,
        f"INVITE sip:{bob} SIP/2.0",
        other,
        "1 INVITE",
        carol,
        bob,
        _sdp(CAROL, 42000, "0"),
    )
    sip(end + 0.510, BOB, CAROL, "SIP/2.0 100 Trying", other, "1 INVITE", carol, bob)
    sip(end + 0.600, BOB, CAROL, "SIP/2.0 486 Busy Here", other, "1 INVITE", carol, bob)
    sip(end + 0.610, CAROL, BOB, f"ACK sip:{bob} SIP/2.0", other, "1 ACK", carol, bob)
    timed.sort(key=lambda tp: tp[0])
    for at, pkt in timed:
        pkt.time = at
    return [pkt for _, pkt in timed]


# voip-calls.pcap: the calls' parties (erin answers them all).
DAVE, ERIN, FRANK, GRACE, HEIDI, IVAN = (f"10.0.1.{i}" for i in range(1, 7))
EVENT_PT = 101  # telephone-event (RFC 4733), mapped by the SDP's rtpmap
DTMF_EVENTS = {"4": (20, 4), "#": (60, 11)}  # digit: (dave's packet index, event id)
SSRC_CHANGE_AT = 25  # frank's stream changes SSRC at this packet
SILENCE_AFTER, SILENCE_S = 10, 1.5  # frank sends nothing for 1.5 s after packet 10


def _rtp(src: str, dst: str, sport: int, dport: int, pt: int, seq: int, ts: int, ssrc: int,
         payload: bytes, marker: int = 0) -> Packet:  # fmt: skip
    return (
        Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
        / RTP(version=2, payload_type=pt, sequence=seq, timestamp=ts, sourcesync=ssrc,
              marker=marker)
        / Raw(payload)
    )  # fmt: skip


class _CallScript:
    """The packets of voip-calls.pcap, each at a time from VOIP_START; SIP
    helpers for calls to erin."""

    def __init__(self) -> None:
        self.timed: list[tuple[float, Packet]] = []

    def at(self, time: float, pkt: Packet) -> None:
        self.timed.append((VOIP_START + time, pkt))

    def sip(self, time: float, src: str, dst: str, first: str, cid: str, cseq: str, frm: str,
            to: str, body: str = "", headers: str = "",
            ctype: str = "application/sdp") -> None:  # fmt: skip
        message = _sip_message(first, src, cid, cseq, frm, to, body, headers, ctype)
        self.at(time, _sip(src, dst, message))

    def invite(self, time: float, caller: str, name: str, cid: str, body: str) -> None:
        self.sip(time, caller, ERIN, f"INVITE sip:erin@{ERIN} SIP/2.0", cid, "1 INVITE",
                 f"{name}@{caller}", f"erin@{ERIN}", body)  # fmt: skip

    def reply(self, time: float, caller: str, name: str, cid: str, status: str,
              cseq: str = "1 INVITE", body: str = "", headers: str = "") -> None:  # fmt: skip
        self.sip(time, ERIN, caller, f"SIP/2.0 {status}", cid, cseq, f"{name}@{caller}",
                 f"erin@{ERIN}", body, headers)  # fmt: skip

    def ack(self, time: float, caller: str, name: str, cid: str) -> None:
        self.sip(time, caller, ERIN, f"ACK sip:erin@{ERIN} SIP/2.0", cid, "1 ACK",
                 f"{name}@{caller}", f"erin@{ERIN}")  # fmt: skip

    def bye(self, time: float, caller: str, name: str, cid: str) -> None:
        """The caller hangs up; erin answers."""
        self.sip(time, caller, ERIN, f"BYE sip:erin@{ERIN} SIP/2.0", cid, "2 BYE",
                 f"{name}@{caller}", f"erin@{ERIN}")  # fmt: skip
        self.reply(time + 0.01, caller, name, cid, "200 OK", cseq="2 BYE")

    def packets(self) -> list[Packet]:
        self.timed.sort(key=lambda tp: tp[0])
        for time, pkt in self.timed:
            pkt.time = time
        return [pkt for _, pkt in self.timed]


_ALAW_SILENCE = bytes([0xD5]) * 160


def _dtmf_call(c: _CallScript) -> None:
    """dave → erin: DTMF both ways, erin hangs up."""
    events = "8 PCMA/8000, 101 telephone-event/8000"
    cid = "dtmf@10.0.1.1"
    c.invite(0.0, DAVE, "dave", cid, _sdp(DAVE, 30000, "8 101", events))
    c.reply(0.01, DAVE, "dave", cid, "100 Trying")
    c.reply(0.3, DAVE, "dave", cid, "180 Ringing")
    c.reply(1.5, DAVE, "dave", cid, "200 OK", body=_sdp(ERIN, 32000, "8 101", events))
    c.ack(1.51, DAVE, "dave", cid)
    by_index = dict(DTMF_EVENTS.values())  # packet index → event id
    for i in range(100):
        t = 1.52 + 0.02 * i
        c.at(t + 0.001, _rtp(ERIN, DAVE, 32000, 30000, 8, 5000 + i, 160 * i, 0x66666666,
                             _ALAW_SILENCE, int(i == 0)))  # fmt: skip
        start = next((k for k in by_index if k <= i < k + 6), None)
        if start is None:
            c.at(t, _rtp(DAVE, ERIN, 30000, 32000, 8, 3000 + i, 160 * i, 0x55555555,
                         _ALAW_SILENCE, int(i == 0)))  # fmt: skip
            continue
        # Six event packets of one digit (all with the timestamp of its start),
        # the last three its end, sent three times as RFC 4733 asks.
        step = min(i - start, 3)
        end = 0x80 if i - start >= 3 else 0
        body = bytes([by_index[start], end | 10]) + struct.pack(">H", 160 * (step + 1))
        c.at(t, _rtp(DAVE, ERIN, 30000, 32000, EVENT_PT, 3000 + i, 160 * start, 0x55555555,
                     body, int(i == start)))  # fmt: skip
    c.sip(2.3, ERIN, DAVE, f"INFO sip:dave@{DAVE} SIP/2.0", cid, "1 INFO", f"erin@{ERIN}",
          f"dave@{DAVE}", "Signal=7\nDuration=250\n", ctype="application/dtmf-relay")  # fmt: skip
    c.sip(2.31, DAVE, ERIN, "SIP/2.0 200 OK", cid, "1 INFO", f"erin@{ERIN}", f"dave@{DAVE}")
    reason = 'Reason: Q.850;cause=16;text="Normal call clearing"\n'
    c.sip(3.6, ERIN, DAVE, f"BYE sip:dave@{DAVE} SIP/2.0", cid, "2 BYE", f"erin@{ERIN}",
          f"dave@{DAVE}", headers=reason)  # fmt: skip
    c.sip(3.61, DAVE, ERIN, "SIP/2.0 200 OK", cid, "2 BYE", f"erin@{ERIN}", f"dave@{DAVE}")


def _one_way_call(c: _CallScript) -> None:
    """frank → erin: one-way audio, codec mismatch, a pause, an SSRC change."""
    cid, base = "oneway@10.0.1.3", 5.0
    c.invite(base, FRANK, "frank", cid, _sdp(FRANK, 34000, "0 8", "0 PCMU/8000, 8 PCMA/8000"))
    c.reply(base + 0.2, FRANK, "frank", cid, "180 Ringing")
    c.reply(base + 0.5, FRANK, "frank", cid, "200 OK", body=_sdp(ERIN, 36000, "0"))
    c.ack(base + 0.51, FRANK, "frank", cid)
    for i in range(50):
        t = base + 0.52 + 0.02 * i + (SILENCE_S if i > SILENCE_AFTER else 0.0)
        ssrc = 0x33333333 if i < SSRC_CHANGE_AT else 0x44444444
        ts = 160 * i + (int(SILENCE_S * 8000) if i > SILENCE_AFTER else 0)
        c.at(t, _rtp(FRANK, ERIN, 34000, 36000, 8, 7000 + i, ts, ssrc, _ALAW_SILENCE,
                     int(i in (0, SSRC_CHANGE_AT))))  # fmt: skip
    c.bye(base + 3.2, FRANK, "frank", cid)


def _calls_without_media(c: _CallScript) -> None:
    """grace's answered call without RTP, heidi's cancelled one and ivan's
    unanswered one."""
    cid, base = "silent@10.0.1.4", 9.0
    c.invite(base, GRACE, "grace", cid, _sdp(GRACE, 38000, "0"))
    c.reply(base + 0.1, GRACE, "grace", cid, "180 Ringing")
    c.reply(base + 0.4, GRACE, "grace", cid, "200 OK", body=_sdp(ERIN, 40000, "0"))
    c.ack(base + 0.41, GRACE, "grace", cid)
    c.bye(base + 2.4, GRACE, "grace", cid)

    cid, base = "cancel@10.0.1.5", 12.0
    c.invite(base, HEIDI, "heidi", cid, _sdp(HEIDI, 42000, "0"))
    c.reply(base + 0.1, HEIDI, "heidi", cid, "180 Ringing")
    c.sip(base + 1.0, HEIDI, ERIN, f"CANCEL sip:erin@{ERIN} SIP/2.0", cid, "1 CANCEL",
          f"heidi@{HEIDI}", f"erin@{ERIN}",
          headers='Reason: SIP;cause=200;text="Call completed elsewhere"\n')  # fmt: skip
    c.reply(base + 1.01, HEIDI, "heidi", cid, "200 OK", cseq="1 CANCEL")
    c.reply(base + 1.02, HEIDI, "heidi", cid, "487 Request Terminated")
    c.ack(base + 1.03, HEIDI, "heidi", cid)

    cid, base = "unavailable@10.0.1.6", 14.0
    c.invite(base, IVAN, "ivan", cid, _sdp(IVAN, 44000, "0"))
    c.reply(base + 0.01, IVAN, "ivan", cid, "100 Trying")
    c.reply(base + 0.8, IVAN, "ivan", cid, "480 Temporarily Unavailable",
            headers="Reason: Q.850;cause=18\n")  # fmt: skip
    c.ack(base + 0.81, IVAN, "ivan", cid)


REGISTRAR = "10.0.1.100"


def _registrations(c: _CallScript) -> None:
    """After the calls (so their frame numbers stay): dave registers after
    a 401 challenge, frank is refused (403), grace unregisters (Expires: 0)."""

    def register(time: float, who: str, addr: str, cseq: int, expires: int, auth: bool = False,
                 status: str = "") -> None:  # fmt: skip
        cid = f"reg-{who}@{addr}"
        headers = f"Expires: {expires}\n"
        if auth:
            headers += f'Authorization: Digest username="{who}", realm="example"\n'
        uri = f"{who}@example.test"
        c.sip(time, addr, REGISTRAR, "REGISTER sip:example.test SIP/2.0", cid,
              f"{cseq} REGISTER", uri, uri, headers=headers)  # fmt: skip
        if status:
            extra = f"Expires: {expires}\n" if status.startswith("200") else ""
            if status.startswith("401"):
                extra = 'WWW-Authenticate: Digest realm="example", nonce="abc"\n'
            c.sip(time + 0.01, REGISTRAR, addr, f"SIP/2.0 {status}", cid, f"{cseq} REGISTER",
                  uri, uri, headers=extra)  # fmt: skip

    register(16.0, "dave", DAVE, 1, 3600, status="401 Unauthorized")
    register(16.1, "dave", DAVE, 2, 3600, auth=True, status="200 OK")
    register(16.5, "frank", FRANK, 1, 3600, status="403 Forbidden")
    register(17.0, "grace", GRACE, 1, 0, status="200 OK")


def voip_calls_packets() -> list[Packet]:
    """Calls for call quality, timings, media problems and DTMF (all to erin):

    1. dave → erin, G.711 A-law both ways with telephone-events (the digits
       "4" and "#" from dave as RFC 4733 events, "7" from erin as a SIP INFO
       with application/dtmf-relay); erin hangs up with a Q.850 Reason.
    2. frank → erin: the answer agrees on PCMU but frank sends PCMA, erin
       sends nothing (one-way audio), frank's stream pauses for 1.5 s and
       then changes SSRC; frank hangs up.
    3. grace → erin: answered, no RTP at all.
    4. heidi → erin: cancelled while ringing (Reason: SIP cause 200).
    5. ivan → erin: 480 Temporarily Unavailable (Reason: Q.850 cause 18, no
       text).

    Then three registrations (_registrations).
    """
    script = _CallScript()
    _dtmf_call(script)
    _one_way_call(script)
    _calls_without_media(script)
    _registrations(script)
    return script.packets()


# voip-media.pcap: G.722, G.726-32 and L16 audio with RTCP (both to erin).
JUDY, KEN = "10.0.1.7", "10.0.1.8"
CODEC_VECTORS = HERE / "codecs"  # ffmpeg-encoded test vectors (see test_codecs.py)
RTCP_RTT_MS = 40  # the round trip judy's report gives (LSR/DLSR of erin's SR)


def _rtcp_report(ssrc: int, fraction: int, lost: int, highest: int, jitter: int, lsr: int,
                 dlsr: int) -> bytes:  # fmt: skip
    return struct.pack(">IIIIII", ssrc, (fraction << 24) | lost, highest, jitter, lsr, dlsr)


def _rtcp_sr(src: str, dst: str, sport: int, dport: int, ssrc: int, ntp: int, rtp_ts: int,
             packets: int, octets: int, block: bytes) -> Packet:  # fmt: skip
    """An RTCP sender report with one report block (RFC 3550 6.4.1)."""
    body = struct.pack(">IQIII", ssrc, ntp, rtp_ts, packets, octets) + block
    header = struct.pack(">BBH", 0x81, 200, (4 + len(body)) // 4 - 1)
    return Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(header + body)


def _media_stream(c: _CallScript, src: str, dst: str, sport: int, dport: int, pt: int,
                  ssrc: int, start: float, payloads: list[bytes]) -> None:  # fmt: skip
    for i, payload in enumerate(payloads):
        c.at(start + 0.02 * i, _rtp(src, dst, sport, dport, pt, 100 + i, 160 * i, ssrc, payload,
                                    int(i == 0)))  # fmt: skip


def voip_media_packets() -> list[Packet]:
    """judy → erin: judy sends G.722 (payload type 9), erin G.726-32
    (dynamic type 96 in the SDP), both from the ffmpeg-encoded vectors in
    codecs/ (0.5 s of 440 Hz + 3 kHz); each side sends an RTCP sender
    report about the other's stream, judy's giving a round trip of
    RTCP_RTT_MS. Then ken → erin: L16 at 8 kHz (dynamic type 97), a 1 kHz
    tone one way."""
    c = _CallScript()
    g722 = (CODEC_VECTORS / "tone.g722").read_bytes()
    g726 = (CODEC_VECTORS / "tone.g726").read_bytes()
    cid = "codecs@10.0.1.7"
    maps = "9 G722/8000, 96 G726-32/8000"
    c.invite(0.0, JUDY, "judy", cid, _sdp(JUDY, 46000, "9 96", maps))
    c.reply(0.1, JUDY, "judy", cid, "180 Ringing")
    c.reply(0.5, JUDY, "judy", cid, "200 OK", body=_sdp(ERIN, 48000, "9 96", maps))
    c.ack(0.51, JUDY, "judy", cid)
    start = 0.52
    _media_stream(c, JUDY, ERIN, 46000, 48000, 9, 0x77777777, start,
                  [g722[i : i + 160] for i in range(0, len(g722), 160)])  # fmt: skip
    _media_stream(c, ERIN, JUDY, 48000, 46000, 96, 0x88888888, start + 0.001,
                  [g726[i : i + 80] for i in range(0, len(g726), 80)])  # fmt: skip
    # erin's SR at +0.30 s; judy's SR at +0.40 s answers it (LSR = the middle 32
    # bits of erin's NTP time, DLSR 60 ms), so the round trip is 40 ms.
    ntp = (3_900_000_000 << 32) | 0x8000_0000
    dlsr = (100 - RTCP_RTT_MS) * 65536 // 1000
    c.at(start + 0.30, _rtcp_sr(ERIN, JUDY, 48001, 46001, 0x88888888, ntp, 2400, 15, 1200,
                                _rtcp_report(0x77777777, 0, 0, 115, 16, 0, 0)))  # fmt: skip
    c.at(start + 0.40, _rtcp_sr(JUDY, ERIN, 46001, 48001, 0x77777777, ntp + (1 << 32) // 10,
                                3200, 20, 3200,
                                _rtcp_report(0x88888888, 26, 2, 119, 40, (ntp >> 16) & 0xFFFFFFFF,
                                             dlsr)))  # fmt: skip
    c.bye(1.2, JUDY, "judy", cid)

    cid = "l16@10.0.1.8"
    c.invite(2.0, KEN, "ken", cid, _sdp(KEN, 50000, "97", "97 L16/8000"))
    c.reply(2.4, KEN, "ken", cid, "200 OK", body=_sdp(ERIN, 52000, "97", "97 L16/8000"))
    c.ack(2.41, KEN, "ken", cid)
    import math  # noqa: PLC0415 - only this fixture needs it

    tone = [int(8000 * math.sin(2 * math.pi * 1000 * n / 8000)) for n in range(4000)]
    frames = [struct.pack(">160h", *tone[i : i + 160]) for i in range(0, 4000, 160)]
    _media_stream(c, KEN, ERIN, 50000, 52000, 97, 0x99999999, 2.42, frames)
    c.bye(3.2, KEN, "ken", cid)
    return c.packets()


# voip-other.pcap: calls over H.323, IAX2 and MGCP.
ALAN, BETTY, CARL = "10.0.2.10", "10.0.2.20", "10.0.2.30"
MIKE, NINA, PBX = "10.0.3.10", "10.0.3.20", "10.0.3.1"
AGENT, GW1, GW2 = "10.0.4.1", "10.0.4.11", "10.0.4.12"
H323_GUIDS = tuple(bytes([0x11 * (n + 1)] * 4) + bytes(range(12)) for n in range(3))
MGCP_CALLS = ("A3C47F21456789F0", "B4D58A3256789AB1")
IAX2_ULAW = 4  # AST_FORMAT_ULAW


def alaw_encode(sample: int) -> int:
    """G.711 A-law byte of a 16-bit linear sample (the usual segment encoder)."""
    sign = 0x80 if sample >= 0 else 0
    magnitude = min(abs(sample), 32767) >> 3
    if magnitude < 32:
        code = magnitude >> 1
    else:
        exponent = magnitude.bit_length() - 5
        code = (exponent << 4) | ((magnitude >> exponent) & 0x0F)
    return (sign | code) ^ 0x55


def _alaw_tone(freq: float, start: int, count: int) -> bytes:
    import math  # noqa: PLC0415 - only the VoIP fixtures need it

    return bytes(
        alaw_encode(int(12000 * math.sin(2 * math.pi * freq * (start + i) / 8000)))
        for i in range(count)
    )


class _Tcp:
    """One TCP connection's segments (no handshake), each at a script time."""

    def __init__(self, c: _CallScript, a: tuple[str, int], b: tuple[str, int]) -> None:
        self.c, self.ends = c, (a, b)
        self.seq = {a: 1000, b: 5000}

    def send(self, time: float, src: tuple[str, int], data: bytes) -> None:
        dst = self.ends[1] if src == self.ends[0] else self.ends[0]
        pkt = (
            Ether() / IP(src=src[0], dst=dst[0])
            / TCP(sport=src[1], dport=dst[1], flags="PA", seq=self.seq[src], ack=self.seq[dst])
            / Raw(data)
        )  # fmt: skip
        self.seq[src] += len(data)
        self.c.at(time, pkt)


def _h323_message(tcp: _Tcp, time: float, src: tuple[str, int], ref: int, kind: int,
                  body: h323.Writer | None, tunnelling: bool = True,
                  h245: Sequence[bytes] = (), **ies: Any) -> None:  # fmt: skip
    """One H.225.0 message; ``ies`` are q931()'s calling/called/cause/display."""
    uuie = h323.user_information(kind, body, tunnelling, h245)
    tcp.send(time, src, h323.q931(ref, src != tcp.ends[0], kind, uuie, **ies))


def _ulaw_stream(c: _CallScript, src: str, dst: str, sport: int, dport: int, ssrc: int,
                 start: float, freq: float) -> None:  # fmt: skip
    payloads = [_tone(freq, 160 * i, 160) for i in range(RTP_PACKETS)]
    _media_stream(c, src, dst, sport, dport, 0, ssrc, start, payloads)


def _h323_calls(c: _CallScript) -> None:
    """1. alan → betty (calling 1001, called 2002), H.245 tunnelled in
       Facility messages: an OpenLogicalChannel and its Ack each way, G.711
       µ-law both ways, a DTMF "5" (UserInputIndication); alan releases
       (Q.850 cause 16).
    2. carl → betty: Setup proposes fast start, but betty's Connect gives
       an h245Address instead; on that H.245 connection carl opens his
       channel and betty's Ack names her media address, and it ends with
       betty's EndSessionCommand; only carl sends RTP; betty releases.
       (One OpenLogicalChannel per message: tshark 4.2.2 fails on a second
       DataType in a packet, so a fast start proposal with a reverse channel
       can't be read there.)
    3. alan → betty: released at once, Q.850 cause 17 (user busy), reason
       inConf."""
    guid = H323_GUIDS[0]
    alan, betty = (ALAN, 11720), (BETTY, 1720)
    tcp = _Tcp(c, alan, betty)
    _h323_message(tcp, 0.0, alan, 1, h323.SETUP, h323.setup(guid, ["alan"], ["2002"]),
                  calling="1001", called="2002", display="Alan")  # fmt: skip
    _h323_message(tcp, 0.01, betty, 1, h323.CALL_PROCEEDING, h323.call_proceeding(guid))
    _h323_message(tcp, 0.1, betty, 1, h323.ALERTING, h323.alerting(guid))
    _h323_message(tcp, 0.8, betty, 1, h323.CONNECT, h323.connect(guid))
    channels = [
        (0.81, alan, h323.open_logical_channel(1, h323.G711_ULAW, control=(ALAN, 5001),
                                               message=True)),
        (0.82, betty, h323.open_logical_channel_ack(1, (BETTY, 6000), (BETTY, 6001))),
        (0.83, betty, h323.open_logical_channel(1, h323.G711_ULAW, control=(BETTY, 6001),
                                                message=True)),
        (0.84, alan, h323.open_logical_channel_ack(1, (ALAN, 5000), (ALAN, 5001))),
    ]  # fmt: skip
    for time, src, message in channels:
        _h323_message(tcp, time, src, 1, h323.EMPTY, None, h245=[message])
    _ulaw_stream(c, ALAN, BETTY, 5000, 6000, 0x23230001, 0.85, RTP_TONES[0])
    _ulaw_stream(c, BETTY, ALAN, 6000, 5000, 0x23230002, 0.851, RTP_TONES[1])
    _h323_message(tcp, 1.3, alan, 1, h323.EMPTY, None, h245=[h323.user_input_signal("5", 160)])
    _h323_message(tcp, 2.0, alan, 1, h323.RELEASE_COMPLETE, h323.release_complete(guid),
                  cause=16)  # fmt: skip

    guid = H323_GUIDS[1]
    carl = (CARL, 11721)
    tcp = _Tcp(c, carl, betty)
    proposal = h323.open_logical_channel(1, h323.G711_ULAW, control=(CARL, 5011))
    _h323_message(tcp, 3.0, carl, 2, h323.SETUP,
                  h323.setup(guid, ["carl"], ["betty"], [proposal]), tunnelling=False,
                  calling="3003", called="2002")  # fmt: skip
    _h323_message(tcp, 3.1, betty, 2, h323.ALERTING, h323.alerting(guid), tunnelling=False)
    _h323_message(tcp, 3.5, betty, 2, h323.CONNECT, h323.connect(guid, h245=(BETTY, 1800)),
                  tunnelling=False)  # fmt: skip
    control = _Tcp(c, (CARL, 11801), (BETTY, 1800))
    control.send(3.52, (CARL, 11801), h323.tpkt(h323.open_logical_channel(
        1, h323.G711_ULAW, control=(CARL, 5011), message=True)))  # fmt: skip
    control.send(
        3.53,
        (BETTY, 1800),
        h323.tpkt(h323.open_logical_channel_ack(1, (BETTY, 6010), (BETTY, 6011))),
    )
    _ulaw_stream(c, CARL, BETTY, 5010, 6010, 0x23230003, 3.54, RTP_TONES[0])
    control.send(4.6, (BETTY, 1800), h323.tpkt(h323.end_session()))
    _h323_message(tcp, 4.7, betty, 2, h323.RELEASE_COMPLETE, h323.release_complete(guid),
                  tunnelling=False, cause=16)  # fmt: skip

    guid = H323_GUIDS[2]
    tcp = _Tcp(c, (ALAN, 11722), betty)
    _h323_message(tcp, 5.0, (ALAN, 11722), 3, h323.SETUP, h323.setup(guid, ["alan"], ["2002"]),
                  calling="1001", called="2002")  # fmt: skip
    _h323_message(tcp, 5.05, betty, 3, h323.RELEASE_COMPLETE,
                  h323.release_complete(guid, h323.IN_CONF), cause=17)  # fmt: skip


def _iax2_ie(ie: int, value: bytes) -> bytes:
    return bytes([ie, len(value)]) + value


class _Iax2:
    """One IAX2 call's frames between a client and the PBX (UDP 4569):
    full frames with both call numbers and sequence numbers, mini frames
    for voice."""

    def __init__(self, c: _CallScript, client: str, start: float, number: int) -> None:
        self.c, self.client, self.start = c, client, start
        self.calls = {client: number, PBX: number + 100}
        self.out = {client: 0, PBX: 0}

    def _send(self, time: float, src: str, data: bytes) -> None:
        dst = PBX if src == self.client else self.client
        self.c.at(time, Ether() / IP(src=src, dst=dst) / UDP(sport=4569, dport=4569) / Raw(data))

    def ts(self, time: float) -> int:
        return round((time - self.start) * 1000) + 3

    def full(self, time: float, src: str, kind: int, subclass: int, ies: bytes = b"",
             first: bool = False) -> None:  # fmt: skip
        """A full frame (``first``: the NEW, before the PBX picked a call number)."""
        dst = PBX if src == self.client else self.client
        header = struct.pack(
            ">HHIBBBB", 0x8000 | self.calls[src], 0 if first else self.calls[dst],
            self.ts(time), self.out[src], self.out[dst], kind, subclass,
        )  # fmt: skip
        if kind != 6 or subclass != 4:  # (an ACK doesn't count)
            self.out[src] += 1
        self._send(time, src, header + ies)

    def mini(self, time: float, src: str, payload: bytes) -> None:
        self._send(time, src, struct.pack(">HH", self.calls[src], self.ts(time) & 0xFFFF) + payload)

    def voice(self, start: float, src: str, freq: float) -> None:
        """RTP_PACKETS 20 ms µ-law frames: a full voice frame, then mini frames."""
        for i in range(RTP_PACKETS):
            payload = _tone(freq, 160 * i, 160)
            if i == 0:
                self.full(start, src, 2, IAX2_ULAW, payload)
            else:
                self.mini(start + 0.02 * i, src, payload)


def _iax2_calls(c: _CallScript) -> None:
    """1. mike (3001, "Mike") → 4001 at the PBX: ringing, answered, µ-law both
       ways, a DTMF "7" from mike; the PBX hangs up (cause 16).
    2. nina → 9999: rejected ("No such context/extension", cause 1)."""
    call = _Iax2(c, MIKE, 6.0, 1)
    fmt = struct.pack(">I", IAX2_ULAW)
    call.full(6.0, MIKE, 6, 1, _iax2_ie(11, b"\x00\x02") + _iax2_ie(1, b"4001")
              + _iax2_ie(2, b"3001") + _iax2_ie(4, b"Mike") + _iax2_ie(5, b"default")
              + _iax2_ie(8, fmt) + _iax2_ie(9, fmt), first=True)  # fmt: skip
    call.full(6.01, PBX, 6, 7, _iax2_ie(9, fmt))  # ACCEPT
    call.full(6.011, MIKE, 6, 4)  # ACK
    call.full(6.1, PBX, 4, 3)  # RINGING
    call.full(6.9, PBX, 4, 4)  # ANSWER
    call.full(6.901, MIKE, 6, 4)
    call.voice(6.92, MIKE, RTP_TONES[0])
    call.voice(6.921, PBX, RTP_TONES[1])
    call.full(7.5, MIKE, 1, ord("7"))  # DTMF end
    call.full(8.0, PBX, 6, 5, _iax2_ie(22, b"Normal Clearing") + _iax2_ie(42, b"\x10"))
    call.full(8.01, MIKE, 6, 4)

    call = _Iax2(c, NINA, 9.0, 2)
    call.full(9.0, NINA, 6, 1, _iax2_ie(11, b"\x00\x02") + _iax2_ie(1, b"9999")
              + _iax2_ie(2, b"3002") + _iax2_ie(9, fmt), first=True)  # fmt: skip
    call.full(9.02, PBX, 6, 6, _iax2_ie(22, b"No such context/extension") + _iax2_ie(42, b"\x01"))
    call.full(9.021, NINA, 6, 4)


def _mgcp(c: _CallScript, time: float, src: str, dst: str, text: str) -> None:
    sport, dport = (2727, 2427) if src == AGENT else (2427, 2727)
    data = text.replace("\n", "\r\n").encode()
    c.at(time, Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(data))


def _mgcp_sdp(addr: str, port: int) -> str:
    return _sdp(addr, port, "8", "8 PCMA/8000")


class _Mgcp:
    """Transactions between the call agent and the gateways: a command (with
    ``sdp``: the other side's), then its response 5 ms later (``code``,
    ``reply`` lines and with ``local`` the gateway's own SDP)."""

    def __init__(self, c: _CallScript) -> None:
        self.c, self.gateway_id, self.agent_id = c, 1000, 2000

    def notify(self, time: float, gw: str, endpoint: str, events: str) -> None:
        self.gateway_id += 1
        tid = self.gateway_id
        _mgcp(self.c, time, gw, AGENT,
              f"NTFY {tid} {endpoint} MGCP 1.0\nX: {tid:012X}\nO: {events}\n")  # fmt: skip
        _mgcp(self.c, time + 0.005, AGENT, gw, f"200 {tid} OK\n")

    def command(self, time: float, gw: str, verb: str, endpoint: str, params: str,
                code: str = "200 OK", reply: str = "", sdp: str = "",
                local: str = "") -> None:  # fmt: skip
        self.agent_id += 1
        tid = self.agent_id
        body = f"\n{sdp}" if sdp else ""
        _mgcp(self.c, time, AGENT, gw, f"{verb} {tid} {endpoint} MGCP 1.0\n{params}{body}")
        status, _, text = code.partition(" ")
        answer = f"\n{local}" if local else ""
        _mgcp(self.c, time + 0.005, gw, AGENT, f"{status} {tid} {text}\n{reply}{answer}")


def _mgcp_calls(c: _CallScript) -> None:
    """1. aaln/1@gw1 dials 2002 → aaln/1@gw2: connections on both gateways
       (CRCX with SDP answers), gw2 rings, answers (off-hook), G.711 A-law
       both ways; gw1 hangs up and the agent deletes both connections.
    2. aaln/1@gw2 dials 1001 → aaln/1@gw1, which refuses the connection (401
       Phone off hook); gw2 gets a busy tone and hangs up.
    Before them an audit (AUEP) that belongs to no call."""
    m = _Mgcp(c)
    ep1, ep2 = "aaln/1@gw1.example.net", "aaln/1@gw2.example.net"
    m.command(9.5, GW1, "AUEP", ep1, "F: A\n", reply="A: a:PCMA, p:10-20\n")
    cid = MGCP_CALLS[0]
    m.notify(10.0, GW1, ep1, "L/hd")
    m.command(10.05, GW1, "RQNT", ep1, "X: 0A1\nS: L/dl\nR: D/[0-9]\n")
    m.notify(10.5, GW1, ep1, "D/2,D/0,D/0,D/2")
    m.command(10.6, GW1, "CRCX", ep1, f"C: {cid}\nL: p:20, a:PCMA\nM: recvonly\n",
              reply="I: FDE234C8\n", local=_mgcp_sdp(GW1, 3456))  # fmt: skip
    m.command(10.7, GW2, "CRCX", ep2, f"C: {cid}\nL: p:20, a:PCMA\nM: sendrecv\n",
              reply="I: 32F345E2\n", sdp=_mgcp_sdp(GW1, 3456),
              local=_mgcp_sdp(GW2, 3460))  # fmt: skip
    m.command(10.8, GW2, "RQNT", ep2, "X: 0A2\nS: L/rg\nR: L/hd\n")
    m.command(10.81, GW1, "MDCX", ep1, f"C: {cid}\nI: FDE234C8\nM: recvonly\nS: L/rt\n",
              sdp=_mgcp_sdp(GW2, 3460))  # fmt: skip
    m.notify(12.0, GW2, ep2, "L/hd")
    m.command(12.05, GW1, "MDCX", ep1, f"C: {cid}\nI: FDE234C8\nM: sendrecv\n")
    for i in range(RTP_PACKETS):
        c.at(
            12.06 + 0.02 * i,
            _rtp(
                GW1,
                GW2,
                3456,
                3460,
                8,
                300 + i,
                160 * i,
                0x6C6C0001,
                _alaw_tone(RTP_TONES[0], 160 * i, 160),
                int(i == 0),
            ),
        )
        c.at(
            12.061 + 0.02 * i,
            _rtp(
                GW2,
                GW1,
                3460,
                3456,
                8,
                700 + i,
                160 * i,
                0x6C6C0002,
                _alaw_tone(RTP_TONES[1], 160 * i, 160),
                int(i == 0),
            ),
        )
    m.notify(13.2, GW1, ep1, "L/hu")
    m.command(13.25, GW1, "DLCX", ep1, f"C: {cid}\nI: FDE234C8\n", code="250 OK",
              reply="P: PS=50, OS=8000, PR=50, OR=8000, PL=0, JI=0, LA=0\n")  # fmt: skip
    m.command(13.26, GW2, "DLCX", ep2, f"C: {cid}\nI: 32F345E2\n", code="250 OK")

    cid = MGCP_CALLS[1]
    m.notify(14.0, GW2, ep2, "L/hd")
    m.notify(14.3, GW2, ep2, "D/1,D/0,D/0,D/1")
    m.command(14.4, GW2, "CRCX", ep2, f"C: {cid}\nM: recvonly\n", reply="I: 43A456F3\n",
              local=_mgcp_sdp(GW2, 3470))  # fmt: skip
    m.command(14.5, GW1, "CRCX", ep1, f"C: {cid}\nM: sendrecv\n", code="401 Phone off hook",
              sdp=_mgcp_sdp(GW2, 3470))  # fmt: skip
    m.command(14.55, GW2, "RQNT", ep2, "X: 0A3\nS: L/bz\nR: L/hu\n")
    m.notify(15.0, GW2, ep2, "L/hu")
    m.command(15.05, GW2, "DLCX", ep2, f"C: {cid}\nI: 43A456F3\n", code="250 OK")


def voip_other_packets() -> list[Packet]:
    """Calls over the other VoIP signalling protocols: _h323_calls,
    _iax2_calls and _mgcp_calls."""
    c = _CallScript()
    _h323_calls(c)
    _iax2_calls(c)
    _mgcp_calls(c)
    return c.packets()


def _h2_frame(kind: int, flags: int, stream: int, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))[1:]
        + bytes([kind, flags])
        + struct.pack(">I", stream)
        + payload
    )


def _hpack(*headers: tuple[bytes, bytes]) -> bytes:
    """HPACK literal header fields without indexing, new names (no Huffman)."""
    return b"".join(b"\0" + bytes([len(n)]) + n + bytes([len(v)]) + v for n, v in headers)


def _ws_frame(payload: bytes, mask: bytes | None = None) -> bytes:
    """A final WebSocket text frame; clients mask theirs (RFC 6455)."""
    if mask is None:
        return b"\x81" + bytes([len(payload)]) + payload
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return b"\x81" + bytes([0x80 | len(payload)]) + mask + masked


def streams_packets() -> list[Packet]:
    """Streams Follow Stream reads above TCP and UDP: an HTTP/2 connection
    (prior knowledge, two requests on HTTP/2 streams 1 and 3; tcp.stream 0),
    a WebSocket conversation (tcp.stream 1) and a QUIC connection with
    STREAM data on streams 0 and 4 (decrypted with the key log that
    ``main`` stores in the file's Decryption Secrets Block)."""
    h2 = _TcpSession("192.168.1.10", "192.168.1.20", 50100, 8080)
    h2.handshake()
    settings, settings_ack = _h2_frame(4, 0, 0, b""), _h2_frame(4, 1, 0, b"")

    def request(stream: int, path: bytes) -> bytes:
        headers = _hpack(
            (b":method", b"GET"), (b":scheme", b"http"), (b":path", path),
            (b":authority", b"example.test"),
        )  # fmt: skip
        return _h2_frame(1, 0x05, stream, headers)  # END_STREAM | END_HEADERS

    def response(stream: int, body: bytes) -> bytes:
        headers = _hpack((b":status", b"200"), (b"content-type", b"text/plain"))
        return _h2_frame(1, 0x04, stream, headers) + _h2_frame(0, 0x01, stream, body)

    h2.client_send(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + settings)
    h2.server_send(settings + settings_ack)
    h2.client_send(settings_ack + request(1, b"/one.txt") + request(3, b"/two.txt"))
    h2.server_send(response(1, b"first stream body\n"))
    h2.server_send(response(3, b"second stream body\n"))
    h2.close()

    ws = _TcpSession("192.168.1.10", "192.168.1.30", 50200, 80)
    ws.handshake()
    ws.client_send(
        b"GET /chat HTTP/1.1\r\nHost: example.test\r\nUpgrade: websocket\r\n"
        b"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        b"Sec-WebSocket-Version: 13\r\n\r\n"
    )
    ws.server_send(
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
    )
    ws.client_send(_ws_frame(b"hello server", mask=b"\x01\x02\x03\x04"))
    ws.server_send(_ws_frame(b"hello client"))
    ws.close()

    ends = [("10.0.0.1", 50300), ("10.0.0.2", 443)]
    datagrams: list[Packet] = []
    for direction, payload in quic.datagrams():
        (src, sport), (dst, dport) = ends[direction], ends[1 - direction]
        datagrams.append(
            Ether(src=CLIENT_MAC if direction == 0 else SERVER_MAC)
            / IP(src=src, dst=dst)
            / UDP(sport=sport, dport=dport)
            / Raw(payload)
        )
    return _stamp(h2.packets + ws.packets + datagrams)


def services_packets() -> list[Packet]:
    """Traffic for the service statistics: HTTP requests with several methods and
    status codes on two hosts, DNS queries of several types (one NXDOMAIN), SNMP
    requests with known response times, and ICMP echoes (one unanswered)."""
    timed: list[tuple[float, Packet]] = []
    exchanges = [
        ("example.com", "93.184.216.34", b"GET /index.html", b"200 OK"),
        ("example.com", "93.184.216.34", b"GET /missing.png", b"404 Not Found"),
        ("example.com", "93.184.216.34", b"POST /form", b"200 OK"),
        ("api.example.net", "198.51.100.7", b"GET /v1/items", b"301 Moved Permanently"),
    ]
    for i, (host, addr, request, status) in enumerate(exchanges):
        s = _TcpSession("192.168.1.10", addr, 51000 + i, 80)
        s.handshake()
        body = b"" if request.startswith(b"GET") else b"a=1"
        s.client_send(
            request
            + b" HTTP/1.1\r\nHost: "
            + host.encode()
            + f"\r\nContent-Length: {len(body)}\r\n\r\n".encode()
            + body
        )
        s.server_send(b"HTTP/1.1 " + status + b"\r\nContent-Length: 0\r\n\r\n")
        s.close()
        timed += [(0.1 * i + 0.001 * j, pkt) for j, pkt in enumerate(s.packets)]
    queries = [
        ("example.com", "A", 0, 0.012),
        ("example.com", "AAAA", 0, 0.020),
        ("example.com", "MX", 0, 0.016),
        ("nothing.invalid", "A", 3, 0.030),
    ]
    for i, (name, qtype, rcode, delay) in enumerate(queries):
        qid = 0x2000 + i
        q = (
            Ether(src=CLIENT_MAC, dst=SERVER_MAC)
            / IP(src="192.168.1.10", dst="8.8.8.8")
            / UDP(sport=41000 + i, dport=53)
            / DNS(id=qid, rd=1, qd=DNSQR(qname=name, qtype=qtype))
        )
        r = (
            Ether(src=SERVER_MAC, dst=CLIENT_MAC)
            / IP(src="8.8.8.8", dst="192.168.1.10")
            / UDP(sport=53, dport=41000 + i)
            / DNS(id=qid, qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=name, qtype=qtype))
        )
        timed += [(0.5 + 0.1 * i, q), (0.5 + 0.1 * i + delay, r)]
    snmp = [
        (SNMPget, "1.3.6.1.2.1.1.1.0", 0.004),
        (SNMPget, "1.3.6.1.2.1.1.3.0", 0.010),
        (SNMPget, "1.3.6.1.2.1.1.5.0", 0.007),
        (SNMPnext, "1.3.6.1.2.1.2.2.1.2", 0.002),
    ]
    for i, (pdu, oid, delay) in enumerate(snmp):
        bind = [SNMPvarbind(oid=ASN1_OID(oid))]
        q = (
            Ether(src=CLIENT_MAC, dst=SERVER_MAC)
            / IP(src="192.168.1.10", dst="192.168.1.20")
            / UDP(sport=42000 + i, dport=161)
            / SNMP(community="public", PDU=pdu(id=100 + i, varbindlist=bind))
        )
        r = (
            Ether(src=SERVER_MAC, dst=CLIENT_MAC)
            / IP(src="192.168.1.20", dst="192.168.1.10")
            / UDP(sport=161, dport=42000 + i)
            / SNMP(community="public", PDU=SNMPresponse(id=100 + i, varbindlist=bind))
        )
        timed += [(1.0 + 0.1 * i, q), (1.0 + 0.1 * i + delay, r)]
    for i, delay in enumerate([0.003, 0.009, None]):
        q = (
            Ether(src=CLIENT_MAC, dst=SERVER_MAC)
            / IP(src="192.168.1.10", dst="192.168.1.1")
            / ICMP(type=8, id=7, seq=i + 1)
            / Raw(b"ping")
        )
        timed.append((1.5 + 0.1 * i, q))
        if delay is not None:
            r = (
                Ether(src=SERVER_MAC, dst=CLIENT_MAC)
                / IP(src="192.168.1.1", dst="192.168.1.10")
                / ICMP(type=0, id=7, seq=i + 1)
                / Raw(b"ping")
            )
            timed.append((1.5 + 0.1 * i + delay, r))
    timed.sort(key=lambda tp: tp[0])
    for at, pkt in timed:
        pkt.time = BASE_TS + at
    return [pkt for _, pkt in timed]


# Sessions (sessions.pcap): HTTP requests with their answers, DNS queries and
# TLS handshakes, with known timings, for the HTTP, DNS and TLS session tables.
SESSIONS_CLIENT = "192.168.1.10"


def _png_1x1() -> bytes:
    """A valid one-pixel grey PNG (tshark dissects the image)."""

    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack("!I", len(data)) + kind + data + struct.pack("!I", zlib.crc32(kind + data))
        )

    ihdr = struct.pack("!IIBBBBB", 1, 1, 8, 0, 0, 0, 0)
    return (
        bytes.fromhex("89504e470d0a1a0a")
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(b"\x00\x80"))
        + chunk(b"IEND", b"")
    )


SESSIONS_PNG = _png_1x1()


def _tls_ext(kind: int, data: bytes) -> bytes:
    return struct.pack("!HH", kind, len(data)) + data


def _tls_alpn(*names: bytes) -> bytes:
    names_ = b"".join(struct.pack("!B", len(n)) + n for n in names)
    return _tls_ext(16, struct.pack("!H", len(names_)) + names_)


def _tls_handshake(kind: int, body: bytes) -> bytes:
    handshake = struct.pack("!B", kind) + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def _client_hello(sni: bytes, alpn: Sequence[bytes], tls13: bool) -> bytes:
    server_name = struct.pack("!BH", 0, len(sni)) + sni
    extensions = _tls_ext(0, struct.pack("!H", len(server_name)) + server_name)
    if alpn:
        extensions += _tls_alpn(*alpn)
    if tls13:
        extensions += _tls_ext(43, b"\x04\x03\x04\x03\x03")  # TLS 1.3, TLS 1.2
    suites = b"\x13\x01\x13\x02\xc0\x2f\x00\x9c"
    body = (
        b"\x03\x03" + bytes(range(32)) + b"\x00"
        + struct.pack("!H", len(suites)) + suites + b"\x01\x00"
        + struct.pack("!H", len(extensions)) + extensions
    )  # fmt: skip
    return _tls_handshake(1, body)


def _server_hello(cipher: int, alpn: bytes, tls13: bool) -> bytes:
    extensions = _tls_alpn(alpn)
    if tls13:
        extensions += _tls_ext(43, b"\x03\x04")
    body = (
        b"\x03\x03" + bytes(range(32, 64)) + b"\x00" + struct.pack("!H", cipher) + b"\x00"
        + struct.pack("!H", len(extensions)) + extensions
    )  # fmt: skip
    return _tls_handshake(2, body)


def sessions_packets() -> list[Packet]:
    """HTTP: a keep-alive connection to www.example.com (GET /index.html 200
    after 30 ms, GET /logo.png 200 image/png after 12 ms, POST /api/items 500
    after 250 ms) and one to api.example.net:8080 (GET /v1/missing 404 after
    5 ms, then GET /slow that gets no answer). DNS to 192.168.1.1: www A (a
    CNAME and an address, 12 ms), www AAAA (8 ms), example.com MX (15 ms),
    missing.example.com NXDOMAIN (20 ms) and lost.example.com, unanswered.
    TLS: two connections to 198.51.100.20:443 for api.example.com (TLS 1.2
    with ECDHE-RSA-AES128-GCM-SHA256, then TLS 1.3 with TLS_AES_128_GCM_SHA256,
    both choosing h2) and one to 203.0.113.5:443 for cdn.example.net that
    gets no ServerHello. Last, pipelined HTTP to pipe.example.com: two GETs
    in one segment, answered by two responses in one segment."""
    timed: list[tuple[float, Packet]] = []

    def step(s: _TcpSession, at: float, action: Any, *args: Any) -> None:
        before = len(s.packets)
        action(*args)
        timed.extend((at + 0.0001 * i, pkt) for i, pkt in enumerate(s.packets[before:]))

    def http_request(method: str, uri: str, host: str, body: bytes = b"") -> bytes:
        head = f"{method} {uri} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {len(body)}\r\n\r\n"
        return head.encode() + body

    def http_response(status: str, kind: str, body: bytes) -> bytes:
        head = f"HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {len(body)}\r\n\r\n"
        return head.encode() + body

    www = _TcpSession(SESSIONS_CLIENT, "192.0.2.80", 51100, 80)
    step(www, 0.0, www.handshake)
    exchanges = [
        (0.01, "GET", "/index.html", b"", 0.030, "200 OK", "text/html", b"<html>hi</html>"),
        (0.10, "GET", "/logo.png", b"", 0.012, "200 OK", "image/png", SESSIONS_PNG),
        (0.20, "POST", "/api/items", b'{"name":"x"}', 0.250, "500 Internal Server Error",
         "application/json", b'{"error":"boom"}'),
    ]  # fmt: skip
    for at, method, uri, body, delay, status, kind, answer in exchanges:
        step(www, at, www.client_send, http_request(method, uri, "www.example.com", body))
        step(www, at + delay, www.server_send, http_response(status, kind, answer))
    step(www, 0.6, www.close)
    api = _TcpSession(SESSIONS_CLIENT, "198.51.100.7", 51101, 8080)
    step(api, 0.7, api.handshake)
    step(api, 0.71, api.client_send, http_request("GET", "/v1/missing", "api.example.net"))
    step(api, 0.715, api.server_send, http_response("404 Not Found", "text/plain", b"no"))
    step(api, 0.8, api.client_send, http_request("GET", "/slow", "api.example.net"))

    queries = [
        ("www.example.com", "A", 0, 0.012, [
            DNSRR(rrname="www.example.com", type="CNAME", rdata="edge.example.net"),
            DNSRR(rrname="edge.example.net", type="A", rdata="192.0.2.80"),
        ]),
        ("www.example.com", "AAAA", 0, 0.008, [
            DNSRR(rrname="www.example.com", type="AAAA", rdata="2001:db8::80"),
        ]),
        ("example.com", "MX", 0, 0.015, [
            DNSRRMX(rrname="example.com", preference=10, exchange="mail.example.com"),
        ]),
        ("missing.example.com", "A", 3, 0.020, []),
        ("lost.example.com", "A", 0, None, []),
    ]  # fmt: skip
    for i, (name, qtype, rcode, delay, answers) in enumerate(queries):
        qid, at = 0x3000 + i, 1.0 + 0.1 * i
        q = (
            Ether(src=CLIENT_MAC, dst=SERVER_MAC)
            / IP(src=SESSIONS_CLIENT, dst="192.168.1.1")
            / UDP(sport=43000 + i, dport=53)
            / DNS(id=qid, rd=1, qd=DNSQR(qname=name, qtype=qtype))
        )
        timed.append((at, q))
        if delay is None:
            continue
        an = None
        for rr in answers:
            an = rr if an is None else an / rr
        r = (
            Ether(src=SERVER_MAC, dst=CLIENT_MAC)
            / IP(src="192.168.1.1", dst=SESSIONS_CLIENT)
            / UDP(sport=53, dport=43000 + i)
            / DNS(
                id=qid, qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=name, qtype=qtype),
                an=an, ancount=len(answers),
            )
        )  # fmt: skip
        timed.append((at + delay, r))

    hellos = [
        (52001, "198.51.100.20", b"api.example.com", False, 0xC02F),
        (52002, "198.51.100.20", b"api.example.com", True, 0x1301),
        (52003, "203.0.113.5", b"cdn.example.net", True, None),
    ]
    for i, (port, server, sni, tls13, cipher) in enumerate(hellos):
        s = _TcpSession(SESSIONS_CLIENT, server, port, 443)
        at = 2.0 + 0.2 * i
        step(s, at, s.handshake)
        step(s, at + 0.01, s.client_send, _client_hello(sni, [b"h2", b"http/1.1"], tls13))
        if cipher is not None:
            step(s, at + 0.04, s.server_send, _server_hello(cipher, b"h2", tls13))
    pipe = _TcpSession(SESSIONS_CLIENT, "192.0.2.81", 51102, 80)
    step(pipe, 3.0, pipe.handshake)
    two = http_request("GET", "/a.txt", "pipe.example.com") + http_request(
        "GET", "/b.txt", "pipe.example.com"
    )
    step(pipe, 3.01, pipe.client_send, two)
    answers = http_response("200 OK", "text/plain", b"a")
    answers += http_response("404 Not Found", "text/plain", b"b")
    step(pipe, 3.03, pipe.server_send, answers)
    timed.sort(key=lambda tp: tp[0])
    for at, pkt in timed:
        pkt.time = BASE_TS + at
    return [pkt for _, pkt in timed]


# Replay to Service (replay.pcap): an operator's delivery function sending to a
# collector, as lawful interception handover does (HI2 on one port, HI3 on
# another). Synthetic data; the expected bytes per recorded target, one entry
# per connection (in the order they open) or per UDP datagram.
REPLAY_OPERATOR, REPLAY_COLLECTOR = "10.10.0.1", "10.20.0.5"
REPLAY_HI2, REPLAY_HI3, REPLAY_UDP = 11000, 11001, 11002


def _pdu(label: str, size: int) -> bytes:
    """A BER SEQUENCE of ``size`` content bytes: the label repeated."""
    body = (f"{label};" * (size // (len(label) + 1) + 1)).encode()[:size]
    return b"\x30\x82" + size.to_bytes(2, "big") + body


REPLAY_PDUS = {
    name: _pdu(name, size)
    for name, size in (
        ("A1", 120), ("A2", 200), ("A3", 80), ("B1", 1200), ("B2", 1200), ("B3", 900),
        ("C1", 60), ("C2", 60), ("D1", 300), ("D2", 300), ("D3", 300), ("E1", 50),
        ("U1", 100), ("U2", 100), ("U3", 100),
    )
}  # fmt: skip
_P = REPLAY_PDUS
REPLAY_EXPECTED = {
    f"tcp {REPLAY_COLLECTOR}:{REPLAY_HI2}": [
        _P["A1"] + _P["A2"] + _P["A3"], _P["E1"], _P["C1"] + _P["C2"],
    ],
    f"tcp {REPLAY_COLLECTOR}:{REPLAY_HI3}": [_P["B1"] + _P["B2"] + _P["B3"], _P["D1"] + _P["D3"]],
    f"udp {REPLAY_COLLECTOR}:{REPLAY_UDP}": [_P["U1"], _P["U2"], _P["U3"]],
}  # fmt: skip
REPLAY_KEEPALIVE = b"\x30\x03ack"  # the collector's answer on connection A


def replay_packets() -> list[Packet]:
    """``replay.pcap``: connections to two collector ports that overlap in
    time. A: data with pauses, a collector reply, a retransmission, a FIN.
    B: large PDUs and a segment overlapping the previous one. C: started
    before the capture (no SYN, no FIN). D: a segment missing from the
    capture (a gap). E: closed with a reset. A UDP flow with a reply, and
    unrelated DNS and ARP packets."""
    timed: list[tuple[float, Packet]] = []
    op, coll = REPLAY_OPERATOR, REPLAY_COLLECTOR

    def at(t: float, s: _TcpSession, step: Any) -> None:
        n = len(s.packets)
        step()
        timed.extend((t + 0.001 * j, pkt) for j, pkt in enumerate(s.packets[n:]))

    a = _TcpSession(op, coll, 40100, REPLAY_HI2)
    at(0.000, a, a.handshake)
    at(0.050, a, lambda: a.client_send(_P["A1"]))
    at(0.060, a, lambda: a.server_send(REPLAY_KEEPALIVE))
    at(0.150, a, lambda: a.client_send(_P["A2"]))
    at(0.170, a, lambda: a.packets.append(a.packets[-2].copy()))  # A2 again
    at(0.250, a, lambda: a.client_send(_P["A3"]))
    at(0.300, a, a.close)

    b = _TcpSession(op, coll, 40101, REPLAY_HI3)
    at(0.020, b, b.handshake)
    at(0.080, b, lambda: b.client_send(_P["B1"]))
    at(0.120, b, lambda: b.client_send(_P["B2"]))

    def overlap() -> None:
        b.cseq -= 100  # the end of B2 again, then B3
        b.client_send(_P["B2"][-100:] + _P["B3"])

    at(0.200, b, overlap)
    at(0.280, b, b.close)

    c = _TcpSession(op, coll, 40102, REPLAY_HI2)
    at(0.100, c, lambda: c.client_send(_P["C1"]))
    at(0.220, c, lambda: c.client_send(_P["C2"]))

    d = _TcpSession(op, coll, 40103, REPLAY_HI3)
    at(0.030, d, d.handshake)
    at(0.090, d, lambda: d.client_send(_P["D1"]))

    def lost() -> None:
        d.cseq += len(_P["D2"])  # sent, but not in the capture

    at(0.140, d, lost)
    at(0.180, d, lambda: d.client_send(_P["D3"]))
    at(0.260, d, d.close)

    e = _TcpSession(op, coll, 40104, REPLAY_HI2)
    at(0.040, e, e.handshake)
    at(0.110, e, lambda: e.client_send(_P["E1"]))
    at(0.130, e, lambda: e._c("R"))

    def udp(t: float, src: str, dst: str, sport: int, dport: int, data: bytes) -> None:
        pkt = (
            Ether(src=CLIENT_MAC, dst=SERVER_MAC)
            / IP(src=src, dst=dst)
            / UDP(sport=sport, dport=dport)
        )
        timed.append((t, pkt / Raw(data)))

    for i, name in enumerate(("U1", "U2", "U3")):
        udp(0.050 + 0.050 * i, op, coll, 40200, REPLAY_UDP, _P[name])
    udp(0.105, coll, op, REPLAY_UDP, 40200, b"udp-ack")

    dns = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=op, dst="10.0.0.53")
    timed.append(
        (0.010, dns / UDP(sport=43000, dport=53) / DNS(id=7, rd=1, qd=DNSQR(qname="collector.lab")))
    )
    timed.append((0.005, Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(psrc=op, pdst=coll)))
    timed.sort(key=lambda tp: tp[0])
    for t, pkt in timed:
        pkt.time = BASE_TS + t
    return [pkt for _, pkt in timed]


def office_packets(problems: bool) -> list[Packet]:
    """A small office network for comparing captures and for the answer-quality
    test set (test/eval): ``office-before.pcap`` is healthy; ``office-after.pcap``
    (``problems``) has the same traffic plus known faults: HTTP 503s, a port
    scan from a new host answered with resets, DNS SERVFAILs and a query with
    no answer, a retransmitted request, and pings with no reply."""
    timed: list[tuple[float, Packet]] = []
    web, dns_server, gateway = "10.0.0.80", "10.0.0.53", "10.0.0.1"
    clients = ["10.0.0.21", "10.0.0.22"]
    pages = [b"/index.html", b"/app.js", b"/api/orders", b"/api/stock"]
    for i, page in enumerate(pages * 2):
        client = clients[i % 2]
        s = _TcpSession(client, web, 52000 + i, 80)
        s.handshake()
        s.client_send(b"GET " + page + b" HTTP/1.1\r\nHost: intranet\r\n\r\n")
        if problems and i == 5:
            # The request again, same sequence number: a retransmission.
            s.packets.append(s.packets[-2].copy())
        failed = problems and page.startswith(b"/api/")
        status = b"503 Service Unavailable" if failed else b"200 OK"
        body = b"" if failed else b"ok" * 40
        s.server_send(
            b"HTTP/1.1 " + status + f"\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body
        )
        s.close()
        timed += [(0.2 * i + 0.002 * j, pkt) for j, pkt in enumerate(s.packets)]
    names = ["intranet.corp", "mail.corp", "files.corp", "example.com", "updates.example.org"]
    for i, name in enumerate(names):
        client = clients[i % 2]
        qid = 0x3000 + i
        q = (
            Ether(src=CLIENT_MAC, dst=SERVER_MAC)
            / IP(src=client, dst=dns_server)
            / UDP(sport=43000 + i, dport=53)
            / DNS(id=qid, rd=1, qd=DNSQR(qname=name))
        )
        timed.append((0.1 + 0.3 * i, q))
        if problems and i == 4:
            continue  # no answer
        rcode = 2 if problems and i in (1, 2, 3) else 0  # SERVFAIL
        an = None if rcode else DNSRR(rrname=name, rdata=f"10.0.1.{i + 10}")
        r = (
            Ether(src=SERVER_MAC, dst=CLIENT_MAC)
            / IP(src=dns_server, dst=client)
            / UDP(sport=53, dport=43000 + i)
            / DNS(id=qid, qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=name), an=an)
        )
        timed.append((0.1 + 0.3 * i + 0.004, r))
    for i in range(3):
        q = (
            Ether(src=CLIENT_MAC, dst=SERVER_MAC)
            / IP(src=clients[0], dst=gateway)
            / ICMP(type=8, id=9, seq=i + 1)
            / Raw(b"ping")
        )
        timed.append((1.6 + 0.1 * i, q))
        if not problems:
            r = (
                Ether(src=SERVER_MAC, dst=CLIENT_MAC)
                / IP(src=gateway, dst=clients[0])
                / ICMP(type=0, id=9, seq=i + 1)
                / Raw(b"ping")
            )
            timed.append((1.6 + 0.1 * i + 0.002, r))
    if problems:
        scanner = "10.0.0.66"
        for i, port in enumerate([22, 23, 445, 3389, 5900]):
            syn = (
                Ether(src=CLIENT_MAC, dst=SERVER_MAC)
                / IP(src=scanner, dst=web)
                / TCP(sport=60000 + i, dport=port, flags="S", seq=777)
            )
            rst = (
                Ether(src=SERVER_MAC, dst=CLIENT_MAC)
                / IP(src=web, dst=scanner)
                / TCP(sport=port, dport=60000 + i, flags="RA", seq=0, ack=778)
            )
            timed += [(1.0 + 0.05 * i, syn), (1.0 + 0.05 * i + 0.001, rst)]
    timed.sort(key=lambda tp: tp[0])
    for at, pkt in timed:
        pkt.time = BASE_TS + at
    return [pkt for _, pkt in timed]


def hex_dump(data: bytes, ascii_column: bool = True) -> str:
    """One packet as Wireshark's *Copy as Hex Dump* writes it: 4-digit hex
    offsets, 16 bytes per line and, optionally, the ASCII column."""
    lines = []
    for at in range(0, len(data), 16):
        chunk = data[at : at + 16]
        line = f"{at:04x}  " + " ".join(f"{b:02x}" for b in chunk)
        if ascii_column:
            text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            line = f"{line:<54}   {text}"
        lines.append(line.rstrip())
    return "\n".join(lines) + "\n"


SIP_PAYLOADS = [
    (
        b"OPTIONS sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1:5060\r\n"
        b"From: <sip:alice@example.com>;tag=1\r\nTo: <sip:bob@example.com>\r\n"
        b"Call-ID: hexdump-1@10.0.0.1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
    ),
    (
        b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 10.0.0.1:5060\r\n"
        b"From: <sip:alice@example.com>;tag=1\r\nTo: <sip:bob@example.com>;tag=2\r\n"
        b"Call-ID: hexdump-1@10.0.0.1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
    ),
]


def hexdump_fixtures() -> None:
    """Hex dumps for Import from Hex Dump (text2pcap): the frames of http.pcap
    as Wireshark copies them; two SIP payloads without headers (imported with a
    dummy UDP header); raw IPv4 packets each after a time of day."""
    folder = HERE / "hexdump"
    folder.mkdir(exist_ok=True)
    frames = [bytes(pkt) for pkt in http_packets()]
    (folder / "frames.txt").write_text("\n".join(hex_dump(f) for f in frames), newline="\n")
    (folder / "sip-payload.txt").write_text(
        "\n".join(hex_dump(p, ascii_column=False) for p in SIP_PAYLOADS), newline="\n"
    )
    ips = [bytes(pkt[IP]) for pkt in dns_packets()[:2]]
    timed = "".join(
        f"10:15:{14 + i:02d}.25\n{hex_dump(ip, ascii_column=False)}" for i, ip in enumerate(ips)
    )
    (folder / "timed-ipv4.txt").write_text(timed, newline="\n")


def mixed_packets() -> list[Packet]:
    extra: list[Packet] = [
        Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, hwsrc=CLIENT_MAC, psrc="192.168.1.10", pdst="192.168.1.1"),
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="192.168.1.10", dst="192.168.1.1")
        / ICMP(type=8, id=1, seq=1)
        / Raw(b"ping"),
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src="192.168.1.1", dst="192.168.1.10")
        / ICMP(type=0, id=1, seq=1)
        / Raw(b"ping"),
    ]
    pkts = extra + dns_packets() + http_packets() + udp_custom_packets()
    return _stamp(pkts, step=0.002)


def large_capture(count: int, dest: Path) -> None:
    """Write a big synthetic capture for manual performance testing (not committed).

    Builds a few hundred template packets with scapy, then writes pcap records
    directly so that millions of packets take seconds rather than minutes.
    """
    rng = random.Random(42)
    templates: list[bytes] = []
    for i in range(512):
        src = f"10.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(1, 255)}"
        if i % 3 == 0:
            pkt = (
                Ether()
                / IP(src=src, dst="10.0.0.1")
                / UDP(sport=rng.randrange(1024, 65535), dport=53)
                / DNS(id=i, qd=DNSQR(qname=f"host{i}.example.com"))
            )
        else:
            pkt = (
                Ether()
                / IP(src=src, dst="10.0.0.1")
                / TCP(sport=rng.randrange(1024, 65535), dport=80, flags="PA", seq=i)
                / Raw(b"x" * rng.randrange(0, 200))
            )
        templates.append(bytes(pkt))
    with dest.open("wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i in range(count):
            data = templates[i % len(templates)]
            sec, usec = divmod(int(BASE_TS) * 1_000_000 + i * 100, 1_000_000)
            fh.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
            fh.write(data)


# --------------------------------------------------------------------------- other formats

FORMATS = HERE / "formats"
BT_EPOCH_US = 0x00DCDDB30F2F8000  # btsnoop timestamps count microseconds from 0 AD


def _records(packets: list[Packet]) -> list[tuple[float, bytes]]:
    return [(float(p.time), bytes(p)) for p in packets]


def _xxh32(data: bytes, seed: int = 0) -> int:
    """xxHash32 (needed for the LZ4 frame header checksum)."""
    p1, p2, p3, p4, p5 = 2654435761, 2246822519, 3266489917, 668265263, 374761393
    mask = 0xFFFFFFFF

    def rotl(x: int, r: int) -> int:
        return ((x << r) | (x >> (32 - r))) & mask

    i, n = 0, len(data)
    if n >= 16:
        v = [(seed + p1 + p2) & mask, (seed + p2) & mask, seed, (seed - p1) & mask]
        while i + 16 <= n:
            for k in range(4):
                lane = struct.unpack_from("<I", data, i + 4 * k)[0]
                v[k] = (rotl((v[k] + lane * p2) & mask, 13) * p1) & mask
            i += 16
        h = (rotl(v[0], 1) + rotl(v[1], 7) + rotl(v[2], 12) + rotl(v[3], 18)) & mask
    else:
        h = (seed + p5) & mask
    h = (h + n) & mask
    while i + 4 <= n:
        h = (rotl((h + struct.unpack_from("<I", data, i)[0] * p3) & mask, 17) * p4) & mask
        i += 4
    while i < n:
        h = (rotl((h + data[i] * p5) & mask, 11) * p1) & mask
        i += 1
    h ^= h >> 15
    h = (h * p2) & mask
    h ^= h >> 13
    h = (h * p3) & mask
    return h ^ (h >> 16)


def lz4_frame(data: bytes) -> bytes:
    """An LZ4 frame holding ``data`` in stored (uncompressed) blocks: valid for any
    LZ4 reader without needing an LZ4 compressor here."""
    descriptor = bytes([0x60, 0x40])  # version 1, independent blocks; 64 KiB max block
    out = bytearray(struct.pack("<I", 0x184D2204) + descriptor)
    out.append((_xxh32(descriptor) >> 8) & 0xFF)
    for i in range(0, len(data), 64 * 1024):
        block = data[i : i + 64 * 1024]
        out += struct.pack("<I", 0x80000000 | len(block)) + block  # high bit: stored
    out += struct.pack("<I", 0)  # end mark
    return bytes(out)


def snoop_file(records: list[tuple[float, bytes]]) -> bytes:
    """RFC 1761 snoop, Ethernet."""
    out = bytearray(b"snoop\0\0\0" + struct.pack(">II", 2, 4))
    for ts, data in records:
        pad = -len(data) % 4
        sec, usec = divmod(round(ts * 1_000_000), 1_000_000)
        out += struct.pack(">IIIIII", len(data), len(data), 24 + len(data) + pad, 0, sec, usec)
        out += data + b"\0" * pad
    return bytes(out)


def erf_file(records: list[tuple[float, bytes]]) -> bytes:
    """Endace ERF, type 2 (Ethernet) records with the 2-byte Ethernet pad."""
    out = bytearray()
    for ts, data in records:
        sec, frac = divmod(round(ts * 2**32), 2**32)
        body = b"\0\0" + data
        pad = -(16 + len(body)) % 8
        rlen = 16 + len(body) + pad
        out += struct.pack("<Q", (sec << 32) | frac)
        out += struct.pack(">BBHHH", 2, 0x04, rlen, 0, len(data))  # 0x04: varying length
        out += body + b"\0" * pad
    return bytes(out)


# HCI traffic for the Bluetooth logs: Reset and Read BD_ADDR, each with its
# Command Complete event. (H4 packet type, HCI bytes.)
HCI_PACKETS: list[tuple[int, bytes]] = [
    (0x01, bytes.fromhex("030c00")),
    (0x04, bytes.fromhex("0e0401030c00")),
    (0x01, bytes.fromhex("091000")),
    (0x04, bytes.fromhex("0e0a01091000665544332211")),
]


def packetlogger_file() -> bytes:
    """Apple PacketLogger (.pklg): length, timestamp, type (0 command, 1 event), HCI."""
    out = bytearray()
    for i, (h4, hci) in enumerate(HCI_PACKETS):
        kind = 0x00 if h4 == 0x01 else 0x01
        out += struct.pack(">IIIB", 9 + len(hci), int(BASE_TS), i * 1000, kind) + hci
    return bytes(out)


def btsnoop_file() -> bytes:
    """btsnoop version 1, HCI UART (H4) datalink 1002."""
    out = bytearray(b"btsnoop\0" + struct.pack(">II", 1, 1002))
    for i, (h4, hci) in enumerate(HCI_PACKETS):
        data = bytes([h4]) + hci
        flags = 0b10 | (0 if h4 == 0x01 else 1)  # command/event; sent/received
        ts = BT_EPOCH_US + int(BASE_TS) * 1_000_000 + i * 1000
        out += struct.pack(">IIIIq", len(data), len(data), flags, 0, ts) + data
    return bytes(out)


def zstd_compress(data: bytes) -> bytes:
    """``compression.zstd`` is optional in CPython builds: Pythons compiled without
    the libzstd headers (e.g. pyenv without libzstd-dev) lack ``_zstd``, so it is
    imported only for the .zst fixtures, and ``--large`` works without it. It is
    new in Python 3.14 (the backend supports 3.12, the fixtures need 3.14)."""
    if sys.version_info < (3, 14):
        raise SystemExit("The .zst fixtures need Python 3.14 (compression.zstd): use 'uv run'.")
    try:
        from compression import zstd  # noqa: PLC0415 - optional module, see above
    except ImportError as exc:
        raise SystemExit(
            f"This Python has no zstd support ({exc}), which the .zst fixtures need. "
            "Rebuild it with the libzstd headers (e.g. 'sudo apt install libzstd-dev', "
            "then 'pyenv install --force 3.14'), or use a uv-managed Python: "
            "'uv venv --python 3.14 --python-preference only-managed' then 'uv sync'."
        ) from exc
    return zstd.compress(data)


# Comments of comments.pcapng (frame → its comments; frame 5 has two).
PACKET_COMMENTS = {
    2: ["SYN-ACK from the server"],
    4: ["The request\nsecond line\twith a tab"],
    5: ["first of two", "second of two"],
}


def comments_pcapng(
    records: list[tuple[float, bytes]],
    comments: dict[int, list[str]],
    key_log: bytes = b"",
) -> bytes:
    """A little-endian pcapng (Ethernet) whose packets carry ``comments``
    (opt_comment options of Enhanced Packet Blocks), written by hand. A TLS
    key log in ``key_log`` goes into a Decryption Secrets Block before them."""

    def block(kind: int, body: bytes) -> bytes:
        body += b"\0" * (-len(body) % 4)
        total = len(body) + 12
        return struct.pack("<II", kind, total) + body + struct.pack("<I", total)

    def option(code: int, value: bytes) -> bytes:
        return struct.pack("<HH", code, len(value)) + value + b"\0" * (-len(value) % 4)

    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack("<HHI", 1, 0, 65535))
    if key_log:
        out += block(10, struct.pack("<II", 0x544C534B, len(key_log)) + key_log)  # "TLSK"
    for n, (ts, data) in enumerate(records, start=1):
        micros = round(ts * 1_000_000)
        body = struct.pack("<IIIII", 0, micros >> 32, micros & 0xFFFFFFFF, len(data), len(data))
        body += data + b"\0" * (-len(data) % 4)
        texts = comments.get(n, [])
        if texts:
            body += b"".join(option(1, t.encode()) for t in texts) + option(0, b"")
        out += block(6, body)
    return out


def format_fixtures() -> None:
    """Every extra file type the viewer registers for, from the base fixtures."""
    FORMATS.mkdir(exist_ok=True)
    pcap = (HERE / "http.pcap").read_bytes()
    pcapng = (HERE / "mixed.pcapng").read_bytes()
    files = {
        # Default editor: unambiguous capture files.
        "http.pcap.gz": gzip.compress(pcap, mtime=0),
        "mixed.pcapng.gz": gzip.compress(pcapng, mtime=0),
        "http.pcap.zst": zstd_compress(pcap),
        "mixed.pcapng.zst": zstd_compress(pcapng),
        "http.pcap.lz4": lz4_frame(pcap),
        "mixed.pcapng.lz4": lz4_frame(pcapng),
        "mixed.ntar": pcapng,  # pcapng's old extension
        "trace.pcap1": (HERE / "dns.pcap").read_bytes(),  # tcpdump -C rotation
        "http.snoop": snoop_file(_records(http_packets())),
        "http.erf": erf_file(_records(http_packets())),
        "hci.pklg": packetlogger_file(),
        "hci.btsnoop": btsnoop_file(),
        # "Reopen Editor With…" only: generic extensions that are sometimes captures.
        "capture.1": pcap,
        "capture.log": pcapng,
        "capture.dmp": pcap,
        "capture.trc": snoop_file(_records(http_packets())),
        # A raw ASN.1 BER file: tshark reads it as one frame. SEQUENCE { 5, "hello" }.
        "capture.ber": bytes.fromhex("300a020105040568656c6c6f"),
        # Not a capture at all: exercises the "unsupported format" message.
        "notes.log": b"2023-11-14 22:13:20 INFO this is a text log, not a capture\n",
    }
    for name, data in files.items():
        (FORMATS / name).write_bytes(data)


TLS_PSK = bytes.fromhex("00112233445566778899aabbccddeeff")


def _psk_context(server: bool, keylog: Path | None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("PSK-AES128-GCM-SHA256")
    if server:
        ctx.set_psk_server_callback(lambda _identity: TLS_PSK)
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_psk_client_callback(lambda _hint: ("pcap-viewer", TLS_PSK))
        ctx.keylog_filename = str(keylog)
    return ctx


def tls_keylog_capture(dest: Path, keylog: Path) -> None:
    """A TLS 1.2 session carrying one HTTP request and response on port 443,
    plus the key log file (SSLKEYLOGFILE format) that decrypts it.

    Not committed: TLS randoms differ on every run. Both ends run in memory
    (``ssl.MemoryBIO``) with a pre-shared key, so no certificate is needed;
    the records they exchange become TCP segments.
    """
    keylog.unlink(missing_ok=True)
    c_in, c_out, s_in, s_out = (ssl.MemoryBIO() for _ in range(4))
    client = _psk_context(False, keylog).wrap_bio(c_in, c_out, server_side=False)
    server = _psk_context(True, None).wrap_bio(s_in, s_out, server_side=True)
    session = _TcpSession("192.168.1.10", "93.184.216.34", 50443, 443)
    session.handshake()

    def pump() -> None:
        if data := c_out.read():
            session.client_send(data)
            s_in.write(data)
        if data := s_out.read():
            session.server_send(data)
            c_in.write(data)

    done = [False, False]
    for _ in range(20):
        for i, end in enumerate((client, server)):
            if not done[i]:
                try:
                    end.do_handshake()
                    done[i] = True
                except ssl.SSLWantReadError:
                    pass
        pump()
        if all(done):
            break
    client.write(b"GET /secret.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
    pump()
    server.read(4096)
    body = b"<html>decrypted with the key log</html>"
    server.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n")
    server.write(f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
    pump()
    client.read(4096)
    session.close()
    wrpcap(str(dest), _stamp(session.packets))


# Decryption keys (PCAP: Decryption Keys…): a WEP network and an IPsec ESP
# pair of security associations, encrypted here so tshark can only read the
# inner packets with the keys below (test_decryption.py).
WEP_KEY = bytes.fromhex("0a1b2c3d4e")  # 40-bit
WEP_BSSID = "02:00:00:00:0a:01"
ESP_SAS = (
    # (source, destination, SPI, AES-128 key + 4-byte nonce for AES-CTR [RFC3686])
    ("10.8.0.1", "10.8.0.2", 0x00001001, bytes.fromhex("00112233445566778899aabbccddeeff01020304")),
    ("10.8.0.2", "10.8.0.1", 0x00002002, bytes.fromhex("ffeeddccbbaa99887766554433221100a1a2a3a4")),
)


def _rc4(key: bytes, data: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(byte ^ s[(s[i] + s[j]) % 256])
    return bytes(out)


def wep_packets() -> list[Packet]:
    """802.11 data frames of an ICMP echo, WEP-encrypted with WEP_KEY (RC4 of
    IV + key over the LLC/SNAP payload and its CRC-32)."""
    station = "02:00:00:00:0a:02"
    out: list[Packet] = []
    for i in range(4):
        request = i % 2 == 0
        inner = bytes(
            LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
            / SNAP(OUI=0, code=0x0800)
            / IP(src="192.168.10.2" if request else "192.168.10.1",
                 dst="192.168.10.1" if request else "192.168.10.2")
            / ICMP(type=8 if request else 0, id=7, seq=i // 2 + 1)
            / Raw(b"wep secret payload")
        )  # fmt: skip
        iv = bytes([0x10 + i, 0x20, 0x30])
        icv = struct.pack("<I", zlib.crc32(inner) & 0xFFFFFFFF)
        body = iv + b"\x00" + _rc4(iv + WEP_KEY, inner + icv)
        header = (
            Dot11(type=2, subtype=0, FCfield=0x41, addr1=WEP_BSSID, addr2=station,
                  addr3="02:00:00:00:0a:03", SC=i << 4)
            if request
            else Dot11(type=2, subtype=0, FCfield=0x42, addr1=station,
                       addr2=WEP_BSSID, addr3="02:00:00:00:0a:03", SC=i << 4)
        )  # fmt: skip
        out.append(header / Raw(body))
    return _stamp(out)


def _aes_ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-128-CTR as ESP uses it (RFC 3686): the key's last 4 bytes are the
    nonce, the counter block is nonce + IV + a 32-bit counter from 1."""
    aes = quic.Aes128(key[:16])
    stream = b"".join(
        aes.encrypt(key[16:] + iv + struct.pack(">I", n + 1)) for n in range(len(data) // 16 + 1)
    )
    return bytes(a ^ b for a, b in zip(data, stream, strict=False))


def esp_packets() -> list[Packet]:
    """ICMP echoes in transport-mode ESP, one SA per direction (ESP_SAS), with
    AES-CTR encryption and no authentication."""
    out: list[Packet] = []
    for i in range(4):
        src, dst, spi, key = ESP_SAS[i % 2]
        icmp = bytes(ICMP(type=8 if i % 2 == 0 else 0, id=9, seq=i // 2 + 1) / Raw(b"esp secret"))
        pad = (-(len(icmp) + 2)) % 4
        plain = icmp + bytes(range(1, pad + 1)) + bytes([pad, 1])  # next header 1: ICMP
        iv = struct.pack(">Q", 0x1000 + i)
        payload = struct.pack(">II", spi, i // 2 + 1) + iv + _aes_ctr(key, iv, plain)
        out.append(
            Ether(src=CLIENT_MAC if i % 2 == 0 else SERVER_MAC,
                  dst=SERVER_MAC if i % 2 == 0 else CLIENT_MAC)
            / IP(src=src, dst=dst, proto=50, id=i + 1)
            / Raw(payload)
        )  # fmt: skip
    return _stamp(out)


# GeoIP (pcapViewer.geoip.databaseFolders): test databases in MaxMind's format
# for the public addresses of mixed.pcapng and http.pcap (made-up records).
GEOIP_CITY = {
    "93.184.216.0/24": {
        "city": {"names": {"en": "Norwell"}},
        "country": {"iso_code": "US", "names": {"en": "United States"}},
        "location": {"latitude": 42.1508, "longitude": -70.8228},
    },
    "8.8.8.0/24": {
        "city": {"names": {"en": "Mountain View"}},
        "country": {"iso_code": "US", "names": {"en": "United States"}},
        "location": {"latitude": 37.386, "longitude": -122.0838},
    },
    "2001:db8:10::/48": {
        "city": {"names": {"en": "Berlin"}},
        "country": {"iso_code": "DE", "names": {"en": "Germany"}},
        "location": {"latitude": 52.52, "longitude": 13.405},
    },
}
GEOIP_ASN = {
    "93.184.216.0/24": {
        "autonomous_system_number": 15133,
        "autonomous_system_organization": "Edgecast",
    },
    "8.8.8.0/24": {
        "autonomous_system_number": 15169,
        "autonomous_system_organization": "Google LLC",
    },
}


def geoip_fixtures() -> None:
    folder = HERE / "geoip"
    folder.mkdir(exist_ok=True)
    (folder / "PCAP-Lens-Test-City.mmdb").write_bytes(mmdb.write_mmdb(GEOIP_CITY, "GeoLite2-City"))
    (folder / "PCAP-Lens-Test-ASN.mmdb").write_bytes(mmdb.write_mmdb(GEOIP_ASN, "GeoLite2-ASN"))


def _sctp(src: str, dst: str, tag: int, chunk: Packet) -> Packet:
    return (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=src, dst=dst)
        / SCTP(sport=2905, dport=2905, tag=tag)
        / chunk
    )


def network_packets() -> list[Packet]:
    """Statistics → IPv4/IPv6, UDP Multicast Streams, Resolved Addresses and SCTP:
    two multicast streams (the first bursting: 60 packets in 60 ms, over the
    50-packet alarm), an SCTP association (handshake, three DATA/SACK pairs,
    a heartbeat), IPv6 TCP and UDP, and a DNS answer naming an address."""
    out: list[tuple[float, Packet]] = []
    t0 = BASE_TS
    for i in range(80):  # 60 in the first 60 ms, then one every 50 ms
        t = t0 + (i * 0.001 if i < 60 else 0.06 + (i - 59) * 0.05)
        out.append((t, Ether(src=CLIENT_MAC, dst="01:00:5e:01:01:01")
                    / IP(src="10.1.1.5", dst="239.1.1.1", ttl=8)
                    / UDP(sport=4000, dport=5000) / Raw(bytes(200))))  # fmt: skip
    second = (
        Ether(src=SERVER_MAC, dst="01:00:5e:02:02:02")
        / IP(src="10.1.1.6", dst="239.2.2.2", ttl=8)
        / UDP(sport=4001, dport=5001)
        / Raw(bytes(50))
    )
    out += [(t0 + 0.5 + i * 0.1, second.copy()) for i in range(10)]
    c, s = "10.2.0.1", "10.2.0.2"
    sctp = [
        _sctp(c, s, 0, SCTPChunkInit(init_tag=0x1111, a_rwnd=65535, n_out_streams=2,
                                      n_in_streams=2, init_tsn=1)),
        _sctp(s, c, 0x1111, SCTPChunkInitAck(init_tag=0x2222, a_rwnd=65535, n_out_streams=2,
              n_in_streams=2, init_tsn=100, params=[SCTPChunkParamStateCookie(cookie=b"cookie")])),
        _sctp(c, s, 0x2222, SCTPChunkCookieEcho(cookie=b"cookie")),
        _sctp(s, c, 0x1111, SCTPChunkCookieAck()),
    ]  # fmt: skip
    for i in range(3):
        data = SCTPChunkData(tsn=1 + i, stream_id=0, stream_seq=i, proto_id=3, data=b"M3UA payload")
        sctp.append(_sctp(c, s, 0x2222, data))
        sctp.append(_sctp(s, c, 0x1111, SCTPChunkSACK(cumul_tsn_ack=1 + i, a_rwnd=65535)))
    sctp += [
        _sctp(c, s, 0x2222, SCTPChunkHeartbeatReq()),
        _sctp(s, c, 0x1111, SCTPChunkHeartbeatAck()),
    ]
    out += [(t0 + 1.0 + i * 0.01, pkt) for i, pkt in enumerate(sctp)]
    v6c, v6s = "2001:db8:1::10", "2001:db8:10::1"
    to_server = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IPv6(src=v6c, dst=v6s)
    out += [
        (t0 + 1.5 + i * 0.01, to_server / TCP(sport=51000, dport=443, flags="S", seq=i))
        for i in range(3)
    ]
    out.append((t0 + 1.6, to_server / UDP(sport=51001, dport=123) / Raw(bytes(48))))
    answer = DNSRR(rrname="ntp.example.org", type="A", rdata="10.1.1.5", ttl=60)
    out.append(
        (
            t0 + 1.7,
            Ether(src=SERVER_MAC, dst=CLIENT_MAC)
            / IP(src="192.168.1.1", dst="192.168.1.10")
            / UDP(sport=53, dport=40100)
            / DNS(id=7, qr=1, aa=1, qd=DNSQR(qname="ntp.example.org", qtype="A"), an=answer),
        )
    )
    out.sort(key=lambda item: item[0])
    for t, pkt in out:
        pkt.time = t
    return [pkt for _, pkt in out]


def sixlowpan_packets() -> list[Packet]:
    """An IEEE 802.15.4 frame carrying UDP in a 6LoWPAN-compressed IPv6 header:
    tshark shows the IPv6, UDP and data trees on a second byte source
    ("Decompressed 6LoWPAN IPHC") with no reassembly item before them."""
    frame = Dot15d4FCS(
        fcf_frametype=1, fcf_srcaddrmode=3, fcf_destaddrmode=3, fcf_panidcompress=1, seqnum=1
    ) / Dot15d4Data(
        dest_panid=0xABCD, dest_addr=0x1122334455667788, src_addr=0x0202000240021002
    )  # fmt: skip
    iphc = LoWPAN_IPHC(tf=3, nh=0, nhField=17, hlim=2, sam=3, dam=3)
    return _stamp([frame / iphc / UDP(sport=7777, dport=7777) / Raw(b"hello 6lowpan")])


def radius_eap_packets() -> list[Packet]:
    """A RADIUS Access-Request whose EAP Response/Identity is split over two
    EAP-Message attributes: tshark shows EAP inside RADIUS with its fields on
    a "Reassembled EAP" buffer (a nested protocol on another byte source)."""
    identity = b"alice@example.org/" + b"x" * 300
    eap = struct.pack("!BBHB", 2, 7, 5 + len(identity), 1) + identity
    attrs = bytes([1, 7]) + b"alice"  # User-Name
    attrs += b"".join(bytes([79, 2 + len(part)]) + part for part in (eap[:253], eap[253:]))
    attrs += bytes([80, 18]) + bytes(16)  # Message-Authenticator
    radius = struct.pack("!BBH", 1, 42, 20 + len(attrs)) + bytes(range(16)) + attrs
    udp = UDP(sport=40001, dport=1812) / Raw(radius)
    return _stamp([Ether() / IP(src="10.0.0.5", dst="10.0.0.1") / udp])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--large", nargs=2, metavar=("COUNT", "DEST"))
    parser.add_argument("--tls-keylog", nargs=2, metavar=("DEST", "KEYLOG"))
    args = parser.parse_args()
    if args.large:
        large_capture(int(args.large[0]), Path(args.large[1]))
        return
    if args.tls_keylog:
        tls_keylog_capture(Path(args.tls_keylog[0]), Path(args.tls_keylog[1]))
        return
    wrpcap(str(HERE / "http.pcap"), http_packets())
    wrpcap(str(HERE / "dns.pcap"), dns_packets())
    wrpcap(str(HERE / "udp_custom.pcap"), udp_custom_packets())
    wrpcap(str(HERE / "tls.pcap"), tls_packets())
    wrpcapng(str(HERE / "mixed.pcapng"), mixed_packets())
    # The walkthrough's sample capture (PCAP: Open Sample Capture) is the same file.
    shutil.copyfile(HERE / "mixed.pcapng", HERE.parents[1] / "media" / "sample.pcapng")
    wrpcap(str(HERE / "objects.pcap"), objects_packets())
    wrpcap(str(HERE / "voip.pcap"), voip_packets())
    wrpcap(str(HERE / "voip-calls.pcap"), voip_calls_packets())
    wrpcap(str(HERE / "voip-media.pcap"), voip_media_packets())
    wrpcap(str(HERE / "voip-other.pcap"), voip_other_packets())
    wrpcap(str(HERE / "services.pcap"), services_packets())
    wrpcap(str(HERE / "credentials.pcap"), credentials_packets())
    wrpcap(str(HERE / "wep.pcap"), wep_packets())
    wrpcap(str(HERE / "esp.pcap"), esp_packets())
    wrpcap(str(HERE / "network.pcap"), network_packets())
    wrpcap(str(HERE / "sixlowpan.pcap"), sixlowpan_packets())
    wrpcap(str(HERE / "radius-eap.pcap"), radius_eap_packets())
    wrpcap(str(HERE / "office-before.pcap"), office_packets(problems=False))
    wrpcap(str(HERE / "office-after.pcap"), office_packets(problems=True))
    wrpcap(str(HERE / "replay.pcap"), replay_packets())
    wrpcap(str(HERE / "sessions.pcap"), sessions_packets())
    geoip_fixtures()
    hexdump_fixtures()
    (HERE / "comments.pcapng").write_bytes(
        comments_pcapng(_records(http_packets()), PACKET_COMMENTS)
    )
    (HERE / "streams.pcapng").write_bytes(
        comments_pcapng(_records(streams_packets()), {}, key_log=quic.KEYLOG)
    )
    # A truncated file to exercise malformed-capture handling.
    data = (HERE / "http.pcap").read_bytes()
    (HERE / "truncated.pcap").write_bytes(data[: len(data) - 30])
    format_fixtures()
    print(f"fixtures written to {HERE}")


if __name__ == "__main__":
    main()
