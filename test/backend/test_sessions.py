"""The HTTP, DNS and TLS session tables (sessions.py, ``stats`` kinds) and HTTP bodies."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from pcap_backend import sessions
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import InvalidParamsError, RequestContext

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
sys.path.insert(0, str(FIXTURES))
import generate  # noqa: E402 - the fixtures' generator (the PNG it wrote)


def test_names() -> None:
    assert sessions.dns_type(28) == "AAAA" and sessions.dns_type(4242) == "TYPE4242"
    assert sessions.tls_version(0x0304) == "TLS 1.3" and sessions.tls_version(0x7A7A) == ""
    assert sessions.tls_version(0x7F17) == "0x7f17"
    assert sessions.cipher_suite(0x1302) == "TLS_AES_256_GCM_SHA384"
    assert sessions.cipher_suite(0xFFFF) == "0xffff"


def test_lines_tshark_cut_short_are_skipped() -> None:
    table = sessions.http_requests(["", "not a row", "4\t0.1"])
    assert table.rows == [] and table.extra["summary"] == {"requests": 0, "unanswered": 0}


def _open(service: PcapService, name: str) -> None:
    service.open({"path": str(FIXTURES / name)}, RequestContext())


def _table(service: PcapService, kind: str, **params: Any) -> dict[str, Any]:
    return service.stats({"kind": kind, **params}, RequestContext())


def _cell(table: dict[str, Any], row: dict[str, Any], label: str) -> Any:
    return row["cells"][[c["label"] for c in table["columns"]].index(label)]


def _matches(service: PcapService, flt: str) -> int:
    return int(service.count_matches({"filter": flt}, RequestContext())["count"])


@pytest.mark.tshark
def test_http_requests(service: PcapService) -> None:
    _open(service, "sessions.pcap")
    table = _table(service, "http_requests")
    assert table["summary"] == {"requests": 7, "unanswered": 1}
    times = [_cell(table, r, "Response Time (ms)") for r in table["rows"]]
    assert times == [30.0, 12.0, 250.0, 5.0, None, 20.0, 20.0]
    for row in table["rows"]:
        assert _matches(service, row["filter"]) == (2 if row["response"] else 1)
        assert row["frame"] == _cell(table, row, "No.")
    logo = table["rows"][1]
    assert logo["response"] == 10 and logo["contentType"] == "image/png"
    assert logo["label"] == "GET www.example.com/logo.png"
    assert _cell(table, logo, "Client") == "192.168.1.10:51100"


@pytest.mark.tshark
def test_pipelined_http_requests(service: PcapService) -> None:
    """Two requests in one packet, two responses in one: tshark names only the
    first response's request (http.request_in), so they pair by stream order."""
    _open(service, "sessions.pcap")
    table = _table(service, "http_requests")
    pipelined = [r for r in table["rows"] if _cell(table, r, "Host") == "pipe.example.com"]
    assert [(_cell(table, r, "Path"), _cell(table, r, "Status")) for r in pipelined] == [
        ("/a.txt", 200),
        ("/b.txt", 404),
    ]
    assert pipelined[0]["frame"] == pipelined[1]["frame"]
    assert pipelined[0]["response"] == pipelined[1]["response"]


def _tls_line(frame: int, kinds: str, alpn: str = "", **cells: str) -> str:
    values = {
        "frame.number": str(frame), "tcp.stream": "0", "ip.src": "10.0.0.1",
        "ip.dst": "10.0.0.2", "tcp.dstport": "443", "tls.handshake.type": kinds,
        "tls.handshake.extensions_alpn_str": alpn, **cells,
    }  # fmt: skip
    return "\t".join(values.get(name, "") for name in sessions.TLS_FIELDS)


def test_tls13_alpn_comes_from_the_encrypted_extensions() -> None:
    """TLS 1.3 sends the chosen ALPN in EncryptedExtensions (type 8), which
    tshark shows when it can decrypt the handshake; the ClientHello's is an offer."""
    hello = _tls_line(1, "1", "h2\x1ehttp/1.1", **{"tls.handshake.extensions_server_name": "a"})
    server = _tls_line(2, "2", **{"tls.handshake.extensions.supported_version": "0x0304"})
    extensions = _tls_line(3, "8", "h2")
    table = sessions.tls_servers([hello, server, extensions])
    columns = [c["label"] for c in table.columns]
    row = table.rows[0]["cells"]
    assert row[columns.index("Versions")] == "TLS 1.3"
    assert row[columns.index("ALPN")] == "h2"
    assert sessions.tls_servers([hello, server]).rows[0]["cells"][columns.index("ALPN")] == ""


@pytest.mark.tshark
def test_dns_queries(service: PcapService) -> None:
    _open(service, "sessions.pcap")
    table = _table(service, "dns_queries")
    assert table["summary"] == {"queries": 5, "unanswered": 1, "failed": 1}
    times = [_cell(table, r, "Response Time (ms)") for r in table["rows"]]
    assert times == [12.0, 8.0, 15.0, 20.0, None]
    assert [_cell(table, r, "ID") for r in table["rows"]][:2] == ["0x3000", "0x3001"]
    for row in table["rows"]:
        assert _matches(service, row["filter"]) in (1, 2)


@pytest.mark.tshark
def test_tls_servers(service: PcapService) -> None:
    _open(service, "sessions.pcap")
    table = _table(service, "tls_servers")
    assert table["summary"] == {"servers": 2, "connections": 3, "unanswered": 1}
    first = table["rows"][0]
    assert _cell(table, first, "Cipher Suites") == (
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_AES_128_GCM_SHA256"
    )
    assert first["frame"] == 40, "the first ClientHello"
    assert _matches(service, first["filter"]) == 14, "both connections, every packet"
    assert _cell(table, table["rows"][1], "ALPN") == "", "what servers chose, not offers"


@pytest.mark.tshark
def test_tls_over_quic(service: PcapService) -> None:
    """streams.pcapng's QUIC connection: the handshake inside QUIC's Initials."""
    _open(service, "streams.pcapng")
    table = _table(service, "tls_servers")
    quic = [r for r in table["rows"] if _cell(table, r, "Transport") == "QUIC"]
    assert len(quic) == 1
    assert _cell(table, quic[0], "Versions") == "TLS 1.3"
    assert quic[0]["filter"].startswith("quic.connection.number in {")
    assert _matches(service, quic[0]["filter"]) > 2


@pytest.mark.tshark
def test_ignored_packets_are_left_out(service: PcapService) -> None:
    _open(service, "sessions.pcap")
    service.ignore_packets({"frames": [36]}, RequestContext())  # lost.example.com
    table = _table(service, "dns_queries")
    assert [_cell(table, r, "Name") for r in table["rows"]][-1] == "missing.example.com"


@pytest.mark.tshark
def test_http_body(service: PcapService) -> None:
    _open(service, "sessions.pcap")
    png = service.http_body({"frame": 10}, RequestContext())
    assert bytes.fromhex(png["hex"]) == generate.SESSIONS_PNG
    assert png["size"] == len(generate.SESSIONS_PNG) and png["truncated"] is False
    assert bytes.fromhex(service.http_body({"frame": 14}, RequestContext())["hex"]) == (
        b'{"error":"boom"}'
    )
    assert service.http_body({"frame": 4}, RequestContext())["size"] == 0, "a GET has no body"
    with pytest.raises(InvalidParamsError, match="no packet 999"):
        service.http_body({"frame": 999}, RequestContext())


@pytest.mark.tshark
def test_http_body_decoded(service: PcapService) -> None:
    """objects.pcap's gzip + chunked answer comes back as the text it holds."""
    _open(service, "objects.pcap")
    body = bytes.fromhex(service.http_body({"frame": 10}, RequestContext())["hex"])
    assert body.startswith(b"report line 0\n")
