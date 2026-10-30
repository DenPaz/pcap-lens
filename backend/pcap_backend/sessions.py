"""Session tables: HTTP requests with their answers, DNS queries and TLS servers.

Each table is one tshark fields pass (``*_FILTER`` and ``*_FIELDS``) read here
into the statistics panel's table model (stats.Table): one row per request,
query or server rather than per packet, each with a display filter for its
packets and the packet it starts at.

* HTTP (HTTP/1.x): a response names its request (``http.request_in``) and
  how long it took (``http.time``), so one pass pairs them; a request no
  response names is "No response".
* DNS: a response names its query (``dns.response_to``) and the time
  (``dns.time``); answers are gathered per type (tshark has no one field
  for an answer's data).
* TLS: ClientHellos and ServerHellos per connection (TCP stream, or QUIC
  connection), grouped by server and the name the client asked for (SNI):
  versions, cipher suites and ALPN the servers chose, and connections whose
  ClientHello got no ServerHello. ALPN is what the servers chose.

tshark prints cipher suites, DNS types and reply codes as numbers; the names
below are the common ones (others show as numbers).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from .navigation import frame_ranges
from .stats import Table, _address_filter, _col

AGGREGATOR = "\x1e"

HTTP_FILTER = "http.request || http.response"
HTTP_FIELDS = (
    "frame.number", "frame.time_relative", "tcp.stream",
    "ip.src", "ipv6.src", "tcp.srcport", "ip.dst", "ipv6.dst", "tcp.dstport",
    "http.request.method", "http.host", "http.request.uri", "http.request.version",
    "http.response.code", "http.response.phrase", "http.content_type",
    "http.content_length", "http.time", "http.request_in",
)  # fmt: skip

DNS_FILTER = "dns"
DNS_FIELDS = (
    "frame.number", "frame.time_relative", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
    "dns.id", "dns.flags.response", "dns.qry.name", "dns.qry.type", "dns.flags.rcode",
    "dns.time", "dns.response_to",
    "dns.a", "dns.aaaa", "dns.cname", "dns.ptr.domain_name", "dns.mx.mail_exchange",
    "dns.ns", "dns.txt", "dns.srv.target",
)  # fmt: skip
# The answer fields above, by the record type they hold.
_DNS_ANSWERS = (
    ("dns.a", "A"),
    ("dns.aaaa", "AAAA"),
    ("dns.cname", "CNAME"),
    ("dns.ptr.domain_name", "PTR"),
    ("dns.mx.mail_exchange", "MX"),
    ("dns.ns", "NS"),
    ("dns.txt", "TXT"),
    ("dns.srv.target", "SRV"),
)

TLS_FILTER = "tls.handshake.type == 1 || tls.handshake.type == 2"
TLS_FIELDS = (
    "frame.number", "tcp.stream", "quic.connection.number",
    "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
    "tcp.dstport", "udp.dstport",
    "tls.handshake.type", "tls.handshake.extensions_server_name",
    "tls.handshake.extensions_alpn_str", "tls.handshake.version",
    "tls.handshake.extensions.supported_version", "tls.handshake.ciphersuite",
)  # fmt: skip

DNS_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 13: "HINFO", 15: "MX", 16: "TXT",
    28: "AAAA", 33: "SRV", 35: "NAPTR", 39: "DNAME", 41: "OPT", 43: "DS", 46: "RRSIG",
    47: "NSEC", 48: "DNSKEY", 50: "NSEC3", 52: "TLSA", 64: "SVCB", 65: "HTTPS",
    99: "SPF", 252: "AXFR", 255: "ANY", 257: "CAA",
}  # fmt: skip
DNS_RCODES = {
    0: "NoError", 1: "FormErr", 2: "ServFail", 3: "NXDomain", 4: "NotImp", 5: "Refused",
    6: "YXDomain", 7: "YXRRSet", 8: "NXRRSet", 9: "NotAuth", 10: "NotZone",
}  # fmt: skip
TLS_VERSIONS = {
    0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3",
}  # fmt: skip
CIPHER_SUITES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
}


def _int(text: str) -> int | None:
    """A decimal or 0x-prefixed number (tshark's -T fields), else None."""
    text = text.strip()
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def _float(text: str) -> float | None:
    try:
        return float(text)
    except ValueError:
        return None


def _first(text: str) -> str:
    """The first occurrence (the innermost header comes last; the first is
    the outer one, which is what a tunnel's packet list shows too)."""
    return text.split(AGGREGATOR, 1)[0]


def _each(text: str) -> list[str]:
    return [v for v in text.split(AGGREGATOR) if v]


def dns_type(value: int | None) -> str:
    return "" if value is None else DNS_TYPES.get(value, f"TYPE{value}")


def tls_version(value: int | None) -> str:
    if value is None:
        return ""
    if value & 0x0F0F == 0x0A0A:
        return ""  # GREASE (RFC 8701): a placeholder clients offer, never chosen
    return TLS_VERSIONS.get(value, f"0x{value:04x}")


def cipher_suite(value: int | None) -> str:
    return "" if value is None else CIPHER_SUITES.get(value, f"0x{value:04x}")


# A row filter listing more connections than this many characters names the
# server instead (a display filter has to fit on tshark's command line).
MAX_SET_FILTER = 2000


def _set_filter(name: str, values: Iterable[int]) -> str:
    """``name in {1..3,7}`` (tshark 4.2 refuses sets without commas)."""
    return f"{name} in {{{','.join(frame_ranges(values))}}}"


def _frames_filter(frames: Iterable[int]) -> str:
    return _set_filter("frame.number", frames)


def _endpoint(addr: str, port: str) -> str:
    if not port:
        return addr
    return f"[{addr}]:{port}" if ":" in addr else f"{addr}:{port}"


def _ms(seconds: float | None) -> float | None:
    return None if seconds is None else round(seconds * 1000, 3)


def _cells(line: str, count: int) -> list[str] | None:
    cells = line.rstrip("\r").split("\t")
    if len(cells) < count:
        return None
    return cells


# ---------------------------------------------------------------------- HTTP


def http_requests(lines: Iterable[str]) -> Table:
    """HTTP requests (rows in capture order) with their responses."""
    requests: dict[int, dict[str, Any]] = {}
    for line in lines:
        cells = _cells(line, len(HTTP_FIELDS))
        if cells is None or not cells[0].isdigit():
            continue
        c = dict(zip(HTTP_FIELDS, cells, strict=False))
        frame = int(c["frame.number"])
        method = _first(c["http.request.method"])
        if method:
            requests[frame] = {
                "frame": frame,
                "time": _float(c["frame.time_relative"]),
                "stream": _int(c["tcp.stream"]),
                "client": _endpoint(_first(c["ip.src"] or c["ipv6.src"]), _first(c["tcp.srcport"])),
                "server": _endpoint(_first(c["ip.dst"] or c["ipv6.dst"]), _first(c["tcp.dstport"])),
                "method": method,
                "host": _first(c["http.host"]),
                "uri": _first(c["http.request.uri"]),
                "version": _first(c["http.request.version"]),
            }
            continue
        request = _int(_first(c["http.request_in"]))
        code = _int(_first(c["http.response.code"]))
        if request is None or code is None or request not in requests:
            continue
        requests[request].update(
            response=frame,
            status=code,
            phrase=_first(c["http.response.phrase"]),
            contentType=_first(c["http.content_type"]).split(";", 1)[0].strip(),
            size=_int(_first(c["http.content_length"])),
            ms=_ms(_float(_first(c["http.time"]))),
        )
    table = Table(
        "http_requests",
        "HTTP Requests",
        [
            _col("frame", "No.", True),
            _col("time", "Time", True),
            _col("client", "Client"),
            _col("server", "Server"),
            _col("method", "Method"),
            _col("host", "Host"),
            _col("uri", "Path"),
            _col("status", "Status", True),
            _col("phrase", "Reason"),
            _col("type", "Content Type"),
            _col("size", "Size (bytes)", True),
            _col("ms", "Response Time (ms)", True),
        ],
    )
    answered = 0
    for r in sorted(requests.values(), key=lambda r: r["frame"]):
        response = r.get("response")
        answered += response is not None
        frames = [r["frame"], response] if response is not None else [r["frame"]]
        table.rows.append(
            {
                "cells": [
                    r["frame"],
                    r["time"],
                    r["client"],
                    r["server"],
                    r["method"],
                    r["host"],
                    r["uri"],
                    r.get("status"),
                    r.get("phrase", "No response"),
                    r.get("contentType", ""),
                    r.get("size"),
                    r.get("ms"),
                ],
                "filter": _frames_filter(frames),
                "frame": r["frame"],
                "response": response,
                "contentType": r.get("contentType", ""),
                "label": f"{r['method']} {r['host']}{r['uri']}",
            }
        )
    table.extra["summary"] = {"requests": len(requests), "unanswered": len(requests) - answered}
    return table


# ---------------------------------------------------------------------- DNS


def _answers(c: dict[str, str]) -> str:
    parts: list[str] = []
    for name, kind in _DNS_ANSWERS:
        parts += [f"{kind} {v}" for v in _each(c.get(name, ""))]
    return ", ".join(parts)


def dns_queries(lines: Iterable[str]) -> Table:
    """DNS queries (rows in capture order) with their responses."""
    queries: dict[int, dict[str, Any]] = {}
    for line in lines:
        cells = _cells(line, len(DNS_FIELDS))
        if cells is None or not cells[0].isdigit():
            continue
        c = dict(zip(DNS_FIELDS, cells, strict=False))
        frame = int(c["frame.number"])
        is_response = _first(c["dns.flags.response"]).lower() in ("true", "1")
        if not is_response:
            queries[frame] = {
                "frame": frame,
                "time": _float(c["frame.time_relative"]),
                "client": _first(c["ip.src"] or c["ipv6.src"]),
                "server": _first(c["ip.dst"] or c["ipv6.dst"]),
                "id": _first(c["dns.id"]),
                "name": _first(c["dns.qry.name"]),
                "type": dns_type(_int(_first(c["dns.qry.type"]))),
            }
            continue
        query = _int(_first(c["dns.response_to"]))
        if query is None or query not in queries:
            continue
        rcode = _int(_first(c["dns.flags.rcode"]))
        queries[query].update(
            response=frame,
            rcode="" if rcode is None else DNS_RCODES.get(rcode, str(rcode)),
            ms=_ms(_float(_first(c["dns.time"]))),
            answers=_answers(c),
        )
    table = Table(
        "dns_queries",
        "DNS Queries",
        [
            _col("frame", "No.", True),
            _col("time", "Time", True),
            _col("client", "Client"),
            _col("server", "Server"),
            _col("id", "ID"),
            _col("name", "Name"),
            _col("type", "Type"),
            _col("rcode", "Result"),
            _col("answers", "Answers"),
            _col("ms", "Response Time (ms)", True),
        ],
    )
    answered = failed = 0
    for q in sorted(queries.values(), key=lambda q: q["frame"]):
        response = q.get("response")
        answered += response is not None
        failed += response is not None and q.get("rcode") not in ("NoError", "")
        frames = [q["frame"], response] if response is not None else [q["frame"]]
        table.rows.append(
            {
                "cells": [
                    q["frame"],
                    q["time"],
                    q["client"],
                    q["server"],
                    q["id"],
                    q["name"],
                    q["type"],
                    q.get("rcode", "No response"),
                    q.get("answers", ""),
                    q.get("ms"),
                ],
                "filter": _frames_filter(frames),
                "frame": q["frame"],
            }
        )
    table.extra["summary"] = {
        "queries": len(queries),
        "unanswered": len(queries) - answered,
        "failed": failed,
    }
    return table


# ---------------------------------------------------------------------- TLS


@dataclass(slots=True)
class _Connection:
    key: str  # "tcp N" or "quic N"
    transport: str
    client: str
    server: str
    port: str
    first: int
    sni: str = ""
    answered: bool = False
    version: str = ""
    cipher: str = ""
    alpn: str = ""


@dataclass(slots=True)
class _Server:
    server: str
    port: str
    transport: str
    sni: str
    connections: list[_Connection] = field(default_factory=list)


def _joined(values: Iterable[str]) -> str:
    return ", ".join(dict.fromkeys(v for v in values if v))


def tls_servers(lines: Iterable[str]) -> Table:
    """TLS (and QUIC) servers by address, port and SNI, from the handshakes."""
    conns: dict[str, _Connection] = {}
    for line in lines:
        cells = _cells(line, len(TLS_FIELDS))
        if cells is None or not cells[0].isdigit():
            continue
        c = dict(zip(TLS_FIELDS, cells, strict=False))
        frame = int(c["frame.number"])
        tcp, quic = _first(c["tcp.stream"]), _first(c["quic.connection.number"])
        key = f"tcp {tcp}" if tcp else f"quic {quic}" if quic else None
        if key is None:
            continue
        kinds = {_int(k) for k in _each(c["tls.handshake.type"])}
        src, dst = _first(c["ip.src"] or c["ipv6.src"]), _first(c["ip.dst"] or c["ipv6.dst"])
        dport = _first(c["tcp.dstport"] or c["udp.dstport"])
        if 1 in kinds and key not in conns:
            conns[key] = _Connection(
                key,
                "TCP" if tcp else "QUIC",
                src,
                dst,
                dport,
                frame,
                sni=_first(c["tls.handshake.extensions_server_name"]),
            )
        conn = conns.get(key)
        if 2 in kinds and conn is not None and not conn.answered:
            supported = _int(_first(c["tls.handshake.extensions.supported_version"]))
            conn.answered = True
            conn.version = tls_version(supported or _int(_first(c["tls.handshake.version"])))
            conn.cipher = cipher_suite(_int(_first(c["tls.handshake.ciphersuite"])))
            conn.alpn = _first(c["tls.handshake.extensions_alpn_str"])
    servers: dict[tuple[str, str, str, str], _Server] = {}
    for conn in sorted(conns.values(), key=lambda c: c.first):
        group = (conn.server, conn.port, conn.transport, conn.sni)
        servers.setdefault(group, _Server(*group)).connections.append(conn)
    table = Table(
        "tls_servers",
        "TLS Servers",
        [
            _col("server", "Server"),
            _col("sni", "Server Name (SNI)"),
            _col("transport", "Transport"),
            _col("connections", "Connections", True),
            _col("unanswered", "No Server Hello", True),
            _col("versions", "Versions"),
            _col("ciphers", "Cipher Suites"),
            _col("alpn", "ALPN"),
            _col("clients", "Clients", True),
        ],
    )
    for s in servers.values():
        cs = s.connections
        answered = [c for c in cs if c.answered]
        field_ = "tcp.stream" if s.transport == "TCP" else "quic.connection.number"
        flt = _set_filter(field_, (int(c.key.split(" ", 1)[1]) for c in cs))
        by_address = _address_filter(s.server)
        if len(flt) > MAX_SET_FILTER and by_address:
            port = "tcp.port" if s.transport == "TCP" else "udp.port"
            flt = f"{by_address} && {port} == {s.port}"
        table.rows.append(
            {
                "cells": [
                    _endpoint(s.server, s.port),
                    s.sni,
                    s.transport,
                    len(cs),
                    len(cs) - len(answered),
                    _joined(c.version for c in answered),
                    _joined(c.cipher for c in answered),
                    _joined(c.alpn for c in answered),
                    len({c.client for c in cs}),
                ],
                "filter": flt,
                "frame": cs[0].first,
            }
        )
    table.extra["summary"] = {
        "servers": len(servers),
        "connections": len(conns),
        "unanswered": sum(1 for c in conns.values() if not c.answered),
    }
    return table
