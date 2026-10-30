"""The capture overview (``overview``): one fields pass over every packet,
summed into the cards the Overview panel shows.

Packets over time, the busiest addresses, the protocols packets carry, TCP
services (by the SYNs that open connections), and HTTP, DNS and TLS at a
glance (methods, statuses, content types and hosts; query types, results and
names; versions and server names). Every item carries the display filter of
its packets, so a card's row can be applied in the viewer.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from typing import Any

from .filterhelp import _quote
from .sessions import AGGREGATOR, DNS_RCODES, _first, _int, dns_type, tls_version
from .stats import _address_filter

FIELDS = (
    "frame.number", "frame.time_relative", "frame.len",
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "frame.protocols",
    "tcp.flags.syn", "tcp.flags.ack", "tcp.dstport",
    "http.request.method", "http.host", "http.response.code", "http.content_type",
    "dns.flags.response", "dns.flags.rcode", "dns.qry.type", "dns.qry.name",
    "tls.handshake.type", "tls.handshake.extensions_server_name", "tls.handshake.version",
    "tls.handshake.extensions.supported_version",
)  # fmt: skip
_COL = {name: i for i, name in enumerate(FIELDS)}

# Items per card.
TOP = 10
# Most buckets of the timeline (and the default).
MAX_BUCKETS = 1000
DEFAULT_BUCKETS = 120
# Timeline intervals in seconds, each a multiple of the one before it, so
# buckets merge exactly when a longer capture needs a longer interval; past
# the last one the interval doubles.
INTERVALS = (
    0.001, 0.002, 0.01, 0.02, 0.1, 0.2, 1, 2, 10, 20, 60, 120, 600, 1200, 3600, 7200,
    21600, 43200, 86400, 604800,
)  # fmt: skip
# Link layers and wrappers every packet of a capture carries: they tell nothing.
_PLUMBING = frozenset(("eth", "ethertype", "sll", "sll2", "null", "loop", "raw", "frame"))


def _true(cell: str) -> bool:
    return _first(cell) in ("True", "1", "true")


class Timeline:
    """Packets and bytes per interval since the first packet, with the
    interval growing (and buckets merging) to keep at most ``buckets``."""

    def __init__(self, buckets: int) -> None:
        self.buckets = buckets
        self.step = 0
        self.packets: list[int] = []
        self.bytes: list[int] = []

    @property
    def interval(self) -> float:
        if self.step < len(INTERVALS):
            return INTERVALS[self.step]
        return float(INTERVALS[-1] * 2 ** (self.step - len(INTERVALS) + 1))

    def add(self, seconds: float, length: int) -> None:
        index = int(max(seconds, 0.0) / self.interval)
        while index >= self.buckets:
            old = self.interval
            self.step += 1
            factor = round(self.interval / old)
            self.packets = _merge(self.packets, factor)
            self.bytes = _merge(self.bytes, factor)
            index //= factor
        if index >= len(self.packets):
            grow = index + 1 - len(self.packets)
            self.packets += [0] * grow
            self.bytes += [0] * grow
        self.packets[index] += 1
        self.bytes[index] += length

    def to_json(self) -> dict[str, Any]:
        return {"interval": self.interval, "packets": self.packets, "bytes": self.bytes}


def _merge(values: list[int], factor: int) -> list[int]:
    return [sum(values[i : i + factor]) for i in range(0, len(values), factor)]


def _items(
    counts: Counter[str],
    filter_of: Any,
    label_of: Any = None,
    sizes: Counter[str] | None = None,
) -> list[dict[str, Any]]:
    """The TOP most counted keys (by ``sizes`` when given), as card rows."""
    ranked = sorted(
        counts,
        key=lambda k: (-(sizes[k] if sizes is not None else counts[k]), -counts[k], k),
    )
    rows = []
    for key in ranked[:TOP]:
        row: dict[str, Any] = {
            "label": label_of(key) if label_of else key,
            "count": counts[key],
            "filter": filter_of(key),
        }
        if sizes is not None:
            row["bytes"] = sizes[key]
        rows.append(row)
    return rows


def _card(counts: Counter[str], total: int, filter_of: Any, label_of: Any = None) -> dict[str, Any]:
    return {
        "total": total,
        "items": _items(counts, filter_of, label_of),
        "more": max(0, len(counts) - TOP),
    }


class Overview:
    """Sums the fields pass, one line (its tab-separated cells) at a time."""

    def __init__(self, buckets: int = DEFAULT_BUCKETS) -> None:
        self.packets = 0
        self.bytes = 0
        self.duration = 0.0
        self.timeline = Timeline(buckets)
        self.address_packets: Counter[str] = Counter()
        self.address_bytes: Counter[str] = Counter()
        self.protocols: Counter[str] = Counter()
        self.services: Counter[str] = Counter()
        self.connections = 0
        self.http = {"requests": 0, "responses": 0}
        self.methods: Counter[str] = Counter()
        self.hosts: Counter[str] = Counter()
        self.statuses: Counter[str] = Counter()
        self.content_types: Counter[str] = Counter()
        self.dns = {"queries": 0, "responses": 0}
        self.rcodes: Counter[str] = Counter()
        self.qtypes: Counter[str] = Counter()
        self.names: Counter[str] = Counter()
        self.tls = {"clientHellos": 0, "serverHellos": 0}
        self.versions: Counter[str] = Counter()
        self.servers: Counter[str] = Counter()

    def add_lines(self, lines: Iterable[str]) -> None:
        for line in lines:
            cells = line.rstrip("\r").split("\t")
            if len(cells) >= len(FIELDS) and cells[0]:
                self.add(cells)

    def add(self, cells: list[str]) -> None:
        def cell(name: str) -> str:
            return cells[_COL[name]]

        length = _int(cell("frame.len")) or 0
        try:
            seconds = float(cell("frame.time_relative"))
        except ValueError:
            seconds = 0.0
        self.packets += 1
        self.bytes += length
        self.duration = max(self.duration, seconds)
        self.timeline.add(seconds, length)
        self._addresses(cell, length)
        for name in set(cell("frame.protocols").split(":")):
            if name and name not in _PLUMBING:
                self.protocols[name] += 1
        if _true(cell("tcp.flags.syn")) and not _true(cell("tcp.flags.ack")):
            port = _first(cell("tcp.dstport"))
            if port:
                self.connections += 1
                self.services[port] += 1
        self._http(cell)
        self._dns(cell)
        self._tls(cell)

    def _addresses(self, cell: Any, length: int) -> None:
        src = _first(cell("ip.src")) or _first(cell("ipv6.src"))
        dst = _first(cell("ip.dst")) or _first(cell("ipv6.dst"))
        for addr in {src, dst} - {""}:
            self.address_packets[addr] += 1
            self.address_bytes[addr] += length

    def _http(self, cell: Any) -> None:
        for method in _each(cell("http.request.method")):
            self.http["requests"] += 1
            self.methods[method] += 1
        for host in _each(cell("http.host")):
            self.hosts[host] += 1
        codes = _each(cell("http.response.code"))
        for code in codes:
            self.http["responses"] += 1
            self.statuses[code] += 1
        if codes:
            for content_type in _each(cell("http.content_type")):
                self.content_types[content_type] += 1

    def _dns(self, cell: Any) -> None:
        if not cell("dns.flags.response"):
            return
        if _true(cell("dns.flags.response")):
            self.dns["responses"] += 1
            rcode = _int(_first(cell("dns.flags.rcode")))
            if rcode is not None:
                self.rcodes[str(rcode)] += 1
            return
        self.dns["queries"] += 1
        for qtype in _each(cell("dns.qry.type")):
            self.qtypes[qtype] += 1
        for name in _each(cell("dns.qry.name")):
            self.names[name] += 1

    def _tls(self, cell: Any) -> None:
        kinds = {_int(k) for k in _each(cell("tls.handshake.type"))}
        if 1 in kinds:
            self.tls["clientHellos"] += 1
            for name in _each(cell("tls.handshake.extensions_server_name")):
                self.servers[name] += 1
        elif 2 in kinds:
            # (A frame with a ClientHello too would mix both hellos' versions.)
            self.tls["serverHellos"] += 1
            chosen = _first(cell("tls.handshake.extensions.supported_version"))
            version = _int(chosen or _first(cell("tls.handshake.version")))
            label = tls_version(version)
            if version is not None and label:
                key = f"{'s' if chosen else 'v'}{version}"
                self.versions[key] += 1

    def to_json(self) -> dict[str, Any]:
        return {
            "packets": self.packets,
            "bytes": self.bytes,
            "duration": round(self.duration, 6),
            "timeline": self.timeline.to_json(),
            "addresses": {
                "total": len(self.address_packets),
                "items": _items(self.address_packets, _address_filter, sizes=self.address_bytes),
                "more": max(0, len(self.address_packets) - TOP),
            },
            "protocols": _card(self.protocols, self.packets, lambda p: p),
            "services": _card(
                self.services,
                self.connections,
                lambda port: f"tcp.port == {port}",
                lambda port: f"{port}/tcp",
            ),
            "http": {
                **self.http,
                "methods": _card(
                    self.methods,
                    self.http["requests"],
                    lambda m: f"http.request.method == {_quote(m)}",
                ),
                "statuses": _card(
                    self.statuses, self.http["responses"], lambda c: f"http.response.code == {c}"
                ),
                "contentTypes": _card(
                    self.content_types,
                    self.http["responses"],
                    lambda t: f"http.response && http.content_type == {_quote(t)}",
                ),
                "hosts": _card(
                    self.hosts, self.http["requests"], lambda h: f"http.host == {_quote(h)}"
                ),
            },
            "dns": {
                **self.dns,
                "rcodes": _card(
                    self.rcodes,
                    self.dns["responses"],
                    lambda r: f"dns.flags.response == 1 && dns.flags.rcode == {r}",
                    lambda r: DNS_RCODES.get(int(r), f"RCODE {r}"),
                ),
                "types": _card(
                    self.qtypes,
                    self.dns["queries"],
                    lambda t: f"dns.flags.response == 0 && dns.qry.type == {t}",
                    lambda t: dns_type(_int(t)),
                ),
                "names": _card(
                    self.names,
                    self.dns["queries"],
                    lambda n: f"dns.flags.response == 0 && dns.qry.name == {_quote(n)}",
                ),
            },
            "tls": {
                **self.tls,
                "versions": _card(
                    self.versions, self.tls["serverHellos"], _version_filter, _version_label
                ),
                "servers": _card(
                    self.servers,
                    self.tls["clientHellos"],
                    lambda s: (
                        "tls.handshake.type == 1 && "
                        f"tls.handshake.extensions_server_name == {_quote(s)}"
                    ),
                ),
            },
        }


def _each(text: str) -> list[str]:
    return [v for v in text.split(AGGREGATOR) if v]


def _version_label(key: str) -> str:
    return tls_version(int(key[1:]))


def _version_filter(key: str) -> str:
    """The ServerHellos that chose a version: in supported_versions (TLS 1.3),
    else the hello's own version field."""
    value = f"0x{int(key[1:]):04x}"
    if key[0] == "s":
        return (
            "tls.handshake.type == 2 && !(tls.handshake.type == 1) && "
            f"tls.handshake.extensions.supported_version == {value}"
        )
    return (
        "tls.handshake.type == 2 && !(tls.handshake.type == 1) && "
        f"!tls.handshake.extensions.supported_version && tls.handshake.version == {value}"
    )
