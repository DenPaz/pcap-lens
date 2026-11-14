"""Activity over time of conversations and endpoints: each row's bytes per
interval, drawn as a small chart in its row (the statistics panel).

One tshark fields pass (``FIELDS``) beside the ``-z conv``/``-z endpoints``
report gives each packet's time, length, addresses and ports; ``Grid`` sums
the bytes per key (a conversation: its two ends, in either order; an
endpoint: each end) in buckets of one interval shared by every row, so the
charts compare. The interval steps through the Capture Overview's
(``overview.INTERVALS``, each a multiple of the one before), so buckets
merge exactly when the capture is longer than ``BUCKETS`` intervals.

Keys follow what the reports count: Ethernet, IPv4 and IPv6 each header
pair (a tunnel's inner and outer ones), TCP and UDP their ports with the
addresses of the IP header carrying them (GTP's inner and outer UDP). A
packet the report counts differently (an ICMP error quoting a header) at
worst draws a little more in one chart: it's a picture, not a count.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .overview import _INTERVALS_NS, _NS, _merge, nanoseconds
from .stats import Table, split_endpoint

FIELDS = (
    "frame.time_relative", "frame.len",
    "eth.src", "eth.dst", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
)  # fmt: skip
AGGREGATOR = "\x1e"
# Buckets of the whole capture (a row's chart).
BUCKETS = 24
# Rows that get a chart (the most bytes first): a capture can hold 100k
# conversations, and their charts would make a reply of megabytes.
MAX_ROWS = 2000

Key = tuple[str, str | None]


class Grid:
    """Bytes per key and interval since the first packet, the interval
    growing (every key's buckets merging) to keep at most ``buckets``."""

    def __init__(self, buckets: int = BUCKETS) -> None:
        self.buckets = buckets
        self.step = 0
        self.data: dict[Any, list[int]] = {}

    @property
    def interval_ns(self) -> int:
        if self.step < len(_INTERVALS_NS):
            return _INTERVALS_NS[self.step]
        return _INTERVALS_NS[-1] << (self.step - len(_INTERVALS_NS) + 1)

    def add(self, keys: Iterable[Any], ns: int, length: int) -> None:
        index = max(ns, 0) // self.interval_ns
        while index >= self.buckets:
            old = self.interval_ns
            self.step += 1
            factor = self.interval_ns // old
            for key, values in self.data.items():
                self.data[key] = _merge(values, factor)
            index //= factor
        for key in keys:
            values = self.data.setdefault(key, [])
            if index >= len(values):
                values += [0] * (index + 1 - len(values))
            values[index] += length

    def length(self) -> int:
        """Buckets every row's chart gets (the longest key's)."""
        return max((len(v) for v in self.data.values()), default=0)


def _each(cell: str) -> list[str]:
    return cell.split(AGGREGATOR) if cell else []


def packet_keys(cells: dict[str, str], typ: str, kind: str) -> set[Any]:
    """The keys of the rows one packet counts in: conversations (a sorted
    pair of ends) or endpoints (each end), by address type."""
    pairs: list[tuple[Key, Key]] = []
    if typ in ("eth", "ip", "ipv6"):
        src = _each(cells[f"{typ}.src"])
        dst = _each(cells[f"{typ}.dst"])
        pairs = [((a, None), (b, None)) for a, b in zip(src, dst, strict=False)]
    elif typ in ("tcp", "udp"):
        src_ports = _each(cells[f"{typ}.srcport"])
        dst_ports = _each(cells[f"{typ}.dstport"])
        # The IP headers in order (IPv4 and IPv6 kept apart: 6in4 is rare);
        # each transport header goes with the IP header before it, matched
        # from the innermost.
        src = _each(cells["ip.src"]) or _each(cells["ipv6.src"])
        dst = _each(cells["ip.dst"]) or _each(cells["ipv6.dst"])
        n = min(len(src), len(dst))
        for i, (sp, dp) in enumerate(zip(src_ports, dst_ports, strict=False)):
            j = n - len(src_ports) + i
            if n and 0 <= j < n:
                pairs.append(((src[j], sp), (dst[j], dp)))
            elif n:
                pairs.append(((src[-1], sp), (dst[-1], dp)))
    keys: set[Any] = set()
    for a, b in pairs:
        if kind == "conversations":
            keys.add(tuple(sorted((a, b))))
        else:
            keys.update((a, b))
    return keys


def collect(lines: Iterable[str], typ: str, kind: str) -> Grid:
    """The grid of one fields pass's lines (``FIELDS``, tab-separated)."""
    grid = Grid()
    for line in lines:
        values = line.rstrip("\r\n").split("\t")
        if len(values) < len(FIELDS):
            continue
        cells = dict(zip(FIELDS, values, strict=False))
        try:
            length = int(cells["frame.len"])
        except ValueError:
            continue
        keys = packet_keys(cells, typ, kind)
        if keys:
            grid.add(keys, nanoseconds(cells["frame.time_relative"]), length)
    return grid


def row_key(table: Table, typ: str) -> Any:
    """A function giving a report row's key (as ``packet_keys`` makes them)."""
    with_port = typ in ("tcp", "udp")

    def end(text: Any) -> Key:
        addr, port = split_endpoint(str(text), with_port)
        return (addr, port)

    if table.kind == "conversations":
        return lambda row: tuple(sorted((end(row["cells"][0]), end(row["cells"][1]))))
    if with_port:
        return lambda row: (str(row["cells"][0]), str(row["cells"][1]))
    return lambda row: (str(row["cells"][0]), None)


def attach(table: Table, typ: str, grid: Grid) -> None:
    """Gives the ``MAX_ROWS`` rows with the most bytes their ``activity``
    (bytes per bucket) and the table ``activity: {interval, buckets}``.

    Several rows can share a key (a TCP port reused for a new connection;
    RTP's two directions, which tshark lists apart): each takes the buckets
    its own time (Rel Start to its end) overlaps. Every chart is scaled to
    its row's bytes, so it adds up to the row (an ICMP error quoting a
    header counts in the pass, not the report)."""
    length = grid.length()
    if not length or not table.rows:
        return
    key = row_key(table, typ)
    ids = [c["id"] for c in table.columns]
    bytes_at = ids.index("bytes")
    start_at = ids.index("start") if "start" in ids else None
    duration_at = ids.index("duration") if "duration" in ids else None
    ranked = sorted(table.rows, key=lambda r: -(r["cells"][bytes_at] or 0))[:MAX_ROWS]
    sharing: dict[Any, int] = {}
    for row in table.rows:
        k = key(row)
        sharing[k] = sharing.get(k, 0) + 1
    interval = grid.interval_ns / _NS
    found = 0
    for row in ranked:
        k = key(row)
        values = grid.data.get(k)
        if not values:
            continue
        values = values + [0] * (length - len(values))
        if sharing[k] > 1 and start_at is not None and duration_at is not None:
            start = float(row["cells"][start_at] or 0)
            end = start + float(row["cells"][duration_at] or 0)
            values = [
                v if (i + 1) * interval > start and i * interval <= end else 0
                for i, v in enumerate(values)
            ]
        total = sum(values)
        if not total:
            continue
        ratio = (row["cells"][bytes_at] or 0) / total
        row["activity"] = [round(v * ratio) for v in values]
        found += 1
    if found:
        table.extra["activity"] = {"interval": interval, "buckets": length}
