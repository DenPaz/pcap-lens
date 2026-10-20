"""A MaxMind DB (.mmdb) writer for the GeoIP fixtures (stdlib only).

Writes the format https://maxmind.github.io/MaxMind-DB/ describes: an IPv6
search tree with 24-, 28- or 32-bit records (IPv4 networks under ::/96), a data section
of typed values without pointers, and the metadata map after its marker. Only
what the fixtures need: no overlapping networks.
"""

from __future__ import annotations

import ipaddress
import struct
from typing import Any

MARKER = b"\xab\xcd\xefMaxMind.com"


def _header(kind: int, size: int) -> bytes:
    if size < 29:
        first, extra = size, b""
    elif size < 285:
        first, extra = 29, bytes([size - 29])
    elif size < 65821:
        first, extra = 30, (size - 285).to_bytes(2, "big")
    else:
        first, extra = 31, (size - 65821).to_bytes(3, "big")
    if kind <= 7:
        return bytes([kind << 5 | first]) + extra
    return bytes([first, kind - 7]) + extra  # extended type


class Uint:
    """An unsigned integer of a given MaxMind type: 16, 32 or 64 bits (the
    metadata's fields have fixed types, which libmaxminddb checks)."""

    def __init__(self, value: int, bits: int) -> None:
        self.value, self.kind = value, {16: 5, 32: 6, 64: 9}[bits]


def encode(value: Any) -> bytes:
    if isinstance(value, Uint):
        data = value.value.to_bytes((value.value.bit_length() + 7) // 8, "big")
        return _header(value.kind, len(data)) + data
    if isinstance(value, bool):
        return _header(14, int(value))
    if isinstance(value, dict):
        return _header(7, len(value)) + b"".join(
            encode(str(k)) + encode(v) for k, v in value.items()
        )
    if isinstance(value, list):
        return _header(11, len(value)) + b"".join(encode(v) for v in value)
    if isinstance(value, str):
        data = value.encode()
        return _header(2, len(data)) + data
    if isinstance(value, float):
        return _header(3, 8) + struct.pack(">d", value)
    if isinstance(value, int):
        data = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return _header(6 if value < 1 << 32 else 9, len(data)) + data
    raise TypeError(f"can't encode {value!r}")


def _node(left: int, right: int, record_size: int) -> bytes:
    if record_size == 24:
        return left.to_bytes(3, "big") + right.to_bytes(3, "big")
    if record_size == 28:
        middle = bytes([(left >> 24) << 4 | right >> 24])
        return (left & 0xFFFFFF).to_bytes(3, "big") + middle + (right & 0xFFFFFF).to_bytes(3, "big")
    return left.to_bytes(4, "big") + right.to_bytes(4, "big")


def write_mmdb(
    networks: dict[str, dict[str, Any]], database_type: str, record_size: int = 24
) -> bytes:
    """A database mapping each network ("93.184.216.0/24", "2001:db8::/32") to its record."""
    # Nodes as [left, right]: an int is another node, ("data", offset) a record, None empty.
    nodes: list[list[Any]] = [[None, None]]
    data = b""
    for text, record in networks.items():
        net = ipaddress.ip_network(text)
        bits = int(net.network_address)
        width = 32 if net.version == 4 else 128
        path = ([0] * 96 if net.version == 4 else []) + [
            (bits >> (width - 1 - i)) & 1 for i in range(net.prefixlen)
        ]
        leaf = ("data", len(data))
        data += encode(record)
        node = 0
        for depth, bit in enumerate(path):
            if depth == len(path) - 1:
                nodes[node][bit] = leaf
            else:
                if not isinstance(nodes[node][bit], int):
                    nodes.append([None, None])
                    nodes[node][bit] = len(nodes) - 1
                node = nodes[node][bit]
    count = len(nodes)

    def record(child: Any) -> int:
        if child is None:
            return count
        if isinstance(child, int):
            return child
        return count + 16 + child[1]

    tree = b"".join(_node(record(left), record(right), record_size) for left, right in nodes)
    metadata = {
        "binary_format_major_version": Uint(2, 16),
        "binary_format_minor_version": Uint(0, 16),
        "build_epoch": Uint(1700000000, 64),
        "database_type": database_type,
        "description": {"en": "PCAP Lens test database"},
        "ip_version": Uint(6, 16),
        "languages": ["en"],
        "node_count": Uint(count, 32),
        "record_size": Uint(record_size, 16),
    }
    return tree + bytes(16) + data + MARKER + encode(metadata)
