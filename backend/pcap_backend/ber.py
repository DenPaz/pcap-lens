"""Files of BER-encoded records (ASN.1): recognising them, and splitting them
into packets.

tshark reads a file that is exactly one BER value (its "BER" file type), but
rejects several values back to back, which is how many record files (call
detail records, for example) are written. ``count_records`` walks the
tag-length headers without reading the values, so probe_file can say why such
a file isn't readable instead of only "not a capture file".

``write_pcapng`` makes such a file readable: one packet per record, in a
pcapng whose link type is Wireshark's "upper PDU export" (252). Each packet
starts with an exported-PDU tag naming the dissector that decodes the record
(``ber``, the generic one, or any dissector tshark knows, a Lua one included),
so tshark hands the record to it as if it had been exported from Wireshark.
"""

from __future__ import annotations

import struct
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import BinaryIO

# Records counted at most (enough to recognise the layout).
MAX_RECORDS = 100_000
# Record files are often padded to a block size with 0x00 or 0xFF bytes.
_PADDING = frozenset(b"\x00\xff")


def _header(fh: BinaryIO) -> int | None:
    """Read one tag-length header; the value's length, or None if it isn't one
    (a truncated header, an indefinite length, or more than 8 length bytes)."""
    tag = fh.read(1)
    if not tag:
        return None
    if tag[0] & 0x1F == 0x1F:  # high tag number: base-128 bytes, the last below 0x80
        for _ in range(5):
            more = fh.read(1)
            if not more:
                return None
            if not more[0] & 0x80:
                break
        else:
            return None
    first = fh.read(1)
    if not first or first[0] == 0x80:  # (indefinite lengths need parsing the value)
        return None
    if first[0] < 0x80:
        return first[0]
    count = first[0] & 0x7F
    raw = fh.read(count)
    if count > 8 or len(raw) != count:
        return None
    return int.from_bytes(raw, "big")


def _only_padding(fh: BinaryIO) -> bool:
    while chunk := fh.read(1 << 16):
        if not set(chunk) <= _PADDING:
            return False
    return True


class NotRecordsError(ValueError):
    """The file isn't BER values back to back (``offset``: where that shows)."""

    def __init__(self, offset: int) -> None:
        super().__init__(f"no BER record starts at byte {offset:,}")
        self.offset = offset


def records(fh: BinaryIO, size: int) -> Iterator[tuple[int, int]]:
    """``(offset, length)`` of each BER value in ``fh`` (``size`` bytes), header
    included, up to trailing 0x00/0xFF padding. Raises NotRecordsError where
    the data stops being BER values (a bad or truncated header, a value running
    past the end, an indefinite length, or bytes after the padding)."""
    count = 0
    while (start := fh.tell()) < size:
        # Padding when only 0x00/0xFF bytes are left (0xFF also starts a
        # private constructed tag with a high tag number, a record then).
        if count and fh.read(1) in (b"\x00", b"\xff"):
            fh.seek(start)
            if _only_padding(fh):
                return
        fh.seek(start)
        length = _header(fh)
        if length is None or fh.tell() + length > size:
            raise NotRecordsError(start)
        fh.seek(length, 1)
        count += 1
        yield start, fh.tell() - start


def count_records(path: Path) -> int | None:
    """How many BER values ``path`` holds back to back, when that is all it
    holds (trailing 0x00/0xFF padding allowed); None if it isn't laid out so.
    Stops counting at MAX_RECORDS."""
    count = 0
    try:
        with path.open("rb") as fh:
            for _ in records(fh, path.stat().st_size):
                count += 1
                if count >= MAX_RECORDS:
                    break
    except NotRecordsError:
        return None
    return count or None


# The largest packet tshark reads from a pcapng (WTAP_MAX_PACKET_SIZE_STANDARD);
# longer records are cut there (the packet keeps its original length).
MAX_PACKET = 262_144
LINKTYPE_UPPER_PDU = 252
_TAG_DISSECTOR_NAME = 12  # EXP_PDU_TAG_DISSECTOR_NAME
_TAG_END = 0


def _block(kind: int, body: bytes) -> bytes:
    pad = -len(body) % 4
    total = 12 + len(body) + pad
    return struct.pack("<II", kind, total) + body + bytes(pad) + struct.pack("<I", total)


def pdu_header(dissector: str) -> bytes:
    """The exported-PDU tags in front of each record: the dissector's name
    (padded to 4 bytes, the padding counted in the tag's length, as Wireshark
    writes it), then end-of-options."""
    name = dissector.encode("ascii")
    name += bytes(-len(name) % 4)
    return struct.pack(">HH", _TAG_DISSECTOR_NAME, len(name)) + name + bytes(4)


def write_pcapng(
    path: Path,
    out: BinaryIO,
    dissector: str,
    cancelled: Callable[[], bool] = lambda: False,
    progress: Callable[[float], None] = lambda _f: None,
) -> tuple[int, int]:
    """Write ``path``'s BER records to ``out`` as a pcapng, one packet each,
    for ``dissector``. Every packet gets the file's modification time (the
    records carry none the reader could know). Returns ``(packets,
    truncated)``: records longer than MAX_PACKET are cut to it. Raises
    NotRecordsError, or InterruptedError when ``cancelled()``."""
    size = path.stat().st_size
    stamp = int(path.stat().st_mtime * 1_000_000)  # microseconds (the default resolution)
    header = pdu_header(dissector)
    room = MAX_PACKET - len(header)
    out.write(_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
    out.write(_block(1, struct.pack("<HHI", LINKTYPE_UPPER_PDU, 0, 0)))
    packets = truncated = 0
    with path.open("rb") as fh, path.open("rb") as data:
        for offset, length in records(fh, size):
            if packets % 4096 == 0:
                if cancelled():
                    raise InterruptedError
                progress(offset / size)
            data.seek(offset)
            record = data.read(min(length, room))
            truncated += length > room
            body = header + record
            epb = struct.pack(
                "<IIIII", 0, stamp >> 32, stamp & 0xFFFFFFFF, len(body), len(header) + length
            )
            out.write(_block(6, epb + body))
            packets += 1
    if not packets:
        raise NotRecordsError(0)
    return packets, truncated
