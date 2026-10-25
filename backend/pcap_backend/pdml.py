"""Turn tshark PDML and ``-x`` hex dumps into the JSON the webview renders.

A detail tree node looks like::

    {
        "id": 7,
        "label": "Source Address: 10.0.0.1",
        "name": "ip.src",
        "show": "10.0.0.1",
        "pos": 26,
        "size": 4,
        "src": 0,
        "children": [...],
    }

``pos``/``size`` index into the byte source ``src`` (0 = the frame itself,
higher indexes = reassembled/decompressed buffers, in the order tshark
prints them with ``-x``).
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

TreeNode = dict[str, Any]

# Top-level items that introduce a new byte source (reassembly info). Every
# item after one of these lives in the next data source.
_NEW_SOURCE_RE = re.compile(r"\.(segments|fragments)$")
_SKIP_PROTOS = frozenset({"geninfo"})


class PdmlError(ValueError):
    """tshark produced PDML we could not parse."""


def parse_pdml(
    data: bytes, source_count: int = 1, sources: Sequence[bytes] | None = None
) -> list[TreeNode]:
    """Parse the first ``<packet>`` of a PDML document into a list of tree nodes.

    PDML doesn't say which byte source a field's ``pos`` refers to. Each
    top-level item goes into the source its fields' bytes match (``sources``,
    the ``-x`` buffers), else the one before it, moving on after reassembly
    info (``*.segments``): 6LoWPAN's IPv6 header, for one, is only in the
    "Decompressed 6LoWPAN IPHC" buffer, with no reassembly item before it.
    """
    try:
        root = ET.fromstring(data)  # noqa: S314 - trusted producer, escaped content
    except ET.ParseError as exc:
        raise PdmlError(f"could not parse tshark PDML output: {exc}") from exc
    packet = root.find("packet")
    if packet is None:
        return []
    counter = _Counter()
    top: list[ET.Element] = []
    for proto in packet:
        if proto.tag != "proto" or proto.get("name") in _SKIP_PROTOS:
            continue
        if proto.get("name") == "fake-field-wrapper":
            # Wireshark shows these children (e.g. reassembly info) at top level.
            top.extend(child for child in proto if child.tag in ("field", "proto"))
        else:
            top.append(proto)
    nodes: list[TreeNode] = []
    src = 0
    for el in top:
        if _NEW_SOURCE_RE.search(el.get("name", "")) and src + 1 < source_count:
            src += 1
        own = src
        if sources and len(sources) > 1:
            src = _matching_source(el, sources, src)
            own = _own_source(el, sources, src, own)
        node = _convert(el, src, counter, sources, own)
        if node is not None:
            nodes.append(node)
    return nodes


def _matching_source(el: ET.Element, sources: Sequence[bytes], default: int) -> int:
    """The byte source whose bytes agree best with ``el``'s fields (each
    field's raw ``value`` at its ``pos``), or ``default`` when none does better."""
    checks: list[tuple[int, bytes]] = []
    for node in el.iter():
        raw = node.get("unmaskedvalue") or node.get("value")
        pos, size = _int(node.get("pos")), _int(node.get("size"))
        if raw and pos is not None and size and len(raw) == 2 * size:
            try:
                checks.append((pos, bytes.fromhex(raw)))
            except ValueError:
                continue
    if not checks:
        return default

    def score(data: bytes) -> int:
        return sum(1 if data[pos : pos + len(b)] == b else -1 for pos, b in checks)

    scores = [score(data) for data in sources]
    best = max(range(len(sources)), key=lambda i: (scores[i], i == default))
    return best if scores[best] > scores[min(default, len(sources) - 1)] else default


class _Counter:
    def __init__(self) -> None:
        self.value = 0

    def next(self) -> int:
        self.value += 1
        return self.value


def _locate_field(
    el: ET.Element, sources: Sequence[bytes], src: int, pos: int, size: int
) -> tuple[int, int]:
    """A leaf field's (source, position): as given while its raw value is
    there, else where it is at that position in another source, else a
    source it fills whole. tshark gives a decrypted TLS record's "TLS segment
    data" the record's frame offset, though its bytes are a whole "Decrypted
    TLS" buffer."""
    raw = el.get("unmaskedvalue") or el.get("value") or ""
    if len(raw) != 2 * size:
        return src, pos
    try:
        value = bytes.fromhex(raw)
    except ValueError:
        return src, pos
    if sources[src][pos : pos + size] == value:
        return src, pos
    for i, data in enumerate(sources):
        if data[pos : pos + size] == value:
            return i, pos
    for i, data in enumerate(sources):
        if data == value:
            return i, 0
    return src, pos


def _own_source(el: ET.Element, sources: Sequence[bytes], inner: int, outer: int) -> int:
    """An item's own source: the one its fields are in, unless its
    own range only fits the enclosing one (EAP reassembled from RADIUS
    attributes: the item spans the attribute in the frame, its fields the
    "Reassembled EAP" buffer)."""
    pos, size = _int(el.get("pos")), _int(el.get("size"))
    if pos is None or not size or pos + size <= len(sources[inner]):
        return inner
    # (Neither fits, as for an EAP item spanning several attributes past the
    # frame's end: the enclosing source, where it starts, if it starts there.)
    return outer if pos < len(sources[outer]) else inner


def _convert(
    el: ET.Element,
    src: int,
    counter: _Counter,
    sources: Sequence[bytes] | None = None,
    own: int | None = None,
) -> TreeNode | None:
    """``src`` is the byte source of ``el``'s fields, ``own`` its own (default
    the same). A nested item (a protocol, or a field with children) whose
    fields' bytes match another source (``sources``) moves its subtree there:
    a decrypted DTLS alert's level and description are offsets in "Decrypted
    DTLS", under a record that is in the frame."""
    if el.get("hide") == "yes":
        return None
    name = el.get("name", "")
    show = el.get("show")
    showname = el.get("showname")
    if showname:
        label = showname
    elif name and show:
        label = f"{name}: {show}"
    else:
        label = show or name or "(unnamed)"
    node: TreeNode = {"id": counter.next(), "label": label, "src": src if own is None else own}
    if name:
        node["name"] = name
    if show is not None:
        node["show"] = show
    value = el.get("value")
    if value:
        node["value"] = value
    size = _int(el.get("size"))
    pos = _int(el.get("pos"))
    if size and pos is not None:
        if sources and len(sources) > 1 and len(el) == 0:
            node["src"], pos = _locate_field(el, sources, node["src"], pos, size)
        node["pos"] = pos
        node["size"] = size
    if el.tag == "proto":
        node["proto"] = True
    children = []
    for child in el:
        if child.tag not in ("field", "proto"):
            continue
        inner, child_own = src, None
        if sources and len(sources) > 1 and len(child):
            inner = _matching_source(child, sources, src)
            child_own = _own_source(child, sources, inner, src)
        converted = _convert(child, inner, counter, sources, child_own)
        if converted is not None:
            children.append(converted)
    if children:
        node["children"] = children
    return node


def _int(v: str | None) -> int | None:
    if v is None:
        return None
    try:
        return int(v)
    except ValueError:
        return None


@dataclass(slots=True)
class ByteSource:
    name: str
    data: bytearray

    def to_json(self) -> dict[str, Any]:
        return {"name": self.name, "hex": self.data.hex()}


# Name of the first byte source (the packet's own bytes) whatever tshark calls it:
# "Frame" up to 4.4, "Packet" from 4.6. Single-source packets print no header.
FRAME_SOURCE = "Frame"
_HEADER_RE = re.compile(r"^(?P<name>.+) \((?P<len>\d+) bytes?\):$")
_ROW_RE = re.compile(r"^(?P<off>[0-9a-fA-F]{4,})  (?P<rest>.*)$")
_BYTE_RE = re.compile(r"[0-9a-fA-F]{2}")


def parse_hexdump(text: str) -> list[ByteSource]:
    """Parse ``tshark -x`` output into byte sources.

    Single-source packets have no header line; multi-source packets print
    ``Frame (N bytes):`` (``Packet (N bytes):`` in tshark 4.6) /
    ``Reassembled TCP (N bytes):`` headers. The first source is always named
    FRAME_SOURCE, so the UI reads the same across tshark versions and for
    single- and multi-source packets.
    """
    sources: list[ByteSource] = []
    current: ByteSource | None = None
    for line in text.splitlines():
        if not line.strip():
            continue
        header = _HEADER_RE.match(line)
        if header:
            current = ByteSource(header["name"] if sources else FRAME_SOURCE, bytearray())
            sources.append(current)
            continue
        row = _ROW_RE.match(line)
        if not row:
            continue
        if current is None:
            current = ByteSource(FRAME_SOURCE, bytearray())
            sources.append(current)
        offset = int(row["off"], 16)
        # Hex area is 16 * "xx " = 48 chars; the ASCII column follows.
        tokens = _BYTE_RE.findall(row["rest"][:48])
        chunk = bytes.fromhex("".join(tokens))
        if offset != len(current.data):
            # Pad defensively if tshark ever skips rows.
            current.data.extend(b"\0" * max(0, offset - len(current.data)))
            del current.data[offset:]
        current.data.extend(chunk)
    return sources


# ---------------------------------------------------------------------- quick detail

_FRAME_LABEL_RE = re.compile(r"^Frame (\d+)(?=:)")
_SEGMENT_REF_RE = re.compile(r"#(\d+)(?=\()")


def _replace_last_number(text: str, old: int, new: int) -> str:
    matches = list(re.finditer(rf"(?<!\d){old}(?!\d)", text))
    if not matches:
        return text
    m = matches[-1]
    return f"{text[: m.start()]}{new}{text[m.end() :]}"


def renumber_tree(
    tree: list[TreeNode],
    offset: int,
    window: int,
    is_framenum: Callable[[str], bool],
    time_relative: str | None = None,
) -> None:
    """Make a tree dissected from an extracted window of packets read like the
    capture's own (in place).

    The window file numbers its packets from 1, so frame ``k`` of the window
    is frame ``k + offset`` of the capture: ``frame.number``, every field for
    which ``is_framenum(name)`` (FT_FRAMENUM: "Request in frame", "ACK of
    frame"…), the "Frame N:" header and the ``#N(len)`` references of
    ``*.segments``/``*.fragments`` get ``offset`` added (only values within
    the window, 1..``window``). ``time_relative`` replaces
    ``frame.time_relative``, which the window measures from its own first packet.
    """

    def shift(n: int) -> int:
        return n + offset if 1 <= n <= window else n

    def fix(node: TreeNode) -> None:
        name = node.get("name", "")
        show = node.get("show")
        label = node["label"]
        if name == "frame" and node.get("proto"):
            node["label"] = _FRAME_LABEL_RE.sub(lambda m: f"Frame {shift(int(m[1]))}", label)
        elif name == "frame.time_relative" and time_relative is not None and show is not None:
            node["label"] = label.replace(show, time_relative) if show in label else label
            node["show"] = time_relative
        elif (name == "frame.number" or is_framenum(name)) and show is not None and show.isdigit():
            old = int(show)
            new = shift(old)
            if new != old:
                node["show"] = str(new)
                node["label"] = _replace_last_number(label, old, new)
        elif _NEW_SOURCE_RE.search(name):
            node["label"] = _SEGMENT_REF_RE.sub(lambda m: f"#{shift(int(m[1]))}", label)
        for child in node.get("children", ()):
            fix(child)

    for node in tree:
        fix(node)
