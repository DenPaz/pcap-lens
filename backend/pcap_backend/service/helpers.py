"""Module-level helpers shared by several request handlers."""

from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from pcap_backend import ber, coloring
from pcap_backend.protocol import InvalidParamsError

from .state import MAX_SELECTION

_INVALID_FIELDS_RE = re.compile(r"Some fields aren't valid:\s*(?P<names>(?:\s*\S+)+)")


_PCAP_MAGICS = frozenset(
    bytes.fromhex(m)
    for m in ("d4c3b2a1", "a1b2c3d4", "4d3cb2a1", "a1b23c4d", "34cdb2a1", "a1b2cd34")
)


_PCAPNG_MAGIC = bytes.fromhex("0a0d0d0a")


def sniff_format(path: Path) -> str | None:
    """``"pcap"`` or ``"pcapng"`` for uncompressed files of those formats, else None."""
    try:
        with path.open("rb") as fh:
            head = fh.read(4)
    except OSError:
        return None
    if head in _PCAP_MAGICS:
        return "pcap"
    return "pcapng" if head == _PCAPNG_MAGIC else None


def ber_records(path: Path, *, first_as_tshark: bool = False) -> int | None:
    """How many BER values ``path`` holds back to back, when it holds more than
    one and nothing else (``ber.count_records``), else None. With
    ``first_as_tshark`` only when tshark's BER reader would take the first value
    (``ber.tshark_takes_first``): asked before tshark, since a tshark that reads
    such a file as one BER value shows only the first record (a Mac's Homebrew
    tshark 4.6.9 did) where others refuse it."""
    try:
        if first_as_tshark:
            with path.open("rb") as fh:
                head = fh.read(2)
            if sniff_format(path) is not None or not ber.tshark_takes_first(head):
                return None
        records = ber.count_records(path)
    except OSError:
        return None
    return records if records and records > 1 else None


def ber_records_message(name: str, records: int) -> str:
    more = "+" if records >= ber.MAX_RECORDS else ""
    return (
        f"{name} holds {records:,}{more} BER records one after another; "
        "tshark reads a file of one BER value only"
    )


def _fields_args(fields: Sequence[str]) -> list[str]:
    args = [
        "-T", "fields",
        "-E", "separator=/t",
        "-E", "occurrence=a",
        "-E", "aggregator=,",
        "-E", "quote=n",
    ]  # fmt: skip
    for f in fields:
        args += ["-e", f]
    return args


def _frame_list(params: dict[str, Any], key: str, limit: int = MAX_SELECTION) -> list[int]:
    frames = params.get(key)
    if not isinstance(frames, list) or not all(
        isinstance(n, int) and not isinstance(n, bool) for n in frames
    ):
        raise InvalidParamsError(f"parameter {key!r} must be a list of frame numbers")
    if len(frames) > limit:
        raise InvalidParamsError(f"parameter {key!r} holds more than {limit:,} frames")
    return frames


def _rejected_fields(stderr: str) -> list[str]:
    m = _INVALID_FIELDS_RE.search(stderr)
    return m["names"].split() if m else []


def _stderr_warnings(stderr: str) -> list[str]:
    """Group tshark stderr into user-facing warnings (Lua errors, truncation...).
    Coloring rules that don't compile are reported per rule instead."""
    out: list[str] = []
    for block in re.split(r"\n(?=tshark: )", stderr.strip()):
        text = block.strip()
        if text and "in colorfilters file" not in text:
            out.append(text.removeprefix("tshark: "))
    return out


def _readable_capture(raw: str) -> Path:
    """The capture's path, once we could read from it ourselves (a sandboxed
    tshark's permission errors are explained separately)."""
    path = Path(raw).expanduser()
    if path.is_dir():
        raise InvalidParamsError(f"{path} is a folder, not a capture file")
    if not path.is_file():
        raise InvalidParamsError(f"capture file not found: {path}")
    try:
        with path.open("rb") as fh:
            fh.read(1)
    except PermissionError as exc:
        raise InvalidParamsError(
            f"cannot read {path}: permission denied (check the file's permissions)"
        ) from exc
    return path


def _parse_rules(raw: list[Any]) -> tuple[list[coloring.ColorRule | str], dict[int, str]]:
    """Coloring rules (at most MAX_RULES) and the reasons some can't be used."""
    rules = [coloring.parse_rule(r) for r in raw[: coloring.MAX_RULES]]
    errors = {i: r for i, r in enumerate(rules) if isinstance(r, str)}
    errors.update(dict.fromkeys(range(coloring.MAX_RULES, len(raw)), "too many coloring rules"))
    return rules, errors
