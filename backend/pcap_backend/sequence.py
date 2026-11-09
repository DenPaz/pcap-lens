"""Sequence checks: per stream (the values of one or more key fields), are a
sequence field's numbers complete and in order?

Interception deliveries (and many other protocols) number their messages per
stream: a LIID and a CIN, a GTP tunnel, an RTP source. ``Checker`` reads the
messages in capture order and reports, per stream, the numbers that never
came (gaps), the ones that came twice (duplicates), the ones that came after
a higher one (late: reordered), and restarts (the numbering began again).
Numbers are kept as sorted ranges, so a stream that is mostly complete costs a
few ranges however long it is. A counter that wraps (16-bit, 32-bit…) is
unwrapped when ``wrap`` is given, as RTP's sequence numbers are.

Pure: the service runs the tshark pass and builds the table (with filters).
"""

from __future__ import annotations

from bisect import bisect_right
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

# A number more than this far below the highest seen starts a new run (the
# sender restarted its numbering) rather than arriving late or twice.
DEFAULT_REORDER = 1000
# Problems kept per stream (the counts are always complete).
MAX_PROBLEMS = 200
# Missing ranges listed per stream.
MAX_RANGES = 50
# Streams tracked at most (the rest are counted).
MAX_STREAMS = 100_000
# The wraps a sequence field may have (a counter of 8, 16, 24 or 32 bits).
WRAPS = (0, 1 << 8, 1 << 16, 1 << 24, 1 << 32)


class Ranges:
    """A set of integers as sorted, disjoint, non-adjacent [lo, hi] ranges."""

    def __init__(self) -> None:
        self.lo: list[int] = []
        self.hi: list[int] = []

    def __contains__(self, n: int) -> bool:
        i = bisect_right(self.lo, n) - 1
        return i >= 0 and n <= self.hi[i]

    def add(self, n: int) -> bool:
        """Add ``n``; False when it was there already."""
        i = bisect_right(self.lo, n) - 1
        if i >= 0 and n <= self.hi[i]:
            return False
        joins_left = i >= 0 and self.hi[i] == n - 1
        joins_right = i + 1 < len(self.lo) and self.lo[i + 1] == n + 1
        if joins_left and joins_right:
            self.hi[i] = self.hi[i + 1]
            del self.lo[i + 1], self.hi[i + 1]
        elif joins_left:
            self.hi[i] = n
        elif joins_right:
            self.lo[i + 1] = n
        else:
            self.lo.insert(i + 1, n)
            self.hi.insert(i + 1, n)
        return True

    def gaps(self) -> list[tuple[int, int]]:
        """The ranges missing between the lowest and the highest number."""
        return [(self.hi[i] + 1, self.lo[i + 1] - 1) for i in range(len(self.lo) - 1)]

    def missing_in(self, lo: int, hi: int) -> int:
        """How many of lo..hi are not in the set."""
        present = 0
        i = max(bisect_right(self.lo, lo) - 1, 0)
        while i < len(self.lo) and self.lo[i] <= hi:
            present += max(0, min(hi, self.hi[i]) - max(lo, self.lo[i]) + 1)
            i += 1
        return (hi - lo + 1) - present


@dataclass
class _Run:
    """One run of numbers (a restart begins the next)."""

    ranges: Ranges = field(default_factory=Ranges)
    highest: int = 0


@dataclass
class Stream:
    key: tuple[str, ...]
    messages: int = 0
    packets: int = 0
    first_frame: int = 0
    last_frame: int = 0
    first_time: float | None = None
    last_time: float | None = None
    first_seq: int = 0
    last_seq: int = 0
    duplicates: int = 0
    late: int = 0
    restarts: int = 0
    runs: list[_Run] = field(default_factory=list)
    problems: list[dict[str, Any]] = field(default_factory=list)
    more_problems: int = 0
    last_n: int = 0

    def problem(self, item: dict[str, Any]) -> None:
        if len(self.problems) < MAX_PROBLEMS:
            self.problems.append(item)
        else:
            self.more_problems += 1

    def missing(self) -> int:
        return sum(hi - lo + 1 for run in self.runs for lo, hi in run.ranges.gaps())

    def to_json(self) -> dict[str, Any]:
        gaps = [[lo, hi] for run in self.runs for lo, hi in run.ranges.gaps()]
        # A gap filled later (all its numbers arrived, late) was reordering, not loss.
        for p in self.problems:
            if p["kind"] == "gap":
                run = self.runs[p["run"]]
                p["stillMissing"] = run.ranges.missing_in(p["from"], p["to"])
        return {
            "key": list(self.key),
            "messages": self.messages,
            "packets": self.packets,
            "firstFrame": self.first_frame,
            "lastFrame": self.last_frame,
            "firstTime": self.first_time,
            "lastTime": self.last_time,
            "firstSeq": self.first_seq,
            "lastSeq": self.last_seq,
            "missing": self.missing(),
            "missingRanges": gaps[:MAX_RANGES],
            "moreRanges": max(0, len(gaps) - MAX_RANGES),
            "duplicates": self.duplicates,
            "late": self.late,
            "restarts": self.restarts,
            "problems": [{k: v for k, v in p.items() if k != "run"} for p in self.problems],
            "moreProblems": self.more_problems,
        }


def parse_number(text: str) -> int | None:
    """A sequence value as tshark prints it: decimal, or 0x hex (BASE_HEX
    fields), else None."""
    text = text.strip()
    try:
        return int(text, 16) if text[:2].lower() == "0x" else int(text)
    except ValueError:
        return None


class Checker:
    """Feed messages in capture order, then ``streams()``."""

    def __init__(self, wrap: int = 0, reorder: int = DEFAULT_REORDER) -> None:
        if wrap not in WRAPS:
            raise ValueError(f"wrap must be one of {', '.join(map(str, WRAPS))}")
        if reorder < 1:
            raise ValueError("reorder must be at least 1")
        self.wrap = wrap
        self.reorder = reorder
        self._streams: dict[tuple[str, ...], Stream] = {}
        self.untracked = 0
        self.unreadable = 0

    def _unwrap(self, s: Stream, raw: int) -> int:
        """``raw`` placed in the wrap cycle nearest the stream's last number."""
        if not self.wrap or not s.runs:
            return raw
        last = s.last_n
        base = last - (last % self.wrap) + raw
        return min((base - self.wrap, base, base + self.wrap), key=lambda c: abs(c - last))

    def _shown(self, n: int) -> int:
        """An unwrapped number as the counter shows it."""
        return n % self.wrap if self.wrap else n

    def feed(self, key: tuple[str, ...], text: str, frame: int, time: float | None) -> None:
        raw = parse_number(text)
        if raw is None:
            self.unreadable += 1
            return
        s = self._streams.get(key)
        if s is None:
            if len(self._streams) >= MAX_STREAMS:
                self.untracked += 1
                return
            s = self._streams[key] = Stream(key, first_frame=frame, first_time=time)
        if s.last_frame != frame:
            s.packets += 1
        s.messages += 1
        s.last_frame = frame
        s.last_time = time
        n = self._unwrap(s, raw)
        if not s.runs:
            s.runs.append(_Run(highest=n))
            s.runs[-1].ranges.add(n)
            s.first_seq = raw
        else:
            self._place(s, n, raw, frame)
        s.last_n = n
        s.last_seq = raw

    def _place(self, s: Stream, n: int, raw: int, frame: int) -> None:
        run = s.runs[-1]
        index = len(s.runs) - 1
        if n > run.highest + 1:
            s.problem(
                {
                    "kind": "gap",
                    "run": index,
                    "from": run.highest + 1,
                    "to": n - 1,
                    "count": n - 1 - run.highest,
                    "fromSeq": self._shown(run.highest + 1),
                    "toSeq": self._shown(n - 1),
                    "frame": frame,
                }
            )
        elif n <= run.highest:
            # Far below: the numbering began again (a restart repeats old
            # numbers, so this comes before the duplicate check).
            if run.highest - n > self.reorder:
                s.restarts += 1
                s.problem(
                    {
                        "kind": "restart",
                        "seq": raw,
                        "after": self._shown(run.highest),
                        "frame": frame,
                    }
                )
                s.runs.append(_Run(highest=n))
                s.runs[-1].ranges.add(n)
                return
            if n in run.ranges:
                s.duplicates += 1
                s.problem({"kind": "duplicate", "seq": raw, "frame": frame})
                return
            s.late += 1
            s.problem({"kind": "late", "seq": raw, "frame": frame})
        run.ranges.add(n)
        run.highest = max(run.highest, n)

    def add_packet(
        self, frame: int, time: float | None, keys: list[list[str]], seqs: list[str]
    ) -> None:
        """One packet's messages: each key field's occurrences and the sequence
        field's. A packet can carry several messages: a key field with as many
        occurrences as the sequence field pairs with them one by one, one with
        a single occurrence applies to all, and a missing one is empty."""
        for i, seq in enumerate(seqs):
            key = tuple(
                (vals[i] if len(vals) == len(seqs) else vals[0]) if vals else "" for vals in keys
            )
            self.feed(key, seq, frame, time)

    def streams(self) -> list[Stream]:
        return list(self._streams.values())


def check(
    rows: Iterable[tuple[int, float | None, list[list[str]], list[str]]],
    wrap: int = 0,
    reorder: int = DEFAULT_REORDER,
) -> Checker:
    """Check messages given per packet: (frame, time, each key field's
    occurrences, the sequence field's occurrences); see ``Checker.add_packet``."""
    checker = Checker(wrap, reorder)
    for row in rows:
        checker.add_packet(*row)
    return checker


# A field's type (FT_STRING…) by name, or None.
TypeOf = Callable[[str], str | None]
# Streams listed at most (problems first).
MAX_ROWS = 1000
_STRING_TYPES = frozenset(
    ("FT_STRING", "FT_STRINGZ", "FT_UINT_STRING", "FT_STRINGZPAD", "FT_STRINGZTRUNC")
)


def _literal(value: str, ftype: str | None) -> str:
    if ftype in _STRING_TYPES or not value.replace(".", "").replace(":", "").isalnum():
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return value


def stream_filter(
    key_fields: list[str], key: tuple[str, ...], seq_field: str, type_of: TypeOf
) -> str:
    """The display filter of one stream's messages: each key field's value
    (absent when the stream had none) and the sequence field present."""
    parts = [
        f"{name} == {_literal(value, type_of(name))}" if value else f"!{name}"
        for name, value in zip(key_fields, key, strict=True)
    ]
    return " && ".join([*parts, seq_field])


def problem_label(p: dict[str, Any]) -> str:
    """A problem row's text, e.g. "Missing 4-5 (2)" (with an en dash)."""
    match p["kind"]:
        case "gap":
            span = f"{p['fromSeq']}" if p["count"] == 1 else f"{p['fromSeq']}\u2013{p['toSeq']}"
            if p.get("stillMissing", p["count"]) == 0:
                return f"Reordered: {span} arrived late"
            late = p["count"] - p.get("stillMissing", p["count"])
            text = f"Missing {span} ({p['count']:,})"
            return f"{text}, {late:,} of them arrived late" if late else text
        case "duplicate":
            return f"Duplicate {p['seq']}"
        case "late":
            return f"Late {p['seq']}"
        case _:
            return f"Restart at {p['seq']} after {p['after']}"


def _trouble(s: dict[str, Any]) -> int:
    return int(s["missing"] + s["duplicates"] + s["late"] + s["restarts"])


def _result(s: dict[str, Any]) -> str:
    parts = [
        f"{s[k]:,} {label}"
        for k, label in (
            ("missing", "missing"),
            ("duplicates", "duplicate"),
            ("late", "late"),
            ("restarts", "restart"),
        )
        if s[k]
    ]
    return ", ".join(parts) or "OK"


def table(checker: Checker, key_fields: list[str], seq_field: str, type_of: Any) -> dict[str, Any]:
    """The statistics panel's table: a row per stream (problems first, then by
    first packet) with its problems as rows under it, each with a filter."""
    streams = [s.to_json() for s in checker.streams()]
    for s in streams:
        s["result"] = _result(s)
    streams.sort(key=lambda s: (_trouble(s) == 0, s["firstFrame"]))
    # (Without key fields every message is one stream, and k0 still names rows.)
    names = key_fields or ["Stream"]
    columns = [
        *({"id": f"k{i}", "label": name, "numeric": False} for i, name in enumerate(names)),
        {"id": "messages", "label": "Messages", "numeric": True},
        {"id": "first", "label": "First", "numeric": True},
        {"id": "last", "label": "Last", "numeric": True},
        {"id": "missing", "label": "Missing", "numeric": True},
        {"id": "duplicates", "label": "Duplicates", "numeric": True},
        {"id": "late", "label": "Late", "numeric": True},
        {"id": "restarts", "label": "Restarts", "numeric": True},
        {"id": "result", "label": "Result", "numeric": False},
    ]
    blank = [None] * (len(columns) - 1)
    rows: list[dict[str, Any]] = []
    for s in streams[:MAX_ROWS]:
        key = tuple(s["key"])
        rows.append(
            {
                "cells": [
                    *([value or "(none)" for value in key] or ["All messages"]),
                    s["messages"],
                    s["firstSeq"],
                    s["lastSeq"],
                    s["missing"],
                    s["duplicates"],
                    s["late"],
                    s["restarts"],
                    s["result"],
                ],
                "frame": s["firstFrame"],
                "filter": stream_filter(key_fields, key, seq_field, type_of),
                "depth": 0,
            }
        )
        rows.extend(
            {
                "cells": [problem_label(p), *blank],
                "frame": p["frame"],
                "filter": f"frame.number == {p['frame']}",
                "depth": 1,
                "problem": p["kind"],
            }
            for p in s["problems"]
        )
        if s["moreProblems"]:
            rows.append({"cells": [f"… {s['moreProblems']:,} more problems", *blank], "depth": 1})
    total = {
        k: sum(s[k] for s in streams)
        for k in ("messages", "missing", "duplicates", "late", "restarts")
    }
    return {
        "kind": "sequences",
        "title": "Sequence Check",
        "columns": columns,
        "rows": rows,
        "summary": {
            "streams": len(streams),
            "withProblems": sum(1 for s in streams if _trouble(s)),
            **total,
            "unreadable": checker.unreadable,
            "untracked": checker.untracked,
            "more": max(0, len(streams) - MAX_ROWS),
        },
        "key": key_fields,
        "seq": seq_field,
    }
