"""Constants and the per-capture state shared by the service's request handlers."""

from __future__ import annotations

import re
import threading
import time
from array import array
from collections.abc import Callable
from concurrent.futures import Future
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pcap_backend import coloring
from pcap_backend.cache import FrameIndex, RowStore
from pcap_backend.cancellation import CancelToken
from pcap_backend.capture import LiveCapture
from pcap_backend.index_cache import IndexCache
from pcap_backend.protocol import RequestContext
from pcap_backend.tshark import Tshark

MAX_PAGE = 5000


# Longest display filter passed as one argv entry (Windows caps the whole command
# line at 32767 characters). Bigger marked-packet exports run in chunks + mergecap.
MAX_FILTER_ARG = 16_000


# Most frames one request may name or return (multi-selection: Shift+click ranges,
# copy, export). 4 bytes each in the backend, ~8 in JSON.
MAX_SELECTION = 1_000_000


PROGRESS_INTERVAL_S = 0.2


# Streaming open: `open` returns once this many rows are indexed (or after
# FIRST_BATCH_S with at least one), and the pass goes on in the background.
FIRST_BATCH = 1000


FIRST_BATCH_S = 0.5


@dataclass(frozen=True, slots=True)
class Column:
    id: str
    title: str
    field: str
    legacy_field: str
    numeric: bool = False
    addresses: bool = False  # sort IPv4/IPv6/MAC numerically (cache.address_key)


BASE_COLUMNS: tuple[Column, ...] = (
    Column("number", "No.", "frame.number", "frame.number", numeric=True),
    Column("time", "Time", "frame.time_relative", "frame.time_relative", numeric=True),
    Column("source", "Source", "_ws.col.def_src", "_ws.col.Source", addresses=True),
    Column("destination", "Destination", "_ws.col.def_dst", "_ws.col.Destination", addresses=True),
    Column("protocol", "Protocol", "_ws.col.protocol", "_ws.col.Protocol"),
    Column("length", "Length", "frame.len", "frame.len", numeric=True),
    Column("info", "Info", "_ws.col.info", "_ws.col.Info"),
)


# With name resolution, Source/Destination can show names; the index pass then
# also stores the addresses (blank when the same as shown) for cell filters.
# These column fields exist only for columns in gui.column.format, which must
# then list every column field used (titles = the legacy field names).
UNRESOLVED_FIELDS = ("_ws.col.unres_src", "_ws.col.unres_dst")


_TIME_IDX = 1  # position of frame.time_relative in BASE_COLUMNS


_LEN_IDX = 5  # position of frame.len in BASE_COLUMNS


_FIELD_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]*$")


_TRUNCATION_HINTS = ("cut short", "appears to be damaged", "corrupt", "truncated")


# Per-record overhead used to estimate progress from frame lengths. Only valid
# for uncompressed pcap/pcapng (recognised by magic number, whatever the file is
# called); other formats and compressed files get indeterminate progress.
_RECORD_OVERHEAD = {"pcap": 16, "pcapng": 32}


_UNSUPPORTED_RE = re.compile(r"isn't a capture file in a format TShark understands")


@dataclass(slots=True)
class CaptureInfo:
    path: str
    frames: int = 0
    start_time: float | None = None
    end_time: float | None = None
    link_type: str | None = None
    file_type: str | None = None
    size: int = 0
    warnings: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "frames": self.frames,
            "startTime": self.start_time,
            "endTime": self.end_time,
            "linkType": self.link_type,
            "fileType": self.file_type,
            "size": self.size,
            "warnings": self.warnings,
        }


@dataclass(slots=True)
class _Store:
    """A row store and the requested field each of its columns serves."""

    rows: RowStore
    fields: tuple[str, ...]  # user-facing field names, parallel to rows.fields


@dataclass(slots=True)
class _Open:
    path: Path
    tshark: Tshark
    info: CaptureInfo
    base: _Store
    extra: list[_Store] = field(default_factory=list)
    columns: list[str] = field(default_factory=list)  # custom column fields
    # Fields tshark refused ("Some fields aren't valid"); never re-run tshark for them.
    rejected: set[str] = field(default_factory=set)
    # Saved-index cache and this capture's key in it (None: not cached).
    cache: IndexCache | None = None
    cache_key: str | None = None
    # Packet comments in the file (comments.py), read in the background after open.
    comments: dict[int, list[str]] = field(default_factory=dict)
    comments_error: str | None = None
    comments_ready: threading.Event = field(default_factory=threading.Event)
    # A live capture writing this file (capture_start), running or not.
    capture: LiveCapture | None = None
    # Expert items per severity (expert_summary), once counted: (the ignored
    # packets' exclusion filter it was counted with, counts).
    expert: tuple[str, dict[str, int]] | None = None

    def frame_count(self) -> int:
        """Frames known so far: during a streaming open, the rows published
        already, even before the view (and ``info.frames``) caught up."""
        return max(self.info.frames, len(self.base.rows))


class _PassProgress:
    """Per-row bookkeeping of an index pass: progress (from frame lengths vs
    file size when the format allows), publishing rows as they come, and the
    first batch for a streaming open."""

    def __init__(
        self,
        ctx: RequestContext,
        store: _Store,
        on_rows: Callable[[_Store], None] | None,
        size: int,
        overhead: int | None,
        resume: _Resume | None = None,
    ) -> None:
        self.ctx = ctx
        self.store = store
        self.on_rows = on_rows
        self.size = size
        self.overhead = overhead
        self.resume = resume
        self.bytes_seen = 0
        self.last_emit = 0.0
        self.started = time.monotonic()

    def progress(self, number: int, fraction: float | None) -> dict[str, Any]:
        """A progress report at frame ``number``: "catching-up" while a resumed
        pass re-reads the rows already shown (``frames`` stays their count),
        then "indexing"."""
        resume = self.resume
        if resume is None:
            return {"phase": "indexing", "frames": number, "fraction": fraction}
        if number <= resume.known:
            return {
                "phase": "catching-up",
                "frames": resume.known,
                "position": number,
                "resumedAt": resume.known,
                "fraction": fraction,
            }
        return {
            "phase": "indexing",
            "frames": number,
            "resumedAt": resume.known,
            "fraction": fraction,
        }

    def ready(self) -> None:
        """Hand the store over now, rows or not (a live capture may be quiet)."""
        if self.on_rows is not None:
            on_rows, self.on_rows = self.on_rows, None
            self.store.rows.publish()
            on_rows(self.store)

    def row(self, number: int, rest: bytes) -> None:
        rows = self.store.rows
        if self.overhead:
            cells = rest.split(b"\t", _LEN_IDX + 1)
            if len(cells) > _LEN_IDX and cells[_LEN_IDX].isdigit():
                self.bytes_seen += int(cells[_LEN_IDX]) + self.overhead
        now = time.monotonic()
        if now - self.last_emit >= PROGRESS_INTERVAL_S:
            self.last_emit = now
            rows.publish()
            fraction = min(0.99, self.bytes_seen / self.size) if self.overhead else None
            self.ctx.progress(self.progress(number, fraction))
        if self.on_rows is not None and (
            rows.appended >= FIRST_BATCH or now - self.started >= FIRST_BATCH_S
        ):
            on_rows, self.on_rows = self.on_rows, None
            rows.publish()
            on_rows(self.store)


@dataclass(slots=True)
class _InlineColoring:
    """Coloring rules evaluated by the index pass itself (``open {coloring}``):
    ``--color`` and ``frame.coloring_rule.name`` as a last field, so every row
    comes with its color. About 6% on the index pass instead of a second pass."""

    raw: list[Any]  # the rules as given (their digest names the saved colors)
    rules: list[coloring.ColorRule | str]
    errors: dict[int, str]  # malformed rules, then tshark's compile errors
    # Rule index + 1 per frame (0 = none), index 0 unused; grows with the rows.
    colors: array[int] = field(default_factory=lambda: array("B", [0]))
    colored: int = 0
    coloring_id: int = 0
    enabled: bool = True  # False if tshark rejected the field (the pass ran without)

    def summary(self) -> dict[str, Any]:
        return {
            "coloringId": self.coloring_id,
            "colored": self.colored,
            "errors": {str(i): m for i, m in sorted(self.errors.items())},
        }


@dataclass(slots=True)
class _Indexing:
    """A (streaming) index pass running in the background."""

    token: CancelToken
    report: Callable[[Any], None]
    first: threading.Event = field(default_factory=threading.Event)  # rows to show
    done: threading.Event = field(default_factory=threading.Event)
    store: _Store | None = None
    error: BaseException | None = None
    future: Future[None] | None = None
    # `open` returned while the pass was running: finishing it updates the capture.
    attached: bool = False
    inline: _InlineColoring | None = None
    # Resuming from an unfinished saved index (its rows are shown at once).
    resume: _Resume | None = None


@dataclass(slots=True)
class _Resume:
    """An open resumed from an unfinished saved index: ``store`` holds its
    ``known`` rows (a private copy, appended to from row ``known + 1``).

    tshark can't start in the middle of a capture: stream numbers, relative
    sequence numbers, reassembly, expert flags and time references depend on
    the packets before. So the pass re-reads the capture from the start;
    rows 1…``known`` are not stored again but ``samples`` of them are compared
    (a mismatch means the rows no longer match: index again from scratch)."""

    store: _Store
    known: int
    samples: dict[int, bytes]
    # (name the caller asked for, field passed to tshark), as when it was saved
    pairs: list[tuple[str, str]]
    columns: list[str]
    caught_up: bool = False


class _ResumeMismatchError(Exception):
    """The re-read rows differ from the saved ones (or the columns do)."""


@dataclass(slots=True)
class _Filtering:
    """A streaming filter pass (``set_filter {stream: true}``) in the background.

    The pass appends matches to ``frames``; ``snapshot`` is the copy the view
    shows (taken every progress tick, so readers never see the array grow).
    While a streaming open is still indexing, the view shows only the matches
    among the rows published so far, even after the pass is done.
    """

    expr: str
    token: CancelToken = field(default_factory=CancelToken)
    frames: array[int] = field(default_factory=lambda: array("I"))
    snapshot: FrameIndex = field(default_factory=lambda: FrameIndex.of(()))
    version: int = 0  # bumped with every snapshot
    shown: tuple[int, int] = (-1, -1)  # (version, matches) the view shows
    fraction: float | None = None
    running: bool = True
    done: threading.Event = field(default_factory=threading.Event)
    future: Future[None] | None = None
    # Started while a live capture was running: it only saw the packets
    # captured by then, so its result is never cached.
    during_capture: bool = False


@dataclass(slots=True)
class _View:
    filter_id: int
    expr: str
    matched: FrameIndex
    sort: tuple[str, bool] | None
    ordered: FrameIndex
    # Streaming filter: matches still arriving (or clipped to a streaming open's rows).
    live: _Filtering | None = None
    # The filter pass stopped early ("stopped", or tshark's error): matches so far.
    partial: str | None = None
    # Its filter ran while a live capture was still writing the file: applying
    # the same filter again reruns it.
    stale: bool = False
