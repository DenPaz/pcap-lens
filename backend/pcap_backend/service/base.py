"""State shared by every request handler, lifecycle and the guards."""

from __future__ import annotations

import itertools
import shutil
import threading
from array import array
from bisect import bisect_right
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor, wait
from pathlib import Path
from typing import Any

from pcap_backend import navigation, procs, voip
from pcap_backend.cache import FrameIndex, LruCache
from pcap_backend.cancellation import CancelToken
from pcap_backend.fields import FieldCatalog
from pcap_backend.objects import ExportedObject
from pcap_backend.prefs import Preference
from pcap_backend.protocol import (
    IndexingError,
    InvalidParamsError,
    NotOpenError,
    RequestContext,
)
from pcap_backend.tshark import EMPTY_CAPTURE, Tshark

from .state import MAX_FILTER_ARG, _Indexing, _Open, _View


class ServiceBase:
    """State shared by every request handler, lifecycle and the guards."""

    def __init__(self, max_cached_frames: int = 5_000_000, detail_cache_size: int = 64) -> None:
        self._lock = threading.RLock()
        # Serialises expensive derived-data builds (sort orders, extra columns) so
        # concurrent page requests don't each redo the same tshark pass or sort.
        self._build_lock = threading.RLock()
        self._tshark: Tshark | None = None
        self._file: _Open | None = None
        self._view: _View | None = None
        self._work_dir: Path | None = None
        # Export Objects: (the capture they came from, the objects), and a lock
        # so concurrent requests extract once.
        self._objects: tuple[_Open, list[ExportedObject]] | None = None
        self._objects_lock = threading.Lock()
        # Flow graph nodes of a view: (filter id, node names, name → index).
        self._flow: tuple[int, list[str], dict[str, int]] | None = None
        # Packet comment edits not saved yet (frame → text; None deletes), set by the host.
        self._comment_edits: dict[int, str | None] = {}
        self._filter_seq = 0
        self._next_filter_id = 0
        self._store_seq = 0
        self._filters: LruCache[str, FrameIndex] = LruCache(max_cached_frames, lambda v: v.cost)
        self._sorts: LruCache[tuple[str, str, bool], FrameIndex] = LruCache(
            max_cached_frames, lambda v: v.cost
        )
        self._sort_columns: LruCache[str, list[str]] = LruCache(2)
        # Exact details by (frame, two-pass); see packet_detail.
        self._details: LruCache[tuple[int, bool], dict[str, Any]] = LruCache(detail_cache_size)
        # Quick (approximate) details by (frame, window); see _quick_detail.
        self._quick: LruCache[tuple[int, int], dict[str, Any]] = LruCache(16)
        self._tcp_graphs: LruCache[int, dict[str, Any]] = LruCache(4)
        # Follow Stream: the sub-streams (HTTP/2, QUIC) of a (proto, stream), by frame.
        self._substreams: LruCache[tuple[str, int], list[tuple[int, list[int]]]] = LruCache(8)
        # VoIP: calls and streams (by heuristic RTP on/off), stream analyses.
        self._voip: LruCache[bool, dict[str, Any]] = LruCache(2)
        self._rtp_streams: LruCache[tuple[voip.StreamKey, bool], dict[str, Any]] = LruCache(8)
        # Display filter help: hints for a filter matching nothing (by expression)
        # and the values a field takes (by field name).
        self._filter_hints: LruCache[str, dict[str, Any]] = LruCache(16)
        self._field_values: LruCache[str, dict[str, Any]] = LruCache(16)
        self._quick_seq = itertools.count()
        self._catalog_warming = threading.Event()
        # Background work nobody asked for (the catalogue warm-up): stopped by shutdown.
        self._background = CancelToken()
        self._warm_future: Future[None] | None = None
        self._field_index: LruCache[tuple[str, ...], FieldCatalog] = LruCache(2)
        self._decode_as: LruCache[str, list[dict[str, str]]] = LruCache(32)
        # Wireshark's preferences with their defaults, by (tshark, Lua scripts).
        self._default_prefs: LruCache[tuple[str, tuple[str, ...]], dict[str, Preference]] = (
            LruCache(2)
        )
        # tshark's named dissectors (`-G dissectors`), by (tshark, Lua scripts).
        self._dissector_names: LruCache[tuple[str, tuple[str, ...]], list[dict[str, str]]] = (
            LruCache(2)
        )
        # Coloring: rule index + 1 per frame (0 = no rule), from the latest set_coloring.
        self._colors: array[int] | None = None
        self._coloring_id = 0
        self._coloring_seq = 0
        # Marked frames (Wireshark's Ctrl+M): per session, not persisted.
        self._marks: set[int] = set()
        # The latest Find Packet's matches (a byte per frame), for the list's overview.
        self._find_hits: bytearray | None = None
        # Ignored frames (Ctrl+D): left out of statistics and exports; per session too.
        self._ignored: set[int] = set()
        # Streaming open: the index pass still running after `open` returned.
        self._indexing: _Indexing | None = None
        # The last index pass, which saves the index after its "done": closing
        # waits for it, so the work dir isn't removed under the save.
        self._last_index: Future[None] | None = None
        self._tshark_versions: dict[Path, str] = {}
        # Backend -> client notifications ("index": progress/done/failed of a streaming open).
        self.notify: Callable[[str, dict[str, Any]], None] = lambda _method, _params: None
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="svc")

    def initialize(self, params: dict[str, Any], _ctx: RequestContext) -> dict[str, Any]:
        """Locate tshark/capinfos. Must be called before ``open``."""
        tshark = Tshark.locate(params.get("tsharkPath") or None, params.get("capinfosPath") or None)
        version = tshark.version()
        with self._lock:
            self._tshark = tshark
        return {
            "tsharkPath": str(tshark.path),
            "capinfosPath": str(tshark.capinfos) if tshark.capinfos else None,
            "version": version,
        }

    def close(self, _params: dict[str, Any] | None = None, _ctx: Any = None) -> dict[str, Any]:
        with self._lock:
            self._close_file()
        return {"ok": True}

    def shutdown(self) -> None:
        self.close()
        # Its tshark must not outlive the service (a test's process count).
        self._background.cancel()
        if self._warm_future is not None:
            wait([self._warm_future], timeout=procs.STOP_TIMEOUT)
        EMPTY_CAPTURE.remove()
        self._pool.shutdown(wait=False, cancel_futures=True)

    def _close_file(self) -> None:
        live = self._view.live if self._view is not None else None
        self._view = None  # (so a stopped filter pass reports nothing)
        if live is not None and live.running:
            live.token.cancel()
            self._wait_unlocked(live.future)
        indexing, self._indexing = self._indexing, None
        if indexing is not None:
            indexing.token.cancel()
            self._wait_unlocked(indexing.future)
        last, self._last_index = self._last_index, None
        if last is not None and not last.done():
            self._wait_unlocked(last)  # (still saving the index: hard links, quick)
        if self._file is not None:
            self._file.base.rows.close()
            for s in self._file.extra:
                s.rows.close()
        self._file = None
        self._view = None
        self._objects = None
        self._colors = None
        self._marks = set()
        self._find_hits = None
        self._ignored = set()
        self._comment_edits = {}
        self._flow = None
        for cache in (
            self._filters,
            self._sorts,
            self._sort_columns,
            self._details,
            self._quick,
            self._tcp_graphs,
            self._substreams,
            self._voip,
            self._rtp_streams,
            self._filter_hints,
            self._field_values,
        ):
            cache.clear()
        if self._work_dir is not None:
            shutil.rmtree(self._work_dir, ignore_errors=True)
            self._work_dir = None

    def _wait_unlocked(self, future: Future[None] | None) -> None:
        """Wait for a cancelled background pass (it takes the lock to finish)."""
        if future is None:
            return
        self._lock.release()
        try:
            future.result(timeout=30)
        except Exception:  # noqa: BLE001, S110 - it was cancelled; errors don't matter now
            pass
        finally:
            self._lock.acquire()

    def _require_tshark(self) -> Tshark:
        with self._lock:
            if self._tshark is None:
                self._tshark = Tshark.locate()
            return self._tshark

    def _ignore_filter(self) -> str:
        """The display filter that leaves the ignored packets out (``""`` when
        none are): statistics and exports add it to theirs."""
        with self._lock:
            ignored = sorted(self._ignored)
        expr = navigation.exclusion_filter(ignored)
        if len(expr) > MAX_FILTER_ARG:
            raise InvalidParamsError(
                f"{len(ignored):,} ignored packets in so many ranges are too many to leave out "
                "of a tshark pass; unignore some of them"
            )
        return expr

    def _without_ignored(self, flt: str) -> str:
        """``flt`` (``""`` = every packet) minus the ignored packets."""
        ignore = self._ignore_filter()
        if not ignore:
            return flt
        return f"({flt}) && {ignore}" if flt else ignore

    def _require_file(self) -> _Open:
        with self._lock:
            if self._file is None:
                raise NotOpenError
            return self._file

    def _require_view(self) -> tuple[_Open, _View]:
        with self._lock:
            if self._file is None or self._view is None:
                raise NotOpenError
            view = self._view
            indexing = self._indexing is not None
            if indexing and not view.expr and view.sort is None:
                # Streaming: the unfiltered view grows with the index pass.
                n = len(self._file.base.rows)
                if len(view.matched) != n:
                    view.matched = view.ordered = FrameIndex.all(n)
                    self._file.info.frames = n
            live = view.live
            if live is not None:
                # Streaming filter: show the latest snapshot, limited to the rows
                # a streaming open has published so far.
                src = live.snapshot
                k = len(src)
                if indexing and k:
                    k = bisect_right(src.frames(), len(self._file.base.rows))
                if live.shown != (live.version, k):
                    live.shown = (live.version, k)
                    shown = src if k == len(src) else FrameIndex.of(src.frames()[:k])
                    view.matched = view.ordered = shown
                if not live.running and not indexing:
                    view.live = None  # final: sorting etc. work from now on
                    if view.partial is None and not live.during_capture:
                        self._filters.put(view.expr, view.matched)
            return self._file, view

    def _require_indexed(self) -> None:
        """Raise IndexingError while a streaming index pass is still running."""
        with self._lock:
            if self._indexing is not None and self._file is not None:
                raise IndexingError(len(self._file.base.rows))

    def _require_complete(self) -> None:
        """Raise IndexingError while the capture is indexed or the view's filter
        runs (for what needs the whole view: sorting, find, export in view order…)."""
        self._require_indexed()
        with self._lock:
            view = self._view
            if view is not None and view.live is not None and view.live.running:
                raise IndexingError(len(view.matched), filtering=True)

    def _install_view(self, view: _View) -> None:
        """Make ``view`` current (under the lock), stopping a streaming filter it replaces."""
        old = self._view
        if old is not None and old is not view and old.live is not None and old.live.running:
            old.live.token.cancel()
        self._view = view
