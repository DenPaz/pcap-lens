"""The packet list: pages, extra columns, sorting and time formats."""

from __future__ import annotations

from bisect import bisect_left
from collections.abc import Sequence
from typing import Any

from pcap_backend import navigation
from pcap_backend.cache import FrameIndex, RowStore, sort_frames, sort_frames_by_key
from pcap_backend.cancellation import CancelledError
from pcap_backend.protocol import InvalidParamsError, RequestContext, RpcError, param, str_list
from pcap_backend.tshark import ToolError

from .dissection import DissectionMixin
from .helpers import _frame_list
from .opening import OpeningMixin
from .state import (
    _FIELD_NAME_RE,
    BASE_COLUMNS,
    MAX_PAGE,
    MAX_SELECTION,
    UNRESOLVED_FIELDS,
    _Open,
    _View,
)

_TIME_FIELD = "frame.time_relative"


# Time column sort keys that differ from capture order: the time format's deltas.
# Internal sort "fields" (never valid field names, so no clash with real ones).
_DELTA_SORTS = {"delta_displayed": "@delta_displayed", "delta_captured": "@delta_captured"}


_ADDRESS_TYPES = frozenset({"FT_IPv4", "FT_IPv6", "FT_ETHER"})


def _parse_sort(raw: Any) -> tuple[str, bool] | None:
    if raw is None:
        return None
    if not isinstance(raw, dict) or not isinstance(raw.get("field"), str):
        raise InvalidParamsError("sort must be {field: string, desc?: boolean}")
    fld = raw["field"]
    if not _FIELD_NAME_RE.match(fld):
        raise InvalidParamsError(f"invalid sort field {fld!r}")
    return fld, bool(raw.get("desc", False))


def _add_addresses(
    fields: Sequence[str], base_rows: Sequence[list[str]], rows: list[dict[str, Any]]
) -> None:
    """Give rows whose Source/Destination show names their ``addresses``
    ([source, destination], for cell filters)."""
    if UNRESOLVED_FIELDS[0] not in fields:
        return
    at = fields.index(UNRESOLVED_FIELDS[0])
    for base_row, row in zip(base_rows, rows, strict=True):
        src, dst = [*base_row[at : at + 2], "", ""][:2]
        if src or dst:
            cells = row["cells"]
            row["addresses"] = [src or cells[2], dst or cells[3]]


class PacketsMixin(OpeningMixin, DissectionMixin):
    """The packet list: pages, extra columns, sorting and time formats."""

    def list_packets(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Return rows ``[offset, offset + limit)`` of the current (filtered, sorted) view.

        With ``frames`` (at most MAX_PAGE frame numbers) instead, the rows of
        those frames that are displayed, in view order (e.g. to copy a
        multi-selection); with ``inView: false`` too, the rows of all of them
        (in range) in the given order, displayed or not (e.g. to explain them).
        ``columns`` is the full list of custom column fields wanted after the
        seven base columns (default: the ones given to ``open``). Fields not
        indexed yet are extracted with one extra tshark pass, then cached.
        """
        offset = param(params, "offset", int, 0)
        limit = param(params, "limit", int, 200)
        if offset < 0 or limit < 0:
            raise InvalidParamsError("offset and limit must be non-negative")
        limit = min(limit, MAX_PAGE)
        f, view = self._require_view()
        base_fields = {c.field for c in BASE_COLUMNS}
        if "columns" in params:
            extra_fields = [
                c for c in self._check_fields(str_list(params, "columns")) if c not in base_fields
            ]
        else:
            extra_fields = list(f.columns)
        with self._lock:
            indexing = self._indexing is not None
        if not indexing:
            self._ensure_columns(f, extra_fields, ctx)
        # (Streaming: columns not indexed yet stay blank until the pass is done.)
        view_ordered = self._apply_sort(f, view, params, ctx)

        if "frames" in params and params.get("inView") is False:
            n_frames = f.frame_count()
            asked = _frame_list(params, "frames", MAX_PAGE)
            frames = [n for n in dict.fromkeys(asked) if 1 <= n <= n_frames]
        elif "frames" in params:
            wanted = set(_frame_list(params, "frames", MAX_PAGE))
            frames = [n for n in view_ordered.frames() if n in wanted] if wanted else []
        else:
            frames = view_ordered.slice(offset, limit)
        rejected = [fld for fld in extra_fields if fld in f.rejected]
        n_base = len(BASE_COLUMNS)
        base_rows = f.base.rows.get_many(frames)
        extra_cols = [self._column_cells(f, fld, frames) for fld in extra_fields]
        rows: list[dict[str, Any]] = [
            {"number": n, "cells": base_rows[i][:n_base] + [col[i] for col in extra_cols]}
            for i, n in enumerate(frames)
        ]
        _add_addresses(f.base.fields, base_rows, rows)
        if "timeFormat" in params:
            fmt = param(params, "timeFormat", str)
            ref = params.get("timeRef")
            if indexing and fmt in navigation.TIME_FORMATS:
                # The other formats need a frame.time_epoch pass: relative until indexed.
                fmt, ref = "relative", None
            times = self._display_times(
                f,
                view.matched,
                frames,
                [r["cells"][1] for r in rows],
                fmt,
                ref,
                ctx,
            )
            for row, text in zip(rows, times, strict=True):
                row["cells"][1] = text
        with self._lock:
            marks = self._marks
            colors, coloring_id = self._colors, self._coloring_id
        for row in rows:
            if row["number"] in marks:
                row["marked"] = True
        self._add_comments(f, rows)
        if colors is not None:
            for row in rows:
                n = row["number"]
                if 0 < n < len(colors) and colors[n]:
                    row["color"] = colors[n] - 1
        return {
            "offset": offset,
            "rows": rows,
            "total": len(view_ordered),
            "filterId": view.filter_id,
            # Row "color" values index the rules of this set_coloring call (0 = none).
            "coloringId": coloring_id if colors is not None else 0,
            "columns": [c.field for c in BASE_COLUMNS] + extra_fields,
            # Unknown to tshark: their cells are blank; the UI should drop them.
            "rejectedColumns": rejected,
        }

    def _apply_sort(
        self, f: _Open, view: _View, params: dict[str, Any], ctx: RequestContext
    ) -> FrameIndex:
        """The view's order after applying ``sort`` (and ``timeFormat``, which picks
        what the Time column sorts by) from ``params``; the new order becomes the
        view's. Every request that uses row indexes takes them, so an index
        request can't overtake the page request that changes the sort."""
        sort = _parse_sort(params.get("sort"))
        if sort and sort[0] == _TIME_FIELD and params.get("timeFormat") in _DELTA_SORTS:
            # "Since previous packet" formats sort by that delta, not by capture time.
            sort = (_DELTA_SORTS[params["timeFormat"]], sort[1])
        if sort == view.sort or view.live is not None:
            return view.ordered  # (a streaming filter's matches stay in capture order)
        if sort is not None:
            self._require_complete()
        ordered = self._sorted(f, view, sort, ctx) if sort else view.matched
        with self._lock:
            if self._view is view:
                view.sort = sort
                view.ordered = ordered
        return ordered

    def find_frame(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Row index of a frame in the current view (for "go to packet").

        ``sort``/``timeFormat`` as for list_packets (omitted: the current order)."""
        number = param(params, "number", int)
        f, view = self._require_view()
        ordered = self._apply_sort(f, view, params, ctx) if "sort" in params else view.ordered
        return {"index": ordered.position_of(number), "filterId": view.filter_id}

    def view_frames(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Frame numbers of rows ``[offset, offset + limit)`` of the current view
        (a Shift+click range; ``limit`` at most MAX_SELECTION), or, with
        ``frames``, those of them that are displayed, in view order.
        ``sort``/``timeFormat`` as for list_packets (omitted: the current order)."""
        f, view = self._require_view()
        ordered = self._apply_sort(f, view, params, ctx) if "sort" in params else view.ordered
        if "frames" in params:
            wanted = set(_frame_list(params, "frames"))
            frames = [n for n in ordered.frames() if n in wanted] if wanted else []
            return {"frames": frames, "filterId": view.filter_id}
        offset = param(params, "offset", int, 0)
        limit = param(params, "limit", int)
        if offset < 0 or not 0 <= limit <= MAX_SELECTION:
            raise InvalidParamsError(f"offset must be >= 0 and limit 0..{MAX_SELECTION}")
        return {"frames": ordered.slice(offset, limit), "filterId": view.filter_id}

    def _locate(self, f: _Open, fld: str) -> tuple[RowStore, int] | None:
        for store in (f.base, *f.extra):
            if fld in store.fields:
                return store.rows, store.fields.index(fld)
        return None

    def _ensure_columns(self, f: _Open, fields: Sequence[str], ctx: RequestContext) -> None:
        """Extract any not-yet-indexed fields (one tshark pass for all of them).

        Fields tshark rejects are remembered in ``f.rejected`` instead of failing
        the request, so one bad custom column can't break the packet list.
        """
        if all(fld in f.rejected or self._locate(f, fld) is not None for fld in fields):
            return
        self._require_indexed()  # a column pass while the index pass still runs: later
        with self._build_lock:
            self._build_columns(f, fields, ctx)

    def _build_columns(self, f: _Open, fields: Sequence[str], ctx: RequestContext) -> None:
        missing = [fld for fld in fields if fld not in f.rejected and self._locate(f, fld) is None]
        if not missing:
            return
        assert self._work_dir is not None
        requested = list(missing)
        store = self._index_pass(f.tshark, f.path, self._work_dir, missing, f.info, ctx, base=False)
        with self._lock:
            f.extra.append(store)
            f.rejected.update(m for m in requested if m not in store.fields)

    def _column_cells(self, f: _Open, fld: str, frames: Sequence[int]) -> list[str]:
        loc = self._locate(f, fld)
        if loc is None:
            return [""] * len(frames)
        rows, idx = loc
        return [r[idx] for r in rows.get_many(frames)]

    def _sorted(
        self, f: _Open, view: _View, sort: tuple[str, bool] | None, ctx: RequestContext
    ) -> FrameIndex:
        if sort is None:
            return view.matched
        key = (view.expr, *sort)
        cached = self._sorts.get(key)
        if cached is not None:
            return cached
        with self._build_lock:
            return self._build_sort(f, view, sort, ctx)

    def _build_sort(
        self, f: _Open, view: _View, sort: tuple[str, bool], ctx: RequestContext
    ) -> FrameIndex:
        fld, desc = sort
        key = (view.expr, fld, desc)
        cached = self._sorts.get(key)
        if cached is not None:
            return cached
        if fld in _DELTA_SORTS.values():
            ctx.progress({"phase": "sort", "fraction": None})
            deltas = self._time_deltas(f, view.matched, fld == _DELTA_SORTS["delta_displayed"], ctx)
            ordered = sort_frames_by_key(view.matched.frames(), deltas, desc)
            self._sorts.put(key, ordered)
            return ordered
        self._ensure_columns(f, [fld], ctx)
        if fld in f.rejected:
            raise InvalidParamsError(f"cannot sort by unknown field {fld!r}")
        ctx.progress({"phase": "sort", "fraction": None})
        values = self._sort_columns.get(fld)
        if values is None:
            loc = self._locate(f, fld)
            assert loc is not None
            rows, idx = loc
            values = rows.column(idx)
            self._sort_columns.put(fld, values)
        ctx.token.raise_if_cancelled()
        base = next((c for c in BASE_COLUMNS if c.field == fld), None)
        if base is not None:
            numeric, addresses = base.numeric or None, base.addresses
        else:
            numeric, addresses = None, self._is_address_field(fld, ctx)
        ordered = sort_frames(
            view.matched.frames(), values, desc, numeric=numeric, addresses=addresses
        )
        self._sorts.put(key, ordered)
        return ordered

    def _is_address_field(self, fld: str, ctx: RequestContext) -> bool:
        """Custom columns of IPv4/IPv6/MAC fields sort numerically, like Source/Destination."""
        try:
            entry = self._catalog(ctx).lookup(fld)
        except CancelledError:
            raise
        except (RpcError, ToolError, OSError):
            return False
        return entry is not None and entry.get("type") in _ADDRESS_TYPES

    def _time_deltas(
        self, f: _Open, matched: FrameIndex, displayed: bool, ctx: RequestContext
    ) -> list[int | None]:
        """Per frame of ``matched``: ns since the previous displayed (``matched``)
        or captured packet, the values the delta time formats show (0 for the first)."""
        fld = "frame.time_epoch"
        self._ensure_columns(f, [fld], ctx)
        loc = self._locate(f, fld)
        assert loc is not None
        rows, idx = loc
        epoch = [navigation.parse_ns(v) for v in rows.column(idx)]
        ctx.token.raise_if_cancelled()
        out: list[int | None] = []
        prev: int | None = None
        for n in matched.frames():
            e = epoch[n - 1] if n <= len(epoch) else None
            p = prev if displayed else (n - 1 if n > 1 else None)
            pe = epoch[p - 1] if p is not None and p <= len(epoch) else None
            if e is None:
                out.append(None)
            else:
                out.append(e - pe if pe is not None else (0 if p is None else None))
            prev = n
        return out

    def _display_times(
        self,
        f: _Open,
        matched: FrameIndex,
        frames: list[int],
        relative: list[str],
        fmt: str,
        ref: Any,
        ctx: RequestContext,
    ) -> list[str]:
        """Time column text for one page in ``fmt`` (see navigation.TIME_FORMATS).

        Everything but plain "seconds since beginning" needs frame.time_epoch,
        extracted once into the row store. "Since previous displayed" is since the
        previous packet of the current filter in capture order (``matched``), like
        Wireshark's frame.time_delta_displayed but for our filter: a property of
        the packet, whatever the sort order, so the Time column can sort by it.
        """
        if fmt not in navigation.TIME_FORMATS:
            raise InvalidParamsError(
                f"timeFormat must be one of {', '.join(navigation.TIME_FORMATS)}"
            )
        if ref is not None and (
            isinstance(ref, bool) or not isinstance(ref, int) or not 1 <= ref <= f.info.frames
        ):
            raise InvalidParamsError(f"timeRef must be a frame number 1..{f.info.frames}")
        if fmt == "relative" and ref is None:
            return [
                navigation.format_seconds(ns) if (ns := navigation.parse_ns(v)) is not None else v
                for v in relative
            ]
        fld = "frame.time_epoch"
        self._ensure_columns(f, [fld], ctx)
        need = set(frames)
        prev_displayed: dict[int, int] = {}
        if fmt == "delta_displayed":
            seq = matched.frames()
            for n in frames:
                i = bisect_left(seq, n)
                if 0 < i <= len(seq):
                    prev_displayed[n] = seq[i - 1]
            need |= set(prev_displayed.values())
        if fmt == "delta_captured":
            need |= {n - 1 for n in frames if n > 1}
        if ref is not None:
            need.add(ref)
        wanted = sorted(need)
        epoch = {
            n: navigation.parse_ns(c)
            for n, c in zip(wanted, self._column_cells(f, fld, wanted), strict=True)
        }
        ref_ns = epoch.get(ref) if ref is not None else None
        zero = navigation.format_seconds(0)
        out: list[str] = []
        for n in frames:
            e = epoch.get(n)
            if n == ref:
                out.append("*REF*")
            elif e is None:
                out.append("")
            elif fmt == "relative":
                out.append(navigation.format_seconds(e - ref_ns) if ref_ns is not None else "")
            elif fmt == "delta_displayed":
                prev = prev_displayed.get(n)
                p = epoch.get(prev) if prev is not None else None
                out.append(navigation.format_seconds(e - p) if p is not None else zero)
            elif fmt == "delta_captured":
                p = epoch.get(n - 1)
                out.append(navigation.format_seconds(e - p) if p is not None else zero)
            elif fmt == "epoch":
                out.append(navigation.format_seconds(e))
            else:
                out.append(navigation.format_absolute(e, utc=fmt == "utc"))
        return out
