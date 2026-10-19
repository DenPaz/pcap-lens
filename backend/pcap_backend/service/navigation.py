"""Find packet, conversation stepping, marks and field types."""

from __future__ import annotations

from array import array
from collections.abc import Callable
from typing import Any

from pcap_backend import navigation
from pcap_backend.cache import FrameIndex
from pcap_backend.protocol import FilterError, InvalidParamsError, RequestContext, param, str_list
from pcap_backend.tshark import StreamResult, stream_lines

from .filtering import FilteringMixin
from .helpers import _frame_list
from .state import BASE_COLUMNS, _Open

NEIGHBOR_CHUNK = 2000
# Packet list search reads the row store in chunks of this many rows.
LIST_FIND_CHUNK = 20_000
# view_overview: at most this many slices (about a tall screen's pixels), and the
# flag bits of a slice holding a marked, commented or found packet.
MAX_OVERVIEW_BUCKETS = 4096
OVERVIEW_MARKED, OVERVIEW_COMMENT, OVERVIEW_FOUND = 1, 2, 4


class NavigationMixin(FilteringMixin):
    """Find packet, conversation stepping, marks and field types."""

    def find_packet(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Next (or previous) frame of the current view that matches a search.

        ``mode``: ``filter`` (a display filter), ``string`` or ``regex`` (text;
        ``caseSensitive``), ``hex`` (bytes, e.g. ``47:45:54``) or ``marked``.
        A string or regex is looked for ``in`` the packet bytes (default; a
        display filter), the packet list (the Source, Destination, Protocol,
        Length and Info cells plus the custom ``columns``, as shown) or the
        packet details (the labels of tshark's ``-V`` tree). The search starts
        after ``from`` (a frame number; omitted: from the top or bottom) in
        view order (current filter and sort) and wraps around. Each search
        runs once over the capture and is cached like a filter.
        """
        self._require_complete()
        mode = param(params, "mode", str)
        direction = param(params, "direction", str, "next")
        where = param(params, "in", str, "bytes")
        if mode not in navigation.FIND_MODES or direction not in ("next", "previous"):
            raise InvalidParamsError("invalid find mode or direction")
        if where not in navigation.FIND_IN:
            raise InvalidParamsError(f"in must be one of {', '.join(navigation.FIND_IN)}")
        f, view = self._require_view()
        hits, expr = self._find_matches(f, mode, where, params, ctx)
        self._find_hits = hits
        ordered = self._apply_sort(f, view, params, ctx) if "sort" in params else view.ordered
        seq = ordered.frames()
        total = len(ordered)
        start = params.get("from")
        pos = ordered.position_of(start) if isinstance(start, int) else None
        step = 1 if direction == "next" else -1
        result: dict[str, Any] = {"frame": None, "index": None, "filterId": view.filter_id}
        if expr:
            result["expr"] = expr
        for k in range(total):
            if pos is None:
                i = k if step == 1 else total - 1 - k
            else:
                i = (pos + step * (k + 1)) % total
            if hits[seq[i]]:
                wrapped = pos is not None and (i <= pos if step == 1 else i >= pos)
                result.update({"frame": seq[i], "index": i, "wrapped": wrapped})
                break
            if k % 65536 == 65535:
                ctx.token.raise_if_cancelled()
        return result

    def _find_matches(
        self, f: _Open, mode: str, where: str, params: dict[str, Any], ctx: RequestContext
    ) -> tuple[bytearray, str]:
        """A byte per frame, 1 where the search matches, and the display filter
        it ran ("" when it ran none)."""
        n_frames = f.info.frames
        hits = bytearray(n_frames + 1)
        if mode == "marked":
            with self._lock:
                for n in self._marks:
                    if 0 < n <= n_frames:
                        hits[n] = 1
            return hits, ""
        if mode in ("string", "regex") and where != "bytes":
            for n in self._text_matches(f, where, mode, params, ctx).frames():
                hits[n] = 1
            return hits, ""
        try:
            expr = navigation.find_expression(
                mode, param(params, "value", str, ""), bool(params.get("caseSensitive"))
            )
        except ValueError as exc:
            raise InvalidParamsError(str(exc)) from exc
        matched = self._filters.get(expr)
        if matched is None:
            error = f.tshark.validate_filter(expr, ctx.token)
            if error:
                raise FilterError(error, {"expr": expr})
            matched = self._run_filter(f, expr, ctx)
            self._filters.put(expr, matched)
        for n in matched.frames():
            hits[n] = 1
        return hits, expr

    def view_overview(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """The current view (filter and sort order) squeezed into ``buckets``
        slices for the list's scrollbar overview: per slice, the coloring rule
        most of its rows have (``colors``: rule index + 1 of ``coloringId``, 0 =
        none) and ``flags`` (OVERVIEW_MARKED, OVERVIEW_COMMENT, and with
        ``find: true`` OVERVIEW_FOUND for the latest Find Packet's matches).
        Ignored packets carry no color, as in the list. Runs over the published
        rows while a capture is still indexing."""
        f, view = self._require_view()
        ordered = self._apply_sort(f, view, params, ctx) if "sort" in params else view.ordered
        total = len(ordered)
        n_buckets = max(0, min(param(params, "buckets", int, 512), MAX_OVERVIEW_BUCKETS, total))
        with self._lock:
            colors, coloring_id = self._colors, self._coloring_id
            marks, ignored = self._marks, self._ignored
            edits = dict(self._comment_edits)
        found = self._find_hits if params.get("find") else None
        commented = {n for n, texts in f.comments.items() if texts and n not in edits}
        commented |= {n for n, text in edits.items() if text}
        seq = ordered.frames()
        out_colors: list[int] = []
        out_flags: list[int] = []
        if colors is None and not marks and not commented and found is None:
            n_buckets = 0  # nothing to draw: skip the pass over the rows
        for b in range(n_buckets):
            if b % 256 == 255:
                ctx.token.raise_if_cancelled()
            counts: dict[int, int] = {}
            flags = 0
            for i in range(b * total // n_buckets, (b + 1) * total // n_buckets):
                n = seq[i]
                if colors is not None and n < len(colors) and colors[n] and n not in ignored:
                    counts[colors[n]] = counts.get(colors[n], 0) + 1
                if n in marks:
                    flags |= OVERVIEW_MARKED
                if n in commented:
                    flags |= OVERVIEW_COMMENT
                if found is not None and n < len(found) and found[n]:
                    flags |= OVERVIEW_FOUND
            out_colors.append(max(counts, key=lambda c: counts[c]) if counts else 0)
            out_flags.append(flags)
        return {
            "rows": total,
            "colors": out_colors,
            "flags": out_flags,
            "coloringId": coloring_id if colors is not None else 0,
            "filterId": view.filter_id,
        }

    def _text_matches(
        self, f: _Open, where: str, mode: str, params: dict[str, Any], ctx: RequestContext
    ) -> FrameIndex:
        """Frames whose packet-list cells or packet-details text match a string
        or regex search; cached in the filter LRU under a key no display filter
        can have."""
        value = param(params, "value", str, "")
        case = bool(params.get("caseSensitive"))
        try:
            test = navigation.text_matcher(mode, value, case)
        except ValueError as exc:
            raise InvalidParamsError(str(exc)) from exc
        columns: list[str] = []
        if where == "list":
            base = {c.field for c in BASE_COLUMNS}
            asked = str_list(params, "columns") if "columns" in params else list(f.columns)
            columns = [c for c in self._check_fields(asked) if c not in base]
        key = "\0".join(("\0find", where, mode, str(int(case)), value, *columns))
        matched = self._filters.get(key)
        if matched is None:
            if where == "list":
                matched = self._list_matches(f, test, columns, ctx)
            else:
                matched = self._details_matches(f, test, ctx)
            self._filters.put(key, matched)
        return matched

    def _list_matches(
        self, f: _Open, test: Callable[[str], bool], columns: list[str], ctx: RequestContext
    ) -> FrameIndex:
        """Packet list search: the row store's text, no tshark (beyond extracting
        custom columns not indexed yet)."""
        self._ensure_columns(f, columns, ctx)
        total = f.frame_count()
        out = array("I")
        for start in range(1, total + 1, LIST_FIND_CHUNK):
            ctx.token.raise_if_cancelled()
            ctx.progress({"phase": "find", "fraction": (start - 1) / max(total, 1)})
            frames = range(start, min(total, start + LIST_FIND_CHUNK - 1) + 1)
            rows = f.base.rows.get_many(frames)
            extra = [self._column_cells(f, fld, frames) for fld in columns]
            for i, n in enumerate(frames):
                # Source … Info (not No. or Time), then the custom columns.
                cells = rows[i][2 : len(BASE_COLUMNS)] + [col[i] for col in extra]
                if test("\n".join(cells)):
                    out.append(n)
        return FrameIndex(out, total)

    def _details_matches(
        self, f: _Open, test: Callable[[str], bool], ctx: RequestContext
    ) -> FrameIndex:
        """Packet details search: one ``tshark -V`` pass (the same dissection
        options as the details pane), each packet's tree text tested once."""
        total = f.frame_count()
        argv = f.tshark.argv("-V", capture=str(f.path))
        result = StreamResult()
        out = array("I")
        seen = 0
        ctx.progress({"phase": "find", "fraction": 0.0})
        lines = (raw.decode("utf-8", "replace") for raw in stream_lines(argv, result, ctx.token))
        for frame, text in navigation.details_blocks(lines):
            seen = frame
            if test(text):
                out.append(frame)
            if frame % 1000 == 0:
                ctx.progress({"phase": "find", "fraction": min(frame / max(total, 1), 1.0)})
        ctx.token.raise_if_cancelled()
        if not seen and result.returncode not in (0, None):
            raise f.tshark.error(
                result.stderr, result.returncode, "searching the packet details failed"
            )
        return FrameIndex(out, total)

    def neighbor_frame(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Next/previous frame of the current view in the same conversation.

        The conversation is the tcp.stream or udp.stream (extracted once into the
        row store), else the Source/Destination address pair. No wrap-around.
        """
        self._require_complete()
        frame = param(params, "frame", int)
        direction = param(params, "direction", str, "next")
        if direction not in ("next", "previous"):
            raise InvalidParamsError("direction must be next or previous")
        f, view = self._require_view()
        ordered = self._apply_sort(f, view, params, ctx) if "sort" in params else view.ordered
        pos = ordered.position_of(frame)
        if pos is None:
            raise InvalidParamsError(f"packet {frame} is not displayed")
        self._ensure_columns(f, ["tcp.stream", "udp.stream"], ctx)
        key = self._conversation_keys(f, [frame])[0]
        result: dict[str, Any] = {"frame": None, "index": None, "filterId": view.filter_id}
        if key is None:
            return result
        seq = ordered.frames()
        step = 1 if direction == "next" else -1
        i = pos + step
        while 0 <= i < len(seq):
            stop = min(len(seq), i + NEIGHBOR_CHUNK) if step == 1 else max(-1, i - NEIGHBOR_CHUNK)
            positions = list(range(i, stop, step))
            keys = self._conversation_keys(f, [seq[p] for p in positions])
            for p, k in zip(positions, keys, strict=True):
                if k == key:
                    result.update({"frame": seq[p], "index": p})
                    return result
            ctx.token.raise_if_cancelled()
            i = stop
        return result

    def _conversation_keys(self, f: _Open, frames: list[int]) -> list[tuple[str, ...] | None]:
        tcp = self._column_cells(f, "tcp.stream", frames)
        udp = self._column_cells(f, "udp.stream", frames)
        base = f.base.rows.get_many(frames)
        keys: list[tuple[str, ...] | None] = []
        for t, u, cells in zip(tcp, udp, base, strict=True):
            if t:
                keys.append(("tcp", t.split(",")[0]))
            elif u:
                keys.append(("udp", u.split(",")[0]))
            elif cells[2] and cells[3]:
                keys.append(("addr", *sorted((cells[2], cells[3]))))
            else:
                keys.append(None)
        return keys

    def mark_packets(self, params: dict[str, Any], _ctx: RequestContext) -> dict[str, Any]:
        """Mark (``mark: true``) or unmark (``false``) ``frames``. Omitted: toggle,
        like Wireshark's Ctrl+M on a multi-selection: mark them all unless all
        of them are already marked, then unmark them."""
        f = self._require_file()
        frames = [n for n in _frame_list(params, "frames") if 1 <= n <= f.frame_count()]
        mark = params.get("mark")
        with self._lock:
            on = bool(mark) if mark is not None else not all(n in self._marks for n in frames)
            for n in frames:
                if on:
                    self._marks.add(n)
                else:
                    self._marks.discard(n)
            return {
                "count": len(self._marks),
                "marked": [n for n in frames if n in self._marks],
                "unmarked": [n for n in frames if n not in self._marks],
            }

    def unmark_all(self, _params: dict[str, Any], _ctx: RequestContext) -> dict[str, Any]:
        self._require_file()
        with self._lock:
            self._marks = set()
        return {"count": 0}

    def ignore_packets(self, params: dict[str, Any], _ctx: RequestContext) -> dict[str, Any]:
        """Ignore (``ignore: true``) or stop ignoring (``false``) ``frames``;
        omitted: toggle like marks (Wireshark's Ctrl+D). Ignored packets stay in
        the list but are left out of statistics and exports."""
        f = self._require_file()
        frames = [n for n in _frame_list(params, "frames") if 1 <= n <= f.frame_count()]
        ignore = params.get("ignore")
        with self._lock:
            on = bool(ignore) if ignore is not None else not all(n in self._ignored for n in frames)
            for n in frames:
                if on:
                    self._ignored.add(n)
                else:
                    self._ignored.discard(n)
            return {
                "count": len(self._ignored),
                "ignored": [n for n in frames if n in self._ignored],
                "unignored": [n for n in frames if n not in self._ignored],
            }

    def unignore_all(self, _params: dict[str, Any], _ctx: RequestContext) -> dict[str, Any]:
        self._require_file()
        with self._lock:
            self._ignored = set()
        return {"count": 0}

    def field_types(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Type and display name of each field in ``names`` (unknown ones are left out),
        e.g. to render FT_FRAMENUM fields as links to the frame they reference."""
        names = str_list(params, "names")[:2000]
        catalog = self._catalog(ctx)
        types: dict[str, dict[str, str]] = {}
        for name in names:
            entry = catalog.lookup(name)
            if entry is not None:
                types[name] = {"type": entry.get("type", "protocol"), "desc": entry.get("desc", "")}
        return {"types": types}
