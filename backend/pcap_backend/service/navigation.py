"""Find packet, conversation stepping, marks and field types."""

from __future__ import annotations

from typing import Any

from pcap_backend import navigation
from pcap_backend.protocol import FilterError, InvalidParamsError, RequestContext, param, str_list

from .filtering import FilteringMixin
from .helpers import _frame_list
from .state import _Open

NEIGHBOR_CHUNK = 2000


class NavigationMixin(FilteringMixin):
    """Find packet, conversation stepping, marks and field types."""

    def find_packet(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Next (or previous) frame of the current view that matches a search.

        ``mode``: ``filter`` (a display filter), ``string`` (text in the packet
        bytes; ``caseSensitive``), ``hex`` (bytes, e.g. ``47:45:54``) or
        ``marked``. The search starts after ``from`` (a frame number; omitted:
        from the top or bottom) in view order (current filter and sort) and
        wraps around. The search filter runs once and is cached like any filter.
        """
        self._require_complete()
        mode = param(params, "mode", str)
        direction = param(params, "direction", str, "next")
        if mode not in navigation.FIND_MODES or direction not in ("next", "previous"):
            raise InvalidParamsError("invalid find mode or direction")
        f, view = self._require_view()
        n_frames = f.info.frames
        hits = bytearray(n_frames + 1)
        expr = ""
        if mode == "marked":
            with self._lock:
                for n in self._marks:
                    if 0 < n <= n_frames:
                        hits[n] = 1
        else:
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
