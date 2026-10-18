"""Display filters: validation, counting, streaming filter passes."""

from __future__ import annotations

import time
from array import array
from typing import Any

from pcap_backend.cache import FrameIndex
from pcap_backend.cancellation import CancelledError
from pcap_backend.protocol import FilterError, InvalidParamsError, RequestContext, param
from pcap_backend.tshark import StreamResult, stream_lines

from .packets import PacketsMixin
from .state import (
    _TRUNCATION_HINTS,
    FIRST_BATCH,
    FIRST_BATCH_S,
    PROGRESS_INTERVAL_S,
    _Filtering,
    _Open,
    _View,
)

# count_matches returns at most this many matching frame numbers.
MAX_MATCH_FRAMES = 100


class FilteringMixin(PacketsMixin):
    """Display filters: validation, counting, streaming filter passes."""

    def validate_filter(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        expr = param(params, "expr", str, "")
        tshark = self._file.tshark if self._file else self._require_tshark()
        error = tshark.validate_filter(expr, ctx.token)
        return {"valid": error is None, "error": error} if error else {"valid": True}

    def count_matches(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """How many packets match display filter ``filter`` (``""``: all), without
        touching the viewer's view (the AI tools use it). ``limit`` (at most
        MAX_MATCH_FRAMES) also returns the first matching frame numbers, in
        capture order. Results come from and go to the filter cache (also the
        saved index), so asking again, or applying the filter later, is instant.
        """
        expr = param(params, "filter", str, "").strip()
        limit = param(params, "limit", int, 0)
        if not 0 <= limit <= MAX_MATCH_FRAMES:
            raise InvalidParamsError(f"limit must be between 0 and {MAX_MATCH_FRAMES}")
        f = self._require_file()
        self._require_indexed()
        total = f.info.frames
        matched = self._filters.get(expr) if expr else FrameIndex.all(total)
        if matched is None and f.cache is not None and f.cache_key is not None:
            saved = f.cache.load_filter(f.cache_key, expr, total)
            if saved is not None:
                matched = FrameIndex(saved, len(saved))
                self._filters.put(expr, matched)
        if matched is None:
            error = f.tshark.validate_filter(expr, ctx.token)
            if error:
                raise FilterError(error, {"expr": expr})
            matched = self._run_filter(f, expr, ctx)
            self._filters.put(expr, matched)
            self._save_filter(f, expr, matched)
        return {
            "filter": expr,
            "count": len(matched),
            "total": total,
            "frames": matched.slice(0, limit),
        }

    def set_filter(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Apply a display filter to the list (``""``: every packet).

        ``stream: true`` returns once the first matches are in (FIRST_BATCH, or
        after FIRST_BATCH_S) with ``filtering: true`` while the pass goes on;
        "filter" notifications (``progress``, then ``done``, ``stopped`` or
        ``failed``, each with ``filterId`` and ``matchCount``) report it, and
        ``stop_filter`` ends it early, keeping the matches so far (``partial``).
        A streaming filter also works while a streaming open is still indexing:
        the list then shows the matches among the rows indexed so far.
        Finished results are cached, also in the saved index.
        """
        if str(params.get("expr") or "").strip() and not params.get("stream"):
            self._require_indexed()
        return self._set_filter(params, ctx)

    def _set_filter(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        expr = param(params, "expr", str, "").strip()
        stream = bool(params.get("stream"))
        f = self._require_file()
        with self._lock:
            self._filter_seq += 1
            seq = self._filter_seq
            current = self._view
            indexing = self._indexing is not None
        if (
            current is not None
            and current.expr == expr
            and current.partial is None
            and not current.stale
        ):
            return self._filter_result(current)

        matched = self._filters.get(expr) if expr else FrameIndex.all(f.info.frames)
        if matched is None and not indexing and f.cache is not None and f.cache_key is not None:
            saved = f.cache.load_filter(f.cache_key, expr, f.info.frames)
            if saved is not None:
                matched = FrameIndex(saved, len(saved))
                self._filters.put(expr, matched)
        if matched is None:
            error = f.tshark.validate_filter(expr, ctx.token)
            if error:
                raise FilterError(error, {"expr": expr})
            if stream:
                return self._start_filter(f, expr, seq, current, ctx)
            matched = self._run_filter(f, expr, ctx)
            self._filters.put(expr, matched)
            self._save_filter(f, expr, matched)

        with self._lock:
            if seq != self._filter_seq:
                raise CancelledError("superseded by a newer filter")
            sort = current.sort if current else None
            self._next_filter_id += 1
            view = _View(self._next_filter_id, expr, matched, sort, matched)
        if sort is not None:
            view.ordered = self._sorted(f, view, sort, ctx)
        with self._lock:
            if seq != self._filter_seq:
                raise CancelledError("superseded by a newer filter")
            self._install_view(view)
        return self._filter_result(view)

    def _start_filter(
        self, f: _Open, expr: str, seq: int, current: _View | None, ctx: RequestContext
    ) -> dict[str, Any]:
        """Show a new view whose matches arrive from a background filter pass."""
        live = _Filtering(
            expr, during_capture=f.capture is not None and not f.capture.ended.is_set()
        )
        with self._lock:
            if seq != self._filter_seq:
                raise CancelledError("superseded by a newer filter")
            self._next_filter_id += 1
            empty = FrameIndex.of(())
            # Capture order while matches arrive; a sort applies once the pass is done.
            view = _View(self._next_filter_id, expr, empty, None, empty, live=live)
            view.stale = live.during_capture
            self._install_view(view)
            live.future = self._pool.submit(self._filter_pass, f, view, live)
        deadline = time.monotonic() + FIRST_BATCH_S
        while not live.done.wait(0.05):
            if ctx.token.cancelled:
                live.token.cancel()
                with self._lock:
                    if self._view is view:
                        self._view = current  # never shown: back to the previous view
                raise CancelledError("filter cancelled")
            if time.monotonic() >= deadline or len(live.frames) >= FIRST_BATCH:
                break
        with self._lock:
            if self._view is not view:
                # A newer filter replaced it meanwhile (and stopped its pass): a
                # success reply would come after the newer one's and name a gone view.
                raise CancelledError("superseded by a newer filter")
            if live.running:
                self._snapshot(live)
        return self._filter_result(view)

    @staticmethod
    def _snapshot(live: _Filtering) -> None:
        """Publish the matches so far to the view (under the lock)."""
        frames = live.frames[:]  # a copy: the pass keeps appending to its array
        live.snapshot = FrameIndex(frames, len(frames))
        live.version += 1

    def _filter_pass(self, f: _Open, view: _View, live: _Filtering) -> None:
        """A streaming filter's tshark pass (in the pool), then the "filter" notification."""

        def tick(p: Any) -> None:
            with self._lock:
                self._snapshot(live)
                live.fraction = None if self._indexing is not None else p.get("fraction")
                if self._view is not view:
                    return
                _f, shown = self._require_view()
                event = {
                    "event": "progress",
                    "filterId": view.filter_id,
                    "matchCount": len(shown.matched),
                    "fraction": live.fraction,
                }
            self.notify("filter", event)

        ctx = RequestContext(token=live.token, progress=tick)
        matched: FrameIndex | None = None
        error: str | None = None
        try:
            matched = self._run_filter(f, live.expr, ctx, live.frames)
        except CancelledError:
            pass
        except Exception as exc:  # noqa: BLE001 - reported to the client as "failed"
            error = str(exc) or type(exc).__name__
        with self._lock:
            live.running = False
            if matched is None:
                self._snapshot(live)
            else:
                live.snapshot = matched
                live.version += 1
            live.done.set()
            # Matches beyond a streaming open's rows so far can't be reused as they are.
            complete = (
                matched is not None
                and self._indexing is None
                and self._file is f
                and not live.during_capture
            )
            if complete and matched is not None:
                self._filters.put(live.expr, matched)
            event: dict[str, Any] | None = None
            if self._view is view:
                if matched is None:
                    view.partial = error or "stopped"
                _f, shown = self._require_view()
                event = {
                    "event": "done" if matched is not None else "failed" if error else "stopped",
                    "filterId": view.filter_id,
                    "matchCount": len(shown.matched),
                    "total": f.info.frames,
                }
                if error:
                    event["message"] = error
        if complete and matched is not None:
            self._save_filter(f, live.expr, matched)
        if event is not None:
            self.notify("filter", event)

    def stop_filter(self, params: dict[str, Any], _ctx: RequestContext) -> dict[str, Any]:
        """Stop the streaming filter of view ``filterId``; its matches so far stay
        (a "filter" notification with event "stopped" follows)."""
        filter_id = param(params, "filterId", int)
        with self._lock:
            view = self._view
            live = view.live if view is not None else None
            if view is None or view.filter_id != filter_id or live is None or not live.running:
                return {"stopped": False}
            live.token.cancel()
        return {"stopped": True}

    @staticmethod
    def _save_filter(f: _Open, expr: str, matched: FrameIndex) -> None:
        if expr and f.cache is not None and f.cache_key is not None:
            frames = matched.frames()
            if isinstance(frames, array):
                f.cache.save_filter(f.cache_key, expr, frames)

    def _filter_result(self, view: _View) -> dict[str, Any]:
        f, _current = self._require_view()  # brings a streaming view up to date
        result: dict[str, Any] = {
            "expr": view.expr,
            "matchCount": len(view.matched),
            "total": f.info.frames,
            "filterId": view.filter_id,
        }
        live = view.live
        if live is not None and live.running:
            result["filtering"] = True
            result["fraction"] = live.fraction
        if view.partial:
            result["partial"] = view.partial
        return result

    def _run_filter(
        self, f: _Open, expr: str, ctx: RequestContext, frames: array[int] | None = None
    ) -> FrameIndex:
        """Run filter ``expr`` over the capture; matches are appended to ``frames``
        (a new array by default) as they come."""
        if frames is None:
            frames = array("I")
        result = StreamResult()
        argv = f.tshark.argv("-Y", expr, "-T", "fields", "-e", "frame.number", capture=str(f.path))
        total = max(1, f.info.frames)
        last_emit = 0.0
        for line in stream_lines(argv, result, ctx.token):
            if ctx.token.cancelled:  # (lines tshark wrote already would still come)
                raise CancelledError("filter stopped")
            try:
                n = int(line)
            except ValueError:
                continue
            frames.append(n)
            now = time.monotonic()
            if now - last_emit >= PROGRESS_INTERVAL_S:
                last_emit = now
                ctx.progress(
                    {"phase": "filter", "matched": len(frames), "fraction": min(0.99, n / total)}
                )
        if result.returncode not in (0, None) and not frames and result.stderr:
            if any(h in result.stderr for h in _TRUNCATION_HINTS):
                return FrameIndex(frames, len(frames))
            raise FilterError(result.stderr.removeprefix("tshark: "), {"expr": expr})
        return FrameIndex(frames, len(frames))
