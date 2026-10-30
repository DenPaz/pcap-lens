"""Opening a capture: the index pass, saved indexes and resuming."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from array import array
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import Future
from pathlib import Path
from typing import Any

from pcap_backend import coloring, comments
from pcap_backend.cache import FrameIndex, RowStore
from pcap_backend.cancellation import CancelledError, CancelToken
from pcap_backend.capture import CaptureOptions, LiveCapture, LiveSource, capture_command
from pcap_backend.follow import FollowFile
from pcap_backend.index_cache import (
    CachedIndex,
    IndexCache,
    folder_fingerprint,
    index_key,
    rules_key,
)
from pcap_backend.protocol import InvalidParamsError, RequestContext, param, str_list
from pcap_backend.tshark import ConfigError, DissectionOptions, ToolError, Tshark, run

from .helpers import _fields_args, _readable_capture, _rejected_fields, sniff_format
from .indexing import (
    _attempt_store,
    _cache_from,
    _drop_rejected,
    _finish_index_pass,
    _index_error,
    _inline_coloring,
    _names_param,
    _pass_fields,
    _pass_lines,
    _personal_folders,
    _reset_colors,
    _sample_frames,
    _stream_rows,
    parse_capinfos,
)
from .packet_comments import CommentsMixin
from .state import (
    _FIELD_NAME_RE,
    _RECORD_OVERHEAD,
    BASE_COLUMNS,
    UNRESOLVED_FIELDS,
    CaptureInfo,
    _Indexing,
    _InlineColoring,
    _Open,
    _PassProgress,
    _Resume,
    _ResumeMismatchError,
    _Store,
    _View,
)

# A resumed open compares this many of the saved rows (evenly spread, plus the
# first and the last) with the rows tshark re-reads before going on.
RESUME_SAMPLES = 16


_UNRESOLVED_FORMAT = (
    'gui.column.format:"Source","%s","Destination","%d","Protocol","%p","Info","%i",'
    '"unres_src","%us","unres_dst","%ud"'
)


_COLOR_FIELD = "frame.coloring_rule.name"


class OpeningMixin(CommentsMixin):
    """Opening a capture: the index pass, saved indexes and resuming."""

    def open(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Index a capture file for the packet list.

        ``cache: {dir, maxBytes}`` reuses a saved index when nothing that
        changes it did (``fromCache: true``), and saves new ones. ``stream:
        true`` returns once the first rows are indexed (``indexing: true``);
        the pass goes on in the background and "index" notifications report
        its progress and end ("progress", then "done" with the final result,
        or "failed"). Until then the unfiltered list grows as rows arrive, and
        what needs every row (sorting, find…) raises IndexingError.

        ``coloring: {rules}`` (as for set_coloring) evaluates the coloring rules
        in the index pass, so rows come with their ``color``; the result (and
        "done") then carries ``coloring: {coloringId, colored, errors}``. From a
        saved index, the colors saved for these rules are used, if any (else no
        ``coloring``: run set_coloring).

        ``follow: true`` follows a file another program is still writing (an
        uncompressed pcap or pcapng; follow.FollowFile): it is shown like a
        live capture (``indexing: true`` and ``capture`` with ``follow: true``;
        "capture" ``stats``/``stopped`` notifications) and never saved as an
        index. ``capture_stop`` stops following; "index" ``done`` follows.
        """
        return self._open(params, ctx)

    def _open(
        self,
        params: dict[str, Any],
        ctx: RequestContext,
        live: tuple[CaptureOptions, Path] | None = None,
    ) -> dict[str, Any]:
        """``open``, or with ``live`` (capture_start) a capture into that file."""
        path = _readable_capture(param(params, "path", str)) if live is None else live[1]
        follow = live is None and bool(params.get("follow"))
        options = DissectionOptions.from_params(
            str_list(params, "lua"),
            str_list(params, "decodeAs"),
            param(params, "prefs", dict, {}),
            _names_param(params),
            param(params, "profile", str, ""),
            param(params, "protocols", dict, {}),
            param(params, "heuristics", dict, {}),
            param(params, "keys", list, []),
            str_list(params, "geoip"),
        )
        base_fields = {c.field for c in BASE_COLUMNS}
        columns = [
            c for c in self._check_fields(str_list(params, "columns")) if c not in base_fields
        ]
        requested_columns = list(columns)  # _index_pass removes fields tshark rejects
        options, switch_warnings = self._known_switches(options, ctx)
        tshark = self._require_tshark().with_options(options)
        tshark.profile_config(ctx.token)  # (a profile that doesn't exist: ConfigError)
        stream = bool(params.get("stream")) or live is not None or follow
        cache = _cache_from(params.get("cache")) if live is None and not follow else None
        inline = _inline_coloring(params.get("coloring"))
        command = capture_command(tshark.path, live[0]) if live is not None else []

        with self._lock:
            self._close_file()
            self._work_dir = Path(tempfile.mkdtemp(prefix="pcapviewer-"))
            work_dir = self._work_dir

        info = CaptureInfo(path=str(path), size=path.stat().st_size if live is None else 0)
        info.warnings += options.check_scripts() + switch_warnings
        key = self._index_key(tshark, path, options, requested_columns, ctx) if cache else None
        resume: _Resume | None = None
        if cache is not None and key is not None:
            hit = cache.load(key)
            if hit is not None and hit.complete:
                return self._open_cached(path, tshark, hit, work_dir, cache, key, inline)
            if hit is not None and stream:
                resume = self._resume_from(hit, work_dir)
                if resume is not None:
                    columns = list(resume.columns)

        capture = self._live_source(live, follow, command, path, ctx)
        info_future: Future[dict[str, Any]] | None = None
        if capture is None:
            info_future = self._pool.submit(self._capinfos, tshark, path, ctx.token)
        indexing = _Indexing(token=CancelToken(), report=ctx.progress, inline=inline)
        if resume is not None:
            # The saved rows are shown at once; the pass catches up behind them.
            indexing.resume, indexing.store = resume, resume.store
            indexing.first.set()
        ctx.token.on_cancel(indexing.token.cancel)
        if capture is not None:
            indexing.token.on_cancel(capture.abort)
        indexing.future = self._pool.submit(
            self._run_index, tshark, path, work_dir, columns, info, info_future, indexing,
            cache, key, capture,
        )  # fmt: skip
        self._last_index = indexing.future
        wait_for = indexing.first if stream else indexing.done
        while not wait_for.wait(0.1):
            ctx.token.raise_if_cancelled()
        ctx.token.raise_if_cancelled()
        rejected = {c for c in requested_columns if c not in columns}
        return self._attach(path, tshark, info, indexing, columns, rejected, cache, key, capture)

    def _live_source(
        self,
        live: tuple[CaptureOptions, Path] | None,
        follow: bool,
        command: list[str],
        path: Path,
        ctx: RequestContext,
    ) -> LiveSource | None:
        """The capture in progress the index pass reads, started (ToolError when
        dumpcap can't capture or the file can't be followed); None for a file."""
        capture: LiveSource
        if live is not None:
            capture = LiveCapture(command, live[0], path, lambda e: self.notify("capture", e))
        elif follow:
            capture = FollowFile(path, lambda e: self.notify("capture", e))
        else:
            return None
        capture.start(ctx.token)
        return capture

    def _attach(
        self,
        path: Path,
        tshark: Tshark,
        info: CaptureInfo,
        indexing: _Indexing,
        columns: list[str],
        rejected: set[str],
        cache: IndexCache | None,
        key: str | None,
        capture: LiveSource | None,
    ) -> dict[str, Any]:
        """Make the capture being indexed the open one; ``open``'s result."""
        inline = indexing.inline
        with self._lock:
            if indexing.error is not None:
                raise indexing.error
            assert indexing.store is not None
            complete = indexing.done.is_set()
            self._file = _Open(
                path,
                tshark,
                info,
                indexing.store,
                columns=columns,
                rejected=rejected,
                cache=cache,
                cache_key=key,
                capture=capture,
            )
            if capture is None or isinstance(capture, FollowFile):
                # (A followed file is read again once following ends: packets
                # written meanwhile can have comments too.)
                self._pool.submit(self._load_comments, self._file)
            else:
                self._file.comments_ready.set()  # (dumpcap writes no packet comments)
            if not complete:
                info.frames = len(indexing.store.rows)
                indexing.attached = True
                indexing.report = self._index_progress
                self._indexing = indexing
            self._next_filter_id += 1
            everything = FrameIndex.all(info.frames)
            self._view = _View(self._next_filter_id, "", everything, None, everything)
            result = self._open_result(self._file, indexing=not complete)
            if not complete and indexing.resume is not None:
                result["resumedAt"] = indexing.resume.known
            if inline is not None and inline.enabled:
                self._show_colors(inline, inline.colors)
                # (The pass keeps appending to inline.colors: published rows have theirs.)
                result["coloring"] = (
                    inline.summary() if complete else {"coloringId": inline.coloring_id}
                )
            return result

    def _show_colors(self, inline: _InlineColoring, colors: array[int]) -> None:
        """Make ``colors`` the list's coloring (under the lock)."""
        self._coloring_id += 1
        inline.coloring_id = self._coloring_id
        self._colors = colors

    def _open_result(self, f: _Open, *, indexing: bool = False) -> dict[str, Any]:
        result = f.info.to_json()
        result["columns"] = self._column_descriptors(f.columns)
        result["filterId"] = self._view.filter_id if self._view else 0
        result["indexing"] = indexing
        # Comment edits can be saved into the file itself only if it is plain pcapng.
        result["comments"] = {"inPlace": comments.is_pcapng(f.path)}
        if f.capture is not None:
            result["capture"] = f.capture.describe()
        return result

    def _run_index(
        self,
        tshark: Tshark,
        path: Path,
        work_dir: Path,
        columns: list[str],
        info: CaptureInfo,
        info_future: Future[dict[str, Any]] | None,
        indexing: _Indexing,
        cache: IndexCache | None,
        key: str | None,
        capture: LiveSource | None = None,
    ) -> None:
        """The index pass (in the pool). Rows become visible as they come
        (``indexing.first`` once there are some; at once for a live capture);
        finishing it completes the capture's info, updates an attached
        (streaming) capture and saves the index."""
        # Not `progress=indexing.report`: open() swaps it for notifications when it returns.
        ctx = RequestContext(token=indexing.token, progress=lambda p: indexing.report(p))  # noqa: PLW0108

        def rows_ready(store: _Store) -> None:
            indexing.store = store
            indexing.first.set()

        resume = indexing.resume
        try:
            try:
                base = self._index_pass(
                    tshark, path, work_dir, columns, info, ctx, base=True,
                    on_rows=None if resume else rows_ready, inline=indexing.inline,
                    live=capture, resume=resume,
                )  # fmt: skip
            except _ResumeMismatchError as exc:
                assert resume is not None
                print(  # noqa: T201 - stderr
                    f"pcap-viewer: can't resume indexing {path.name} ({exc}): indexing it again",
                    file=sys.stderr,
                    flush=True,
                )
                if cache is not None and key is not None:
                    cache.discard(key)
                resume = indexing.resume = None
                base = self._index_pass(
                    tshark, path, work_dir, columns, info, ctx, base=True,
                    on_rows=lambda store: self._replace_base(indexing, store),
                    inline=indexing.inline,
                )  # fmt: skip
            indexing.store = base
            if capture is not None:
                capture.join()  # the file is complete
                self._capture_ended(info, capture)
                info.size = path.stat().st_size
                meta = self._capinfos(tshark, path, indexing.token)
            else:
                assert info_future is not None
                meta = info_future.result()
            for name in ("start_time", "end_time", "link_type", "file_type"):
                if getattr(info, name) is None and meta.get(name) is not None:
                    setattr(info, name, meta[name])
            if info.start_time is None and len(base.rows):
                info.start_time = self._first_epoch(tshark, path, indexing.token)
        except BaseException as exc:  # noqa: BLE001 - handed to `open` or the client
            indexing.error = exc
            if capture is not None:
                capture.abort()
                capture.close_reader()
                capture.join()
        with self._lock:
            if indexing.error is None:
                assert indexing.store is not None
                info.frames = len(indexing.store.rows)
            indexing.done.set()
            indexing.first.set()
            attached = indexing.attached and self._indexing is indexing
            if attached:
                self._indexing = None
                done = self._finish_streaming(indexing)
        if attached:
            self.notify("index", done)
        if cache is not None and key is not None:
            self._save_index(cache, key, info, columns, indexing, resume)

    @staticmethod
    def _save_index(
        cache: IndexCache,
        key: str,
        info: CaptureInfo,
        columns: list[str],
        indexing: _Indexing,
        resume: _Resume | None,
    ) -> None:
        """Save a finished pass as a complete index (with its colors). A pass
        closed on the way (cancelled) keeps its rows as an incomplete entry,
        which the next open resumes from; anything else saves nothing."""
        store = indexing.store
        if store is None:
            return
        meta = {
            "info": info.to_json(),
            "fields": list(store.rows.fields),
            "names": list(store.fields),
            "columns": columns,
        }
        if indexing.error is None:
            cache.save(key, store.rows.path, store.rows.offsets, meta, complete=True)
            inline = indexing.inline
            if inline is not None and inline.enabled:
                extra = {"colored": inline.colored, "errors": inline.summary()["errors"]}
                cache.save_colors(key, rules_key(inline.raw), inline.colors, extra)
            return
        if not isinstance(indexing.error, CancelledError):
            return  # (tshark failed: resuming would fail again)
        # (While catching up, the saved entry already holds these rows.)
        known = resume.known if resume is not None and store is resume.store else 0
        if len(store.rows) > known:
            cache.save(key, store.rows.path, store.rows.offsets, meta, complete=False)

    def _resume_from(self, hit: CachedIndex, work_dir: Path) -> _Resume | None:
        """Resume from an unfinished saved index: a private copy of its rows
        (the pass appends to it), and the rows to compare (None if unusable)."""
        meta = hit.meta
        known = len(hit.offsets)
        if not known:
            return None
        self._store_seq += 1
        rows_path = work_dir / f"rows-{self._store_seq}.tsv"
        try:
            shutil.copyfile(hit.rows, rows_path)  # (not a hard link: it grows)
            fields, names = list(meta["fields"]), list(meta["names"])
            rows = RowStore.resume(rows_path, fields, array("Q", hit.offsets))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            print(f"pcap-viewer: can't resume indexing: {exc}", file=sys.stderr)  # noqa: T201
            return None
        if len(fields) != len(names):
            rows.close()
            return None
        samples = rows.raw(_sample_frames(known, RESUME_SAMPLES))
        return _Resume(
            store=_Store(rows, tuple(names)),
            known=known,
            samples=samples,
            pairs=list(zip(names, fields, strict=True)),
            columns=[str(c) for c in meta.get("columns", [])],
        )

    def _replace_base(self, indexing: _Indexing, store: _Store) -> None:
        """A resumed open fell back to indexing from scratch: once the new
        pass has rows, they replace the saved ones shown so far."""
        with self._lock:
            old, indexing.store = indexing.store, store
            f = self._file
            attached = indexing.attached and self._indexing is indexing and f is not None
            event: dict[str, Any] | None = None
            if attached and f is not None:
                f.base = store
                f.info.frames = len(store.rows)
                for cache in (self._filters, self._sorts, self._sort_columns):
                    cache.clear()
                view = self._view
                if view is not None and not view.expr:
                    view.matched = view.ordered = FrameIndex.all(f.info.frames)
                    view.sort = None
                event = {
                    "event": "progress",
                    "phase": "indexing",
                    "frames": f.info.frames,
                    "fraction": None,
                    "restarted": True,
                }
                counts = self._view_counts()
                if counts is not None:
                    event["view"] = counts
        if old is not None and old is not store:
            old.rows.close()
        if event is not None:
            self.notify("index", event)

    def _capture_ended(self, info: CaptureInfo, capture: LiveSource) -> None:
        """The capture or the following ended: its warnings, and a followed
        file's comments read again (packets written meanwhile can have some)."""
        with self._lock:
            f = self._file if isinstance(capture, FollowFile) else None
            if f is not None and f.capture is capture:
                f.comments_ready.clear()
                self._pool.submit(self._load_comments, f)
        if capture.error:
            what = "Following the file" if isinstance(capture, FollowFile) else "The capture"
            info.warnings.append(f"{what} stopped: {capture.error}")
        if capture.dropped:
            info.warnings.append(f"{capture.dropped:,} packets were dropped while capturing")

    def _index_progress(self, progress: Any) -> None:
        """A streaming open's "index" progress notification. With a filter
        applied, ``view`` says how many of its matches are shown by now."""
        event = {"event": "progress", **progress}
        with self._lock:
            view = self._view_counts()
        if view is not None:
            event["view"] = view
        self.notify("index", event)

    def _view_counts(self) -> dict[str, Any] | None:
        """``{filterId, matchCount}`` of the current filtered view (under the lock)."""
        if self._file is None or self._view is None or not self._view.expr:
            return None
        _f, view = self._require_view()
        return {"filterId": view.filter_id, "matchCount": len(view.matched)}

    def _finish_streaming(self, indexing: _Indexing) -> dict[str, Any]:
        """The end of a streaming index pass: update the capture (under the lock)
        and return the "index" notification to send."""
        f = self._file
        if f is None:
            return {"event": "failed", "message": "the capture was closed"}
        if indexing.error is not None:
            if isinstance(indexing.error, CancelledError):
                return {"event": "failed", "message": "indexing was cancelled"}
            message = str(indexing.error) or type(indexing.error).__name__
            f.info.warnings.append(
                f"Indexing stopped after {len(f.base.rows):,} packets: {message}"
            )
            f.info.frames = len(f.base.rows)
            failed = {"event": "failed", "message": message, "info": self._open_result(f)}
            counts = self._view_counts()
            if counts is not None:
                failed["view"] = counts
            return failed
        view = self._view
        if view is not None and not view.expr and view.sort is None:
            view.matched = view.ordered = FrameIndex.all(f.info.frames)
        done: dict[str, Any] = {"event": "done", "info": self._open_result(f)}
        inline = indexing.inline
        if inline is not None and inline.enabled and inline.coloring_id == self._coloring_id:
            done["coloring"] = inline.summary()
        counts = self._view_counts()
        if counts is not None:
            done["view"] = counts
        return done

    def _open_cached(
        self,
        path: Path,
        tshark: Tshark,
        hit: Any,
        work_dir: Path,
        cache: IndexCache,
        key: str,
        inline: _InlineColoring | None = None,
    ) -> dict[str, Any]:
        """Open from a saved index: no tshark pass at all (and the colors saved
        for these coloring rules, if any)."""
        meta = hit.meta
        rows_path = work_dir / "rows-cached.tsv"
        try:
            os.link(hit.rows, rows_path)  # instant, and safe if the cache entry goes away
        except OSError:
            shutil.copyfile(hit.rows, rows_path)
        store = _Store(RowStore(rows_path, meta["fields"], hit.offsets), tuple(meta["names"]))
        saved = meta["info"]
        info = CaptureInfo(
            path=str(path),
            frames=len(store.rows),
            start_time=saved.get("startTime"),
            end_time=saved.get("endTime"),
            link_type=saved.get("linkType"),
            file_type=saved.get("fileType"),
            size=path.stat().st_size,
            warnings=list(saved.get("warnings", [])),
        )
        columns = list(meta.get("columns", []))
        with self._lock:
            self._file = _Open(
                path, tshark, info, store, columns=columns, cache=cache, cache_key=key
            )
            self._pool.submit(self._load_comments, self._file)
            self._next_filter_id += 1
            everything = FrameIndex.all(info.frames)
            self._view = _View(self._next_filter_id, "", everything, None, everything)
            result = self._open_result(self._file)
            saved_colors = (
                cache.load_colors(key, rules_key(inline.raw), info.frames) if inline else None
            )
            if inline is not None and saved_colors is not None:
                colors, extra = saved_colors
                self._show_colors(inline, colors)
                inline.colored = int(extra.get("colored", 0))
                inline.errors.update({int(i): str(m) for i, m in extra.get("errors", {}).items()})
                result["coloring"] = inline.summary()
        result["fromCache"] = True
        return result

    def _known_switches(
        self, options: DissectionOptions, ctx: RequestContext
    ) -> tuple[DissectionOptions, list[str]]:
        """``options`` without the protocols and heuristic dissectors this
        tshark doesn't know (it won't start for one), and warnings for them."""
        if not options.protocols and not options.heuristics:
            return options, []
        known = self._protocol_list(self._require_tshark().with_options(options), ctx.token)
        return options.without_unknown(known.protocols, known.heuristics)

    def _index_key(
        self,
        tshark: Tshark,
        path: Path,
        options: DissectionOptions,
        columns: list[str],
        ctx: RequestContext,
    ) -> str | None:
        """The saved-index key of this capture with these settings (None if it
        can't be computed: then the index is neither loaded nor saved)."""
        try:
            version = self._tshark_versions.get(tshark.path)
            if version is None:
                version = tshark.version()
                self._tshark_versions[tshark.path] = version
            folders = _personal_folders(tshark.folders(ctx.token))
            profile = tshark.profile_config(ctx.token)
            if profile is not None:
                folders.append(profile[1])  # (a global profile is outside the personal folder)
            return index_key(
                capture=path,
                tshark=tshark.path,
                tshark_version=version,
                lua_scripts=list(options.lua_scripts),
                decode_as=list(options.decode_as),
                prefs=dict(options.prefs),
                columns=columns,
                config=folder_fingerprint(folders),
                names=options.names,
                profile=options.profile,
                switches=[list(options.protocols), list(options.heuristics)],
                secrets=list(options.secrets),
                files=list(options.files),
            )
        except (OSError, ToolError, ConfigError) as exc:
            print(f"pcap-viewer: index cache off for this capture: {exc}", file=sys.stderr)  # noqa: T201
            return None

    def _column_descriptors(self, custom: Sequence[str]) -> list[dict[str, Any]]:
        cols: list[dict[str, Any]] = [
            {"id": c.id, "title": c.title, "field": c.field, "numeric": c.numeric}
            for c in BASE_COLUMNS
        ]
        cols += [{"id": f, "title": f, "field": f, "numeric": False} for f in custom]
        return cols

    @staticmethod
    def _check_fields(fields: Iterable[str]) -> list[str]:
        out: list[str] = []
        for raw in fields:
            name = raw.strip()
            if not name:
                continue
            if not _FIELD_NAME_RE.match(name):
                raise InvalidParamsError(f"invalid field name {name!r}")
            if name not in out:
                out.append(name)
        return out

    def _index_pass(
        self,
        tshark: Tshark,
        path: Path,
        work_dir: Path,
        custom: list[str],
        info: CaptureInfo,
        ctx: RequestContext,
        *,
        base: bool,
        on_rows: Callable[[_Store], None] | None = None,
        inline: _InlineColoring | None = None,
        live: LiveSource | None = None,
        resume: _Resume | None = None,
    ) -> _Store:
        """Run one ``-T fields`` pass, writing every frame's row to a RowStore.

        Retries without fields tshark rejects (unknown custom columns, or the
        column field names of older tshark versions). Rows are published as
        they come; ``on_rows`` gets the store once the first ones are readable
        (FIRST_BATCH rows, or FIRST_BATCH_S with at least one). With ``inline``
        (base pass only), the coloring rules are evaluated too: the last field
        is the matching rule, kept in ``inline.colors`` (not in the row store).

        With ``live``, tshark reads the capture's pipe (``-r - -l``) and
        ``on_rows`` gets the store at once. That stream can be read only once,
        so the fields are first tried against the empty capture (tshark checks
        them before reading any packet) and the retries happen there.

        With ``resume`` (base pass), the pass goes on from an unfinished saved
        index: same fields, the saved store (``on_rows`` already had it), and
        rows 1…``resume.known`` compared instead of stored (_read_rows). Raises
        _ResumeMismatchError when they don't match (or tshark refuses those fields).
        """
        pairs, unresolved = _pass_fields(tshark, custom, base=base, resume=resume)
        legacy = {c.field: c.legacy_field for c in BASE_COLUMNS}
        size = max(1, info.size)
        overhead = _RECORD_OVERHEAD.get(sniff_format(path) or "") if base and not live else None
        if not base:
            inline = None
        env = self._coloring_env(tshark, work_dir, inline, ctx) if inline else None
        for _attempt in range(4):
            self._store_seq += 1
            store_path = work_dir / f"rows-{self._store_seq}.tsv"
            actual = [a for _, a in pairs]
            store = _attempt_store(pairs, store_path, resume)
            rows = store.rows
            # tshark blanks duplicated -e fields, so only prepend frame.number
            # when it is not already the first column.
            fields = actual if base else ["frame.number", *actual]
            color_args: list[str] = []
            if inline is not None:
                fields = [*fields, _COLOR_FIELD]
                color_args = ["--color"]
                _reset_colors(inline)
            column_args = ["-o", _UNRESOLVED_FORMAT] if unresolved else []
            options = [*column_args, *color_args, *_fields_args(fields)]
            tracker = _PassProgress(ctx, store, on_rows, size, overhead, resume)
            result, bad_lines = _stream_rows(
                lambda result: _pass_lines(tshark, path, options, result, ctx, env, live, tracker),  # noqa: B023 - called at once
                tracker,
                base=base,
                inline=inline,
                unresolved=unresolved,
            )
            # (A live pass that fails after its probe has no rejected fields to
            # retry without: the stream is read once.)
            if result.lines == 0 and result.returncode not in (0, None):
                if resume is not None:  # (never delete the saved rows' copy)
                    raise _ResumeMismatchError("tshark refused the saved columns")
                rows.close()
                store_path.unlink(missing_ok=True)
                rejected = _rejected_fields(result.stderr)
                if inline is not None and _COLOR_FIELD in rejected:
                    inline.enabled, inline, env = False, None, None  # index without colors
                    continue
                if unresolved and set(UNRESOLVED_FIELDS) & set(rejected):
                    unresolved = False  # cell filters then only work on addresses shown
                    pairs = [p for p in pairs if p[1] not in UNRESOLVED_FIELDS]
                    continue
                if rejected and _drop_rejected(pairs, rejected, legacy, custom, info.warnings):
                    continue
                raise _index_error(tshark, path, result)
            _finish_index_pass(info, result, bad_lines, len(rows), inline)
            ctx.progress({"phase": "indexing", "frames": len(rows), "fraction": 1.0})
            # Columns are exposed under the names the caller asked for.
            return store
        raise ToolError("tshark rejected the requested columns")

    @staticmethod
    def _coloring_env(
        tshark: Tshark, work_dir: Path, inline: _InlineColoring, ctx: RequestContext
    ) -> dict[str, str]:
        """Environment for a pass that evaluates ``inline``'s rules: tshark reads
        them only from its personal config folder (see coloring.py)."""
        color_dir = work_dir / "colorfilters"
        color_dir.mkdir(exist_ok=True)
        personal = coloring.personal_config_dir(tshark.folders(ctx.token))
        coloring.prepare_config_dir(
            color_dir, inline.rules, personal, tshark.profile_config(ctx.token)
        )
        return {**os.environ, "WIRESHARK_CONFIG_DIR": str(color_dir)}

    def _capinfos(self, tshark: Tshark, path: Path, token: CancelToken) -> dict[str, Any]:
        if tshark.capinfos is None:
            return {}
        try:
            res = run(
                [str(tshark.capinfos), "-T", "-M", "-a", "-e", "-E", "-S", "-t", str(path)], token
            )
        except (OSError, CancelledError):
            return {}
        return parse_capinfos(res.stdout.decode("utf-8", "replace"))

    @staticmethod
    def _first_epoch(tshark: Tshark, path: Path, token: CancelToken) -> float | None:
        res = run(
            tshark.argv("-c", "1", "-T", "fields", "-e", "frame.time_epoch", capture=str(path)),
            token,
        )
        try:
            return float(res.stdout.decode().strip())
        except ValueError:
            return None

    def capture_info(self, _params: dict[str, Any], _ctx: RequestContext) -> dict[str, Any]:
        f = self._require_file()
        result = f.info.to_json()
        result["columns"] = self._column_descriptors(f.columns)
        return result
