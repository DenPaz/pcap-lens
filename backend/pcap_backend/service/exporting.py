"""Exports: captures, the packet list, dissections and packet bytes."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from pcap_backend import navigation
from pcap_backend.cache import FrameIndex
from pcap_backend.export import (
    CAPTURE_FORMATS,
    DISSECTION_FORMATS,
    EXPORT_KINDS,
    LIST_FORMATS,
    DissectionWriter,
    PacketListWriter,
    atomic_output,
    check_destination,
)
from pcap_backend.protocol import FilterError, InvalidParamsError, RequestContext, param, str_list
from pcap_backend.tshark import (
    StreamResult,
    ToolError,
    ToolNotFoundError,
    find_tool,
    run,
    stream_lines,
)

from .detail import DetailMixin
from .helpers import _frame_list, _stderr_warnings
from .packets import PacketsMixin
from .state import _TRUNCATION_HINTS, BASE_COLUMNS, MAX_FILTER_ARG, PROGRESS_INTERVAL_S, _Open

EXPORT_CHUNK = 5000


class ExportMixin(DetailMixin, PacketsMixin):
    """Exports: captures, the packet list, dissections and packet bytes."""

    def export_tls_keys(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Export TLS Session Keys: the keys of the TLS sessions tshark could
        decrypt (a key log, a Decryption Secrets Block…) as a key log file at
        ``dest`` (``tshark --export-tls-session-keys``, over the TLS packets:
        with ``-q`` alone tshark decrypts nothing). Returns ``{sessions}``; a
        capture without any is an InvalidParamsError and writes nothing."""
        f = self._require_file()
        dest = check_destination(param(params, "dest", str), f.path)
        ctx.progress({"phase": "export", "fraction": None})
        with atomic_output(dest) as tmp:
            argv = f.tshark.argv(
                "-Y", "tls", "-T", "fields", "-e", "frame.number",
                "--export-tls-session-keys", str(tmp), capture=str(f.path),
            )  # fmt: skip
            res = run(argv, ctx.token)
            if res.returncode != 0 and not tmp.exists():
                raise f.tshark.error(res.stderr, res.returncode, "exporting TLS keys failed")
            try:
                text = tmp.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            sessions = sum(
                1 for line in text.split("\n") if line.strip() and not line.startswith("#")
            )
            if not sessions:
                raise InvalidParamsError(
                    "this capture has no decrypted TLS sessions: set a TLS key log file first",
                    {"empty": True},
                )
        return {"sessions": sessions, "path": str(dest)}

    def export(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Write an export file at ``dest`` (absolute path, never the open capture).

        ``kind``:

        * ``pcapng`` / ``pcap``: packets matching ``filter`` (default: the current
          display filter; ``""`` for all packets), written by tshark. Or the
          marked packets (``marked: true``) or the packets in ``frames`` (a
          multi-selection).
        * ``csv`` / ``json``: the packet list of the current view, in its current
          order, with the base columns plus ``columns`` (custom fields; titles in
          the parallel ``titles`` list); only the rows of ``frames`` if given.
        * ``bytes``: the raw bytes of frame ``number`` (data ``source`` index,
          default 0: the frame itself).
        * ``dissections``: tshark's full packet details, ``format`` ``text``
          (``-V``), ``pdml`` or ``json``, with the hex bytes too if ``bytes``;
          packets chosen as for pcapng (filter, ``marked`` or ``frames``).

        Ignored packets (``ignore_packets``) are never exported, except as bytes.

        The file only appears once complete; cancelling leaves nothing behind.
        """
        kind = param(params, "kind", str)
        if kind not in EXPORT_KINDS:
            raise InvalidParamsError(f"kind must be one of {', '.join(EXPORT_KINDS)}")
        f = self._require_file()
        dest = check_destination(param(params, "dest", str), f.path)
        if kind in CAPTURE_FORMATS:
            result = self._export_capture(f, kind, dest, params, ctx)
        elif kind in LIST_FORMATS:
            result = self._export_list(f, kind, dest, params, ctx)
        elif kind == "dissections":
            result = self._export_dissections(f, dest, params, ctx)
        else:
            result = self._export_bytes(dest, params, ctx)
        result.update({"ok": True, "path": str(dest), "size": dest.stat().st_size})
        return result

    def _chosen_frames(self, f: _Open, params: dict[str, Any]) -> tuple[list[int], str] | None:
        """The marked (``marked: true``) or selected (``frames``) packets an
        export takes, minus the ignored ones, and their label; None when the
        export takes a filter instead."""
        if params.get("marked"):
            with self._lock:
                frames = sorted(self._marks - self._ignored)
                none = "No packets are marked" if not self._marks else None
            label = "marked packets"
        elif "frames" in params:
            n_frames = f.frame_count()
            chosen = {n for n in _frame_list(params, "frames") if 1 <= n <= n_frames}
            with self._lock:
                frames = sorted(chosen - self._ignored)
            none = "No packets are selected" if not chosen else None
            label = "selected packets"
        else:
            return None
        if not frames:
            raise InvalidParamsError(none or f"Every one of the {label} is ignored")
        return frames, label

    def _export_capture(
        self, f: _Open, fmt: str, dest: Path, params: dict[str, Any], ctx: RequestContext
    ) -> dict[str, Any]:
        chosen = self._chosen_frames(f, params)
        if chosen is not None:
            return self._export_frames(f, fmt, dest, *chosen, ctx)
        if "filter" in params:
            flt = param(params, "filter", str, "").strip()
        else:
            flt = self._require_view()[1].expr
        if flt:
            error = f.tshark.validate_filter(flt, ctx.token)
            if error:
                raise FilterError(error, {"expr": flt})
        result = self._write_capture(f, fmt, dest, self._without_ignored(flt), ctx)
        result["filter"] = flt
        return result

    def _write_capture(
        self, f: _Open, fmt: str, dest: Path, flt: str, ctx: RequestContext
    ) -> dict[str, Any]:
        """The packets matching ``flt`` (a checked filter; ``""`` = all) to a capture."""
        packets = 0
        with atomic_output(dest) as tmp:
            if flt:
                # -P prints each written packet's number: that is our progress.
                argv = f.tshark.argv(
                    "-Y", flt, "-F", fmt, "-w", str(tmp),
                    "-P", "-T", "fields", "-e", "frame.number",
                    capture=str(f.path),
                )  # fmt: skip
            else:
                # Every packet: nothing to dissect, tshark just copies records.
                argv = f.tshark.argv("-F", fmt, "-w", str(tmp), capture=str(f.path), dissect=False)
            result = StreamResult()
            total = max(1, f.info.frames)
            last_emit = 0.0
            ctx.progress({"phase": "export", "fraction": None})
            for line in stream_lines(argv, result, ctx.token):
                try:
                    n = int(line)
                except ValueError:
                    continue
                packets += 1
                now = time.monotonic()
                if now - last_emit >= PROGRESS_INTERVAL_S:
                    last_emit = now
                    ctx.progress({"phase": "export", "fraction": min(0.99, n / total)})
            truncated = any(h in result.stderr for h in _TRUNCATION_HINTS)
            if result.returncode not in (0, None) and not (truncated and tmp.exists()):
                raise f.tshark.error(
                    result.stderr, result.returncode, f"tshark exited with code {result.returncode}"
                )
            if not tmp.exists():
                raise f.tshark.error(
                    result.stderr, result.returncode, "tshark wrote no output file"
                )
        return {
            "packets": packets if flt else f.info.frames,
            "filter": flt,
            "warnings": _stderr_warnings(result.stderr),
        }

    def _export_frames(
        self, f: _Open, fmt: str, dest: Path, frames: list[int], label: str, ctx: RequestContext
    ) -> dict[str, Any]:
        """Some frames (marked or selected) to a capture: ``frame.number in {...}``
        (ranges compressed).

        A filter longer than MAX_FILTER_ARG would overflow the command line
        (Windows caps it at 32767 characters), so big frame sets are written in
        chunks and joined in frame order with ``mergecap -a``.
        """
        filters = navigation.frame_set_filters(frames, MAX_FILTER_ARG)
        if len(filters) == 1:
            result = self._write_capture(f, fmt, dest, filters[0], ctx)
            result["filter"] = label
            return result
        try:
            mergecap = find_tool("mergecap", sibling_of=f.tshark.path)
        except ToolNotFoundError as exc:
            raise ToolError(
                f"{len(frames):,} {label} need mergecap (part of Wireshark), "
                "which was not found; export fewer packets or install mergecap"
            ) from exc
        assert self._work_dir is not None
        parts: list[Path] = []
        packets = 0
        warnings: list[str] = []
        try:
            for i, flt in enumerate(filters):
                ctx.token.raise_if_cancelled()
                part = self._work_dir / f"frames-{i}.{fmt}"
                parts.append(part)
                res = self._write_capture(f, fmt, part, flt, ctx)
                packets += res["packets"]
                warnings += res["warnings"]
                ctx.progress({"phase": "export", "fraction": min(0.99, (i + 1) / len(filters))})
            with atomic_output(dest) as tmp:
                merged = run(
                    [str(mergecap), "-a", "-F", fmt, "-w", str(tmp), *map(str, parts)], ctx.token
                )
                if merged.returncode != 0 or not tmp.exists():
                    raise ToolError(
                        merged.stderr or "mergecap failed", merged.stderr, merged.returncode
                    )
        finally:
            for part in parts:
                part.unlink(missing_ok=True)
        return {"packets": packets, "filter": label, "warnings": warnings}

    def _export_list(
        self, f: _Open, fmt: str, dest: Path, params: dict[str, Any], ctx: RequestContext
    ) -> dict[str, Any]:
        self._require_complete()
        _f, view = self._require_view()
        base_fields = {c.field for c in BASE_COLUMNS}
        requested = str_list(params, "columns") if "columns" in params else list(f.columns)
        titles = str_list(params, "titles")
        title_of = {
            fld: (titles[i] if i < len(titles) and titles[i].strip() else fld)
            for i, fld in enumerate(requested)
        }
        custom = [c for c in self._check_fields(requested) if c not in base_fields]
        self._ensure_columns(f, custom, ctx)
        custom = [c for c in custom if c not in f.rejected]
        headers = [c.title for c in BASE_COLUMNS] + [title_of.get(c, c) for c in custom]
        keys = [c.id for c in BASE_COLUMNS] + custom
        numeric = [c.numeric for c in BASE_COLUMNS] + [False] * len(custom)
        ordered = view.ordered
        with self._lock:
            ignored = set(self._ignored)
        if "frames" in params:
            wanted = set(_frame_list(params, "frames")) - ignored
            ordered = FrameIndex.of(n for n in ordered.frames() if n in wanted)
        elif ignored:
            ordered = FrameIndex.of(n for n in ordered.frames() if n not in ignored)
        total = len(ordered)
        n_base = len(BASE_COLUMNS)
        with atomic_output(dest) as tmp, tmp.open("w", encoding="utf-8", newline="") as fh:
            writer = PacketListWriter(fh, fmt, headers, keys, numeric)
            for offset in range(0, total, EXPORT_CHUNK):
                ctx.token.raise_if_cancelled()
                frames = ordered.slice(offset, EXPORT_CHUNK)
                base_rows = f.base.rows.get_many(frames)
                extra = [self._column_cells(f, fld, frames) for fld in custom]
                writer.write(
                    base_rows[i][:n_base] + [col[i] for col in extra] for i in range(len(frames))
                )
                ctx.progress(
                    {"phase": "export", "fraction": min(0.99, (offset + len(frames)) / total)}
                )
            writer.close()
        label = "selected packets" if "frames" in params else view.expr
        return {"packets": total, "filter": label, "columns": keys}

    def _export_scope(
        self, f: _Open, params: dict[str, Any]
    ) -> tuple[list[str], str, int | None, str]:
        """Which packets an export takes, as display filters (one pass each;
        ``""`` = every packet): (filters, label, expected packets if known,
        the user's filter to validate, if any). Ignored packets are left out."""
        chosen = self._chosen_frames(f, params)
        if chosen is not None:
            frames, label = chosen
            return navigation.frame_set_filters(frames, MAX_FILTER_ARG), label, len(frames), ""
        _f, view = self._require_view()
        flt = param(params, "filter", str, "").strip() if "filter" in params else view.expr
        with self._lock:
            n_ignored = len(self._ignored)
        known = flt == view.expr and view.live is None and view.partial is None
        if not flt:
            expected: int | None = max(0, f.info.frames - n_ignored)
        elif known and not n_ignored:
            expected = len(view.matched)
        else:
            expected = None
        return [self._without_ignored(flt)], flt, expected, flt

    def _export_dissections(
        self, f: _Open, dest: Path, params: dict[str, Any], ctx: RequestContext
    ) -> dict[str, Any]:
        """Full dissections (Wireshark's "Export Packet Dissections"), streamed
        from tshark to the file; big frame sets are filtered in chunks and joined."""
        fmt = param(params, "format", str, "text")
        if fmt not in DISSECTION_FORMATS:
            raise InvalidParamsError(f"format must be one of {', '.join(DISSECTION_FORMATS)}")
        filters, label, expected, user_filter = self._export_scope(f, params)
        if user_filter:
            error = f.tshark.validate_filter(user_filter, ctx.token)
            if error:
                raise FilterError(error, {"expr": user_filter})
        options = [*DISSECTION_FORMATS[fmt], *(["-x"] if params.get("bytes") else [])]
        packets = 0
        warnings: list[str] = []
        last_emit = 0.0
        ctx.progress({"phase": "export", "fraction": None})
        with atomic_output(dest) as tmp, tmp.open("wb") as out:
            writer = DissectionWriter(fmt, out)
            for flt in filters:
                writer.next_pass()
                argv = f.tshark.argv(*(["-Y", flt] if flt else []), *options, capture=str(f.path))
                result = StreamResult()
                for line in stream_lines(argv, result, ctx.token):
                    if not writer.line(line):
                        continue
                    packets += 1
                    now = time.monotonic()
                    if expected and now - last_emit >= PROGRESS_INTERVAL_S:
                        last_emit = now
                        fraction = min(0.99, packets / expected)
                        ctx.progress({"phase": "export", "fraction": fraction})
                truncated = any(h in result.stderr for h in _TRUNCATION_HINTS)
                if result.returncode not in (0, None) and not (truncated and result.lines):
                    raise f.tshark.error(
                        result.stderr, result.returncode, "tshark could not dissect the packets"
                    )
                warnings += _stderr_warnings(result.stderr)
            writer.close()
        return {"packets": packets, "filter": label, "format": fmt, "warnings": warnings}

    def _export_bytes(
        self, dest: Path, params: dict[str, Any], ctx: RequestContext
    ) -> dict[str, Any]:
        number = param(params, "number", int)
        source = param(params, "source", int, 0)
        sources = self.packet_detail({"number": number}, ctx)["sources"]
        if not 0 <= source < len(sources):
            raise InvalidParamsError(f"frame {number} has no data source {source}")
        data = bytes.fromhex(sources[source]["hex"])
        with atomic_output(dest) as tmp:
            tmp.write_bytes(data)
        return {"number": number, "source": sources[source]["name"], "bytes": len(data)}
