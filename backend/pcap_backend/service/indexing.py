"""The index pass's helpers: tshark's field output into the row store, inline colors, resuming."""

from __future__ import annotations

from collections.abc import Callable, Generator, Iterable, Sequence
from pathlib import Path
from typing import Any

from pcap_backend import coloring
from pcap_backend.cache import RowStore
from pcap_backend.capture import LiveCapture
from pcap_backend.index_cache import IndexCache
from pcap_backend.protocol import InvalidParamsError, RequestContext, UnsupportedFormatError
from pcap_backend.tshark import EMPTY_CAPTURE, StreamResult, ToolError, Tshark, run, stream_lines

from .helpers import _parse_rules, _stderr_warnings
from .state import (
    _UNSUPPORTED_RE,
    BASE_COLUMNS,
    UNRESOLVED_FIELDS,
    CaptureInfo,
    _InlineColoring,
    _PassProgress,
    _Resume,
    _ResumeMismatchError,
    _Store,
)

DEFAULT_CACHE_BYTES = 1 << 30


def _index_error(tshark: Tshark, path: Path, result: StreamResult) -> Exception:
    """The error for an index pass that produced nothing."""
    if _UNSUPPORTED_RE.search(result.stderr):
        return UnsupportedFormatError(
            f"{path.name} is not a capture file that tshark can read",
            {"path": str(path), "stderr": result.stderr},
        )
    return tshark.error(
        result.stderr, result.returncode, f"tshark exited with code {result.returncode}"
    )


def _cache_from(raw: Any) -> IndexCache | None:
    """``{dir, maxBytes?}`` -> the saved-index cache (None: caching off)."""
    if not isinstance(raw, dict) or not isinstance(raw.get("dir"), str) or not raw["dir"]:
        return None
    max_bytes = raw.get("maxBytes", DEFAULT_CACHE_BYTES)
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0:
        raise InvalidParamsError("cache.maxBytes must be a non-negative integer")
    return IndexCache(Path(raw["dir"]).expanduser(), max_bytes)


def _personal_folders(folders_output: str) -> list[Path]:
    """tshark's personal configuration and plugin folders (``tshark -G folders``):
    their contents change dissection, so they are part of the saved-index key."""
    wanted = {"Personal configuration", "Personal Plugins", "Personal Lua Plugins"}
    out: list[Path] = []
    for line in folders_output.split("\n"):
        name, sep, value = line.partition(":")
        if sep and name.strip() in wanted and value.strip():
            out.append(Path(value.strip()))
    return out


def _drop_rejected(
    pairs: list[tuple[str, str]],
    rejected: Sequence[str],
    legacy: dict[str, str],
    custom: list[str],
    warnings: list[str],
) -> bool:
    """Swap in legacy column names / drop unknown custom fields. True if anything changed."""
    changed = False
    for bad in rejected:
        for i, (name, actual) in enumerate(pairs):
            if actual != bad:
                continue
            if legacy.get(name, name) != actual:
                pairs[i] = (name, legacy[name])
            elif name in custom:
                del pairs[i]
                custom.remove(name)
                warnings.append(f"Unknown field removed from columns: {name}")
            else:
                continue
            changed = True
            break
    return changed


def _pass_lines(
    tshark: Tshark,
    path: Path,
    options: list[str],
    result: StreamResult,
    ctx: RequestContext,
    env: dict[str, str] | None,
    live: LiveCapture | None,
    tracker: _PassProgress,
) -> Iterable[bytes] | None:
    """An index pass's output lines. A live capture's pipe can be read once,
    so its fields are tried against the empty capture first: None if tshark
    rejected them (``result`` then holds its complaint, for a retry)."""
    if live is None:
        return stream_lines(tshark.argv(*options, capture=str(path)), result, ctx.token, env=env)
    probe = run(tshark.argv(*options, capture=str(EMPTY_CAPTURE.get())), ctx.token, env)
    if probe.returncode != 0:
        result.returncode, result.stderr = probe.returncode, probe.stderr
        return None
    tracker.ready()
    argv = tshark.argv("-l", *options, capture="-")
    return stream_lines(argv, result, ctx.token, env=env, stdin=live.take_reader())


def _pass_fields(
    tshark: Tshark, custom: list[str], *, base: bool, resume: _Resume | None
) -> tuple[list[tuple[str, str]], bool]:
    """An index pass's (name the caller asked for, name passed to tshark)
    pairs, and whether they end with the UNRESOLVED_FIELDS. A resumed pass
    uses the fields its saved rows were indexed with."""
    if resume is not None:
        pairs = list(resume.pairs)
        return pairs, UNRESOLVED_FIELDS[0] in {a for _, a in pairs}
    pairs = [(c.field, c.field) for c in BASE_COLUMNS] if base else []
    pairs += [(fld, fld) for fld in custom]
    unresolved = base and tshark.options.resolves_addresses
    if unresolved:
        pairs += [(fld, fld) for fld in UNRESOLVED_FIELDS]
    return pairs, unresolved


def _attempt_store(pairs: list[tuple[str, str]], path: Path, resume: _Resume | None) -> _Store:
    """The store an index pass attempt writes: a new one at ``path``, or a
    resumed pass's saved rows (its fields must be the ones it was saved with)."""
    actual = tuple(a for _, a in pairs)
    names = tuple(name for name, _ in pairs)
    if resume is None:
        return _Store(RowStore(path, actual), names)
    if actual != resume.store.rows.fields or names != resume.store.fields:
        raise _ResumeMismatchError("the columns changed")
    return resume.store


def _reset_colors(inline: _InlineColoring) -> None:
    """Forget the colors of an earlier attempt, in place (a resumed open
    already shows this array)."""
    del inline.colors[1:]
    inline.colored = 0


def _stream_rows(
    start: Callable[[StreamResult], Iterable[bytes] | None],
    tracker: _PassProgress,
    *,
    base: bool,
    inline: _InlineColoring | None,
    unresolved: bool,
) -> tuple[StreamResult, int]:
    """Run an index pass attempt (``start`` gives its output lines) into
    ``tracker``'s store; returns tshark's result and the unparseable lines."""
    result = StreamResult()
    rows = tracker.store.rows
    lines: Iterable[bytes] | None = None
    try:
        lines = start(result)
        bad_lines = _read_rows(
            lines or iter(()), rows, tracker, base=base, inline=inline, unresolved=unresolved
        )
    finally:
        if isinstance(lines, Generator):
            lines.close()  # (stops tshark when a resumed pass's rows didn't match)
        rows.finish()
    # A cancelled pass is never a finished one, however its output ended.
    tracker.ctx.token.raise_if_cancelled()
    return result, bad_lines


def _finish_index_pass(
    info: CaptureInfo,
    result: StreamResult,
    bad_lines: int,
    frames: int,
    inline: _InlineColoring | None,
) -> None:
    """Warnings and coloring results of a finished index pass."""
    if result.returncode is not None and result.returncode < 0:
        # Killed by a signal (not by us: that raises CancelledError): its
        # output ended early, so this is not the whole capture.
        raise ToolError(
            f"tshark was stopped (signal {-result.returncode}) after {frames:,} packets"
        )
    if bad_lines:
        info.warnings.append(f"{bad_lines} unparseable line(s) in tshark output skipped")
    if result.stderr:
        info.warnings += _stderr_warnings(result.stderr)
    if inline is not None:
        inline.errors.update(coloring.parse_compile_errors(result.stderr))
        while len(inline.colors) <= frames:  # one byte per frame, like set_coloring
            inline.colors.append(0)


def _names_param(params: dict[str, Any]) -> dict[str, Any] | None:
    """The optional ``names`` switches (pcapViewer.nameResolution.*)."""
    names = params.get("names")
    if names is not None and not isinstance(names, dict):
        raise InvalidParamsError("parameter 'names' must be dict")
    return names


def _inline_coloring(raw: Any) -> _InlineColoring | None:
    """``open``'s ``coloring: {rules}`` (None without valid rules)."""
    if raw is None:
        return None
    if not isinstance(raw, dict) or not isinstance(raw.get("rules"), list):
        raise InvalidParamsError("parameter 'coloring' must be {rules: [...]}")
    rules, errors = _parse_rules(raw["rules"])
    if not any(isinstance(r, coloring.ColorRule) for r in rules):
        return None
    return _InlineColoring(raw["rules"], rules, errors)


def _sample_frames(known: int, count: int) -> list[int]:
    """Frames 1…``known`` a resumed pass compares: ``count`` evenly spread,
    always including the first and the last (``known``)."""
    step = max(1, known // max(1, count))
    return sorted({1, known, *range(step, known, step)})


def _read_rows(
    lines: Iterable[bytes],
    rows: RowStore,
    tracker: _PassProgress,
    *,
    base: bool,
    inline: _InlineColoring | None,
    unresolved: bool = False,
) -> int:
    """Store an index pass's rows (and colors); returns the unparseable lines.

    With ``unresolved``, the row ends with the UNRESOLVED_FIELDS, which are
    blanked when they equal the Source/Destination shown (the usual case).

    A resumed pass (``tracker.resume``) doesn't store rows 1…``known`` again:
    it compares the sampled ones with the saved rows and raises
    _ResumeMismatchError if they differ, or if the capture ends before ``known``."""
    bad_lines = 0
    resume = tracker.resume
    known = resume.known if resume is not None else 0
    token = tracker.ctx.token
    last = 0
    for line in lines:
        if token.cancelled:
            break  # (tshark's buffered output would still come)
        parts = line.split(b"\t", 1)
        try:
            number = int(parts[0])
        except ValueError:
            bad_lines += 1
            continue
        row = line
        if inline is not None:
            row, _sep, rule = line.rpartition(b"\t")
            _add_color(inline, number, rule)  # before the row is published
        if unresolved:
            row = _blank_same_addresses(row)
        rest = row if base else (parts[1] if len(parts) > 1 else b"")
        last = number
        if resume is not None and number <= known:
            saved = resume.samples.get(number)
            if saved is not None and rest != saved:
                raise _ResumeMismatchError(f"packet {number} differs from its saved row")
            resume.caught_up = number == known
            tracker.row(number, rest)
            continue
        rows.append(number, rest)
        tracker.row(number, rest)
    if resume is not None and not resume.caught_up and not token.cancelled:
        raise _ResumeMismatchError(f"the capture ended at packet {last:,}, before {known:,}")
    return bad_lines


def _blank_same_addresses(row: bytes) -> bytes:
    """Blank the trailing unresolved addresses that equal Source/Destination."""
    head, src, dst = row.rsplit(b"\t", 2) if row.count(b"\t") >= 2 else (row, b"", b"")
    cells = head.split(b"\t", 4)
    if len(cells) < 4 or (src != cells[2] and dst != cells[3]):
        return row
    return b"\t".join((head, b"" if src == cells[2] else src, b"" if dst == cells[3] else dst))


def _add_color(inline: _InlineColoring, number: int, rule: bytes) -> None:
    """Record frame ``number``'s matching rule (tshark names rules by index)."""
    colors = inline.colors
    while len(colors) < number:  # (frames are dense; pad like the row store would)
        colors.append(0)
    idx = int(rule) if rule.isdigit() else -1
    if 0 <= idx < len(inline.rules):
        colors.append(idx + 1)
        inline.colored += 1
    else:
        colors.append(0)


def parse_capinfos(text: str) -> dict[str, Any]:
    """Parse ``capinfos -T -M -a -e -E -S -t`` table output (header row + value row)."""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) < 2:
        return {}
    header = lines[0].split("\t")
    values = lines[1].split("\t")
    extra = len(values) - len(header)
    if extra > 0:  # the file name (first column) contained tabs
        values = ["\t".join(values[: extra + 1]), *values[extra + 1 :]]
    row = dict(zip(header, values, strict=False))

    def num(key: str) -> float | None:
        try:
            return float(row.get(key, ""))
        except ValueError:
            return None

    return {
        "start_time": num("Start time"),
        "end_time": num("End time"),
        "link_type": row.get("File encapsulation") or None,
        "file_type": row.get("File type") or None,
    }
