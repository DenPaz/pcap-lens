"""Display filter help: hints for a filter that matches nothing, and the
values a field takes (the filter builder)."""

from __future__ import annotations

from collections.abc import Generator
from typing import Any

from pcap_backend import filterhelp
from pcap_backend.protocol import FilterError, InvalidParamsError, RequestContext, param
from pcap_backend.tshark import StreamResult, stream_lines

from .dissection import DissectionMixin

# field_values: the most frequent values returned (of up to filterhelp.MAX_DISTINCT).
MAX_VALUES = 200
# filter_hints: fields of one expression looked for (the first ones).
MAX_HINT_FIELDS = 8


class FilterHelpMixin(DissectionMixin):
    """Display filter help: empty-result hints and field values."""

    def filter_hints(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Why ``expr`` might match nothing: which of the fields it names occur
        in no packet of the capture (``fields: [{name, present}]``, one fields
        pass that stops once every field was seen), and ``caseHints`` for
        case-sensitive string comparisons (``field == "Text"``) with the
        case-insensitive filter to try. Cached per expression."""
        expr = param(params, "expr", str).strip()
        if not expr:
            raise InvalidParamsError("expr is empty")
        f = self._require_file()
        cached = self._filter_hints.get(expr)
        if cached is not None:
            return cached
        error = f.tshark.validate_filter(expr, ctx.token)
        if error:
            raise FilterError(error, {"expr": expr})
        catalog = self._catalog(ctx)
        names = filterhelp.filter_fields(expr, catalog.__contains__)[:MAX_HINT_FIELDS]
        present = {n for n in names if filterhelp.always_present(n)}
        look = [n for n in names if n not in present]
        if look:
            present |= self._fields_present(look, ctx)

        def type_of(name: str) -> str | None:
            entry = catalog.lookup(name)
            return entry.get("type") if entry else None

        result = {
            "expr": expr,
            "fields": [{"name": n, "present": n in present} for n in names],
            "caseHints": [h for h in filterhelp.case_hints(expr, type_of) if h["field"] in present],
        }
        if self._indexing is None:  # (a growing capture may still gain them)
            self._filter_hints.put(expr, result)
        return result

    def _fields_present(self, names: list[str], ctx: RequestContext) -> set[str]:
        """Which of ``names`` occur in some packet: one ``-Y "a || b"`` fields
        pass, stopped as soon as each one was seen."""
        f = self._require_file()
        expr = " || ".join(f"({n})" for n in names)
        fields: list[str] = []
        for n in names:
            fields += ["-e", n]
        argv = f.tshark.argv(
            "-Y", expr, "-T", "fields", "-E", "occurrence=f", *fields, capture=str(f.path)
        )
        seen: set[str] = set()
        result = StreamResult()
        lines = stream_lines(argv, result, ctx.token)
        try:
            for raw in lines:
                cells = raw.decode("utf-8", "replace").split("\t")
                seen.update(n for n, cell in zip(names, cells, strict=False) if cell)
                if len(seen) == len(names):
                    break
        finally:
            if isinstance(lines, Generator):
                lines.close()  # (stops tshark once every field was seen)
        ctx.token.raise_if_cancelled()
        if not seen and result.returncode not in (0, None):
            raise f.tshark.error(result.stderr, result.returncode, "looking for the fields failed")
        return seen

    def field_values(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """The values ``field`` takes in the capture, most frequent first (at
        most ``limit``, default and cap MAX_VALUES): ``values: [{value,
        count}]`` (packets holding it; a packet counts once per value),
        ``packets`` (packets with the field), ``distinct`` and ``more``
        (values beyond the distinct cap). ``filter`` (a display filter) counts
        only the packets matching it. One ``-Y field`` fields pass with
        progress; cached per field and filter once the capture is complete."""
        name = param(params, "field", str).strip()
        limit = max(1, min(param(params, "limit", int, MAX_VALUES), MAX_VALUES))
        flt = param(params, "filter", str, "").strip()
        f = self._require_file()
        catalog = self._catalog(ctx)
        entry = catalog.lookup(name)
        if entry is None:
            raise InvalidParamsError(f"{name} is not a field tshark knows")
        if flt:
            error = f.tshark.validate_filter(flt, ctx.token)
            if error:
                raise FilterError(error, {"expr": flt})
        key = f"{name}\0{flt}"
        cached = self._field_values.get(key)
        if cached is None:
            cached = self._count_field_values(name, flt, ctx)
            if self._indexing is None:
                self._field_values.put(key, cached)
        result = {**cached, "values": cached["values"][:limit], "type": entry.get("type", "")}
        if flt:
            result["filter"] = flt
        return result

    def _count_field_values(self, name: str, flt: str, ctx: RequestContext) -> dict[str, Any]:
        f = self._require_file()
        total = max(f.frame_count(), 1)
        argv = f.tshark.argv(
            "-Y",
            f"({name}) && ({flt})" if flt else name,
            "-T",
            "fields",
            "-E",
            "occurrence=a",
            "-E",
            "aggregator=\x1e",
            "-e",
            "frame.number",
            "-e",
            name,
            capture=str(f.path),
        )
        result = StreamResult()
        ctx.progress({"phase": "values", "fraction": 0.0})

        def cells() -> Any:
            for i, raw in enumerate(stream_lines(argv, result, ctx.token)):
                number, _, cell = raw.decode("utf-8", "replace").partition("\t")
                if i % 1000 == 0 and number.isdigit():
                    ctx.progress({"phase": "values", "fraction": min(int(number) / total, 1.0)})
                yield cell

        counted = filterhelp.count_values(cells())
        ctx.token.raise_if_cancelled()
        if not counted["packets"] and result.returncode not in (0, None):
            raise f.tshark.error(result.stderr, result.returncode, f"reading {name} failed")
        counts = counted["counts"]
        ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        return {
            "field": name,
            "values": [{"value": v, "count": c} for v, c in ranked[:MAX_VALUES]],
            "packets": counted["packets"],
            "distinct": len(counts),
            "more": counted["more"],
        }
