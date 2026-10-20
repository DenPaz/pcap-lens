"""Statistics from tshark's -z reports."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from pcap_backend import stats
from pcap_backend.protocol import FilterError, InvalidParamsError, RequestContext, param
from pcap_backend.stats import IoSeries, Table
from pcap_backend.tshark import ToolError, run

from .base import ServiceBase
from .state import _FIELD_NAME_RE, _Open


class StatisticsMixin(ServiceBase):
    """Statistics from tshark's -z reports."""

    def stats(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Statistics tables from tshark's ``-z`` reports.

        ``kind``: ``conversations`` / ``endpoints`` (with ``type`` eth, ip, ipv6,
        tcp, udp), ``phs`` (protocol hierarchy), ``io`` (with optional
        ``interval`` in seconds and ``series``, see ``_io``), ``expert``,
        ``properties`` (capinfos),
        ``http`` (``type`` packets, requests or load), ``dns``, ``plen``
        (packet lengths), ``srt`` (service response time, ``type`` a
        protocol of ``stats.SRT_PROTOCOLS`` or ``auto``) or ``sip``.
        ``filter`` limits the statistics to packets matching a display filter.
        """
        kind = param(params, "kind", str)
        f = self._require_file()
        flt = param(params, "filter", str, "").strip()
        if flt and kind != "properties":
            error = f.tshark.validate_filter(flt, ctx.token)
            if error:
                raise FilterError(error, {"expr": flt})
        # Ignored packets (Ctrl+D) are left out of every report.
        counted = self._without_ignored(flt)
        suffix = f",{counted}" if counted else ""
        ctx.progress({"phase": "stats", "fraction": None})
        match kind:
            case "conversations" | "endpoints":
                typ = param(params, "type", str, "tcp")
                if typ not in stats.CONV_TYPES:
                    raise InvalidParamsError(f"type must be one of {', '.join(stats.CONV_TYPES)}")
                tap = "conv" if kind == "conversations" else "endpoints"
                text = self._tap(f, f"{tap},{typ}{suffix}", ctx)
                parse = (
                    stats.parse_conversations if kind == "conversations" else stats.parse_endpoints
                )
                table = parse(text, typ)
                table.extra["type"] = typ
            case "phs":
                table = stats.parse_protocol_hierarchy(self._tap(f, f"io,phs{suffix}", ctx))
            case "io":
                table = self._io(f, params, counted, ctx)
            case "expert":
                table = self._expert(f, counted, ctx)
            case "http" | "dns" | "plen":
                table = self._tree_stats(f, kind, param(params, "type", str, ""), suffix, ctx)
            case "srt":
                table = self._srt(f, param(params, "type", str, "auto"), suffix, ctx)
            case "sip":
                table = stats.parse_sip_stat(self._tap(f, f"sip,stat{suffix}", ctx))
            case "properties":
                if f.tshark.capinfos is None:
                    raise ToolError("capinfos (part of Wireshark) was not found")
                res = run([str(f.tshark.capinfos), str(f.path)], ctx.token)
                table = stats.parse_capinfos_properties(res.stdout.decode("utf-8", "replace"))
            case _:
                raise InvalidParamsError(f"unknown statistics kind {kind!r}")
        result = table.to_json()
        result["filter"] = flt
        return result

    def _io(self, f: _Open, params: dict[str, Any], counted: str, ctx: RequestContext) -> Table:
        """The IO graph: packets and bytes per ``interval`` (default: about 100
        intervals) of the packets in ``counted``, plus the ``series``."""
        duration = (
            f.info.end_time - f.info.start_time
            if f.info.end_time is not None and f.info.start_time is not None
            else None
        )
        interval = param(params, "interval", float, 0.0) or stats.io_interval(duration)
        if not 0.000001 <= interval <= 86400:
            raise InvalidParamsError("interval must be between 1 µs and 1 day")
        series = self._io_series(f, params.get("series"), ctx)
        # (tshark refuses an empty last argument: "frame" is every packet too.)
        scope = [counted or "frame"] if counted or series else []
        spec = ",".join([f"io,stat,{interval:g}", *scope, *(s.tap_arg(counted) for s in series)])
        argv = f.tshark.argv("-q", "-n", "-z", spec, capture=str(f.path))
        res = run(argv, ctx.token)
        text = res.stdout.decode("utf-8", "replace")
        if "Interval" not in text:
            # (A field without numbers for SUM etc.: tshark says so and exits 0.)
            raise f.tshark.error(res.stderr, res.returncode, "tshark -z io,stat failed")
        return stats.parse_io_stat(text, interval, series)

    def _io_series(self, f: _Open, raw: object, ctx: RequestContext) -> list[IoSeries]:
        """The IO graph's ``series``: up to ``stats.MAX_IO_SERIES`` of
        ``{metric, filter?, field?}`` (``stats.IO_METRICS``; field metrics need
        a ``field``). Each filter is validated with its field (a FilterError
        names the series as ``data.series``); io,stat separates its arguments
        with commas, so neither may hold one."""
        if raw is None:
            return []
        if not isinstance(raw, list) or len(raw) > stats.MAX_IO_SERIES:
            raise InvalidParamsError(f"series must list at most {stats.MAX_IO_SERIES} graphs")
        series: list[IoSeries] = []
        for i, item in enumerate(raw):
            if not isinstance(item, dict):
                raise InvalidParamsError("each series must be an object")
            metric = item.get("metric", "packets")
            flt = str(item.get("filter") or "").strip()
            fld = str(item.get("field") or "").strip()
            if metric not in stats.IO_METRICS:
                raise InvalidParamsError(f"metric must be one of {', '.join(stats.IO_METRICS)}")
            if metric in stats.IO_FIELD_METRICS:
                if not _FIELD_NAME_RE.match(fld):
                    raise InvalidParamsError(
                        f"graph {i + 1}: {metric.upper()} needs a field name", {"series": i}
                    )
            else:
                fld = ""
            if "," in flt:
                raise FilterError(
                    "tshark's I/O statistics separate graphs with commas: this filter can't"
                    " hold one (write a set as {1 2} or with ||)",
                    {"expr": flt, "series": i},
                )
            check = " && ".join(p for p in (fld, f"({flt})" if flt else "") if p)
            if check:
                error = f.tshark.validate_filter(check, ctx.token)
                if error:
                    raise FilterError(error, {"expr": flt or fld, "series": i})
            series.append(IoSeries(metric, flt, fld))
        return series

    def _expert(self, f: _Open, counted: str, ctx: RequestContext) -> Table:
        """Expert info: the ``-z expert`` summary joined with a fields pass for
        the frames of each item (``counted``: the filter, without ignored)."""
        fields_args = ["-T", "fields", "-e", "frame.number", "-e", "_ws.expert"]
        fields_args += [
            "-E",
            "aggregator=\x1e",
            "-Y",
            f"_ws.expert && ({counted})" if counted else "_ws.expert",
        ]
        fields_future = self._pool.submit(
            run, f.tshark.argv(*fields_args, capture=str(f.path)), ctx.token
        )
        # "comment" is the lowest severity, i.e. everything.
        suffix = f",{counted}" if counted else ""
        summary = self._tap(f, f"expert,comment{suffix}", ctx)
        fields_text = fields_future.result().stdout.decode("utf-8", "replace")
        return stats.parse_expert(summary, fields_text)

    def expert_summary(self, _params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """How many expert items of each severity the whole capture has
        (``{counts: {error, warning, note, chat, comment}}``), for the status
        bar: one ``-q -z expert`` pass without the ignored packets, cached per
        open capture (and set of ignored packets). Needs the
        capture completely indexed (IndexingError while indexing or capturing)."""
        self._require_indexed()
        f = self._require_file()
        ignore = self._ignore_filter()
        if f.expert is None or f.expert[0] != ignore:
            # (No progress: it runs quietly in the background, not behind the busy bar.)
            spec = f"expert,comment,{ignore}" if ignore else "expert,comment"
            f.expert = (ignore, stats.parse_expert_counts(self._tap(f, spec, ctx)))
        return {"counts": f.expert[1]}

    def _tree_stats(self, f: _Open, kind: str, typ: str, suffix: str, ctx: RequestContext) -> Table:
        """A stats_tree report: HTTP (``type`` packets, requests or load), DNS or
        packet lengths."""
        tree = kind
        if kind == "http":
            typ = typ or "packets"
            trees = {"packets": "http", "requests": "http_requests", "load": "http_load"}
            if typ not in trees:
                raise InvalidParamsError("type must be packets, requests or load")
            tree = trees[typ]
        table = stats.parse_stats_tree(self._tap(f, stats.TREE_TAPS[tree] + suffix, ctx), tree)
        table.kind = kind
        if kind == "http":
            table.extra["type"] = typ
        return table

    def _srt(self, f: _Open, protocol: str, suffix: str, ctx: RequestContext) -> Table:
        """Service response times of one protocol. ``auto`` picks the first
        protocol (in SRT_PROTOCOLS order) the protocol hierarchy shows traffic
        for; the result's ``available`` lists every such protocol."""
        phs = stats.parse_protocol_hierarchy(self._tap(f, "io,phs" + suffix, ctx))
        present = {str(row["cells"][0]) for row in phs.rows}
        available = [
            p for p in stats.SRT_PROTOCOLS if present.intersection(stats.SRT_PHS_NAMES.get(p, (p,)))
        ]
        if protocol == "auto":
            protocol = available[0] if available else "icmp"
        if protocol not in stats.SRT_PROTOCOLS:
            raise InvalidParamsError(
                f"type must be auto or one of {', '.join(stats.SRT_PROTOCOLS)}"
            )
        text = self._tap(f, f"{protocol},srt{suffix}", ctx)
        parse = stats.parse_icmp_srt if protocol in ("icmp", "icmpv6") else stats.parse_srt
        table = parse(text, protocol)
        table.extra["type"] = protocol
        table.extra["available"] = available
        return table

    def _tap(self, f: _Open, spec: str, ctx: RequestContext, extra: Sequence[str] = ()) -> str:
        # -n (after the name resolution options): report rows become address filters.
        argv = f.tshark.argv(*extra, "-q", "-n", "-z", spec, capture=str(f.path))
        res = run(argv, ctx.token)
        text = res.stdout.decode("utf-8", "replace")
        if res.returncode != 0 and not text.strip():
            raise f.tshark.error(res.stderr, res.returncode, f"tshark -z {spec} failed")
        return text
