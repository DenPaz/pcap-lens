"""Statistics from tshark's -z reports."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from pcap_backend import stats, triage
from pcap_backend.protocol import FilterError, InvalidParamsError, RequestContext, param
from pcap_backend.stats import IoSeries, Table
from pcap_backend.tshark import ToolError, run

from .base import ServiceBase
from .state import _FIELD_NAME_RE, _Open

# The IO graph's longest interval (100 years), so a default always fits.
MAX_IO_INTERVAL_S = 100 * 365 * 86400


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
        protocol of ``stats.SRT_PROTOCOLS`` or ``auto``), ``sip``,
        ``credentials`` (Tools → Credentials), ``ipv4`` / ``ipv6`` (``type``
        addresses, srcdst, ptype or dests), ``multicast`` (UDP multicast
        streams), ``hosts`` (resolved addresses) or ``sctp`` (associations).
        ``filter`` limits the statistics to packets matching a display filter
        (``hosts`` and ``sctp`` can't be limited: the result says
        ``unfiltered``).
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
                table = self._conversations(f, kind, param(params, "type", str, "tcp"), suffix, ctx)
            case "phs":
                table = stats.parse_protocol_hierarchy(self._tap(f, f"io,phs{suffix}", ctx))
            case "io":
                table = self._io(f, params, counted, ctx)
            case "expert":
                table = self._expert(f, counted, ctx)
            case "http" | "dns" | "plen" | "ipv4" | "ipv6":
                table = self._tree_stats(f, kind, param(params, "type", str, ""), suffix, ctx)
            case "multicast":
                table = self._multicast(f, counted, ctx)
            case "hosts" | "sctp":
                table = self._whole_capture_report(f, kind, ctx)
                table.extra["unfiltered"] = bool(counted)
            case "srt":
                table = self._srt(f, param(params, "type", str, "auto"), suffix, ctx)
            case "sip":
                table = stats.parse_sip_stat(self._tap(f, f"sip,stat{suffix}", ctx))
            case "credentials":
                # (The tap takes no filter: rows outside it, or ignored, are left out here.)
                # (Usernames are packet text: not numbers to convert.)
                table = stats.parse_credentials(self._tap(f, "credentials", ctx, numbers=False))
                if counted:
                    table.rows = self._rows_matching(f, table.rows, counted, ctx)
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

    def _conversations(
        self, f: _Open, kind: str, typ: str, suffix: str, ctx: RequestContext
    ) -> Table:
        """Conversations or endpoints of one address type (IP endpoints with
        their GeoIP locations)."""
        if typ not in stats.CONV_TYPES:
            raise InvalidParamsError(f"type must be one of {', '.join(stats.CONV_TYPES)}")
        tap = "conv" if kind == "conversations" else "endpoints"
        text = self._tap(f, f"{tap},{typ}{suffix}", ctx)
        parse = stats.parse_conversations if kind == "conversations" else stats.parse_endpoints
        table = parse(text, typ)
        table.extra["type"] = typ
        if kind == "endpoints" and typ in ("ip", "ipv6"):
            self._add_geoip(f, table)
        return table

    def _add_geoip(self, f: _Open, table: Table) -> None:
        """Country, city and AS columns for IP endpoints, from the MaxMind
        databases of the settings' folders and tshark's usual ones (none found:
        the table is unchanged); rows with a location get ``geo: {lat, lon}``
        (the panel's map) and the table ``geoip: true``."""
        geo = self._geo_databases(f.tshark.options.geoip)
        if not geo:
            return
        table.columns[1:1] = [
            {"id": "country", "label": "Country", "numeric": False},
            {"id": "city", "label": "City", "numeric": False},
            {"id": "asn", "label": "AS Number", "numeric": True},
            {"id": "org", "label": "AS Organization", "numeric": False},
        ]
        for row in table.rows:
            found = geo.lookup(str(row["cells"][0]))
            row["cells"][1:1] = [
                found.get("country", ""),
                found.get("city", ""),
                found.get("asn", ""),
                found.get("org", ""),
            ]
            if "lat" in found:
                row["geo"] = {"lat": found["lat"], "lon": found["lon"]}
        table.extra["geoip"] = True

    def _io(self, f: _Open, params: dict[str, Any], counted: str, ctx: RequestContext) -> Table:
        """The IO graph: packets and bytes per ``interval`` (default: about 100
        intervals) of the packets in ``counted``, plus the ``series``."""
        duration = (
            f.info.end_time - f.info.start_time
            if f.info.end_time is not None and f.info.start_time is not None
            else None
        )
        interval = param(params, "interval", float, 0.0) or stats.io_interval(duration)
        # (A capture can span decades: a packet stamped 1970 beside one from
        # today, as in Wireshark's bt_attr.pcapng; tshark takes such intervals.)
        if not 0.000001 <= interval <= MAX_IO_INTERVAL_S:
            raise InvalidParamsError("interval must be between 1 µs and 100 years")
        series = self._io_series(f, params.get("series"), ctx)
        # (tshark refuses an empty last argument: "frame" is every packet too.)
        scope = [counted or "frame"] if counted or series else []
        # (A comma locale's tshark reads "0,5": the comma is then part of the number.)
        step = f.tshark.decimal(interval, ctx.token)
        spec = ",".join([f"io,stat,{step}", *scope, *(s.tap_arg(counted) for s in series)])
        argv = f.tshark.argv("-q", "-n", "-z", spec, capture=str(f.path))
        res = run(argv, ctx.token)
        text = f.tshark.report_text(res.stdout.decode("utf-8", "replace"), ctx.token)
        if "Interval" not in text:
            # (A field without numbers for SUM etc.: tshark says so and exits 0.)
            raise f.tshark.error(res.stderr, res.returncode, "tshark -z io,stat failed")
        return stats.parse_io_stat(text, interval, series)

    def triage(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """The triage checks (``triage.CHECKS``) counted in one ``-z io,stat``
        pass over the whole capture without the ignored packets: each check's
        ``count`` and ``first``/``last`` packet, or ``error`` when this tshark
        refuses its filter (a field it doesn't know), or ``skipped`` (a
        two-pass check on a capture over ``triage.TWO_PASS_LIMIT`` packets).
        ``checks`` (ids) picks some. Needs the capture completely indexed."""
        self._require_indexed()
        f = self._require_file()
        wanted = params.get("checks")
        checks = list(triage.CHECKS)
        if wanted is not None:
            if not isinstance(wanted, list) or not all(isinstance(w, str) for w in wanted):
                raise InvalidParamsError("checks must be a list of check ids")
            known = {c.id for c in checks}
            unknown = [w for w in wanted if w not in known]
            if unknown:
                raise InvalidParamsError(f"unknown triage checks: {', '.join(unknown)}")
            checks = [c for c in checks if c.id in wanted]
        ctx.progress({"phase": "stats", "fraction": None})
        two_pass = f.info.frames <= triage.TWO_PASS_LIMIT
        skipped = {c.id for c in checks if c.two_pass and not two_pass}
        checks_run = [c for c in checks if c.id not in skipped]
        # One validation for all of them; only when it fails, one per check.
        refused: dict[str, str] = {}
        if checks_run and f.tshark.validate_filter(
            " || ".join(f"({c.filter})" for c in checks_run)
        ):
            for c in checks_run:
                error = f.tshark.validate_filter(c.filter, ctx.token)
                if error:
                    refused[c.id] = error
        usable = [c for c in checks_run if c.id not in refused]
        counted = self._without_ignored("")
        found: dict[str, dict[str, object]] = {}
        if usable:
            series = triage.series(usable)
            # (Interval 0: the whole capture in one row.)
            spec = ",".join(
                ["io,stat,0", counted or "frame", *(s.tap_arg(counted) for s in series)]
            )
            # (-2: requests are linked to their responses only on a second pass.)
            passes = ["-2"] if two_pass else []
            argv = f.tshark.argv(*passes, "-q", "-n", "-z", spec, capture=str(f.path))
            res = run(argv, ctx.token)
            text = f.tshark.report_text(res.stdout.decode("utf-8", "replace"), ctx.token)
            if "Interval" not in text:
                raise f.tshark.error(res.stderr, res.returncode, "tshark -z io,stat failed")
            table = stats.parse_io_stat(text, 0.0, series)
            found = {str(r["id"]): r for r in triage.results(usable, table)}

        def missing(c: triage.Check) -> dict[str, Any]:
            if c.id in skipped:
                why = f"needs two passes, done up to {triage.TWO_PASS_LIMIT:,} packets"
                return {"id": c.id, "title": c.title, "filter": c.filter, "skipped": why}
            return {"id": c.id, "title": c.title, "filter": c.filter, "error": refused[c.id]}

        return {
            "total": f.info.frames,
            "ignored": bool(counted),
            "twoPass": two_pass,
            "checks": [found.get(c.id) or missing(c) for c in checks],
        }

    def _rows_matching(
        self, f: _Open, rows: list[dict[str, Any]], flt: str, ctx: RequestContext
    ) -> list[dict[str, Any]]:
        """The rows whose ``frame`` matches display filter ``flt`` (one pass)."""
        frames = {r["frame"] for r in rows}
        if not frames:
            return rows
        res = run(
            f.tshark.argv("-Y", flt, "-T", "fields", "-e", "frame.number", capture=str(f.path)),
            ctx.token,
        )
        matching = {int(n) for n in res.stdout.split() if n.isdigit()}
        return [r for r in rows if r["frame"] in matching]

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
        elif kind in ("ipv4", "ipv6"):
            typ = typ or "addresses"
            if typ not in stats.IP_STATS_TYPES:
                raise InvalidParamsError(f"type must be one of {', '.join(stats.IP_STATS_TYPES)}")
            tree = f"{kind}_{typ}"
        table = stats.parse_stats_tree(self._tap(f, stats.TREE_TAPS[tree] + suffix, ctx), tree)
        table.kind = kind
        if kind in ("http", "ipv4", "ipv6"):
            table.extra["type"] = typ
        return table

    def _whole_capture_report(self, f: _Open, kind: str, ctx: RequestContext) -> Table:
        """Resolved addresses (``hosts``) or SCTP associations: reports whose
        taps take no filter."""
        if kind == "sctp":
            return stats.parse_sctp_stat(self._tap(f, "sctp,stat", ctx))
        # (Names from the capture's DNS answers: -N d, not the taps' -n.)
        argv = f.tshark.argv("-q", "-N", "d", "-z", "hosts", capture=str(f.path))
        return stats.parse_hosts(run(argv, ctx.token).stdout.decode("utf-8", "replace"))

    def _multicast(self, f: _Open, counted: str, ctx: RequestContext) -> Table:
        """UDP multicast streams: one fields pass over the multicast packets
        (and ``counted``, the filter without the ignored packets)."""
        flt = f"({stats.MULTICAST_FILTER}) && ({counted})" if counted else stats.MULTICAST_FILTER
        args = ["-Y", flt, "-T", "fields", "-E", "occurrence=f"]
        for name in stats.MULTICAST_FIELDS:
            args += ["-e", name]
        res = run(f.tshark.argv(*args, capture=str(f.path)), ctx.token)
        if res.returncode != 0 and not res.stdout:
            raise f.tshark.error(res.stderr, res.returncode, "tshark failed")
        return stats.multicast_streams(res.stdout.decode("utf-8", "replace").split("\n"))

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

    def _tap(
        self,
        f: _Open,
        spec: str,
        ctx: RequestContext,
        extra: Sequence[str] = (),
        numbers: bool = True,
    ) -> str:
        """A ``-z`` report's text; ``numbers``: with decimal points whatever
        tshark's locale (``Tshark.report_text``)."""
        # -n (after the name resolution options): report rows become address filters.
        argv = f.tshark.argv(*extra, "-q", "-n", "-z", spec, capture=str(f.path))
        res = run(argv, ctx.token)
        text = res.stdout.decode("utf-8", "replace")
        if res.returncode != 0 and not text.strip():
            raise f.tshark.error(res.stderr, res.returncode, f"tshark -z {spec} failed")
        return f.tshark.report_text(text, ctx.token) if numbers else text
