"""Replay to Service (see replay.py): the recorded targets, the replay, stop."""

from __future__ import annotations

import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pcap_backend import replay as engine
from pcap_backend.cancellation import CancelledError, CancelToken
from pcap_backend.protocol import FilterError, InvalidParamsError, RequestContext, RpcError, param
from pcap_backend.tshark import StreamResult, ToolError, Tshark, failed, stream_lines

from .base import ServiceBase
from .helpers import _readable_capture
from .state import _Open

_PROTOCOL_IDX = 4  # position of the Protocol column in BASE_COLUMNS
MAX_SPEED = 1000.0
MAX_LOOPS = 1000  # (0: until stopped)
MAX_FILES = 100  # other captures in one replay
MAX_JITTER_MS = 60_000.0
ORDERS = ("sequence", "merged")


@dataclass(frozen=True, slots=True)
class _Source:
    """One capture a replay reads: the open one (its filter, without the
    ignored packets) or another file (all of it)."""

    name: str
    path: Path
    scope: str
    key: tuple[str, ...]  # the targets cache's key
    file: str | None = None  # another capture's path as given; None: the open one


@dataclass(frozen=True, slots=True)
class _Options:
    speed: float
    loops: int
    jitter: float  # ms
    loss: float  # percent
    order: str
    seed: int | None


def _replay_options(params: dict[str, Any]) -> _Options:
    """A replay request's timing options, checked."""
    speed = param(params, "speed", float, 1.0)
    if not 0 <= speed <= MAX_SPEED:
        raise InvalidParamsError(f"speed must be between 0 (no pauses) and {MAX_SPEED:g}")
    loops = param(params, "loops", int, 1)
    if not 0 <= loops <= MAX_LOOPS:
        raise InvalidParamsError(f"loops must be between 1 and {MAX_LOOPS} (0: until stopped)")
    jitter = param(params, "jitter", float, 0.0)
    if not 0 <= jitter <= MAX_JITTER_MS:
        raise InvalidParamsError(f"jitter must be between 0 and {MAX_JITTER_MS:g} ms")
    loss = param(params, "loss", float, 0.0)
    if not 0 <= loss <= 100:
        raise InvalidParamsError("loss must be a percentage between 0 and 100")
    order = param(params, "order", str, "sequence")
    if order not in ORDERS:
        raise InvalidParamsError(f"order must be one of {', '.join(ORDERS)}")
    seed = params.get("seed")
    if seed is not None and (isinstance(seed, bool) or not isinstance(seed, int)):
        raise InvalidParamsError("seed must be a whole number")
    return _Options(speed, loops, jitter, loss, order, seed)


def _destinations(
    mapping: object, protos: dict[str, str], allow_public: bool
) -> dict[str, engine.Destination]:
    """Where each chosen recorded target goes: checked, resolved, local unless allowed."""
    if not isinstance(mapping, dict) or not mapping:
        raise InvalidParamsError("choose at least one recorded target to replay")
    destinations: dict[str, engine.Destination] = {}
    for key, dest in mapping.items():
        if key not in protos:
            raise InvalidParamsError(
                f"{key} is not a recorded target of these packets", {"target": key}
            )
        if not isinstance(dest, dict):
            raise InvalidParamsError(f"{key}: the destination must be {{ip, port}}")
        ip, port = dest.get("ip"), dest.get("port")
        if not isinstance(ip, str) or isinstance(port, bool) or not isinstance(port, int):
            raise InvalidParamsError(f"{key}: the destination needs an ip and a port number")
        try:
            addresses = engine.resolve_target(ip, port, protos[key], allow_public)
        except engine.TargetError as exc:
            raise InvalidParamsError(f"{key}: {exc}", {"target": key}) from exc
        host = ip.strip().removeprefix("[").removesuffix("]")
        label = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        destinations[key] = engine.Destination(protos[key], addresses, label)
    return destinations


class ReplayMixin(ServiceBase):
    """Replay to Service: send captures' client sides again to live services."""

    def replay_targets(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """The recorded targets of the replay's captures: the open one's
        packets matching ``filter`` (``""``: all, never the ignored ones)
        unless ``capture`` is false, and every packet of each of ``files``
        (other captures, read with the open one's dissection options), the
        open capture at position ``openAt`` among them (default 0: first).
        ``{filter, targets: [{key, proto, ip, port, connections, packets,
        bytes, retransmissions, gaps, first, last, firstFrame, protocol}],
        first, last, duration, span, sources: [{name, file, targets,
        packets, bytes, first, last, duration, error}]}``: targets merged by
        key across the captures, in order of their first data; ``duration``
        is the captures' recorded time one after another, ``span`` from the
        first to the last packet of all (merged by time); a capture that
        can't be read has an ``error`` and no targets. ``protocol`` is the
        packet list's Protocol column of the first data packet (the open
        capture's; another capture's targets show the transport).
        ``firstFrame`` is a packet of the open capture: a target it doesn't
        record (or every target, with ``capture`` false) has ``firstFrame:
        null`` and ``recordedIn``, the first capture in play order that has
        it. Cached per capture and scope. The open capture must be
        completely indexed."""
        f = self._require_file()
        sources = self._replay_sources(f, params, ctx)
        merged: dict[str, dict[str, Any]] = {}
        plans = [self._source_targets(f, source, ctx) for source in sources]
        rows = [plan["source"] for plan in plans]  # (in play order)
        # The open capture's targets first, wherever it plays: a shared
        # target keeps its firstFrame (Go to Packet in the viewer) and its
        # dissected protocol. The sums, minimums and maximums don't mind.
        for plan in sorted(plans, key=lambda plan: plan["source"]["file"] is not None):
            other = plan["source"]["file"] is not None
            for t in plan["targets"]:
                have = merged.get(t["key"])
                if have is None:
                    merged[t["key"]] = dict(t)
                    if other:  # (its frame numbers aren't the viewer's)
                        merged[t["key"]].update(firstFrame=None, recordedIn=plan["source"]["name"])
                    continue
                for k in ("connections", "packets", "bytes", "retransmissions", "gaps"):
                    have[k] += t[k]
                if t["first"] is not None and (have["first"] is None or t["first"] < have["first"]):
                    have["first"] = t["first"]
                if t["last"] is not None and (have["last"] is None or t["last"] > have["last"]):
                    have["last"] = t["last"]
        targets = sorted(
            merged.values(), key=lambda t: (t["first"] is None, t["first"] or 0.0, t["key"])
        )
        firsts = [s["first"] for s in rows if s["first"] is not None]
        lasts = [s["last"] for s in rows if s["last"] is not None]
        first = min(firsts) if firsts else None
        last = max(lasts) if lasts else None
        return {
            "filter": param(params, "filter", str, "").strip(),
            "targets": targets,
            "first": first,
            "last": last,
            "duration": sum(s["duration"] for s in rows),
            "span": (last - first) if first is not None and last is not None else 0.0,
            "sources": rows,
        }

    def replay(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Replay the client side of the captures (as in replay_targets:
        ``filter``, ``capture``, ``files``, ``openAt``) to live services: ``targets`` maps
        recorded target keys to ``{ip, port}``; the others are left out. Each
        recorded TCP connection becomes a new connection carrying the bytes
        its client sent (retransmissions once), each UDP datagram a datagram,
        at the recorded times divided by ``speed`` (0: no pauses), each moved
        by a random amount within ±``jitter`` ms (paced replays only), UDP
        datagrams left out with the probability ``loss`` (percent; ``seed``
        makes it repeatable), ``loops`` times (0: until stopped). Several
        captures play one after another (``order: "sequence"``, the default)
        or ``"merged"`` by their recorded times. Destinations must be on this
        machine or a private network unless ``allowPublic``. Reports progress
        (``phase: "replay"``, ``fraction``, ``loop``, ``capture`` (``{index,
        count, name}`` one after another), ``sent``, ``received``, ``open``,
        ``targets`` as below and the new ``log`` lines ``{time, level, text,
        target?}``); runs until done, replay_stop (``stopped``) or cancelled.
        Returns ``{filter, stopped, seconds, loops, speed, targets: [{key, to,
        connections, opened, refused, reset, closedByPeer, packets, bytes,
        dropped, received, datagrams, lost, errors, errorCount}], sources:
        [{name, packets, bytes, lost, retransmissions, gaps}], log}`` (the log
        lines not reported yet)."""
        opts = _replay_options(params)
        known = self.replay_targets(params, ctx)
        destinations = _destinations(
            params.get("targets"),
            {t["key"]: t["proto"] for t in known["targets"]},
            param(params, "allowPublic", bool, False),
        )
        f = self._require_file()
        sources = self._replay_sources(f, params, ctx)
        merged = opts.order == "merged" and len(sources) > 1
        stats = [
            engine.SourceStats(s["name"], s["duration"])
            for s in known["sources"]  # (in the order of `sources`)
        ]
        runner = engine.Replayer(
            destinations,
            opts.speed,
            ctx.token,
            ctx.progress,
            (known["span"] if merged else known["duration"]) or None,
            sources=stats,
            merged=merged,
            jitter=opts.jitter / 1000,
            loss=opts.loss / 100,
            seed=opts.seed,
        )
        with self._lock:
            if self._replay is not None:
                raise InvalidParamsError("a replay is already running in this editor")
            self._replay = runner
        started = time.monotonic()

        def source_events(i: int, source: _Source) -> Iterator[engine.Event]:
            planner = engine.Planner(i)
            try:
                for rec in self._replay_records(
                    f.tshark, source.path, source.scope, runner.pass_token
                ):
                    yield from planner.feed(rec)
                yield from planner.finish()
            except (ToolError, RpcError, OSError) as exc:
                if runner.pass_token.cancelled:
                    raise CancelledError from exc
                runner.log(f"{source.name} can't be read: {exc}", level="error")
            runner.planned(i, planner)

        def events() -> Iterator[engine.Event]:
            if merged:
                yield from engine.merge_by_time(
                    [source_events(i, s) for i, s in enumerate(sources)]
                )
                return
            for i, source in enumerate(sources):
                yield engine.Event("start", 0.0, 0, "", source=i)
                yield from source_events(i, source)

        try:
            runner.run(events, opts.loops)
        finally:
            with self._lock:
                self._replay = None
        return {
            "filter": known["filter"],
            "stopped": runner.stopped,
            "seconds": round(time.monotonic() - started, 3),
            "loops": runner.loops_done,
            "speed": opts.speed,
            "targets": runner.summary(),
            "sources": [s.to_json() for s in runner.sources],
            "log": runner.take_log(),
        }

    def replay_stop(self, _params: dict[str, Any], _ctx: RequestContext) -> dict[str, Any]:
        """End the running replay (``stopped: false`` if none is running)."""
        with self._lock:
            runner = self._replay
        return {"stopped": runner is not None and runner.stop()}

    def _replay_sources(
        self, f: _Open, params: dict[str, Any], ctx: RequestContext
    ) -> list[_Source]:
        """The captures a replay reads, in order: ``files``, with the open one
        (``capture``, default true; its ``filter``) at ``openAt`` among them
        (default 0: first)."""
        sources: list[_Source] = []
        files = params.get("files", [])
        if not isinstance(files, list) or not all(isinstance(p, str) for p in files):
            raise InvalidParamsError("files must be a list of capture paths")
        if len(files) > MAX_FILES:
            raise InvalidParamsError(f"at most {MAX_FILES} other captures can be replayed at once")
        open_at = param(params, "openAt", int, 0)
        if not 0 <= open_at <= len(files):
            raise InvalidParamsError(
                f"openAt must be between 0 (first) and {len(files)} (after the other captures)"
            )
        for raw in files:
            path = _readable_capture(raw)
            st = path.stat()
            key = ("file", str(path.resolve()), str(st.st_size), str(st.st_mtime_ns))
            sources.append(_Source(path.name, path, engine.FILTER, key, raw))
        if param(params, "capture", bool, True):
            flt = param(params, "filter", str, "").strip()
            self._require_indexed()
            scope = self._replay_scope(f, flt, ctx)
            sources.insert(open_at, _Source(f.path.name, f.path, scope, ("open", scope)))
        if not sources:
            raise InvalidParamsError("choose at least one capture to replay")
        return sources

    def _source_targets(self, f: _Open, source: _Source, ctx: RequestContext) -> dict[str, Any]:
        """One capture's targets and its ``source`` row (cached)."""
        cached = self._replay_targets.get(source.key)
        if cached is not None:
            return cached
        ctx.progress({"phase": "replay-targets", "fraction": None, "capture": source.name})
        planner = engine.Planner()
        error = None
        try:
            for rec in self._replay_records(f.tshark, source.path, source.scope, ctx.token):
                planner.feed(rec)
            planner.finish()
        except (ToolError, RpcError) as exc:
            if source.file is None:
                raise
            error = str(exc).strip().split("\n", 1)[0].removeprefix("tshark: ")
            planner = engine.Planner()
        rows = []
        for t in planner.targets.values():
            if not t.connections:
                continue
            row = t.to_json()
            label = ""
            if source.file is None and t.first_frame:
                label = f.base.rows.get(t.first_frame)[_PROTOCOL_IDX]
            row["protocol"] = label or t.proto.upper()
            rows.append(row)
        first, last = planner.first, planner.last
        result = {
            "targets": rows,
            "source": {
                "name": source.name,
                "file": source.file,
                "targets": len(rows),
                "packets": sum(t["packets"] for t in rows),
                "bytes": sum(t["bytes"] for t in rows),
                "first": first,
                "last": last,
                "duration": (last - first) if first is not None and last is not None else 0.0,
                "error": error,
            },
        }
        self._replay_targets.put(source.key, result)
        return result

    def _replay_scope(self, f: _Open, flt: str, ctx: RequestContext) -> str:
        """The display filter of the open capture's packets a replay reads."""
        if flt:
            error = f.tshark.validate_filter(flt, ctx.token)
            if error:
                raise FilterError(error, {"expr": flt})
        scope = self._without_ignored(flt)
        return f"({engine.FILTER}) && ({scope})" if scope else engine.FILTER

    def _replay_records(
        self, tshark: Tshark, path: Path, scope: str, token: CancelToken
    ) -> Iterator[engine.Record]:
        """The TCP segments and UDP datagrams of ``scope``, in capture order."""
        args = ["-n", "-Y", scope, "-T", "fields", "-E", "occurrence=l"]
        for name in engine.FIELDS:
            args += ["-e", name]
        result = StreamResult()
        for raw in stream_lines(tshark.argv(*args, capture=str(path)), result, token):
            rec = engine.parse_record(raw.decode("utf-8", "replace"))
            if rec is not None:
                yield rec
        if failed(result.returncode, result.stderr) and not result.lines:
            raise tshark.error(result.stderr, result.returncode, "tshark failed")
