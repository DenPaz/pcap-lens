"""Replay to Service (see replay.py): the recorded targets, the replay, stop."""

from __future__ import annotations

import time
from collections.abc import Iterator
from typing import Any

from pcap_backend import replay as engine
from pcap_backend.cancellation import CancelToken
from pcap_backend.protocol import FilterError, InvalidParamsError, RequestContext, param
from pcap_backend.tshark import StreamResult, stream_lines

from .base import ServiceBase
from .state import _Open

_PROTOCOL_IDX = 4  # position of the Protocol column in BASE_COLUMNS
MAX_SPEED = 1000.0
MAX_LOOPS = 1000


class ReplayMixin(ServiceBase):
    """Replay to Service: send a capture's client side again to live services."""

    def replay_targets(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """The recorded targets of the packets matching ``filter`` (``""``: all,
        never the ignored ones): ``{filter, targets: [{key, proto, ip, port,
        connections, packets, bytes, retransmissions, gaps, first, last,
        firstFrame, protocol}], first, last, duration}``, in order of their
        first data. ``protocol`` is the packet list's Protocol column of the
        first data packet (what the dissectors, Lua ones included, call it).
        Cached per scope. Needs a completely indexed capture."""
        flt = param(params, "filter", str, "").strip()
        f = self._require_file()
        self._require_indexed()
        scope = self._replay_scope(f, flt, ctx)
        cached = self._replay_targets.get(scope)
        if cached is not None:
            return {**cached, "filter": flt}
        ctx.progress({"phase": "replay-targets", "fraction": None})
        planner = engine.Planner()
        for rec in self._replay_records(f, scope, ctx.token):
            planner.feed(rec)
        planner.finish()
        targets = sorted(
            (t for t in planner.targets.values() if t.connections),
            key=lambda t: (t.first is None, t.first or 0.0, t.key),
        )
        rows = []
        for t in targets:
            row = t.to_json()
            label = f.base.rows.get(t.first_frame)[_PROTOCOL_IDX] if t.first_frame else ""
            row["protocol"] = label or t.proto.upper()
            rows.append(row)
        first, last = planner.first, planner.last
        result = {
            "filter": flt,
            "targets": rows,
            "first": first,
            "last": last,
            "duration": (last - first) if first is not None and last is not None else 0.0,
        }
        self._replay_targets.put(scope, result)
        return result

    def replay(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Replay the client side of the packets matching ``filter`` to live
        services: ``targets`` maps recorded target keys (from replay_targets)
        to ``{ip, port}``; the others are left out. Each recorded TCP
        connection becomes a new connection carrying the bytes its client sent
        (retransmissions once), each UDP datagram a datagram, at the recorded
        times divided by ``speed`` (0: no pauses), ``loops`` times.
        Destinations must be on this machine or a private network unless
        ``allowPublic``. Reports progress (``phase: "replay"``, ``fraction``,
        ``loop``, ``sent``, ``received``, ``open``, ``targets`` as below and
        the new ``log`` lines ``{time, level, text, target?}``); runs until
        done, replay_stop (``stopped``) or cancelled. Returns ``{filter,
        stopped, seconds, loops, speed, targets: [{key, to, connections,
        opened, refused, reset, closedByPeer, packets, bytes, dropped,
        received, datagrams, errors, errorCount}], log}`` (the log lines not
        reported yet)."""
        flt = param(params, "filter", str, "").strip()
        speed = param(params, "speed", float, 1.0)
        if not 0 <= speed <= MAX_SPEED:
            raise InvalidParamsError(f"speed must be between 0 (no pauses) and {MAX_SPEED:g}")
        loops = param(params, "loops", int, 1)
        if not 1 <= loops <= MAX_LOOPS:
            raise InvalidParamsError(f"loops must be between 1 and {MAX_LOOPS}")
        allow_public = param(params, "allowPublic", bool, False)
        mapping = params.get("targets")
        if not isinstance(mapping, dict) or not mapping:
            raise InvalidParamsError("choose at least one recorded target to replay")
        known = self.replay_targets({"filter": flt}, ctx)
        protos = {t["key"]: t["proto"] for t in known["targets"]}
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
        f = self._require_file()
        scope = self._replay_scope(f, flt, ctx)
        runner = engine.Replayer(
            destinations, speed, ctx.token, ctx.progress, known["duration"] or None
        )
        with self._lock:
            if self._replay is not None:
                raise InvalidParamsError("a replay is already running in this editor")
            self._replay = runner
        started = time.monotonic()

        def events() -> Iterator[engine.Event]:
            planner = engine.Planner()
            for rec in self._replay_records(f, scope, runner.pass_token):
                yield from planner.feed(rec)
            yield from planner.finish()

        try:
            runner.run(events, loops)
        finally:
            with self._lock:
                self._replay = None
        return {
            "filter": flt,
            "stopped": runner.stopped,
            "seconds": round(time.monotonic() - started, 3),
            "loops": runner.loops_done,
            "speed": speed,
            "targets": runner.summary(),
            "log": runner.take_log(),
        }

    def replay_stop(self, _params: dict[str, Any], _ctx: RequestContext) -> dict[str, Any]:
        """End the running replay (``stopped: false`` if none is running)."""
        with self._lock:
            runner = self._replay
        return {"stopped": runner is not None and runner.stop()}

    def _replay_scope(self, f: _Open, flt: str, ctx: RequestContext) -> str:
        """The display filter of the packets a replay reads."""
        if flt:
            error = f.tshark.validate_filter(flt, ctx.token)
            if error:
                raise FilterError(error, {"expr": flt})
        scope = self._without_ignored(flt)
        return f"({engine.FILTER}) && ({scope})" if scope else engine.FILTER

    def _replay_records(self, f: _Open, scope: str, token: CancelToken) -> Iterator[engine.Record]:
        """The TCP segments and UDP datagrams of ``scope``, in capture order."""
        args = ["-n", "-Y", scope, "-T", "fields", "-E", "occurrence=l"]
        for name in engine.FIELDS:
            args += ["-e", name]
        result = StreamResult()
        for raw in stream_lines(f.tshark.argv(*args, capture=str(f.path)), result, token):
            rec = engine.parse_record(raw.decode("utf-8", "replace"))
            if rec is not None:
                yield rec
        if result.returncode not in (0, None) and not result.lines:
            raise f.tshark.error(result.stderr, result.returncode, "tshark failed")
