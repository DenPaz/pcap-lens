"""Replay to Service: the client side of a capture's TCP connections and UDP
flows, sent again to a live service over new connections.

A recorded TCP connection can't be replayed packet by packet against a live
TCP stack (the recorded sequence numbers don't match the new connection's), so
this replays its *content*: one new connection per recorded connection,
carrying exactly the bytes the client sent, with the recorded pauses. That is
what an interception collector (the operator's delivery function connects and
sends HI2/HI3 data) or any server needs to see the traffic again.

Three parts, all stdlib:

* :func:`parse_record` reads one line of tshark's fields pass (``FIELDS``).
* :class:`Planner` turns records, in capture order, into events (open, data,
  close, datagram) for each recorded target: it finds the client side,
  deduplicates TCP data by sequence number (retransmissions skipped, overlaps
  trimmed, gaps counted) and keeps per-target counts.
* :class:`Replayer` carries the events out with non-blocking sockets and one
  selector: each event at its recorded time (divided by ``speed``), the
  service's answers read and counted but never waited on.
"""

from __future__ import annotations

import contextlib
import errno
import ipaddress
import os
import selectors
import socket
import struct
import sys
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

from .cancellation import CancelledError, CancelToken

IS_WINDOWS = sys.platform == "win32"

# tshark's fields pass (`-E occurrence=l`: the innermost header of a tunnel).
# ICMP errors quote a TCP/UDP header of another packet: not traffic to replay.
FILTER = "(tcp || udp) && !icmp && !icmpv6"
FIELDS = (
    "frame.number",
    "frame.time_relative",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "tcp.stream",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.fin",
    "tcp.flags.reset",
    "tcp.seq_raw",
    "udp.stream",
    "udp.srcport",
    "udp.dstport",
    "tcp.payload",
    "udp.payload",
)

# Data waiting to be written (all connections): above it the timeline waits.
MAX_BUFFERED = 32 << 20
# After the last event: how long data still being written may take, then how
# long to wait for the service's last answers.
DRAIN_S = 10.0
ANSWER_GRACE_S = 0.5
PROGRESS_EVERY_S = 0.25
# Errors kept per target (the rest are counted).
MAX_ERRORS = 10
MAX_LOG = 200  # log lines a progress report carries (the rest are counted)
# TCP segments captured ahead of a gap wait for the missing bytes (captured
# out of order) this long in capture time, or until this much waits; then
# the gap is taken as bytes the capture lacks.
REORDER_WINDOW_S = 0.5
MAX_HELD = 4 << 20
_CONNECTING = (0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, 10035)  # WSAEWOULDBLOCK


@dataclass(frozen=True, slots=True)
class Record:
    """One TCP segment or UDP datagram of the capture."""

    frame: int
    time: float
    proto: str  # "tcp" | "udp"
    stream: int
    src: str
    sport: int
    dst: str
    dport: int
    payload: bytes = b""
    syn: bool = False
    ack: bool = False
    fin: bool = False
    rst: bool = False
    seq: int | None = None


def _flag(cell: str) -> bool:
    return cell in ("True", "1", "true")


def parse_record(line: str) -> Record | None:
    """A ``FIELDS`` line, or None (not TCP/UDP over IP, or unreadable)."""
    cells = line.removesuffix("\r").split("\t")
    if len(cells) < len(FIELDS) or not cells[0].isdigit():
        return None
    (number, t, src4, src6, dst4, dst6, tstream, tsport, tdport, syn, ack, fin, rst, seq,
     ustream, usport, udport, tpayload, upayload) = cells[: len(FIELDS)]  # fmt: skip
    src, dst = src4 or src6, dst4 or dst6
    try:
        if tstream.isdigit() and tsport and tdport:
            return Record(
                int(number), float(t), "tcp", int(tstream), src, int(tsport), dst, int(tdport),
                bytes.fromhex(tpayload), _flag(syn), _flag(ack), _flag(fin), _flag(rst),
                int(seq) if seq.isdigit() else None,
            )  # fmt: skip
        if ustream.isdigit() and usport and udport:
            return Record(
                int(number), float(t), "udp", int(ustream), src, int(usport), dst, int(udport),
                bytes.fromhex(upayload),
            )  # fmt: skip
    except ValueError:
        return None
    return None


def target_key(proto: str, ip: str, port: int) -> str:
    """``"tcp 10.20.0.5:11001"``, ``"udp [fd00::5]:5060"``."""
    host = f"[{ip}]" if ":" in ip else ip
    return f"{proto} {host}:{port}"


@dataclass(frozen=True, slots=True)
class Event:
    """What the replay does at ``time`` (capture time, seconds)."""

    kind: str  # "open" | "data" | "close" | "datagram"
    time: float
    flow: int  # the recorded connection or UDP flow (planner numbering)
    target: str
    data: bytes = b""
    reset: bool = False


@dataclass(slots=True)
class TargetInfo:
    """A recorded target as the planner saw it."""

    key: str
    proto: str
    ip: str
    port: int
    connections: int = 0
    packets: int = 0
    bytes: int = 0
    retransmissions: int = 0
    gaps: int = 0
    first: float | None = None
    last: float | None = None
    first_frame: int | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "proto": self.proto,
            "ip": self.ip,
            "port": self.port,
            "connections": self.connections,
            "packets": self.packets,
            "bytes": self.bytes,
            "retransmissions": self.retransmissions,
            "gaps": self.gaps,
            "first": self.first,
            "last": self.last,
            "firstFrame": self.first_frame,
        }


@dataclass(slots=True)
class _TcpFlow:
    flow: int
    client: tuple[str, int]
    target: str
    next_seq: int | None = None
    opened: bool = False
    closed: bool = False
    # Segments after a gap: sequence number → (capture time, frame, data).
    held: dict[int, tuple[float, int, bytes]] = field(default_factory=dict)
    held_bytes: int = 0


@dataclass(slots=True)
class _UdpFlow:
    flow: int
    client: tuple[str, int]
    target: str


def _seq_diff(a: int, b: int) -> int:
    """``a - b`` in 32-bit sequence space (negative when ``a`` is before ``b``)."""
    return ((a - b + (1 << 31)) % (1 << 32)) - (1 << 31)


class Planner:
    """Records (capture order) → events, plus what each recorded target holds.

    The client of a TCP connection is the sender of its SYN (the receiver of a
    SYN-ACK seen first); without either in the capture, the end with the
    higher port. A UDP flow's client sends its first datagram. Only the
    client's data is replayed; the server's packets are ignored.
    """

    def __init__(self) -> None:
        self.targets: dict[str, TargetInfo] = {}
        self._tcp: dict[int, _TcpFlow] = {}
        self._holding: dict[int, _TcpFlow] = {}  # flows with held segments, by flow number
        self._now = 0.0
        self._udp: dict[int, _UdpFlow] = {}
        self._flows = 0
        self.first: float | None = None
        self.last: float | None = None

    def _target(self, proto: str, ip: str, port: int) -> TargetInfo:
        key = target_key(proto, ip, port)
        info = self.targets.get(key)
        if info is None:
            info = self.targets[key] = TargetInfo(key, proto, ip, port)
        return info

    def _note(self, info: TargetInfo, time_: float, frame: int, size: int) -> None:
        info.packets += 1
        info.bytes += size
        if info.first is None:
            info.first, info.first_frame = time_, frame
        info.last = time_
        if self.first is None:
            self.first = time_
        self.last = time_

    def _next_flow(self) -> int:
        self._flows += 1
        return self._flows

    def feed(self, rec: Record) -> list[Event]:
        self._now = rec.time
        events = self._expire(rec.time)
        if rec.proto == "udp":
            return events + self._udp_event(rec)
        return events + self._tcp_events(rec)

    def finish(self) -> list[Event]:
        """The end of the capture: segments still waiting behind a gap go on."""
        events: list[Event] = []
        for flow in list(self._holding.values()):
            # (When the window would have run out, had the capture gone on.)
            oldest = min(t for t, _, _ in flow.held.values())
            events += self._give_up(flow, min(self._now, oldest + REORDER_WINDOW_S))
        return events

    def _udp_event(self, rec: Record) -> list[Event]:
        flow = self._udp.get(rec.stream)
        if flow is None:
            info = self._target("udp", rec.dst, rec.dport)
            info.connections += 1
            flow = self._udp[rec.stream] = _UdpFlow(
                self._next_flow(), (rec.src, rec.sport), info.key
            )
        if (rec.src, rec.sport) != flow.client:
            return []
        self._note(self.targets[flow.target], rec.time, rec.frame, len(rec.payload))
        return [Event("datagram", rec.time, flow.flow, flow.target, rec.payload)]

    def _tcp_events(self, rec: Record) -> list[Event]:
        flow = self._tcp.get(rec.stream)
        if flow is None:
            if rec.syn and not rec.ack:
                client, server = (rec.src, rec.sport), (rec.dst, rec.dport)
            elif rec.syn:
                client, server = (rec.dst, rec.dport), (rec.src, rec.sport)
            elif rec.sport >= rec.dport:
                client, server = (rec.src, rec.sport), (rec.dst, rec.dport)
            else:
                client, server = (rec.dst, rec.dport), (rec.src, rec.sport)
            info = self._target("tcp", *server)
            flow = self._tcp[rec.stream] = _TcpFlow(self._next_flow(), client, info.key)
        if (rec.src, rec.sport) != flow.client or flow.closed:
            return []
        info = self.targets[flow.target]
        events: list[Event] = []
        if not flow.opened and (rec.syn or rec.payload):
            flow.opened = True
            info.connections += 1
            events.append(Event("open", rec.time, flow.flow, flow.target))
        if rec.syn and rec.seq is not None:
            flow.next_seq = (rec.seq + 1) % (1 << 32)
        if rec.payload and rec.seq is not None:
            # (A SYN's own data, TCP Fast Open, starts after the SYN's sequence number.)
            seq = (rec.seq + 1) % (1 << 32) if rec.syn else rec.seq
            if flow.next_seq is None:
                flow.next_seq = seq
            if _seq_diff(seq, flow.next_seq) > 0:
                self._hold(flow, rec, seq)  # after a gap: wait for the missing bytes
            else:
                events += self._accept(flow, rec.time, rec.frame, seq, rec.payload)
                events += self._release(flow, rec.time)
        elif rec.payload:
            events += self._accept(flow, rec.time, rec.frame, None, rec.payload)
        if (rec.fin or rec.rst) and flow.opened:
            events += self._give_up(flow, rec.time)
            flow.closed = True
            events.append(Event("close", rec.time, flow.flow, flow.target, reset=rec.rst))
        return events

    def _accept(
        self, flow: _TcpFlow, time_: float, frame: int, seq: int | None, data: bytes
    ) -> list[Event]:
        """Data starting at or before the next expected byte: its new part."""
        info = self.targets[flow.target]
        if seq is not None and flow.next_seq is not None:
            diff = _seq_diff(seq, flow.next_seq)
            if -diff >= len(data):
                info.retransmissions += 1
                return []
            if diff < 0:
                info.retransmissions += 1
                data = data[-diff:]
            flow.next_seq = (flow.next_seq + len(data)) % (1 << 32)
        self._note(info, time_, frame, len(data))
        return [Event("data", time_, flow.flow, flow.target, data)]

    def _hold(self, flow: _TcpFlow, rec: Record, seq: int) -> None:
        old = flow.held.get(seq)
        if old is not None:
            if len(old[2]) >= len(rec.payload):
                self.targets[flow.target].retransmissions += 1
                return
            flow.held_bytes -= len(old[2])
        flow.held[seq] = (rec.time, rec.frame, rec.payload)
        flow.held_bytes += len(rec.payload)
        self._holding[flow.flow] = flow

    def _release(self, flow: _TcpFlow, time_: float) -> list[Event]:
        """Held segments that the data so far reaches, in sequence order."""
        events: list[Event] = []
        while flow.held and flow.next_seq is not None:
            base = flow.next_seq
            ready = sorted(
                (s for s in flow.held if _seq_diff(s, base) <= 0),
                key=lambda s: _seq_diff(s, base),
            )
            if not ready:
                break
            for seq in ready:
                _, frame, data = flow.held.pop(seq)
                flow.held_bytes -= len(data)
                events += self._accept(flow, time_, frame, seq, data)
        if not flow.held:
            self._holding.pop(flow.flow, None)
        return events

    def _give_up(self, flow: _TcpFlow, time_: float) -> list[Event]:
        """The bytes before the held segments aren't in the capture: go on."""
        events: list[Event] = []
        while flow.held and flow.next_seq is not None:
            base = flow.next_seq
            flow.next_seq = min(flow.held, key=lambda s: _seq_diff(s, base))
            self.targets[flow.target].gaps += 1
            events += self._release(flow, time_)
        return events

    def _expire(self, now: float) -> list[Event]:
        """Gaps that out-of-order segments haven't filled in time, or hold too much."""
        events: list[Event] = []
        for flow in list(self._holding.values()):
            oldest = min(t for t, _, _ in flow.held.values())
            if now - oldest > REORDER_WINDOW_S or flow.held_bytes > MAX_HELD:
                events += self._give_up(flow, now)
        return events


def plan(records: Iterable[Record]) -> tuple[Planner, list[Event]]:
    """Every event of ``records`` (tests, small captures)."""
    planner = Planner()
    events = [ev for rec in records for ev in planner.feed(rec)]
    return planner, events + planner.finish()


class TargetError(ValueError):
    """A replay destination that can't be used (bad port, unknown or public host)."""


def is_local(address: str) -> bool:
    """Loopback, private or link-local: this machine, Docker, the lab network."""
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_loopback or ip.is_private or ip.is_link_local


# (family, protocol, socket address): one way to reach a destination.
Address = tuple[int, int, Any]


def resolve_target(host: str, port: int, proto: str, allow_public: bool) -> list[Address]:
    """The socket addresses to send ``proto`` traffic for ``host``:``port`` to,
    IPv4 first: ``localhost`` is often ``::1`` first, while most local services
    listen on IPv4 (TCP tries the next address when one fails). Every address
    the name resolves to must be local unless ``allow_public``."""
    host = host.strip().removeprefix("[").removesuffix("]")
    if not host:
        raise TargetError("the replay destination needs an IP address or host name")
    if not 1 <= port <= 65535:
        raise TargetError(f"port {port} is not between 1 and 65535")
    kind = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
    try:
        infos = socket.getaddrinfo(host, port, type=kind)
    except OSError as exc:
        raise TargetError(f"{host} can't be resolved: {exc}") from exc
    if not infos:
        raise TargetError(f"{host} can't be resolved")
    if not allow_public:
        public = sorted({str(i[4][0]) for i in infos if not is_local(str(i[4][0]))})
        if public:
            raise TargetError(
                f"{host} is not on this machine or a private network ({', '.join(public)}); "
                "replaying to it must be allowed explicitly"
            )
    addresses: list[Address] = []
    for family, _, proto_num, _, address in infos:
        if (family, proto_num, address) not in addresses:
            addresses.append((family, proto_num, address))
    addresses.sort(key=lambda a: a[0] != socket.AF_INET)
    return addresses


@dataclass(slots=True)
class TargetStats:
    """What happened to one recorded target's traffic."""

    key: str
    to: str
    connections: int = 0
    opened: int = 0
    refused: int = 0
    reset: int = 0
    closed_by_peer: int = 0
    packets: int = 0
    bytes: int = 0
    dropped: int = 0
    received: int = 0
    datagrams: int = 0
    errors: list[str] = field(default_factory=list)
    error_count: int = 0

    def error(self, text: str) -> bool:
        """Count an error; True while it is one of the first MAX_ERRORS (kept)."""
        self.error_count += 1
        if len(self.errors) < MAX_ERRORS:
            self.errors.append(text)
            return True
        return False

    def to_json(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "to": self.to,
            "connections": self.connections,
            "opened": self.opened,
            "refused": self.refused,
            "reset": self.reset,
            "closedByPeer": self.closed_by_peer,
            "packets": self.packets,
            "bytes": self.bytes,
            "dropped": self.dropped,
            "received": self.received,
            "datagrams": self.datagrams,
            "errors": self.errors,
            "errorCount": self.error_count,
        }


@dataclass(slots=True)
class Destination:
    """Where a recorded target's traffic goes."""

    proto: str
    addresses: list[Address]  # tried in order; the one that worked moves first
    label: str  # "127.0.0.1:11001"


@dataclass(eq=False, slots=True)
class _Conn:
    flow: tuple[int, int]  # (loop, planner flow)
    sock: socket.socket
    stats: TargetStats
    udp: bool = False
    connected: bool = False
    out: bytearray = field(default_factory=bytearray)
    after: str | None = None  # "fin" | "rst" once the recording closed it
    write_shut: bool = False
    peer_closed: bool = False
    dead: bool = False
    number: int = 0  # the target's connection number (1, 2…), for the log
    candidates: list[Address] = field(default_factory=list)  # TCP: still to try


class StoppedError(Exception):
    """replay_stop ended the replay."""


class Replayer:
    """Carries out the planner's events against live services.

    ``destinations`` maps recorded target keys to where they go; events for
    other targets are skipped. ``speed`` divides the recorded pauses (0: none).
    """

    def __init__(
        self,
        destinations: dict[str, Destination],
        speed: float,
        token: CancelToken,
        progress: Callable[[dict[str, Any]], None] = lambda _p: None,
        duration: float | None = None,
    ) -> None:
        self._dest = destinations
        self._speed = speed
        self._token = token
        self._progress = progress
        self._duration = duration
        self._stop = threading.Event()
        # The tshark passes' token: stop() ends a pass still looking for records.
        self.pass_token = CancelToken()
        token.on_cancel(self.pass_token.cancel)
        self._sel = selectors.DefaultSelector()
        self._conns: dict[tuple[int, int], _Conn] = {}
        self._buffered = 0
        self._last_progress = 0.0
        self._started = time.monotonic()
        self._log: list[dict[str, Any]] = []
        self._log_dropped = 0
        self.stats = {
            key: TargetStats(key, d.label) for key, d in self._dest.items()
        }  # fmt: skip
        self.loops_done = 0

    def log(self, text: str, target: str = "", level: str = "info") -> None:
        """A line for the event log, sent with the next progress report."""
        if len(self._log) >= MAX_LOG:
            self._log_dropped += 1
            return
        line = {"time": round(time.monotonic() - self._started, 3), "level": level, "text": text}
        if target:
            line["target"] = target
        self._log.append(line)

    def take_log(self) -> list[dict[str, Any]]:
        """The log lines not reported yet (and how many didn't fit)."""
        lines, self._log = self._log, []
        if self._log_dropped:
            lines.append(
                {
                    "time": round(time.monotonic() - self._started, 3),
                    "level": "info",
                    "text": f"{self._log_dropped:,} more lines not shown",
                }
            )
            self._log_dropped = 0
        return lines

    def _error(self, stats: TargetStats, text: str) -> None:
        if stats.error(text):
            self.log(text, stats.key, "error")
        elif stats.error_count == MAX_ERRORS + 1:
            self.log("further errors of this target are only counted", stats.key, "error")

    def stop(self) -> bool:
        """End the replay at the next step (connections are closed)."""
        already = self._stop.is_set()
        self._stop.set()
        self.pass_token.cancel()
        return not already

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()

    # -- the timeline -----------------------------------------------------------------

    def run(self, passes: Callable[[], Iterator[Event]], loops: int = 1) -> None:
        """Replay ``passes()`` (a fresh event iterator per loop) ``loops`` times."""
        try:
            for loop in range(loops):
                if loops > 1:
                    self.log(f"loop {loop + 1} of {loops}")
                self._loop(loop, passes())
                self.loops_done = loop + 1
            self._drain()
        except StoppedError:
            pass
        except CancelledError:
            if not self._stop.is_set():
                raise  # (cancelled: raised below; else a pass that stop() ended)
        finally:
            self._close_all()
        self._token.raise_if_cancelled()

    def _check(self) -> None:
        if self._token.cancelled or self._stop.is_set():
            raise StoppedError

    def _loop(self, loop: int, events: Iterator[Event]) -> None:
        try:
            self._timeline(loop, events)
        finally:
            close = getattr(events, "close", None)
            if close is not None:
                close()  # (a stopped replay's tshark pass ends now)

    def _timeline(self, loop: int, events: Iterator[Event]) -> None:
        start = t0 = None
        for ev in events:
            self._check()
            if ev.target not in self._dest:
                continue
            if start is None or t0 is None:
                # The clock starts with the first event (not before tshark's start-up).
                start, t0 = time.monotonic(), ev.time
            if self._speed > 0:
                self._wait_until(start + (ev.time - t0) / self._speed)
            while self._buffered > MAX_BUFFERED:
                self._check()  # (a service that stops reading mustn't keep Stop waiting)
                self._service(0.05)
            self._apply((loop, ev.flow), ev)
            self._service(0)
            self._report(ev.time, t0, loop)
        # (Connections left open by the recording stay open until the end.)

    def _wait_until(self, due: float) -> None:
        while True:
            self._check()
            left = due - time.monotonic()
            if left <= 0:
                return
            self._service(min(left, 0.05))

    def _drain(self) -> None:
        """Write what is still buffered, close what the recording closed, then
        give the service a moment to answer."""
        deadline = time.monotonic() + DRAIN_S
        while any(c.out for c in self._conns.values() if not c.dead):
            self._check()
            if time.monotonic() > deadline:
                # The service stopped reading: what it didn't take is lost.
                for conn in self._conns.values():
                    if conn.out and not conn.dead:
                        conn.stats.dropped += len(conn.out)
                        self._error(
                            conn.stats,
                            f"{len(conn.out):,} bytes not delivered: {conn.stats.to} "
                            f"stopped reading for {DRAIN_S:g} s",
                        )
                        self._close(conn)
                break
            self._service(0.05)
        grace = time.monotonic() + ANSWER_GRACE_S
        while time.monotonic() < grace:
            self._check()
            self._service(0.05)

    def _report(self, at: float, t0: float, loop: int, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last_progress < PROGRESS_EVERY_S:
            return
        self._last_progress = now
        fraction = None
        if self._duration:
            fraction = min(1.0, max(0.0, (at - t0) / self._duration))
        self._progress(
            {
                "phase": "replay",
                "fraction": fraction,
                "loop": loop + 1,
                "sent": sum(s.bytes for s in self.stats.values()),
                "received": sum(s.received for s in self.stats.values()),
                "open": sum(1 for c in self._conns.values() if not c.dead and not c.udp),
                "targets": self.summary(),
                "log": self.take_log(),
            }
        )

    # -- events -----------------------------------------------------------------------

    def _apply(self, flow: tuple[int, int], ev: Event) -> None:
        dest = self._dest[ev.target]
        stats = self.stats[ev.target]
        conn = self._conns.get(flow)
        if ev.kind == "open":
            self._open(flow, dest, stats)
        elif ev.kind == "data":
            if conn is None or conn.dead:
                stats.dropped += len(ev.data)
                return
            stats.packets += 1
            conn.out += ev.data
            self._buffered += len(ev.data)
            self._flush(conn)
        elif ev.kind == "close":
            if conn is not None and not conn.dead:
                conn.after = "rst" if ev.reset else "fin"
                self._flush(conn)
        elif ev.kind == "datagram":
            self._datagram(flow, dest, stats, ev.data)

    def _open(self, flow: tuple[int, int], dest: Destination, stats: TargetStats) -> None:
        stats.connections += 1
        conn = _Conn(flow, socket.socket(socket.AF_INET, socket.SOCK_STREAM), stats)
        conn.number = stats.connections
        conn.candidates = list(dest.addresses)
        self._conns[flow] = conn
        self._connect(conn)

    def _connect(self, conn: _Conn) -> None:
        """Connect a new socket to the first address still to try."""
        family, proto_num, address = conn.candidates[0]
        conn.sock.close()
        try:
            conn.sock = socket.socket(family, socket.SOCK_STREAM, proto_num)
            conn.sock.setblocking(False)
            code = conn.sock.connect_ex(address)
        except OSError as exc:  # (no IPv6 on this machine…)
            code = exc.errno or errno.EADDRNOTAVAIL
        if code not in _CONNECTING:
            self._connect_failed(conn, code)
            return
        self._sel.register(conn.sock, selectors.EVENT_READ | selectors.EVENT_WRITE, conn)

    def _connect_failed(self, conn: _Conn, code: int) -> None:
        """Try the destination's next address, else count the failure."""
        dest = self._dest[conn.stats.key]
        conn.candidates.pop(0)
        if conn.candidates:
            with contextlib.suppress(KeyError, ValueError):
                self._sel.unregister(conn.sock)
            self._connect(conn)
            return
        self._fail(conn, f"connection to {dest.label} failed: {_error_text(code)}", code)

    def _connected(self, conn: _Conn) -> None:
        conn.connected = True
        conn.stats.opened += 1
        dest = self._dest[conn.stats.key]
        self.log(f"connection {conn.number} to {dest.label} opened", conn.stats.key)
        working = conn.candidates[0]
        if dest.addresses[0] != working:  # (later connections try it first)
            dest.addresses.remove(working)
            dest.addresses.insert(0, working)

    def _datagram(
        self, flow: tuple[int, int], dest: Destination, stats: TargetStats, data: bytes
    ) -> None:
        conn = self._conns.get(flow)
        if conn is None:
            stats.connections += 1
            family, proto_num, address = dest.addresses[0]
            sock = socket.socket(family, socket.SOCK_DGRAM, proto_num)
            sock.setblocking(False)
            conn = _Conn(flow, sock, stats, udp=True, connected=True)
            self._conns[flow] = conn
            try:
                sock.connect(address)  # (a refused port then shows as an error)
            except OSError as exc:
                self._fail(conn, f"{dest.label}: {exc.strerror or exc}")
                return
            self._sel.register(sock, selectors.EVENT_READ, conn)
        if conn.dead:
            stats.dropped += len(data)
            return
        try:
            sock = conn.sock
            sock.send(data)
            stats.datagrams += 1
            stats.packets += 1
            stats.bytes += len(data)
        except ConnectionRefusedError:
            stats.refused += 1
            stats.dropped += len(data)
            self._error(stats, f"{dest.label}: nothing listens on this UDP port (refused)")
        except BlockingIOError:
            stats.dropped += len(data)
            self._error(stats, f"{dest.label}: datagram dropped (send buffer full)")
        except OSError as exc:
            stats.dropped += len(data)
            self._error(stats, f"{dest.label}: {exc.strerror or exc}")

    # -- sockets ----------------------------------------------------------------------

    def _service(self, timeout: float) -> None:
        if not self._sel.get_map():
            if timeout > 0:
                time.sleep(timeout)
            return
        for key, mask in self._sel.select(timeout):
            conn: _Conn = key.data
            if conn.dead:
                continue
            if not conn.connected and mask & selectors.EVENT_WRITE:
                code = conn.sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if code:
                    self._connect_failed(conn, code)
                    continue
                self._connected(conn)
            if mask & selectors.EVENT_READ:
                self._read(conn)
            if not conn.dead and conn.connected and not conn.udp:
                self._flush(conn)

    def _read(self, conn: _Conn) -> None:
        try:
            data = conn.sock.recv(65536)
        except BlockingIOError:
            return
        except ConnectionRefusedError:
            if conn.udp:
                conn.stats.refused += 1
                text = f"{conn.stats.to}: nothing listens on this UDP port (refused)"
                self._error(conn.stats, text)
                return
            if not conn.connected:
                self._connect_failed(conn, errno.ECONNREFUSED)
                return
            self._fail(conn, f"connection to {conn.stats.to} refused", errno.ECONNREFUSED)
            return
        except OSError as exc:
            if conn.udp:
                self._error(conn.stats, f"{conn.stats.to}: {exc.strerror or exc}")
                return
            conn.stats.reset += 1
            self._fail(conn, f"{conn.stats.to} reset the connection")
            return
        if data:
            conn.stats.received += len(data)
            return
        if conn.udp:
            return
        # The service closed its side: count it, stop reading.
        if not conn.peer_closed:
            conn.peer_closed = True
            conn.stats.closed_by_peer += 1
            self.log(f"{conn.stats.to} closed connection {conn.number}", conn.stats.key)
        self._update(conn)

    def _flush(self, conn: _Conn) -> None:
        if not conn.connected or conn.dead:
            self._update(conn)
            return
        while conn.out:
            try:
                n = conn.sock.send(conn.out)
            except BlockingIOError:
                break
            except OSError as exc:
                conn.stats.reset += 1
                self._fail(conn, f"{conn.stats.to}: {exc.strerror or exc} while sending")
                return
            del conn.out[:n]
            self._buffered -= n
            conn.stats.bytes += n
        if not conn.out and conn.after is not None:
            if conn.after == "rst":
                self._abort(conn)
                return
            if not conn.write_shut:
                conn.write_shut = True
                # (A service that reset it already is counted when read.)
                with contextlib.suppress(OSError):
                    conn.sock.shutdown(socket.SHUT_WR)
        self._update(conn)

    def _update(self, conn: _Conn) -> None:
        """Ask the selector for what the connection still needs."""
        if conn.dead:
            return
        mask = 0
        if not conn.peer_closed:
            mask |= selectors.EVENT_READ
        if not conn.connected or conn.out:
            mask |= selectors.EVENT_WRITE
        if mask == 0:
            if conn.write_shut:
                self._close(conn)  # both sides done
                return
            # (The service closed, the recording hasn't: idle until more data.)
            with contextlib.suppress(KeyError):
                self._sel.unregister(conn.sock)
            return
        try:
            self._sel.modify(conn.sock, mask, conn)
        except KeyError:
            self._sel.register(conn.sock, mask, conn)

    def _fail(self, conn: _Conn, text: str, code: int | None = None) -> None:
        if code in (errno.ECONNREFUSED, 10061):  # WSAECONNREFUSED
            conn.stats.refused += 1
        self._error(conn.stats, text)
        conn.stats.dropped += len(conn.out)
        self._close(conn)

    def _abort(self, conn: _Conn) -> None:
        """Close with a reset, as the recording did."""
        linger = struct.pack("HH" if IS_WINDOWS else "ii", 1, 0)
        with contextlib.suppress(OSError):
            conn.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
        self._close(conn)

    def _close(self, conn: _Conn) -> None:
        if conn.dead:
            return
        conn.dead = True
        self._buffered -= len(conn.out)
        conn.out.clear()
        with contextlib.suppress(KeyError, ValueError):
            self._sel.unregister(conn.sock)
        conn.sock.close()

    def _close_all(self) -> None:
        for conn in list(self._conns.values()):
            self._close(conn)
        self._sel.close()

    def summary(self) -> list[dict[str, Any]]:
        return [s.to_json() for s in self.stats.values()]


def _error_text(code: int) -> str:
    if code in (errno.ECONNREFUSED, 10061):  # (10061: WSAECONNREFUSED)
        return "refused (is the service listening on that port?)"
    return os.strerror(code)
