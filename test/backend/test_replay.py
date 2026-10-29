"""Replay to Service: the planner, destination checks, and replays of
replay.pcap (an operator delivering HI2/HI3-like data) into local servers."""

from __future__ import annotations

import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from pcap_backend import replay
from pcap_backend.cancellation import CancelledError, CancelToken
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import FilterError, InvalidParamsError, RequestContext
from pcap_backend.replay import Record, TargetError
from pcap_backend.tshark import find_tool

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
sys.path.insert(0, str(FIXTURES))
import generate  # noqa: E402 - the fixture's PDUs and expected bytes

HI2 = f"tcp {generate.REPLAY_COLLECTOR}:{generate.REPLAY_HI2}"
HI3 = f"tcp {generate.REPLAY_COLLECTOR}:{generate.REPLAY_HI3}"
UDP = f"udp {generate.REPLAY_COLLECTOR}:{generate.REPLAY_UDP}"
DNS = "udp 10.0.0.53:53"


# -- the planner ------------------------------------------------------------------------


def test_parse_record() -> None:
    addresses = ["15", "0.05", "10.10.0.1", "", "10.20.0.5", "", "0", "40100", "11000"]
    tcp = "\t".join([*addresses, "False", "True", "False", "False", "1000", "", "", "", "3082", ""])
    assert replay.parse_record(tcp) == Record(
        15, 0.05, "tcp", 0, "10.10.0.1", 40100, "10.20.0.5", 11000, b"\x30\x82", ack=True, seq=1000
    )
    udp = "16\t0.05\t\tfd00::1\t\tfd00::5\t\t\t\t\t\t\t\t\t1\t40200\t11002\t\t0102"
    rec = replay.parse_record(udp)
    assert rec is not None and (rec.proto, rec.src, rec.dst, rec.payload) == (
        "udp", "fd00::1", "fd00::5", b"\x01\x02",
    )  # fmt: skip
    assert replay.target_key("udp", rec.dst, rec.dport) == "udp [fd00::5]:11002"
    # tshark 4.6 prints booleans as 1/0.
    syn = "1\t0\t10.0.0.1\t\t10.0.0.2\t\t0\t5000\t80\t1\t0\t0\t0\t7\t\t\t\t\t"
    assert replay.parse_record(syn) == Record(
        1, 0.0, "tcp", 0, "10.0.0.1", 5000, "10.0.0.2", 80, syn=True, seq=7
    )
    assert replay.parse_record("4\t0.005\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t") is None  # ARP
    assert replay.parse_record("garbage") is None


def _tcp(
    frame: int, src: str, sport: int, dst: str, dport: int, payload: bytes = b"", **kw: Any
) -> Record:
    return Record(frame, frame / 100, "tcp", 0, src, sport, dst, dport, payload, **kw)


C, S = "10.0.0.1", "10.0.0.2"


def test_planner_sends_the_client_side_once() -> None:
    planner, events = replay.plan(
        [
            _tcp(1, C, 40000, S, 9000, syn=True, seq=99),
            _tcp(2, S, 9000, C, 40000, syn=True, ack=True, seq=499),
            _tcp(3, C, 40000, S, 9000, b"abcd", ack=True, seq=100),
            _tcp(4, S, 9000, C, 40000, b"answer", ack=True, seq=500),  # the server: ignored
            _tcp(5, C, 40000, S, 9000, b"abcd", ack=True, seq=100),  # retransmission
            _tcp(6, C, 40000, S, 9000, b"cdef", ack=True, seq=102),  # overlaps by 2
            _tcp(7, C, 40000, S, 9000, b"xyz", ack=True, seq=110),  # 4 bytes missing
            _tcp(8, C, 40000, S, 9000, fin=True, ack=True, seq=113),
            _tcp(9, C, 40000, S, 9000, b"late", ack=True, seq=114),  # after the FIN
        ]
    )
    key = f"tcp {S}:9000"
    assert [(e.kind, e.data, e.reset) for e in events] == [
        ("open", b"", False),
        ("data", b"abcd", False),
        ("data", b"ef", False),
        ("data", b"xyz", False),
        ("close", b"", False),
    ]
    assert all(e.target == key for e in events) and events[0].time == 0.01
    info = planner.targets[key]
    assert (info.connections, info.packets, info.bytes) == (1, 3, 9)
    assert (info.retransmissions, info.gaps, info.first_frame) == (2, 1, 3)


def test_planner_puts_out_of_order_segments_back_in_order() -> None:
    # Captured out of order: held until the missing bytes come, not dropped.
    planner, events = replay.plan(
        [
            _tcp(1, C, 40000, S, 9000, syn=True, seq=99),
            _tcp(2, C, 40000, S, 9000, b"efgh", ack=True, seq=104),
            _tcp(3, C, 40000, S, 9000, b"ijkl", ack=True, seq=108),
            _tcp(4, C, 40000, S, 9000, b"abcd", ack=True, seq=100),
            _tcp(5, C, 40000, S, 9000, b"efgh", ack=True, seq=104),  # retransmission
            _tcp(6, C, 40000, S, 9000, fin=True, ack=True, seq=112),
        ]
    )
    assert [(e.kind, e.data, e.time) for e in events] == [
        ("open", b"", 0.01),
        ("data", b"abcd", 0.04),
        ("data", b"efgh", 0.04),
        ("data", b"ijkl", 0.04),
        ("close", b"", 0.06),
    ]
    info = planner.targets[f"tcp {S}:9000"]
    assert (info.gaps, info.retransmissions, info.bytes) == (0, 1, 12)


def test_planner_gives_up_on_a_gap_in_time() -> None:
    # Bytes the capture lacks: the data after them waits REORDER_WINDOW_S at most.
    late = 0.02 + replay.REORDER_WINDOW_S + 0.01
    gap = Record(9, late, "udp", 7, C, 5000, S, 5004, b"x")  # (another flow's packet)
    planner, events = replay.plan(
        [
            _tcp(1, C, 40000, S, 9000, b"abcd", ack=True, seq=100),
            _tcp(2, C, 40000, S, 9000, b"ijkl", ack=True, seq=108),  # "efgh" never captured
            gap,
            _tcp(10, C, 40000, S, 9000, b"mn", ack=True, seq=112),
        ]
    )
    data = [(e.data, e.time) for e in events if e.kind == "data"]
    assert data == [(b"abcd", 0.01), (b"ijkl", late), (b"mn", 0.1)]
    assert planner.targets[f"tcp {S}:9000"].gaps == 1
    # At the end of the capture, held data goes when its window would have ended.
    planner, events = replay.plan(
        [
            _tcp(1, C, 40000, S, 9000, b"abcd", ack=True, seq=100),
            _tcp(2, C, 40000, S, 9000, b"ijkl", ack=True, seq=108),
        ]
    )
    assert [(e.data, e.time) for e in events if e.kind == "data"] == [
        (b"abcd", 0.01),
        (b"ijkl", 0.02),
    ]


def test_planner_sends_a_syn_s_own_data() -> None:
    # TCP Fast Open: the SYN carries data, which starts after the SYN's number.
    _, events = replay.plan(
        [
            _tcp(1, C, 40000, S, 9000, b"abcd", syn=True, seq=99),
            _tcp(2, C, 40000, S, 9000, b"efgh", ack=True, seq=104),
            _tcp(3, C, 40000, S, 9000, b"x", ack=True, seq=103),  # already sent
        ]
    )
    assert [e.data for e in events if e.kind == "data"] == [b"abcd", b"efgh"]
    # A retransmitted SYN brings the same data again (tcpdump's
    # bgp-shutdown-msg-variations.pcap: three SYNs with data, found by test/realworld).
    planner, events = replay.plan(
        [
            _tcp(1, C, 40000, S, 9000, b"abcd", syn=True, seq=99),
            _tcp(2, C, 40000, S, 9000, b"abcd", syn=True, seq=99),
            _tcp(3, C, 40000, S, 9000, b"efgh", ack=True, seq=104),
        ]
    )
    assert [e.data for e in events if e.kind == "data"] == [b"abcd", b"efgh"]
    assert planner.targets[f"tcp {S}:9000"].retransmissions == 1


def test_planner_finds_the_client_without_a_handshake() -> None:
    # Started before the capture: the higher port is the client, from either side.
    _, events = replay.plan(
        [
            _tcp(1, S, 11000, C, 40102, b"ack", ack=True, seq=5),
            _tcp(2, C, 40102, S, 11000, b"PDU", ack=True, seq=4294967294),  # wraps
            _tcp(3, C, 40102, S, 11000, b"!", ack=True, seq=1),
            _tcp(4, C, 40102, S, 11000, rst=True, seq=2),
        ]
    )
    assert [(e.kind, e.target, e.data, e.reset) for e in events] == [
        ("open", f"tcp {S}:11000", b"", False),
        ("data", f"tcp {S}:11000", b"PDU", False),
        ("data", f"tcp {S}:11000", b"!", False),
        ("close", f"tcp {S}:11000", b"", True),
    ]
    # A SYN-ACK seen first: its receiver is the client.
    _, events = replay.plan(
        [
            _tcp(1, S, 80, C, 50000, syn=True, ack=True, seq=0),
            _tcp(2, C, 50000, S, 80, b"GET", ack=True, seq=1),
        ]
    )
    assert [(e.kind, e.target) for e in events] == [
        ("open", f"tcp {S}:80"),
        ("data", f"tcp {S}:80"),
    ]


def test_planner_udp_flows() -> None:
    def udp(frame: int, src: str, sport: int, dst: str, dport: int, data: bytes) -> Record:
        return Record(frame, frame / 10, "udp", 3, src, sport, dst, dport, data)

    planner, events = replay.plan(
        [
            udp(1, C, 5060, S, 5070, b"INVITE"),
            udp(2, S, 5070, C, 5060, b"100"),
            udp(3, C, 5060, S, 5070, b"ACK"),
        ]
    )
    assert [(e.kind, e.target, e.data) for e in events] == [
        ("datagram", f"udp {S}:5070", b"INVITE"),
        ("datagram", f"udp {S}:5070", b"ACK"),
    ]
    assert planner.targets[f"udp {S}:5070"].connections == 1


def test_destinations_stay_local_unless_allowed() -> None:
    for host in ("127.0.0.1", "localhost", "10.1.2.3", "192.168.65.2", "::1", "[::1]"):
        replay.resolve_target(host, 11000, "tcp", allow_public=False)
    with pytest.raises(TargetError, match="not on this machine"):
        replay.resolve_target("8.8.8.8", 53, "udp", allow_public=False)
    assert replay.resolve_target("8.8.8.8", 53, "udp", allow_public=True)[0][2][0] == "8.8.8.8"
    # localhost: IPv4 first (most local services listen there), then IPv6.
    families = [a[0] for a in replay.resolve_target("localhost", 80, "tcp", allow_public=False)]
    assert families[0] == socket.AF_INET and families == sorted(
        families, key=lambda f: f != socket.AF_INET
    )
    with pytest.raises(TargetError, match="between 1 and 65535"):
        replay.resolve_target("127.0.0.1", 0, "tcp", allow_public=False)
    with pytest.raises(TargetError, match="needs an IP"):
        replay.resolve_target(" ", 80, "tcp", allow_public=False)
    assert replay.is_local("::ffff:10.0.0.1") and not replay.is_local("::ffff:8.8.8.8")


# -- local services ---------------------------------------------------------------------


class Collector:
    """A TCP server on 127.0.0.1 keeping each connection's bytes (in accept
    order); it answers ``answer`` to each connection's first data."""

    def __init__(self, answer: bytes = b"") -> None:
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.sock.settimeout(0.1)
        self.port = self.sock.getsockname()[1]
        self.answer = answer
        self.received: list[bytes] = []
        self.times: list[float] = []  # when each chunk of data arrived (monotonic)
        self._threads: list[threading.Thread] = []
        self._done = threading.Event()
        self._lock = threading.Lock()
        self._accept = threading.Thread(target=self._loop, daemon=True)
        self._accept.start()

    def _loop(self) -> None:
        while not self._done.is_set():
            try:
                conn, _ = self.sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with self._lock:
                index = len(self.received)
                self.received.append(b"")
            t = threading.Thread(target=self._serve, args=(conn, index), daemon=True)
            t.start()
            self._threads.append(t)

    def _serve(self, conn: socket.socket, index: int) -> None:
        answered = False
        with conn:
            conn.settimeout(10)
            while True:
                try:
                    data = conn.recv(65536)
                except OSError:
                    return  # (reset)
                if not data:
                    return
                with self._lock:
                    self.received[index] += data
                    self.times.append(time.monotonic())
                if self.answer and not answered:
                    answered = True
                    try:
                        conn.sendall(self.answer)
                    except OSError:
                        return  # (the replay reset it, as the recording did)

    def close(self) -> None:
        self._done.set()
        self._accept.join(5)
        self.sock.close()
        for t in self._threads:
            t.join(5)


class Datagrams:
    """A UDP socket on 127.0.0.1 keeping what arrives and answering each."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.1)
        self.port = self.sock.getsockname()[1]
        self.received: list[bytes] = []
        self._done = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._done.is_set():
            try:
                data, peer = self.sock.recvfrom(65536)
            except TimeoutError:
                continue
            except OSError:
                return
            self.received.append(data)
            self.sock.sendto(b"ok", peer)

    def close(self) -> None:
        self._done.set()
        self._thread.join(5)
        self.sock.close()


@pytest.fixture
def services() -> Iterator[tuple[Collector, Collector, Datagrams]]:
    hi2, hi3, udp = Collector(answer=b"\x30\x03ack"), Collector(), Datagrams()
    try:
        yield hi2, hi3, udp
    finally:
        hi2.close()
        hi3.close()
        udp.close()


@pytest.fixture
def opened(service: PcapService, ctx: RequestContext) -> PcapService:
    service.open({"path": str(FIXTURES / "replay.pcap"), "names": {}}, ctx)
    return service


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _settle() -> None:
    """Let the servers' threads read what was sent before checking it."""
    time.sleep(0.2)


def test_a_refused_address_falls_back_to_the_next(services: Any) -> None:
    # As with localhost resolving to ::1 first and a service listening on IPv4.
    hi2, _, _ = services
    closed = (socket.AF_INET, socket.IPPROTO_TCP, ("127.0.0.1", _free_port()))
    working = (socket.AF_INET, socket.IPPROTO_TCP, ("127.0.0.1", hi2.port))
    dest = replay.Destination("tcp", [closed, working], "localhost:11000")
    events = [
        replay.Event("open", 0.0, 1, "t"),
        replay.Event("data", 0.0, 1, "t", b"first"),
        replay.Event("close", 0.0, 1, "t"),
        replay.Event("open", 0.0, 2, "t"),
        replay.Event("data", 0.0, 2, "t", b"second"),
    ]
    runner = replay.Replayer({"t": dest}, 0, CancelToken())
    runner.run(lambda: iter(events))
    _settle()
    assert sorted(hi2.received) == [b"first", b"second"]
    stats = runner.stats["t"]
    assert (stats.connections, stats.opened, stats.refused, stats.errors) == (2, 2, 0, [])
    assert dest.addresses[0] == working  # (tried first from then on)


def test_data_a_service_does_not_read_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(replay, "DRAIN_S", 0.5)
    monkeypatch.setattr(replay, "ANSWER_GRACE_S", 0.0)
    server = socket.create_server(("127.0.0.1", 0))
    server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)  # (accepted ones inherit it)
    accepted: list[socket.socket] = []
    taker = threading.Thread(target=lambda: accepted.append(server.accept()[0]), daemon=True)
    taker.start()
    address = (socket.AF_INET, socket.IPPROTO_TCP, server.getsockname())
    dest = replay.Destination("tcp", [address], "127.0.0.1:1")
    # More than the socket buffers on both sides hold (under MAX_BUFFERED), in
    # 64 KB pieces as a capture's segments come: Windows takes one send of any
    # size into an empty buffer, so 16 MB at once all counted as sent there.
    chunk, count = 64 << 10, 256
    size = chunk * count
    events = [
        replay.Event("open", 0.0, 1, "t"),
        *(replay.Event("data", 0.0, 1, "t", bytes(chunk)) for _ in range(count)),
        replay.Event("close", 0.0, 1, "t"),
    ]
    runner = replay.Replayer({"t": dest}, 0, CancelToken())
    try:
        runner.run(lambda: iter(events))
    finally:
        taker.join(5)
        for sock in accepted:
            sock.close()
        server.close()
    stats = runner.stats["t"]
    assert stats.bytes + stats.dropped == size and stats.dropped > 0
    assert stats.error_count == 1
    assert "not delivered" in stats.errors[0] and "stopped reading" in stats.errors[0]
    last = runner.take_log()[-1]  # (earlier lines went out with progress reports)
    assert (last["level"], last["text"]) == ("error", stats.errors[0])


# -- replays of replay.pcap -------------------------------------------------------------


@pytest.mark.tshark
def test_recorded_targets(opened: PcapService, ctx: RequestContext) -> None:
    found = opened.replay_targets({}, ctx)
    targets = {t["key"]: t for t in found["targets"]}
    assert list(targets) == [DNS, HI2, UDP, HI3]  # by first data
    hi2, hi3, udp = targets[HI2], targets[HI3], targets[UDP]
    assert (hi2["connections"], hi2["retransmissions"], hi2["gaps"]) == (3, 1, 0)
    assert hi2["bytes"] == sum(map(len, generate.REPLAY_EXPECTED[HI2]))
    assert (hi3["connections"], hi3["retransmissions"], hi3["gaps"]) == (2, 1, 1)
    assert hi3["bytes"] == sum(map(len, generate.REPLAY_EXPECTED[HI3]))
    assert (udp["connections"], udp["packets"]) == (1, 3)
    assert hi2["protocol"] == "TCP" and targets[DNS]["protocol"] == "DNS"
    assert (hi2["proto"], hi2["ip"], hi2["port"]) == ("tcp", generate.REPLAY_COLLECTOR, 11000)
    # First data 0.01 (DNS), last 0.26: D3 waited behind D's gap until D's FIN.
    assert found["duration"] == pytest.approx(0.25)
    only = opened.replay_targets({"filter": "tcp.port == 11001"}, ctx)
    assert [t["key"] for t in only["targets"]] == [HI3] and only["filter"] == "tcp.port == 11001"
    with pytest.raises(FilterError):
        opened.replay_targets({"filter": "tcp.port =="}, ctx)


@pytest.mark.tshark
def test_replay_sends_the_operator_side(
    opened: PcapService, ctx: RequestContext, services: tuple[Collector, Collector, Datagrams]
) -> None:
    hi2, hi3, udp = services
    progress: list[dict[str, Any]] = []
    ctx.progress = progress.append
    result = opened.replay(
        {
            "speed": 0,
            "targets": {
                HI2: {"ip": "127.0.0.1", "port": hi2.port},
                HI3: {"ip": "localhost", "port": hi3.port},
                UDP: {"ip": "127.0.0.1", "port": udp.port},
            },
        },
        ctx,
    )
    _settle()
    assert result["stopped"] is False and result["loops"] == 1
    stats = {t["key"]: t for t in result["targets"]}
    assert set(stats) == {HI2, HI3, UDP}  # (DNS not asked for: not sent)
    # Every connection's operator bytes, once, in order. E's reset may take its PDU
    # with it (Windows drops data the service hasn't read yet when a reset comes).
    a, e, c = generate.REPLAY_EXPECTED[HI2]
    assert sorted(hi2.received) in (sorted([a, e, c]), sorted([a, b"", c]))
    assert len(hi2.received) == 3
    assert sorted(hi3.received) == sorted(generate.REPLAY_EXPECTED[HI3])
    assert udp.received == generate.REPLAY_EXPECTED[UDP]
    s2, s3, su = stats[HI2], stats[HI3], stats[UDP]
    assert (s2["connections"], s2["opened"], s2["refused"]) == (3, 3, 0)
    assert s2["bytes"] == sum(map(len, generate.REPLAY_EXPECTED[HI2]))
    assert s2["received"] > 0 and s2["to"] == f"127.0.0.1:{hi2.port}"
    assert (s3["connections"], s3["opened"], s3["bytes"], s3["received"]) == (
        2, 2, sum(map(len, generate.REPLAY_EXPECTED[HI3])), 0,
    )  # fmt: skip
    assert (su["datagrams"], su["received"]) == (3, 6)
    assert progress and progress[0]["phase"] == "replay-targets"
    reports = [p for p in progress if p["phase"] == "replay"]
    assert reports and {t["key"] for t in reports[-1]["targets"]} == {HI2, HI3, UDP}
    log = [line for p in reports for line in p["log"]] + result["log"]
    opened_lines = [line["text"] for line in log if line.get("target") == HI2]
    assert opened_lines[:1] == [f"connection 1 to 127.0.0.1:{hi2.port} opened"]
    assert all(line["level"] == "info" for line in log)


@pytest.mark.tshark
def test_replay_keeps_the_recorded_timing(
    opened: PcapService,
    ctx: RequestContext,
    services: tuple[Collector, Collector, Datagrams],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(replay, "ANSWER_GRACE_S", 0.0)
    hi2, _, _ = services

    def spread(speed: float) -> float:
        """Seconds between the first and the last data the service got."""
        hi2.times.clear()
        params = {"speed": speed, "targets": {HI2: {"ip": "127.0.0.1", "port": hi2.port}}}
        opened.replay(params, ctx)
        _settle()
        return max(hi2.times) - min(hi2.times)

    # HI2's data was recorded from 0.05 s to 0.25 s. Measured where the service
    # sees it, not as the request's duration, which includes tshark's start-up
    # (0.22 s for a first, cold run on Windows CI, then less).
    assert spread(1) >= 0.18
    assert spread(2) >= 0.08
    assert spread(0) < spread(1)


@pytest.mark.tshark
def test_replay_reports_refused_ports_and_loops(
    opened: PcapService, ctx: RequestContext, services: tuple[Collector, Collector, Datagrams]
) -> None:
    hi2, _, _ = services
    progress: list[dict[str, Any]] = []
    ctx.progress = progress.append
    result = opened.replay(
        {
            "speed": 0,
            "loops": 2,
            "targets": {
                HI2: {"ip": "127.0.0.1", "port": hi2.port},
                HI3: {"ip": "127.0.0.1", "port": _free_port()},
            },
        },
        ctx,
    )
    _settle()
    stats = {t["key"]: t for t in result["targets"]}
    assert result["loops"] == 2 and len(hi2.received) == 6
    assert (stats[HI3]["connections"], stats[HI3]["opened"], stats[HI3]["refused"]) == (4, 0, 4)
    assert stats[HI3]["dropped"] == 2 * sum(map(len, generate.REPLAY_EXPECTED[HI3]))
    assert "refused" in stats[HI3]["errors"][0] and stats[HI3]["errorCount"] == 4
    log = [line for p in progress if p["phase"] == "replay" for line in p["log"]] + result["log"]
    loops = [line["text"] for line in log if line["text"].startswith("loop")]
    assert loops == ["loop 1 of 2", "loop 2 of 2"]
    refused = [line for line in log if line["level"] == "error"]
    assert len(refused) == 4 and all(line["target"] == HI3 for line in refused)


@pytest.mark.tshark
def test_replay_stop(
    opened: PcapService, ctx: RequestContext, services: tuple[Collector, Collector, Datagrams]
) -> None:
    hi2, _, _ = services
    assert opened.replay_stop({}, ctx) == {"stopped": False}
    opened.replay_targets({}, ctx)  # (so the replay starts at once)
    params = {"speed": 0.02, "targets": {HI2: {"ip": "127.0.0.1", "port": hi2.port}}}
    out: dict[str, Any] = {}
    worker = threading.Thread(target=lambda: out.update(opened.replay(params, ctx)))
    worker.start()
    time.sleep(0.5)
    with pytest.raises(InvalidParamsError, match="already running"):
        opened.replay(params, ctx)
    assert opened.replay_stop({}, ctx) == {"stopped": True}
    worker.join(10)
    assert out["stopped"] is True and out["seconds"] < 5  # (15 s at that speed)
    assert out["targets"][0]["opened"] >= 1


@pytest.mark.tshark
def test_replay_parameters(opened: PcapService, ctx: RequestContext) -> None:
    local = {"ip": "127.0.0.1", "port": 11000}
    with pytest.raises(InvalidParamsError, match="at least one"):
        opened.replay({"targets": {}}, ctx)
    with pytest.raises(InvalidParamsError, match="not a recorded target"):
        opened.replay({"targets": {"tcp 10.9.9.9:1": local}}, ctx)
    with pytest.raises(InvalidParamsError, match="not on this machine") as public:
        opened.replay({"targets": {HI2: {"ip": "8.8.8.8", "port": 11000}}}, ctx)
    assert public.value.data == {"target": HI2}
    with pytest.raises(InvalidParamsError, match="ip and a port"):
        opened.replay({"targets": {HI2: {"ip": "127.0.0.1", "port": "11000"}}}, ctx)
    with pytest.raises(InvalidParamsError, match="speed"):
        opened.replay({"speed": -1, "targets": {HI2: local}}, ctx)
    with pytest.raises(InvalidParamsError, match="loops"):
        opened.replay({"loops": -1, "targets": {HI2: local}}, ctx)  # (0: until stopped)
    with pytest.raises(InvalidParamsError, match="jitter"):
        opened.replay({"jitter": -5, "targets": {HI2: local}}, ctx)
    with pytest.raises(InvalidParamsError, match="loss"):
        opened.replay({"loss": 101, "targets": {HI2: local}}, ctx)
    with pytest.raises(InvalidParamsError, match="order"):
        opened.replay({"order": "random", "targets": {HI2: local}}, ctx)
    with pytest.raises(InvalidParamsError, match="not found"):
        opened.replay({"files": ["/nowhere/x.pcap"], "targets": {HI2: local}}, ctx)
    with pytest.raises(InvalidParamsError, match="at least one capture"):
        opened.replay({"capture": False, "targets": {HI2: local}}, ctx)
    with pytest.raises(InvalidParamsError, match="openAt must be between 0"):
        opened.replay({"openAt": 1, "targets": {HI2: local}}, ctx)  # (no other capture)
    with pytest.raises(InvalidParamsError, match="openAt"):
        opened.replay({"openAt": -1, "targets": {HI2: local}}, ctx)


@pytest.mark.tshark
def test_replay_stop_while_tshark_looks_for_packets(
    opened: PcapService,
    ctx: RequestContext,
    services: tuple[Collector, Collector, Datagrams],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A big capture with few packets in scope: the pass reads a long time
    # before its first record. Stop must end it, and still give the summary.
    hi2, _, _ = services
    opened.replay_targets({}, ctx)

    def searching(_t: Any, _path: Any, _scope: str, token: CancelToken) -> Iterator[Record]:
        while not token.cancelled:
            time.sleep(0.01)
        raise CancelledError("request cancelled")  # (as stream_lines does)
        yield  # (a generator)

    monkeypatch.setattr(opened, "_replay_records", searching)
    params = {"speed": 1, "targets": {HI2: {"ip": "127.0.0.1", "port": hi2.port}}}
    out: dict[str, Any] = {}
    worker = threading.Thread(target=lambda: out.update(opened.replay(params, ctx)))
    worker.start()
    time.sleep(0.3)
    assert opened.replay_stop({}, ctx) == {"stopped": True}
    worker.join(10)
    assert out["stopped"] is True and out["targets"][0]["connections"] == 0


# -- several captures, jitter, loss, until stopped ------------------------------------


def _shifted(tmp_path: Path, seconds: float, name: str) -> Path:
    """replay.pcap again, ``seconds`` later (another capture of the same delivery)."""
    out = tmp_path / name
    subprocess.run(
        [str(find_tool("editcap")), "-t", str(seconds), str(FIXTURES / "replay.pcap"), str(out)],
        check=True,
        capture_output=True,
    )
    return out


def _log(progress: list[dict[str, Any]], result: dict[str, Any]) -> list[str]:
    lines = [line for p in progress if p["phase"] == "replay" for line in p["log"]]
    return [line["text"] for line in lines + result["log"]]


@pytest.mark.tshark
def test_targets_of_several_captures(
    opened: PcapService, ctx: RequestContext, tmp_path: Path
) -> None:
    later = _shifted(tmp_path, 100, "later.pcap")
    notes = tmp_path / "notes.pcap"
    notes.write_text("not a capture\n")
    found = opened.replay_targets({"files": [str(later), str(notes)]}, ctx)
    targets = {t["key"]: t for t in found["targets"]}
    assert list(targets) == [DNS, HI2, UDP, HI3]  # (the open capture's come first)
    assert (targets[HI2]["connections"], targets[HI2]["retransmissions"]) == (6, 2)
    assert targets[HI2]["bytes"] == 2 * sum(map(len, generate.REPLAY_EXPECTED[HI2]))
    names = [(s["name"], s["file"], s["targets"]) for s in found["sources"]]
    assert names == [
        ("replay.pcap", None, 4),
        ("later.pcap", str(later), 4),
        ("notes.pcap", str(notes), 0),
    ]
    assert found["sources"][2]["error"]  # (read with tshark: not a capture)
    assert found["duration"] == pytest.approx(0.5)  # one after another
    assert found["span"] == pytest.approx(100.25)  # first to last of all
    # Without the open capture: only the other file's.
    alone = opened.replay_targets({"capture": False, "files": [str(later)]}, ctx)
    assert [s["name"] for s in alone["sources"]] == ["later.pcap"]
    assert {t["key"] for t in alone["targets"]} == {DNS, HI2, UDP, HI3}
    # The open capture anywhere in the list.
    moved = opened.replay_targets({"files": [str(later), str(notes)], "openAt": 1}, ctx)
    assert [s["name"] for s in moved["sources"]] == ["later.pcap", "replay.pcap", "notes.pcap"]
    assert [t["key"] for t in moved["targets"]] == list(targets)  # (by first data)
    # A shared target keeps the open capture's frame and protocol, even when
    # another capture plays first: Go to Packet goes to the viewer's packet.
    no_arp = tmp_path / "no-arp.pcap"  # (frame 4 left out: DNS is frame 4 there)
    subprocess.run(
        [str(find_tool("editcap")), str(FIXTURES / "replay.pcap"), str(no_arp), "4"],
        check=True,
        capture_output=True,
    )
    other = opened.replay_targets({"capture": False, "files": [str(no_arp)]}, ctx)
    assert [(t["firstFrame"], t["protocol"]) for t in other["targets"] if t["key"] == DNS] == [
        (4, "UDP")
    ]
    for open_at in (0, 1):
        both = opened.replay_targets({"files": [str(no_arp)], "openAt": open_at}, ctx)
        dns = next(t for t in both["targets"] if t["key"] == DNS)
        assert (dns["firstFrame"], dns["protocol"]) == (5, "DNS"), open_at


@pytest.mark.tshark
def test_replay_plays_captures_one_after_another(
    opened: PcapService,
    ctx: RequestContext,
    services: tuple[Collector, Collector, Datagrams],
    tmp_path: Path,
) -> None:
    hi2, _, udp = services
    later = _shifted(tmp_path, 100, "later.pcap")
    progress: list[dict[str, Any]] = []
    ctx.progress = progress.append
    targets = {
        HI2: {"ip": "127.0.0.1", "port": hi2.port},
        UDP: {"ip": "127.0.0.1", "port": udp.port},
    }
    result = opened.replay({"speed": 0, "files": [str(later)], "targets": targets}, ctx)
    _settle()
    assert len(hi2.received) == 6 and len(udp.received) == 6
    assert [s["name"] for s in result["sources"]] == ["replay.pcap", "later.pcap"]
    first, second = result["sources"]
    assert first["packets"] == second["packets"] > 0 and first["retransmissions"] == 1
    log = _log(progress, result)
    assert "Playing replay.pcap (1 of 2)" in log and "Playing later.pcap (2 of 2)" in log
    done = [line for line in log if line.startswith("Finished")]
    assert done == [
        f"Finished {name}: {first['packets']} packets sent, 1 retransmission skipped"
        for name in ("replay.pcap", "later.pcap")
    ]
    captures = [p["capture"] for p in progress if p["phase"] == "replay" and p["capture"]]
    assert captures and captures[-1] == {"index": 2, "count": 2, "name": "later.pcap"}
    # The open capture second: it plays after the other one.
    progress.clear()
    params = {"speed": 0, "files": [str(later)], "openAt": 1, "targets": targets}
    result = opened.replay(params, ctx)
    assert [s["name"] for s in result["sources"]] == ["later.pcap", "replay.pcap"]
    log = _log(progress, result)
    assert log.index("Playing later.pcap (1 of 2)") < log.index("Playing replay.pcap (2 of 2)")


@pytest.mark.tshark
def test_replay_merges_captures_by_time(
    opened: PcapService,
    ctx: RequestContext,
    services: tuple[Collector, Collector, Datagrams],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(replay, "ANSWER_GRACE_S", 0.0)
    hi2, _, _ = services
    later = _shifted(tmp_path, 0.1, "later.pcap")
    targets = {HI2: {"ip": "127.0.0.1", "port": hi2.port}}

    def spread(order: str) -> float:
        hi2.times.clear()
        hi2.received.clear()
        progress: list[dict[str, Any]] = []
        ctx.progress = progress.append
        params = {"speed": 1, "files": [str(later)], "order": order, "targets": targets}
        result = opened.replay(params, ctx)
        _settle()
        assert len(hi2.received) == 6
        merged = "Playing 2 captures merged by their recorded times" in _log(progress, result)
        assert merged == (order == "merged")
        return max(hi2.times) - min(hi2.times)

    # HI2's data: 0.05 s to 0.25 s in each capture, the second 0.1 s later:
    # interleaved it ends at 0.35 s; one after another, after both.
    assert spread("merged") < spread("sequence")


@pytest.mark.tshark
def test_replay_loses_datagrams_on_purpose(
    opened: PcapService, ctx: RequestContext, services: tuple[Collector, Collector, Datagrams]
) -> None:
    hi2, _, udp = services
    targets = {
        HI2: {"ip": "127.0.0.1", "port": hi2.port},
        UDP: {"ip": "127.0.0.1", "port": udp.port},
    }
    result = opened.replay({"speed": 0, "loss": 100, "targets": targets}, ctx)
    _settle()
    stats = {t["key"]: t for t in result["targets"]}
    assert udp.received == [] and (stats[UDP]["lost"], stats[UDP]["datagrams"]) == (3, 0)
    assert len(hi2.received) == 3 and stats[HI2]["lost"] == 0  # (TCP data is never lost)
    assert result["sources"][0]["lost"] == 3
    assert any("3 lost on purpose" in line["text"] for line in result["log"])


@pytest.mark.tshark
def test_replay_with_jitter_keeps_each_connection_in_order(
    opened: PcapService, ctx: RequestContext, services: tuple[Collector, Collector, Datagrams]
) -> None:
    hi2, hi3, _ = services
    targets = {
        HI2: {"ip": "127.0.0.1", "port": hi2.port},
        HI3: {"ip": "127.0.0.1", "port": hi3.port},
    }
    opened.replay({"speed": 1, "jitter": 40, "seed": 7, "targets": targets}, ctx)
    _settle()
    a, e, c = generate.REPLAY_EXPECTED[HI2]
    assert sorted(hi2.received) in (sorted([a, e, c]), sorted([a, b"", c]))
    assert sorted(hi3.received) == sorted(generate.REPLAY_EXPECTED[HI3])


@pytest.mark.tshark
def test_replay_until_stopped(
    opened: PcapService, ctx: RequestContext, services: tuple[Collector, Collector, Datagrams]
) -> None:
    hi2, _, _ = services
    opened.replay_targets({}, ctx)
    params = {"speed": 0, "loops": 0, "targets": {HI2: {"ip": "127.0.0.1", "port": hi2.port}}}
    out: dict[str, Any] = {}
    worker = threading.Thread(target=lambda: out.update(opened.replay(params, ctx)))
    worker.start()
    deadline = time.monotonic() + 10
    while len(hi2.received) < 9 and time.monotonic() < deadline:
        time.sleep(0.05)
    assert opened.replay_stop({}, ctx) == {"stopped": True}
    worker.join(10)
    assert out["stopped"] is True and out["loops"] >= 2
