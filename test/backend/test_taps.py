"""taps.py: several -z reports in one tshark pass."""

from __future__ import annotations

import subprocess
import threading
import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from pcap_backend import taps
from pcap_backend.cancellation import CancelledError, CancelToken
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import RequestContext
from pcap_backend.service import statistics
from pcap_backend.tshark import RunResult, find_tool

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _block(title: str, rows: Sequence[str] = ()) -> str:
    rule = "=" * 80
    return (
        "\n".join([rule, f"{title} Conversations", "Filter:<No Filter>", "  | head |", *rows, rule])
        + "\n"
    )


FIRST, BETWEEN, LAST = _block("FDDI"), _block("Token-Ring"), _block("IPX")


def test_reports_are_split_between_the_sentinels_in_either_order() -> None:
    assert taps.batch_args(["a,b", "c,d"]) == [
        *("-z", "conv,fddi", "-z", "a,b", "-z", "conv,tr", "-z", "c,d", "-z", "conv,ipx"),
    ]
    one, two = "report one\n\n", "\nreport two\n"
    forward = FIRST + one + BETWEEN + two + LAST
    assert taps.split_reports(forward, 2) == [one, two]
    # (tshark 4.2 prints the taps last first.)
    backward = LAST + two + BETWEEN + one + FIRST
    assert taps.split_reports(backward, 2) == [one, two]
    # Windows line ends, and a sentinel with rows (a capture with FDDI traffic).
    crlf = FIRST.replace("\n", "\r\n") + "x\r\n" + _block("IPX", ["a <-> b 1 2"])
    assert taps.split_reports(crlf, 1) == ["x\r\n"]


@pytest.mark.parametrize(
    "text",
    [
        FIRST + "one" + BETWEEN + "two",  # (tshark stopped before the last report)
        FIRST + "one" + LAST,  # (a report missing)
        FIRST + "one" + LAST + BETWEEN + "two",  # (out of order)
        "stray\n" + FIRST + "one" + BETWEEN + "two" + LAST,
        FIRST + "one" + BETWEEN + "two" + LAST + "stray\n",
        "",
    ],
)
def test_output_without_every_sentinel_in_order_is_not_split(text: str) -> None:
    assert taps.split_reports(text, 2) is None


def test_reports_share_a_pass_only_with_reports_dissected_alike() -> None:
    tree = ["io,phs", "io,stat,0.1", "conv,tcp,ip", "expert,comment,tcp", "http,tree,dns"]
    no_tree = ["conv,tcp", "endpoints,ipv6", "expert,comment", "http,tree", "credentials"]
    assert all(taps.builds_tree(s) for s in tree)
    assert not any(taps.builds_tree(s) for s in no_tree)
    key = taps.batch_key
    assert key([], "conv,tcp") == key([], "endpoints,ip") != key([], "io,phs")
    assert key([], "io,phs") == key([], "conv,tcp,ip") != key([], "conv,tcp,!(frame.number == 2)")
    assert key(["-2"], "io,stat,0") != key([], "io,stat,0")


class FakeTshark:
    """A runner that answers each -z argument with its own report."""

    def __init__(self, delay: float = 0.0, fail: bool = False) -> None:
        self.passes: list[list[str]] = []
        self.delay = delay
        self.fail = fail
        self.lock = threading.Lock()

    def __call__(self, z_args: Sequence[str], token: CancelToken) -> RunResult:
        specs = list(z_args[1::2])
        with self.lock:
            self.passes.append(specs)
        deadline = time.monotonic() + self.delay
        while time.monotonic() < deadline:
            token.raise_if_cancelled()
            time.sleep(0.005)
        if self.fail:
            return RunResult(-11, b"", "Segmentation fault")
        blocks = {"conv,fddi": FIRST, "conv,tr": BETWEEN, "conv,ipx": LAST}
        text = "".join(blocks.get(s) or f"report of {s}\n" for s in reversed(specs))
        return RunResult(0, text.encode(), "")


def _ask(
    batcher: taps.TapBatcher,
    runner: FakeTshark,
    specs: Sequence[str],
    token: CancelToken | None = None,
) -> list[object]:
    with ThreadPoolExecutor(len(specs)) as pool:
        futures = [
            pool.submit(batcher.report, [], s, token or CancelToken(), runner) for s in specs
        ]
        return [f.result() for f in futures]


def test_reports_asked_for_together_share_one_pass() -> None:
    runner = FakeTshark()
    batcher = taps.TapBatcher(window=0.2)
    specs = ["conv,tcp", "conv,udp", "endpoints,ip", "expert,comment"]
    assert _ask(batcher, runner, specs) == [f"report of {s}\n" for s in specs]
    assert len(runner.passes) == 1
    # Alone, a report gets its pass's own result (the caller checks it).
    alone = _ask(batcher, runner, ["conv,tcp"])[0]
    assert isinstance(alone, RunResult)
    assert alone.stdout == b"report of conv,tcp\n"
    assert runner.passes[-1] == ["conv,tcp"]
    # Reports dissected differently get passes of their own.
    _ask(batcher, runner, ["conv,tcp", "io,phs"])
    assert sorted(map(tuple, runner.passes[-2:])) == [("conv,tcp",), ("io,phs",)]


def test_a_full_batch_starts_at_once() -> None:
    runner = FakeTshark()
    batcher = taps.TapBatcher(window=30, max_batch=2)
    started = time.monotonic()
    assert _ask(batcher, runner, ["conv,tcp", "conv,udp"]) == [
        "report of conv,tcp\n",
        "report of conv,udp\n",
    ]
    assert time.monotonic() - started < 10


def test_a_failed_shared_pass_lets_each_caller_run_its_own() -> None:
    runner = FakeTshark(fail=True)
    batcher = taps.TapBatcher(window=0.2)
    assert _ask(batcher, runner, ["conv,tcp", "conv,udp"]) == [None, None]


def test_a_cancelled_caller_leaves_and_the_pass_stops_when_all_have() -> None:
    runner = FakeTshark(delay=0.5)
    batcher = taps.TapBatcher(window=0.05)
    gone, staying = CancelToken(), CancelToken()
    with ThreadPoolExecutor(2) as pool:
        first = pool.submit(batcher.report, [], "conv,tcp", gone, runner)
        second = pool.submit(batcher.report, [], "conv,udp", staying, runner)
        time.sleep(0.2)
        gone.cancel()
        with pytest.raises(CancelledError):
            first.result(timeout=0.2)  # (at once, not after the pass)
        assert second.result() == "report of conv,udp\n"
    # Every caller cancelled: the pass's token is too (tshark is killed).
    runner = FakeTshark(delay=5)
    tokens = [CancelToken(), CancelToken()]
    started = time.monotonic()
    with ThreadPoolExecutor(2) as pool:
        futures = [
            pool.submit(batcher.report, [], s, t, runner)
            for s, t in zip(["conv,tcp", "conv,udp"], tokens, strict=True)
        ]
        time.sleep(0.2)
        for t in tokens:
            t.cancel()
        for f in futures:
            with pytest.raises(CancelledError):
                f.result()
    time.sleep(0.2)
    assert time.monotonic() - started < 2


# The groups of reports the service asks for together: the summary, the
# capture report and a comparison's profile, filtered or not, and others.
GROUPS = [
    ["io,phs", "conv,tcp", "conv,udp", "endpoints,ip", "endpoints,ipv6", "expert,comment"],
    ["io,phs", "io,stat,0.1"],
    ["io,phs,ip", "conv,tcp,ip", "endpoints,ip,!tcp", "expert,comment,udp"],
    ["io,phs,!(frame.number == 2)", "conv,tcp,!(frame.number == 2)", "io,stat,0,frame"],
    ["http,tree", "dns,tree", "plen,tree", "sip,stat", "credentials", "sctp,stat", "icmp,srt"],
]
CAPTURES = ["mixed.pcapng", "network.pcap", "services.pcap", "voip-calls.pcap", "sessions.pcap"]


def _tshark(capture: str, z_args: Sequence[str]) -> str:
    argv = [str(find_tool("tshark")), "-r", str(FIXTURES / capture), "-q", "-n", *z_args]
    return subprocess.run(argv, capture_output=True, check=False).stdout.decode()


@pytest.mark.tshark
@pytest.mark.parametrize("capture", CAPTURES)
def test_each_report_of_a_shared_pass_is_the_one_it_prints_alone(capture: str) -> None:
    for group in GROUPS:
        by_key: dict[tuple[str, ...], list[str]] = {}
        for spec in group:
            by_key.setdefault(taps.batch_key([], spec), []).append(spec)
        for specs in by_key.values():
            reports = taps.split_reports(_tshark(capture, taps.batch_args(specs)), len(specs))
            assert reports is not None, specs
            for spec, report in zip(specs, reports, strict=True):
                assert report == _tshark(capture, ["-z", spec]), spec


@pytest.mark.tshark
def test_the_taps_said_to_build_no_tree_build_none() -> None:
    """network.pcap's SCTP throws "Malformed Packet" only when tshark builds
    the protocol tree: an expert report beside a tap shows whether it did."""

    def malformed(*specs: str) -> bool:
        args = ["-z", "expert,error"]
        for spec in specs:
            args += ["-z", spec]
        return "Malformed Packet" in _tshark("network.pcap", args)

    if not malformed("io,phs"):
        pytest.skip("this tshark dissects network.pcap's SCTP alike with and without a tree")
    for spec in [*GROUPS[0], *GROUPS[1], *GROUPS[4], "conv,tcp,ip", "endpoints,ip,!tcp"]:
        assert malformed(spec) == taps.builds_tree(spec), spec


@pytest.mark.tshark
def test_statistics_asked_for_together_are_the_ones_asked_for_alone(
    patch_service: Callable[[str, object], None],
) -> None:
    passes: list[Sequence[str]] = []
    real_run = statistics.run

    def counting_run(argv: Sequence[str], *args: object, **kwargs: object) -> RunResult:
        if "-z" in argv:
            passes.append(argv)
        return real_run(argv, *args, **kwargs)  # type: ignore[arg-type]

    patch_service("run", counting_run)
    asks = [
        {"kind": "phs"},
        {"kind": "conversations", "type": "tcp"},
        {"kind": "conversations", "type": "udp"},
        {"kind": "endpoints", "type": "ip"},
        {"kind": "expert"},
        {"kind": "io"},
    ]

    def tables(together: bool) -> list[dict[str, object]]:
        svc = PcapService()
        try:
            svc.open({"path": str(FIXTURES / "network.pcap")}, RequestContext())
            if not together:
                return [svc.stats(a, RequestContext()) for a in asks]
            with ThreadPoolExecutor(len(asks)) as pool:
                futures = [pool.submit(svc.stats, a, RequestContext()) for a in asks]
                return [f.result() for f in futures]
        finally:
            svc.shutdown()

    alone = tables(together=False)
    count = len(passes)
    assert tables(together=True) == alone
    # Three passes: the hierarchy and the I/O graph build the tree; the expert
    # report too, filtered on "frame" (statistics._expert_spec), so apart from
    # the hierarchy; the conversations and endpoints share the third.
    assert len(passes) - count == 3
