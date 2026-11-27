"""Several ``-z`` reports in one tshark pass.

tshark reads the capture once however many ``-z`` taps it is given, and a
pass costs about the same with one tap as with six (200,000 packets: 4.5 s
for TCP conversations alone, 5.2 s for six reports together, 24 s for the six
one after another). The summary, the capture report, a comparison's profile
and the AI tools ask for several reports at once, each in its own request, so
``TapBatcher`` lets the reports asked for within ``WINDOW_S`` of each other
(with the same tshark options) share one pass.

tshark prints the reports one after another (in reverse order of the
arguments, in 4.2), and some of them have no header of their own (an expert
report without errors starts with its notes), so the reports are put between
sentinels: conversation taps of link types next to no capture has (FDDI
first, Token-Ring between two reports, IPX last), which cost nothing and
print a header. They take no filter: one that names a field (frame.number)
makes tshark keep that protocol in the tree, and the protocol hierarchy then
gained a "frame" row. A pass whose output doesn't hold every sentinel in
order (tshark stopped early) is not split: its callers run their reports
alone, as before, so a failing report gets its own error.

Only reports that build the protocol tree, or that don't, share a pass
(``builds_tree``): tshark dissects some packets differently with a tree
(network.pcap's SCTP throws "Malformed Packet" only then), so a report
without one, batched with the protocol hierarchy, could count other packets
than it does alone, and its result would depend on which reports happened to
be asked for at the same time. Likewise a filter naming the frame protocol
(the I/O graph's ``frame`` scope, the ignored packets' ``frame.number``)
gives the protocol hierarchy of the same pass a "frame" row, so reports
mentioning it share a pass only with each other (``batch_key``).
"""

from __future__ import annotations

import itertools
import re
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from .cancellation import CancelledError, CancelToken
from .tshark import RunResult, ToolError, broke

# How long the first report waits for others to join its pass.
WINDOW_S = 0.05
# At most this many reports share a pass (a longer wait for none).
MAX_BATCH = 8

# The sentinels: before the first report, between two, after the last.
_FIRST, _BETWEEN, _LAST = "conv,fddi", "conv,tr", "conv,ipx"
_TITLES = {"FDDI": _FIRST, "Token-Ring": _BETWEEN, "IPX": _LAST}
_SENTINEL = re.compile(
    r"={20,}\r?\n(FDDI|Token-Ring|IPX) Conversations\r?\nFilter:<No Filter>\r?\n"
    r"(?:[^=\n]*\n)*?={20,}\r?\n"
)


def batch_args(specs: Sequence[str]) -> list[str]:
    """The ``-z`` arguments for ``specs`` in one pass, each report between
    two sentinels."""
    args = ["-z", _FIRST]
    for k, spec in enumerate(specs):
        args += ["-z", spec, "-z", _LAST if k == len(specs) - 1 else _BETWEEN]
    return args


def split_reports(text: str, count: int) -> list[str] | None:
    """The ``count`` reports of a pass run with ``batch_args``, in the order
    of their specs, or None when the output doesn't hold the sentinels in
    order (either way round) with nothing outside them."""
    marks = list(_SENTINEL.finditer(text))
    kinds = [_TITLES[m.group(1)] for m in marks]
    expected = [_FIRST, *[_BETWEEN] * (count - 1), _LAST]
    if kinds not in (expected, expected[::-1]):
        return None
    if text[: marks[0].start()].strip() or text[marks[-1].end() :].strip():
        return None
    reports = [text[a.end() : b.start()] for a, b in itertools.pairwise(marks)]
    return reports if kinds == expected else reports[::-1]


def builds_tree(spec: str) -> bool:
    """Whether tap ``spec`` makes tshark build the protocol tree when it runs
    alone: the protocol hierarchy and the I/O graph do, and so does any tap
    given a display filter (its fields need one); the conversation, endpoint,
    expert, stats_tree and other taps the service runs don't. Taps take the
    filter after their kind (``conv,tcp,<filter>``, ``expert,comment,<filter>``),
    so a third argument means a filter; test_taps.py checks each kind."""
    return spec.startswith(("io,phs", "io,stat")) or spec.count(",") >= 2


def batch_key(options: Sequence[str], spec: str) -> tuple[str, ...]:
    """Reports with the same key can share a pass: the same tshark options,
    both building the protocol tree or neither, both naming the frame
    protocol or neither."""
    return (*options, "tree" if builds_tree(spec) else "", "frame" if "frame" in spec else "")


# Runs tshark with these -z arguments (and the batch's own options).
Runner = Callable[[Sequence[str], CancelToken], RunResult]


@dataclass
class _Batch:
    """The reports waiting for one pass."""

    specs: list[str] = field(default_factory=list)
    wakes: list[threading.Event] = field(default_factory=list)
    # The callers still waiting: when the last one is cancelled, so is the pass.
    waiting: int = 0
    token: CancelToken = field(default_factory=CancelToken)
    full: threading.Event = field(default_factory=threading.Event)
    # What each caller gets: its report, the pass's own result when it ran
    # alone, or None (the shared pass failed: run it alone).
    results: list[str | RunResult | None] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def leave(self) -> None:
        with self.lock:
            self.waiting -= 1
            last = self.waiting == 0
        if last:
            self.token.cancel()


class TapBatcher:
    """Runs the ``-z`` reports asked for at about the same time, with the same
    tshark options, in one pass (one per open capture)."""

    def __init__(self, window: float = WINDOW_S, max_batch: int = MAX_BATCH) -> None:
        self._window = window
        self._max_batch = max_batch
        self._lock = threading.Lock()
        self._pending: dict[tuple[str, ...], _Batch] = {}

    def report(
        self, options: Sequence[str], spec: str, token: CancelToken, runner: Runner
    ) -> str | RunResult | None:
        """``spec``'s report from a pass shared with the reports asked for
        within the window with the same ``options`` (str), or the pass's own
        result when no other joined it (RunResult: the caller checks it as it
        would its own run), or None when the shared pass couldn't be used.
        ``runner`` runs the pass (the first caller's). Cancelling ``token``
        answers at once (CancelledError); the pass stops when every caller
        has gone."""
        token.raise_if_cancelled()
        key = batch_key(options, spec)
        wake = threading.Event()
        with self._lock:
            batch = self._pending.get(key)
            first = batch is None
            if batch is None:
                batch = self._pending[key] = _Batch()
            index = len(batch.specs)
            batch.specs.append(spec)
            batch.wakes.append(wake)
            with batch.lock:
                batch.waiting += 1
            if len(batch.specs) >= self._max_batch:
                del self._pending[key]
                batch.full.set()
        if first:
            threading.Thread(
                target=self._run, args=(key, batch, runner), name="taps", daemon=True
            ).start()
        token.on_cancel(wake.set)
        wake.wait()
        if token.cancelled:
            batch.leave()
            raise CancelledError("request cancelled")
        return batch.results[index]

    def _run(self, key: tuple[str, ...], batch: _Batch, runner: Runner) -> None:
        batch.full.wait(self._window)
        with self._lock:
            if self._pending.get(key) is batch:
                del self._pending[key]
        specs = list(batch.specs)  # (no one joins now)
        results: list[str | RunResult | None] = [None] * len(specs)
        try:
            if len(specs) == 1:
                results = [runner(["-z", specs[0]], batch.token)]
            else:
                res = runner(batch_args(specs), batch.token)
                text = res.stdout.decode("utf-8", "replace")
                if not broke(res.returncode, res.stderr, bool(text.strip())):
                    results = list(split_reports(text, len(specs)) or results)
        except (CancelledError, ToolError, OSError):
            pass  # (each caller still waiting runs its own: its own error)
        finally:
            batch.results = results
            for wake in batch.wakes:
                wake.set()
