"""Sequence checks (sequence.py): gaps, duplicates, late messages, restarts
and wrapping counters, per stream."""

from __future__ import annotations

import pytest

from pcap_backend import sequence
from pcap_backend.sequence import Checker, Ranges


def test_ranges() -> None:
    r = Ranges()
    for n in (5, 7, 6, 1, 3):
        assert r.add(n)
    assert not r.add(6)
    assert (r.lo, r.hi) == ([1, 3, 5], [1, 3, 7])
    assert r.gaps() == [(2, 2), (4, 4)]
    assert 6 in r and 4 not in r and 0 not in r
    assert r.missing_in(1, 7) == 2 and r.missing_in(4, 4) == 1 and r.missing_in(5, 7) == 0
    r.add(2)
    r.add(4)
    assert (r.lo, r.hi) == ([1], [7])


def _feed(checker: Checker, numbers: list[int | str], key: str = "a") -> None:
    for frame, n in enumerate(numbers, start=1):
        checker.feed((key,), str(n), frame, frame / 10)


def test_a_complete_stream_has_no_problems() -> None:
    c = Checker()
    _feed(c, [1, 2, 3, 4])
    (s,) = c.streams()
    out = s.to_json()
    assert (out["messages"], out["packets"], out["firstSeq"], out["lastSeq"]) == (4, 4, 1, 4)
    assert (out["missing"], out["duplicates"], out["late"], out["restarts"]) == (0, 0, 0, 0)
    assert out["problems"] == [] and out["firstFrame"] == 1 and out["lastFrame"] == 4


def test_gaps_duplicates_late_and_restarts() -> None:
    c = Checker(reorder=5)
    # 3-4 never come; 7 comes late (after 8); 8 twice; then a restart at 1.
    _feed(c, [1, 2, 5, 6, 8, 7, 8, 9, 1, 2, 4])
    out = c.streams()[0].to_json()
    assert out["missing"] == 2 + 1  # 3-4 in the first run, 3 in the second
    assert out["missingRanges"] == [[3, 4], [3, 3]]
    assert (out["duplicates"], out["late"], out["restarts"]) == (1, 1, 1)
    kinds = [(p["kind"], p["frame"]) for p in out["problems"]]
    assert kinds == [
        ("gap", 3),
        ("gap", 5),
        ("late", 6),
        ("duplicate", 7),
        ("restart", 9),
        ("gap", 11),
    ]
    gaps = [p for p in out["problems"] if p["kind"] == "gap"]
    # 7's gap was filled later: reordering, not loss.
    assert [(g["fromSeq"], g["toSeq"], g["count"], g["stillMissing"]) for g in gaps] == [
        (3, 4, 2, 2),
        (7, 7, 1, 0),
        (3, 3, 1, 1),
    ]
    restart = out["problems"][4]
    assert (restart["seq"], restart["after"]) == (1, 9)


def test_a_drop_within_the_reorder_window_is_late_not_a_restart() -> None:
    c = Checker(reorder=1000)
    _feed(c, [500, 502, 501, 10])
    out = c.streams()[0].to_json()
    assert (out["late"], out["restarts"]) == (2, 0)
    # 10 is below the first number: the numbers between are not counted missing.
    assert out["missingRanges"] == [[11, 499]]


def test_a_wrapping_counter() -> None:
    c = Checker(wrap=65536)
    _feed(c, [65533, 65534, 65535, 0, 2, 1])
    out = c.streams()[0].to_json()
    assert (out["missing"], out["late"], out["restarts"]) == (0, 1, 0)
    gap = out["problems"][0]
    assert (gap["kind"], gap["fromSeq"], gap["toSeq"], gap["stillMissing"]) == ("gap", 1, 1, 0)
    # Without the wrap, 0 after 65535 is a restart.
    c = Checker()
    _feed(c, [65534, 65535, 0, 1])
    assert c.streams()[0].restarts == 1


def test_streams_by_key_several_messages_a_packet_and_unreadable_numbers() -> None:
    rows = [
        (1, 0.0, [["7"], ["x"]], ["1"]),
        # Two messages in one packet: the key field once applies to both.
        (2, 0.1, [["7"], ["x"]], ["2", "3"]),
        # Two keys, two numbers: paired.
        (3, 0.2, [["7", "8"], ["x"]], ["4", "1"]),
        (4, 0.3, [[], ["x"]], ["0x10"]),
        (5, 0.4, [["7"], ["x"]], ["n/a"]),
    ]
    c = sequence.check(rows)
    by_key = {s.key: s for s in c.streams()}
    assert set(by_key) == {("7", "x"), ("8", "x"), ("", "x")}
    seven = by_key[("7", "x")]
    assert (seven.messages, seven.packets, seven.last_seq) == (4, 3, 4)
    assert by_key[("", "x")].first_seq == 16  # hex
    assert c.unreadable == 1


def test_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sequence, "MAX_PROBLEMS", 2)
    monkeypatch.setattr(sequence, "MAX_STREAMS", 1)
    c = Checker()
    _feed(c, [1, 1, 1, 1])
    _feed(c, [1], key="other")
    out = c.streams()[0].to_json()
    assert (len(out["problems"]), out["moreProblems"], out["duplicates"]) == (2, 1, 3)
    assert c.untracked == 1
    with pytest.raises(ValueError, match="wrap"):
        Checker(wrap=1000)
