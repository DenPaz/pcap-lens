"""Following a capture file another program is still writing (follow.py, ``open {follow}``)."""

from __future__ import annotations

import gzip
import struct
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from pcap_backend import follow
from pcap_backend.capture import _Blocks
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import RequestContext
from pcap_backend.tshark import ToolError

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
HTTP_PACKETS = 11
MIXED_PACKETS = 26


def _pieces(path: Path) -> tuple[bytes, list[bytes]]:
    """A capture's header and its records (pcap) or blocks (pcapng), whole."""
    data = path.read_bytes()
    splitter: Any = _Blocks() if data[:4] == bytes.fromhex("0a0d0d0a") else follow._Records()
    if isinstance(splitter, follow._Records):
        head, rest = data[:24], data[24:]
        splitter.feed(head)
    else:
        (first,) = struct.unpack_from("<I", data, 4)  # (the SHB; the fixtures are little-endian)
        head, rest = data[:first], data[first:]
        splitter.feed(head)
    pieces = []
    pos = 0
    while pos < len(rest):
        for size in range(1, len(rest) - pos + 1):
            out = splitter.feed(rest[pos + size - 1 : pos + size])
            if out:
                pieces.append(out)
                pos += size
                break
    while isinstance(splitter, _Blocks) and struct.unpack_from("<I", pieces[0])[0] not in (2, 3, 6):
        head += pieces.pop(0)  # (pcapng: the interface blocks before the first packet)
    return head, pieces


def test_pcap_records_are_cut_whole() -> None:
    head, records = _pieces(FIXTURES / "http.pcap")
    assert len(head) == 24 and len(records) == HTTP_PACKETS
    records_ = follow._Records()
    data = head + b"".join(records)
    got = b"".join(records_.feed(data[i : i + 7]) for i in range(0, len(data), 7))
    assert got == data and records_.packets == HTTP_PACKETS
    assert follow._Records().feed(head + records[0][:-1]) == head, "a half record waits"


@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize(
    ("magic", "header"), [(0xA1B2C3D4, 16), (0xA1B23C4D, 16), (0xA1B2CD34, 24)]
)
def test_pcap_variants(endian: str, magic: int, header: int) -> None:
    file_header = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, 1)
    record = struct.pack(endian + "IIII", 1, 2, 3, 3) + b"\0" * (header - 16) + b"abc"
    records = follow._Records()
    assert records.feed(file_header + record + record[:5]) == file_header + record
    assert records.packets == 1 and records.feed(record[5:]) == record


def test_what_isnt_a_record_is_refused() -> None:
    with pytest.raises(ToolError, match="header changed"):
        follow._Records().feed(b"not a pcap header at all")
    head = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    with pytest.raises(ToolError, match="isn't a pcap record"):
        follow._Records().feed(head + struct.pack("<IIII", 0, 0, 1 << 30, 1))


def test_only_uncompressed_pcap_and_pcapng_can_be_followed(tmp_path: Path) -> None:
    assert follow.follow_format(FIXTURES / "http.pcap") == "pcap"
    assert follow.follow_format(FIXTURES / "mixed.pcapng") == "pcapng"
    empty = tmp_path / "new.pcap"
    empty.touch()
    assert follow.follow_format(empty) == "pending"
    packed = tmp_path / "http.pcap.gz"
    packed.write_bytes(gzip.compress((FIXTURES / "http.pcap").read_bytes()))
    with pytest.raises(ToolError, match="can't be followed"):
        follow.follow_format(packed)


def _events(service: PcapService) -> list[tuple[str, dict[str, Any]]]:
    events: list[tuple[str, dict[str, Any]]] = []
    service.notify = lambda method, params: events.append((method, params))
    return events


def _wait(check: Callable[[], bool], timeout: float = 20) -> None:
    deadline = time.monotonic() + timeout
    while not check():
        assert time.monotonic() < deadline, "timed out"
        time.sleep(0.02)


def _index_done(events: list[tuple[str, dict[str, Any]]]) -> dict[str, Any] | None:
    return next((p for m, p in events if m == "index" and p["event"] != "progress"), None)


def _rows(service: PcapService) -> int:
    return len(service.list_packets({"limit": 100}, RequestContext())["rows"])


def _follow(service: PcapService, path: Path, **params: Any) -> dict[str, Any]:
    return service.open({"path": str(path), "follow": True, **params}, RequestContext())


@pytest.mark.tshark
@pytest.mark.parametrize(
    ("name", "total"), [("http.pcap", HTTP_PACKETS), ("mixed.pcapng", MIXED_PACKETS)]
)
def test_a_growing_file_is_shown_as_it_grows(
    service: PcapService, tmp_path: Path, name: str, total: int
) -> None:
    head, pieces = _pieces(FIXTURES / name)
    path = tmp_path / name
    with path.open("wb") as fh:
        fh.write(head + b"".join(pieces[:3]))
    events = _events(service)
    cache = tmp_path / "index-cache"
    res = _follow(service, path, cache={"dir": str(cache), "maxBytes": 1 << 30})
    assert res["indexing"] is True
    assert res["capture"]["follow"] is True and res["capture"]["file"] == name
    _wait(lambda: _rows(service) == 3)
    with path.open("ab") as fh:  # the writer goes on, half a record at first
        fh.write(pieces[3][:10])
        fh.flush()
        time.sleep(1.2)
        assert _rows(service) == 3, "half a record isn't shown"
        fh.write(pieces[3][10:] + b"".join(pieces[4:]))
    _wait(lambda: _rows(service) == total)
    detail = service.packet_detail({"number": total}, RequestContext())
    assert detail["tree"][0]["label"].startswith(f"Frame {total}:"), "the file is read meanwhile"
    _wait(lambda: any(m == "capture" and p["event"] == "stats" for m, p in events))
    assert service.capture_stop({}, RequestContext()) == {"stopped": True}
    _wait(lambda: _index_done(events) is not None)
    done = _index_done(events)
    assert done is not None and done["event"] == "done"
    assert done["info"]["frames"] == total and done["info"]["capture"]["running"] is False
    stopped = next(p for m, p in events if m == "capture" and p["event"] == "stopped")
    assert stopped["packets"] == total and "error" not in stopped
    assert service.capture_stop({}, RequestContext()) == {"stopped": False}
    page = service.list_packets({"limit": 3, "sort": {"field": "frame.len"}}, RequestContext())
    assert len(page["rows"]) == 3, "a finished file sorts"
    assert not cache.exists() or not any(cache.iterdir()), "a followed file has no saved index"


@pytest.mark.tshark
def test_a_file_created_empty_is_followed_once_its_header_comes(
    service: PcapService, tmp_path: Path
) -> None:
    head, pieces = _pieces(FIXTURES / "http.pcap")
    path = tmp_path / "new.pcap"
    path.touch()

    def writer() -> None:
        time.sleep(0.5)
        path.write_bytes(head + b"".join(pieces))

    thread = threading.Thread(target=writer)
    thread.start()
    events = _events(service)
    try:
        _follow(service, path)
        _wait(lambda: _rows(service) == HTTP_PACKETS)
    finally:
        thread.join()
    service.capture_stop({}, RequestContext())
    _wait(lambda: _index_done(events) is not None)


@pytest.mark.tshark
def test_a_file_that_gets_shorter_stops_following(service: PcapService, tmp_path: Path) -> None:
    head, pieces = _pieces(FIXTURES / "http.pcap")
    path = tmp_path / "rotated.pcap"
    path.write_bytes(head + b"".join(pieces))
    events = _events(service)
    _follow(service, path)
    _wait(lambda: _rows(service) == HTTP_PACKETS)
    path.write_bytes(head + pieces[0])  # replaced by a new, shorter file
    _wait(lambda: _index_done(events) is not None)
    done = _index_done(events)
    assert done is not None and done["info"]["frames"] == HTTP_PACKETS
    assert any(
        "Following the file stopped" in w and "got shorter" in w for w in done["info"]["warnings"]
    )


@pytest.mark.tshark
def test_a_compressed_file_cannot_be_followed(service: PcapService, tmp_path: Path) -> None:
    packed = tmp_path / "http.pcap.gz"
    packed.write_bytes(gzip.compress((FIXTURES / "http.pcap").read_bytes()))
    with pytest.raises(ToolError, match="can't be followed"):
        _follow(service, packed)


@pytest.mark.tshark
def test_closing_while_following(service: PcapService, tmp_path: Path) -> None:
    path = tmp_path / "http.pcap"
    path.write_bytes((FIXTURES / "http.pcap").read_bytes())
    _follow(service, path)
    _wait(lambda: _rows(service) == HTTP_PACKETS)
    started = time.monotonic()
    service.close()
    assert time.monotonic() - started < 10
