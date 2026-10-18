"""probe_file (Open File in PCAP Lens…): whether tshark reads a file,
whatever it is called, and why not (ber.count_records for record files);
split_ber, which opens such record files as packets."""

from __future__ import annotations

import io
import shutil
import struct
from pathlib import Path

import pytest

from pcap_backend import ber
from pcap_backend.cancellation import CancelledError
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import InvalidParamsError, RequestContext, UnsupportedFormatError

# SEQUENCE { INTEGER 5, OCTET STRING "hello" }, as test/fixtures/formats/capture.ber.
RECORD = bytes.fromhex("300a020105040568656c6c6f")


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_count_records(tmp_path: Path) -> None:
    assert ber.count_records(_write(tmp_path, "one", RECORD)) == 1
    assert ber.count_records(_write(tmp_path, "three", RECORD * 3)) == 3
    # Block padding after the records.
    assert ber.count_records(_write(tmp_path, "padded", RECORD * 2 + b"\x00" * 20)) == 2
    assert ber.count_records(_write(tmp_path, "ff", RECORD * 2 + b"\xff" * 7)) == 2
    # Long-form length (0x82 0x01 0x00 = 256) and a high tag number (0x1f 0x81 0x01).
    long_value = bytes.fromhex("048201") + b"\x00" + b"x" * 256
    assert ber.count_records(_write(tmp_path, "long", long_value + RECORD)) == 2
    high_tag = bytes.fromhex("1f810103") + b"abc"
    assert ber.count_records(_write(tmp_path, "tag", high_tag * 2)) == 2
    # Not BER records: a cut-off record, junk after the records, an indefinite length, text.
    assert ber.count_records(_write(tmp_path, "cut", RECORD + RECORD[:-1])) is None
    assert ber.count_records(_write(tmp_path, "junk", RECORD + b"\x00junk")) is None
    assert ber.count_records(_write(tmp_path, "indef", bytes.fromhex("3080") + RECORD)) is None
    assert ber.count_records(_write(tmp_path, "text", b"hello world, not ASN.1\n")) is None
    assert ber.count_records(_write(tmp_path, "empty", b"")) is None


def test_count_records_stops_at_the_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ber, "MAX_RECORDS", 5)
    assert ber.count_records(_write(tmp_path, "many", RECORD * 50)) == 5


@pytest.mark.tshark
def test_probe_file(service: PcapService, fixtures: Path, tmp_path: Path) -> None:
    ctx = RequestContext()

    def probe(path: Path) -> dict:
        return service.probe_file({"path": str(path)}, ctx)

    # Captures open whatever they are called.
    renamed = tmp_path / "trace"
    shutil.copyfile(fixtures / "http.pcap", renamed)
    assert probe(renamed) == {"readable": True, "format": "pcap"}
    shutil.copyfile(fixtures / "mixed.pcapng", tmp_path / "mixed.dat")
    assert probe(tmp_path / "mixed.dat") == {"readable": True, "format": "pcapng"}
    # One BER value per file is tshark's BER file type, even without an extension.
    assert probe(_write(tmp_path, "record", RECORD)) == {"readable": True, "format": None}

    records = probe(_write(tmp_path, "cdrs", RECORD * 3))
    assert records["readable"] is False
    assert records["berRecords"] == 3
    assert "3 BER records one after another" in records["message"]
    text = probe(_write(tmp_path, "notes", b"just some text\n"))
    assert text == {
        "readable": False,
        "message": "notes isn't a capture file in a format tshark can read",
    }
    assert probe(_write(tmp_path, "nothing", b"")) == {
        "readable": False,
        "message": "nothing is empty",
    }
    with pytest.raises(InvalidParamsError, match="not found"):
        probe(tmp_path / "missing")


def _blocks(data: bytes) -> list[tuple[int, bytes]]:
    """(type, body) of each pcapng block."""
    out = []
    while data:
        kind, total = struct.unpack_from("<II", data)
        out.append((kind, data[8 : total - 4]))
        data = data[total:]
    return out


def test_write_pcapng_one_packet_per_record(tmp_path: Path) -> None:
    second = bytes.fromhex("3003020107")  # SEQUENCE { INTEGER 7 }
    path = _write(tmp_path, "cdrs", RECORD + second + RECORD + b"\x00" * 9)
    out = io.BytesIO()
    assert ber.write_pcapng(path, out, "ber") == (3, 0)
    blocks = _blocks(out.getvalue())
    assert [kind for kind, _ in blocks] == [0x0A0D0D0A, 1, 6, 6, 6]
    assert struct.unpack_from("<H", blocks[1][1])[0] == ber.LINKTYPE_UPPER_PDU
    header = ber.pdu_header("ber")
    # Tag 12 (dissector name), length 4 ("ber" padded), then end-of-options.
    assert header == bytes.fromhex("000c0004") + b"ber\x00" + bytes(4)
    stamp = int(path.stat().st_mtime * 1_000_000)
    for (_, body), record in zip(blocks[2:], (RECORD, second, RECORD), strict=True):
        _iface, high, low, captured, length = struct.unpack_from("<IIIII", body)
        assert (high << 32 | low) == stamp
        assert captured == length == len(header) + len(record)
        assert body[20 : 20 + captured] == header + record


def test_write_pcapng_cuts_long_records_and_refuses_other_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ber, "MAX_PACKET", 32)
    long_value = bytes.fromhex("0440") + b"x" * 64  # OCTET STRING of 64 bytes
    out = io.BytesIO()
    assert ber.write_pcapng(_write(tmp_path, "long", RECORD + long_value), out, "ber") == (2, 1)
    _, body = _blocks(out.getvalue())[3]
    _iface, _high, _low, captured, length = struct.unpack_from("<IIIII", body)
    assert (captured, length) == (32, len(ber.pdu_header("ber")) + len(long_value))
    with pytest.raises(ber.NotRecordsError, match="byte 12"):
        ber.write_pcapng(_write(tmp_path, "junk", RECORD + b"junk"), io.BytesIO(), "ber")
    with pytest.raises(InterruptedError):
        ber.write_pcapng(_write(tmp_path, "ok", RECORD), io.BytesIO(), "ber", lambda: True)


@pytest.mark.tshark
def test_split_ber_opens_the_records_as_packets(
    service: PcapService, ctx: RequestContext, tmp_path: Path
) -> None:
    second = bytes.fromhex("3003020107")
    source = _write(tmp_path, "cdrs.dat", RECORD + second + RECORD * 2)
    # Opening it directly fails, saying it holds BER records.
    with pytest.raises(UnsupportedFormatError) as info:
        service.open({"path": str(source)}, ctx)
    assert info.value.data["berRecords"] == 4

    names = service.dissector_names({}, ctx)["dissectors"]
    assert {"name": "ber", "protocol": "BER"} in names
    dest = tmp_path / "cdrs.pcapng"
    res = service.split_ber({"path": str(source), "dest": str(dest)}, ctx)
    assert res == {"path": str(dest), "packets": 4, "truncated": 0, "dissector": "ber"}
    assert service.open({"path": str(dest)}, ctx)["frames"] == 4
    rows = service.list_packets({"offset": 0, "limit": 10}, ctx)["rows"]
    assert [r["cells"][4] for r in rows] == ["BER"] * 4
    tree = service.packet_detail({"number": 2}, ctx)["tree"]
    labels = []

    def walk(nodes: list[dict]) -> None:
        for node in nodes:
            labels.append(node["label"])
            walk(node.get("children", []))

    walk(tree)
    assert "INTEGER: 7" in labels
    assert "OCTETSTRING: 68656c6c6f" not in labels  # (that is packets 1, 3 and 4)


@pytest.mark.tshark
def test_split_ber_errors(service: PcapService, ctx: RequestContext, tmp_path: Path) -> None:
    source = _write(tmp_path, "cdrs", RECORD * 2)
    dest = str(tmp_path / "out.pcapng")
    with pytest.raises(InvalidParamsError, match="invalid dissector name"):
        service.split_ber({"path": str(source), "dest": dest, "dissector": "ber; rm"}, ctx)
    text = _write(tmp_path, "notes", b"just some text\n")
    with pytest.raises(InvalidParamsError, match="notes isn't a file of BER records"):
        service.split_ber({"path": str(text), "dest": dest}, ctx)
    with pytest.raises(InvalidParamsError):
        service.split_ber({"path": str(source), "dest": str(source)}, ctx)  # never over the input
    cancelled = RequestContext()
    cancelled.token.cancel()
    with pytest.raises(CancelledError):
        service.split_ber({"path": str(source), "dest": dest}, cancelled)
    assert not Path(dest).exists()  # (nothing half-written either)


@pytest.mark.tshark
def test_split_ber_with_another_dissector(
    service: PcapService, ctx: RequestContext, tmp_path: Path
) -> None:
    """Each packet names the chosen dissector, which tshark only looks up when
    reading (a Lua dissector may not be loaded by this backend), so any
    well-formed name is written as given."""
    source = _write(tmp_path, "values", RECORD * 2)
    dest = tmp_path / "out.pcapng"
    service.split_ber({"path": str(source), "dest": str(dest), "dissector": "no_such"}, ctx)
    service.open({"path": str(dest)}, ctx)
    names: dict[str, str] = {}

    def walk(nodes: list[dict]) -> None:
        for node in nodes:
            names[node.get("name", "")] = node.get("show", "")
            walk(node.get("children", []))

    walk(service.packet_detail({"number": 2}, ctx)["tree"])
    assert names["exported_pdu.prot_name"] == "no_such"
