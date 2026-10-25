"""Capture file types: format sniffing, and a fixture for every editor file pattern."""

from __future__ import annotations

import fnmatch
import json
import struct
from pathlib import Path

import pytest

from pcap_backend.pcap_service import PcapService, sniff_format
from pcap_backend.protocol import RequestContext, UnsupportedFormatError

ROOT = Path(__file__).resolve().parents[2]
FORMATS = ROOT / "test" / "fixtures" / "formats"


def _selectors() -> dict[str, list[str]]:
    manifest = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    return {
        e["viewType"]: [s["filenamePattern"] for s in e["selector"]]
        for e in manifest["contributes"]["customEditors"]
    }


def _matches(pattern: str, name: str) -> bool:
    # VS Code matches selectors against the basename, ignoring case.
    return fnmatch.fnmatchcase(name.lower(), pattern.lower())


def test_sniff_format(fixtures: Path, tmp_path: Path) -> None:
    assert sniff_format(fixtures / "http.pcap") == "pcap"
    assert sniff_format(fixtures / "mixed.pcapng") == "pcapng"
    assert sniff_format(FORMATS / "trace.pcap1") == "pcap"  # by content, not name
    assert sniff_format(FORMATS / "capture.log") == "pcapng"
    for name in ("http.pcap.gz", "http.pcap.zst", "http.pcap.lz4", "http.snoop", "http.erf"):
        assert sniff_format(FORMATS / name) is None, name
    assert sniff_format(tmp_path / "missing") is None


def test_editor_selectors() -> None:
    selectors = _selectors()
    assert set(selectors) == {"pcapViewer.editor", "pcapViewer.editorOptional"}
    default, optional = selectors["pcapViewer.editor"], selectors["pcapViewer.editorOptional"]
    assert {"*.pcap", "*.pcapng", "*.cap", "*.pcap.gz", "*.pcap[0-9]*"} <= set(default)
    assert set(optional) == {"*.[0-9]", "*.log", "*.dmp", "*.trc", "*.ber"}
    # A file never matches both editors, and generic names stay with other editors.
    for name in [p.name for p in FORMATS.iterdir()] + ["notes.txt", "archive.gz", "capture.10"]:
        hits = [v for v, pats in selectors.items() if any(_matches(p, name) for p in pats)]
        assert len(hits) <= 1, (name, hits)
    assert not any(_matches(p, "archive.gz") for p in default + optional)


def test_every_file_pattern_has_a_fixture() -> None:
    names = [p.name for p in FORMATS.iterdir()]
    for patterns in _selectors().values():
        for pattern in patterns:
            if pattern in ("*.pcap", "*.pcapng", "*.cap"):
                continue  # the main fixtures (and *.cap is plain pcap)
            assert any(_matches(pattern, n) for n in names), f"no fixture for {pattern}"


CAPTURES = sorted(p.name for p in FORMATS.iterdir() if p.name != "notes.log")


@pytest.mark.tshark
@pytest.mark.parametrize("name", CAPTURES)
def test_every_format_fixture_opens(service: PcapService, ctx: RequestContext, name: str) -> None:
    info = service.open({"path": str(FORMATS / name)}, ctx)
    assert info["frames"] > 0
    page = service.list_packets({"offset": 0, "limit": 5}, ctx)
    assert page["rows"] and page["rows"][0]["number"] == 1
    assert service.packet_detail({"number": 1}, ctx)["tree"]


@pytest.mark.tshark
def test_not_a_capture(service: PcapService, ctx: RequestContext) -> None:
    with pytest.raises(UnsupportedFormatError) as info:
        service.open({"path": str(FORMATS / "notes.log")}, ctx)
    assert info.value.code == -32011
    assert "notes.log is not a capture file" in str(info.value)


@pytest.mark.tshark
@pytest.mark.parametrize("stream", [False, True])
def test_packets_tshark_cannot_read(
    service: PcapService, ctx: RequestContext, tmp_path: Path, stream: bool
) -> None:
    # A pcap of a link type tshark doesn't know (tcpdump's
    # frf16_magic_ie-oobr.pcap, type 182; found by test/realworld) is an
    # unsupported format with tshark's reason, not a tshark failure.
    capture = tmp_path / "linktype-182.pcap"
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 182)
    capture.write_bytes(header + struct.pack("<IIII", 0, 0, 4, 4) + b"\x01\x02\x03\x04")
    with pytest.raises(UnsupportedFormatError, match=r"tshark can't read \(pcap: network type 182"):
        service.open({"path": str(capture), "stream": stream}, ctx)
    probe = service.probe_file({"path": str(capture)}, ctx)
    assert not probe["readable"] and "network type 182" in probe["message"]
