from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from pcap_backend import comments
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import FilterError, InvalidParamsError, RequestContext
from pcap_backend.service.exporting import parse_pdu_taps

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"

# (tshark's first line, "The available export tap names and the encapsulation
# types they produce for the "-U tap_name" option are:", cut short.)
TAP_LIST = """\
tshark: The available export tap names and the encapsulation types they produce…
    DLT User - Wireshark Upper PDU export
    Ethernet - Ethernet
    IP - Raw IP
    OSI layer 7 - Wireshark Upper PDU export
"""


def test_tap_list_is_parsed() -> None:
    assert parse_pdu_taps(TAP_LIST) == [
        {"name": "DLT User", "encapsulation": "Wireshark Upper PDU export"},
        {"name": "Ethernet", "encapsulation": "Ethernet"},
        {"name": "IP", "encapsulation": "Raw IP"},
        {"name": "OSI layer 7", "encapsulation": "Wireshark Upper PDU export"},
    ]


@pytest.mark.tshark
def test_export_pdus(service: PcapService, ctx: RequestContext, tmp_path: Path) -> None:
    service.open({"path": str(FIXTURES / "voip.pcap")}, ctx)
    names = [t["name"] for t in service.export_pdu_taps({}, ctx)["taps"]]
    assert "OSI layer 4" in names and "OSI layer 7" in names
    # SIP exports its messages at layer 7: one PDU per SIP packet.
    sip = tmp_path / "sip.pcapng"
    res = service.export_pdus({"tap": "OSI layer 7", "dest": str(sip)}, ctx)
    assert (res["pdus"], res["frames"]) == (11, 110)
    assert comments.packet_count(sip) == 11
    # Limited to a filter, and the ignored packets left out.
    service.ignore_packets({"frames": [1]}, ctx)
    out = tmp_path / "rtp.pcapng"
    res = service.export_pdus({"tap": "OSI layer 4", "dest": str(out), "filter": "sip"}, ctx)
    assert (res["pdus"], res["frames"], res["filter"]) == (10, 10, "sip")
    with pytest.raises(InvalidParamsError, match="no OSI layer 7 PDUs") as err:
        service.export_pdus(
            {"tap": "OSI layer 7", "dest": str(tmp_path / "none.pcapng"), "filter": "rtp"}, ctx
        )
    assert err.value.data == {"empty": True}
    assert not (tmp_path / "none.pcapng").exists()
    with pytest.raises(InvalidParamsError, match="unknown export tap"):
        service.export_pdus({"tap": "Bogus", "dest": str(tmp_path / "x.pcapng")}, ctx)
    with pytest.raises(FilterError):
        service.export_pdus(
            {"tap": "IP", "dest": str(tmp_path / "x.pcapng"), "filter": "ip.src =="}, ctx
        )


@pytest.mark.tshark
@pytest.mark.parametrize(
    ("fixture", "label", "first"),
    [
        ("comments.pcapng", "PCAPNG File Format", "Block 1: Section Header Block 1"),
        ("http.pcap", "PCAP File Format", "Header"),
    ],
)
def test_file_format(
    service: PcapService, ctx: RequestContext, fixture: str, label: str, first: str
) -> None:
    service.open({"path": str(FIXTURES / fixture)}, ctx)
    res = service.file_format({}, ctx)
    size = (FIXTURES / fixture).stat().st_size
    assert (res["format"], res["size"], res["shown"], res["truncated"]) == (
        label,
        size,
        size,
        False,
    )
    [root] = res["tree"]
    assert root["children"][0]["label"] == first
    # The record is the whole file: its bytes are the file's.
    assert bytes.fromhex(res["sources"][0]["hex"]) == (FIXTURES / fixture).read_bytes()
    assert service.file_format({}, ctx) is res  # (cached)


@pytest.mark.tshark
def test_file_format_of_a_large_file_shows_its_start(
    service: PcapService,
    ctx: RequestContext,
    patch_service: Callable[[str, object], None],
) -> None:
    patch_service("FILE_FORMAT_LIMIT", 500)
    service.open({"path": str(FIXTURES / "comments.pcapng")}, ctx)
    res = service.file_format({}, ctx)
    assert (res["shown"], res["truncated"]) == (500, True)
    assert len(bytes.fromhex(res["sources"][0]["hex"])) == 500
    service.open({"path": str(FIXTURES / "formats" / "http.pcap.gz")}, ctx)
    with pytest.raises(InvalidParamsError, match="compressed"):
        service.file_format({}, ctx)
