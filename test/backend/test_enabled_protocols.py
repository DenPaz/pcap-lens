from __future__ import annotations

from pathlib import Path

import pytest

from pcap_backend import index_cache, tshark
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import RequestContext
from pcap_backend.protocols import ProtocolList, wireshark_switches
from pcap_backend.tshark import ConfigError, DissectionOptions

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"

# `tshark -G protocols` (name, short name, filter name, enabled, enabled by
# default, can toggle) and `-G heuristic-decodes` (underlying protocol,
# protocol, enabled, enabled by default, short name, description), cut down.
PROTOCOLS = """\
Expert Info\tExpert\t_ws.expert\tT\tT\tF
Hypertext Transfer Protocol\tHTTP\thttp\tT\tT\tT
Community ID Flow Hashing\tCommunityID\tcommunityid\tF\tF\tT
"""
LUA_PROTOCOLS = PROTOCOLS + "My Protocol\tMYPROTO\tmyproto\tT\tT\tT\n"
HEURISTICS = """\
udp\trtp\tF\tF\trtp_udp\tRTP over UDP
sctp\tsip\tT\tT\tsip_sctp\tSIP over SCTP
"""


def test_listings_are_parsed_and_merged() -> None:
    listing = ProtocolList.parse([PROTOCOLS, LUA_PROTOCOLS], [HEURISTICS, ""])
    assert list(listing.protocols) == ["_ws.expert", "http", "communityid", "myproto"]
    assert listing.protocols["communityid"] == {
        "name": "communityid",
        "short": "CommunityID",
        "title": "Community ID Flow Hashing",
        "default": False,
        "toggle": True,
    }
    assert listing.protocols["_ws.expert"]["toggle"] is False
    assert listing.heuristics["rtp_udp"] == {
        "name": "rtp_udp",
        "protocol": "rtp",
        "on": "udp",
        "title": "RTP over UDP",
        "default": False,
    }


def test_wireshark_switches_come_from_the_profile_files(tmp_path: Path) -> None:
    (tmp_path / "disabled_protos").write_text("# disabled\ndns\nhttp\n")
    (tmp_path / "enabled_protos").write_text("communityid\n")
    (tmp_path / "heuristic_protos").write_text("rtp_udp,1\nsip_sctp,0\nbroken\n")
    assert wireshark_switches(tmp_path) == {
        "protocols": {"dns": False, "http": False, "communityid": True},
        "heuristics": {"rtp_udp": True, "sip_sctp": False},
    }
    assert wireshark_switches(tmp_path / "missing") == {"protocols": {}, "heuristics": {}}
    assert wireshark_switches(None) == {"protocols": {}, "heuristics": {}}


def test_switches_become_tshark_options() -> None:
    options = DissectionOptions.from_params(
        protocols={"sip": False, "communityid": True}, heuristics={"rtp_udp": True}
    )
    assert options.args() == [
        "--enable-protocol",
        "communityid",
        "--disable-protocol",
        "sip",
        "--enable-heuristic",
        "rtp_udp",
    ]
    kept, warnings = options.without_unknown({"sip"}, set())
    assert kept.args() == ["--disable-protocol", "sip"]
    assert len(warnings) == 2 and "communityid" in warnings[0] and "rtp_udp" in warnings[1]
    assert options.without_unknown({"sip", "communityid"}, {"rtp_udp"}) == (options, [])
    with pytest.raises(ConfigError, match="protocol"):
        DissectionOptions.from_params(protocols={"sip; rm": False})
    with pytest.raises(ConfigError, match="heuristic"):
        DissectionOptions.from_params(heuristics={"rtp_udp": "yes"})


def test_switches_are_part_of_the_index_key() -> None:
    key = {
        "capture": FIXTURES / "http.pcap",
        "tshark": Path("/usr/bin/tshark"),
        "tshark_version": "4.2.2",
        "lua_scripts": [],
        "decode_as": [],
        "prefs": {},
        "columns": [],
        "config": [],
    }
    plain = index_cache.index_key(**key)
    off = index_cache.index_key(**key, switches=[[("sip", False)], []])
    assert plain != off
    assert off != index_cache.index_key(**key, switches=[[], [("rtp_udp", True)]])


@pytest.mark.tshark
def test_open_with_protocols_and_heuristics_switched(
    service: PcapService, ctx: RequestContext
) -> None:
    voip = str(FIXTURES / "voip.pcap")
    service.open({"path": voip}, ctx)
    assert service.set_filter({"expr": "rtp"}, ctx)["matchCount"] == 99
    # Without SIP the RTP streams aren't found (SDP announced them)…
    info = service.open({"path": voip, "protocols": {"sip": False}}, ctx)
    assert service.set_filter({"expr": "rtp"}, ctx)["matchCount"] == 0
    assert service.set_filter({"expr": "udp"}, ctx)["matchCount"] > 99
    assert info["warnings"] == []
    # … until the RTP heuristic looks at every UDP payload.
    service.open({"path": voip, "protocols": {"sip": False}, "heuristics": {"rtp_udp": True}}, ctx)
    assert service.set_filter({"expr": "rtp"}, ctx)["matchCount"] == 99
    # An unknown name is dropped with a warning (tshark would refuse to start).
    info = service.open({"path": voip, "protocols": {"nosuchproto": False}}, ctx)
    assert any("nosuchproto" in w for w in info["warnings"])
    assert service.set_filter({"expr": "sip"}, ctx)["matchCount"] == 11


@pytest.mark.tshark
def test_enabled_protocols_lists_what_can_be_switched(
    service: PcapService, ctx: RequestContext, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for var in ("HOME", "APPDATA", "XDG_CONFIG_HOME"):
        monkeypatch.setenv(var, str(tmp_path / "home"))
    monkeypatch.setattr(tshark, "_FOLDERS", {})  # folders are cached per tshark
    service.initialize({}, ctx)
    personal = Path(service.wireshark_profiles({}, ctx)["profiles"][0]["path"])
    personal.mkdir(parents=True)
    (personal / "disabled_protos").write_text("dns\n")
    (personal / "heuristic_protos").write_text("rtp_udp,1\n")
    res = service.enabled_protocols({}, ctx)
    names = {p["name"]: p for p in res["protocols"]}
    assert names["http"]["default"] is True and names["http"]["short"] == "HTTP"
    assert "_ws.expert" not in names  # (can't be switched)
    shorts = [p["short"].lower() for p in res["protocols"]]
    assert shorts == sorted(shorts)
    assert any(h["name"] == "rtp_udp" and h["default"] is False for h in res["heuristics"])
    assert res["wireshark"] == {"protocols": {"dns": False}, "heuristics": {"rtp_udp": True}}
