"""VoIP calls over H.323, MGCP and IAX2 (voip_protocols.py)."""

from __future__ import annotations

import sys
import wave
from pathlib import Path
from typing import Any

import pytest

from pcap_backend import voip, voip_protocols
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import InvalidParamsError, RequestContext

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
sys.path.insert(0, str(FIXTURES))
import generate  # noqa: E402 - the fixture's addresses and constants

FIELDS = voip.SIP_FIELDS + voip_protocols.OTHER_FIELDS


def _line(common: dict[str, str], **values: str) -> str:
    """A signalling pass line of FIELDS: ``common``'s cells, then ``values``
    (field names with "__" for ".")."""
    cells = dict.fromkeys(FIELDS, "")
    for name, value in [*common.items(), *((k.replace("__", "."), v) for k, v in values.items())]:
        assert name in cells, name
        cells[name] = value
    return "\t".join(cells[f] for f in FIELDS)


def _common(frame: int, time: float, src: str, dst: str, sport: int, dport: int,
            transport: str = "udp") -> dict[str, str]:  # fmt: skip
    return {
        "frame.number": str(frame), "frame.time_relative": str(time),
        "ip.src": src, "ip.dst": dst,
        f"{transport}.srcport": str(sport), f"{transport}.dstport": str(dport),
    }  # fmt: skip


# ---------------------------------------------------------------------- pure


def test_columns_and_events() -> None:
    cols = voip_protocols.Columns(["a", "b"])
    cells = ["x\x1ey", ""]
    assert cols.all(cells, "a") == ["x", "y"] and cols.first(cells, "a") == "x"
    assert cols.get(cells, "missing") == "" and cols.all(cells, "b") == []
    assert voip_protocols._events("L/hd") == ["hd"]
    assert voip_protocols._events("D/2,D/0, D/*") == ["2", "0", "*"]
    assert voip_protocols._events("L/rg,L/hu(N)") == ["rg", "hu"]


def test_iax2_as_rtp() -> None:
    """IAX2 voice frames become RTP pass lines: counted sequence numbers,
    ms timestamps in 8 kHz units, the stream's payload type."""
    lines = ["5\t1700.0\t923\tffff", "6\t1700.02\t943\t7f7f", "7\t1700.04\t\tff", "bad"]
    rtp = list(voip_protocols.iax2_as_rtp(lines, 0, voip.RTP_FIELDS))
    assert rtp == ["5\t1700.0\t0\t7384\t1\t0", "6\t1700.02\t1\t7544\t0\t0"]
    audio = list(voip_protocols.iax2_as_rtp(lines, None, voip.AUDIO_FIELDS))
    assert audio == ["0\t7384\t96\tffff", "1\t7544\t96\t7f7f"], "unknown codec: type 96"


def test_iax2_stream_key() -> None:
    key = voip.StreamKey.from_json({
        "src": "10.0.3.10", "srcPort": 4569, "dst": "10.0.3.1", "dstPort": 4569,
        "ssrc": "0x00000000", "iax2": 7, "payloadTypes": [8],
    })  # fmt: skip
    assert (key.iax2, key.codec) == (7, 8)
    assert key.to_json()["iax2"] == 7 and "codec" not in key.to_json()
    assert key.filter() == (
        "iax2.call == 7 && ip.src == 10.0.3.10 && udp.srcport == 4569 && "
        "(iax2.packet_type == 0 || iax2.type == 2)"
    )
    rtp = voip.StreamKey.from_json({
        "src": "10.0.0.1", "srcPort": 4000, "dst": "10.0.0.2", "dstPort": 4002,
        "ssrc": "0x1", "payloadTypes": [8],
    })  # fmt: skip
    assert (rtp.iax2, rtp.codec) == (None, None), "RTP streams keep their key"
    with pytest.raises(InvalidParamsError):
        voip.StreamKey.from_json({"src": "1.2.3.4", "srcPort": 1, "dst": "1.2.3.5",
                                  "dstPort": 2, "ssrc": "0", "iax2": -1})  # fmt: skip


def test_h323_call_without_guid_on_its_connection() -> None:
    """Messages without a GUID (tunnelled H.245 in a Facility) join the call
    of their TCP connection; the separate H.245 connection joins by the
    Connect's h245Address; a Setup's numbers win over its aliases."""
    a, b = "10.9.0.1", "10.9.0.2"
    lines = [
        _line(_common(1, 0.0, a, b, 30000, 1720, "tcp"), q931__message_type="0x05",
              h225__guid="g1", h225__h323_ID="ann\x1ebob", h225__sourceAddress="1",
              h225__destinationAddress="1", q931__calling_party_number__digits="100"),
        _line(_common(2, 0.5, b, a, 1720, 30000, "tcp"), q931__message_type="0x07",
              h225__guid="g1", h225__h245Ip=b, h225__h245IpPort="1800"),
        _line(_common(3, 0.6, a, b, 30000, 1720, "tcp"), q931__message_type="0x62",
              h245__pdu_type="0", h245__request="3", h245__audioData="3",
              h245__ip4_network=a, h245__tsapIdentifier="5001"),
        _line(_common(4, 0.7, b, a, 1800, 30001, "tcp"), h245__pdu_type="1",
              h245__response="5", h245__ip4_network=f"{b}\x1e{b}",
              h245__tsapIdentifier="6000\x1e6001"),
        _line(_common(5, 0.8, a, b, 30000, 1720, "tcp"), q931__message_type="0x62",
              h245__pdu_type="3", h245__indication="13", h245__alphanumeric="12"),
        _line(_common(6, 9.0, a, b, 30000, 1720, "tcp"), q931__message_type="0x5a",
              h225__guid="g1", q931__cause_value="16"),
    ]  # fmt: skip
    cols = voip_protocols.Columns(FIELDS)
    (call,) = voip_protocols.parse_h323_calls(lines, cols)
    assert (call.from_uri, call.to_uri, call.protocol) == ("ann <100>", "bob", "H.323")
    assert [m[4] for m in call.messages] == [
        "Setup", "Connect", "Facility: OpenLogicalChannel", "OpenLogicalChannelAck",
        "Facility: UserInputIndication", "Release Complete",
    ]  # fmt: skip
    assert call.media == {(a, 5001): "caller", (b, 6000): "callee", (b, 6001): "callee"}
    assert call.offer == [0], "G.711 µ-law"
    assert [d["digit"] for d in call.dtmf] == ["1", "2"]
    assert (call.state, call.ended_by, call.reasons) == (
        "Completed", "caller", ["Q.850 cause 16: Normal call clearing"],
    )  # fmt: skip


def test_mgcp_messages_outside_calls() -> None:
    """Only endpoints that went off-hook and then took part in a call are
    kept; an audit or an off-hook that ends without a connection are not."""
    agent, gw = "10.9.1.1", "10.9.1.2"
    ep = "aaln/1@gw"
    lines = [
        _line(_common(1, 0.0, agent, gw, 2727, 2427), mgcp__req__verb="AUEP", mgcp__transid="1",
              mgcp__req__endpoint=ep),
        _line(_common(2, 0.1, gw, agent, 2427, 2727), mgcp__req__verb="NTFY", mgcp__transid="2",
              mgcp__req__endpoint=ep, mgcp__param__observedevents="L/hd"),
        _line(_common(3, 0.2, gw, agent, 2427, 2727), mgcp__req__verb="NTFY", mgcp__transid="3",
              mgcp__req__endpoint=ep, mgcp__param__observedevents="L/hu"),
    ]  # fmt: skip
    assert voip_protocols.parse_mgcp_calls(lines, voip_protocols.Columns(FIELDS)) == []


def test_mgcp_busy_tone() -> None:
    """A busy tone to the caller rejects the call; the caller hanging up
    afterwards doesn't make it the caller's doing."""
    agent, gw1, gw2 = "10.9.1.1", "10.9.1.2", "10.9.1.3"
    ep1, ep2 = "aaln/1@gw1", "aaln/1@gw2"

    def command(frame: int, gw: str, verb: str, ep: str, **values: str) -> str:
        return _line(_common(frame, frame / 10, agent, gw, 2727, 2427), mgcp__req__verb=verb,
                     mgcp__transid=str(frame), mgcp__req__endpoint=ep, **values)  # fmt: skip

    def notify(frame: int, gw: str, ep: str, events: str) -> str:
        return _line(_common(frame, frame / 10, gw, agent, 2427, 2727), mgcp__req__verb="NTFY",
                     mgcp__transid=str(frame), mgcp__req__endpoint=ep,
                     mgcp__param__observedevents=events)  # fmt: skip

    lines = [
        notify(1, gw1, ep1, "L/hd"),
        command(2, gw1, "CRCX", ep1, mgcp__param__callid="C1"),
        command(3, gw2, "CRCX", ep2, mgcp__param__callid="C1"),
        command(4, gw1, "RQNT", ep1, mgcp__param__signalreq="L/bz"),
        notify(5, gw1, ep1, "L/hu"),
    ]
    (call,) = voip_protocols.parse_mgcp_calls(lines, voip_protocols.Columns(FIELDS))
    assert (call.state, call.reason, call.ended_by) == ("Rejected", "Busy", "callee")
    assert (call.caller, call.callee) == (gw1, gw2)
    assert [m[0] for m in call.messages] == [1, 2, 3, 4, 5]


def test_other_calls_need_no_fields() -> None:
    """A tshark that refused the other protocols' fields leaves just SIP."""
    streams: list[dict[str, Any]] = []
    lines = ["\t".join(["1", "0.0"] + [""] * (len(voip.SIP_FIELDS) - 2))]
    assert voip_protocols.parse_other_calls(lines, voip.SIP_FIELDS, streams) == []
    assert streams == []


# ---------------------------------------------------------------------- with tshark


@pytest.fixture
def other_calls(service: PcapService, ctx: RequestContext) -> dict[str, Any]:
    service.open({"path": str(FIXTURES / "voip-other.pcap")}, ctx)
    return service.voip_calls({}, ctx)


@pytest.mark.tshark
def test_h323_calls(other_calls: dict[str, Any]) -> None:
    calls = [c for c in other_calls["calls"] if c["protocol"] == "H.323"]
    tunnelled, separate, busy = calls
    assert (tunnelled["from"], tunnelled["to"]) == ("alan <1001>", "2002")
    assert (tunnelled["caller"], tunnelled["callee"]) == (generate.ALAN, generate.BETTY)
    assert tunnelled["state"] == "Completed" and tunnelled["endedBy"] == "caller"
    assert tunnelled["ringing"] == pytest.approx(0.1) and tunnelled["setup"] == pytest.approx(0.8)
    assert tunnelled["reasons"] == ["Q.850 cause 16: Normal call clearing"]
    assert [m[4] for m in tunnelled["messages"]] == [
        "Setup", "Call Proceeding", "Alerting", "Connect",
        "Facility: OpenLogicalChannel", "Facility: OpenLogicalChannelAck",
        "Facility: OpenLogicalChannel", "Facility: OpenLogicalChannelAck",
        "Facility: UserInputIndication", "Release Complete",
    ]  # fmt: skip
    streams = other_calls["streams"]
    linked = {(streams[i]["srcPort"], side) for i, side in
              zip(tunnelled["streams"], tunnelled["sides"], strict=True)}  # fmt: skip
    assert linked == {(5000, "caller"), (6000, "callee")}
    assert [(d["digit"], d["duration"], d["method"]) for d in tunnelled["dtmf"]] == [
        ("5", 160, "H.245 UserInputIndication"),
    ]
    assert tunnelled["problems"] == [] and tunnelled["quality"]["rating"] == "Best"

    assert (separate["from"], separate["to"]) == ("carl <3003>", "betty <2002>")
    assert [m[4] for m in separate["messages"]] == [
        "Setup (fast start)", "Alerting", "Connect", "OpenLogicalChannel",
        "OpenLogicalChannelAck", "EndSessionCommand", "Release Complete",
    ]  # fmt: skip
    assert separate["endedBy"] == "callee"
    assert [p["text"] for p in separate["problems"]] == [
        "One-way audio: only the caller sends RTP, the callee sends none",
    ]

    assert (busy["state"], busy["reason"], busy["endedBy"]) == ("Rejected", "User busy", "callee")
    assert busy["reasons"] == ["Q.850 cause 17: User busy", "H.225 inConf"]
    assert busy["filter"] == "frame.number in {168..169}"


@pytest.mark.tshark
def test_iax2_calls_and_voice(service: PcapService, other_calls: dict[str, Any],
                              ctx: RequestContext, tmp_path: Path) -> None:  # fmt: skip
    answered, rejected = [c for c in other_calls["calls"] if c["protocol"] == "IAX2"]
    assert (answered["from"], answered["to"]) == ("Mike <3001>", "4001@default")
    assert [m[4] for m in answered["messages"]] == [
        "NEW",
        "ACCEPT",
        "RINGING",
        "ANSWER",
        "DTMF 7",
        "HANGUP",
    ], "ACKs aren't listed"
    assert (answered["state"], answered["endedBy"]) == ("Completed", "callee")
    assert answered["setup"] == pytest.approx(0.9) and answered["ringing"] == pytest.approx(0.1)
    assert answered["reasons"] == ["Q.850 cause 16: Normal Clearing"]
    assert [d["digit"] for d in answered["dtmf"]] == ["7"]
    assert answered["filter"].startswith("iax2.call == ")
    voice = [other_calls["streams"][i] for i in answered["streams"]]
    assert {(v["src"], v["payload"], v["packets"]) for v in voice} == {
        (generate.MIKE, "g711U", generate.RTP_PACKETS),
        (generate.PBX, "g711U", generate.RTP_PACKETS),
    }
    assert all(v["iax2"] == voice[0]["iax2"] and v["maxDelta"] == 20.0 for v in voice)
    assert (rejected["state"], rejected["reason"]) == ("Rejected", "No such context/extension")
    assert rejected["reasons"] == ["Q.850 cause 1: No such context/extension"]
    # The voice streams go through the RTP stream analysis and the audio decoders.
    mike = next(v for v in voice if v["src"] == generate.MIKE)
    analysis = service.rtp_stream({"stream": mike}, ctx)
    assert analysis["summary"]["packets"] == generate.RTP_PACKETS
    assert analysis["summary"]["maxJitter"] == 0.0 and analysis["filter"] == mike["filter"]
    saved = service.rtp_audio({"stream": mike, "dest": str(tmp_path / "mike.wav")}, ctx)
    assert (saved["codec"], saved["seconds"]) == ("G.711 µ-law", 1.0)
    with wave.open(str(tmp_path / "mike.wav")) as w:
        assert w.getnframes() == 8000
    # Filtering by a stream shows just its frames.
    assert service.set_filter({"expr": mike["filter"]}, ctx)["matchCount"] == generate.RTP_PACKETS
    assert service.set_filter({"expr": answered["filter"]}, ctx)["matchCount"] > 100


@pytest.mark.tshark
def test_mgcp_calls(service: PcapService, other_calls: dict[str, Any],
                    ctx: RequestContext) -> None:  # fmt: skip
    answered, busy = [c for c in other_calls["calls"] if c["protocol"] == "MGCP"]
    assert (answered["from"], answered["to"]) == ("aaln/1@gw1.example.net",
                                                  "aaln/1@gw2.example.net")  # fmt: skip
    assert (answered["caller"], answered["callee"]) == (generate.GW1, generate.GW2)
    assert answered["callId"] == generate.MGCP_CALLS[0] and answered["dialed"] == "2002"
    assert (answered["state"], answered["endedBy"]) == ("Completed", "caller")
    assert answered["ringing"] == pytest.approx(0.8) and answered["setup"] == pytest.approx(2.0)
    labels = [m[4] for m in answered["messages"]]
    assert labels[:5] == ["NTFY L/hd", "200 OK", "RQNT (S: L/dl)", "200 OK",
                          "NTFY D/2,D/0,D/0,D/2"]  # fmt: skip
    assert "CRCX (recvonly)" in labels and "MDCX (recvonly, S: L/rt, SDP)" in labels
    assert labels[-1] == "250 OK" and "AUEP" not in " ".join(labels)
    assert sorted(answered["sides"]) == ["callee", "caller"] and answered["problems"] == []
    # The filter covers its messages (with the responses) and both streams.
    shown = service.set_filter({"expr": answered["filter"]}, ctx)
    assert shown["matchCount"] == len(answered["messages"]) + 2 * generate.RTP_PACKETS

    assert (busy["state"], busy["reason"], busy["endedBy"]) == (
        "Rejected", "401 Phone off hook", "callee",
    )  # fmt: skip
    assert busy["dialed"] == "1001" and busy["streams"] == []


@pytest.mark.tshark
def test_calls_in_start_order(other_calls: dict[str, Any]) -> None:
    calls = other_calls["calls"]
    assert [c["protocol"] for c in calls] == ["H.323"] * 3 + ["IAX2"] * 2 + ["MGCP"] * 2
    assert [c["id"] for c in calls] == list(range(len(calls)))
    assert [c["start"] for c in calls] == sorted(c["start"] for c in calls)


@pytest.mark.tshark
def test_refused_fields_are_left_out(service: PcapService, ctx: RequestContext,
                                     monkeypatch: pytest.MonkeyPatch) -> None:  # fmt: skip
    """A field this tshark doesn't know drops out and the pass runs again."""
    monkeypatch.setattr(voip_protocols, "OTHER_FIELDS",
                        [*voip_protocols.OTHER_FIELDS, "iax2.no_such_field"])  # fmt: skip
    service.open({"path": str(FIXTURES / "voip-other.pcap")}, ctx)
    calls = service.voip_calls({}, ctx)["calls"]
    assert len(calls) == 7


@pytest.mark.tshark
def test_sip_calls_keep_working(service: PcapService, ctx: RequestContext) -> None:
    """The SIP fixture's calls are still found by the combined pass."""
    service.open({"path": str(FIXTURES / "voip.pcap")}, ctx)
    calls = service.voip_calls({}, ctx)["calls"]
    assert [(c["protocol"], c["state"]) for c in calls] == [
        ("SIP", "Completed"),
        ("SIP", "Rejected"),
    ]
