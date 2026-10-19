"""VoIP analysis: RTP streams, SIP calls, RTP stream analysis and audio."""

from __future__ import annotations

import itertools
import sys
import wave
from array import array
from pathlib import Path
from typing import Any

import pytest

from pcap_backend import voip
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import InvalidParamsError, RequestContext

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
sys.path.insert(0, str(FIXTURES))
import generate  # noqa: E402 - the fixture generator's G.711 encoder and constants

# tshark 4.2's report for voip.pcap (the jitter columns are one space apart).
RTP_STREAMS_REPORT = """\
========================= RTP Streams ========================
   Start time      End time     Src IP addr  Port    Dest IP addr  Port       SSRC          Payload  Pkts         Lost   Min Delta(ms)  Mean Delta(ms)   Max Delta(ms)  Min Jitter(ms) Mean Jitter(ms)  Max Jitter(ms) Problems?
     1.021295      2.002918        10.0.0.1 40000        10.0.0.2 50000 0x11111111            g711U    49     1 (2.0%)          16.281          20.450          42.318           0.043           0.992           1.406 X
     1.021000      2.001000        10.0.0.2 50000        10.0.0.1 40000 0x22222222            g711U    50     0 (0.0%)          20.000          20.000          20.000           0.000           0.000           0.000
     3.000000      4.000000      2001:db8::1  5004     2001:db8::2  5006 0xDEADBEEF  RTPType-96, g729   10    -2 (-20.0%)          20.000          20.000          20.000           0.000           0.000           0.000
==============================================================
"""  # noqa: E501


def _sip_lines(*rows: list[str]) -> str:
    """-T fields lines of SIP_FIELDS from short rows (missing cells empty)."""
    width = len(voip.SIP_FIELDS)
    return "\n".join("\t".join(row + [""] * (width - len(row))) for row in rows)


def _sip(frame: int, time: float, src: str, dst: str, call_id: str, **kw: str) -> list[str]:
    cells = dict.fromkeys(voip.SIP_FIELDS, "")
    cells.update({
        "frame.number": str(frame), "frame.time_relative": str(time), "ip.src": src,
        "ip.dst": dst, "sip.Call-ID": call_id,
    })  # fmt: skip
    for key, value in kw.items():
        cells[{
            "method": "sip.Method", "code": "sip.Status-Code", "line": "sip.Status-Line",
            "cseq": "sip.CSeq.method", "from_user": "sip.from.user", "to_user": "sip.to.user",
            "sdp_addr": "sdp.connection_info.address", "sdp_port": "sdp.media.port",
        }[key]] = value  # fmt: skip
    return [cells[f] for f in voip.SIP_FIELDS]


def _zero_crossing_hz(samples: array[int], rate: int) -> float:
    crossings = sum(1 for a, b in itertools.pairwise(samples) if (a < 0) != (b < 0))
    return crossings / 2 / (len(samples) / rate)


# ---------------------------------------------------------------------- pure


def test_rtp_streams_report_is_parsed_whatever_the_column_spacing() -> None:
    first, second, v6 = voip.parse_rtp_streams(RTP_STREAMS_REPORT)
    assert first["src"] == "10.0.0.1" and first["srcPort"] == 40000
    assert (first["dst"], first["dstPort"], first["ssrc"]) == ("10.0.0.2", 50000, "0x11111111")
    assert (first["packets"], first["lost"], first["lostPercent"]) == (49, 1, 2.0)
    assert (first["maxDelta"], first["meanJitter"], first["maxJitter"]) == (42.318, 0.992, 1.406)
    assert first["problem"] is True and second["problem"] is False
    assert first["start"] == 1.021295 and first["payload"] == "g711U"
    assert first["filter"] == (
        "rtp.ssrc == 0x11111111 && ip.src == 10.0.0.1 && udp.srcport == 40000 && "
        "ip.dst == 10.0.0.2 && udp.dstport == 50000"
    )
    # IPv6, a payload name with spaces and more packets than expected (duplicates).
    assert v6["payload"] == "RTPType-96, g729" and v6["lost"] == -2
    assert v6["ssrc"] == "0xdeadbeef" and v6["filter"].startswith("rtp.ssrc == 0xdeadbeef && ipv6")


def test_stream_keys_from_the_client_are_checked() -> None:
    """The key goes into a display filter: nothing but addresses and numbers."""
    good = {"src": "10.0.0.1", "srcPort": 1, "dst": "::1", "dstPort": 2, "ssrc": "0x10"}
    assert voip.StreamKey.from_json(good).ssrc == 16
    for bad in (
        {**good, "src": "10.0.0.1 || frame"},
        {**good, "dst": 'a" or "b'},
        {**good, "srcPort": 70000},
        {**good, "ssrc": "0x1ffffffff"},
        {**good, "ssrc": "nope"},
        {key: value for key, value in good.items() if key != "dst"},
        "not an object",
    ):
        with pytest.raises(InvalidParamsError):
            voip.StreamKey.from_json(bad)


def test_sip_call_states() -> None:
    text = _sip_lines(
        _sip(1, 0.0, "a", "b", "c1", method="INVITE", from_user="alice", to_user="bob"),
        _sip(2, 0.1, "b", "a", "c1", code="180", line="SIP/2.0 180 Ringing", cseq="INVITE"),
        _sip(3, 0.5, "a", "b", "c1", method="CANCEL"),
        _sip(
            4, 0.6, "b", "a", "c1", code="487", line="SIP/2.0 487 Request Terminated", cseq="INVITE"
        ),
        _sip(5, 1.0, "a", "b", "c2", method="INVITE"),
        _sip(6, 1.1, "b", "a", "c2", code="200", line="SIP/2.0 200 OK", cseq="INVITE"),
        _sip(7, 2.0, "a", "r", "reg", method="REGISTER"),
        _sip(8, 3.0, "a", "b", 'odd"id\\', method="INVITE"),
    )
    cancelled, in_call, odd = voip.parse_sip_calls(text, [])
    assert cancelled["state"] == "Cancelled" and cancelled["from"] == "alice"
    assert cancelled["setup"] is None and cancelled["duration"] is None
    assert [m[4] for m in cancelled["messages"]] == [
        "INVITE", "180 Ringing", "CANCEL", "487 Request Terminated",
    ]  # fmt: skip
    assert in_call["state"] == "In call" and in_call["setup"] == pytest.approx(0.1)
    assert odd["state"] == "Calling"
    assert odd["filter"] == 'sip.Call-ID == "odd\\"id\\\\"', "quotes and backslashes escaped"
    # Timings and who ended it.
    assert (cancelled["ringing"], cancelled["endedBy"]) == (pytest.approx(0.1), "caller")
    assert cancelled["final"] == "487 Request Terminated"
    assert (in_call["ringing"], in_call["final"], in_call["endedBy"]) == (None, "200 OK", None)


def test_how_calls_end_and_sip_info_dtmf() -> None:
    def info(frame: int, time: float, ctype: str, body: bytes) -> list[str]:
        row = _sip(frame, time, "b", "a", "c1", method="INFO")
        row[voip.SIP_FIELDS.index("sip.Content-Type")] = ctype
        row[voip.SIP_FIELDS.index("sip.msg_body")] = body.hex()
        return row

    bye = _sip(9, 5.0, "b", "a", "c1", method="BYE")
    bye[voip.SIP_FIELDS.index("sip.Reason")] = (
        'Q.850;cause=16;text="Normal call clearing"\x1eSIP;cause=200'
    )
    text = _sip_lines(
        _sip(1, 0.0, "a", "b", "c1", method="INVITE"),
        _sip(2, 0.2, "b", "a", "c1", code="183", line="SIP/2.0 183 Session Progress",
             cseq="INVITE"),
        _sip(3, 1.0, "b", "a", "c1", code="200", line="SIP/2.0 200 OK", cseq="INVITE"),
        info(4, 2.0, "application/dtmf-relay", b"Signal=5\r\nDuration=160\r\n"),
        info(5, 2.5, "application/dtmf-relay; charset=x", b"Signal=11\nDuration=x\n"),
        info(6, 3.0, "application/dtmf", b"*\r\n"),
        info(7, 3.5, "text/plain", b"Signal=9"),
        info(8, 4.0, "application/dtmf-relay", b"Duration=100"),
        bye,
        _sip(10, 6.0, "a", "b", "c2", method="INVITE"),
        _sip(11, 6.5, "b", "a", "c2", code="603", line="SIP/2.0 603 Decline", cseq="INVITE"),
    )  # fmt: skip
    call, declined = voip.parse_sip_calls(text, [])
    assert (call["ringing"], call["setup"], call["duration"]) == (0.2, 1.0, 4.0)
    assert (call["state"], call["endedBy"]) == ("Completed", "callee")
    assert call["reasons"] == ["Q.850 cause 16: Normal call clearing", "SIP 200"]
    assert [(d["digit"], d["duration"], d["frame"]) for d in call["dtmf"]] == [
        ("5", 160, 4), ("#", None, 5), ("*", None, 6),
    ]  # fmt: skip
    assert {d["method"] for d in call["dtmf"]} == {"SIP INFO"}
    assert call["problems"] == [
        {"kind": "no-rtp", "text": "No RTP after the call was answered", "frame": 3,
         "stream": None},
    ]  # fmt: skip
    assert (declined["state"], declined["endedBy"], declined["problems"]) == (
        "Rejected", "callee", [],
    )  # fmt: skip


def test_reason_headers() -> None:
    assert voip.describe_reasons("Q.850;cause=17") == ["Q.850 cause 17: User busy"]
    assert voip.describe_reasons("q.850 ; cause = 999") == ["Q.850 cause 999"]
    assert voip.describe_reasons('SIP;cause=600;text="Busy Everywhere"') == [
        "SIP 600: Busy Everywhere"
    ]
    assert voip.describe_reasons("nonsense") == []


def test_emodel() -> None:
    clean = voip.emodel(0.0, 0.0, 0)
    assert clean == {"r": 93.0, "mos": 4.4, "rating": "Best", "codec": "G.711", "assumed": False}
    # 2 % random loss with packet loss concealment: Ie,eff = 95 · 2 / (2 + 25.1).
    lossy = voip.emodel(2.0, 1.0, 8)
    assert (lossy["r"], lossy["mos"], lossy["rating"]) == (85.9, 4.23, "High")
    # G.729 starts lower (Ie 11); an unknown codec is rated as G.711, "assumed".
    assert voip.emodel(0.0, 0.0, 18)["r"] == 82.0
    assert voip.emodel(0.0, 0.0, 96)["assumed"] is True
    assert voip.emodel(0.0, 0.0, None)["codec"] == "G.711"
    # A jitter buffer past 177.3 ms adds the steep part of the delay impairment.
    assert voip.emodel(0.0, 100.0, 0)["r"] == pytest.approx(93.2 - 5.04 - 0.11 * 32.7, abs=0.05)
    bad = voip.emodel(40.0, 30.0, 0)
    assert bad["rating"] == "Poor" and bad["mos"] < 2.6
    assert voip.emodel(100.0, 1000.0, 4) == {
        "r": 0.0, "mos": 1.0, "rating": "Poor", "codec": "G.723.1", "assumed": False,
    }  # fmt: skip


def test_media_pass() -> None:
    def rtp(frame: int, time: float, pt: int, ts: int, event: str = "", dur: str = "") -> str:
        cells = [str(frame), str(time), "10.0.0.1", "", "4000", "10.0.0.2", "", "5000",
                 "0x00000010", str(pt), str(ts), event, dur, "", "", "", "", "", ""]  # fmt: skip
        return "\t".join(cells)

    media = voip.parse_media([
        rtp(1, 0.00, 0, 0), rtp(2, 0.02, 0, 160),
        rtp(3, 0.04, 101, 320, "11", "160"), rtp(4, 0.06, 101, 320, "11", "480"),
        rtp(5, 0.08, 101, 320, "11", "480"), rtp(6, 1.50, 0, 480), rtp(7, 1.52, 13, 640),
        "garbage",
    ])  # fmt: skip
    (key,) = media.streams
    assert key == voip.StreamKey("10.0.0.1", 4000, "10.0.0.2", 5000, 16)
    m = media.streams[key]
    assert (m.first_frame, m.audio_types, m.gaps) == (1, {0: 3, 13: 1}, [[6, 0.08, 1.42]])
    stream = {"src": "10.0.0.1", "srcPort": 4000, "payload": "g711U", "lostPercent": 0.0,
              "meanJitter": 0.0}  # fmt: skip
    voip.stream_media(stream, m)
    assert stream["payloadTypes"] == [0, 13]
    assert stream["dtmf"] == [
        {"digit": "#", "frame": 3, "time": 0.04, "duration": 60, "method": "RFC 4733",
         "src": "10.0.0.1"},
    ]  # fmt: skip
    assert stream["quality"]["mos"] == 4.4
    # Without the media pass the report's payload name picks the codec.
    bare = {"src": "a", "srcPort": 1, "payload": "g729", "lostPercent": -5.0, "maxJitter": 0.0}
    voip.stream_media(bare, None)
    assert (bare["payloadTypes"], bare["dtmf"], bare["firstFrame"]) == ([], [], None)
    assert bare["quality"]["codec"] == "G.729"


def test_g711_tables() -> None:
    assert voip.ULAW[0xFF] == 0 and voip.ULAW[0x7F] == 0
    assert voip.ULAW[0x00] == -32124 and voip.ULAW[0x80] == 32124
    assert voip.ALAW[0xD5] == 8 and voip.ALAW[0x55] == -8
    assert voip.ALAW[0xAA] == 32256 and voip.ALAW[0x2A] == -32256
    for sample in range(-32000, 32001, 997):
        decoded = voip.ULAW[generate.ulaw_encode(sample)]
        assert abs(decoded - sample) <= abs(sample) / 16 + 8, sample


def test_sequence_numbers_wrap_around() -> None:
    lines = [
        f"{i + 1}\t{100 + i * 0.02:.3f}\t{seq}\t{i * 160}\tFalse\t0"
        for i, seq in enumerate([65534, 65535, 0, 1, 3, 2])
    ]
    result = voip.analyse_stream(lines)
    statuses = [p[7] for p in result["points"]]
    assert statuses == [voip.OK, voip.OK, voip.OK, voip.OK, voip.SEQUENCE_GAP, voip.OUT_OF_ORDER]
    assert result["points"][4][8] == 1, "one packet missing before seq 3"
    assert result["summary"]["expected"] == 6 and result["summary"]["lost"] == 0


def test_audio_needs_g711_and_raw_payload_keeps_sequence_order() -> None:
    with pytest.raises(ValueError, match="payload type 18"):
        voip.decode_audio([(1, 0, 18, b"\x00" * 20)])
    packets = [(2, 160, 18, b"b"), (1, 0, 18, b"a"), (2, 160, 18, b"b"), (3, 320, 18, b"c")]
    assert voip.raw_payload(packets) == b"abc"
    # DTMF events in a G.711 stream are skipped, duplicates dropped.
    audio = voip.decode_audio([(1, 0, 0, b"\xff" * 160), (2, 160, 101, b"\x00" * 4),
                               (1, 0, 0, b"\xff" * 160), (3, 320, 0, b"\xff" * 160)])  # fmt: skip
    assert (audio.packets, audio.skipped, audio.silence) == (2, 1, 160)
    assert len(audio.samples) == 480


# ---------------------------------------------------------------------- with tshark


@pytest.fixture
def voip_open(service: PcapService, ctx: RequestContext) -> PcapService:
    service.open({"path": str(FIXTURES / "voip.pcap")}, ctx)
    return service


def _streams(svc: PcapService, ctx: RequestContext) -> dict[int, dict[str, Any]]:
    """The fixture's streams by source port (40000: alice's, 50000: bob's)."""
    return {s["srcPort"]: s for s in svc.voip_calls({}, ctx)["streams"]}


@pytest.mark.tshark
def test_calls_and_streams(voip_open: PcapService, ctx: RequestContext) -> None:
    result = voip_open.voip_calls({}, ctx)
    streams = {s["srcPort"]: i for i, s in enumerate(result["streams"])}
    alice = result["streams"][streams[40000]]
    assert (alice["packets"], alice["lost"], alice["payload"]) == (49, 1, "g711U")
    assert alice["maxJitter"] > 0 and alice["problem"] is True
    call, busy = result["calls"]
    assert (call["from"], call["to"], call["state"]) == (
        "alice@10.0.0.1", "bob@10.0.0.2", "Completed",
    )  # fmt: skip
    assert (call["caller"], call["callee"]) == (generate.ALICE, generate.BOB)
    assert call["setup"] == pytest.approx(1.0) and call["duration"] == pytest.approx(1.07)
    assert [m[4] for m in call["messages"]] == [
        "INVITE (SDP)", "100 Trying", "180 Ringing", "200 OK (SDP)", "ACK", "BYE", "200 OK",
    ]  # fmt: skip
    assert sorted(call["streams"]) == sorted(streams.values()), "both streams belong to it"
    assert (busy["state"], busy["reason"], busy["streams"]) == ("Rejected", "486 Busy Here", [])
    # The call's filter shows its signalling and its media.
    shown = voip_open.set_filter({"expr": call["filter"]}, ctx)
    assert shown["matchCount"] == 7 + 2 * generate.RTP_PACKETS - 1
    assert voip_open.voip_calls({}, ctx) is result, "cached"


@pytest.mark.tshark
def test_stream_analysis_matches_tshark(voip_open: PcapService, ctx: RequestContext) -> None:
    alice = _streams(voip_open, ctx)[40000]
    result = voip_open.rtp_stream({"stream": alice}, ctx)
    summary = result["summary"]
    assert (summary["packets"], summary["expected"], summary["lost"]) == (49, 50, 1)
    assert summary["maxJitter"] == pytest.approx(alice["maxJitter"], abs=0.002)
    assert summary["meanJitter"] == pytest.approx(alice["meanJitter"], abs=0.002)
    assert summary["maxDelta"] == pytest.approx(alice["maxDelta"], abs=0.002)
    (gap,) = [p for p in result["points"] if p[7] == voip.SEQUENCE_GAP]
    assert gap[2] == 1000 + generate.RTP_LOST + 1 and gap[8] == 1
    assert result["points"][0][6] == 1, "the first packet has the marker bit"
    assert result["filter"] == alice["filter"]


@pytest.mark.tshark
def test_saving_audio(voip_open: PcapService, ctx: RequestContext, tmp_path: Path) -> None:
    streams = _streams(voip_open, ctx)
    for port, tone in ((40000, generate.RTP_TONES[0]), (50000, generate.RTP_TONES[1])):
        dest = tmp_path / f"{port}.wav"
        result = voip_open.rtp_audio({"stream": streams[port], "dest": str(dest)}, ctx)
        assert result["codec"] == "G.711 µ-law" and result["seconds"] == pytest.approx(1.0)
        with wave.open(str(dest), "rb") as wav:
            assert (wav.getnchannels(), wav.getsampwidth(), wav.getframerate()) == (1, 2, 8000)
            samples = array("h", wav.readframes(wav.getnframes()))
        if sys.byteorder == "big":
            samples.byteswap()
        lost = port == 40000
        assert result["silence"] == pytest.approx(0.02 if lost else 0.0)
        # Only the lost packet's 20 ms are silent (the tone never crosses zero for that long).
        quiet = [i for i in range(0, len(samples), 160) if not any(samples[i : i + 160])]
        assert quiet == ([160 * generate.RTP_LOST] if lost else [])
        audible = array("h", samples[: 160 * generate.RTP_LOST])
        assert _zero_crossing_hz(audible, 8000) == pytest.approx(tone, rel=0.03)
    raw = voip_open.rtp_audio(
        {"stream": streams[40000], "dest": str(tmp_path / "a.raw"), "format": "raw"}, ctx
    )
    assert raw["bytes"] == (tmp_path / "a.raw").stat().st_size == 49 * 160


@pytest.mark.tshark
def test_bad_audio_requests(voip_open: PcapService, ctx: RequestContext, tmp_path: Path) -> None:
    stream = _streams(voip_open, ctx)[40000]
    with pytest.raises(InvalidParamsError, match="absolute"):
        voip_open.rtp_audio({"stream": stream, "dest": "relative.wav"}, ctx)
    with pytest.raises(InvalidParamsError, match="format"):
        voip_open.rtp_audio({"stream": stream, "dest": str(tmp_path / "x"), "format": "mp3"}, ctx)
    with pytest.raises(InvalidParamsError, match="open capture"):
        voip_open.rtp_audio({"stream": stream, "dest": str(FIXTURES / "voip.pcap")}, ctx)
    # A stream with no packets (wrong SSRC): nothing to save.
    ghost = {**stream, "ssrc": "0x12345678"}
    with pytest.raises(InvalidParamsError, match="no packets"):
        voip_open.rtp_audio({"stream": ghost, "dest": str(tmp_path / "g.wav")}, ctx)
    assert not (tmp_path / "g.wav").exists()


@pytest.mark.tshark
def test_heuristic_rtp_finds_streams_without_signalling(
    service: PcapService, ctx: RequestContext, tmp_path: Path
) -> None:
    """Without the SIP messages tshark only finds the RTP heuristically."""
    from scapy.utils import wrpcap  # noqa: PLC0415 - dev dependency, this test only

    media = [p for p in generate.voip_packets() if p.haslayer("RTP")]
    wrpcap(str(tmp_path / "rtp-only.pcap"), media)
    service.open({"path": str(tmp_path / "rtp-only.pcap")}, ctx)
    assert service.voip_calls({}, ctx)["streams"] == []
    found = service.voip_calls({"heuristic": True}, ctx)["streams"]
    assert sorted(s["srcPort"] for s in found) == [40000, 50000]
    assert all(s["heuristic"] for s in found)
    analysis = service.rtp_stream({"stream": found[0]}, ctx)
    assert analysis["summary"]["packets"] in (49, 50)


@pytest.mark.tshark
def test_call_details(service: PcapService, ctx: RequestContext) -> None:
    """voip-calls.pcap: DTMF, Reason headers and every kind of media problem."""
    service.open({"path": str(FIXTURES / "voip-calls.pcap")}, ctx)
    result = service.voip_calls({}, ctx)
    dtmf, oneway, silent, cancelled, unavailable = result["calls"]
    assert [(d["digit"], d["method"], d["src"]) for d in dtmf["dtmf"]] == [
        ("4", "RFC 4733", generate.DAVE), ("7", "SIP INFO", generate.ERIN),
        ("#", "RFC 4733", generate.DAVE),
    ]  # fmt: skip
    assert dtmf["dtmf"][0]["duration"] == 80 and dtmf["dtmf"][1]["duration"] == 250
    assert dtmf["quality"]["rating"] == "Best" and dtmf["problems"] == []
    texts = [p["text"] for p in oneway["problems"]]
    assert texts == [
        "One-way audio: only the caller sends RTP, the callee sends none",
        "10.0.1.3:34000 → 10.0.1.2:36000 sends PCMA (8), but the SDP answer agreed on PCMU (0)",
        "10.0.1.3:34000 → 10.0.1.2:36000 changed SSRC from 0x33333333 to 0x44444444 at 7.520 s",
        "No RTP from 10.0.1.3:34000 for 1.52 s before packet 225",
    ]
    # Each problem points at a packet: the 200 OK, a stream's first packet, the gap's end.
    frames = [p["frame"] for p in oneway["problems"]]
    assert frames[0] == next(m[0] for m in oneway["messages"] if m[4] == "200 OK (SDP)")
    assert frames[3] == 225
    assert [p["kind"] for p in silent["problems"]] == ["no-rtp"]
    assert (cancelled["state"], cancelled["endedBy"]) == ("Cancelled", "caller")
    assert unavailable["reasons"] == ["Q.850 cause 18: No user responding"]
    # The call's filter adds its streams' RTCP (none in this capture).
    assert "(rtcp && ip.src == 10.0.1.3 && udp.srcport == 34001)" in oneway["filter"]
    assert oneway["filter"].count("rtcp") == 1, "one per sending endpoint"


SIP_STAT_REPORT = """
===================================================================
SIP Statistics

Number of SIP messages: 12
Number of resent SIP messages: 1

* SIP Status Codes in reply packets
  SIP 486 Busy Here       :     1 Packets
  SIP 200 OK              :     3 Packets
  SIP 401 Unauthorized    :     1 Packets

* List of SIP Request methods
  INVITE          :     2 Packets
  ACK             :     2 Packets
  REGISTER        :     3 Packets

* Average setup time 500 ms
 Min 100 ms
 Max 900 ms
===================================================================
"""


def test_sip_stat_report() -> None:
    from pcap_backend import stats  # noqa: PLC0415 - this test only

    table = stats.parse_sip_stat(SIP_STAT_REPORT).to_json()
    rows = [(r["depth"], *r["cells"], r.get("filter")) for r in table["rows"]]
    assert rows == [
        (0, "SIP messages", 12, None, "sip"),
        (1, "Resent", 1, None, "sip.resend == 1"),
        (0, "Responses", 5, None, "sip.Status-Code"),
        (1, "200 OK", 3, None, "sip.Status-Code == 200"),
        (1, "401 Unauthorized", 1, None, "sip.Status-Code == 401"),
        (1, "486 Busy Here", 1, None, "sip.Status-Code == 486"),
        (0, "Requests", 7, None, "sip.Method"),
        (1, "REGISTER", 3, None, 'sip.Method == "REGISTER"'),
        (1, "INVITE", 2, None, 'sip.Method == "INVITE"'),
        (1, "ACK", 2, None, 'sip.Method == "ACK"'),
        (0, "Setup time (average)", None, 500, None),
        (1, "Min", None, 100, None),
        (1, "Max", None, 900, None),
    ]
    assert stats.parse_sip_stat("nothing").rows == []


def test_mixing_a_call_and_its_waveform() -> None:
    caller = voip.Audio(array("h", [1000] * 8), 8000, "G.711 µ-law", 1, 0, 0)
    callee = voip.Audio(array("h", [-2000] * 8), 16000, "G.722", 1, 0, 0)
    # The callee's audio starts 1 ms later (16 samples at 16 kHz) and is at 16 kHz.
    mixed = voip.mix_call([(1, 0.101, callee), (0, 0.1, caller)])
    assert (mixed.rate, mixed.channels, mixed.codec) == (16000, 2, "G.711 µ-law + G.722")
    left, right = list(mixed.samples[0::2]), list(mixed.samples[1::2])
    assert left[:16] == [1000] * 16 and left[16:] == [0] * 8
    assert right[:16] == [0] * 16 and right[16:] == [-2000] * 8
    # Two streams on one side (an SSRC change) are added where they overlap.
    both = voip.mix_call([(0, 0.0, caller), (0, 0.0005, caller)])
    assert list(both.samples[0::2]) == [1000] * 4 + [2000] * 4 + [1000] * 4
    peaks = voip.peaks(mixed, 3)
    assert peaks == [[30, 30, 0], [0, 0, 61]]


@pytest.fixture
def media_open(service: PcapService, ctx: RequestContext) -> PcapService:
    service.open({"path": str(FIXTURES / "voip-media.pcap")}, ctx)
    return service


@pytest.mark.tshark
def test_g722_g726_and_l16_streams_decode(
    media_open: PcapService, ctx: RequestContext, tmp_path: Path
) -> None:
    import test_codecs  # noqa: PLC0415 - its reference vectors

    result = media_open.voip_calls({}, ctx)
    streams = {s["srcPort"]: s for s in result["streams"]}
    assert streams[48000]["rtpmap"] == {"9": "G722/8000", "96": "G726-32/8000"}
    decoded: dict[int, array[int]] = {}
    for port, codec in ((46000, "G.722"), (48000, "G.726-32"), (50000, "L16")):
        dest = tmp_path / f"{port}.wav"
        res = media_open.rtp_audio({"stream": streams[port], "dest": str(dest)}, ctx)
        assert (res["codec"], res["seconds"]) == (codec, pytest.approx(0.5))
        with wave.open(str(dest), "rb") as wav:
            decoded[port] = array("h", wav.readframes(wav.getnframes()))
        if sys.byteorder == "big":
            decoded[port].byteswap()
    assert decoded[46000] == test_codecs._pcm("ref-g722.pcm")
    assert test_codecs._snr_db(decoded[48000], test_codecs._pcm("ref-g726.pcm")) > 35
    assert _zero_crossing_hz(decoded[50000], 8000) == pytest.approx(1000, rel=0.02)
    # Without the SDP's rtpmap, the dynamic types can't be decoded.
    bare = {k: v for k, v in streams[48000].items() if k != "rtpmap"}
    with pytest.raises(InvalidParamsError, match="payload type 96") as err:
        media_open.rtp_audio({"stream": bare, "dest": str(tmp_path / "x.wav")}, ctx)
    assert err.value.data == {"unsupported": True}


@pytest.mark.tshark
def test_rtcp_reports_per_stream(media_open: PcapService, ctx: RequestContext) -> None:
    streams = {s["srcPort"]: s for s in media_open.voip_calls({}, ctx)["streams"]}
    # judy (10.0.1.7) reported on erin's stream: 26/256 lost, 2 in all, jitter
    # 40 units of the 8 kHz clock, and the round trip from erin's SR.
    erin = streams[48000]["rtcp"]
    assert erin["from"] == generate.JUDY and erin["reports"] == 1
    assert (erin["fractionLost"], erin["cumulativeLost"], erin["maxJitter"]) == (10.2, 2, 5.0)
    assert erin["rtt"] == pytest.approx(generate.RTCP_RTT_MS, abs=1)
    judy = streams[46000]["rtcp"]
    assert (judy["from"], judy["fractionLost"], judy["rtt"]) == (generate.ERIN, 0.0, None)
    assert streams[50000]["rtcp"] is None


@pytest.mark.tshark
def test_a_whole_call_as_stereo(
    voip_open: PcapService, ctx: RequestContext, tmp_path: Path
) -> None:
    result = voip_open.voip_calls({}, ctx)
    call = result["calls"][0]
    assert sorted(call["sides"]) == ["callee", "caller"]
    streams = [
        {**result["streams"][i], "channel": 0 if side == "caller" else 1}
        for i, side in zip(call["streams"], call["sides"], strict=True)
    ]
    dest = tmp_path / "call.wav"
    res = voip_open.call_audio({"streams": streams, "dest": str(dest), "buckets": 100}, ctx)
    assert (res["rate"], res["seconds"], res["skipped"]) == (8000, pytest.approx(1.0), [])
    assert [len(p) for p in res["peaks"]] == [100, 100]
    with wave.open(str(dest), "rb") as wav:
        assert (wav.getnchannels(), wav.getframerate()) == (2, 8000)
        samples = array("h", wav.readframes(wav.getnframes()))
    if sys.byteorder == "big":
        samples.byteswap()
    # Caller (alice, 440 Hz) left, callee (bob, 880 Hz) right, each from its
    # first packet's time (alice's comes a fraction of a ms later).
    left, right = samples[0::2], samples[1::2]
    start = {s["channel"]: s["start"] for s in streams}
    lead = round((start[0] - start[1]) * 8000)
    assert lead > 0 and not any(left[:lead]) and any(right[:lead])
    assert _zero_crossing_hz(left[: 160 * generate.RTP_LOST], 8000) == pytest.approx(440, rel=0.03)
    assert _zero_crossing_hz(right[:4000], 8000) == pytest.approx(880, rel=0.03)
    with pytest.raises(InvalidParamsError, match="channel"):
        voip_open.call_audio({"streams": [{**streams[0], "channel": 2}], "dest": str(dest)}, ctx)
    with pytest.raises(InvalidParamsError, match="streams"):
        voip_open.call_audio({"streams": [], "dest": str(dest)}, ctx)


@pytest.mark.tshark
def test_registrations_and_sip_statistics(service: PcapService, ctx: RequestContext) -> None:
    service.open({"path": str(FIXTURES / "voip-calls.pcap")}, ctx)
    regs = service.voip_calls({}, ctx)["registrations"]
    assert [(r["aor"], r["state"], r["final"], r["expires"], r["challenges"]) for r in regs] == [
        ("dave@example.test", "Registered", "200 OK", 3600, 1),
        ("frank@example.test", "Failed", "403 Forbidden", 3600, 0),
        ("grace@example.test", "Unregistered", "200 OK", 0, 0),
    ]
    assert regs[0]["client"] == generate.DAVE and regs[0]["registrar"] == generate.REGISTRAR
    shown = service.set_filter({"expr": regs[0]["filter"]}, ctx)
    assert shown["matchCount"] == 4  # REGISTER, 401, REGISTER, 200
    table = service.stats({"kind": "sip"}, ctx)
    counts = {r["cells"][0]: r["cells"][1] for r in table["rows"]}
    assert counts["SIP messages"] == 39 and counts["REGISTER"] == 4 and counts["INVITE"] == 5
    assert counts["401 Unauthorized"] == 1
    # Every row's filter matches as many messages as the row counts.
    for row in table["rows"]:
        if row.get("filter"):
            shown = service.set_filter({"expr": row["filter"]}, ctx)
            assert shown["matchCount"] == row["cells"][1], row
    setup = {r["cells"][0]: r["cells"][2] for r in table["rows"] if r["cells"][2] is not None}
    assert setup["Min"] <= setup["Setup time (average)"] <= setup["Max"]
