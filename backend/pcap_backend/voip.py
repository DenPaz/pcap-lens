"""VoIP analysis: RTP streams, SIP calls, RTP stream analysis and G.711 audio.

* RTP streams come from tshark's ``-z rtp,streams`` report (packets, loss,
  delta and jitter per stream, as Wireshark computes them).
* SIP calls are built from one ``-T fields`` pass over the SIP messages:
  tshark has no call list report. A call is a Call-ID with an INVITE; its
  SDP offers/answers name the media endpoints that link RTP streams to it.
  Each call gets its timings (ringing, answer, duration), how it ended (who
  hung up, the final response, Reason headers), DTMF digits (RFC 4733
  events and SIP INFO) and media problems (no RTP, one-way audio, codec
  mismatch, SSRC change, long silences).
* A media pass (``-T fields`` over every RTP packet) gives each stream its
  payload types, RFC 4733 telephone-events and long gaps, and the E-model
  (ITU-T G.107) turns loss, jitter and codec into an R-factor and MOS.
* The stream analysis follows one stream packet by packet (RFC 3550 jitter,
  sequence errors, skew), like Wireshark's RTP Stream Analysis.
* Audio: G.711 µ-law and A-law, G.722, G.726-32 and L16 payloads are decoded
  to 16-bit PCM (codecs.py; dynamic payload types by the SDP's rtpmap) and
  written as a WAV file (stdlib ``wave``), with silence for lost packets; a
  call's two directions can be written as one stereo file, in step.

Everything here is pure (text in, data out); the service runs tshark.
"""

from __future__ import annotations

import itertools
import re
import sys
import wave
from array import array
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

from . import codecs
from .protocol import InvalidParamsError
from .stats import _lines

# RTP timestamp clock rates of the static payload types (RFC 3551); dynamic
# types (96-127) use the SDP's rate, which we don't track: 8000 by default.
CLOCK_RATES = {
    0: 8000, 3: 8000, 4: 8000, 5: 8000, 6: 16000, 7: 8000, 8: 8000, 9: 8000,
    10: 44100, 11: 44100, 12: 8000, 13: 8000, 14: 90000, 15: 8000, 16: 11025,
    17: 22050, 18: 8000, 25: 90000, 26: 90000, 28: 90000, 31: 90000,
    32: 90000, 33: 90000, 34: 90000,
}  # fmt: skip
DEFAULT_CLOCK = 8000
PCMU, PCMA = 0, 8
# Longest silence inserted for missing audio; a bigger timestamp jump (a new
# talk spurt after a long pause, a reset) just continues the audio.
MAX_GAP_S = 10

# The per-packet analysis: [frame, time (s from the stream's first packet),
# seq, delta ms, jitter ms, skew ms, marker 0/1, status, packets missing before].
POINT_FIELDS = ["frame", "time", "seq", "delta", "jitter", "skew", "marker", "status", "gap"]
OK, SEQUENCE_GAP, OUT_OF_ORDER, PAYLOAD_CHANGED = 0, 1, 2, 3

SIP_FIELDS = [
    "frame.number",
    "frame.time_relative",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "sip.Call-ID",
    "sip.Method",
    "sip.Status-Code",
    "sip.Status-Line",
    "sip.CSeq.method",
    "sip.from.user",
    "sip.from.host",
    "sip.to.user",
    "sip.to.host",
    "sdp.connection_info.address",
    "sdp.media.port",
]
# Appended after the fields above (older code indexes the first 17).
SIP_EXTRA_FIELDS = [
    "sip.Reason",
    "sip.Content-Type",
    "sip.msg_body",
    "sdp.media",
    "sdp.media_attr",
    "sip.Expires",
]
SIP_FIELDS += SIP_EXTRA_FIELDS
# The media pass: every RTP packet (the stream key, payload type, events).
MEDIA_FIELDS = [
    "frame.number",
    "frame.time_relative",
    "ip.src",
    "ipv6.src",
    "udp.srcport",
    "ip.dst",
    "ipv6.dst",
    "udp.dstport",
    "rtp.ssrc",
    "rtp.p_type",
    "rtp.timestamp",
    "rtpevent.event_id",
    "rtpevent.duration",
    # RTCP rows (``-Y "rtp || rtcp"``): report blocks, one value per block.
    "rtcp.pt",
    "rtcp.ssrc.identifier",
    "rtcp.ssrc.fraction",
    "rtcp.ssrc.cum_nr",
    "rtcp.ssrc.jitter",
    "rtcp.roundtrip-delay",
]
# Makes tshark compute rtcp.roundtrip-delay (from an SR's time and a later
# report block's LSR and DLSR).
MEDIA_OPTIONS = ["-o", "rtcp.show_roundtrip_calculation:TRUE"]
RTP_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "rtp.seq",
    "rtp.timestamp",
    "rtp.marker",
    "rtp.p_type",
]
AUDIO_FIELDS = ["rtp.seq", "rtp.timestamp", "rtp.p_type", "rtp.payload"]
# The SIP pass joins repeated fields with this (Call-IDs may hold commas).
AGGREGATOR = "\x1e"

# A pause in a stream at least this long (s) is a media problem ("long
# silence"); at most MAX_GAPS of them are listed per stream.
SILENCE_GAP_S = 1.0
MAX_GAPS = 5
# RFC 4733 event codes of the DTMF digits.
DTMF_DIGITS = "0123456789*#ABCD"
# Names of the static payload types (RFC 3551) a codec problem mentions.
PAYLOAD_NAMES = {
    0: "PCMU", 3: "GSM", 4: "G723", 8: "PCMA", 9: "G722", 13: "CN", 15: "G728", 18: "G729",
}  # fmt: skip
# The rtp,streams report's payload names of the codecs the E-model knows.
_REPORT_PAYLOADS = {"g711U": 0, "g711A": 8, "g723": 4, "g729": 18}
# E-model codec impairment Ie and packet-loss robustness Bpl (ITU-T G.113
# Appendix I; G.711 with packet loss concealment). Other codecs are rated
# as G.711 and marked "assumed".
EMODEL_CODECS = {
    0: ("G.711", 0.0, 25.1),
    8: ("G.711", 0.0, 25.1),
    4: ("G.723.1", 15.0, 16.1),
    18: ("G.729", 11.0, 19.0),
}
# One-way delay the E-model gets (ms): a jitter buffer of twice the mean
# jitter plus this much for the codec. The network delay can't be measured
# at one capture point, so it is left out.
CODEC_DELAY_MS = 10.0
# Q.850 cause texts for Reason headers that carry none (the common ones).
Q850_CAUSES = {
    1: "Unallocated number", 3: "No route to destination", 16: "Normal call clearing",
    17: "User busy", 18: "No user responding", 19: "No answer from user",
    20: "Subscriber absent", 21: "Call rejected", 22: "Number changed",
    27: "Destination out of order", 28: "Invalid number format", 31: "Normal, unspecified",
    34: "No circuit/channel available", 38: "Network out of order",
    41: "Temporary failure", 42: "Switching equipment congestion",
    47: "Resource unavailable", 58: "Bearer capability not available",
    65: "Bearer capability not implemented", 88: "Incompatible destination",
    102: "Recovery on timer expiry", 111: "Protocol error", 127: "Interworking",
}  # fmt: skip
_REASON_RE = re.compile(
    r"(?P<proto>[\w.\-]+)\s*;\s*cause\s*=\s*(?P<cause>\d+)"
    r'(?:\s*;\s*text\s*=\s*"(?P<text>[^"]*)")?',
    re.IGNORECASE,
)

_STREAM_RE = re.compile(
    r"^\s*(?P<start>[\d.]+)\s+(?P<end>[\d.]+)\s+(?P<src>\S+)\s+(?P<sport>\d+)\s+"
    r"(?P<dst>\S+)\s+(?P<dport>\d+)\s+(?P<ssrc>0x[0-9A-Fa-f]+)\s+(?P<payload>.+?)\s+"
    r"(?P<packets>\d+)\s+(?P<lost>-?\d+)\s+\((?P<pct>-?[\d.]+)%\)\s*(?P<rest>.*)$"
)
# Report columns after "Lost" (their set depends on the tshark version).
_TAIL_KEYS = {
    "Min Delta(ms)": "minDelta",
    "Mean Delta(ms)": "meanDelta",
    "Max Delta(ms)": "maxDelta",
    "Min Jitter(ms)": "minJitter",
    "Mean Jitter(ms)": "meanJitter",
    "Max Jitter(ms)": "maxJitter",
}


# ---------------------------------------------------------------------- RTP streams


@dataclass(frozen=True, slots=True)
class StreamKey:
    """One RTP stream: its 5-tuple and SSRC (as the rtp,streams report has it)."""

    src: str
    src_port: int
    dst: str
    dst_port: int
    ssrc: int

    @classmethod
    def from_json(cls, raw: Any) -> StreamKey:
        if not isinstance(raw, dict):
            raise InvalidParamsError("stream must be an object")
        try:
            key = cls(
                str(raw["src"]),
                int(raw["srcPort"]),
                str(raw["dst"]),
                int(raw["dstPort"]),
                int(str(raw["ssrc"]), 0),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise InvalidParamsError(f"bad stream: {exc}") from exc
        for addr in (key.src, key.dst):
            if not re.fullmatch(r"[0-9A-Fa-f.:]+", addr):
                raise InvalidParamsError(f"bad address {addr!r}")
        if not (0 <= key.src_port < 65536 and 0 <= key.dst_port < 65536 and 0 <= key.ssrc < 2**32):
            raise InvalidParamsError("stream ports or SSRC out of range")
        return key

    def to_json(self) -> dict[str, Any]:
        return {
            "src": self.src,
            "srcPort": self.src_port,
            "dst": self.dst,
            "dstPort": self.dst_port,
            "ssrc": f"0x{self.ssrc:08x}",
        }

    def filter(self) -> str:
        """A display filter for the stream's packets."""
        ip = "ipv6" if ":" in self.src else "ip"
        return (
            f"rtp.ssrc == 0x{self.ssrc:08x} && {ip}.src == {self.src} && "
            f"udp.srcport == {self.src_port} && {ip}.dst == {self.dst} && "
            f"udp.dstport == {self.dst_port}"
        )


def parse_rtp_streams(text: str) -> list[dict[str, Any]]:
    """Rows of tshark's ``-z rtp,streams`` report: the stream (``src``,
    ``srcPort``, ``dst``, ``dstPort``, ``ssrc``), ``start``/``end`` (seconds
    from the first packet), ``payload``, ``packets``, ``lost``, ``lostPercent``,
    the delta and jitter columns in ms, and ``problem`` (tshark's X)."""
    tail: list[str] = []
    streams: list[dict[str, Any]] = []
    for line in _lines(text):
        if "SSRC" in line and "Payload" in line and "Lost" in line:
            # (Some names are one space apart: "Min Jitter(ms) Mean Jitter(ms)".)
            tail = re.findall(r"[A-Z][a-z]+ [A-Za-z]+\(ms\)", line)
            continue
        m = _STREAM_RE.match(line)
        if m is None:
            continue
        rest = m["rest"].split()
        problem = bool(rest) and rest[-1] == "X"
        numbers = rest[:-1] if problem else rest
        key = StreamKey(m["src"], int(m["sport"]), m["dst"], int(m["dport"]), int(m["ssrc"], 16))
        row: dict[str, Any] = {
            **key.to_json(),
            "start": float(m["start"]),
            "end": float(m["end"]),
            "payload": m["payload"].strip(),
            "packets": int(m["packets"]),
            "lost": int(m["lost"]),
            "lostPercent": float(m["pct"]),
            "problem": problem,
            "filter": key.filter(),
        }
        for name, value in zip(tail, numbers, strict=False):
            if name in _TAIL_KEYS:
                try:
                    row[_TAIL_KEYS[name]] = float(value)
                except ValueError:
                    continue
        streams.append(row)
    return streams


# ---------------------------------------------------------------------- media pass


@dataclass(slots=True)
class _Media:
    """What the media pass saw of one stream."""

    first_frame: int
    audio_types: dict[int, int] = field(default_factory=dict)  # payload type → packets
    # (RTP timestamp, event id) → [frame, time, duration in timestamp units]
    events: dict[tuple[int, int], list[Any]] = field(default_factory=dict)
    gaps: list[list[Any]] = field(default_factory=list)  # [frame, time, seconds]
    last_time: float | None = None


@dataclass(slots=True)
class _Rtcp:
    """The RTCP report blocks about one SSRC (sent by the stream's receiver)."""

    reporter: str
    reports: int = 0
    fraction: int = 0  # the last report's fraction lost (/256)
    max_fraction: int = 0
    cumulative: int = 0
    max_jitter: int = 0  # timestamp units
    rtt: int | None = None  # ms, the last round trip tshark computed
    max_rtt: int | None = None
    frame: int = 0  # the last report


@dataclass(slots=True)
class MediaPass:
    """parse_media's result: RTP streams by key, RTCP reports by reported SSRC."""

    streams: dict[StreamKey, _Media] = field(default_factory=dict)
    rtcp: dict[int, _Rtcp] = field(default_factory=dict)


def _last(cell: str) -> str:
    """The innermost of a field's occurrences (tunnels repeat ip.src)."""
    return cell.rsplit(",", 1)[-1]


def parse_media(lines: str | Iterable[str]) -> MediaPass:
    """Per stream, from a ``-T fields`` pass with MEDIA_FIELDS over the RTP
    and RTCP packets (its text or lines, in capture order): the audio payload
    types and their packet counts, the RFC 4733 telephone-events (one per
    event and timestamp: the end packet is sent three times), the gaps of at
    least SILENCE_GAP_S between two packets, and the RTCP report blocks
    about each SSRC."""
    media = MediaPass()
    for cells in _rows(lines, len(MEDIA_FIELDS)):
        frame_cell, rel, src4, src6, sport, dst4, dst6, dport, ssrc, pt, ts, event, dur = cells[:13]
        if cells[13]:
            _rtcp_row(media, cells, _last(src4 or src6))
            continue
        try:
            frame, time = int(frame_cell), float(rel)
            key = StreamKey(
                _last(src4 or src6), int(_last(sport)), _last(dst4 or dst6), int(_last(dport)),
                int(_last(ssrc), 0),
            )  # fmt: skip
            payload_type = int(_last(pt))
        except ValueError:
            continue
        m = media.streams.get(key)
        if m is None:
            m = media.streams[key] = _Media(frame)
        gap = time - m.last_time if m.last_time is not None else 0.0
        if gap >= SILENCE_GAP_S and len(m.gaps) < MAX_GAPS:
            m.gaps.append([frame, round(time - gap, 6), round(gap, 3)])
        m.last_time = time
        if event and ts.isdigit() and _last(event).isdigit():
            seen = m.events.setdefault((int(ts), int(_last(event))), [frame, time, 0])
            if _last(dur).isdigit():
                seen[2] = max(seen[2], int(_last(dur)))
        else:
            m.audio_types[payload_type] = m.audio_types.get(payload_type, 0) + 1
    return media


def _rtcp_row(media: MediaPass, cells: list[str], reporter: str) -> None:
    """Count an RTCP packet's report blocks (aligned lists: SSRC, fraction,
    cumulative lost, jitter) under the SSRCs they report on."""
    blocks = zip(*(c.split(",") for c in cells[14:18]), strict=False)
    rtt = cells[18].split(",")[0]
    for ssrc, fraction, cumulative, jitter in blocks:
        try:
            key = int(ssrc, 0)
            values = int(fraction), int(cumulative), int(jitter)
        except ValueError:
            continue
        r = media.rtcp.setdefault(key, _Rtcp(reporter))
        r.reports += 1
        r.fraction, r.cumulative = values[0], values[1]
        r.max_fraction = max(r.max_fraction, values[0])
        r.max_jitter = max(r.max_jitter, values[2])
        r.frame = int(cells[0]) if cells[0].isdigit() else r.frame
        if rtt.isdigit():
            r.rtt = int(rtt)
            r.max_rtt = max(r.max_rtt or 0, r.rtt)


def _digit(event: int) -> str:
    return DTMF_DIGITS[event] if event < len(DTMF_DIGITS) else f"event {event}"


def stream_media(stream: dict[str, Any], m: _Media | None, rtcp: _Rtcp | None = None) -> None:
    """Add the media pass's findings to an rtp,streams row: ``payloadTypes``
    (audio, most packets first), ``dtmf`` [{digit, frame, time, duration
    (ms), method, src}], ``gaps`` [[frame, time, seconds]], ``firstFrame``,
    the E-model ``quality``, and ``rtcp``: what the receiver's report blocks
    said (``reports``, ``fractionLost``/``maxFractionLost`` in %,
    ``cumulativeLost``, ``maxJitter`` ms, ``rtt``/``maxRtt`` ms, ``from``,
    ``frame``) or None."""
    types = sorted(m.audio_types, key=lambda t: -m.audio_types[t]) if m else []
    stream["payloadTypes"] = types
    stream["firstFrame"] = m.first_frame if m else None
    stream["gaps"] = m.gaps if m else []
    audio = types[0] if types else _REPORT_PAYLOADS.get(stream["payload"].split(",")[0])
    clock = CLOCK_RATES.get(audio, DEFAULT_CLOCK) if audio is not None else DEFAULT_CLOCK
    stream["dtmf"] = [
        {
            "digit": _digit(event),
            "frame": frame,
            "time": round(time, 6),
            "duration": round(units * 1000 / clock),
            "method": "RFC 4733",
            "src": stream["src"],
        }
        for (_ts, event), (frame, time, units) in (m.events.items() if m else ())
    ]
    stream["rtcp"] = (
        {
            "reports": rtcp.reports,
            "fractionLost": round(rtcp.fraction * 100 / 256, 1),
            "maxFractionLost": round(rtcp.max_fraction * 100 / 256, 1),
            "cumulativeLost": rtcp.cumulative,
            "maxJitter": round(rtcp.max_jitter * 1000 / clock, 3),
            "rtt": rtcp.rtt,
            "maxRtt": rtcp.max_rtt,
            "from": rtcp.reporter,
            "frame": rtcp.frame,
        }
        if rtcp
        else None
    )
    jitter = stream.get("meanJitter", stream.get("maxJitter", 0.0))
    stream["quality"] = emodel(max(stream["lostPercent"], 0.0), jitter, audio)


# ---------------------------------------------------------------------- call quality


def emodel(loss_percent: float, jitter_ms: float, payload_type: int | None) -> dict[str, Any]:
    """An estimate of a stream's listening quality with the E-model (ITU-T
    G.107, default values, random loss): ``r`` (R-factor, 0-100), ``mos``
    (1-4.5), ``rating`` (G.109's categories), ``codec`` and ``assumed``
    (the codec's impairment isn't in EMODEL_CODECS: rated as G.711). The
    delay is a jitter buffer of twice ``jitter_ms`` plus CODEC_DELAY_MS."""
    known = EMODEL_CODECS.get(payload_type) if payload_type is not None else None
    codec, ie, bpl = known or EMODEL_CODECS[PCMU]
    delay = 2 * jitter_ms + CODEC_DELAY_MS
    i_delay = 0.024 * delay + (0.11 * (delay - 177.3) if delay > 177.3 else 0.0)
    i_equipment = ie + (95 - ie) * loss_percent / (loss_percent + bpl)
    r = max(0.0, min(100.0, 93.2 - i_delay - i_equipment))
    mos = (
        1 + 0.035 * r + r * (r - 60) * (100 - r) * 7e-6 if 0 < r < 100 else (1.0 if r <= 0 else 4.5)
    )
    rating = (
        "Best" if r >= 90 else "High" if r >= 80 else "Medium" if r >= 70
        else "Low" if r >= 60 else "Poor"
    )  # fmt: skip
    return {
        "r": round(r, 1),
        "mos": round(mos, 2),
        "rating": rating,
        "codec": codec,
        "assumed": known is None,
    }


# ---------------------------------------------------------------------- SIP calls


@dataclass(slots=True)
class _Call:
    call_id: str
    caller: str
    callee: str
    from_uri: str
    to_uri: str
    start: float
    state: str = "Calling"
    ringing: float | None = None
    answered: float | None = None
    answer_frame: int | None = None
    ended: float | None = None
    ended_by: str | None = None  # "caller" | "callee"
    last: float = 0.0
    reason: str = ""
    final: str = ""  # the final response to the INVITE ("200 OK", "486 Busy Here")
    reasons: list[str] = field(default_factory=list)  # Reason headers, described
    messages: list[list[Any]] = field(default_factory=list)
    # SDP media endpoints → the side that offered them ("caller" or "callee").
    media: dict[tuple[str, int], str] = field(default_factory=dict)
    offer: list[int] | None = None  # payload types of the first SDP offer and answer
    answer: list[int] | None = None
    names: dict[int, str] = field(default_factory=dict)  # rtpmap: payload type → name
    rtpmap: dict[int, str] = field(default_factory=dict)  # payload type → "G726-32/8000"
    dtmf: list[dict[str, Any]] = field(default_factory=list)  # SIP INFO digits


def _uri(user: str, host: str) -> str:
    return f"{user}@{host}" if user and host else user or host


def describe_reasons(cell: str) -> list[str]:
    """Reason headers (RFC 3326) as text: "Q.850 cause 16: Normal call
    clearing", "SIP 200: Call completed elsewhere"; a Q.850 cause without
    text gets Q850_CAUSES' name."""
    out: list[str] = []
    for m in _REASON_RE.finditer(cell):
        proto, cause, text = m["proto"], int(m["cause"]), m["text"]
        if proto.upper() == "Q.850":
            label = f"Q.850 cause {cause}"
            text = text or Q850_CAUSES.get(cause)
        else:
            label = f"{proto.upper()} {cause}"
        out.append(f"{label}: {text}" if text else label)
    return out


def _sdp_formats(media_cell: str) -> list[int] | None:
    """The payload types of the audio m= lines ("audio 30000 RTP/AVP 8 101")."""
    found: list[int] | None = None
    for line in media_cell.split(AGGREGATOR):
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "audio":
            found = (found or []) + [int(p) for p in parts[3:] if p.isdigit()]
    return found


def _info_dtmf(content_type: str, body_hex: str) -> tuple[str, int | None] | None:
    """(digit, duration ms) of a SIP INFO's application/dtmf-relay
    ("Signal=5\r\nDuration=160") or application/dtmf body."""
    kind = content_type.split(";", maxsplit=1)[0].strip().lower()
    if kind not in ("application/dtmf-relay", "application/dtmf"):
        return None
    try:
        body = bytes.fromhex(body_hex.replace(":", "")).decode("utf-8", "replace")
    except ValueError:
        return None
    if kind == "application/dtmf":
        digit = body.strip()
        return (digit, None) if digit else None
    values = {
        k.strip().lower(): v.strip()
        for k, _, v in (line.partition("=") for line in body.split("\n"))
        if v
    }
    signal = values.get("signal", "")
    if not signal:
        return None
    if signal.isdigit() and int(signal) >= 10:
        signal = _digit(int(signal))  # (10 = *, 11 = #, as some phones send)
    duration = values.get("duration", "")
    return signal, int(duration) if duration.isdigit() else None


def parse_sip_calls(
    text: str | Iterable[str], streams: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """SIP calls (Call-IDs with an INVITE) from a ``-T fields`` pass with
    SIP_FIELDS (repeated fields joined with AGGREGATOR; its text or lines),
    in order of their first message: ``from``/``to`` (URIs),
    ``caller``/``callee`` (addresses of the first INVITE), ``state``
    (Calling, Ringing, In call, Completed, Rejected, Cancelled), ``start``,
    ``ringing`` (INVITE → first 180/183, s), ``setup`` (INVITE → answer, s),
    ``duration`` (answer → BYE or the last message, s), ``endedBy`` (caller
    or callee: who sent the BYE or CANCEL, or rejected the call), ``final``
    (the final response to the INVITE), ``reason`` (a failure's response),
    ``reasons`` (Reason headers, see describe_reasons), ``messages``
    [[frame, time, src, dst, label]], ``streams`` (indexes into ``streams``
    whose endpoints the call's SDP named), ``dtmf`` (SIP INFO digits plus
    the streams' RFC 4733 events, in time order), ``quality`` (the worst
    stream's E-model estimate), ``problems`` [{kind, text, frame, stream}]
    and a ``filter`` for the call's signalling and media (SIP by Call-ID,
    the linked RTP streams and their RTCP). ``streams`` rows
    carry stream_media's fields when the media pass ran."""
    calls: dict[str, _Call] = {}
    width = len(SIP_FIELDS)
    for line in _lines(text) if isinstance(text, str) else text:
        cells = line.split("\t")
        if len(cells) < width - len(SIP_EXTRA_FIELDS):
            continue
        cells += [""] * (width - len(cells))
        frame, rel, src4, src6, dst4, dst6, call_id, method, code = cells[:9]
        status_line, cseq_method, from_user, from_host, to_user, to_host = cells[9:15]
        sdp_addr, sdp_port, reason_hdr, content_type, body, sdp_media, sdp_attr = cells[15:22]
        if not call_id or not frame.isdigit():
            continue
        call_id = call_id.split(AGGREGATOR)[0]
        try:
            time = float(rel)
        except ValueError:
            continue
        src, dst = src4 or src6, dst4 or dst6
        call = calls.get(call_id)
        if call is None:
            if method != "INVITE":
                continue  # (REGISTER, OPTIONS…: not calls)
            call = calls[call_id] = _Call(
                call_id, src, dst, _uri(from_user, from_host), _uri(to_user, to_host), time
            )
        call.last = time
        side = "caller" if src == call.caller else "callee"
        if method:
            label = method
            _request(call, method, side, time)
            if method == "INFO" and (dtmf := _info_dtmf(content_type, body)):
                call.dtmf.append({
                    "digit": dtmf[0], "frame": int(frame), "time": time, "duration": dtmf[1],
                    "method": "SIP INFO", "src": src,
                })  # fmt: skip
        else:
            label = status_line.removeprefix("SIP/2.0 ").strip() or code
            _response(call, code, cseq_method, label, time, int(frame))
        call.reasons += [r for r in describe_reasons(reason_hdr) if r not in call.reasons]
        if sdp_port:
            label += " (SDP)"
            addrs = [a for a in sdp_addr.split(AGGREGATOR) if a]
            for port in sdp_port.split(AGGREGATOR):
                if port.isdigit() and addrs:
                    call.media.setdefault((addrs[-1], int(port)), side)
            formats = _sdp_formats(sdp_media)
            if method == "INVITE" and call.offer is None:
                call.offer = formats
            elif not method and cseq_method == "INVITE" and formats is not None:
                call.answer = formats
            for attr in sdp_attr.split(AGGREGATOR):
                m = re.match(r"rtpmap:(\d+)\s+(([^/\s]+)\S*)", attr)
                if m:
                    call.names[int(m[1])] = m[3]
                    call.rtpmap[int(m[1])] = m[2]
        call.messages.append([int(frame), time, src, dst, label])
    return [_call_json(i, call, streams) for i, call in enumerate(calls.values())]


@dataclass(slots=True)
class _Registration:
    aor: str
    client: str
    registrar: str
    start: float
    first_frame: int
    expires: int | None = None
    requests: int = 0
    challenges: int = 0
    final: str = ""
    code: int = 0
    last_frame: int = 0


def parse_registrations(text: str | Iterable[str]) -> list[dict[str, Any]]:
    """REGISTER transactions by Call-ID from the SIP pass's lines, in order:
    ``aor`` (the To URI), ``client`` and ``registrar`` (addresses),
    ``state`` (Registered, Unregistered (Expires: 0), Challenged (401/407
    with no later answer), Failed, No response), ``final`` (the last final
    response), ``expires`` (s: the 2xx's, else the request's), ``requests``,
    ``challenges``, ``start``, ``frames`` [first, last] and a ``filter``."""
    regs: dict[str, _Registration] = {}
    for line in _lines(text) if isinstance(text, str) else text:
        cells = line.split("\t")
        if len(cells) < len(SIP_FIELDS):
            continue
        frame, rel, src4, src6, dst4, dst6, call_id, method, code = cells[:9]
        status_line, cseq_method, _fu, _fh, to_user, to_host = cells[9:15]
        expires = cells[SIP_FIELDS.index("sip.Expires")].split(AGGREGATOR)[0]
        if cseq_method != "REGISTER" or not call_id or not frame.isdigit():
            continue
        call_id = call_id.split(AGGREGATOR)[0]
        try:
            time = float(rel)
        except ValueError:
            continue
        reg = regs.get(call_id)
        if method == "REGISTER":
            if reg is None:
                reg = regs[call_id] = _Registration(
                    _uri(to_user, to_host), src4 or src6, dst4 or dst6, time, int(frame)
                )
            reg.requests += 1
            if expires.isdigit():
                reg.expires = int(expires)
        elif reg is not None and code.isdigit():
            status = int(code)
            if status in (401, 407):
                reg.challenges += 1
            if status >= 200:
                reg.code, reg.final = status, status_line.removeprefix("SIP/2.0 ").strip() or code
                if 200 <= status < 300 and expires.isdigit():
                    reg.expires = int(expires)
        if reg is not None:
            reg.last_frame = int(frame)
    out: list[dict[str, Any]] = []
    for call_id, reg in regs.items():
        if 200 <= reg.code < 300:
            state = "Unregistered" if reg.expires == 0 else "Registered"
        elif reg.code in (401, 407):
            state = "Challenged"
        elif reg.code:
            state = "Failed"
        else:
            state = "No response"
        quoted = call_id.replace("\\", "\\\\").replace('"', '\\"')
        out.append({
            "aor": reg.aor, "client": reg.client, "registrar": reg.registrar, "state": state,
            "final": reg.final, "expires": reg.expires, "requests": reg.requests,
            "challenges": reg.challenges, "start": reg.start,
            "frames": [reg.first_frame, reg.last_frame],
            "filter": f'sip.Call-ID == "{quoted}"',
        })  # fmt: skip
    return out


def _request(call: _Call, method: str, side: str, time: float) -> None:
    if method == "BYE" and call.state in ("In call", "Calling", "Ringing"):
        call.state = "Completed" if call.answered is not None else "Cancelled"
        call.ended, call.ended_by = time, side
    elif method == "CANCEL" and call.answered is None:
        call.state, call.ended, call.ended_by = "Cancelled", time, "caller"


def _response(
    call: _Call, code: str, cseq_method: str, label: str, time: float, frame: int
) -> None:
    if cseq_method != "INVITE" or not code.isdigit():
        return
    status = int(code)
    if status in (180, 183) and call.ringing is None:
        call.ringing = time
    if status >= 200 and not call.final:
        call.final = label
    if status in (180, 183) and call.state == "Calling":
        call.state = "Ringing"
    elif 200 <= status < 300 and call.answered is None and call.state in ("Calling", "Ringing"):
        call.state, call.answered, call.answer_frame = "In call", time, frame
    elif status >= 300 and call.answered is None:  # (a final failure)
        if call.state != "Cancelled":
            call.state, call.ended_by = "Rejected", "callee"
        call.reason, call.ended = label, time


def _rtcp_filter(addr: str, rtp_port: int) -> str:
    ip = "ipv6" if ":" in addr else "ip"
    return f"rtcp && {ip}.src == {addr} && udp.srcport == {rtp_port + 1}"


def _endpoint(s: dict[str, Any], src: bool) -> str:
    return f"{s['src']}:{s['srcPort']}" if src else f"{s['dst']}:{s['dstPort']}"


def _stream_name(s: dict[str, Any]) -> str:
    return f"{_endpoint(s, True)} → {_endpoint(s, False)}"


def _types_text(types: Iterable[int], names: dict[int, str]) -> str:
    return ", ".join(f"{names.get(t) or PAYLOAD_NAMES.get(t, 'type')} ({t})" for t in types)


def _from_caller(call: _Call, s: dict[str, Any]) -> bool:
    """Whether a linked stream goes from the caller's side to the callee's
    (by which side's SDP named its source or destination)."""
    return (
        call.media.get((s["src"], s["srcPort"])) == "caller"
        or call.media.get((s["dst"], s["dstPort"])) == "callee"
    )


def _problems(
    call: _Call, streams: list[dict[str, Any]], linked: list[int]
) -> list[dict[str, Any]]:
    """The call's media problems: no RTP or one-way audio after the answer,
    streams sending a codec the SDP didn't agree on, SSRC changes, and long
    silences (gaps in a stream)."""
    out: list[dict[str, Any]] = []
    linked = sorted(linked, key=lambda i: streams[i]["start"])

    def add(kind: str, text: str, frame: int | None, stream: int | None) -> None:
        if all(p["text"] != text for p in out):  # (one per path, not per SSRC)
            out.append({"kind": kind, "text": text, "frame": frame, "stream": stream})

    if call.answered is not None:
        if not linked:
            add("no-rtp", "No RTP after the call was answered", call.answer_frame, None)
        else:
            sides = {_from_caller(call, streams[i]) for i in linked}
            if len(sides) == 1:
                sender, silent = ("caller", "callee") if sides == {True} else ("callee", "caller")
                add(
                    "one-way",
                    f"One-way audio: only the {sender} sends RTP, the {silent} sends none",
                    call.answer_frame,
                    linked[0],
                )
    agreed = call.answer if call.answer is not None else call.offer
    if agreed:
        which = "answer" if call.answer is not None else "offer"
        for i in linked:
            s = streams[i]
            wrong = [t for t in s.get("payloadTypes", []) if t not in agreed]
            if wrong:
                add(
                    "codec",
                    f"{_stream_name(s)} sends {_types_text(wrong, call.names)}, but the SDP "
                    f"{which} agreed on {_types_text(agreed, call.names)}",
                    s.get("firstFrame"),
                    i,
                )
    by_path: dict[tuple[str, int, str, int], list[int]] = {}
    for i in linked:
        s = streams[i]
        by_path.setdefault((s["src"], s["srcPort"], s["dst"], s["dstPort"]), []).append(i)
    for group in by_path.values():
        group.sort(key=lambda i: streams[i]["start"])
        for before, after in itertools.pairwise(group):
            old, new = streams[before], streams[after]
            add(
                "ssrc",
                f"{_stream_name(new)} changed SSRC from {old['ssrc']} to {new['ssrc']} "
                f"at {new['start']:.3f} s",
                new.get("firstFrame"),
                after,
            )
    for i in linked:
        s = streams[i]
        for frame, _time, seconds in s.get("gaps", []):
            add(
                "gap",
                f"No RTP from {_endpoint(s, True)} for {seconds:.2f} s before packet {frame}",
                frame,
                i,
            )
    return out


def _call_json(index: int, call: _Call, streams: list[dict[str, Any]]) -> dict[str, Any]:
    linked = [
        i
        for i, s in enumerate(streams)
        if (s["dst"], s["dstPort"]) in call.media or (s["src"], s["srcPort"]) in call.media
    ]
    end = call.ended if call.ended is not None else call.last
    if linked:
        end = max(end, *(streams[i]["end"] for i in linked))
    quoted = call.call_id.replace("\\", "\\\\").replace('"', '\\"')
    parts = [f'sip.Call-ID == "{quoted}"', *(f"({streams[i]['filter']})" for i in linked)]
    # The streams' RTCP (on the RTP port + 1), once per sending endpoint.
    parts += dict.fromkeys(
        f"({_rtcp_filter(streams[i]['src'], streams[i]['srcPort'])})" for i in linked
    )
    for i in linked:  # (how to decode the streams' dynamic payload types)
        streams[i].setdefault("rtpmap", {}).update({str(pt): e for pt, e in call.rtpmap.items()})
    rated = [(streams[i]["quality"], i) for i in linked if streams[i].get("quality")]
    worst = min(rated, key=lambda qi: qi[0]["mos"], default=None)
    dtmf = sorted(
        call.dtmf + [d for i in linked for d in streams[i].get("dtmf", [])],
        key=lambda d: d["time"],
    )

    def since_start(t: float | None) -> float | None:
        return round(t - call.start, 6) if t is not None else None

    return {
        "id": index,
        "callId": call.call_id,
        "from": call.from_uri,
        "to": call.to_uri,
        "caller": call.caller,
        "callee": call.callee,
        "state": call.state,
        "reason": call.reason,
        "final": call.final,
        "reasons": call.reasons,
        "endedBy": call.ended_by,
        "start": call.start,
        "ringing": since_start(call.ringing),
        "setup": since_start(call.answered),
        "duration": round(end - call.answered, 6) if call.answered is not None else None,
        "messages": call.messages,
        "streams": linked,
        # (parallel to streams: who sends each; whole-call audio puts the caller left)
        "sides": ["caller" if _from_caller(call, streams[i]) else "callee" for i in linked],
        "quality": {**worst[0], "stream": worst[1]} if worst else None,
        "dtmf": dtmf,
        "problems": _problems(call, streams, linked),
        "filter": " || ".join(parts),
    }


# ---------------------------------------------------------------------- stream analysis


def _rows(text: str | Iterable[str], width: int) -> Iterator[list[str]]:
    for line in _lines(text) if isinstance(text, str) else text:
        cells = line.split("\t")
        if len(cells) >= width and cells[0]:
            yield cells[:width]


def _flag(cell: str) -> int:
    return 1 if cell in ("1", "True", "true") else 0


class _Extended:
    """Unwraps a 16-bit sequence number or 32-bit timestamp into a
    monotonic counter (RFC 3550 A.1), accepting late (older) values."""

    def __init__(self, bits: int) -> None:
        self.mod = 1 << bits
        self.half = self.mod >> 1
        self.cycles = 0
        self.max: int | None = None

    def __call__(self, value: int) -> int:
        if self.max is None:
            self.max = value
            return value
        diff = (value - self.max) % self.mod
        if diff < self.half:  # newer (or equal)
            if value < self.max:
                self.cycles += self.mod
            self.max = value
            return self.cycles + value
        # Older: in the previous cycle if it is "ahead" of max numerically.
        return self.cycles + value - (self.mod if value > self.max else 0)


class _StreamAnalysis:
    """The running state of analyse_stream (Wireshark's tap-rtp-analysis)."""

    def __init__(self) -> None:
        self.points: list[list[Any]] = []
        self.seq_ext, self.ts_ext = _Extended(16), _Extended(32)
        self.clock = DEFAULT_CLOCK
        self.payload_types: list[int] = []
        self.first_time = self.prev_time = 0.0
        self.first_ts = self.prev_transit = 0.0
        self.base_seq = self.max_seq = 0
        self.jitter = self.max_jitter = self.jitter_sum = 0.0
        self.max_delta = self.max_skew = 0.0
        self.max_delta_frame = self.errors = 0

    def packet(self, frame: int, arrival: float, seq: int, ts: int, marker: int, pt: int) -> None:
        eseq, ets = self.seq_ext(seq), self.ts_ext(ts)
        if pt not in self.payload_types:
            self.payload_types.append(pt)
        if not self.points:
            self.clock = CLOCK_RATES.get(pt, DEFAULT_CLOCK)
            self.first_time = self.prev_time = arrival
            self.first_ts = ets
            self.prev_transit = arrival * self.clock - ets
            self.base_seq = self.max_seq = eseq
            self.points.append([frame, 0.0, seq, 0.0, 0.0, 0.0, marker, OK, 0])
            return
        status, gap = self._sequence(eseq)
        if pt != self.payload_types[0] and status == OK:
            status = PAYLOAD_CHANGED
        if status != OK:
            self.errors += 1
        delta = (arrival - self.prev_time) * 1000
        transit = arrival * self.clock - ets
        self.jitter += (abs(transit - self.prev_transit) - self.jitter) / 16
        self.prev_transit, self.prev_time = transit, arrival
        jitter_ms = self.jitter * 1000 / self.clock
        skew = (ets - self.first_ts) * 1000 / self.clock - (arrival - self.first_time) * 1000
        if delta > self.max_delta:
            self.max_delta, self.max_delta_frame = delta, frame
        self.max_jitter = max(self.max_jitter, jitter_ms)
        self.max_skew = max(self.max_skew, abs(skew))
        self.jitter_sum += jitter_ms
        self.points.append([
            frame, round(arrival - self.first_time, 6), seq, round(delta, 3),
            round(jitter_ms, 3), round(skew, 3), marker, status, gap,
        ])  # fmt: skip

    def _sequence(self, eseq: int) -> tuple[int, int]:
        """(status, packets missing before) of a packet's extended sequence number."""
        if eseq == self.max_seq + 1:
            self.max_seq = eseq
            return OK, 0
        if eseq > self.max_seq:
            gap = eseq - self.max_seq - 1
            self.max_seq = eseq
            return SEQUENCE_GAP, gap
        return OUT_OF_ORDER, 0  # (late or duplicated)

    def summary(self) -> dict[str, Any]:
        received = len(self.points)
        expected = self.max_seq - self.base_seq + 1 if self.points else 0
        lost = expected - received
        return {
            "packets": received,
            "expected": expected,
            "lost": lost,
            "lostPercent": round(100 * lost / expected, 2) if expected else 0.0,
            "sequenceErrors": self.errors,
            "maxDelta": round(self.max_delta, 3),
            "maxDeltaFrame": self.max_delta_frame,
            "maxJitter": round(self.max_jitter, 3),
            "meanJitter": round(self.jitter_sum / (received - 1), 3) if received > 1 else 0.0,
            "maxSkew": round(self.max_skew, 3),
            "clockRate": self.clock,
            "payloadTypes": self.payload_types,
            "duration": self.points[-1][1] if self.points else 0.0,
        }


def analyse_stream(text: str | Iterable[str]) -> dict[str, Any]:
    """Per-packet analysis of one stream from a ``-T fields`` pass with
    RTP_FIELDS (its text or lines, in arrival order): ``points`` (see
    POINT_FIELDS) and a ``summary``: packets, expected, lost, lostPercent,
    sequenceErrors, maxDelta/maxDeltaFrame, maxJitter, meanJitter, maxSkew
    (ms), clockRate, payloadTypes, duration (s). Jitter is RFC 3550's running
    estimate, as Wireshark computes it."""
    analysis = _StreamAnalysis()
    for cells in _rows(text, len(RTP_FIELDS)):
        try:
            frame, arrival = int(cells[0]), float(cells[1])
            seq, ts, pt = int(cells[2]), int(cells[3]), int(cells[5])
        except ValueError:
            continue
        analysis.packet(frame, arrival, seq, ts, _flag(cells[4]), pt)
    return {"fields": POINT_FIELDS, "points": analysis.points, "summary": analysis.summary()}


# ---------------------------------------------------------------------- audio


def _ulaw(byte: int) -> int:
    byte = ~byte & 0xFF
    magnitude = ((((byte & 0x0F) << 3) + 0x84) << ((byte >> 4) & 0x07)) - 0x84
    return -magnitude if byte & 0x80 else magnitude


def _alaw(byte: int) -> int:
    byte ^= 0x55
    exponent, mantissa = (byte >> 4) & 0x07, byte & 0x0F
    magnitude = (
        (mantissa << 4) + 8 if exponent == 0 else ((mantissa << 4) + 0x108) << (exponent - 1)
    )
    return magnitude if byte & 0x80 else -magnitude


# 256-entry decoding tables (ITU-T G.711), 16-bit linear samples.
ULAW = array("h", (_ulaw(b) for b in range(256)))
ALAW = array("h", (_alaw(b) for b in range(256)))


def _g711(table: array[int]) -> Callable[[], codecs.Decoder]:
    return lambda: lambda payload: array("h", (table[b] for b in payload))


@dataclass(frozen=True, slots=True)
class Codec:
    """A codec the audio can be decoded with: its decoded sample ``rate``
    and RTP timestamp ``clock`` (G.722: 16 kHz audio on an 8 kHz clock)."""

    name: str
    rate: int
    clock: int
    decoder: Callable[[], codecs.Decoder]


STATIC_CODECS = {
    PCMU: Codec("G.711 µ-law", 8000, 8000, _g711(ULAW)),
    PCMA: Codec("G.711 A-law", 8000, 8000, _g711(ALAW)),
    9: Codec("G.722", 16000, 8000, codecs.g722_decoder),
    10: Codec("L16 stereo", 44100, 44100, lambda: codecs.l16_decoder(2)),
    11: Codec("L16", 44100, 44100, codecs.l16_decoder),
}
_ENCODING_RE = re.compile(r"([\w.\-]+)/(\d{3,6})(?:/([1-8]))?")
PLAYABLE = "G.711 µ-law and A-law, G.722, G.726-32 and L16"


def codec_for(payload_type: int, rtpmap: dict[int, str] | None = None) -> Codec | None:
    """How to decode ``payload_type``: by the SDP's rtpmap encoding ("G726-32/8000",
    "L16/16000/2") when it names one we decode, else the static types."""
    encoding = (rtpmap or {}).get(payload_type)
    m = _ENCODING_RE.fullmatch(encoding or "")
    if m:
        name, clock, channels = m[1].upper(), int(m[2]), int(m[3] or 1)
        if name == "PCMU":
            return STATIC_CODECS[PCMU]
        if name == "PCMA":
            return STATIC_CODECS[PCMA]
        if name == "G722":
            return STATIC_CODECS[9]
        if name == "G726-32":
            return Codec("G.726-32", clock, clock, codecs.g726_32_decoder)
        if name == "L16":
            label = "L16" if channels == 1 else f"L16 ({channels} channels)"
            return Codec(label, clock, clock, lambda: codecs.l16_decoder(channels))
    return STATIC_CODECS.get(payload_type) if payload_type < 96 else None


def rtpmap_param(raw: Any) -> dict[int, str]:
    """A stream's ``rtpmap`` as the client sends it back ({"96": "G726-32/8000"}):
    only well-formed entries are kept (it only picks a decoder)."""
    if not isinstance(raw, dict):
        return {}
    return {
        int(k): v
        for k, v in raw.items()
        if isinstance(k, str) and k.isdigit() and int(k) < 128
        and isinstance(v, str) and _ENCODING_RE.fullmatch(v)
    }  # fmt: skip


def _payload(cell: str) -> bytes:
    try:
        return bytes.fromhex(cell.replace(":", ""))
    except ValueError:
        return b""


def audio_packets(text: str | Iterable[str]) -> Iterator[tuple[int, int, int, bytes]]:
    """(seq, timestamp, payload type, payload) of a ``-T fields`` pass with
    AUDIO_FIELDS (its text or lines)."""
    for cells in _rows(text, len(AUDIO_FIELDS)):
        try:
            yield int(cells[0]), int(cells[1]), int(cells[2]), _payload(cells[3])
        except ValueError:
            continue


def raw_payload(packets: Iterable[tuple[int, int, int, bytes]]) -> bytes:
    """The payloads in sequence order, duplicates dropped (for codecs we
    can't decode: tools such as ffmpeg or sox read the raw bytes)."""
    seq_ext = _Extended(16)
    ordered: dict[int, bytes] = {}
    for seq, _ts, _pt, payload in packets:
        ordered.setdefault(seq_ext(seq), payload)
    return b"".join(ordered[k] for k in sorted(ordered))


@dataclass(slots=True)
class Audio:
    """Decoded audio: 16-bit PCM at ``rate``, ``channels`` interleaved."""

    samples: array[int]
    rate: int
    codec: str
    packets: int
    silence: int  # samples inserted for missing packets (per channel)
    skipped: int  # packets of another payload type (e.g. DTMF events)
    channels: int = 1


def decode_audio(
    packets: Iterable[tuple[int, int, int, bytes]], rtpmap: dict[int, str] | None = None
) -> Audio:
    """Decode a stream in sequence order, placing each packet at its
    timestamp: missing packets become silence (up to MAX_GAP_S), duplicates
    are dropped. The first payload type we can decode (codec_for) decides the
    codec; packets of other types are skipped. Raises ValueError when no
    packet can be decoded (other codecs can only be saved as raw payload)."""
    seq_ext, ts_ext = _Extended(16), _Extended(32)
    ordered: dict[int, tuple[int, bytes]] = {}
    codec_pt: int | None = None
    codec: Codec | None = None
    other_types: set[int] = set()
    skipped = 0
    for seq, ts, pt, payload in packets:
        eseq, ets = seq_ext(seq), ts_ext(ts)
        if codec is None and (found := codec_for(pt, rtpmap)) is not None:
            codec_pt, codec = pt, found
        if pt != codec_pt:
            skipped += 1
            other_types.add(pt)
            continue
        ordered.setdefault(eseq, (ets, payload))
    if codec is None:
        types = ", ".join(str(t) for t in sorted(other_types)) or "none"
        raise ValueError(f"only {PLAYABLE} can be played; this stream has payload type {types}")
    decode = codec.decoder()
    samples = array("h")
    silence = 0
    start: int | None = None
    for eseq in sorted(ordered):
        ets, payload = ordered[eseq]
        if start is None:
            start = ets
        pcm = decode(payload)  # (always: ADPCM decoders keep state)
        missing = (ets - start) * codec.rate // codec.clock - len(samples)
        if 0 < missing <= MAX_GAP_S * codec.rate:
            samples.extend(array("h", bytes(2 * missing)))
            silence += missing
        elif missing < 0 and -missing >= len(pcm):
            continue  # (all of it already played: a duplicate)
        samples.extend(pcm)
    return Audio(samples, codec.rate, codec.name, len(ordered), silence, skipped)


def resample(samples: array[int], rate: int, to: int) -> array[int]:
    """Linear interpolation from ``rate`` to ``to`` (a call mixing codecs:
    G.722's 16 kHz with G.711's 8 kHz)."""
    if rate == to or not samples:
        return samples
    count = len(samples) * to // rate
    last = len(samples) - 1
    out = array("h", bytes(2 * count))
    for i in range(count):
        pos = i * rate / to
        j = int(pos)
        frac = pos - j
        nxt = samples[j + 1] if j < last else samples[j]
        out[i] = int(samples[j] + (nxt - samples[j]) * frac)
    return out


def mix_call(parts: Iterable[tuple[int, float, Audio]]) -> Audio:
    """One stereo Audio from a call's decoded streams: ``(channel, start,
    audio)`` with channel 0 (left: the caller's) or 1 and ``start`` the
    stream's first packet (s), so both directions play in step. Streams on
    one channel (an SSRC change) are added; everything is resampled to the
    highest rate."""
    parts = list(parts)
    rate = max(a.rate for _c, _s, a in parts)
    first = min(start for _c, start, _a in parts)
    channels: list[array[int]] = [array("h"), array("h")]
    for channel, start, audio in parts:
        pcm = resample(audio.samples, audio.rate, rate)
        target = channels[channel]
        offset = round((start - first) * rate)
        if len(target) < offset + len(pcm):
            target.extend(array("h", bytes(2 * (offset + len(pcm) - len(target)))))
        if not any(target[offset : offset + len(pcm)]):
            target[offset : offset + len(pcm)] = pcm
        else:  # (overlapping audio on one side: add, saturated)
            for i, v in enumerate(pcm):
                target[offset + i] = max(-32768, min(32767, target[offset + i] + v))
    length = max(len(c) for c in channels)
    stereo = array("h", bytes(4 * length))
    for i, c in enumerate(channels):
        c.extend(array("h", bytes(2 * (length - len(c)))))
        stereo[i::2] = c
    return Audio(
        stereo,
        rate,
        " + ".join(dict.fromkeys(a.codec for _c, _s, a in sorted(parts, key=lambda p: p[0]))),
        sum(a.packets for _c, _s, a in parts),
        sum(a.silence * rate // a.rate for _c, _s, a in parts),
        sum(a.skipped for _c, _s, a in parts),
        channels=2,
    )


def peaks(audio: Audio, buckets: int) -> list[list[int]]:
    """Per channel, the loudest sample of each of ``buckets`` equal slices (or
    of each sample, when there are fewer), 0-1000 of full scale: what the panel
    draws as the waveform."""
    out: list[list[int]] = []
    for c in range(audio.channels):
        samples = audio.samples[c :: audio.channels]
        n = len(samples)
        count = min(buckets, n)
        out.append([
            max(map(abs, samples[i * n // count : (i + 1) * n // count])) * 1000 // 32768
            for i in range(count)
        ])  # fmt: skip
    return out


def write_wav(audio: Audio, out: BinaryIO | Path) -> None:
    """Write ``audio`` as a 16-bit WAV file (little-endian samples)."""
    data = array("h", audio.samples)
    if sys.byteorder == "big":
        data.byteswap()
    target = str(out) if isinstance(out, Path) else out
    with wave.open(target, "wb") as wav:
        wav.setnchannels(audio.channels)
        wav.setsampwidth(2)
        wav.setframerate(audio.rate)
        wav.writeframes(data.tobytes())
