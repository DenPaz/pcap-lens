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
* Audio: G.711 µ-law and A-law payloads are decoded to 16-bit PCM and
  written as a WAV file (stdlib ``wave``), with silence for lost packets.

Everything here is pure (text in, data out); the service runs tshark.
"""

from __future__ import annotations

import itertools
import re
import sys
import wave
from array import array
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

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
]
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


def _last(cell: str) -> str:
    """The innermost of a field's occurrences (tunnels repeat ip.src)."""
    return cell.rsplit(",", 1)[-1]


def parse_media(lines: str | Iterable[str]) -> dict[StreamKey, _Media]:
    """Per stream, from a ``-T fields`` pass with MEDIA_FIELDS over the RTP
    packets (its text or lines, in capture order): the audio payload types
    and their packet counts, the RFC 4733 telephone-events (one per event
    and timestamp: the end packet is sent three times) and the gaps of at
    least SILENCE_GAP_S between two packets."""
    media: dict[StreamKey, _Media] = {}
    for cells in _rows(lines, len(MEDIA_FIELDS)):
        frame_cell, rel, src4, src6, sport, dst4, dst6, dport, ssrc, pt, ts, event, dur = cells
        try:
            frame, time = int(frame_cell), float(rel)
            key = StreamKey(
                _last(src4 or src6), int(_last(sport)), _last(dst4 or dst6), int(_last(dport)),
                int(_last(ssrc), 0),
            )  # fmt: skip
            payload_type = int(_last(pt))
        except ValueError:
            continue
        m = media.get(key)
        if m is None:
            m = media[key] = _Media(frame)
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


def _digit(event: int) -> str:
    return DTMF_DIGITS[event] if event < len(DTMF_DIGITS) else f"event {event}"


def stream_media(stream: dict[str, Any], m: _Media | None) -> None:
    """Add the media pass's findings to an rtp,streams row: ``payloadTypes``
    (audio, most packets first), ``dtmf`` [{digit, frame, time, duration
    (ms), method, src}], ``gaps`` [[frame, time, seconds]], ``firstFrame``,
    and the E-model ``quality``."""
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
                m = re.match(r"rtpmap:(\d+)\s+([^/\s]+)", attr)
                if m:
                    call.names[int(m[1])] = m[2]
        call.messages.append([int(frame), time, src, dst, label])
    return [_call_json(i, call, streams) for i, call in enumerate(calls.values())]


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

            def from_caller(s: dict[str, Any]) -> bool:
                return (
                    call.media.get((s["src"], s["srcPort"])) == "caller"
                    or call.media.get((s["dst"], s["dstPort"])) == "callee"
                )

            sides = {from_caller(streams[i]) for i in linked}
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
CODECS = {PCMU: ("G.711 µ-law", ULAW), PCMA: ("G.711 A-law", ALAW)}


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
    """Decoded audio of a stream: 16-bit mono PCM at ``rate``."""

    samples: array[int]
    rate: int
    codec: str
    packets: int
    silence: int  # samples inserted for missing packets
    skipped: int  # packets of another payload type (e.g. DTMF events)


def decode_audio(packets: Iterable[tuple[int, int, int, bytes]]) -> Audio:
    """Decode a G.711 stream in sequence order, placing each packet at its
    timestamp: missing packets become silence (up to MAX_GAP_S), duplicates
    are dropped. The stream's first G.711 payload type decides the codec;
    packets of other types are skipped. Raises ValueError when no packet is
    G.711 (other codecs can only be saved as raw payload)."""
    seq_ext, ts_ext = _Extended(16), _Extended(32)
    ordered: dict[int, tuple[int, int, bytes]] = {}
    codec_pt: int | None = None
    other_types: set[int] = set()
    skipped = 0
    for seq, ts, pt, payload in packets:
        eseq, ets = seq_ext(seq), ts_ext(ts)
        if codec_pt is None and pt in CODECS:
            codec_pt = pt
        if pt != codec_pt:
            skipped += 1
            other_types.add(pt)
            continue
        ordered.setdefault(eseq, (ets, pt, payload))
    if codec_pt is None:
        types = ", ".join(str(t) for t in sorted(other_types)) or "none"
        raise ValueError(
            f"only G.711 µ-law and A-law (payload types 0 and 8) can be played; "
            f"this stream has payload type {types}"
        )
    name, table = CODECS[codec_pt]
    rate = CLOCK_RATES[codec_pt]
    samples = array("h")
    silence = 0
    start: int | None = None
    for eseq in sorted(ordered):
        ets, _pt, payload = ordered[eseq]
        if start is None:
            start = ets
        offset = ets - start
        missing = offset - len(samples)
        if 0 < missing <= MAX_GAP_S * rate:
            samples.extend(array("h", bytes(2 * missing)))
            silence += missing
        elif missing < 0 and -missing >= len(payload):
            continue  # (all of it already played: a duplicate)
        samples.extend(table[b] for b in payload)
    return Audio(samples, rate, name, len(ordered), silence, skipped)


def write_wav(audio: Audio, out: BinaryIO | Path) -> None:
    """Write ``audio`` as a 16-bit mono WAV file (little-endian samples)."""
    data = array("h", audio.samples)
    if sys.byteorder == "big":
        data.byteswap()
    target = str(out) if isinstance(out, Path) else out
    with wave.open(target, "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(audio.rate)
        wav.writeframes(data.tobytes())
