"""VoIP calls over H.323, MGCP and IAX2 (SIP calls are in voip.py).

All three come from the same ``-T fields`` pass as the SIP messages
(SIGNALLING_FILTER, the columns of voip.SIP_FIELDS then OTHER_FIELDS; tshark
may refuse some of the latter, so the parsers look columns up by name) and
become voip._Call objects, so they share SIP's JSON, stream linking, timings,
quality and media problems:

* H.323: H.225.0 call signalling (Q.931 messages: Setup, Alerting, Connect,
  Release Complete…) grouped by the call's GUID, or by the TCP connection
  and call reference for messages without one; H.245 (fast start proposals,
  tunnelled messages, and the separate H.245 connection a Connect's
  h245Address names) gives the media addresses (OpenLogicalChannel and its
  Ack) that link RTP streams, the codecs and UserInputIndication DTMF.
* MGCP: a call is a CallId (C:) the call agent's CRCX/MDCX/DLCX commands
  carry; a gateway endpoint's NTFY/RQNT before it (from its off-hook) and
  while it takes part belong to it, and responses to their command. The
  gateways' SDP answers link the RTP streams; observed events give the
  off-hook/on-hook times and the dialled digits, requested signals the
  ringing and a busy tone.
* IAX2: a call is tshark's ``iax2.call`` (NEW, ACCEPT, RINGING, ANSWER,
  HANGUP, REJECT…); its voice frames aren't RTP, so each direction becomes a
  stream of its own (iax2_streams), with jitter from the frames' timestamps.

Everything here is pure (lines in, data out).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

from .navigation import frame_ranges
from .voip import (
    AGGREGATOR,
    MAX_GAPS,
    PAYLOAD_NAMES,
    Q850_CAUSES,
    SILENCE_GAP_S,
    StreamKey,
    _Call,
    _call_json,
    emodel,
)

SIGNALLING_FILTER = "sip || h225 || h245 || mgcp || iax2"
# Appended to voip.SIP_FIELDS in the signalling pass.
OTHER_FIELDS = [
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    # H.225.0 / Q.931
    "q931.message_type",
    "q931.call_ref",
    "q931.cause_value",
    "q931.calling_party_number.digits",
    "q931.called_party_number.digits",
    "h225.guid",
    "h225.h323_ID",
    "h225.dialledDigits",
    "h225.sourceAddress",
    "h225.destinationAddress",
    "h225.reason",
    "h225.h245Ip",
    "h225.h245IpPort",
    "h225.fastStart",
    # H.245
    "h245.pdu_type",
    "h245.request",
    "h245.response",
    "h245.command",
    "h245.indication",
    "h245.audioData",
    "h245.ip4_network",
    "h245.tsapIdentifier",
    "h245.signalType",
    "h245.alphanumeric",
    "h245.duration",
    # MGCP
    "mgcp.req.verb",
    "mgcp.transid",
    "mgcp.req.endpoint",
    "mgcp.rsp.rspcode",
    "mgcp.rsp.rspstring",
    "mgcp.reqframe",
    "mgcp.param.callid",
    "mgcp.param.observedevents",
    "mgcp.param.signalreq",
    "mgcp.param.connectionmode",
    "mgcp.param.reasoncode",
    # IAX2
    "iax2.call",
    "iax2.packet_type",
    "iax2.type",
    "iax2.iax.subclass",
    "iax2.control.subclass",
    "iax2.voice.codec",
    "iax2.timestamp",
    "iax2.dtmf.subclass",
    "iax2.iax.cause",
    "iax2.iax.causecode",
    "iax2.iax.called_number",
    "iax2.iax.called_context",
    "iax2.iax.calling_number",
    "iax2.iax.calling_name",
    "iax2.iax.format",
]

Q931_MESSAGES = {
    0x01: "Alerting", 0x02: "Call Proceeding", 0x03: "Progress", 0x05: "Setup",
    0x07: "Connect", 0x0D: "Setup Acknowledge", 0x5A: "Release Complete", 0x62: "Facility",
    0x6E: "Notify", 0x7B: "Information", 0x7D: "Status", 0x75: "Status Enquiry",
}  # fmt: skip
SETUP, ALERTING, CONNECT, RELEASE_COMPLETE = 0x05, 0x01, 0x07, 0x5A
# H.225.0 ReleaseCompleteReason alternatives.
H225_REASONS = [
    "noBandwidth", "gatekeeperResources", "unreachableDestination", "destinationRejection",
    "invalidRevision", "noPermission", "unreachableGatekeeper", "gatewayResources",
    "badFormatAddress", "adaptiveBusy", "inConf", "undefinedReason", "facilityCallDeflection",
    "securityDenied", "calledPartyNotRegistered", "callerNotRegistered", "newConnectionNeeded",
    "nonStandardReason", "replaceWithConferenceInvite", "genericDataReason",
    "neededFeatureNotSupported", "tunnelledSignallingRejected", "invalidCID", "securityError",
    "hopCountExceeded",
]  # fmt: skip
# H.245 MultimediaSystemControlMessage: (PDU type, alternative) → name.
H245_PDUS = ("request", "response", "command", "indication")
H245_MESSAGES = {
    (0, 1): "MasterSlaveDetermination", (0, 2): "TerminalCapabilitySet",
    (0, 3): "OpenLogicalChannel", (0, 4): "CloseLogicalChannel",
    (0, 5): "RequestChannelClose", (0, 9): "RoundTripDelayRequest",
    (1, 1): "MasterSlaveDeterminationAck", (1, 2): "MasterSlaveDeterminationReject",
    (1, 3): "TerminalCapabilitySetAck", (1, 4): "TerminalCapabilitySetReject",
    (1, 5): "OpenLogicalChannelAck", (1, 6): "OpenLogicalChannelReject",
    (1, 7): "CloseLogicalChannelAck", (1, 8): "RequestChannelCloseAck",
    (1, 16): "RoundTripDelayResponse",
    (2, 2): "SendTerminalCapabilitySet", (2, 4): "FlowControlCommand",
    (2, 5): "EndSessionCommand", (2, 6): "MiscellaneousCommand",
    (3, 1): "FunctionNotUnderstood", (3, 9): "MiscellaneousIndication",
    (3, 13): "UserInputIndication",
}  # fmt: skip
# H.245 AudioCapability alternatives → RTP payload types.
H245_AUDIO = {
    1: 8, 2: 8, 3: 0, 4: 0, 5: 9, 6: 9, 7: 9, 8: 4, 9: 15, 10: 18, 11: 18, 14: 18, 15: 18,
}  # fmt: skip

# IAX2 frame types and subclasses.
IAX2_DTMF, IAX2_VOICE, IAX2_CONTROL, IAX2_IAX, IAX2_TEXT, IAX2_DTMF_BEGIN = 1, 2, 4, 6, 7, 12
IAX2_COMMANDS = {
    1: "NEW", 2: "PING", 3: "PONG", 4: "ACK", 5: "HANGUP", 6: "REJECT", 7: "ACCEPT",
    8: "AUTHREQ", 9: "AUTHREP", 10: "INVAL", 11: "LAGRQ", 12: "LAGRP", 13: "REGREQ",
    14: "REGAUTH", 15: "REGACK", 16: "REGREJ", 17: "REGREL", 18: "VNAK", 19: "DPREQ",
    20: "DPREP", 21: "DIAL", 22: "TXREQ", 23: "TXCNT", 24: "TXACC", 25: "TXREADY",
    26: "TXREL", 27: "TXREJ", 28: "QUELCH", 29: "UNQUELCH", 30: "POKE", 32: "MWI",
    33: "UNSUPPORT", 34: "TRANSFER", 40: "CALLTOKEN",
}  # fmt: skip
IAX2_CONTROLS = {
    1: "HANGUP", 2: "RING", 3: "RINGING", 4: "ANSWER", 5: "BUSY", 8: "CONGESTION",
    14: "PROGRESS", 15: "PROCEEDING", 16: "HOLD", 17: "UNHOLD",
}  # fmt: skip
# Not worth a row in the call flow (transport housekeeping).
_IAX2_QUIET = {2, 3, 4, 11, 12}
NEW, HANGUP, REJECT = 1, 5, 6
RINGING, ANSWER, BUSY, CONGESTION = 3, 4, 5, 8
# IAX2 codec bits (Asterisk's format numbers) → RTP payload types.
IAX2_CODECS = {1: 4, 2: 3, 4: 0, 8: 8, 0x100: 18, 0x1000: 9}
# Payload names as tshark's rtp,streams report writes them.
_STREAM_PAYLOADS = {0: "g711U", 8: "g711A", 9: "g722", 18: "g729", 4: "g723", 3: "GSM"}


class Columns:
    """A signalling pass's columns by field name; a field tshark refused is
    always empty."""

    def __init__(self, fields: list[str]) -> None:
        self.index = {name: i for i, name in enumerate(fields)}

    def get(self, cells: list[str], name: str) -> str:
        i = self.index.get(name)
        return cells[i] if i is not None and i < len(cells) else ""

    def all(self, cells: list[str], name: str) -> list[str]:
        """A repeated field's values."""
        return [v for v in self.get(cells, name).split(AGGREGATOR) if v]

    def first(self, cells: list[str], name: str) -> str:
        values = self.all(cells, name)
        return values[0] if values else ""


@dataclass(slots=True)
class _Row:
    """What every protocol needs of a line."""

    cells: list[str]
    frame: int
    time: float
    src: str
    dst: str
    sport: int
    dport: int


def _rows(lines: Iterable[str], cols: Columns, *protocol_fields: str) -> Iterable[_Row]:
    """The lines with one of ``protocol_fields`` (a protocol's own fields)."""
    for line in lines:
        cells = line.split("\t")
        if not any(cols.get(cells, f) for f in protocol_fields):
            continue
        frame, rel = cols.get(cells, "frame.number"), cols.get(cells, "frame.time_relative")
        try:
            time = float(rel)
        except ValueError:
            continue
        if not frame.isdigit():
            continue
        src = (cols.get(cells, "ip.src") or cols.get(cells, "ipv6.src")).split(AGGREGATOR)[-1]
        dst = (cols.get(cells, "ip.dst") or cols.get(cells, "ipv6.dst")).split(AGGREGATOR)[-1]
        ports = [
            (cols.get(cells, f"{t}.srcport"), cols.get(cells, f"{t}.dstport"))
            for t in ("udp", "tcp")
        ]
        sport, dport = next(((a, b) for a, b in ports if a and b), ("0", "0"))
        last = sport.split(AGGREGATOR)[-1], dport.split(AGGREGATOR)[-1]
        yield _Row(cells, int(frame), time, src, dst, _int(last[0]), _int(last[1]))


def _int(text: str, default: int = 0) -> int:
    try:
        return int(text, 0)
    except ValueError:
        return default


def _frames_filter(call: _Call) -> str:
    return f"frame.number in {{{','.join(frame_ranges(m[0] for m in call.messages))}}}"


def _cause(cause: int, text: str = "") -> str:
    """A Q.850 cause as text: "Q.850 cause 17: User busy"."""
    text = text or Q850_CAUSES.get(cause, "")
    return f"Q.850 cause {cause}: {text}" if text else f"Q.850 cause {cause}"


def _hang_up(call: _Call, side: str, time: float, reason: str = "") -> None:
    """The call ends: completed once answered; before that the caller
    cancelled it or the callee rejected it (a call already rejected, say by
    a busy tone, keeps who rejected it when the caller then hangs up)."""
    if call.ended is not None:
        return
    rejected_by = call.ended_by if call.state == "Rejected" else None
    call.ended, call.ended_by = time, rejected_by or side
    if call.answered is not None:
        call.state = "Completed"
    elif call.state != "Rejected":
        call.state = "Cancelled" if side == "caller" else "Rejected"
        if call.state == "Rejected" and reason:
            call.reason = reason


def _finish(calls: Iterable[_Call], streams: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for call in calls:
        if not call.signalling:
            call.signalling = _frames_filter(call)
        out.append(_call_json(0, call, streams))
    return out


# ---------------------------------------------------------------------- H.323


def _connection(row: _Row, call_ref: str) -> tuple[str, int, str, int, str]:
    """A TCP connection (either way round) and a Q.931 call reference: one
    connection can carry several calls."""
    a, b = (row.src, row.sport), (row.dst, row.dport)
    return (*min(a, b), *max(a, b), call_ref)


def _h245_labels(cols: Columns, cells: list[str]) -> list[str]:
    """The names of a packet's H.245 messages (several when tunnelled)."""
    queues = {p: cols.all(cells, f"h245.{p}") for p in H245_PDUS}
    names = []
    for pdu in cols.all(cells, "h245.pdu_type"):
        kind = _int(pdu, -1)
        if not 0 <= kind < len(H245_PDUS):
            continue
        queue = queues[H245_PDUS[kind]]
        choice = _int(queue.pop(0), -1) if queue else -1
        names.append(H245_MESSAGES.get((kind, choice), f"H.245 {H245_PDUS[kind]}"))
    return names


def parse_h323_calls(lines: Iterable[str], cols: Columns) -> list[_Call]:
    """H.323 calls (a Setup and what follows it) from the signalling pass,
    in order of their Setup."""
    calls: dict[str, _Call] = {}
    by_connection: dict[tuple[str, int, str, int, str], _Call] = {}
    by_h245: dict[tuple[str, int], _Call] = {}  # separate H.245 connections' addresses
    for row in _rows(lines, cols, "q931.message_type", "h245.pdu_type"):
        cells = row.cells
        q931 = cols.get(cells, "q931.message_type")
        h245 = _h245_labels(cols, cells)
        guid = cols.first(cells, "h225.guid")
        message = _int(q931, -1) if q931 else None
        connection = _connection(row, cols.first(cells, "q931.call_ref"))
        call = calls.get(guid) if guid else None
        if call is None:
            call = by_connection.get(connection) if message is not None else None
        if call is None and message is None:
            call = by_h245.get((row.dst, row.dport)) or by_h245.get((row.src, row.sport))
        if call is None:
            if message != SETUP:
                continue
            call = _setup(cols, cells, row, guid)
            calls[guid or f"{row.frame}"] = call
        if message is not None:
            by_connection[connection] = call
        call.last = row.time
        side = "caller" if row.src == call.caller else "callee"
        label = Q931_MESSAGES.get(message, f"Q.931 {q931}") if message is not None else ""
        if message is not None:
            _h225_message(call, cols, cells, row, message, side)
            if _int(cols.get(cells, "h225.fastStart")) > 0:
                label += " (fast start)"
            h245_ip, h245_port = cols.get(cells, "h225.h245Ip"), cols.get(cells, "h225.h245IpPort")
            if h245_ip and h245_port.isdigit():
                by_h245[(h245_ip, int(h245_port))] = call
        if h245:
            label = f"{label}: {', '.join(h245)}" if label else ", ".join(h245)
            _h245_message(call, cols, cells, row, side)
        call.messages.append([row.frame, row.time, row.src, row.dst, label])
    return list(calls.values())


def _setup(cols: Columns, cells: list[str], row: _Row, guid: str) -> _Call:
    """A new call from its Setup: the parties' numbers (Q.931 calling and
    called party numbers), else their aliases (h323-IDs or dialled digits;
    the source's come first)."""
    ids, digits = cols.all(cells, "h225.h323_ID"), cols.all(cells, "h225.dialledDigits")
    has_source = cols.get(cells, "h225.sourceAddress") not in ("", "0")
    has_destination = cols.get(cells, "h225.destinationAddress") not in ("", "0")
    aliases = ids + digits
    source = (ids[0] if ids else digits[0]) if has_source and aliases else ""
    destination = ""
    if has_destination and aliases:
        destination = digits[-1] if digits and (not has_source or ids) else ids[-1]
    calling = cols.get(cells, "q931.calling_party_number.digits")
    called = cols.get(cells, "q931.called_party_number.digits")
    return _Call(
        guid or f"frame {row.frame}",
        row.src,
        row.dst,
        _party(calling, source) or row.src,
        _party(called, destination) or row.dst,
        row.time,
        protocol="H.323",
    )


def _party(number: str, alias: str) -> str:
    """A party as "alan <1001>", or whichever of the two there is."""
    if number and alias and alias != number:
        return f"{alias} <{number}>"
    return number or alias


def _h225_message(call: _Call, cols: Columns, cells: list[str], row: _Row, message: int,
                  side: str) -> None:  # fmt: skip
    if message == ALERTING and call.ringing is None:
        call.ringing = row.time
        if call.state == "Calling":
            call.state = "Ringing"
    elif message == CONNECT and call.answered is None:
        call.state, call.answered, call.answer_frame = "In call", row.time, row.frame
    elif message == RELEASE_COMPLETE:
        reasons = []
        cause = cols.get(cells, "q931.cause_value")
        if cause.isdigit():
            reasons.append(_cause(int(cause)))
        reason = cols.get(cells, "h225.reason")
        if reason.isdigit() and int(reason) < len(H225_REASONS):
            reasons.append(f"H.225 {H225_REASONS[int(reason)]}")
        call.reasons += [r for r in reasons if r not in call.reasons]
        short = Q850_CAUSES.get(int(cause), f"cause {cause}") if cause.isdigit() else ""
        _hang_up(call, side, row.time, short or (reasons[0] if reasons else ""))


def _h245_message(call: _Call, cols: Columns, cells: list[str], row: _Row, side: str) -> None:
    """Media addresses (OpenLogicalChannel's and its Ack's: the sender's own
    RTP and RTCP addresses), codecs and DTMF."""
    networks = cols.all(cells, "h245.ip4_network")
    ports = cols.all(cells, "h245.tsapIdentifier")
    for addr, port in zip(networks, ports, strict=False):
        if port.isdigit():
            call.media.setdefault((addr, int(port)), side)
    for choice in cols.all(cells, "h245.audioData"):
        pt = H245_AUDIO.get(_int(choice, -1))
        if pt is not None and pt not in (call.offer or []):
            call.offer = [*(call.offer or []), pt]
    durations = cols.all(cells, "h245.duration")
    for i, digit in enumerate(cols.all(cells, "h245.signalType")):
        duration = durations[i] if i < len(durations) else ""
        call.dtmf.append({
            "digit": digit, "frame": row.frame, "time": row.time,
            "duration": int(duration) if duration.isdigit() else None,
            "method": "H.245 UserInputIndication", "src": row.src,
        })  # fmt: skip
    for text in cols.all(cells, "h245.alphanumeric"):
        for digit in text:
            call.dtmf.append({
                "digit": digit, "frame": row.frame, "time": row.time, "duration": None,
                "method": "H.245 alphanumeric", "src": row.src,
            })  # fmt: skip


# ---------------------------------------------------------------------- MGCP


@dataclass(slots=True)
class _Mgcp(_Call):
    endpoints: list[str] = field(default_factory=list)  # the caller's first
    gateways: dict[str, str] = field(default_factory=dict)  # endpoint → gateway address


@dataclass(slots=True)
class _Request:
    """A command; responses go where it went (a call, or an endpoint's
    messages since its off-hook)."""

    verb: str
    endpoint: str
    call: _Mgcp | None
    pending: list[tuple[_Row, str]] | None = None


MGCP_GATEWAY_PORT = 2427
_DIGIT_RE = re.compile(r"^(?:[A-Za-z]+/)?([0-9*#A-D])$")


def _events(cell: str) -> list[str]:
    """MGCP events without their package and parameters ("L/hd" → "hd",
    "D/2" → "2", "L/rg(to=6000)" → "rg")."""
    out = []
    for raw in re.split(r"[,\s]+", re.sub(r"\([^)]*\)", "", cell)):
        name = raw.strip().rpartition("/")[2].lower()
        if name:
            out.append(name.upper() if _DIGIT_RE.match(raw.strip()) else name)
    return out


class _MgcpCalls:
    """parse_mgcp_calls' state: the calls by CallId, commands by frame, each
    endpoint's call and its messages (and digits) since its off-hook."""

    def __init__(self, cols: Columns) -> None:
        self.cols = cols
        self.calls: dict[str, _Mgcp] = {}
        self.requests: dict[int, _Request] = {}
        self.active: dict[str, _Mgcp] = {}
        self.pending: dict[str, list[tuple[_Row, str]]] = {}
        self.dialed: dict[str, str] = {}

    def response(self, row: _Row) -> None:
        cells = row.cells
        request = self.requests.get(_int(self.cols.get(cells, "mgcp.reqframe"), -1))
        if request is not None and request.call is not None:
            _mgcp_response(self.cols, cells, row, request)
        elif request is not None and request.pending is not None:
            code = self.cols.get(cells, "mgcp.rsp.rspcode")
            text = self.cols.get(cells, "mgcp.rsp.rspstring")
            request.pending.append((row, f"{code} {text}".strip()))

    def join(self, call_id: str, endpoint: str, row: _Row) -> _Mgcp:
        """The call a command with a CallId belongs to (new or not); the
        endpoint joins it with its messages since its off-hook."""
        call = self.calls.get(call_id)
        if call is None:
            early = self.pending.get(endpoint)
            start = early[0][0].time if early else row.time
            call = self.calls[call_id] = _Mgcp(
                call_id, row.dst, "", endpoint, "", start, protocol="MGCP"
            )
            call.dialed = self.dialed.get(endpoint, "")
        if endpoint not in call.endpoints:
            call.endpoints.append(endpoint)
            call.gateways[endpoint] = _gateway(row)
            if len(call.endpoints) == 2:
                call.callee, call.to_uri = call.gateways[endpoint], endpoint
        for message, label in self.pending.pop(endpoint, []):
            call.messages.append([message.frame, message.time, message.src, message.dst, label])
            if message.frame in self.requests:  # (later responses to it join the call)
                self.requests[message.frame].call = call
        self.active[endpoint] = call
        return call

    def idle(self, row: _Row, verb: str, endpoint: str, label: str, events: list[str]) -> None:
        """A command outside any call: an off-hook starts collecting the
        endpoint's messages and digits, an on-hook drops them."""
        if verb == "NTFY" and "hd" in events:
            self.pending[endpoint] = [(row, label)]
            self.dialed.pop(endpoint, None)
        elif endpoint in self.pending:
            self.pending[endpoint].append((row, label))
            if verb == "NTFY":
                digits = "".join(e for e in events if len(e) == 1)
                self.dialed[endpoint] = self.dialed.get(endpoint, "") + digits
                if "hu" in events:
                    del self.pending[endpoint]
        self.requests[row.frame] = _Request(verb, endpoint, None, self.pending.get(endpoint))

    def request(self, row: _Row, verb: str) -> None:
        cols, cells = self.cols, row.cells
        endpoint = cols.get(cells, "mgcp.req.endpoint").lower()
        call_id = cols.get(cells, "mgcp.param.callid")
        label = _mgcp_label(cols, cells, verb)
        events = _events(cols.get(cells, "mgcp.param.observedevents"))
        call = self.join(call_id, endpoint, row) if call_id else self.active.get(endpoint)
        if call is None:
            self.idle(row, verb, endpoint, label, events)
            return
        self.requests[row.frame] = _Request(verb, endpoint, call)
        call.last = row.time
        call.messages.append([row.frame, row.time, row.src, row.dst, label])
        side = "caller" if endpoint == call.endpoints[0] else "callee"
        _mgcp_events(call, cols, cells, row, verb, side, events)
        if verb == "DLCX":
            self.active.pop(endpoint, None)
            if call.answered is not None:
                _hang_up(call, side, row.time)


def parse_mgcp_calls(lines: Iterable[str], cols: Columns) -> list[_Call]:
    """MGCP calls (CallIds) from the signalling pass, in order of their first
    message (the caller's off-hook)."""
    state = _MgcpCalls(cols)
    for row in _rows(lines, cols, "mgcp.transid"):
        verb = cols.get(row.cells, "mgcp.req.verb")
        if verb:
            state.request(row, verb)
        else:
            state.response(row)
    for call in state.calls.values():
        call.caller = call.gateways.get(call.endpoints[0], call.caller) if call.endpoints else ""
        call.from_uri = call.endpoints[0] if call.endpoints else call.from_uri
        if not call.to_uri:
            call.to_uri = call.dialed or ""
    return list(state.calls.values())


def _gateway(row: _Row) -> str:
    """The gateway's address of a message with the call agent (gateways
    listen on UDP 2427, agents on 2727; commands mostly come from the agent)."""
    return row.src if row.sport == MGCP_GATEWAY_PORT != row.dport else row.dst


def _mgcp_label(cols: Columns, cells: list[str], verb: str) -> str:
    """ "NTFY L/hd", "RQNT S: L/rg", "CRCX (recvonly)"."""
    if verb == "NTFY":
        return f"NTFY {cols.get(cells, 'mgcp.param.observedevents')}".strip()
    details = []
    if mode := cols.get(cells, "mgcp.param.connectionmode"):
        details.append(mode)
    if signal := cols.get(cells, "mgcp.param.signalreq"):
        details.append(f"S: {signal}")
    if cols.get(cells, "sdp.media.port"):
        details.append("SDP")
    return f"{verb} ({', '.join(details)})" if details else verb


def _mgcp_events(call: _Mgcp, cols: Columns, cells: list[str], row: _Row, verb: str,
                 side: str, events: list[str]) -> None:  # fmt: skip
    """Ringing (a ringing or ringback signal), the answer (the callee's
    off-hook), a busy tone, hanging up (on-hook), DTMF during the call."""
    signals = _events(cols.get(cells, "mgcp.param.signalreq"))
    if call.ringing is None and (
        ("rg" in signals and side == "callee") or ("rt" in signals and side == "caller")
    ):
        call.ringing = row.time
        if call.state == "Calling":
            call.state = "Ringing"
    if "bz" in signals and side == "caller" and call.answered is None:
        call.state, call.ended_by = "Rejected", call.ended_by or "callee"
        call.reason = call.reason or "Busy"
    if verb == "NTFY":
        if "hd" in events and side == "callee" and call.answered is None:
            call.state, call.answered, call.answer_frame = "In call", row.time, row.frame
        if "hu" in events:
            _hang_up(call, side, row.time)
        if call.answered is not None:
            for digit in (e for e in events if len(e) == 1):
                call.dtmf.append({
                    "digit": digit, "frame": row.frame, "time": row.time, "duration": None,
                    "method": "MGCP NTFY", "src": row.src,
                })  # fmt: skip
    reason = cols.get(cells, "mgcp.param.reasoncode")
    if reason and f"MGCP reason {reason}" not in call.reasons:
        call.reasons.append(f"MGCP reason {reason}")


def _mgcp_response(cols: Columns, cells: list[str], row: _Row, request: _Request) -> None:
    """A response joins its command's call: the gateway's SDP names its
    endpoint's media, an error to a CRCX rejects the call."""
    call = request.call
    assert call is not None
    code = cols.get(cells, "mgcp.rsp.rspcode")
    text = cols.get(cells, "mgcp.rsp.rspstring")
    label = f"{code} {text}".strip()
    side = "caller" if call.endpoints and request.endpoint == call.endpoints[0] else "callee"
    addrs = [a for a in cols.get(cells, "sdp.connection_info.address").split(AGGREGATOR) if a]
    for port in cols.get(cells, "sdp.media.port").split(AGGREGATOR):
        if port.isdigit() and addrs:
            call.media.setdefault((addrs[-1], int(port)), side)
            label += " (SDP)" if not label.endswith("(SDP)") else ""
    call.last = row.time
    call.messages.append([row.frame, row.time, row.src, row.dst, label])
    if request.verb == "CRCX" and code.isdigit() and int(code) >= 400 and call.answered is None:
        call.state, call.ended_by = "Rejected", side
        call.reason, call.ended = label, call.ended or row.time


# ---------------------------------------------------------------------- IAX2


@dataclass(slots=True)
class _Voice:
    """One direction of an IAX2 call's voice frames."""

    call: int
    src: str
    sport: int
    dst: str
    dport: int
    first_frame: int
    start: float
    end: float = 0.0
    packets: int = 0
    codec: int | None = None
    last: tuple[float, int] | None = None  # (arrival, timestamp ms)
    jitter: float = 0.0
    jitter_sum: float = 0.0
    max_jitter: float = 0.0
    deltas: list[float] = field(default_factory=list)
    gaps: list[list[Any]] = field(default_factory=list)

    def add(self, row: _Row, timestamp: int | None) -> None:
        if self.last is not None:
            arrival, ts = self.last
            delta = row.time - arrival
            self.deltas.append(delta * 1000)
            if delta >= SILENCE_GAP_S and len(self.gaps) < MAX_GAPS:
                self.gaps.append([row.frame, round(arrival, 6), round(delta, 3)])
            if timestamp is not None:
                d = abs(delta * 1000 - (timestamp - ts))  # RFC 3550 6.4.1, in ms
                self.jitter += (d - self.jitter) / 16
                self.max_jitter = max(self.max_jitter, self.jitter)
                self.jitter_sum += self.jitter
        self.packets += 1
        self.end = row.time
        if timestamp is not None:
            self.last = (row.time, timestamp)


def _iax2_codec(cell: str) -> int | None:
    value = _int(cell, -1)
    return IAX2_CODECS.get(value) if value > 0 else None


def iax2_streams(lines: Iterable[str], cols: Columns) -> list[dict[str, Any]]:
    """Each IAX2 call's voice frames per direction, as rows like
    voip.parse_rtp_streams' (``iax2``: the call; SSRC 0; no loss: mini
    frames carry no sequence number) with stream_media's fields."""
    voices: dict[tuple[int, str, int], _Voice] = {}
    codecs: dict[int, int] = {}  # call → payload type (NEW/ACCEPT's format)
    for row in _rows(lines, cols, "iax2.call"):
        cells = row.cells
        call = _int(cols.get(cells, "iax2.call"), -1)
        kind = cols.get(cells, "iax2.type")
        if (codec := _iax2_codec(cols.get(cells, "iax2.iax.format"))) is not None:
            codecs[call] = codec
        voice = cols.get(cells, "iax2.packet_type") == "0" or kind == str(IAX2_VOICE)
        if call < 0 or not voice:
            continue
        key = (call, row.src, row.sport)
        v = voices.get(key)
        if v is None:
            v = voices[key] = _Voice(call, row.src, row.sport, row.dst, row.dport, row.frame,
                                     row.time)  # fmt: skip
        if (codec := _iax2_codec(cols.get(cells, "iax2.voice.codec"))) is not None:
            v.codec = codec
        ts = cols.get(cells, "iax2.timestamp")
        v.add(row, int(ts) if ts.isdigit() else None)
    return [_voice_json(v, codecs.get(v.call)) for v in voices.values()]


def _voice_json(v: _Voice, call_codec: int | None) -> dict[str, Any]:
    pt = v.codec if v.codec is not None else call_codec
    key = StreamKey(v.src, v.sport, v.dst, v.dport, 0, v.call, pt)
    jitters = v.packets - 1 if v.packets > 1 else 0
    mean_jitter = v.jitter_sum / jitters if jitters else 0.0
    name = "IAX2" if pt is None else _STREAM_PAYLOADS.get(pt, PAYLOAD_NAMES.get(pt, "IAX2"))
    row: dict[str, Any] = {
        **key.to_json(),
        "protocol": "IAX2",
        "start": round(v.start, 6),
        "end": round(v.end, 6),
        "payload": name,
        "packets": v.packets,
        "lost": 0,
        "lostPercent": 0.0,
        "problem": False,
        "filter": key.filter(),
        "minDelta": round(min(v.deltas), 3) if v.deltas else 0.0,
        "meanDelta": round(sum(v.deltas) / len(v.deltas), 3) if v.deltas else 0.0,
        "maxDelta": round(max(v.deltas), 3) if v.deltas else 0.0,
        "meanJitter": round(mean_jitter, 3),
        "maxJitter": round(v.max_jitter, 3),
        "payloadTypes": [pt] if pt is not None else [],
        "firstFrame": v.first_frame,
        "gaps": v.gaps,
        "dtmf": [],
        "rtcp": None,
    }
    row["quality"] = emodel(0.0, mean_jitter, pt)
    return row


def parse_iax2_calls(lines: Iterable[str], cols: Columns) -> list[_Call]:
    """IAX2 calls (a NEW and what follows on its call) from the signalling
    pass, in order of their NEW."""
    calls: dict[int, _Call] = {}
    for row in _rows(lines, cols, "iax2.call"):
        cells = row.cells
        number = _int(cols.get(cells, "iax2.call"), -1)
        kind = _int(cols.get(cells, "iax2.type"), -1)
        if cols.get(cells, "iax2.packet_type") == "0" or kind == IAX2_VOICE:
            continue
        iax = _int(cols.get(cells, "iax2.iax.subclass"), -1) if kind == IAX2_IAX else -1
        call = calls.get(number)
        if call is None:
            if iax != NEW:
                continue
            calling = cols.get(cells, "iax2.iax.calling_number")
            name = cols.get(cells, "iax2.iax.calling_name")
            called = cols.get(cells, "iax2.iax.called_number")
            context = cols.get(cells, "iax2.iax.called_context")
            call = calls[number] = _Call(
                str(number), row.src, row.dst, _party(calling, name) or row.src,
                f"{called}@{context}" if called and context else called or row.dst,
                row.time, protocol="IAX2", iax2=number, signalling=f"iax2.call == {number}",
            )  # fmt: skip
            # (only used to tell the directions apart: the streams link by call)
            call.media[(row.src, row.sport)] = "caller"
            call.media[(row.dst, row.dport)] = "callee"
        if (codec := _iax2_codec(cols.get(cells, "iax2.iax.format"))) is not None:
            call.offer = [codec]
        call.last = row.time
        side = "caller" if (row.src, row.sport) == next(iter(call.media)) else "callee"
        label = _iax2_frame(call, cols, cells, row, kind, iax, side)
        if label:
            call.messages.append([row.frame, row.time, row.src, row.dst, label])
    return list(calls.values())


def _iax2_frame(call: _Call, cols: Columns, cells: list[str], row: _Row, kind: int, iax: int,
                side: str) -> str:  # fmt: skip
    """A full frame's effect on the call and its label ("" for housekeeping)."""
    if kind == IAX2_IAX:
        if iax in (HANGUP, REJECT):
            reasons = []
            text = cols.get(cells, "iax2.iax.cause")
            code = _int(cols.get(cells, "iax2.iax.causecode"), -1)
            if code >= 0:
                reasons.append(_cause(code, text))
            elif text:
                reasons.append(text)
            call.reasons += [r for r in reasons if r not in call.reasons]
            if iax == REJECT and call.answered is None:
                call.state, call.reason = "Rejected", text or (reasons[0] if reasons else "")
            _hang_up(call, side, row.time, text)
        return "" if iax in _IAX2_QUIET else IAX2_COMMANDS.get(iax, f"IAX {iax}")
    if kind == IAX2_CONTROL:
        control = _int(cols.get(cells, "iax2.control.subclass"), -1)
        if control == RINGING and call.ringing is None:
            call.ringing = row.time
            call.state = "Ringing" if call.state == "Calling" else call.state
        elif control == ANSWER and call.answered is None:
            call.state, call.answered, call.answer_frame = "In call", row.time, row.frame
        elif control in (BUSY, CONGESTION) and call.answered is None:
            call.state = "Rejected"
            call.reason = "Busy" if control == BUSY else "Congestion"
        elif control == 1:
            _hang_up(call, side, row.time)
        return IAX2_CONTROLS.get(control, f"Control {control}")
    if kind in (IAX2_DTMF, IAX2_DTMF_BEGIN):
        digit = cols.get(cells, "iax2.dtmf.subclass")
        if kind == IAX2_DTMF and digit:
            call.dtmf.append({
                "digit": digit, "frame": row.frame, "time": row.time, "duration": None,
                "method": "IAX2 DTMF", "src": row.src,
            })  # fmt: skip
        return f"DTMF {digit}" if kind == IAX2_DTMF else ""
    if kind == IAX2_TEXT:
        return "Text"
    return ""


# The pass over one IAX2 voice stream (iax2_as_rtp turns it into an RTP pass).
IAX2_VOICE_FIELDS = ["frame.number", "frame.time_epoch", "iax2.timestamp", "iax2.payload_data"]
# The payload type of voice in a codec without one (its audio can be saved raw).
UNKNOWN_CODEC = 96


def iax2_as_rtp(lines: Iterable[str], payload_type: int | None,
                fields: list[str]) -> Iterator[str]:  # fmt: skip
    """An IAX2 voice stream's frames (lines of IAX2_VOICE_FIELDS) as the
    lines of an RTP pass with ``fields`` (voip.RTP_FIELDS or AUDIO_FIELDS),
    so the stream analysis and the audio decoders take them as they are: a
    sequence number counting the frames (mini frames have none), the
    timestamp in 8 kHz units (IAX2's are ms) and the stream's payload type."""
    pt = str(UNKNOWN_CODEC if payload_type is None else payload_type)
    seq = 0
    for line in lines:
        cells = line.split("\t")
        if len(cells) < len(IAX2_VOICE_FIELDS) or not cells[2].isdigit() or not cells[3]:
            continue
        values = {
            "frame.number": cells[0],
            "frame.time_epoch": cells[1],
            "rtp.seq": str(seq & 0xFFFF),
            "rtp.timestamp": str((int(cells[2]) * 8) & 0xFFFFFFFF),
            "rtp.marker": "1" if seq == 0 else "0",
            "rtp.p_type": pt,
            "rtp.payload": cells[3],
        }
        seq += 1
        yield "\t".join(values.get(f, "") for f in fields)


# ---------------------------------------------------------------------- all of them


def parse_other_calls(lines: list[str], fields: list[str],
                      streams: list[dict[str, Any]]) -> list[dict[str, Any]]:  # fmt: skip
    """The H.323, MGCP and IAX2 calls of a signalling pass (its lines and
    field list) as voip_calls lists them. ``streams`` (the RTP streams) gets
    the IAX2 voice streams appended first, so the calls can link them."""
    cols = Columns(fields)
    streams += iax2_streams(lines, cols)
    calls = [
        *parse_h323_calls(lines, cols),
        *parse_mgcp_calls(lines, cols),
        *parse_iax2_calls(lines, cols),
    ]
    return _finish(calls, streams)
