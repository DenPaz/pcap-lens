"""H.323 call signalling for the VoIP fixtures, encoded by hand.

H.225.0 messages are Q.931 messages (in TPKT on TCP 1720) whose User-user
information element holds an ASN.1 ``H323-UserInformation`` value in aligned
PER (ITU-T X.691); H.245 messages (fast start proposals, tunnelled or on
their own TCP connection) are ``MultimediaSystemControlMessage`` values in
the same encoding. :class:`Bits` implements the few aligned PER rules these
types need, and the builders below follow the ASN.1 modules Wireshark 4.2
dissects (``H323-MESSAGES.asn``, ``MULTIMEDIA-SYSTEM-CONTROL.asn``): the
numbers of root alternatives, optional components and extension additions
are what decides the encoding, so they are spelled out next to each type.
Standard library only.
"""

from __future__ import annotations

import ipaddress
import struct
from collections.abc import Callable, Sequence

# H.225.0 version 4 (itu-t recommendation h 2250 0 4).
H225_PROTOCOL = bytes([0x00, 0x08, 0x91, 0x4A, 0x00, 0x04])


class Bits:
    """An aligned PER bit stream (X.691, the ALIGNED variant)."""

    def __init__(self) -> None:
        self.bits: list[int] = []

    def bit(self, value: bool | int) -> Bits:
        self.bits.append(1 if value else 0)
        return self

    def field(self, value: int, width: int) -> Bits:
        """``value`` in ``width`` bits, no alignment."""
        self.bits.extend((value >> (width - 1 - i)) & 1 for i in range(width))
        return self

    def align(self) -> Bits:
        while len(self.bits) % 8:
            self.bits.append(0)
        return self

    def octets(self, data: bytes) -> Bits:
        self.align()
        for byte in data:
            self.field(byte, 8)
        return self

    def integer(self, value: int, lb: int, ub: int) -> Bits:
        """A constrained whole number (10.5.7): a bit-field up to a range of
        255, one aligned octet for 256, two aligned octets up to 64K."""
        rng, offset = ub - lb + 1, value - lb
        assert 0 <= offset < rng, (value, lb, ub)
        if rng <= 255:
            return self.field(offset, (rng - 1).bit_length())
        if rng == 256:
            return self.align().field(offset, 8)
        assert rng <= 65536
        return self.align().field(offset, 16)

    def length(self, n: int) -> Bits:
        """An unconstrained length determinant (10.9.3.6-7): aligned, one
        octet below 128, two (10xxxxxx) below 16K."""
        self.align()
        if n < 128:
            return self.field(n, 8)
        assert n < 16384
        return self.field(0x8000 | n, 16)

    def small(self, n: int) -> Bits:
        """A normally small non-negative whole number (10.6), n < 64."""
        assert n < 64
        return self.bit(0).field(n, 6)

    def choice(self, index: int, roots: int, extensible: bool = True) -> Bits:
        """A root alternative of a CHOICE with ``roots`` root alternatives."""
        if extensible:
            self.bit(0)
        if roots > 1:
            self.field(index, (roots - 1).bit_length())
        return self

    def ext_choice(self, index: int, value: bytes) -> Bits:
        """An extension alternative: its index, then the value as an open type."""
        return self.bit(1).small(index).open(value)

    def open(self, encoding: bytes) -> Bits:
        """An open type: a length determinant and a complete encoding."""
        return self.length(len(encoding)).octets(encoding)

    def octet_string(self, data: bytes) -> Bits:
        """An unconstrained OCTET STRING."""
        return self.length(len(data)).octets(data)

    def oid(self, contents: bytes) -> Bits:
        return self.length(len(contents)).octets(contents)

    def extensions(self, count: int, present: dict[int, bytes]) -> Bits:
        """A SEQUENCE's extension additions (19.7-19.9): the bit-map of all
        ``count`` additions, then each present one as an open type."""
        self.small(count - 1)
        for i in range(count):
            self.bit(i in present)
        for i in sorted(present):
            self.open(present[i])
        return self

    def bytes(self) -> bytes:
        """The complete encoding (at least one octet, X.691 10.1.3)."""
        self.align()
        if not self.bits:
            return b"\x00"
        return bytes(
            int("".join(map(str, self.bits[i : i + 8])), 2) for i in range(0, len(self.bits), 8)
        )


def _encode(build: Callable[[Bits], object]) -> bytes:
    b = Bits()
    build(b)
    return b.bytes()


def _boolean(value: bool) -> bytes:
    return _encode(lambda b: b.bit(value))


# ---------------------------------------------------------------------- H.245


def h245_address(addr: str, port: int) -> Callable[[Bits], None]:
    """H.245 TransportAddress (2 root alternatives) → unicastAddress
    UnicastAddress (5 roots) → iPAddress {network, tsapIdentifier, ...}."""

    def build(b: Bits) -> None:
        b.choice(0, 2).choice(0, 5)
        b.bit(0)  # iPAddress: no extensions
        b.octets(ipaddress.IPv4Address(addr).packed).integer(port, 0, 65535)

    return build


def _h2250_parameters(media: tuple[str, int] | None, control: tuple[str, int] | None) -> bytes:
    """H2250LogicalChannelParameters for audio (session 1): 10 root
    optionals (nonStandard, associatedSessionID, mediaChannel,
    mediaGuaranteedDelivery, mediaControlChannel, …)."""

    def build(b: Bits) -> None:
        b.bit(0)  # no extensions
        for i in range(10):
            b.bit((i == 2 and media is not None) or (i == 4 and control is not None))
        b.integer(1, 0, 255)  # sessionID
        if media:
            h245_address(*media)(b)
        if control:
            h245_address(*control)(b)

    return _encode(build)


# AudioCapability's root alternatives (14): nonStandard, g711Alaw64k,
# g711Alaw56k, g711Ulaw64k, … The value is the frames per packet.
G711_ALAW, G711_ULAW = 1, 3


def _audio(b: Bits, codec: int) -> None:
    b.choice(3, 6)  # DataType (6 roots): audioData
    b.choice(codec, 14).integer(20, 1, 256)


def open_logical_channel(number: int, codec: int, forward_media: tuple[str, int] | None = None,
                         control: tuple[str, int] | None = None,
                         reverse_media: tuple[str, int] | None = None,
                         message: bool = False) -> bytes:  # fmt: skip
    """An OpenLogicalChannel (as fast start carries it; with ``message`` a
    MultimediaSystemControlMessage request openLogicalChannel): a forward
    audio channel with its media (RTP) and media control (RTCP) addresses,
    and with ``reverse_media`` a reverse channel (fast start's proposal to
    receive there)."""

    def build(b: Bits) -> None:
        if message:
            b.choice(0, 4).choice(3, 11)  # request (4 roots) → openLogicalChannel (11 roots)
        b.bit(0).bit(reverse_media is not None)  # OpenLogicalChannel: extensions, reverse
        b.integer(number, 1, 65535)
        b.bit(0).bit(0)  # forwardLogicalChannelParameters: extensions, portNumber
        _audio(b, codec)
        # multiplexParameters (3 roots): h2250LogicalChannelParameters is extension 0
        b.ext_choice(0, _h2250_parameters(forward_media, control))
        if reverse_media is not None:
            b.bit(0).bit(1)  # reverseLogicalChannelParameters: extensions, multiplexParameters
            _audio(b, codec)
            b.ext_choice(0, _h2250_parameters(reverse_media, control))

    return _encode(build)


def open_logical_channel_ack(number: int, media: tuple[str, int],
                             control: tuple[str, int]) -> bytes:  # fmt: skip
    """response openLogicalChannelAck: where to send the channel's RTP
    (forwardMultiplexAckParameters' mediaChannel) and RTCP."""

    def ack_parameters(b: Bits) -> None:
        b.choice(0, 1)  # forwardMultiplexAckParameters (1 root): h2250LogicalChannelAckParameters
        b.bit(0)  # no extensions; 5 optionals: nonStandard, sessionID, mediaChannel, …
        b.bit(0).bit(1).bit(1).bit(1).bit(0)
        b.integer(1, 1, 255)
        h245_address(*media)(b)
        h245_address(*control)(b)

    def build(b: Bits) -> None:
        b.choice(1, 4).choice(5, 19)  # response (4 roots) → openLogicalChannelAck (19 roots)
        b.bit(1).bit(0)  # extensions present; no reverseLogicalChannelParameters
        b.integer(number, 1, 65535)
        # additions: separateStack, forwardMultiplexAckParameters, encryptionSync,
        # genericInformation
        b.extensions(4, {1: _encode(ack_parameters)})

    return _encode(build)


def user_input_signal(digit: str, duration_ms: int) -> bytes:
    """indication userInput: a DTMF signal (UserInputIndication's extension
    alternative 1, ``signal {signalType, duration}``)."""

    def signal(b: Bits) -> None:
        b.bit(0).bit(1).bit(0)  # extensions; duration present, rtp absent
        # signalType IA5String(SIZE (1)) FROM ("0123456789#*ABCD!"): 17 characters,
        # 8 bits each in aligned PER (5 rounded up to a power of 2); the
        # characters' own codes fit, so no index table.
        b.field(ord(digit), 8)
        b.integer(duration_ms, 1, 65535)

    def build(b: Bits) -> None:
        b.choice(3, 4).choice(13, 14)  # indication (4 roots) → userInput (14 roots)
        b.ext_choice(1, _encode(signal))

    return _encode(build)


def end_session() -> bytes:
    """command endSessionCommand disconnect."""

    def build(b: Bits) -> None:
        b.choice(2, 4).choice(5, 7)  # command (4 roots) → endSessionCommand (7 roots)
        b.choice(1, 3)  # EndSessionCommand (3 roots): disconnect

    return _encode(build)


# ---------------------------------------------------------------------- H.225.0


def _h225_address(addr: str, port: int) -> Callable[[Bits], None]:
    """H.225 TransportAddress (7 roots) → ipAddress {ip, port} (no extensions)."""

    def build(b: Bits) -> None:
        b.choice(0, 7).octets(ipaddress.IPv4Address(addr).packed).integer(port, 0, 65535)

    return build


_DIGITS = "#*,0123456789"  # dialledDigits' alphabet in code order


def _alias(b: Bits, alias: str) -> None:
    """AliasAddress (2 roots): dialledDigits for digits, else h323-ID."""
    if alias and all(c in _DIGITS for c in alias):
        b.choice(0, 2)
        # IA5String(SIZE (1..128)): 7-bit length, then 4 bits per character
        # (13 characters → 4 bits; their codes don't fit, so the index), aligned
        # since 128 * 4 > 16 bits.
        b.integer(len(alias), 1, 128).align()
        for c in alias:
            b.field(_DIGITS.index(c), 4)
    else:
        b.choice(1, 2)
        text = alias.encode("utf-16-be")
        b.integer(len(alias), 1, 256).octets(text)  # BMPString(SIZE (1..256))


def _aliases(b: Bits, aliases: Sequence[str]) -> None:
    b.length(len(aliases))
    for alias in aliases:
        _alias(b, alias)


def _endpoint(b: Bits) -> None:
    """EndpointType of a terminal: 6 root optionals (…, terminal), mc and
    undefinedNode false."""
    b.bit(0).field(0b000001, 6)
    b.bit(0).bit(0)  # TerminalInfo: extensions, nonStandardData
    b.bit(0).bit(0)


def _call_identifier(guid: bytes) -> bytes:
    return _encode(lambda b: b.bit(0).octets(guid))


def _fast_start(items: Sequence[bytes]) -> bytes:
    def build(b: Bits) -> None:
        b.length(len(items))
        for item in items:
            b.octet_string(item)

    return _encode(build)


Writer = Callable[[Bits], object]


def setup(guid: bytes, source: Sequence[str], destination: Sequence[str],
          fast_start: Sequence[bytes] = ()) -> Writer:  # fmt: skip
    """Setup-UUIE: 7 root optionals (h245Address, sourceAddress,
    destinationAddress, destCallSignalAddress, destExtraCallInfo,
    destExtraCRV, callServices), 28 extension additions."""

    def build(b: Bits) -> None:
        b.bit(1)
        b.bit(0).bit(bool(source)).bit(bool(destination)).field(0, 4)
        b.oid(H225_PROTOCOL)
        if source:
            _aliases(b, source)
        _endpoint(b)
        if destination:
            _aliases(b, destination)
        b.bit(0)  # activeMC
        b.octets(guid)  # conferenceID
        b.choice(0, 3)  # conferenceGoal: create
        b.choice(0, 4)  # callType: pointToPoint
        additions = {2: _call_identifier(guid), 7: _boolean(False), 8: _boolean(False),
                     10: _boolean(False), 11: _boolean(False)}  # fmt: skip
        if fast_start:
            additions[6] = _fast_start(fast_start)
        b.extensions(28, additions)

    return build


def _answer_uuie(guid: bytes, additions_count: int, fast_index: int,
                 fast_start: Sequence[bytes], h245: tuple[str, int] | None,
                 conference: bool) -> Writer:  # fmt: skip
    """CallProceeding-, Alerting- and Connect-UUIE: protocolIdentifier,
    destinationInfo, h245Address OPTIONAL (Connect: before destinationInfo,
    and the conferenceID after it); extension additions callIdentifier (0),
    …, fastStart, multipleCalls and maintainConnection after it."""

    def build(b: Bits) -> None:
        b.bit(1).bit(h245 is not None)
        b.oid(H225_PROTOCOL)
        if conference and h245:
            _h225_address(*h245)(b)
        _endpoint(b)
        if not conference and h245:
            _h225_address(*h245)(b)
        if conference:
            b.octets(guid)
        additions = {0: _call_identifier(guid), fast_index + 1: _boolean(False),
                     fast_index + 2: _boolean(False)}  # fmt: skip
        if fast_start:
            additions[fast_index] = _fast_start(fast_start)
        b.extensions(additions_count, additions)

    return build


def call_proceeding(guid: bytes) -> Writer:
    return _answer_uuie(guid, 9, 4, (), None, conference=False)


def alerting(guid: bytes, fast_start: Sequence[bytes] = ()) -> Writer:
    return _answer_uuie(guid, 15, 4, fast_start, None, conference=False)


def connect(guid: bytes, fast_start: Sequence[bytes] = (),
            h245: tuple[str, int] | None = None) -> Writer:  # fmt: skip
    return _answer_uuie(guid, 16, 4, fast_start, h245, conference=True)


# ReleaseCompleteReason's root alternatives (12).
DESTINATION_REJECTION, IN_CONF, UNDEFINED_REASON = 3, 10, 11


def release_complete(guid: bytes, reason: int | None = None) -> Writer:
    """ReleaseComplete-UUIE: reason OPTIONAL, 11 extension additions."""

    def build(b: Bits) -> None:
        b.bit(1).bit(reason is not None)
        b.oid(H225_PROTOCOL)
        if reason is not None:
            b.choice(reason, 12)
        b.extensions(11, {0: _call_identifier(guid)})

    return build


# H323-UU-PDU's h323-message-body root alternatives (7).
SETUP, CALL_PROCEEDING, CONNECT, ALERTING, INFORMATION, RELEASE_COMPLETE, FACILITY = range(7)
EMPTY = -1  # (the extension alternative "empty")


def user_information(body_kind: int, body: Writer | None, tunnelling: bool,
                     h245: Sequence[bytes] = ()) -> bytes:  # fmt: skip
    """H323-UserInformation {h323-uu-pdu}: the message body, then the
    H323-UU-PDU's extension additions h245Tunnelling (1) and h245Control (2)
    (9 additions). ``body`` writes the UUIE; EMPTY (a Facility without
    one) takes none."""

    def build(b: Bits) -> None:
        b.bit(0).bit(0)  # H323-UserInformation: extensions, user-data
        b.bit(1).bit(0)  # H323-UU-PDU: extensions, nonStandardData
        if body_kind == EMPTY:
            b.ext_choice(1, b"\x00")  # (NULL's complete encoding is one octet)
        else:
            b.choice(body_kind, 7)
            assert body is not None
            body(b)
        additions = {1: _boolean(tunnelling)}
        if h245:
            additions[2] = _fast_start(h245)  # (SEQUENCE OF OCTET STRING, like fastStart)
        b.extensions(9, additions)

    return _encode(build)


# ---------------------------------------------------------------------- Q.931


# Q.931 message types.
Q931_TYPES = {
    SETUP: 0x05,
    CALL_PROCEEDING: 0x02,
    ALERTING: 0x01,
    CONNECT: 0x07,
    RELEASE_COMPLETE: 0x5A,
    FACILITY: 0x62,
    EMPTY: 0x62,
}


def _number_ie(ie: int, digits: str) -> bytes:
    # (octet 3: extension, type of number unknown, numbering plan ISDN/E.164)
    return bytes([ie, len(digits) + 1, 0x81]) + digits.encode()


def q931(call_ref: int, from_destination: bool, body_kind: int, uuie: bytes,
         calling: str = "", called: str = "", cause: int | None = None,
         display: str = "") -> bytes:  # fmt: skip
    """A TPKT-framed Q.931 message holding ``uuie`` (an H323-UserInformation
    encoding) in its User-user IE; the call reference's flag is set on
    messages from the destination side."""
    ref = call_ref | (0x8000 if from_destination else 0)
    msg = bytes([0x08, 0x02]) + struct.pack(">H", ref) + bytes([Q931_TYPES[body_kind]])
    if body_kind == SETUP:
        msg += bytes([0x04, 0x03, 0x80, 0x90, 0xA2])  # bearer capability: speech, 64k, µ-law
    if cause is not None:
        msg += bytes([0x08, 0x02, 0x80, 0x80 | cause])
    if display:
        msg += bytes([0x28, len(display)]) + display.encode()
    if calling:
        msg += _number_ie(0x6C, calling)
    if called:
        msg += _number_ie(0x70, called)
    # User-user: a two-octet length, protocol discriminator 5 (X.208/X.209).
    msg += bytes([0x7E]) + struct.pack(">H", len(uuie) + 1) + bytes([0x05]) + uuie
    return tpkt(msg)


def tpkt(payload: bytes) -> bytes:
    return struct.pack(">BBH", 3, 0, len(payload) + 4) + payload
