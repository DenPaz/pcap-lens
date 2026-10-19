"""A QUIC v1 connection for the Follow QUIC Stream fixture, encrypted by hand.

QUIC is always encrypted, and the standard library has no AES, so this module
carries a small AES-128 and AES-128-GCM (fixture-sized data only: it is slow
and not constant-time). The connection is what Wireshark needs to decrypt it
with a key log: a client Initial holding a TLS 1.3 ClientHello and a server
Initial holding the ServerHello (both protected with the Initial keys every
QUIC endpoint derives from the client's first Destination Connection ID, RFC
9001 section 5.2), then 1-RTT packets whose keys come from the made-up
``CLIENT_TRAFFIC_SECRET_0`` / ``SERVER_TRAFFIC_SECRET_0`` in ``KEYLOG``. No
handshake keys exist, so the Handshake packets are left out; Wireshark only
needs the client random and the cipher suite to use the 1-RTT secrets.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from collections.abc import Iterator


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def _make_sbox() -> list[int]:
    """AES's S-box: the inverse in GF(2^8), then the affine map."""
    sbox = [0] * 256
    p = q = 1
    while True:
        p ^= _xtime(p)  # p * 3
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09  # q / 3
        rot = 0
        for shift in range(5):
            rot ^= ((q << shift) | (q >> (8 - shift))) & 0xFF
        sbox[p] = rot ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


_SBOX = _make_sbox()


class Aes128:
    """AES-128 block encryption (FIPS-197)."""

    def __init__(self, key: bytes) -> None:
        words = [list(key[i : i + 4]) for i in range(0, 16, 4)]
        rcon = 1
        for i in range(4, 44):
            t = list(words[i - 1])
            if i % 4 == 0:
                t = [_SBOX[b] for b in t[1:] + t[:1]]
                t[0] ^= rcon
                rcon = _xtime(rcon)
            words.append([a ^ b for a, b in zip(words[i - 4], t, strict=True)])
        self._round_keys = [[b for w in words[r * 4 : r * 4 + 4] for b in w] for r in range(11)]

    def encrypt(self, block: bytes) -> bytes:
        s = [b ^ k for b, k in zip(block, self._round_keys[0], strict=True)]
        for r in range(1, 11):
            s = [_SBOX[b] for b in s]
            s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]  # ShiftRows, column-major
            if r != 10:
                mixed: list[int] = []
                for c in range(0, 16, 4):
                    a = s[c : c + 4]
                    t = a[0] ^ a[1] ^ a[2] ^ a[3]
                    mixed += [a[i] ^ t ^ _xtime(a[i] ^ a[(i + 1) % 4]) for i in range(4)]
                s = mixed
            s = [b ^ k for b, k in zip(s, self._round_keys[r], strict=True)]
        return bytes(s)


def _gf_mult(x: int, y: int) -> int:
    """Multiplication in GCM's GF(2^128) (NIST SP 800-38D, algorithm 1)."""
    z = 0
    for i in range(127, -1, -1):
        if (y >> i) & 1:
            z ^= x
        x = (x >> 1) ^ (0xE1 << 120) if x & 1 else x >> 1
    return z


def _blocks(data: bytes) -> Iterator[int]:
    for i in range(0, len(data), 16):
        yield int.from_bytes(data[i : i + 16].ljust(16, b"\0"), "big")


def aes128_gcm_seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """AES-128-GCM with a 12-byte nonce: ciphertext followed by the 16-byte tag."""
    aes = Aes128(key)
    h = int.from_bytes(aes.encrypt(bytes(16)), "big")
    j0 = nonce + b"\0\0\0\1"
    counter = int.from_bytes(j0, "big")
    out = bytearray()
    for i in range(0, len(plaintext), 16):
        counter = (counter & ~0xFFFFFFFF) | ((counter + 1) & 0xFFFFFFFF)
        stream = aes.encrypt(counter.to_bytes(16, "big"))
        out += bytes(a ^ b for a, b in zip(plaintext[i : i + 16], stream, strict=False))
    ghash = 0
    for block in [*_blocks(aad), *_blocks(bytes(out)), (len(aad) * 8) << 64 | len(out) * 8]:
        ghash = _gf_mult(ghash ^ block, h)
    tag = ghash ^ int.from_bytes(aes.encrypt(j0), "big")
    return bytes(out) + tag.to_bytes(16, "big")


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _expand_label(secret: bytes, label: str, length: int) -> bytes:
    """TLS 1.3's HKDF-Expand-Label with an empty context (one block suffices)."""
    full = b"tls13 " + label.encode()
    info = struct.pack(">HB", length, len(full)) + full + b"\0"
    return hmac.new(secret, info + b"\1", hashlib.sha256).digest()[:length]


def _varint(n: int) -> bytes:
    if n < 0x40:
        return bytes([n])
    if n < 0x4000:
        return struct.pack(">H", n | 0x4000)
    return struct.pack(">I", n | 0x80000000)


_PN_LEN = 2


def _protect(header: bytes, pn_offset: int, payload: bytes, secret: bytes, pn: int) -> bytes:
    """Encrypt the payload and apply header protection (RFC 9001 section 5)."""
    key = _expand_label(secret, "quic key", 16)
    iv = _expand_label(secret, "quic iv", 12)
    hp = _expand_label(secret, "quic hp", 16)
    nonce = (int.from_bytes(iv, "big") ^ pn).to_bytes(12, "big")
    sealed = aes128_gcm_seal(key, nonce, payload, header)
    sample = sealed[4 - _PN_LEN : 4 - _PN_LEN + 16]
    mask = Aes128(hp).encrypt(sample)
    out = bytearray(header)
    out[0] ^= mask[0] & (0x0F if out[0] & 0x80 else 0x1F)
    for i in range(_PN_LEN):
        out[pn_offset + i] ^= mask[1 + i]
    return bytes(out) + sealed


def _initial(dcid: bytes, scid: bytes, secret: bytes, pn: int, frames: bytes) -> bytes:
    header = (
        bytes([0xC0 | (_PN_LEN - 1)])
        + struct.pack(">I", 1)
        + bytes([len(dcid)])
        + dcid
        + bytes([len(scid)])
        + scid
        + _varint(0)  # no token
        + struct.pack(">H", 0x4000 | (_PN_LEN + len(frames) + 16))
    )
    return _protect(header + pn.to_bytes(_PN_LEN, "big"), len(header), frames, secret, pn)


def _short(dcid: bytes, secret: bytes, pn: int, frames: bytes) -> bytes:
    header = bytes([0x40 | (_PN_LEN - 1)]) + dcid
    return _protect(header + pn.to_bytes(_PN_LEN, "big"), len(header), frames, secret, pn)


def _crypto(data: bytes) -> bytes:
    return b"\x06" + _varint(0) + _varint(len(data)) + data


def _stream(stream_id: int, data: bytes, fin: bool) -> bytes:
    # STREAM with the OFF and LEN bits (offset 0), FIN when the stream ends.
    kind = 0x08 | 0x04 | 0x02 | (0x01 if fin else 0)
    return bytes([kind]) + _varint(stream_id) + _varint(0) + _varint(len(data)) + data


def _extension(kind: int, data: bytes) -> bytes:
    return struct.pack(">HH", kind, len(data)) + data


def _handshake(kind: int, body: bytes) -> bytes:
    return bytes([kind]) + len(body).to_bytes(3, "big") + body


CLIENT_RANDOM = bytes(range(32))
_SERVER_RANDOM = bytes(range(32, 64))
_TLS_AES_128_GCM_SHA256 = b"\x13\x01"
_X25519_SHARE = struct.pack(">H", 0x001D) + struct.pack(">H", 32) + bytes(32)


def _client_hello() -> bytes:
    extensions = (
        _extension(0x002B, b"\x02\x03\x04")  # supported_versions: TLS 1.3
        + _extension(0x000A, b"\x00\x02\x00\x1d")  # supported_groups: x25519
        + _extension(0x0033, struct.pack(">H", len(_X25519_SHARE)) + _X25519_SHARE)
        + _extension(0x0039, b"")  # quic_transport_parameters
    )
    body = (
        b"\x03\x03"
        + CLIENT_RANDOM
        + b"\x00"  # no legacy session id
        + struct.pack(">H", 2)
        + _TLS_AES_128_GCM_SHA256
        + b"\x01\x00"  # null compression
        + struct.pack(">H", len(extensions))
        + extensions
    )
    return _handshake(1, body)


def _server_hello() -> bytes:
    extensions = _extension(0x002B, b"\x03\x04") + _extension(0x0033, _X25519_SHARE)
    body = (
        b"\x03\x03"
        + _SERVER_RANDOM
        + b"\x00"
        + _TLS_AES_128_GCM_SHA256
        + b"\x00"
        + struct.pack(">H", len(extensions))
        + extensions
    )
    return _handshake(2, body)


_CLIENT_SECRET = hashlib.sha256(b"PCAP Lens QUIC client").digest()
_SERVER_SECRET = hashlib.sha256(b"PCAP Lens QUIC server").digest()

KEYLOG = (
    f"CLIENT_TRAFFIC_SECRET_0 {CLIENT_RANDOM.hex()} {_CLIENT_SECRET.hex()}\n"
    f"SERVER_TRAFFIC_SECRET_0 {CLIENT_RANDOM.hex()} {_SERVER_SECRET.hex()}\n"
).encode()

# Stream 0 is a request and its answer; stream 4 carries data from the client only.
STREAM_DATA = {
    0: (b"GET /hello.txt\r\n", b"Hello over QUIC!\n"),
    4: (b"second stream data\n", b""),
}


def datagrams() -> list[tuple[int, bytes]]:
    """(direction, UDP payload) of the connection: 0 = client → server."""
    odcid = bytes.fromhex("8394c8f03e515708")
    client_cid, server_cid = bytes.fromhex("c1c1c1c1"), bytes.fromhex("5e5e5e5e")
    initial = _hkdf_extract(bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"), odcid)
    client_in = _expand_label(initial, "client in", 32)
    server_in = _expand_label(initial, "server in", 32)
    hello = _crypto(_client_hello()).ljust(1162, b"\0")  # PADDING: client Initials fill 1200 bytes
    request, answer = STREAM_DATA[0]
    second, _ = STREAM_DATA[4]
    ack = b"\x02\x00\x00\x00\x00"  # ACK of packet 0
    return [
        (0, _initial(odcid, client_cid, client_in, 0, hello)),
        (1, _initial(client_cid, server_cid, server_in, 0, ack + _crypto(_server_hello()))),
        (0, _short(server_cid, _CLIENT_SECRET, 1, _stream(0, request, fin=False))),
        (1, _short(client_cid, _SERVER_SECRET, 1, _stream(0, answer, fin=True))),
        (0, _short(server_cid, _CLIENT_SECRET, 2, _stream(4, second, fin=True))),
    ]
