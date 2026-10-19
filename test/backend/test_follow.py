"""Follow Stream: sub-stream defaults, and the hand-written crypto behind the
QUIC fixture (checked against published test vectors, so a fixture that
tshark can't decrypt points at the connection, not at AES)."""

from __future__ import annotations

import sys
from pathlib import Path

from pcap_backend.service.streams import _default_substream

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
sys.path.insert(0, str(FIXTURES))
import quic  # noqa: E402 - the fixture generator's QUIC module


def test_aes128_fips197_vector() -> None:
    aes = quic.Aes128(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    block = aes.encrypt(bytes.fromhex("00112233445566778899aabbccddeeff"))
    assert block.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"


def test_aes128_gcm_nist_vectors() -> None:
    # The GCM specification's test cases 2 and 4.
    sealed = quic.aes128_gcm_seal(bytes(16), bytes(12), bytes(16), b"")
    assert sealed.hex() == "0388dace60b6a392f328c2b971b2fe78" + "ab6e47d42cec13bdf53a67b21257bddf"
    sealed = quic.aes128_gcm_seal(
        bytes.fromhex("feffe9928665731c6d6a8f9467308308"),
        bytes.fromhex("cafebabefacedbaddecaf888"),
        bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
        ),
        bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
    )
    assert sealed.hex() == (
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
        "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
        "5bc94fbc3221a5db94fae95ae7121a47"
    )


def test_quic_initial_keys_rfc9001_vector() -> None:
    # RFC 9001 appendix A.1: the client Initial keys for DCID 8394c8f03e515708.
    salt = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
    initial = quic._hkdf_extract(salt, bytes.fromhex("8394c8f03e515708"))
    client = quic._expand_label(initial, "client in", 32)
    assert quic._expand_label(client, "quic key", 16).hex() == "1f369613dd76d5467730efcbe3b1a22d"
    assert quic._expand_label(client, "quic iv", 12).hex() == "fa044b2f42a3fd3b46fb255c"
    assert quic._expand_label(client, "quic hp", 16).hex() == "9f50449e04a0e810283a1e9933adedd2"


def test_default_substream() -> None:
    by_frame = [(8, [0, 1, 3]), (10, [1]), (12, [3]), (13, [0])]
    ids = [0, 1, 3]
    assert _default_substream("http2", by_frame, ids, 12) == 3
    assert _default_substream("http2", by_frame, ids, 8) == 1, "not the connection's stream 0"
    assert _default_substream("http2", by_frame, ids, 13) == 1, "only stream 0: the lowest other"
    assert _default_substream("http2", by_frame, ids, None) == 1
    assert _default_substream("http2", [(4, [0])], [0], 4) == 0, "nothing else"
    assert _default_substream("quic", [(5, [0]), (6, [4])], [0, 4], None) == 0
    assert _default_substream("quic", [(5, [0]), (6, [4])], [0, 4], 6) == 4
    assert _default_substream("quic", [], [], 6) == 0
