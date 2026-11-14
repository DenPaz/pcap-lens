"""x509.py: a certificate's names, validity and DNS names."""

from __future__ import annotations

import base64
import sys
from pathlib import Path

from pcap_backend import x509

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
sys.path.insert(0, str(FIXTURES))
import generate  # noqa: E402 - the fixtures' generator (its test certificate)

# A self-signed CA certificate (openssl, ECDSA P-256): CN=PCAP Lens Test CA,
# O=PCAP Lens; the issuer of generate.SESSIONS_CERT.
CA = base64.b64decode(
    "MIIBtjCCAVugAwIBAgIUN0rB5R1Dt6cy8xv4uPCyfROoGRcwCgYIKoZIzj0EAwIwMDEaMBgGA1UE"
    "AwwRUENBUCBMZW5zIFRlc3QgQ0ExEjAQBgNVBAoMCVBDQVAgTGVuczAeFw0yNjExMTQxNDUxMTNa"
    "Fw0zNjExMTExNDUxMTNaMDAxGjAYBgNVBAMMEVBDQVAgTGVucyBUZXN0IENBMRIwEAYDVQQKDAlQ"
    "Q0FQIExlbnMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARfIcaXH4waM3PYtMxw0AO6AhbwToni"
    "v/j0zwkeqHXmRvo1EAgIyfIVKOinecWPs4KRP556nG8s7ClFYRQLSSvlo1MwUTAdBgNVHQ4EFgQU"
    "XC4eXAm8yIeGfLpx1jbtV683vCwwHwYDVR0jBBgwFoAUXC4eXAm8yIeGfLpx1jbtV683vCwwDwYD"
    "VR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEAu0017nfGCvwSaJAHH+GT4vGmxbW5S3e5"
    "m67WfO+b9W8CIQDOIXyDIlvXA9Evg/7BthxlcFfXENjUsBRTNZ42d0gOyA=="
)


def test_a_leaf_certificate() -> None:
    cert = x509.parse_certificate(generate.SESSIONS_CERT)
    assert cert is not None
    assert cert.subject == {"cn": "api.example.com", "o": "Example API"}
    assert cert.issuer == {"cn": "PCAP Lens Test CA", "o": "PCAP Lens"}
    assert (cert.not_before, cert.not_after) == (1577836800.0, 1609459200.0)  # 2020, 2021
    assert cert.dns_names == ["api.example.com", "www.api.example.com"]
    assert cert.self_signed is False


def test_a_self_signed_certificate() -> None:
    cert = x509.parse_certificate(CA)
    assert cert is not None
    assert cert.self_signed is True and cert.subject == cert.issuer
    assert cert.dns_names == [] and cert.covers("PCAP Lens Test CA"), "its CN, without a SAN"


def test_covers_its_names_and_one_label_wildcards() -> None:
    cert = x509.Certificate({"cn": "ignored.example"}, {}, 0, 1, ["a.example.com", "*.b.example"])
    assert cert.covers("A.EXAMPLE.COM.")
    assert cert.covers("x.b.example")
    assert not cert.covers("b.example")
    assert not cert.covers("y.x.b.example")
    assert not cert.covers("ignored.example"), "the SAN wins over the common name"
    assert x509.Certificate({"cn": "only.example"}, {}, 0, 1).covers("only.example")


def test_anything_but_a_certificate_is_none() -> None:
    der = generate.SESSIONS_CERT
    for cut in (0, 1, 2, 10, 100, len(der) - 1):
        assert x509.parse_certificate(der[:cut]) is None
    assert x509.parse_certificate(b"\x04\x02ab") is None  # an OCTET STRING
    assert x509.parse_certificate(b"\x30\x84\xff\xff\xff\xff") is None  # a length past the end
    # Every byte flipped in turn: never an exception.
    for i in range(len(der)):
        broken = bytearray(der)
        broken[i] ^= 0xFF
        x509.parse_certificate(bytes(broken))


def test_times_two_and_four_digit_years() -> None:
    assert x509._time(0x17, b"491231235959Z") == 2524607999.0  # UTCTime 49: 2049
    assert x509._time(0x17, b"500101000000Z") == -631152000.0  # UTCTime 50: 1950
    assert x509._time(0x18, b"20500101000000Z") == 2524608000.0
