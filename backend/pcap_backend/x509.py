"""The parts of an X.509 certificate TLS Servers shows: subject and issuer
names, validity and the DNS names it is for (stdlib only: a small DER reader).

tshark gives a Certificate message's certificates as raw bytes
(``tls.handshake.certificate``, the server's own first); reading them here
keeps the subject apart from the issuer, which tshark's fields can't (both
are sequences of the same ``x509sat.*`` fields), and costs one fields pass
instead of the PDML of every certificate packet.

Certificates come from the capture: anything malformed is ``None``, never an
exception, and every length is checked against what is left.
"""

from __future__ import annotations

import calendar
import re
from dataclasses import dataclass, field
from typing import Any

# Attribute types (OIDs) of a name that are shown.
_COMMON_NAME = "2.5.4.3"
_ORGANIZATION = "2.5.4.10"
_SUBJECT_ALT_NAME = "2.5.29.17"
# String types a name's values use, and how to read them.
_STRINGS = {
    0x0C: "utf-8",  # UTF8String
    0x13: "latin-1",  # PrintableString
    0x14: "latin-1",  # TeletexString (T61, read as Latin-1)
    0x16: "latin-1",  # IA5String
    0x1A: "latin-1",  # VisibleString
    0x1C: "utf-32-be",  # UniversalString
    0x1E: "utf-16-be",  # BMPString
}


class _MalformedError(ValueError):
    pass


def _read(data: bytes, at: int) -> tuple[int, bytes, int]:
    """One DER element at ``at``: (tag, contents, offset after it)."""
    if at + 2 > len(data):
        raise _MalformedError("truncated")
    tag = data[at]
    if tag & 0x1F == 0x1F:
        raise _MalformedError("high tag numbers aren't used by certificates")
    length = data[at + 1]
    at += 2
    if length & 0x80:
        n = length & 0x7F
        if not 1 <= n <= 4 or at + n > len(data):
            raise _MalformedError("bad length")
        length = int.from_bytes(data[at : at + n], "big")
        at += n
    if at + length > len(data):
        raise _MalformedError("truncated")
    return tag, data[at : at + length], at + length


def _children(contents: bytes) -> list[tuple[int, bytes]]:
    items = []
    at = 0
    while at < len(contents):
        tag, value, at = _read(contents, at)
        items.append((tag, value))
    return items


def _oid(value: bytes) -> str:
    if not value:
        raise _MalformedError("empty OID")
    first = value[0]
    parts = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    n = 0
    for b in value[1:]:
        n = (n << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(n)
            n = 0
    return ".".join(map(str, parts))


def _string(tag: int, value: bytes) -> str:
    return value.decode(_STRINGS.get(tag, "latin-1"), "replace")


def _name(contents: bytes) -> dict[str, str]:
    """A Name's common name and organization (the last of each, as shown)."""
    out: dict[str, str] = {}
    for _set_tag, rdn in _children(contents):
        for _seq_tag, attribute in _children(rdn):
            parts = _children(attribute)
            if len(parts) < 2 or parts[0][0] != 0x06:
                continue
            oid = _oid(parts[0][1])
            if oid in (_COMMON_NAME, _ORGANIZATION):
                out["cn" if oid == _COMMON_NAME else "o"] = _string(*parts[1])
    return out


_TIME = re.compile(r"^(\d{2}|\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$")


def _time(tag: int, value: bytes) -> float:
    m = _TIME.match(value.decode("ascii", "replace"))
    if not m or tag not in (0x17, 0x18):
        raise _MalformedError("bad time")
    year = int(m[1])
    if tag == 0x17:  # UTCTime: two digits, 1950-2049
        year += 2000 if year < 50 else 1900
    return float(
        calendar.timegm((year, int(m[2]), int(m[3]), int(m[4]), int(m[5]), int(m[6] or 0)))
    )


@dataclass
class Certificate:
    subject: dict[str, str]
    issuer: dict[str, str]
    not_before: float
    not_after: float
    dns_names: list[str] = field(default_factory=list)
    self_signed: bool = False

    def to_json(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "notBefore": self.not_before,
            "notAfter": self.not_after,
            "dnsNames": self.dns_names,
            "selfSigned": self.self_signed,
        }

    def covers(self, host: str) -> bool:
        """Whether the certificate is for ``host`` (its DNS names, else its
        common name; a wildcard stands for one label, RFC 6125)."""
        host = host.rstrip(".").lower()
        names = self.dns_names or ([self.subject["cn"]] if self.subject.get("cn") else [])
        for name in names:
            pattern = name.rstrip(".").lower()
            if pattern == host:
                return True
            if pattern.startswith("*.") and "." in host and host.split(".", 1)[1] == pattern[2:]:
                return True
        return False


def parse_certificate(der: bytes) -> Certificate | None:
    """The certificate's names, validity and DNS names, or None when the
    bytes aren't a certificate this reader understands."""
    try:
        tag, cert, _ = _read(der, 0)
        if tag != 0x30:
            return None
        tag, tbs, _ = _read(cert, 0)
        if tag != 0x30:
            return None
        parts = _children(tbs)
        if parts and parts[0][0] == 0xA0:  # [0] version
            parts = parts[1:]
        # serial, signature algorithm, issuer, validity, subject, key, …
        if len(parts) < 6:
            return None
        issuer_raw, validity, subject_raw = parts[2][1], parts[3][1], parts[4][1]
        times = _children(validity)
        if len(times) != 2:
            return None
        result = Certificate(
            subject=_name(subject_raw),
            issuer=_name(issuer_raw),
            not_before=_time(*times[0]),
            not_after=_time(*times[1]),
            self_signed=subject_raw == issuer_raw,
        )
        for tag, value in parts[6:]:
            if tag != 0xA3:  # [3] extensions
                continue
            for _t, extension in _children(_children(value)[0][1]):
                items = _children(extension)
                if not items or items[0][0] != 0x06 or _oid(items[0][1]) != _SUBJECT_ALT_NAME:
                    continue
                _t2, names = items[-1]  # (OCTET STRING holding GeneralNames)
                for name_tag, name in _children(_children(names)[0][1]):
                    if name_tag == 0x82:  # [2] dNSName
                        result.dns_names.append(name.decode("latin-1", "replace"))
    except (_MalformedError, IndexError, ValueError, OverflowError):
        return None
    return result
