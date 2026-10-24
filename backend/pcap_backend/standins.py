"""Stand-ins for addresses in what the MCP server returns (``--stand-ins``).

A port of the extension's ``src/aiPrivacy.ts``: IPv4, IPv6 and unicast MAC
addresses become tokens (IP_PRIVATE_1, IP_PUBLIC_2, IP6_LOCAL_1,
IP6_PUBLIC_1, MAC_3), the same address always the same token for one
server, and tokens in tool arguments (a display filter naming IP_PRIVATE_1)
get the real values back before tshark sees them. Unspecified, loopback,
multicast and broadcast addresses and MAC group addresses stay: they name no
machine. The regexes match candidates only; each is checked before it is
replaced (an OID or a version number isn't an address).
"""

from __future__ import annotations

import ipaddress
import re
import threading
from typing import Any

KINDS = ("IP_PRIVATE", "IP_PUBLIC", "IP6_LOCAL", "IP6_PUBLIC", "MAC")

NOTE = (
    "Addresses in these results are stand-ins such as IP_PRIVATE_1, IP_PUBLIC_2, IP6_LOCAL_1, "
    "IP6_PUBLIC_1 and MAC_3 (each always stands for the same address; IP_PRIVATE means a "
    "private or link-local address). Use them as written, also inside display filters "
    "(ip.addr == IP_PRIVATE_1): the tools turn them back into the real values."
)

_TOKEN = re.compile(r"\b(" + "|".join(KINDS) + r")_(\d+)\b")
_IPV4 = re.compile(r"(?<![\w.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?!\w|\.\d)")
# Candidates only: ipaddress decides (times like 12:34:56 aren't addresses).
# The dotted form (::ffff:192.168.1.2) first, and never a match that stops
# before ".<digit>": "::ffff:192" alone would leave ".168.1.2" readable.
_IPV6 = re.compile(
    r"(?<![\w:.])(?:(?:[0-9A-Fa-f]{0,4}:){2,6}\d{1,3}(?:\.\d{1,3}){3}"
    r"|(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})(?![\w:]|\.\d)"
)
_MAC = re.compile(r"(?<![\w:-])[0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}(?:\1[0-9A-Fa-f]{2}){4}(?![\w:-])")
# tshark's resolved form: the vendor and the last three bytes ("Apple_12:34:56").
_VENDOR_MAC = re.compile(
    r"(?<![\w:-])[A-Za-z][\w-]*_[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){2}(?![\w:-])"
)


def _ipv4_kind(octets: list[int]) -> str | None:
    a, b = octets[0], octets[1]
    if any(o > 255 for o in octets):
        return None  # not an address
    if a in (0, 127) or a >= 224:
        return None  # unspecified, loopback, multicast, reserved, broadcast
    private = (
        a == 10
        or (a == 172 and 16 <= b <= 31)
        or (a == 192 and b == 168)
        or (a == 100 and 64 <= b <= 127)
        or (a == 169 and b == 254)
    )
    return "IP_PRIVATE" if private else "IP_PUBLIC"


def _ipv6_kind(text: str) -> str | None:
    try:
        address = ipaddress.IPv6Address(text)
    except ValueError:
        return None
    if address.is_unspecified or address.is_loopback or address.is_multicast:
        return None
    return "IP6_LOCAL" if address.is_link_local or address in _ULA else "IP6_PUBLIC"


_ULA = ipaddress.IPv6Network("fc00::/7")


def _ipv4_mapped(text: str) -> ipaddress.IPv4Address | None:
    """The IPv4 address of an IPv4-mapped IPv6 address written dotted."""
    if "." not in text:
        return None
    try:
        return ipaddress.IPv6Address(text).ipv4_mapped
    except ValueError:
        return None


def _mac_kind(text: str) -> str | None:
    # Group addresses (broadcast, multicast) name no machine; all-zero neither.
    if int(text[:2], 16) & 1 or not text.strip("0:-"):
        return None
    return "MAC"


class AddressMasker:
    """Tokens for addresses, and the real values back (thread-safe)."""

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self._tokens: dict[str, str] = {}  # normalized real value → token
        self._reals: dict[str, str] = {}  # token → real value as first seen
        self._counts: dict[str, int] = {}
        self._lock = threading.Lock()

    def _token(self, kind: str, key: str, real: str) -> str:
        with self._lock:
            token = self._tokens.get(key)
            if token is None:
                n = self._counts.get(kind, 0) + 1
                self._counts[kind] = n
                token = f"{kind}_{n}"
                self._tokens[key] = token
                self._reals[token] = real
            return token

    def mask(self, text: str) -> str:
        """The text with stand-ins for its addresses."""
        if not self.enabled or not text:
            return text

        def mac(m: re.Match[str]) -> str:
            real = m.group(0)
            kind = _mac_kind(real)
            return self._token(kind, real.lower().replace("-", ":"), real) if kind else real

        def ipv6(m: re.Match[str]) -> str:
            real = m.group(0)
            mapped = _ipv4_mapped(real)
            if mapped is not None:
                # ::ffff:192.168.1.2 is that IPv4 host: its token after the prefix.
                prefix, v4 = real.rsplit(":", 1)
                v4_kind = _ipv4_kind([int(o) for o in v4.split(".")])
                return f"{prefix}:{self._token(v4_kind, v4, v4)}" if v4_kind else real
            kind = _ipv6_kind(real)
            return self._token(kind, real.lower(), real) if kind else real

        def ipv4(m: re.Match[str]) -> str:
            real = m.group(0)
            kind = _ipv4_kind([int(g) for g in m.groups()])
            return self._token(kind, real, real) if kind else real

        text = _MAC.sub(mac, text)
        text = _VENDOR_MAC.sub(lambda m: self._token("MAC", m.group(0).lower(), m.group(0)), text)
        text = _IPV6.sub(ipv6, text)
        return _IPV4.sub(ipv4, text)

    def restore(self, text: str) -> str:
        """The text with the real values back (unknown tokens stay)."""
        if not self.enabled or not text:
            return text
        with self._lock:
            reals = dict(self._reals)
        return _TOKEN.sub(lambda m: reals.get(m.group(0), m.group(0)), text)

    def restore_deep(self, value: Any) -> Any:
        """Strings inside a value (a tool's arguments) restored."""
        if isinstance(value, str):
            return self.restore(value)
        if isinstance(value, list):
            return [self.restore_deep(v) for v in value]
        if isinstance(value, dict):
            return {k: self.restore_deep(v) for k, v in value.items()}
        return value

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._reals)
