"""Decryption keys and GeoIP databases as tshark ``-o`` options.

Wireshark keeps most secrets in UAT tables (``80211_keys``, ``rsa_keys``,
``esp_sa``, ``maxmind_db_paths``); ``-o uat:<table>:<record>`` adds one record
per option, on top of the user's own table files. The rest are preferences
naming a file (``ssh.keylog_file``, ``wg.keylog_file``, ``kerberos.file``).

A key is a dict with a ``type`` (``KEY_TYPES``) and that type's fields; every
value is checked here (they come from the host's secret storage, but end up
on tshark's command line). ``options`` returns the ``-o`` items and the files
the keys and databases name, which the saved-index key fingerprints. A bad
value raises ValueError naming the key (``DissectionOptions`` makes it a
ConfigError).
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path
from urllib.parse import quote

KEY_TYPES = ("wep", "wpa-pwd", "wpa-psk", "rsa", "ssh", "wireguard", "esp", "kerberos")

# The values tshark's esp_sa table accepts (its value strings), checked against
# tshark 4.2 (an unknown name is "invalid value" and tshark won't start).
ESP_ENCRYPTION = (
    "NULL",
    "TripleDES-CBC [RFC2451]",
    "AES-CBC [RFC3602]",
    "AES-CTR [RFC3686]",
    "DES-CBC [RFC2405]",
    "CAST5-CBC [RFC2144]",
    "BLOWFISH-CBC [RFC2451]",
    "TWOFISH-CBC",
    "AES-GCM with 8 octet ICV [RFC4106]",
    "AES-GCM with 12 octet ICV [RFC4106]",
    "AES-GCM with 16 octet ICV [RFC4106]",
)
ESP_AUTHENTICATION = (
    "NULL",
    "HMAC-SHA-1-96 [RFC2404]",
    "HMAC-SHA-256-96 [draft-ietf-ipsec-ciph-sha-256-00]",
    "HMAC-SHA-256-128 [RFC4868]",
    "HMAC-SHA-384-192 [RFC4868]",
    "HMAC-SHA-512-256 [RFC4868]",
    "HMAC-MD5-96 [RFC2403]",
    "MAC-RIPEMD-160-96 [RFC2857]",
    "ANY 64 bit authentication [no checking]",
    "ANY 96 bit authentication [no checking]",
    "ANY 128 bit authentication [no checking]",
    "ANY 192 bit authentication [no checking]",
    "ANY 256 bit authentication [no checking]",
)

_HEX_RE = re.compile(r"^(0x)?[0-9a-fA-F]*$")
_SPI_RE = re.compile(r"^(\*|0x[0-9a-fA-F]{1,8}|\d{1,10})$")
# An address, a prefix, or "*" (tshark also takes wildcards like 10.0.0.*).
_SA_ADDRESS_RE = re.compile(r"^[0-9a-fA-F:.*/]{1,64}$")
# Key types that name a preference, which holds one file only.
_FILE_PREFS = {"ssh": "ssh.keylog_file", "wireguard": "wg.keylog_file", "kerberos": "kerberos.file"}


def uat_escape(text: str) -> str:
    """A UAT field's text: quotes, backslashes and control characters as \\xHH."""
    return "".join(
        f"\\x{ord(c):02x}" if c in '"\\' or ord(c) < 0x20 or ord(c) == 0x7F else c for c in text
    )


def uat_record(*fields: str) -> str:
    return ",".join(f'"{uat_escape(f)}"' for f in fields)


def options(keys: Sequence[object], geoip: Sequence[str] = ()) -> tuple[
    tuple[tuple[str, str], ...], tuple[str, ...]
]:  # fmt: skip
    """The ``-o`` items for ``keys`` and the GeoIP database folders, and the
    files they name. Raises ValueError naming the first bad key."""
    items: list[tuple[str, str]] = []
    files: list[str] = []
    seen_prefs: dict[str, int] = {}
    for i, raw in enumerate(keys):
        where = f"decryption key {i + 1}"
        if not isinstance(raw, dict):
            raise ValueError(f"{where} must be an object")  # noqa: TRY004 - a bad setting, reported as one
        typ = raw.get("type")
        if typ not in KEY_TYPES:
            raise ValueError(f"{where}: type must be one of {', '.join(KEY_TYPES)}")
        if typ in _FILE_PREFS:
            path = _file(raw, "file", where)
            pref = _FILE_PREFS[typ]
            if pref in seen_prefs:
                raise ValueError(
                    f"{where}: tshark takes one {typ} file only (key {seen_prefs[pref]} is one)"
                )
            seen_prefs[pref] = i + 1
            if typ == "kerberos":
                items.append(("kerberos.decrypt", "TRUE"))
            items.append((pref, path))
            files.append(path)
        elif typ == "rsa":
            path = _file(raw, "file", where)
            items.append(("uat:rsa_keys", uat_record(path, _text(raw, "password", where, 256))))
            files.append(path)
        elif typ == "esp":
            items.append(("esp.enable_encryption_decode", "TRUE"))
            items.append(("uat:esp_sa", _esp_record(raw, where)))
        else:
            items.append(("wlan.enable_decryption", "TRUE"))
            items.append(("uat:80211_keys", uat_record(typ, _wlan_key(typ, raw, where))))
    for folder in geoip:
        if not isinstance(folder, str) or not folder or not Path(folder).is_absolute():
            raise ValueError(f"GeoIP database folder must be an absolute path: {folder!r}")
        if "\n" in folder or "\r" in folder:
            raise ValueError("a GeoIP database folder must be a single line")
        items.append(("uat:maxmind_db_paths", uat_record(folder)))
        files.append(folder)
    # (Each switch once, before the records: duplicates are harmless but noisy.)
    switches = list(dict.fromkeys(item for item in items if not item[0].startswith("uat:")))
    return tuple(switches + [item for item in items if item[0].startswith("uat:")]), tuple(files)


def _text(raw: dict[str, object], key: str, where: str, limit: int) -> str:
    value = raw.get(key, "")
    if not isinstance(value, str) or len(value) > limit or "\n" in value or "\r" in value:
        raise ValueError(f"{where}: {key} must be one line of at most {limit} characters")
    return value


def _file(raw: dict[str, object], key: str, where: str) -> str:
    path = _text(raw, key, where, 4096)
    if not path or not Path(path).is_absolute():
        raise ValueError(f"{where}: {key} must be an absolute path")
    return path


def _hex(raw: dict[str, object], key: str, where: str, sizes: Sequence[int]) -> str:
    """A hex key without separators (``:``, ``-`` and spaces are dropped) whose
    length in bytes is one of ``sizes`` (empty: any)."""
    text = re.sub(r"[\s:-]", "", _text(raw, key, where, 600))
    digits = text[2:] if text.lower().startswith("0x") else text
    if not _HEX_RE.match(text) or len(digits) % 2 or (sizes and len(digits) // 2 not in sizes):
        need = " or ".join(str(n) for n in sizes) + " bytes" if sizes else "whole bytes"
        raise ValueError(f"{where}: {key} must be hexadecimal digits ({need})")
    return digits.lower()


def _wlan_key(typ: str, raw: dict[str, object], where: str) -> str:
    """The key column of an 80211_keys record."""
    if typ == "wep":
        return _hex(raw, "key", where, (5, 13, 16))
    if typ == "wpa-psk":
        return _hex(raw, "key", where, (32,))
    password = _text(raw, "password", where, 63)
    ssid = _text(raw, "ssid", where, 32)
    if not 8 <= len(password) <= 63 or not password.isascii() or not password.isprintable():
        raise ValueError(f"{where}: a WPA passphrase is 8 to 63 printable ASCII characters")
    if len(ssid.encode()) > 32:
        raise ValueError(f"{where}: an SSID is at most 32 bytes")
    # Wireshark percent-decodes both ("passphrase:SSID", a colon as %3a).
    return quote(password, safe="") + (f":{quote(ssid, safe='')}" if ssid else "")


def _esp_record(raw: dict[str, object], where: str) -> str:
    """An esp_sa record: protocol, source, destination, SPI, encryption and its
    key, authentication and its key."""
    protocol = raw.get("protocol", "IPv4")
    if protocol not in ("IPv4", "IPv6"):
        raise ValueError(f"{where}: protocol must be IPv4 or IPv6")
    src = _text(raw, "src", where, 64) or "*"
    dst = _text(raw, "dst", where, 64) or "*"
    spi = _text(raw, "spi", where, 12) or "*"
    for name, value in (("src", src), ("dst", dst)):
        if not _SA_ADDRESS_RE.match(value):
            raise ValueError(f"{where}: {name} must be an address, a prefix or *")
    if not _SPI_RE.match(spi):
        raise ValueError(f"{where}: spi must be * or a number such as 0x00000100")
    encryption = raw.get("encryption", "NULL")
    authentication = raw.get("authentication", "NULL")
    if encryption not in ESP_ENCRYPTION:
        raise ValueError(f"{where}: unknown encryption {encryption!r}")
    if authentication not in ESP_AUTHENTICATION:
        raise ValueError(f"{where}: unknown authentication {authentication!r}")
    enc_key = _hex(raw, "encryptionKey", where, ())
    auth_key = _hex(raw, "authenticationKey", where, ())
    return uat_record(
        str(protocol),
        src,
        dst,
        spi,
        str(encryption),
        f"0x{enc_key}" if enc_key else "",
        str(authentication),
        f"0x{auth_key}" if auth_key else "",
    )
