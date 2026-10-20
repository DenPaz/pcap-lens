"""GeoIP: MaxMind databases (``.mmdb``) read with the standard library.

tshark resolves ``ip.geoip.*`` itself (given ``maxmind_db_paths``, see
decryption.py), but its Endpoints report has no location columns, so the
Endpoints statistics look the addresses up here: a reader for the MaxMind DB
format (https://maxmind.github.io/MaxMind-DB/: a binary search tree over the
address bits, then a data section of typed values, then the metadata map
after a marker), memory-mapped so a 70 MB City database costs nothing until
read. ``GeoDatabases`` merges every database of the configured folders (and
tshark's usual ones): country and city from a City or Country database, the
AS from an ASN database.
"""

from __future__ import annotations

import contextlib
import ipaddress
import mmap
import struct
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

_MARKER = b"\xab\xcd\xefMaxMind.com"
_MAX_DATABASES = 16

# Where tshark (Wireshark's maxmind_db_paths defaults) looks without settings.
if sys.platform == "win32":
    DEFAULT_FOLDERS: tuple[str, ...] = ()
elif sys.platform == "darwin":
    DEFAULT_FOLDERS = (
        "/usr/local/share/GeoIP",
        "/usr/local/var/GeoIP",
        "/opt/homebrew/share/GeoIP",
        "/opt/homebrew/var/GeoIP",
    )
else:
    DEFAULT_FOLDERS = ("/usr/share/GeoIP", "/var/lib/GeoIP", "/usr/local/share/GeoIP")


class MmdbError(ValueError):
    """Not a MaxMind DB, or a damaged one."""


class MmdbReader:
    """One ``.mmdb`` file: ``lookup(address)`` gives its record (a dict) or None."""

    def __init__(self, path: Path) -> None:
        self.path = path
        with path.open("rb") as fh:
            try:
                self._buf: mmap.mmap | bytes = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
            except ValueError:  # (an empty file can't be mapped)
                self._buf = b""
        start = self._buf.rfind(_MARKER, max(0, len(self._buf) - 128 * 1024))
        if start < 0:
            self.close()
            raise MmdbError(f"{path.name} is not a MaxMind database")
        # (Pointers in the metadata count from the metadata's start.)
        self._data_start = start + len(_MARKER)
        meta, _ = self._decode(self._data_start)
        if not isinstance(meta, dict):
            self.close()
            raise MmdbError(f"{path.name}: unreadable metadata")
        self.metadata: dict[str, Any] = meta
        self.node_count = int(meta.get("node_count", 0))
        self.record_size = int(meta.get("record_size", 0))
        self.ip_version = int(meta.get("ip_version", 6))
        if self.record_size not in (24, 28, 32) or self.node_count <= 0:
            self.close()
            raise MmdbError(f"{path.name}: unsupported record size {self.record_size}")
        self._node_bytes = self.record_size // 4
        self._data_start = self.node_count * self._node_bytes + 16
        self._ipv4_start: int | None = None

    @property
    def database_type(self) -> str:
        return str(self.metadata.get("database_type", ""))

    def close(self) -> None:
        if isinstance(self._buf, mmap.mmap):
            self._buf.close()

    def lookup(self, address: str) -> dict[str, Any] | None:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return None
        if ip.version == 6 and self.ip_version == 4:
            return None
        bits = int(ip)
        width = 32 if ip.version == 4 else 128
        node = self._ipv4_node() if ip.version == 4 and self.ip_version == 6 else 0
        for i in range(width - 1, -1, -1):
            if node >= self.node_count:
                break
            node = self._record(node, (bits >> i) & 1)
        if node <= self.node_count:  # (== node_count: no data for this address)
            return None
        value, _ = self._decode(self._data_start + node - self.node_count - 16)
        return value if isinstance(value, dict) else None

    def _ipv4_node(self) -> int:
        """IPv4 addresses sit under ::/96 of an IPv6 tree."""
        if self._ipv4_start is None:
            node = 0
            for _ in range(96):
                if node >= self.node_count:
                    break
                node = self._record(node, 0)
            self._ipv4_start = node
        return self._ipv4_start

    def _record(self, node: int, bit: int) -> int:
        b = self._buf[node * self._node_bytes : (node + 1) * self._node_bytes]
        if len(b) < self._node_bytes:
            raise MmdbError(f"{self.path.name}: truncated search tree")
        if self.record_size == 24:
            return int.from_bytes(b[3:6] if bit else b[0:3], "big")
        if self.record_size == 28:
            if bit:
                return ((b[3] & 0x0F) << 24) | int.from_bytes(b[4:7], "big")
            return ((b[3] & 0xF0) << 20) | int.from_bytes(b[0:3], "big")
        return int.from_bytes(b[4:8] if bit else b[0:4], "big")

    def _decode(self, offset: int, depth: int = 0) -> tuple[Any, int]:
        """The value at ``offset`` and the offset after it."""
        if depth > 32:
            raise MmdbError(f"{self.path.name}: data nested too deep")
        buf = self._buf
        ctrl = buf[offset]
        offset += 1
        kind = ctrl >> 5
        if kind == 1:  # pointer
            ss, vvv = (ctrl >> 3) & 3, ctrl & 7
            raw = buf[offset : offset + ss + 1]
            offset += ss + 1
            n = int.from_bytes(raw, "big")
            target = (
                (vvv << 8 | n)
                if ss == 0
                else (vvv << 16 | n) + 2048
                if ss == 1
                else (vvv << 24 | n) + 526336
                if ss == 2
                else n
            )
            value, _ = self._decode(self._data_start + target, depth + 1)
            return value, offset
        if kind == 0:  # extended type
            kind = 7 + buf[offset]
            offset += 1
        size = ctrl & 0x1F
        if size >= 29:
            extra = size - 28
            n = int.from_bytes(buf[offset : offset + extra], "big")
            offset += extra
            size = (29, 285, 65821)[extra - 1] + n
        if kind == 2:  # UTF-8 string
            return bytes(buf[offset : offset + size]).decode("utf-8", "replace"), offset + size
        if kind == 3:  # double
            return struct.unpack(">d", buf[offset : offset + 8])[0], offset + 8
        if kind == 4:  # bytes
            return bytes(buf[offset : offset + size]), offset + size
        if kind in (5, 6, 9, 10):  # unsigned integers
            return int.from_bytes(buf[offset : offset + size], "big"), offset + size
        if kind == 7:  # map
            out: dict[str, Any] = {}
            for _ in range(size):
                key, offset = self._decode(offset, depth + 1)
                out[str(key)], offset = self._decode(offset, depth + 1)
            return out, offset
        if kind == 8:  # int32
            return int.from_bytes(
                buf[offset : offset + size], "big", signed=size == 4
            ), offset + size
        if kind == 11:  # array
            items: list[Any] = []
            for _ in range(size):
                item, offset = self._decode(offset, depth + 1)
                items.append(item)
            return items, offset
        if kind == 14:  # boolean (the size is the value)
            return bool(size), offset
        if kind == 15:  # float
            return struct.unpack(">f", buf[offset : offset + 4])[0], offset + 4
        raise MmdbError(f"{self.path.name}: unknown data type {kind}")


def _name(record: dict[str, Any], key: str) -> str:
    names = record.get(key, {}).get("names", {}) if isinstance(record.get(key), dict) else {}
    return str(names.get("en", "")) if isinstance(names, dict) else ""


class GeoDatabases:
    """Every readable ``.mmdb`` in some folders, merged per address."""

    def __init__(self, folders: Iterable[str]) -> None:
        self.readers: list[MmdbReader] = []
        self.errors: list[str] = []
        seen: set[Path] = set()
        for folder in folders:
            directory = Path(folder)
            if not directory.is_dir():
                continue
            for path in sorted(directory.glob("*.mmdb")):
                if path.resolve() in seen or len(self.readers) >= _MAX_DATABASES:
                    continue
                seen.add(path.resolve())
                try:
                    self.readers.append(MmdbReader(path))
                except (OSError, MmdbError, IndexError, struct.error) as exc:
                    self.errors.append(f"{path.name}: {exc}")

    def __bool__(self) -> bool:
        return bool(self.readers)

    def close(self) -> None:
        for reader in self.readers:
            reader.close()

    def lookup(self, address: str) -> dict[str, Any]:
        """``{country, countryCode, city, lat, lon, asn, org}`` (what is known)."""
        out: dict[str, Any] = {}
        for reader in self.readers:
            with contextlib.suppress(MmdbError, IndexError, struct.error):
                record = reader.lookup(address)
                if not record:
                    continue
                country = record.get("country")
                if isinstance(country, dict):
                    out.setdefault("countryCode", str(country.get("iso_code", "")))
                    out.setdefault("country", _name(record, "country"))
                city = _name(record, "city")
                if city:
                    out.setdefault("city", city)
                location = record.get("location")
                if isinstance(location, dict) and "latitude" in location:
                    out.setdefault("lat", float(location["latitude"]))
                    out.setdefault("lon", float(location.get("longitude", 0.0)))
                if "autonomous_system_number" in record:
                    out.setdefault("asn", int(record["autonomous_system_number"]))
                    out.setdefault("org", str(record.get("autonomous_system_organization", "")))
        return {k: v for k, v in out.items() if v not in ("", None)}


def geo_folders(configured: Sequence[str]) -> list[str]:
    """The configured folders, then tshark's usual ones."""
    return list(dict.fromkeys([*configured, *DEFAULT_FOLDERS]))
