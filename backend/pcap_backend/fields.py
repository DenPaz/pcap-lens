"""tshark's field/protocol catalogue (``tshark -G fields``) with fast prefix search.

Used for display-filter autocomplete and the "add column" picker. The
catalogue has ~250k entries, so lookups bisect a sorted, lower-cased key list
instead of scanning.
"""

from __future__ import annotations

from bisect import bisect_left
from dataclasses import dataclass, field
from typing import Any

Entry = dict[str, str]


def parse_field_list(text: str) -> dict[str, list[Entry]]:
    """Parse ``tshark -G fields`` output.

    Lines are ``P<TAB>name<TAB>abbrev`` for protocols and
    ``F<TAB>name<TAB>abbrev<TAB>type<TAB>proto<TAB>display<TAB>bitmask<TAB>blurb``
    for fields. Both lists come back sorted case-insensitively by abbreviation,
    without duplicates (the input may concatenate several ``-G fields`` runs).
    """
    protocols: list[Entry] = []
    fields: list[Entry] = []
    seen: set[tuple[str, str]] = set()
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 3 or (parts[0], parts[2]) in seen:
            continue  # merged outputs repeat entries
        seen.add((parts[0], parts[2]))
        if parts[0] == "P":
            protocols.append({"name": parts[2], "desc": parts[1]})
        elif parts[0] == "F" and len(parts) >= 5:
            fields.append(
                {
                    "name": parts[2],
                    "desc": parts[1],
                    "type": parts[3],
                    "proto": parts[4],
                    "blurb": parts[7] if len(parts) > 7 else "",
                }
            )
    protocols.sort(key=lambda p: p["name"].lower())
    fields.sort(key=lambda fd: fd["name"].lower())
    return {"protocols": protocols, "fields": fields}


def _prefix_slice(keys: list[str], entries: list[Entry], prefix: str, limit: int) -> list[Entry]:
    start = bisect_left(keys, prefix)
    out: list[Entry] = []
    for i in range(start, len(keys)):
        if not keys[i].startswith(prefix) or len(out) >= limit:
            break
        out.append(entries[i])
    return out


@dataclass
class FieldCatalog:
    protocols: list[Entry]
    fields: list[Entry]
    _pkeys: list[str] = field(init=False, repr=False)
    _fkeys: list[str] = field(init=False, repr=False)
    # find(): lower-cased "name<TAB>description" per entry, built on first use.
    _text: list[tuple[str, Entry]] | None = field(init=False, repr=False, default=None)

    def __post_init__(self) -> None:
        self._pkeys = [p["name"].lower() for p in self.protocols]
        self._fkeys = [f["name"].lower() for f in self.fields]

    @classmethod
    def parse(cls, text: str) -> FieldCatalog:
        parsed = parse_field_list(text)
        return cls(parsed["protocols"], parsed["fields"])

    def search(self, prefix: str, limit: int) -> dict[str, Any]:
        """Case-insensitive prefix search.

        An exact match sorts first in its list. ``truncated`` is true when more
        fields match than ``limit``.
        """
        p = prefix.lower()
        protocols = _prefix_slice(self._pkeys, self.protocols, p, limit)
        fields = _prefix_slice(self._fkeys, self.fields, p, limit + 1)
        truncated = len(fields) > limit
        fields = fields[:limit]
        return {"protocols": protocols, "fields": fields, "truncated": truncated}

    def find(self, query: str, limit: int) -> list[Entry]:
        """Fields and protocols whose name or description holds every word of
        ``query`` (case-insensitive), for the filter builder: exact names
        first, then names starting with the query, names with it as a dotted
        part, names holding it, and description matches; each protocol is
        marked ``type: "protocol"``."""
        words = query.lower().split()
        if not words:
            return []
        if self._text is None:
            self._text = [
                (f"{e['name']}\t{e.get('desc', '')}".lower(), e)
                for e in (
                    *({**p, "type": "protocol"} for p in self.protocols),
                    *self.fields,
                )
            ]
        q = query.strip().lower()
        ranked: list[tuple[int, str, Entry]] = []
        for text, entry in self._text:
            if all(w in text for w in words):
                name = entry["name"].lower()
                if name == q:
                    rank = 0
                elif name.startswith(q):
                    rank = 1
                elif q in name.split("."):
                    rank = 2  # ip.ttl for "ttl"
                else:
                    rank = 3 if q in name else 4
                ranked.append((rank, name, entry))
        ranked.sort(key=lambda r: (r[0], len(r[1]), r[1]))
        return [entry for _, _, entry in ranked[:limit]]

    def lookup(self, name: str) -> Entry | None:
        """The field (or protocol) called ``name`` (case-insensitive), if any."""
        key = name.lower()
        for keys, entries in ((self._fkeys, self.fields), (self._pkeys, self.protocols)):
            i = bisect_left(keys, key)
            if i < len(keys) and keys[i] == key:
                return entries[i]
        return None

    def __contains__(self, name: object) -> bool:
        if not isinstance(name, str):
            return False
        key = name.lower()
        for keys in (self._fkeys, self._pkeys):
            i = bisect_left(keys, key)
            if i < len(keys) and keys[i] == key:
                return True
        return False
