"""Wireshark preferences as tshark lists them (``-G defaultprefs`` / ``-G currentprefs``).

Each preference is a block of comment lines (the description, then a line
naming the type) followed by ``name: value``, commented out (``#name: value``)
while it has its default value::

    # Make the TCP dissector analyze TCP sequence numbers …
    # TRUE or FALSE (case-insensitive)
    # tcp.analyze_sequence_numbers: TRUE

    # Make the TCP dissector use this scaling factor …
    # One of: Not known, 0 (no scaling), 1 (multiply by 2), …
    # (case-insensitive).
    # tcp.default_window_scaling: Not known

Sections start with ``####### Protocols ########`` and the like; only the
"Protocols" section holds dissector preferences.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# The type line, matched against the last comment line before the value
# (tshark 4.6 writes "true or false", 4.2 "TRUE or FALSE").
_TYPES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^TRUE or FALSE", re.IGNORECASE), "bool"),
    (re.compile(r"^A decimal number", re.IGNORECASE), "uint"),
    (re.compile(r"^A hexadecimal number", re.IGNORECASE), "hex"),
    (re.compile(r"^A string denoting an positive integer range \(", re.IGNORECASE), "range"),
    (re.compile(r"^A six-digit hexadecimal RGB color", re.IGNORECASE), "color"),
    (re.compile(r"^A path to a file", re.IGNORECASE), "file"),
    (re.compile(r"^A path to a directory", re.IGNORECASE), "directory"),
    (re.compile(r"^A string$", re.IGNORECASE), "string"),
]
_SECTION = re.compile(r"^#{7} (.+?) #{8}$")
_VALUE = re.compile(r"^(#?)([A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)+):[ ]?(.*)$")
_ONE_OF = "one of: "
# tshark 4.6 adds the choices' descriptions when they differ from their names.
_EQUIVALENTLY = "equivalently, one of: "
_CASE_NOTE = "(case-insensitive)."


@dataclass(slots=True)
class Preference:
    name: str
    description: str
    type: str  # bool, uint, hex, range, color, file, directory, string, enum, other
    value: str
    # True when the listing shows it commented out (the default value).
    is_default: bool
    choices: list[str] = field(default_factory=list)

    @property
    def module(self) -> str:
        return self.name.split(".", 1)[0]

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "name": self.name,
            "description": self.description,
            "type": self.type,
        }
        if self.choices:
            out["choices"] = self.choices
        return out


def parse_prefs(text: str) -> dict[str, Preference]:
    """Preferences of the "Protocols" section, by name, in listing order."""
    prefs: dict[str, Preference] = {}
    section = ""
    comments: list[str] = []
    for raw in text.split("\n"):
        line = raw.rstrip("\r")
        if m := _SECTION.match(line):
            section = m.group(1)
            comments = []
            continue
        if not line.strip():
            comments = []
            continue
        if (m := _VALUE.match(line)) and not line.startswith("# "):
            if section == "Protocols" and comments:
                pref = _preference(m.group(2), m.group(3), m.group(1) == "#", comments)
                prefs[pref.name] = pref
            comments = []
            continue
        if line.startswith("#"):
            comments.append(line[1:].strip())
    return prefs


def _preference(name: str, value: str, is_default: bool, comments: list[str]) -> Preference:
    kind = "other"
    choices: list[str] = []
    lines = list(comments)
    if lines and lines[-1].lower() == _CASE_NOTE:
        lines.pop()
    # Enum choices: the names, and (4.6) their descriptions; the value is
    # written as one of the two, and tshark accepts either.
    lists: list[list[str]] = []
    if lines and lines[-1].lower().startswith(_EQUIVALENTLY):
        lists.append(_choices(lines.pop()[len(_EQUIVALENTLY) :]))
    typeline = lines[-1] if lines else ""
    if typeline.lower().startswith(_ONE_OF):
        kind = "enum"
        lists.insert(0, _choices(typeline[len(_ONE_OF) :]))
        lines.pop()
        wanted = value.strip().lower()
        choices = next((lst for lst in lists if wanted in {c.lower() for c in lst}), lists[0])
    else:
        for pattern, typ in _TYPES:
            if pattern.match(typeline):
                kind = typ
                lines.pop()
                break
    description = " ".join(line for line in lines if line).strip()
    value = value.strip()
    # The list is joined with ", ", which a few choice names contain too
    # ("AES-128 Encryption, 64-bit Integrity Protection"): when the value isn't
    # one of the pieces, the split is wrong, so the value is free text instead.
    if kind == "enum" and value.lower() not in {c.lower() for c in choices}:
        kind, choices = "other", []
    return Preference(name, description, kind, value, is_default, choices)


def _choices(text: str) -> list[str]:
    return [c.strip() for c in text.split(", ") if c.strip()]


def protocols_with_prefs(prefs: dict[str, Preference]) -> list[dict[str, Any]]:
    """Each protocol (preference module) with its number of preferences, by name."""
    counts: dict[str, int] = {}
    for pref in prefs.values():
        counts[pref.module] = counts.get(pref.module, 0) + 1
    return [{"protocol": p, "count": counts[p]} for p in sorted(counts)]
