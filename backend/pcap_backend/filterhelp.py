"""Display filter help: the fields an expression names, hints for a filter
that matches nothing, and the values a field takes in a capture."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable, Iterable
from typing import Any

# Quoted strings (with \-escapes) are skipped; what is left is scanned for names.
_STRING = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'')
_NAME = re.compile(r"(?<![\w.\-:])[A-Za-z_][\w\-]*(?:\.[\w\-]+)*")
# Words of the filter language that also look like names.
_KEYWORDS = frozenset(
    (
        *("and", "or", "not", "xor", "in", "contains", "matches", "any", "all"),
        *("eq", "ne", "gt", "lt", "ge", "le", "bitand", "bitwise_and", "true", "false"),
    )
)
_STRING_TYPES = frozenset(
    ("FT_STRING", "FT_STRINGZ", "FT_UINT_STRING", "FT_STRINGZPAD", "FT_STRINGZTRUNC")
)
# `field == "literal"` (or eq), the field possibly wrapped in nothing else.
_EQUALS_STRING = re.compile(r'(?<![\w.])([A-Za-z_][\w.\-]*)\s*(?:==|\beq\b)\s*"((?:[^"\\]|\\.)*)"')
# Fields tshark names but no protocol row would: always "present".
ALWAYS_PRESENT = ("frame", "_ws", "geninfo")
# field_values: distinct values kept (the rest are only counted as "more").
MAX_DISTINCT = 10_000


def filter_fields(expr: str, known: Callable[[str], bool]) -> list[str]:
    """The field and protocol names ``expr`` uses, in order, without duplicates
    (``known`` tells names from value words such as ``http`` in
    ``tcp.port == http``, which are kept only when they are fields too)."""
    text = _STRING.sub(" ", expr)
    out: list[str] = []
    for m in _NAME.finditer(text):
        name = m.group(0)
        end = m.end()
        if name.lower() in _KEYWORDS or name in out:
            continue
        if end < len(text) and text[end] == "(":
            continue  # a function: len(), lower(), …
        if known(name):
            out.append(name)
    return out


def always_present(name: str) -> bool:
    return any(name == p or name.startswith(p + ".") for p in ALWAYS_PRESENT)


def _unescape(literal: str) -> str:
    return re.sub(r"\\(.)", r"\1", literal)


def _quote(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def case_hints(expr: str, type_of: Callable[[str], str | None]) -> list[dict[str, str]]:
    """``field == "Text"`` on a string field is case-sensitive: for each such
    comparison whose text has letters, the case-insensitive filter to try."""
    out: list[dict[str, str]] = []
    for m in _EQUALS_STRING.finditer(expr):
        name, literal = m.group(1), _unescape(m.group(2))
        if type_of(name) not in _STRING_TYPES or literal.lower() == literal.upper():
            continue
        out.append(
            {
                "field": name,
                "value": literal,
                "filter": f"lower({name}) == {_quote(literal.lower())}",
            }
        )
    return out


def count_values(cells: Iterable[str], aggregator: str = "\x1e") -> dict[str, Any]:
    """Distinct values of a field from its ``-T fields`` cells (one per packet,
    occurrences joined by ``aggregator``): ``counts`` (value → packets holding
    it, at most MAX_DISTINCT values), ``packets`` (cells with a value) and
    ``more`` (values left out once the cap was reached)."""
    counts: Counter[str] = Counter()
    packets = more = 0
    for cell in cells:
        if not cell:
            continue
        packets += 1
        for value in dict.fromkeys(cell.split(aggregator)):  # once per packet
            if value in counts or len(counts) < MAX_DISTINCT:
                counts[value] += 1
            else:
                more += 1
    return {"counts": counts, "packets": packets, "more": more}
