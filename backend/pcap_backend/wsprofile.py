"""Wireshark configuration profiles: where they are and what they hold.

A profile is a folder of configuration files: the Default profile is the
personal configuration folder itself, the others are ``profiles/<name>`` in
it, and Wireshark ships a few in the global folder's ``profiles``. tshark
uses one with ``-C <name>`` (preferences, Decode As, display filter macros,
disabled protocols…). The files PCAP Lens keeps as settings instead (coloring
rules, filter buttons, saved display filters, columns) are read here so they
can be imported.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

_MAX_FILE = 1 << 20  # (configuration files are small; anything bigger isn't one)
# The files tshark reads from a profile; listed to show what a profile holds.
PROFILE_FILES = (
    "preferences",
    "colorfilters",
    "dfilter_buttons",
    "dfilters",
    "dfilter_macros",
    "decode_as_entries",
    "disabled_protos",
)
# A profile name as tshark's -C takes it (Wireshark refuses these characters too).
_NAME_RE = re.compile(r"^[^/\\:*?\"<>|\x00-\x1f]{1,100}$")


def valid_name(name: str) -> bool:
    return bool(_NAME_RE.match(name)) and name.strip() == name and name not in (".", "..")


def config_folders(folders_output: str) -> tuple[Path | None, Path | None]:
    """The personal and global configuration folders from ``tshark -G folders``."""
    found: dict[str, Path] = {}
    for line in folders_output.split("\n"):
        name, sep, value = line.partition(":")
        if sep and value.strip():
            found[name.strip()] = Path(value.strip())
    return found.get("Personal configuration"), found.get("Global configuration")


def _files(folder: Path) -> list[str]:
    return [f for f in PROFILE_FILES if (folder / f).is_file()]


def list_profiles(personal: Path | None, global_: Path | None) -> list[dict[str, Any]]:
    """The Default profile, the personal ones (by name) and the global ones a
    personal profile of the same name doesn't hide: ``{name, path, default,
    global, files}``."""
    out: list[dict[str, Any]] = []
    if personal is not None:
        out.append(
            {
                "name": "Default",
                "path": str(personal),
                "default": True,
                "global": False,
                "files": _files(personal) if personal.is_dir() else [],
            }
        )
    seen: set[str] = set()
    for root, is_global in ((personal, False), (global_, True)):
        folder = root / "profiles" if root is not None else None
        if folder is None or not folder.is_dir():
            continue
        for item in sorted(folder.iterdir(), key=lambda p: p.name.lower()):
            if not item.is_dir() or item.name in seen or not valid_name(item.name):
                continue
            seen.add(item.name)
            out.append(
                {
                    "name": item.name,
                    "path": str(item),
                    "default": False,
                    "global": is_global,
                    "files": _files(item),
                }
            )
    return out


def profile_dir(personal: Path | None, global_: Path | None, name: str) -> Path | None:
    """Where tshark finds profile ``name``: the personal one, else the global one."""
    for root in (personal, global_):
        if root is not None and (root / "profiles" / name).is_dir():
            return root / "profiles" / name
    return None


def _read(path: Path) -> str:
    try:
        if path.stat().st_size > _MAX_FILE:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _lines(text: str) -> list[str]:
    return [line.rstrip("\r") for line in text.split("\n")]


_UAT_FIELD = re.compile(r'\s*"((?:[^"\\]|\\.)*)"\s*(,|$)')


def uat_fields(line: str) -> list[str] | None:
    """The quoted fields of a UAT line (Wireshark's tables: Decode As, filter
    buttons, macros…), ``\\xHH`` and ``\\"`` escapes decoded; None for a
    comment, a blank line or one that isn't a list of quoted fields."""
    text = line.strip()
    if not text or text.startswith("#"):
        return None
    fields: list[str] = []
    at = 0
    while at < len(text):
        m = _UAT_FIELD.match(text, at)
        if not m:
            return None
        fields.append(_unescape(m[1]))
        at = m.end()
        if not m[2]:
            break
    return fields if at >= len(text) else None


def _unescape(value: str) -> str:
    def repl(m: re.Match[str]) -> str:
        if m[1]:
            return chr(int(m[1], 16))
        return m[2]

    return re.sub(r"\\x([0-9a-fA-F]{2})|\\(.)", repl, value)


_COLOR_RULE = re.compile(
    r"^(?P<off>!)?@(?P<name>[^@]*)@(?P<filter>[^@]*)@"
    r"\[(?P<fg>\d+,\d+,\d+)\]\[(?P<bg>\d+,\d+,\d+)\]\s*$"
)


def _hex(rgb: str) -> str:
    """``65535,24383,0`` (16-bit channels) → ``#ff5f00``."""
    return "#" + "".join(f"{round(int(c) / 257):02x}" for c in rgb.split(","))


def parse_colorfilters(text: str) -> list[dict[str, Any]]:
    """``@name@filter@[fg][bg]`` lines (``!`` first: disabled) as PCAP Lens
    coloring rules ``{name, filter, foreground, background, enabled}``."""
    rules = []
    for line in _lines(text):
        m = _COLOR_RULE.match(line.strip())
        if m:
            rules.append(
                {
                    "name": m["name"],
                    "filter": m["filter"],
                    "foreground": _hex(m["fg"]),
                    "background": _hex(m["bg"]),
                    "enabled": not m["off"],
                }
            )
    return rules


def parse_filter_buttons(text: str) -> list[dict[str, Any]]:
    """``dfilter_buttons`` (UAT: enabled, label, expression, comment)."""
    buttons = []
    for line in _lines(text):
        fields = uat_fields(line)
        if fields and len(fields) >= 3 and fields[1] and fields[2]:
            buttons.append(
                {
                    "label": fields[1],
                    "filter": fields[2],
                    "comment": fields[3] if len(fields) > 3 else "",
                    "enabled": fields[0].upper() == "TRUE",
                }
            )
    return buttons


_DFILTER = re.compile(r'^"((?:[^"\\]|\\.)*)"\s+(.+)$')


def parse_dfilters(text: str) -> list[dict[str, str]]:
    """The saved display filters (``dfilters``: ``"name" expression`` lines)."""
    out = []
    for line in _lines(text):
        m = _DFILTER.match(line.strip())
        if m and not line.lstrip().startswith("#"):
            out.append({"name": _unescape(m[1]), "filter": m[2].strip()})
    return out


def parse_macros(text: str) -> list[dict[str, str]]:
    """Display filter macros (UAT: name, text; tshark expands them itself)."""
    out = []
    for line in _lines(text):
        fields = uat_fields(line)
        if fields and len(fields) >= 2 and fields[0]:
            out.append({"name": fields[0], "text": fields[1]})
    return out


def preference(text: str, key: str) -> str | None:
    """A preference's value (set, not commented out), its continuation lines
    (indented) joined."""
    lines = _lines(text)
    for i, line in enumerate(lines):
        name, sep, value = line.partition(":")
        if sep and name.strip() == key and not line.startswith("#"):
            parts = [value.strip()]
            for more in lines[i + 1 :]:
                if not more[:1].isspace() or not more.strip():
                    break
                parts.append(more.strip())
            return " ".join(p for p in parts if p)
    return None


# Wireshark's built-in column formats → PCAP Lens's base column ids.
_COLUMN_FORMATS = {
    "%m": "number",
    "%t": "time",
    "%s": "source",
    "%rs": "source",
    "%us": "source",
    "%hs": "source",
    "%d": "destination",
    "%rd": "destination",
    "%ud": "destination",
    "%hd": "destination",
    "%p": "protocol",
    "%L": "length",
    "%i": "info",
}
_CUSTOM_COLUMN = re.compile(r"^%Cus:(?P<field>[^:]+)(?::\d+)?(?::[RUD])?$")
_FIELD = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]*$")


def parse_columns(preferences_text: str) -> list[dict[str, str]]:
    """The profile's packet list columns (``gui.column.format``: title, format
    pairs) as ``{title, id}`` for a base column or ``{title, field}`` for a
    custom one. Columns PCAP Lens can't show (other formats, a custom column
    of several fields) are left out."""
    value = preference(preferences_text, "gui.column.format")
    if value is None:
        return []
    quoted = [_unescape(s) for s in re.findall(r'"((?:[^"\\]|\\.)*)"', value)]
    out = []
    seen: set[str] = set()
    for title, fmt in zip(quoted[::2], quoted[1::2], strict=False):
        # (Every time format, e.g. %Yt or %Gt, is the one Time column.)
        base = "time" if re.fullmatch(r"%[A-Za-z]{0,2}t", fmt) else _COLUMN_FORMATS.get(fmt)
        if base:
            if base not in seen:
                seen.add(base)
                out.append({"title": title, "id": base})
            continue
        m = _CUSTOM_COLUMN.match(fmt)
        if m and _FIELD.match(m["field"]):
            out.append({"title": title, "field": m["field"]})
    return out


def read_profile(folder: Path) -> dict[str, Any]:
    """What a profile holds that PCAP Lens keeps as settings, plus what tshark
    reads from it when the profile is used (counted)."""
    prefs = _read(folder / "preferences")
    changed = sum(
        1
        for line in _lines(prefs)
        if line and not line.startswith(("#", " ", "\t")) and ":" in line
    )
    return {
        "coloringRules": parse_colorfilters(_read(folder / "colorfilters")),
        "filterButtons": parse_filter_buttons(_read(folder / "dfilter_buttons")),
        "savedFilters": parse_dfilters(_read(folder / "dfilters")),
        # (Same "name" filter format; Wireshark's capture filters, which tshark doesn't read.)
        "captureFilters": parse_dfilters(_read(folder / "cfilters")),
        "macros": parse_macros(_read(folder / "dfilter_macros")),
        "columns": parse_columns(prefs),
        "preferences": changed,
        "decodeAs": sum(
            1 for line in _lines(_read(folder / "decode_as_entries")) if uat_fields(line)
        ),
    }
