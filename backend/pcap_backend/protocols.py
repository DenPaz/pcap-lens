"""Enabled Protocols: the protocols and heuristic dissectors tshark can switch.

``tshark -G protocols`` lists every protocol as ``name, short name, filter
name, enabled, enabled by default, can toggle`` (T/F) and ``-G
heuristic-decodes`` every heuristic dissector as ``underlying protocol,
protocol, enabled, enabled by default, short name, description``. Both show
the built-in state only: ``-G`` runs before the personal configuration is
read, so what the user switched in Wireshark comes from the profile's
``disabled_protos``, ``enabled_protos`` (protocols off by default, turned on)
and ``heuristic_protos`` (``short_name,0|1``) files, read here.
``--disable-protocol``, ``--enable-protocol``, ``--disable-heuristic`` and
``--enable-heuristic`` on the command line override those files.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_MAX_FILE = 1 << 20


@dataclass
class ProtocolList:
    """``-G protocols`` and ``-G heuristic-decodes``, merged across listings
    (the plain one, then the one with the Lua scripts)."""

    protocols: dict[str, dict[str, Any]] = field(default_factory=dict)
    heuristics: dict[str, dict[str, Any]] = field(default_factory=dict)

    @classmethod
    def parse(cls, protocols: list[str], heuristics: list[str]) -> ProtocolList:
        out = cls()
        for text in protocols:
            for line in text.split("\n"):
                cells = line.rstrip("\r").split("\t")
                if len(cells) < 6 or not cells[2]:
                    continue
                out.protocols.setdefault(
                    cells[2],
                    {
                        "name": cells[2],
                        "short": cells[1],
                        "title": cells[0],
                        "default": cells[4] == "T",
                        "toggle": cells[5] == "T",
                    },
                )
        for text in heuristics:
            for line in text.split("\n"):
                cells = line.rstrip("\r").split("\t")
                if len(cells) < 6 or not cells[4]:
                    continue
                out.heuristics.setdefault(
                    cells[4],
                    {
                        "name": cells[4],
                        "protocol": cells[1],
                        "on": cells[0],
                        "title": cells[5],
                        "default": cells[3] == "T",
                    },
                )
        return out


def _read(path: Path) -> list[str]:
    """A configuration file's lines without comments and blanks ([] if missing)."""
    try:
        with path.open("rb") as fh:
            text = fh.read(_MAX_FILE).decode("utf-8", "replace")
    except OSError:
        return []
    lines = (line.split("#", 1)[0].strip() for line in text.split("\n"))
    return [line for line in lines if line]


def wireshark_switches(folder: Path | None) -> dict[str, Any]:
    """What the user switched in Wireshark (the profile's folder, None = no
    personal configuration): ``{protocols: {name: on}, heuristics: {name: on}}``."""
    protocols: dict[str, bool] = {}
    heuristics: dict[str, bool] = {}
    if folder is not None:
        for name in _read(folder / "disabled_protos"):
            protocols[name] = False
        for name in _read(folder / "enabled_protos"):
            protocols[name] = True
        for line in _read(folder / "heuristic_protos"):
            name, _, on = line.partition(",")
            if name.strip() and on.strip() in ("0", "1"):
                heuristics[name.strip()] = on.strip() == "1"
    return {"protocols": protocols, "heuristics": heuristics}
