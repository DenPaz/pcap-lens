"""Extcap: Wireshark's capture helpers (sshdump, ciscodump, androiddump, udpdump…).

An extcap is a program in one of tshark's extcap folders (``tshark -G folders``)
that answers ``--extcap-interfaces`` with the interfaces it offers and
``--extcap-interface X --extcap-config`` with its options, one sentence per
line: ``arg {number=0}{call=--remote-host}{display=…}{type=string}…`` and
``value {arg=8}{value=tcpdump}{display=tcpdump}{default=true}``. dumpcap
doesn't know them: tshark runs the helper (writing to a FIFO) and dumpcap
together, taking the helper's options as preferences named
``extcap.<interface>.<option>`` (:func:`settings_key`), so a capture on an
extcap interface runs ``tshark -i <interface> -o extcap.…:… -w -``.
"""

from __future__ import annotations

import os
import re
import sys
import threading
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .cancellation import CancelledError, CancelToken
from .tshark import run

HELPER_TIMEOUT_S = 10.0
# `{key=value}` pieces; a value may hold braces, so it ends at "}" before "{" or the end.
_PIECE_RE = re.compile(r"\{([A-Za-z]+)=(.*?)\}(?=\{|\s*$)")
_SENTENCE_RE = re.compile(r"^(extcap|interface|arg|value|dlt|control)\s+(\{.*\})\s*$")
# Wireshark's extcap_settings_key: anything but [A-Za-z0-9_] goes.
_NOT_KEY_RE = re.compile(r"[^A-Za-z0-9_]")
# What a call may look like (it becomes a preference name and a helper option).
CALL_RE = re.compile(r"^--[A-Za-z0-9][A-Za-z0-9_-]*$")


def settings_key(interface: str, call: str) -> str:
    """The tshark preference holding an extcap option (Wireshark's
    ``extcap_settings_key``): ``extcap.<interface>.<call>``, the interface
    lower-cased with other characters as "_", the call without them."""
    name = _NOT_KEY_RE.sub("_", interface).lower()
    return f"extcap.{name}.{_NOT_KEY_RE.sub('', call)}"


def sentences(text: str) -> list[tuple[str, dict[str, str]]]:
    """The ``kind {key=value}…`` lines of an extcap answer."""
    out = []
    for raw in text.split("\n"):
        m = _SENTENCE_RE.match(raw.strip())
        if m:
            out.append((m.group(1), dict(_PIECE_RE.findall(m.group(2)))))
    return out


@dataclass(slots=True)
class Helper:
    path: Path
    version: str = ""
    help: str = ""
    interfaces: list[tuple[str, str]] = field(default_factory=list)  # (value, display)


def parse_interfaces(path: Path, text: str) -> Helper:
    """A helper's ``--extcap-interfaces`` answer."""
    helper = Helper(path)
    for kind, pieces in sentences(text):
        if kind == "extcap":
            helper.version = pieces.get("version", "")
            helper.help = pieces.get("help", "")
        elif kind == "interface" and pieces.get("value"):
            helper.interfaces.append((pieces["value"], pieces.get("display", "")))
    return helper


_ARG_KEYS = (
    "call",
    "display",
    "type",
    "default",
    "tooltip",
    "placeholder",
    "required",
    "group",
    "range",
    "mustexist",
    "validation",
    "fileext",
    "prefix",
    "save",
    "reload",
)


def parse_config(text: str) -> list[dict[str, Any]]:
    """A helper's ``--extcap-config`` answer: its options in order, each
    ``{number, call, display, type, default?, tooltip?, required, group?,
    range?, mustexist, values: [{value, display, default, parent?}]}``."""
    args: dict[str, dict[str, Any]] = {}
    for kind, pieces in sentences(text):
        if kind == "arg" and pieces.get("number") and CALL_RE.match(pieces.get("call", "")):
            arg: dict[str, Any] = {"number": int(pieces["number"]), "values": []}
            for key in _ARG_KEYS:
                if key in pieces:
                    arg[key] = pieces[key]
            arg["type"] = arg.get("type", "string")
            arg["required"] = arg.get("required", "false").lower() == "true"
            arg["mustexist"] = arg.get("mustexist", "false").lower() == "true"
            args[pieces["number"]] = arg
        elif kind == "value" and pieces.get("arg") in args and "value" in pieces:
            value = {
                "value": pieces["value"],
                "display": pieces.get("display", pieces["value"]),
                "default": pieces.get("default", "false").lower() == "true",
            }
            if pieces.get("parent"):
                value["parent"] = pieces["parent"]
            args[pieces["arg"]]["values"].append(value)
    return sorted(args.values(), key=lambda a: a["number"])


def extcap_folders(folders_output: str, as_root: bool) -> list[Path]:
    """The extcap folders of ``tshark -G folders`` (personal first). As root
    Wireshark leaves the personal one out, like personal plugins."""
    personal: list[Path] = []
    other: list[Path] = []
    for line in folders_output.split("\n"):
        name, sep, value = line.partition(":")
        if not sep or "extcap" not in name.lower() or not value.strip():
            continue
        target = personal if "personal" in name.lower() else other
        target.append(Path(value.strip()))
    return (other if as_root else [*personal, *other]) if personal or other else []


def helper_files(folders: Iterable[Path], platform: str = sys.platform) -> list[Path]:
    """The programs in the extcap folders: executables (on Windows .exe
    files; batch files would need a shell)."""
    out: list[Path] = []
    for folder in folders:
        try:
            entries = sorted(folder.iterdir())
        except OSError:
            continue
        for path in entries:
            if not path.is_file():
                continue
            if platform == "win32":
                if path.suffix.lower() == ".exe":
                    out.append(path)
            elif os.access(path, os.X_OK):
                out.append(path)
    return out


def _run_limited(argv: list[str], token: CancelToken, timeout: float) -> str:
    """A helper's answer, given up on after ``timeout`` (a helper may hang
    looking for devices)."""
    own = CancelToken()
    timer = threading.Timer(timeout, own.cancel)
    timer.start()
    token.on_cancel(own.cancel)
    try:
        res = run(argv, own)
    finally:
        timer.cancel()
    token.raise_if_cancelled()
    return res.stdout.decode("utf-8", "replace")


def find_helpers(
    files: Iterable[Path],
    token: CancelToken,
    timeout: float = HELPER_TIMEOUT_S,
    runner: Callable[[list[str], CancelToken, float], str] = _run_limited,
) -> list[Helper]:
    """Ask every helper for its interfaces (in parallel; one that fails,
    hangs or answers nothing is left out)."""

    def ask(path: Path) -> Helper | None:
        try:
            answer = runner([str(path), "--extcap-interfaces"], token, timeout)
            helper = parse_interfaces(path, answer)
        except CancelledError:
            if token.cancelled:
                raise
            return None
        except OSError:
            return None
        return helper if helper.interfaces else None

    paths = list(files)
    if not paths:
        return []
    with ThreadPoolExecutor(max_workers=min(8, len(paths))) as pool:
        found = list(pool.map(ask, paths))
    return [h for h in found if h is not None]
