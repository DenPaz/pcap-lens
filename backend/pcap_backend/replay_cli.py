"""Replay to Service from the command line: ``pcap-lens-replay``.

Runs the replay engine (replay.py, service/replaying.py) without VS Code:
the captures' client sides go to live services, as the panel's Start does.
Started as ``python -m pcap_backend.replay_cli``, as the launcher
``backend/pcap-lens-replay.py`` (what the panel's Copy Command Line gives:
the script's folder is on ``sys.path``, so no PYTHONPATH is needed) or as
the ``pcap-lens-replay`` script of an installed package.

Captures come from the command line (every packet, or ``--filter``'s) or
from a setup file the panel saved (``--setup``: its captures, destinations
and options; command-line options override them). Recorded targets go where
``--map`` rules (exact keys or ``*`` wildcards) or ``--to`` send them; the
others are left out. Progress and the log go to stderr (``--json``: JSON
lines on stdout), the summary to stdout, and ``--results`` writes what the
panel's Save Results… writes. Ctrl+C (or SIGTERM, or ``--duration``) stops
the replay cleanly: its summary still comes.

Exit status: 0 everything chosen was delivered; 1 the replay ran with
problems (refused or reset connections, data the service didn't read,
errors); 2 a usage error (arguments, a missing file, the setup file, the
mapping, a filter, a public destination not allowed); 3 the replay couldn't
run (tshark, a capture tshark can't read); 130 stopped before anything was
sent.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import signal
import sys
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

from .cancellation import CancelledError
from .mcp import ToolFailureError, read_dissection
from .pcap_service import PcapService
from .protocol import FilterError, InvalidParamsError, RequestContext, RpcError
from .service.replaying import MAX_FILES, MAX_JITTER_MS, MAX_LOOPS, MAX_SPEED, ORDERS
from .tshark import PROCESSES, ConfigError, ToolNotFoundError

PROG = "pcap-lens-replay"
EXIT_OK, EXIT_PROBLEMS, EXIT_USAGE, EXIT_FAILED, EXIT_STOPPED = 0, 1, 2, 3, 130

# The panel's formats (src/replayModel.ts).
SETUP_FORMAT = "pcap-lens-replay"
SETUP_VERSION = 1
RESULTS_FORMAT = "pcap-lens-replay-results"
MAX_SAVED_LOG = 100_000  # log lines kept for --results (the rest are counted)
# The options a setup file can hold, and their defaults (replayModel.DEFAULT_OPTIONS).
DEFAULT_OPTIONS: dict[str, Any] = {
    "speed": 1.0,
    "loops": 1,
    "scope": "all",
    "order": "sequence",
    "jitter": 0.0,
    "loss": 0.0,
}
STATUS_EVERY_S = 10.0  # the status line when stderr isn't a terminal


class UsageError(Exception):
    """Arguments, a setup file or a mapping that can't be used (exit 2)."""


# -- mapping rules ----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Rule:
    """``--map PATTERN=DEST``: recorded targets matching the pattern (a
    protocol or any, a server address or ``*``, a port or ``*``) go to DEST
    (a host, and a port unless the recorded one is kept)."""

    text: str
    proto: str | None
    host: str | None
    port: int | None
    to_host: str
    to_port: int | None

    @property
    def exact(self) -> bool:
        return None not in (self.proto, self.host, self.port)

    def matches(self, target: dict[str, Any]) -> bool:
        return (
            (self.proto is None or self.proto == target["proto"])
            and (self.host is None or _same_host(self.host, str(target["ip"])))
            and (self.port is None or self.port == target["port"])
        )


def _same_host(a: str, b: str) -> bool:
    try:
        return ipaddress.ip_address(a) == ipaddress.ip_address(b)
    except ValueError:
        return a == b


def _port(text: str, what: str) -> int:
    if not text.isdigit() or not 1 <= int(text) <= 65535:
        raise UsageError(f"{what}: {text!r} isn't a port between 1 and 65535")
    return int(text)


def _host_port(text: str, what: str, *, port_required: bool) -> tuple[str, str | None]:
    """``host:port``, ``[v6]:port``, or (``port_required`` false) a host alone."""
    text = text.strip()
    if text.startswith("["):
        end = text.find("]")
        if end < 0:
            raise UsageError(f"{what}: {text!r} has no closing ]")
        host, rest = text[1:end], text[end + 1 :]
        if rest and not rest.startswith(":"):
            raise UsageError(f"{what}: {text!r}: write [address]:port")
        port = rest[1:] if rest else None
    elif text.count(":") == 1:
        host, port = text.split(":")
    elif ":" in text:  # (an IPv6 address alone)
        host, port = text, None
    else:
        host, port = text, None
    if not host:
        raise UsageError(f"{what}: {text!r} has no host")
    if port is None and port_required:
        raise UsageError(f"{what}: {text!r} needs a port (or * for any)")
    return host, port


def parse_rule(text: str) -> Rule:
    """``--map``'s value: ``[tcp|udp/]host:port=host[:port]`` (``tcp 10.0.0.5:11001``
    as replay_targets writes keys works too; ``*`` for any host or port)."""
    pattern, sep, dest = text.partition("=")
    if not sep or not pattern.strip() or not dest.strip():
        raise UsageError(f"--map {text!r}: write PATTERN=DESTINATION, e.g. tcp/*:11001=127.0.0.1")
    pattern = pattern.strip()
    proto: str | None = None
    for prefix in ("tcp/", "udp/", "tcp ", "udp ", "*/"):
        if pattern.lower().startswith(prefix):
            proto = None if prefix == "*/" else prefix[:3]
            pattern = pattern[len(prefix) :].strip()
            break
    host, port = _host_port(pattern, f"--map {text!r}", port_required=True)
    to_host, to_port = _host_port(dest, f"--map {text!r}", port_required=False)
    if to_host == "*":
        raise UsageError(f"--map {text!r}: the destination needs a host")
    return Rule(
        text,
        proto,
        None if host == "*" else host,
        None if port == "*" else _port(str(port), f"--map {text!r}"),
        to_host,
        None if to_port in (None, "*") else _port(str(to_port), f"--map {text!r}"),
    )


def choose_destinations(
    targets: list[dict[str, Any]],
    rules: list[Rule],
    to: str | None,
    setup: dict[str, dict[str, Any]] | None = None,
) -> tuple[dict[str, dict[str, Any]], list[str], list[Rule]]:
    """Where each recorded target goes: ``{key: {ip, port}}``, the keys left
    out, and the rules that matched nothing (a typo, or another capture's).

    A setup's targets come first (its unchecked ones stay out); then rules
    naming a target exactly, then wildcard rules in the order given, each
    replacing what came before; ``to`` sends the targets still without a
    destination (and not left out by the setup) to that host, recorded port."""
    setup = setup or {}
    chosen: dict[str, dict[str, Any]] = {}
    unused = list(rules)
    ordered = [r for r in rules if r.exact] + [r for r in rules if not r.exact]
    for t in targets:
        key = t["key"]
        dest: dict[str, Any] | None = None
        saved = setup.get(key)
        if saved is not None and saved.get("enabled", True):
            dest = {"ip": saved["ip"], "port": saved["port"]}
        rule = next((r for r in ordered if r.matches(t)), None)
        if rule is not None:
            dest = {"ip": rule.to_host, "port": rule.to_port or t["port"]}
            if rule in unused:
                unused.remove(rule)
        elif dest is None and to and saved is None:
            dest = {"ip": to, "port": t["port"]}
        if dest is not None:
            chosen[key] = dest
    left_out = [t["key"] for t in targets if t["key"] not in chosen]
    return chosen, left_out, unused


# -- setup files ------------------------------------------------------------------------


@dataclass(slots=True)
class Setup:
    """A setup file the panel saved (replayModel.setupToJson)."""

    path: Path
    open_capture: Path | None = None
    include_open: bool = True
    open_at: int = 0
    captures: list[tuple[Path, bool]] = field(default_factory=list)
    filter: str = ""
    targets: dict[str, dict[str, Any]] = field(default_factory=dict)
    options: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_OPTIONS))
    problems: list[str] = field(default_factory=list)


def _number(raw: object, low: float, high: float, fallback: float) -> float:
    if isinstance(raw, bool) or not isinstance(raw, int | float) or not low <= raw <= high:
        return fallback
    return float(raw)


def _setup_options(raw: object) -> dict[str, Any]:
    """The options as replayModel.normalizeOptions reads them."""
    o = raw if isinstance(raw, dict) else {}
    loops = o.get("loops")
    ok_loops = isinstance(loops, int) and not isinstance(loops, bool) and 0 <= loops <= MAX_LOOPS
    return {
        "speed": _number(o.get("speed"), 0, MAX_SPEED, DEFAULT_OPTIONS["speed"]),
        "loops": loops if ok_loops else DEFAULT_OPTIONS["loops"],
        "scope": "filter" if o.get("scope") == "filter" else "all",
        "order": "merged" if o.get("order") == "merged" else "sequence",
        "jitter": _number(o.get("jitter"), 0, MAX_JITTER_MS, DEFAULT_OPTIONS["jitter"]),
        "loss": _number(o.get("loss"), 0, 100, DEFAULT_OPTIONS["loss"]),
    }


def _setup_targets(raw: object, problems: list[str]) -> dict[str, dict[str, Any]]:
    """A setup's destinations: ``{key: {ip, port, enabled}}``."""
    targets: dict[str, dict[str, Any]] = {}
    for key, value in (raw if isinstance(raw, dict) else {}).items():
        ip = value.get("ip") if isinstance(value, dict) else None
        port = value.get("port") if isinstance(value, dict) else None
        if (
            not isinstance(ip, str)
            or not ip.strip()
            or isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
        ):
            problems.append(f"{key}: not a recorded target with an IP and port")
            continue
        enabled = value.get("enabled") is not False
        targets[str(key)] = {"ip": ip.strip(), "port": port, "enabled": enabled}
    return targets


def read_setup(path: Path) -> Setup:
    """A setup file, checked like the panel's Load Setup… (replayModel.parseSetup):
    relative paths from the file's folder, unusable entries named in ``problems``."""
    try:
        doc = json.loads(path.read_text("utf-8"))
    except OSError as exc:
        raise UsageError(f"can't read the setup {path}: {exc.strerror or exc}") from exc
    except ValueError as exc:
        raise UsageError(f"the setup {path} isn't JSON: {exc}") from exc
    if not isinstance(doc, dict) or doc.get("format") != SETUP_FORMAT:
        raise UsageError(f'{path} isn\'t a replay setup ("format" is not "{SETUP_FORMAT}")')
    version = doc.get("version")
    if isinstance(version, bool) or not isinstance(version, int | float) or version > SETUP_VERSION:
        raise UsageError(f"{path} was saved by a newer PCAP Lens")
    base = path.resolve().parent
    setup = Setup(path)
    raw_open = doc.get("openCapture")
    if isinstance(raw_open, str) and raw_open.strip():
        setup.open_capture = base / Path(raw_open.strip()).expanduser()
    setup.include_open = doc.get("includeOpenCapture") is not False
    wanted = doc.get("openCapturePosition", 0)
    if isinstance(wanted, bool) or not isinstance(wanted, int) or wanted < 0:
        setup.problems.append(
            "openCapturePosition isn't a whole number from 0: the open capture plays first"
        )
        wanted = 0
    open_at: int | None = None
    seen: set[Path] = set()
    raw_captures = doc.get("captures")
    for i, item in enumerate(raw_captures if isinstance(raw_captures, list) else []):
        if i == wanted:
            open_at = len(setup.captures)
        entry = item if isinstance(item, dict) else {}
        raw = entry.get("path")
        if not isinstance(raw, str) or not raw.strip():
            setup.problems.append("a capture without a path was left out")
            continue
        full = (base / Path(raw.strip()).expanduser()).resolve()
        if full in seen:
            continue
        if len(setup.captures) == MAX_FILES:
            setup.problems.append(f"only the first {MAX_FILES} captures were kept")
            break
        seen.add(full)
        setup.captures.append((full, entry.get("enabled") is not False))
    setup.open_at = len(setup.captures) if open_at is None else open_at
    raw_filter = doc.get("filter")
    setup.filter = raw_filter.strip() if isinstance(raw_filter, str) else ""
    setup.targets = _setup_targets(doc.get("targets"), setup.problems)
    setup.options = _setup_options(doc.get("options"))
    if setup.options["scope"] == "filter" and not setup.filter:
        setup.problems.append(
            "it plays the viewer's filter, which it doesn't hold (saved before 0.30.0): "
            "every packet plays unless --filter names it"
        )
    return setup


# -- the plan ---------------------------------------------------------------------------


@dataclass(slots=True)
class Plan:
    """What to replay: the captures in play order, each with its display
    filter, and the options."""

    files: list[tuple[Path, str]]
    options: dict[str, Any]
    setup: Setup | None = None
    open_capture: Path | None = None  # (the setup's: for the results)


def _option(args: argparse.Namespace, name: str, setup: Setup | None) -> Any:
    value = getattr(args, name)
    if value is not None:
        return value
    return (setup.options if setup else DEFAULT_OPTIONS)[name]


def make_plan(args: argparse.Namespace) -> Plan:
    """The captures and options from the arguments and the setup file."""
    setup = read_setup(Path(args.setup).expanduser()) if args.setup else None
    options = {
        name: _option(args, name, setup) for name in ("speed", "loops", "order", "jitter", "loss")
    }
    if not 0 <= options["speed"] <= MAX_SPEED:
        raise UsageError(f"--speed must be between 0 (no pauses) and {MAX_SPEED:g}")
    if not 0 <= options["loops"] <= MAX_LOOPS:
        raise UsageError(f"--loops must be between 1 and {MAX_LOOPS} (0: until stopped)")
    if not 0 <= options["jitter"] <= MAX_JITTER_MS:
        raise UsageError(f"--jitter must be between 0 and {MAX_JITTER_MS:g} ms")
    if not 0 <= options["loss"] <= 100:
        raise UsageError("--loss must be a percentage between 0 and 100")
    named = [Path(p).expanduser() for p in args.captures]
    if setup is None:
        if not named:
            raise UsageError("name the captures to replay (or a --setup file)")
        if len(named) > MAX_FILES + 1:
            raise UsageError(f"at most {MAX_FILES + 1} captures can be replayed at once")
        flt = (args.filter or "").strip()
        return Plan([(p, flt) for p in named], options)
    # A setup: its captures, the one that was open in the viewer among them.
    if len(named) > 1:
        raise UsageError(
            "with --setup, name at most one capture: the one that was open in the viewer"
        )
    open_capture = named[0] if named else setup.open_capture
    files: list[tuple[Path, str]] = []
    for i, (path, enabled) in enumerate(setup.captures):
        if i == setup.open_at and setup.include_open and open_capture is not None:
            files.append((open_capture, ""))
        if enabled:
            files.append((path, ""))
    if setup.include_open:
        if open_capture is None:
            raise UsageError(
                f"{setup.path.name} plays the capture that was open in the viewer: name it"
            )
        if setup.open_at >= len(setup.captures):
            files.append((open_capture, ""))
        # The viewer's filter applies to the open capture only (as in the panel).
        flt = args.filter if args.filter is not None else setup.filter
        if setup.options["scope"] == "filter" or args.filter is not None:
            files = [(p, flt.strip()) if p == open_capture else (p, f) for p, f in files]
    elif named:
        raise UsageError(f"{setup.path.name} leaves the open capture out: name no capture")
    if not files:
        raise UsageError(f"{setup.path.name} plays no capture")
    return Plan(files, options, setup, open_capture if setup.include_open else None)


# -- dissection options -----------------------------------------------------------------


def dissection_options(args: argparse.Namespace, first: Path) -> tuple[dict[str, Any], list[str]]:
    """``configure``'s parameters: the options file's (as the MCP server reads
    it, for the first capture's folder), then the command line's."""
    options: dict[str, Any] = {"names": {}}
    warnings: list[str] = []
    if args.options:
        try:
            found = read_dissection(Path(args.options).expanduser())
        except ToolFailureError as exc:
            raise UsageError(str(exc)) from exc
        if found.warning:
            warnings.append(found.warning)
        options.update(found.for_path(first.expanduser().resolve()))
    if args.lua:
        options["lua"] = [*options.get("lua", []), *args.lua]
    if args.decode_as:
        options["decodeAs"] = [*options.get("decodeAs", []), *args.decode_as]
    for pref in args.pref:
        name, sep, value = pref.partition(":")
        if not sep or not name.strip():
            raise UsageError(
                f"--pref {pref!r}: write NAME:VALUE, e.g. tcp.desegment_tcp_streams:TRUE"
            )
        options["prefs"] = {**options.get("prefs", {}), name.strip(): value}
    if args.profile is not None:
        options["profile"] = args.profile
    return options, warnings


# -- output -----------------------------------------------------------------------------


def size(n: float) -> str:
    """Bytes as the panel writes them (replayModel's size)."""
    units = ["B", "KB", "MB", "GB"]
    unit = 0
    while n >= 1000 and unit < len(units) - 1:
        n /= 1000
        unit += 1
    return f"{n:.1f} {units[unit]}" if unit else f"{int(n)} B"


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n:,} {one if n == 1 else (many or one + 's')}"


def target_outcome(t: dict[str, Any]) -> str:
    """What happened to one target, in words (replayModel.targetOutcome)."""
    parts: list[str] = []
    if str(t["key"]).startswith("udp"):
        parts.append(_plural(t["datagrams"], "datagram"))
        if t.get("lost"):
            parts.append(f"{_plural(t['lost'], 'datagram')} lost on purpose")
    else:
        parts.append(f"{t['opened']:,} of {_plural(t['connections'], 'connection')} opened")
        if t["refused"]:
            parts.append(f"{t['refused']:,} refused")
        if t["reset"]:
            parts.append(f"{t['reset']:,} reset")
        if t["closedByPeer"]:
            parts.append(f"{t['closedByPeer']:,} closed by the service")
    parts += [f"{size(t['bytes'])} sent", f"{size(t['received'])} received"]
    if t["dropped"]:
        parts.append(f"{size(t['dropped'])} not read by the service")
    if t["errorCount"]:
        parts.append(_plural(t["errorCount"], "error"))
    return ", ".join(parts)


def has_problems(t: dict[str, Any]) -> bool:
    """A target whose traffic didn't all arrive (exit status 1)."""
    return bool(t["errorCount"] or t["refused"] or t["reset"] or t["dropped"] or t.get("tooLarge"))


def results_text(run: dict[str, Any]) -> str:
    """A run as plain text (replayModel.resultsToText)."""
    o = run["options"]
    times = "\u00d7"  # (the multiplication sign, as the panel writes speeds)
    speed = f"speed {o['speed']:g}{times}" if o["speed"] > 0 else "no pauses"
    loops = (
        f"until stopped ({_plural(run['loops'], 'loop')} played)"
        if o["loops"] == 0
        else f"{_plural(run['loops'], 'loop')} of {o['loops']}"
    )
    notes = [
        speed,
        loops,
        ("merged by time" if o["order"] == "merged" else "one after another")
        if run["files"]
        else "",
        f"jitter ±{o['jitter']:g} ms" if o["speed"] > 0 and o["jitter"] else "",
        f"UDP loss {o['loss']:g}%" if o["loss"] else "",
        f"packets: {run['filter']}" if run["filter"] else "packets: all",
    ]
    ended = f"{run['ended']} ({run['seconds']:.1f} s{', stopped' if run['stopped'] else ''})"
    lines = [
        "PCAP Lens replay results",
        "",
        f"Capture:  {run['capture']}",
        f"Started:  {run['started']}",
        f"Ended:    {ended}",
        "Options:  " + " · ".join(n for n in notes if n),
        "",
        "Captures:",
    ]
    for s in run["sources"]:
        parts = [
            f"{_plural(s['packets'], 'packet')} sent ({size(s['bytes'])})",
            f"{_plural(s['lost'], 'datagram')} lost on purpose" if s["lost"] else "",
            f"{_plural(s['retransmissions'], 'retransmission')} skipped"
            if s["retransmissions"]
            else "",
            f"{_plural(s['gaps'], 'gap')} in the capture" if s["gaps"] else "",
        ]
        lines.append(f"  {s['name']}: {', '.join(p for p in parts if p)}")
    lines += ["", "Targets:"]
    for t in run["targets"]:
        lines.append(f"  {t['key']} → {t['to']}: {target_outcome(t)}")
        lines += [f"    error: {e}" for e in t["errors"]]
    lines += ["", "Log:"]
    for line in run["log"]:
        target = f"{line['target']}  " if line.get("target") else ""
        level = "ERROR " if line["level"] == "error" else ""
        lines.append(f"  {line['time']:10.3f} s  {level}{target}{line['text']}")
    if run["logOmitted"]:
        lines.append(f"  ({_plural(run['logOmitted'], 'more line')} not kept)")
    return "\n".join(lines) + "\n"


def results_json(run: dict[str, Any]) -> str:
    """A run as JSON (replayModel.resultsToJson)."""
    return json.dumps({"format": RESULTS_FORMAT, "version": 1, **run}, indent=2) + "\n"


def targets_table(found: dict[str, Any]) -> str:
    """``--list``: the recorded targets and the captures they come from."""
    rows = [("TARGET", "CONNECTIONS", "PACKETS", "BYTES", "NOTES")]
    for t in found["targets"]:
        notes = [
            _plural(t["retransmissions"], "retransmission") if t["retransmissions"] else "",
            _plural(t["gaps"], "gap") if t["gaps"] else "",
        ]
        rows.append(
            (
                t["key"],
                f"{t['connections']:,}",
                f"{t['packets']:,}",
                size(t["bytes"]),
                ", ".join(n for n in notes if n),
            )
        )
    widths = [max(len(r[i]) for r in rows) for i in range(4)]
    lines = [
        "  ".join(
            [r[0].ljust(widths[0]), *(r[i].rjust(widths[i]) for i in (1, 2, 3)), r[4]]
        ).rstrip()
        for r in rows
    ]
    lines += ["", "Captures:"]
    for s in found["sources"]:
        if s.get("error"):
            lines.append(f"  {s['name']}: can't be read: {s['error']}")
        else:
            lines.append(
                f"  {s['name']}: {_plural(s['targets'], 'target')}, "
                f"{_plural(s['packets'], 'packet')}, {s['duration']:.3f} s recorded"
            )
    return "\n".join(lines) + "\n"


class Reporter:
    """Progress and the log while a replay runs (called from its thread)."""

    def __init__(self, err: TextIO, out: TextIO, *, quiet: bool, json_lines: bool) -> None:
        self.err, self.out = err, out
        self.quiet, self.json_lines = quiet, json_lines
        self.tty = not json_lines and not quiet and err.isatty()
        self.log: list[dict[str, Any]] = []
        self.omitted = 0
        self.replaying = threading.Event()  # (the first report: sending began)
        self._status = ""
        self._last_status = 0.0
        self._lock = threading.Lock()

    def event(self, kind: str, data: Mapping[str, Any]) -> None:
        if self.json_lines:
            with self._lock:
                self.out.write(json.dumps({"type": kind, **data}) + "\n")
                self.out.flush()

    def message(self, text: str) -> None:
        """A line for the person running it (stderr), above the status line."""
        if self.quiet or self.json_lines:
            return
        with self._lock:
            self._clear()
            self.err.write(text + "\n")
            self._draw()

    def warn(self, text: str) -> None:
        if self.json_lines:
            self.event("warning", {"text": text})
            return
        with self._lock:
            self._clear()
            self.err.write(f"{PROG}: {text}\n")
            self._draw()

    def keep(self, lines: object) -> None:
        for line in lines if isinstance(lines, list) else []:
            if len(self.log) < MAX_SAVED_LOG:
                self.log.append(line)
            else:
                self.omitted += 1

    def progress(self, p: Mapping[str, Any]) -> None:
        if p.get("phase") != "replay":
            if p.get("phase") == "replay-targets" and p.get("capture"):
                self.message(f"Reading {p['capture']}…")
            return
        self.replaying.set()
        self.keep(p.get("log"))
        self.event("progress", p)
        if self.quiet or self.json_lines:
            return
        for line in p.get("log") or []:
            self.log_line(line)
        self._status = self._status_text(p)
        now = time.monotonic()
        with self._lock:
            if self.tty:
                self._clear()
                self._draw()
            elif now - self._last_status >= STATUS_EVERY_S:
                self._last_status = now
                self.err.write(self._status + "\n")
                self.err.flush()

    def finish(self) -> None:
        with self._lock:
            self._clear()
            self._status = ""

    def log_line(self, line: dict[str, Any]) -> None:
        target = f"{line['target']}  " if line.get("target") else ""
        level = "error: " if line.get("level") == "error" else ""
        with self._lock:
            self._clear()
            self.err.write(f"{line['time']:9.3f} s  {target}{level}{line['text']}\n")
            self._draw()

    @staticmethod
    def _status_text(p: Mapping[str, Any]) -> str:
        parts = [f"loop {p.get('loop', 1)}"]
        capture = p.get("capture")
        if capture:
            parts.append(f"capture {capture['index']} of {capture['count']} ({capture['name']})")
        if p.get("fraction") is not None:
            parts.append(f"{p['fraction'] * 100:.0f}%")
        parts += [
            f"{size(p.get('sent', 0))} sent",
            f"{size(p.get('received', 0))} received",
            f"{p.get('open', 0)} open",
        ]
        return "Replaying · " + " · ".join(parts)

    def _clear(self) -> None:
        if self.tty and self._status:
            self.err.write("\r\x1b[K")

    def _draw(self) -> None:
        if self.tty and self._status:
            self.err.write(self._status[:200])
        self.err.flush()


# -- running ----------------------------------------------------------------------------


@dataclass(slots=True)
class _Outcome:
    result: dict[str, Any] | None = None
    error: BaseException | None = None


def run_replay(
    service: PcapService,
    params: dict[str, Any],
    ctx: RequestContext,
    reporter: Reporter,
    duration: float | None,
) -> dict[str, Any]:
    """``service.replay`` in a thread, so this one can stop it cleanly on
    Ctrl+C, SIGTERM or after ``duration`` seconds of sending; a second
    Ctrl+C cancels it outright."""
    outcome = _Outcome()

    def work() -> None:
        try:
            outcome.result = service.replay(params, ctx)
        except BaseException as exc:  # noqa: BLE001 - handed to the main thread
            outcome.error = exc

    requests = [0]

    def on_signal(_signum: int, _frame: object) -> None:
        requests[0] += 1

    stoppable = [s for s in ("SIGINT", "SIGTERM", "SIGBREAK") if hasattr(signal, s)]
    previous: dict[int, Any] = {}
    if threading.current_thread() is threading.main_thread():
        for name in stoppable:
            sig = getattr(signal, name)
            previous[sig] = signal.signal(sig, on_signal)
    worker = threading.Thread(target=work, name="replay", daemon=True)
    worker.start()
    stopping = False
    deadline: float | None = None
    try:
        while worker.is_alive():
            worker.join(0.1)
            if duration is not None and deadline is None and reporter.replaying.is_set():
                deadline = time.monotonic() + duration
            timed_out = deadline is not None and time.monotonic() >= deadline
            if requests[0] >= 2:
                ctx.token.cancel()  # (asked twice: no waiting for a clean end)
            elif (requests[0] or timed_out) and not stopping:
                stopping = True
                reporter.message(
                    "Stopping… (Ctrl+C again to cancel)" if requests[0] else "Time is up: stopping…"
                )
                if not service.replay_stop({}, ctx)["stopped"]:
                    ctx.token.cancel()  # (still starting: nothing to stop cleanly)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        reporter.finish()
    if outcome.error is not None:
        raise outcome.error
    assert outcome.result is not None
    return outcome.result


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=PROG,
        description=(
            "Replay the client side of captures to live services (PCAP Lens's Replay to…):\n"
            "each recorded TCP connection becomes a new connection carrying the bytes its\n"
            "client sent, each UDP datagram a datagram, with the recorded timing."
        ),
        epilog=(
            "Examples:\n"
            f"  {PROG} --list delivery.pcapng\n"
            f"  {PROG} delivery.pcapng --to 127.0.0.1\n"
            f"  {PROG} a.pcap b.pcap --map 'tcp/*:11001=127.0.0.1:12001' --order merged\n"
            f"  {PROG} --setup lab.json --loops 0 --duration 3600 --results run.json\n\n"
            "Exit status: 0 delivered, 1 delivered with problems, 2 usage, "
            "3 couldn't run, 130 stopped before sending."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("captures", nargs="*", help="captures, played in this order")
    what = p.add_argument_group("what to replay")
    what.add_argument(
        "--setup", metavar="FILE", help="a setup saved by the panel (captures, targets, options)"
    )
    what.add_argument(
        "--filter",
        metavar="EXPR",
        help="only the packets matching this display filter (with --setup: of the open capture)",
    )
    what.add_argument(
        "--list", action="store_true", help="list the recorded targets and exit (no replay)"
    )
    where = p.add_argument_group("where it goes")
    where.add_argument(
        "--map",
        action="append",
        default=[],
        metavar="PATTERN=DEST",
        help="send recorded targets matching PATTERN ([tcp|udp/]host:port, * for any host "
        "or port) to DEST (host[:port]; no port: the recorded one). Repeatable",
    )
    where.add_argument(
        "--to", metavar="HOST", help="send every other recorded target to HOST, recorded port"
    )
    where.add_argument(
        "--allow-public",
        action="store_true",
        help="allow destinations outside this machine and private networks",
    )
    how = p.add_argument_group("how (a setup's options unless given)")
    how.add_argument("--speed", type=float, help="1 = real time (default), 0 = no pauses")
    how.add_argument("--loops", type=int, help="times to play (default 1; 0 = until stopped)")
    how.add_argument(
        "--order", choices=ORDERS, help="several captures: one after another or merged"
    )
    how.add_argument("--jitter", type=float, metavar="MS", help="move each paced event by ±MS")
    how.add_argument("--loss", type=float, metavar="PCT", help="leave out PCT%% of UDP datagrams")
    how.add_argument("--seed", type=int, help="repeatable jitter and loss")
    how.add_argument("--duration", type=float, metavar="S", help="stop after S seconds of sending")
    out = p.add_argument_group("output")
    out.add_argument(
        "--results", metavar="FILE", help="write the results (text, or JSON for a .json name)"
    )
    out.add_argument(
        "--json", action="store_true", help="JSON lines on stdout instead of text (for scripts)"
    )
    out.add_argument("--quiet", "-q", action="store_true", help="only the summary and errors")
    diss = p.add_argument_group("dissection (as in the viewer)")
    diss.add_argument("--tshark", metavar="PATH", help="tshark's path (default: found as usual)")
    diss.add_argument(
        "--options",
        metavar="FILE",
        help="PCAP Lens's dissection options file (Lua, Decode As, preferences, profile)",
    )
    diss.add_argument("--lua", action="append", default=[], metavar="FILE", help="a Lua script")
    diss.add_argument(
        "--decode-as", action="append", default=[], metavar="RULE", help="tshark -d RULE"
    )
    diss.add_argument(
        "--pref", action="append", default=[], metavar="NAME:VALUE", help="tshark -o NAME:VALUE"
    )
    diss.add_argument("--profile", metavar="NAME", help="a Wireshark configuration profile")
    return p


def _say(stream: TextIO, text: str) -> None:
    stream.write(text if text.endswith("\n") else text + "\n")
    stream.flush()


def main(
    argv: list[str] | None = None, out: TextIO | None = None, err: TextIO | None = None
) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    args = _parser().parse_args(argv)
    try:
        plan = make_plan(args)
        rules = [parse_rule(m) for m in args.map]
        options, warnings = dissection_options(args, plan.files[0][0])
    except UsageError as exc:
        _say(err, f"{PROG}: {exc}")
        return EXIT_USAGE
    reporter = Reporter(err, out, quiet=args.quiet, json_lines=args.json)
    if plan.setup:
        for problem in plan.setup.problems:
            reporter.warn(f"{plan.setup.path.name}: {problem}")
    for warning in warnings:
        reporter.warn(warning)
    ctx = RequestContext(progress=reporter.progress)
    service = PcapService()
    try:
        return _run(service, args, plan, rules, options, ctx, reporter, out, err)
    except UsageError as exc:
        _say(err, f"{PROG}: {exc}")
        return EXIT_USAGE
    except FilterError as exc:
        expr = (exc.data or {}).get("expr", "")
        _say(err, f"{PROG}: the filter {expr!r}: {str(exc).strip()}")
        return EXIT_USAGE
    except (InvalidParamsError, ConfigError) as exc:
        _say(err, f"{PROG}: {str(exc).strip()}")
        return EXIT_USAGE
    except ToolNotFoundError as exc:
        _say(err, f"{PROG}: {str(exc).strip()}")
        return EXIT_FAILED
    except (CancelledError, KeyboardInterrupt):
        _say(err, f"{PROG}: stopped before anything was sent")
        return EXIT_STOPPED
    except RpcError as exc:
        _say(err, f"{PROG}: {exc}".rstrip())
        return EXIT_FAILED
    finally:
        service.shutdown()
        PROCESSES.kill_all()


def _run(
    service: PcapService,
    args: argparse.Namespace,
    plan: Plan,
    rules: list[Rule],
    options: dict[str, Any],
    ctx: RequestContext,
    reporter: Reporter,
    out: TextIO,
    err: TextIO,
) -> int:
    service.initialize({"tsharkPath": args.tshark} if args.tshark else {}, ctx)
    for warning in service.configure(options, ctx)["warnings"]:
        reporter.warn(warning)
    files = [{"path": str(path), "filter": flt} for path, flt in plan.files]
    found = service.replay_targets({"capture": False, "files": files}, ctx)
    unreadable = [s for s in found["sources"] if s.get("error")]
    if args.list:
        if args.json:
            reporter.event("targets", found)
        else:
            out.write(targets_table(found))
        return EXIT_FAILED if unreadable else EXIT_OK
    for s in unreadable:
        _say(err, f"{PROG}: {s['name']} can't be read: {s['error']}")
    if unreadable:
        return EXIT_FAILED
    targets, left_out, unused = choose_destinations(
        found["targets"], rules, args.to, plan.setup.targets if plan.setup else None
    )
    for rule in unused:
        reporter.warn(f"--map {rule.text} matches no recorded target")
    if not targets:
        raise UsageError(
            "no recorded target has a destination: use --map or --to "
            f"(the recorded targets: {', '.join(t['key'] for t in found['targets']) or 'none'})"
        )
    reporter.event("targets", {**found, "destinations": targets, "leftOut": left_out})
    for key, dest in targets.items():
        reporter.message(f"{key} → {dest['ip']}:{dest['port']}")
    if left_out:
        reporter.message(f"Left out: {', '.join(left_out)}")
    o = plan.options
    params: dict[str, Any] = {
        "capture": False,
        "files": files,
        "targets": targets,
        "speed": o["speed"],
        "loops": o["loops"],
        "order": o["order"],
        "jitter": o["jitter"],
        "loss": o["loss"],
        "allowPublic": args.allow_public,
    }
    if args.seed is not None:
        params["seed"] = args.seed
    started = datetime.now(UTC)
    result = run_replay(service, params, ctx, reporter, args.duration)
    reporter.keep(result.get("log"))
    for line in result.get("log") or []:
        if not reporter.quiet and not reporter.json_lines:
            reporter.log_line(line)  # (the last lines, as progress shows them)
    run = _run_record(plan, result, started, reporter)
    if args.results:
        saved = Path(args.results).expanduser()
        text = results_json(run) if saved.suffix.lower() == ".json" else results_text(run)
        try:
            saved.write_text(text, "utf-8")
        except OSError as exc:
            _say(err, f"{PROG}: can't write {saved}: {exc.strerror or exc}")
            return EXIT_FAILED
    reporter.event("result", result)
    if not args.json:
        out.write(_summary(result))
        out.flush()
    return EXIT_PROBLEMS if any(has_problems(t) for t in result["targets"]) else EXIT_OK


def _run_record(
    plan: Plan, result: dict[str, Any], started: datetime, reporter: Reporter
) -> dict[str, Any]:
    """The run as Save Results… keeps it (replayModel.ReplayRun): as if the
    capture open in the viewer was a setup's, else the first one named; the
    others as ``files``."""
    paths = [str(p) for p, _ in plan.files]
    include_open = plan.open_capture is not None or plan.setup is None
    capture = str(plan.open_capture or paths[0])
    open_at = paths.index(capture) if include_open else 0
    files = paths[:open_at] + paths[open_at + 1 :] if include_open else paths
    flt = plan.files[open_at][1] if include_open else ""
    options = {**plan.options, "scope": "filter" if flt else "all"}
    return {
        "capture": capture,
        "started": started.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "ended": datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "options": options,
        "filter": flt,
        "files": files,
        "includeOpen": include_open,
        "openAt": open_at,
        "stopped": result["stopped"],
        "seconds": result["seconds"],
        "loops": result["loops"],
        "targets": result["targets"],
        "sources": result.get("sources", []),
        "log": reporter.log,
        "logOmitted": reporter.omitted,
    }


def _summary(result: dict[str, Any]) -> str:
    sent = sum(t["bytes"] for t in result["targets"])
    received = sum(t["received"] for t in result["targets"])
    head = (
        f"{'Stopped' if result['stopped'] else 'Done'} after {result['seconds']:.1f} s: "
        f"{_plural(result['loops'], 'loop')}, {size(sent)} sent, {size(received)} received"
    )
    lines = [head]
    for t in result["targets"]:
        mark = "!" if has_problems(t) else " "
        lines.append(f"{mark} {t['key']} → {t['to']}: {target_outcome(t)}")
        lines += [f"    error: {e}" for e in t["errors"]]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
