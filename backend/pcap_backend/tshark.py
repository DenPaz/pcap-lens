"""tshark/capinfos discovery, argument building and process helpers.

Security rule for this module: commands are always argv lists handed to
``subprocess.Popen`` without a shell. Nothing here ever builds a command
string.
"""

from __future__ import annotations

import atexit
import contextlib
import logging
import os
import re
import selectors
import shutil
import subprocess
import sys
import tempfile
import threading
import weakref
from collections.abc import Container, Generator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

from . import decryption, procs, wsprofile
from .cancellation import CancelledError, CancelToken
from .sandbox import permission_hint

log = logging.getLogger(__name__)

IS_WINDOWS = sys.platform == "win32"


class ToolNotFoundError(Exception):
    """A Wireshark command-line tool could not be located."""

    def __init__(self, tool: str, searched: list[str]) -> None:
        super().__init__(
            f"{tool} was not found. Install Wireshark (which provides {tool}) or set "
            f"'pcapViewer.tsharkPath'. Searched: {', '.join(searched) or '(nothing)'}"
        )
        self.tool = tool
        self.searched = searched


class ToolError(Exception):
    """tshark (or capinfos) failed in a way that produced no usable output."""

    def __init__(self, message: str, stderr: str = "", returncode: int | None = None) -> None:
        super().__init__(message)
        self.stderr = stderr
        self.returncode = returncode


class ConfigError(ValueError):
    """Invalid user configuration (decode-as rule, preference key, script path...)."""


# --------------------------------------------------------------------------- discovery


def _default_locations(exe: str) -> list[Path]:
    if IS_WINDOWS:
        roots = {
            os.environ.get("PROGRAMFILES", r"C:\Program Files"),
            os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
            os.environ.get("PROGRAMW6432", r"C:\Program Files"),
        }
        return [Path(r) / "Wireshark" / f"{exe}.exe" for r in sorted(roots)]
    if sys.platform == "darwin":
        return [
            Path("/Applications/Wireshark.app/Contents/MacOS") / exe,
            Path("/opt/homebrew/bin") / exe,
            Path("/usr/local/bin") / exe,
        ]
    return [Path("/usr/bin") / exe, Path("/usr/local/bin") / exe, Path("/snap/bin") / exe]


def find_tool(exe: str, configured: str | None = None, sibling_of: Path | None = None) -> Path:
    """Locate a Wireshark CLI tool.

    Order: explicit configuration, the directory of ``sibling_of`` (so capinfos is
    taken from the same install as tshark), ``PATH``, then default install
    locations for the current platform.
    """
    searched: list[str] = []
    if configured:
        p = Path(configured).expanduser()
        searched.append(str(p))
        if p.is_file():
            return p
        raise ToolNotFoundError(exe, searched)
    candidates: list[Path] = []
    if sibling_of is not None:
        name = f"{exe}.exe" if IS_WINDOWS else exe
        candidates.append(sibling_of.parent / name)
    on_path = shutil.which(exe)
    if on_path:
        candidates.append(Path(on_path))
    candidates += _default_locations(exe)
    for c in candidates:
        searched.append(str(c))
        if c.is_file():
            return c
    raise ToolNotFoundError(exe, searched)


# --------------------------------------------------------------------------- options

_DECODE_AS_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]*(==|:)[^,\s]+,[A-Za-z0-9_.\-]+$")
_PREF_KEY_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]*$")
# tshark refuses to start for an -o preference or a -d rule it can't use (the
# first one it meets), saying so in one of these ways.
# A UAT table this tshark lacks (``uat:maxmind_db_paths`` without MaxMind
# support, found on a Mac) is the second form.
_UNKNOWN_PREF_RE = re.compile(
    r'-o flag "((?:uat:)?[^":]+):.*"(?: specifies unknown preference|: Unknown preference)'
)
_UNKNOWN_DECODE_AS_RE = re.compile(
    r'Unknown protocol -- "(?P<proto>[^"]+)"|Unknown layer type -- (?P<layer>\S+)'
    r'|Invalid selector number "(?P<selector>[^"]*)"'
)
# A protocol's filter name (``_ws.expert``, ``ieee802.11``…) or a heuristic
# dissector's short name (``sip_sctp``).
_PROTOCOL_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]*$")


@dataclass(frozen=True, slots=True)
class DissectionOptions:
    """Options that change how tshark dissects packets.

    They are applied identically to *every* tshark invocation for a file so that
    the packet list, filters and detail views always agree.
    """

    lua_scripts: tuple[str, ...] = ()
    decode_as: tuple[str, ...] = ()
    prefs: tuple[tuple[str, str], ...] = ()
    # Name resolution as ``-N`` letters ("" = ``-n``); None leaves tshark's own
    # preferences (see name_flags).
    names: str | None = None
    # A Wireshark configuration profile (``-C``; "" = the Default profile).
    profile: str = ""
    # Protocols (filter names) and heuristic dissectors (short names) switched
    # on (True) or off (False), whatever Wireshark's own settings say.
    protocols: tuple[tuple[str, bool], ...] = ()
    heuristics: tuple[tuple[str, bool], ...] = ()
    # Decryption keys and GeoIP databases as further ``-o`` options
    # (decryption.py; not in the repr: they hold secrets), and the files they
    # name (the saved-index key fingerprints them).
    secrets: tuple[tuple[str, str], ...] = field(default=(), repr=False)
    files: tuple[str, ...] = ()
    # The GeoIP database folders (also in ``secrets`` as maxmind_db_paths):
    # the Endpoints statistics read them too.
    geoip: tuple[str, ...] = ()

    @classmethod
    def from_params(
        cls,
        lua: Sequence[str] = (),
        decode_as: Sequence[str] = (),
        prefs: Mapping[str, object] | None = None,
        names: Mapping[str, object] | None = None,
        profile: str = "",
        protocols: Mapping[str, object] | None = None,
        heuristics: Mapping[str, object] | None = None,
        keys: Sequence[object] = (),
        geoip: Sequence[str] = (),
    ) -> DissectionOptions:
        if profile and not wsprofile.valid_name(profile):
            raise ConfigError(f"invalid Wireshark profile name {profile!r}")
        for rule in decode_as:
            if not _DECODE_AS_RE.match(rule):
                raise ConfigError(
                    f"invalid Decode As rule {rule!r}; expected e.g. 'tcp.port==8080,http'"
                )
        pref_items: list[tuple[str, str]] = []
        for key, value in (prefs or {}).items():
            if not _PREF_KEY_RE.match(key):
                raise ConfigError(f"invalid preference name {key!r}")
            text = _pref_value(value)
            if "\n" in text or "\r" in text:
                raise ConfigError(f"preference {key!r} must be a single line")
            pref_items.append((key, text))
        flags = name_flags(names) if names is not None else None
        try:
            secrets, files = decryption.options(keys, geoip)
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
        return cls(
            tuple(lua),
            tuple(decode_as),
            tuple(sorted(pref_items)),
            flags,
            profile,
            _switches("protocol", protocols),
            _switches("heuristic dissector", heuristics),
            secrets,
            files,
            tuple(geoip),
        )

    @property
    def resolves_addresses(self) -> bool:
        """Source/Destination may show names instead of addresses."""
        return self.names is None or "m" in self.names or "n" in self.names

    def args(self, profile: bool = True) -> list[str]:
        """tshark's options for these settings (``profile=False``: without
        ``-C``, for a pass whose configuration folder holds the profile's files)."""
        out: list[str] = ["-C", self.profile] if self.profile and profile else []
        if self.names is not None:
            out += ["-N", self.names] if self.names else ["-n"]
        for script in self.lua_scripts:
            out += ["-X", f"lua_script:{script}"]
        for rule in self.decode_as:
            out += ["-d", rule]
        for key, value in self.prefs:
            out += ["-o", f"{key}:{value}"]
        for name, on in self.protocols:
            out += ["--enable-protocol" if on else "--disable-protocol", name]
        for name, on in self.heuristics:
            out += ["--enable-heuristic" if on else "--disable-heuristic", name]
        for key, value in self.secrets:
            out += ["-o", f"{key}:{value}"]
        return out

    def without(self, refused: tuple[str, str]) -> tuple[DissectionOptions, str]:
        """These options without the preference or Decode As rule tshark
        refused (``Tshark.refused_option``), and a warning saying so."""
        kind, item = refused
        if kind == "pref":
            return replace(self, prefs=tuple(p for p in self.prefs if p[0] != item)), (
                f"Unknown preference {item!r} in pcapViewer.prefs: ignored"
            )
        if kind == "secret":
            # (A build without the library behind it: MaxMind, GnuTLS…)
            kept = replace(self, secrets=tuple(s for s in self.secrets if s[0] != item))
            if item == "uat:maxmind_db_paths":
                return kept, (
                    "This tshark has no GeoIP (MaxMind) support: packets get no ip.geoip"
                    " fields (the Endpoints statistics still show locations)"
                )
            return (
                kept,
                f"This tshark doesn't support {item}: the decryption keys for it are ignored",
            )
        return replace(self, decode_as=tuple(r for r in self.decode_as if r != item)), (
            f"Decode As rule {item!r} names something tshark doesn't know: ignored"
        )

    def without_unknown(
        self, protocols: Container[str], heuristics: Container[str]
    ) -> tuple[DissectionOptions, list[str]]:
        """These options without the protocols and heuristic dissectors tshark
        doesn't know (it refuses to start for one), and a warning for each."""
        warnings = [
            f"Unknown protocol {name!r} in pcapViewer.enabledProtocols: ignored"
            for name, _ in self.protocols
            if name not in protocols
        ] + [
            f"Unknown heuristic dissector {name!r} in pcapViewer.heuristicDissectors: ignored"
            for name, _ in self.heuristics
            if name not in heuristics
        ]
        if not warnings:
            return self, []
        return replace(
            self,
            protocols=tuple(p for p in self.protocols if p[0] in protocols),
            heuristics=tuple(h for h in self.heuristics if h[0] in heuristics),
        ), warnings

    def check_scripts(self) -> list[str]:
        """Return warnings for Lua scripts and key log files tshark would silently ignore."""
        warnings = [f"Lua script not found: {s}" for s in self.lua_scripts if not Path(s).is_file()]
        for key, value in self.prefs:
            if key.endswith(".keylog_file") and value and not Path(value).is_file():
                warnings.append(f"Key log file not found ({key}): {value}")
        warnings += [f"File not found: {f}" for f in self.files if not Path(f).exists()]
        if self.lua_scripts and hasattr(os, "geteuid") and os.geteuid() == 0:
            warnings.append(
                "tshark disables Lua dissectors when running as root; Lua scripts were not loaded"
            )
        return warnings


# Name resolution switches (the host's pcapViewer.nameResolution.* settings) and
# their ``-N`` letters. "external" (N: ask the system's DNS resolver) only works
# with "network" (n); without it names come from the capture's DNS answers (d)
# and hosts files.
_NAME_FLAGS = (("mac", "m"), ("network", "n"), ("capturedDns", "d"), ("external", "N"),
               ("transport", "t"))  # fmt: skip


def name_flags(names: Mapping[str, object]) -> str:
    """``-N`` letters for name resolution switches ("" = none, i.e. ``-n``)."""
    unknown = set(names) - {key for key, _ in _NAME_FLAGS}
    if unknown:
        raise ConfigError(f"unknown name resolution option(s): {', '.join(sorted(unknown))}")
    on = {key for key, _ in _NAME_FLAGS if names.get(key) is True}
    if "network" not in on:
        on -= {"capturedDns", "external"}
    return "".join(letter for key, letter in _NAME_FLAGS if key in on)


def _switches(what: str, raw: Mapping[str, object] | None) -> tuple[tuple[str, bool], ...]:
    """``{name: true|false}`` settings as sorted (name, on) pairs, checked."""
    out: list[tuple[str, bool]] = []
    for name, on in (raw or {}).items():
        if not _PROTOCOL_NAME_RE.match(name) or not isinstance(on, bool):
            raise ConfigError(f"invalid {what} setting {name!r}: expected a name and true/false")
        out.append((name, on))
    return tuple(sorted(out))


def _pref_value(value: object) -> str:
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    return str(value)


# --------------------------------------------------------------------------- processes

_NOISE = ("Running as user", "This could be dangerous")

# Wireshark's own diagnostics of its tables, logged through wslog ("** (tshark:
# 123) 22:30:01.1 [WSUtil WARNING] …/value_string.c:476 -- _try_val_to_str_
# ext_init(): Extended value string 'mcc_mnc_codes' forced to fall back to
# linear search: …", tshark 4.6.8 with a 5G capture; "[Epan WARNING]" before
# value_string.c moved to wsutil). Nothing about the capture or the settings,
# and nothing the user can change, so they go to the log instead of a warning.
_INTERNAL_DIAGNOSTIC = re.compile(
    r"^\*\* \(\S+:\d+\) .*\[\w+ [A-Z]+\].*\b(?:Extended value string|_val_to_str_ext_init)"
)
_logged_diagnostics: set[str] = set()


def clean_stderr(text: str) -> str:
    """Strip tshark's harmless root warning, its internal table diagnostics
    (logged once each) and blank lines."""
    lines: list[str] = []
    diagnostic: list[str] = []  # one being read: its indented lines follow it
    for ln in [*text.splitlines(), ""]:
        if diagnostic and ln[:1].isspace() and ln.strip():
            diagnostic.append(ln.strip())
            continue
        if diagnostic:
            _log_diagnostic(" ".join(diagnostic))
            diagnostic = []
        if not ln.strip() or any(n in ln for n in _NOISE):
            continue
        if _INTERNAL_DIAGNOSTIC.match(ln):
            diagnostic = [ln.split("] ", 1)[-1]]
            continue
        lines.append(ln)
    return "\n".join(lines)


def _log_diagnostic(message: str) -> None:
    if message not in _logged_diagnostics:  # (stderr is cleaned more than once)
        _logged_diagnostics.add(message)
        log.info("tshark's own diagnostic (not shown as a warning): %s", message)


# Why a tool's exit code means it crashed: a signal on POSIX (a negative
# code; numbered here, since Windows' signal module numbers SIGABRT 22), an
# exception's NTSTATUS on Windows.
_CRASH_SIGNALS = {
    11: "a segmentation fault",
    10 if sys.platform == "darwin" else 7: "a bus error",
    6: "a failed internal check",
    8: "an arithmetic error",
    4: "an illegal instruction",
}
_CRASH_STATUSES = {
    0xC0000005: "an access violation",
    0xC00000FD: "a stack overflow",
    0xC0000409: "a failed internal check",
}
CRASH_HINT = (
    "That is a bug in tshark (Wireshark's dissectors), not in the capture or PCAP Lens: "
    "a newer Wireshark may read it."
)
# SIGKILL from outside (PCAP Lens's own kills end as cancelled): most often
# the system out of memory; some fuzzed captures take tshark past 10 GB.
KILLED_HINT = (
    "Something outside PCAP Lens killed it, most often the system when it runs out of memory."
)


def crash(returncode: int | None) -> str | None:
    """What crashed a tool ("a segmentation fault"), or None when its exit
    code isn't a crash (an error, or killed by SIGKILL/SIGTERM)."""
    if returncode is None:
        return None
    if returncode < 0:
        return _CRASH_SIGNALS.get(-returncode)
    return _CRASH_STATUSES.get(returncode)


_ENDS_EARLY_RE = re.compile(r"cut short in the middle of a packet|appears to be damaged or corrupt")


def failed(returncode: int | None, stderr: str) -> bool:
    """Whether a pass that wrote nothing failed. tshark exits with 2 when the
    capture ends in the middle of a packet or is damaged further on, after
    reading the packets before that (the ones the viewer shows): when that
    is all it says, the pass just found nothing in them."""
    if returncode in (0, None):
        return False
    said = [ln for ln in clean_stderr(stderr).split("\n") if not ln.startswith("(")]
    return not said or not all(_ENDS_EARLY_RE.search(ln) for ln in said)


def broke(returncode: int | None, stderr: str, wrote: bool) -> bool:
    """Whether the output of a pass read to its end can't be used: tshark
    crashed or was killed, even after writing some (the rest is missing: a
    replay of rtcp_coverage.pcap.gz sent half its bytes when tshark 4.6 died
    partway through the pass reading it), or it failed without writing
    anything (``failed``). A kill of the backend's own (a cancel, shutdown)
    never gets here: stream_lines and run raise CancelledError for it, so a
    signal is someone else's (an out-of-memory killer, the real-capture
    harness's memory watch, a user). A pass that stops tshark early on
    purpose has its own check."""
    killed = returncode is not None and returncode < 0
    return killed or crash(returncode) is not None or (not wrote and failed(returncode, stderr))


class ProcessRegistry:
    """Every live child process, so shutdown can guarantee no orphans."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._procs: set[subprocess.Popen[bytes]] = set()
        # Children kill_all stopped: their output was cut off, not finished
        # (weak, so a reaped child doesn't stay here).
        self._killed: weakref.WeakSet[subprocess.Popen[bytes]] = weakref.WeakSet()

    def add(self, proc: subprocess.Popen[bytes]) -> None:
        with self._lock:
            self._procs.add(proc)

    def discard(self, proc: subprocess.Popen[bytes]) -> None:
        with self._lock:
            self._procs.discard(proc)

    def kill_all(self) -> None:
        """Kill every child (shutdown). A child that can't be signalled (AppArmor) is
        stopped by the thread that owns it, which closes its pipes and reaps it."""
        with self._lock:
            live = list(self._procs)
            self._procs.clear()
            self._killed.update(live)
        for proc in live:
            if procs.kill_process(proc):
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=2)

    def __len__(self) -> int:
        with self._lock:
            return sum(1 for p in self._procs if p.poll() is None)

    def was_killed(self, proc: subprocess.Popen[bytes]) -> bool:
        """Whether kill_all stopped ``proc`` (its output ended early)."""
        with self._lock:
            return proc in self._killed


PROCESSES = ProcessRegistry()


def tool_env(env: Mapping[str, str] | None = None) -> dict[str, str]:
    """``env`` (default: ours) with C number formatting for a Wireshark tool.

    tshark formats and reads numbers by the locale: in pt_BR "1.175 bytes",
    "0,000000" and a refused ``-z io,stat,0.5``, which no parser here reads.
    LC_NUMERIC=C keeps the user's language and character set for the rest;
    LC_ALL would override it, so its value moves to LANG (the other LC_*
    variables go: LC_ALL overrode them too). Windows ignores these variables
    (tshark takes the user's regional settings there: see decimal_comma).
    """
    out = dict(os.environ if env is None else env)
    every = out.pop("LC_ALL", "")
    if every:
        for name in [n for n in out if n.startswith("LC_")]:
            del out[name]
        out["LANG"] = every
    out["LC_NUMERIC"] = "C"
    return out


def _popen(
    argv: Sequence[str], env: Mapping[str, str] | None = None, stdin: int | None = None
) -> subprocess.Popen[bytes]:
    # No console window flashing up for every tshark run on Windows.
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if IS_WINDOWS else 0
    return subprocess.Popen(
        list(argv),
        stdin=subprocess.DEVNULL if stdin is None else stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=flags,
        env=tool_env(env),
    )


@dataclass(slots=True)
class RunResult:
    returncode: int
    stdout: bytes
    stderr: str


@dataclass(slots=True)
class StreamResult:
    """Filled in once a streamed run finishes."""

    returncode: int | None = None
    stderr: str = ""
    lines: int = 0
    warnings: list[str] = field(default_factory=list)


class _StderrCollector(threading.Thread):
    def __init__(self, proc: subprocess.Popen[bytes]) -> None:
        super().__init__(daemon=True)
        self._proc = proc
        self.chunks: list[bytes] = []

    def run(self) -> None:
        assert self._proc.stderr is not None
        for chunk in iter(lambda: self._proc.stderr.read(65536), b""):  # type: ignore[union-attr]
            if sum(len(c) for c in self.chunks) < 1 << 20:  # cap at 1 MiB
                self.chunks.append(chunk)

    @property
    def text(self) -> str:
        return clean_stderr(b"".join(self.chunks).decode("utf-8", "replace"))


# What run() keeps of a child's stdout. Every report it parses is far
# smaller; past this a dissector loops: tshark 4.6's expert reports of
# Wireshark's openflow_v5/v6_coverage captures took the backend to 2-5.6 GB
# (the real-capture harness only watches tshark's own memory).
MAX_OUTPUT_BYTES = 256 << 20


def run(
    argv: Sequence[str],
    token: CancelToken | None = None,
    env: Mapping[str, str] | None = None,
    max_bytes: int | None = None,
) -> RunResult:
    """Run a command to completion, capturing output. Cancellable via ``token``.

    ``env`` replaces the environment when given (defaults to inheriting ours).
    stdout is kept up to ``max_bytes`` (MAX_OUTPUT_BYTES): past that the child
    is stopped and a ToolError says so. stderr keeps its first MiB.
    """
    limit = MAX_OUTPUT_BYTES if max_bytes is None else max_bytes
    token = token or CancelToken()
    proc = _popen(argv, env)
    PROCESSES.add(proc)
    collector = _StderrCollector(proc)
    collector.start()
    out = bytearray()
    try:
        token.register(proc)  # kills the process if the token is already cancelled
        try:
            for chunk in _chunks(proc, token):
                out += chunk
                if len(out) > limit:
                    break
            else:
                _exited_cleanly(proc, token)  # (waits for it, a cancel stops the wait)
        finally:
            token.unregister(proc)
    finally:
        # Stops it if it's still running (too much output or a cancel), reaps
        # it or leaves it to a reaper, and closes its pipes.
        procs.stop_process(proc, [collector], on_reaped=lambda: PROCESSES.discard(proc))
    token.raise_if_cancelled()
    stderr = collector.text
    if len(out) > limit:
        raise ToolError(
            f"{Path(argv[0]).name} wrote more than {limit >> 20} MB, which usually means a"
            " dissector looping; it was stopped",
            stderr,
            proc.returncode,
        )
    return RunResult(proc.returncode, bytes(out), stderr)


def stream_lines(
    argv: Sequence[str],
    result: StreamResult,
    token: CancelToken | None = None,
    env: Mapping[str, str] | None = None,
    stdin: int | None = None,
) -> Generator[bytes]:
    """Yield stdout lines (with trailing newline stripped) as the process runs.

    ``result`` receives the exit code and stderr when the generator finishes.
    Closing the generator early kills the process. ``env`` replaces the
    environment when given. ``stdin`` is a file descriptor the child reads
    (e.g. a live capture's pipe); it is closed here once the child has it.
    """
    token = token or CancelToken()
    try:
        proc = _popen(argv, env, stdin)
    finally:
        if stdin is not None:
            os.close(stdin)
    PROCESSES.add(proc)
    collector = _StderrCollector(proc)
    collector.start()
    lines = _lines(proc, token)
    try:
        token.register(proc)
        for line in lines:
            result.lines += 1
            yield line
        if not token.cancelled:
            proc.wait()  # end of output: let it exit on its own (keeps its exit code)
    finally:
        lines.close()
        token.unregister(proc)
        # Stops it if it's still running (an early exit or a cancel), reaps it or
        # leaves it to a reaper if it can't be stopped, and closes its pipes.
        procs.stop_process(proc, [collector], on_reaped=lambda: PROCESSES.discard(proc))
        result.returncode = proc.returncode
        result.stderr = collector.text
    # A child killed at shutdown ends its output early: that is not the end
    # of the capture (an index pass must not be saved as complete).
    if token.cancelled or PROCESSES.was_killed(proc):
        raise CancelledError("request cancelled")


def _lines(proc: subprocess.Popen[bytes], token: CancelToken) -> Generator[bytes]:
    """stdout lines without the line break; stops early once ``token`` is cancelled.

    A last line without its line break is passed on only when the child exits
    with 0: a tshark that crashed mid-line (Wireshark's pfcp_coverage under
    4.6) left "48" of "488\t…", which the index pass read as packet 48.
    """

    # (Windows: a child's text-mode stdout writes "\r\n" as "\r\r\n".)
    def strip(line: bytes) -> bytes:
        return line.rstrip(b"\r") if IS_WINDOWS else line.removesuffix(b"\r")

    pending = b""
    for chunk in _chunks(proc, token):
        lines = (pending + chunk).split(b"\n")
        pending = lines.pop()
        for line in lines:
            yield strip(line)
    if pending and not token.cancelled and _exited_cleanly(proc, token):
        yield strip(pending)


def _chunks(proc: subprocess.Popen[bytes], token: CancelToken) -> Generator[bytes]:
    """stdout as it comes; stops early once ``token`` is cancelled.

    On POSIX the pipe is polled, so a cancel is noticed within POLL_INTERVAL
    even when the child writes nothing and can't be killed (AppArmor). Windows
    can't poll pipes, but there the kill always works and ends the read.
    """
    assert proc.stdout is not None
    if IS_WINDOWS:
        while not token.cancelled:
            chunk = proc.stdout.read1(1 << 16)  # type: ignore[attr-defined]
            if not chunk:
                return
            yield chunk
        return
    fd = proc.stdout.fileno()
    with selectors.DefaultSelector() as sel:
        sel.register(fd, selectors.EVENT_READ)
        while not token.cancelled:
            if not sel.select(procs.POLL_INTERVAL):
                continue
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                return
            yield chunk


def _exited_cleanly(proc: subprocess.Popen[bytes], token: CancelToken) -> bool:
    """Whether a child whose output just ended exits with 0 (its output is
    over, so it is exiting; a cancel stops the wait)."""
    while not token.cancelled:
        try:
            return proc.wait(timeout=procs.POLL_INTERVAL) == 0
        except subprocess.TimeoutExpired:
            continue
    return False


# --------------------------------------------------------------------------- tshark


# Minimal valid libpcap header (Ethernet link type); used to compile filters
# without reading the user's capture.
_EMPTY_PCAP = bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000")


class _EmptyCapture:
    """One shared empty capture file per process, removed at exit."""

    def __init__(self) -> None:
        self._path: Path | None = None
        self._lock = threading.Lock()
        atexit.register(self.remove)

    def get(self) -> Path:
        with self._lock:
            if self._path is None or not self._path.exists():
                fd, name = tempfile.mkstemp(prefix="pcapviewer-empty-", suffix=".pcap")
                with os.fdopen(fd, "wb") as fh:
                    fh.write(_EMPTY_PCAP)
                self._path = Path(name)
            return self._path

    def remove(self) -> None:
        with self._lock:
            if self._path is not None:
                self._path.unlink(missing_ok=True)
                self._path = None


EMPTY_CAPTURE = _EmptyCapture()

_FOLDERS: dict[Path, str] = {}
_DECIMAL_COMMA: dict[Path, bool] = {}
_FOLDERS_LOCK = threading.Lock()


class Tshark:
    """A located tshark binary plus the dissection options for one capture."""

    def __init__(
        self,
        path: Path,
        options: DissectionOptions | None = None,
        capinfos: Path | None = None,
    ) -> None:
        self.path = path
        self.options = options or DissectionOptions()
        self.capinfos = capinfos

    @classmethod
    def locate(
        cls,
        tshark_path: str | None = None,
        capinfos_path: str | None = None,
        options: DissectionOptions | None = None,
    ) -> Tshark:
        tshark = find_tool("tshark", tshark_path)
        try:
            capinfos: Path | None = find_tool("capinfos", capinfos_path, sibling_of=tshark)
        except ToolNotFoundError:
            capinfos = None
        return cls(tshark, options, capinfos)

    def with_options(self, options: DissectionOptions) -> Tshark:
        return Tshark(self.path, options, self.capinfos)

    def argv(self, *args: str, capture: str | None = None, dissect: bool = True) -> list[str]:
        """Build a tshark argv. Dissection options are always included when dissecting."""
        out = [str(self.path)]
        if dissect:
            out += self.options.args()
        if capture is not None:
            out += ["-r", capture]
        out += list(args)
        return out

    def field_list(self, token: CancelToken | None = None) -> str:
        """``tshark -G fields`` output, including fields of the configured Lua scripts."""
        return "\n".join(self.glossary("fields", token))

    def glossary(self, report: str, token: CancelToken | None = None) -> list[str]:
        """``tshark -G <report>`` output, plus the same report with the configured
        Lua scripts loaded (their fields, their preferences).

        ``-G`` must be tshark's first option and ignores ``-X lua_script:``, so
        the Lua scripts are copied into a temporary plugin folder and a second
        run is made with ``WIRESHARK_PLUGIN_DIR`` pointing at it. That run
        replaces the global plugin folder, so the normal run is kept too and
        the caller merges both.
        """
        argv = [str(self.path), "-G", report]
        outputs = [run(argv, token).stdout.decode("utf-8", "replace")]
        scripts = [Path(s) for s in self.options.lua_scripts if Path(s).is_file()]
        if scripts:
            with tempfile.TemporaryDirectory(prefix="pcapviewer-lua-") as tmp:
                for i, script in enumerate(scripts):
                    # Numbered copies keep load order and avoid name clashes.
                    shutil.copyfile(script, Path(tmp) / f"{i:03d}_{script.name}")
                env = {**os.environ, "WIRESHARK_PLUGIN_DIR": tmp}
                res = run(argv, token, env=env)
                outputs.append(res.stdout.decode("utf-8", "replace"))
        return outputs

    def folders(self, token: CancelToken | None = None) -> str:
        """``tshark -G folders`` output (configuration and plugin locations), cached."""
        with _FOLDERS_LOCK:
            cached = _FOLDERS.get(self.path)
        if cached is None:
            cached = run([str(self.path), "-G", "folders"], token).stdout.decode("utf-8", "replace")
            with _FOLDERS_LOCK:
                _FOLDERS[self.path] = cached
        return cached

    def profile_config(self, token: CancelToken | None = None) -> tuple[str, Path] | None:
        """The Wireshark profile in use (``-C``) and its folder, or None."""
        name = self.options.profile
        if not name:
            return None
        personal, global_ = wsprofile.config_folders(self.folders(token))
        folder = wsprofile.profile_dir(personal, global_, name)
        if folder is None:
            raise ConfigError(f'Wireshark profile "{name}" does not exist')
        return name, folder

    def error(self, stderr: str, returncode: int | None, default: str) -> ToolError:
        """A ToolError for a failed run, explaining crashes and sandbox
        permission problems."""
        message = stderr or default
        if what := crash(returncode):
            message = f"tshark crashed ({what}) while reading this capture. {CRASH_HINT}"
            if stderr.strip():
                message += f"\n\n{stderr.strip()}"
        elif returncode == -9:  # (SIGKILL; not numbered on Windows)
            message = f"tshark was killed (signal 9) while reading this capture. {KILLED_HINT}"
            if stderr.strip():
                message += f"\n\n{stderr.strip()}"
        hint = permission_hint(self.path, stderr)
        if hint:
            message = f"{message}\n\n{hint}"
        return ToolError(message, stderr, returncode)

    def decimal_comma(self, token: CancelToken | None = None) -> bool:
        """Whether this tshark writes and reads numbers with a decimal comma.

        tool_env makes it a point on macOS and Linux, but on Windows tshark
        takes the user's regional settings (``setlocale(LC_ALL, ".UTF-8")``)
        and ignores LC_*. In a comma locale it refuses ``-z io,stat,0.5``
        (sscanf stops at the point), which is the question asked, once per
        tshark. Its reports' number cells then hold decimal commas, which
        the parsers read (``stats._point``); names and messages are left as
        they are. (No thousands separators there: Windows' printf lacks "%'".)
        """
        with _FOLDERS_LOCK:
            cached = _DECIMAL_COMMA.get(self.path)
        if cached is None:
            argv = [str(self.path), "-r", str(EMPTY_CAPTURE.get()), "-q", "-z", "io,stat,0.5"]
            res = run(argv, token)
            cached = res.returncode != 0 and "io,stat" in res.stderr
            with _FOLDERS_LOCK:
                _DECIMAL_COMMA[self.path] = cached
        return cached

    def decimal(self, value: float, token: CancelToken | None = None) -> str:
        """``value`` as this tshark reads a number (``0.5``, or ``0,5`` in a
        comma locale: io,stat's interval)."""
        text = f"{value:g}"
        return text.replace(".", ",") if self.decimal_comma(token) else text

    def version(self) -> str:
        res = run([str(self.path), "--version"])
        first = res.stdout.decode("utf-8", "replace").splitlines()
        return first[0].strip() if first else "unknown"

    def refused_option(self, token: CancelToken | None = None) -> tuple[str, str] | None:
        """The first preference (``("pref", key)``), decryption key or GeoIP
        table (``("secret", key)``) or Decode As rule (``("decodeAs", rule)``)
        of the options that this tshark, with their Lua scripts and profile,
        refuses to start with; None if there is none (or tshark fails for
        another reason, which the caller then meets)."""
        res = run(self.argv(capture=str(EMPTY_CAPTURE.get())), token)
        if res.returncode == 0:
            return None
        if found := _UNKNOWN_PREF_RE.search(res.stderr):
            key = found.group(1)
            if key in {k for k, _ in self.options.prefs}:
                return ("pref", key)
            return ("secret", key) if key in {k for k, _ in self.options.secrets} else None
        if found := _UNKNOWN_DECODE_AS_RE.search(res.stderr):
            for rule in self.options.decode_as:
                layer, _, rest = re.split(r"(==|:)", rule, maxsplit=1)
                selector, _, proto = rest.rpartition(",")
                if (
                    (found["proto"] is not None and proto == found["proto"])
                    or (found["layer"] is not None and layer == found["layer"])
                    or (found["selector"] is not None and selector == found["selector"])
                ):
                    return ("decodeAs", rule)
        return None

    def validate_filter(self, expr: str, token: CancelToken | None = None) -> str | None:
        """Return ``None`` if ``expr`` compiles, else tshark's error message."""
        if not expr.strip():
            return None
        res = run(self.argv("-Y", expr, capture=str(EMPTY_CAPTURE.get())), token)
        if res.returncode == 0:
            return None
        msg = res.stderr.strip()
        return msg.removeprefix("tshark: ") if msg else f"invalid filter (exit {res.returncode})"
