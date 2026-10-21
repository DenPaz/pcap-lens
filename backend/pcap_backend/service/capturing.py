"""Live capture: dumpcap's interfaces, capture filters, starting and stopping."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from pcap_backend import extcap
from pcap_backend.capture import (
    CaptureOptions,
    FileCapture,
    FileOptions,
    capture_command,
    capture_error,
    dumpcap_command,
    filter_problem,
    parse_interfaces,
)
from pcap_backend.protocol import InvalidParamsError, RequestContext, param, str_list
from pcap_backend.tshark import ToolError, run

from .opening import OpeningMixin


def _positive[T: (int, float)](params: dict[str, Any], key: str, kind: type[T]) -> T | None:
    """An optional positive number parameter (None when absent or 0)."""
    raw = params.get(key)
    if raw is None or raw == 0:
        return None
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise InvalidParamsError(f"{key} must be a number")
    if kind is int and not float(raw).is_integer():
        raise InvalidParamsError(f"{key} must be a whole number")
    if raw < 0:
        raise InvalidParamsError(f"{key} must be positive")
    return kind(raw)


def _extcap_options(raw: Any, interfaces: tuple[str, ...]) -> dict[str, dict[str, str]]:
    """capture_start's ``extcap``: ``{interface: {"--option": "value"}}`` for the
    extcap interfaces among ``interfaces`` (an empty object for one without
    options). Values are single lines: they become ``-o`` preferences."""
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise InvalidParamsError("extcap must be an object")
    out: dict[str, dict[str, str]] = {}
    for name, values in raw.items():
        if name not in interfaces:
            raise InvalidParamsError(f"extcap names {name!r}, which isn't one of the interfaces")
        if not isinstance(values, dict):
            raise InvalidParamsError(f"extcap.{name} must be an object")
        opts: dict[str, str] = {}
        for call, value in values.items():
            if not isinstance(call, str) or not extcap.CALL_RE.match(call):
                raise InvalidParamsError(f"extcap.{name}: {call!r} isn't an option like --name")
            if not isinstance(value, (str, int, float)):
                raise InvalidParamsError(f"extcap.{name}.{call} must be a string")
            text = ("true" if value else "false") if isinstance(value, bool) else str(value)
            if any(c in text for c in "\r\n\0"):
                raise InvalidParamsError(f"extcap.{name}.{call} must be one line")
            opts[call] = text
        out[name] = opts
    return out


def _capture_options(params: dict[str, Any]) -> CaptureOptions:
    """The interfaces and options shared by capture_start and capture_to_files."""
    interfaces = tuple(str_list(params, "interfaces"))
    if not interfaces or any(not i.strip() for i in interfaces):
        raise InvalidParamsError("interfaces must name at least one interface")
    limits = param(params, "limits", dict, {})
    return CaptureOptions(
        interfaces=interfaces,
        capture_filter=param(params, "filter", str, "").strip(),
        packets=_positive(limits, "packets", int),
        seconds=_positive(limits, "seconds", float),
        max_bytes=_positive(limits, "bytes", int),
        promiscuous=bool(params.get("promiscuous", True)),
        snaplen=_positive(params, "snaplen", int),
        extcap=_extcap_options(params.get("extcap"), interfaces),
    )


_BAD_NAME = re.compile(r'[\\/:*?"<>|\x00-\x1f]')


def _file_options(params: dict[str, Any]) -> FileOptions:
    """capture_to_files' ``folder``, ``name``, ``format`` and ``files: {switchBytes,
    switchSeconds, switchPackets, ring, stopAfter}``."""
    folder = Path(param(params, "folder", str)).expanduser()
    if not folder.is_absolute():
        raise InvalidParamsError("folder must be an absolute path")
    name = param(params, "name", str).strip()
    if not name or _BAD_NAME.search(name) or name in {".", ".."}:
        raise InvalidParamsError("name must be a file name (no folders or special characters)")
    fmt = param(params, "format", str, "pcapng")
    if fmt not in {"pcapng", "pcap"}:
        raise InvalidParamsError("format must be pcapng or pcap")
    files = param(params, "files", dict, {})
    options = FileOptions(
        folder=folder,
        name=name,
        pcap=fmt == "pcap",
        switch_bytes=_positive(files, "switchBytes", int),
        switch_seconds=_positive(files, "switchSeconds", int),
        switch_packets=_positive(files, "switchPackets", int),
        ring_files=_positive(files, "ring", int),
        stop_files=_positive(files, "stopAfter", int),
    )
    if (options.ring_files or options.stop_files) and not options.switches:
        raise InvalidParamsError(
            "a ring buffer or a number of files needs a new file every so many bytes, seconds "
            "or packets"
        )
    return options


class CaptureMixin(OpeningMixin):
    """Live capture: dumpcap's interfaces, capture filters, starting and stopping."""

    def list_interfaces(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """The interfaces dumpcap can capture on (``dumpcap -D -M``), then the
        extcap helpers' (``extcap: true``, with ``helper`` = the program's
        name; ``extcap: false`` in the params leaves them out): those that
        ``tshark -D`` lists too, since tshark is what runs them (it can leave
        out a helper our scan of its folders finds). A dumpcap that lists
        nothing is only an error when no helper offers an interface."""
        tshark = self._require_tshark()
        command = dumpcap_command(tshark.path)
        want_extcap = params.get("extcap", True)
        helpers = self._pool.submit(self._extcap_helpers, ctx) if want_extcap else None
        tshark_d = [str(tshark.path), "-D"]
        listed = self._pool.submit(run, tshark_d, ctx.token) if want_extcap else None
        res = run([*command, "-D", "-M"], ctx.token)
        interfaces = [i.to_json() for i in parse_interfaces(res.stdout.decode("utf-8", "replace"))]
        if helpers is not None and listed is not None:
            shown = listed.result()
            # (Only when tshark could list: without Npcap, Windows' tshark -D fails.)
            names = extcap.listed_names(shown.stdout.decode()) if shown.returncode == 0 else None
            for helper in helpers.result():
                for value, display in helper.interfaces:
                    if names is not None and value not in names:
                        continue
                    interfaces.append(
                        {
                            "name": value,
                            "description": display,
                            "addresses": [],
                            "loopback": False,
                            "extcap": True,
                            "helper": helper.path.name,
                        }
                    )
        if res.returncode != 0 and not interfaces:
            raise capture_error(res.stderr, res.returncode, "dumpcap could not list interfaces")
        return {"interfaces": interfaces}

    def _extcap_helpers(self, ctx: RequestContext) -> list[extcap.Helper]:
        """The extcap helpers tshark would run, remembered by interface for
        ``extcap_config``."""
        tshark = self._require_tshark()
        as_root = hasattr(os, "geteuid") and os.geteuid() == 0
        folders = extcap.extcap_folders(tshark.folders(ctx.token), as_root)
        helpers = extcap.find_helpers(extcap.helper_files(folders), ctx.token)
        with self._lock:
            self._extcap_tools = {name: h.path for h in helpers for name, _ in h.interfaces}
        return helpers

    def extcap_config(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """An extcap interface's options (``--extcap-config``): ``{interface,
        args: [{number, call, display, type, default?, tooltip?, required,
        group?, range?, values}]}``."""
        interface = param(params, "interface", str)
        with self._lock:
            tool = self._extcap_tools.get(interface)
        if tool is None:
            self._extcap_helpers(ctx)
            with self._lock:
                tool = self._extcap_tools.get(interface)
        if tool is None:
            raise InvalidParamsError(f"no extcap helper offers the interface {interface!r}")
        res = run([str(tool), "--extcap-interface", interface, "--extcap-config"], ctx.token)
        if res.returncode != 0:
            message = res.stderr.strip() or f"{tool.name} exited with code {res.returncode}"
            raise ToolError(message, res.stderr, res.returncode)
        return {
            "interface": interface,
            "helper": tool.name,
            "args": extcap.parse_config(res.stdout.decode("utf-8", "replace")),
        }

    def validate_capture_filter(
        self, params: dict[str, Any], ctx: RequestContext
    ) -> dict[str, Any]:
        """Compile a capture (BPF) filter for an interface (``dumpcap -d``).
        ``checked: false`` when dumpcap couldn't try (e.g. no permission to
        open the interface): the capture itself then reports the problem."""
        expr = param(params, "filter", str, "").strip()
        interface = param(params, "interface", str)
        if not expr:
            return {"valid": True, "checked": True}
        command = dumpcap_command(self._require_tshark().path)
        res = run([*command, "-i", interface, "-f", expr, "-d"], ctx.token)
        problem = filter_problem(res.stderr)
        if problem:
            return {"valid": False, "checked": True, "error": problem}
        if res.returncode != 0 or "dumpcap: " in res.stderr:
            message = capture_error(res.stderr, res.returncode, "dumpcap failed").args[0]
            return {"valid": True, "checked": False, "message": message}
        return {"valid": True, "checked": True}

    def capture_start(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Capture live into ``dest`` (a new pcapng file) and show it like a
        streaming ``open`` (same parameters, minus ``path`` and ``cache``).

        ``interfaces`` (dumpcap names), ``filter`` (capture filter), ``limits:
        {packets, seconds, bytes}``, ``promiscuous`` (default true), ``snaplen``.
        Returns once dumpcap captures (ToolError with its message, and how to
        allow capturing, if it can't), with ``indexing: true`` and ``capture``.
        "capture" notifications report ``stats`` (packets, bytes, seconds) and
        ``stopped`` (plus ``dropped`` and ``error``); the index pass then ends
        with the usual "index" ``done``. ``capture_stop`` stops it.
        """
        dest = Path(param(params, "dest", str)).expanduser()
        if not dest.is_absolute():
            raise InvalidParamsError("dest must be an absolute path")
        options = _capture_options(params)
        return self._open(params, ctx, live=(options, dest))

    def capture_stop(self, _params: dict[str, Any], _ctx: RequestContext) -> dict[str, Any]:
        """Stop the live capture (``stopped: false`` if none is running). The
        packets captured so far stay; "capture" ``stopped`` and "index" ``done`` follow."""
        with self._lock:
            capture = self._file.capture if self._file is not None else None
        return {"stopped": capture is not None and capture.stop()}

    def capture_to_files(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Capture into files (no open capture needed, nothing shown live):
        dumpcap writes ``folder/name.pcapng`` (``format: "pcap"`` for pcap;
        extcap captures always write pcapng), or with ``files`` a new
        ``name_00001_<time>.pcapng`` every ``switchBytes``/``switchSeconds``/
        ``switchPackets``, keeping the newest ``ring`` and stopping after
        ``stopAfter``. Same interfaces, ``filter``, ``limits`` (packets,
        seconds), ``extcap``… as capture_start. Runs until a limit,
        ``capture_files_stop`` or a failure, reporting progress (packets,
        files, bytes, seconds, current) every second; returns ``{files,
        packets, seconds, dropped, stopped, error?}``. Cancelling it kills the
        capture (what was written stays)."""
        options = _capture_options(params)
        files = _file_options(params)
        command = capture_command(self._require_tshark().path, options)
        runner = FileCapture(command, options, files, ctx.progress)
        with self._lock:
            if self._file_capture is not None:
                raise InvalidParamsError("this backend is already capturing to files")
            self._file_capture = runner
        try:
            return runner.run(ctx.token)
        finally:
            with self._lock:
                self._file_capture = None

    def capture_files_stop(self, _params: dict[str, Any], _ctx: RequestContext) -> dict[str, Any]:
        """End capture_to_files cleanly (``stopped: false`` if none is running)."""
        with self._lock:
            runner = self._file_capture
        return {"stopped": runner is not None and runner.stop()}
