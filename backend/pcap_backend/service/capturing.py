"""Live capture: dumpcap's interfaces, capture filters, starting and stopping."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pcap_backend.capture import (
    CaptureOptions,
    capture_error,
    dumpcap_command,
    filter_problem,
    parse_interfaces,
)
from pcap_backend.protocol import InvalidParamsError, RequestContext, param, str_list
from pcap_backend.tshark import run

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


class CaptureMixin(OpeningMixin):
    """Live capture: dumpcap's interfaces, capture filters, starting and stopping."""

    def list_interfaces(self, _params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """The interfaces dumpcap can capture on (``dumpcap -D -M``)."""
        command = dumpcap_command(self._require_tshark().path)
        res = run([*command, "-D", "-M"], ctx.token)
        interfaces = parse_interfaces(res.stdout.decode("utf-8", "replace"))
        if res.returncode != 0 and not interfaces:
            raise capture_error(res.stderr, res.returncode, "dumpcap could not list interfaces")
        return {"interfaces": [i.to_json() for i in interfaces]}

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
        interfaces = tuple(str_list(params, "interfaces"))
        if not interfaces or any(not i.strip() for i in interfaces):
            raise InvalidParamsError("interfaces must name at least one interface")
        limits = param(params, "limits", dict, {})
        options = CaptureOptions(
            interfaces=interfaces,
            capture_filter=param(params, "filter", str, "").strip(),
            packets=_positive(limits, "packets", int),
            seconds=_positive(limits, "seconds", float),
            max_bytes=_positive(limits, "bytes", int),
            promiscuous=bool(params.get("promiscuous", True)),
            snaplen=_positive(params, "snaplen", int),
        )
        return self._open(params, ctx, live=(options, dest))

    def capture_stop(self, _params: dict[str, Any], _ctx: RequestContext) -> dict[str, Any]:
        """Stop the live capture (``stopped: false`` if none is running). The
        packets captured so far stay; "capture" ``stopped`` and "index" ``done`` follow."""
        with self._lock:
            capture = self._file.capture if self._file is not None else None
        return {"stopped": capture is not None and capture.stop()}
