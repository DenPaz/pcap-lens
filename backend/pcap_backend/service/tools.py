"""Requests that need no open capture or edit a copy: merge, import, probe, plugins, editing."""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from pcap_backend import ber, comments, editing, hexdump, objects, plugins
from pcap_backend.export import CAPTURE_FORMATS, atomic_output, check_destination
from pcap_backend.protocol import InvalidParamsError, RequestContext, param, str_list
from pcap_backend.tshark import ToolError, ToolNotFoundError, find_tool, run

from .base import ServiceBase
from .helpers import _readable_capture, sniff_format
from .state import _UNSUPPORTED_RE, _Open


class ToolsMixin(ServiceBase):
    """Requests that need no open capture or edit a copy: merge, import, probe, plugins, editing."""

    def merge(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Merge capture files into ``dest`` with mergecap: by timestamp, or one
        after another in the given order with ``append`` (a rotated capture's
        files). ``format``: ``pcapng`` (default) or ``pcap``. Needs no open
        capture. The file only appears once complete."""
        inputs = [Path(p).expanduser() for p in str_list(params, "inputs")]
        if len(inputs) < 2:
            raise InvalidParamsError("choose at least two capture files to merge")
        for path in inputs:
            if not path.is_file():
                raise InvalidParamsError(f"capture file not found: {path}")
        fmt = param(params, "format", str, "pcapng")
        if fmt not in CAPTURE_FORMATS:
            raise InvalidParamsError(f"format must be one of {', '.join(CAPTURE_FORMATS)}")
        dest = check_destination(param(params, "dest", str), inputs[0])
        for path in inputs[1:]:
            check_destination(str(dest), path)  # never over one of the inputs
        tshark = self._require_tshark()
        try:
            mergecap = find_tool("mergecap", sibling_of=tshark.path)
        except ToolNotFoundError as exc:
            raise ToolError("merging captures needs mergecap (part of Wireshark)") from exc
        ctx.progress({"phase": "merge", "fraction": None})
        with atomic_output(dest) as tmp:
            argv = [str(mergecap), *(["-a"] if params.get("append") else []), "-F", fmt]
            res = run([*argv, "-w", str(tmp), *map(str, inputs)], ctx.token)
            if res.returncode != 0 or not tmp.exists():
                raise ToolError(res.stderr.strip() or "mergecap failed", res.stderr, res.returncode)
        return {"ok": True, "path": str(dest), "size": dest.stat().st_size, "inputs": len(inputs)}

    def import_hexdump(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Build a capture from a hex dump with text2pcap (hexdump.py): ``text``
        (the dump itself) or ``input`` (a text file), written to ``dest`` as
        pcapng (appears once complete), with the options of
        ``hexdump.text2pcap_options``. Needs no open capture. A dump in which
        text2pcap finds no packets is an error (nothing is written).
        Returns ``{path, packets}``."""
        text = params.get("text")
        source = param(params, "input", str, "")
        if (text is None) == (not source):
            raise InvalidParamsError("give either text or input")
        if text is not None and (not isinstance(text, str) or len(text) > hexdump.MAX_TEXT):
            raise InvalidParamsError("text must be a string of at most 64 MB")
        options = hexdump.text2pcap_options(params)
        tshark = self._require_tshark()
        try:
            text2pcap = find_tool("text2pcap", sibling_of=tshark.path)
        except ToolNotFoundError as exc:
            raise ToolError("importing a hex dump needs text2pcap (part of Wireshark)") from exc
        ctx.progress({"phase": "import", "fraction": None})
        with tempfile.TemporaryDirectory(prefix="pcapviewer-hexdump-") as scratch:
            if text is not None:
                infile = Path(scratch) / "dump.txt"
                infile.write_text(text, encoding="utf-8", newline="\n")
            else:
                infile = Path(source).expanduser()
                if not infile.is_file():
                    raise InvalidParamsError(f"file not found: {infile}")
            dest = check_destination(param(params, "dest", str), infile)
            with atomic_output(dest) as tmp:
                argv = [str(text2pcap), "-F", "pcapng", *options, str(infile), str(tmp)]
                res = run(argv, ctx.token)
                if res.returncode != 0 or not tmp.exists():
                    raise ToolError(
                        res.stderr.strip() or "text2pcap failed", res.stderr, res.returncode
                    )
                counts = hexdump.written_packets(res.stderr)
                if counts is not None and counts[1] == 0:
                    raise InvalidParamsError(
                        "no packets found in the hex dump: each line needs an offset "
                        "(e.g. 0000) followed by hex bytes, unless offsets are none"
                    )
        return {"path": str(dest), "packets": counts[1] if counts else comments.packet_count(dest)}

    def probe_file(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Whether tshark can read ``path`` as a capture, whatever it is called
        (for "Open File in PCAP Lens…"): ``{readable: true, format}``
        (pcap/pcapng/null for other formats tshark reads), or ``{readable:
        false, message}``, with ``berRecords: N`` when the file is several BER
        values back to back (tshark reads one BER value per file). Needs no open
        capture; a missing or unreadable file is an InvalidParamsError."""
        path = _readable_capture(param(params, "path", str))
        if path.stat().st_size == 0:
            return {"readable": False, "message": f"{path.name} is empty"}
        tshark = self._require_tshark()
        argv = tshark.argv(
            "-c", "1", "-T", "fields", "-e", "frame.number", capture=str(path), dissect=False
        )  # fmt: skip
        res = run(argv, ctx.token)
        if res.returncode == 0 and not _UNSUPPORTED_RE.search(res.stderr):
            return {"readable": True, "format": sniff_format(path)}
        if not _UNSUPPORTED_RE.search(res.stderr):
            raise tshark.error(res.stderr, res.returncode, f"tshark could not read {path.name}")
        records = ber.count_records(path)
        if records and records > 1:
            return {
                "readable": False,
                "berRecords": records,
                "message": (
                    f"{path.name} holds {records:,}{'+' if records >= ber.MAX_RECORDS else ''} "
                    "BER records one after another; tshark reads a file of one BER value only"
                ),
            }
        return {
            "readable": False,
            "message": f"{path.name} isn't a capture file in a format tshark can read",
        }

    def tshark_plugins(self, _params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """The plugins tshark loads (``tshark -G plugins``, never cached: the
        point is to see one just installed) and its plugin folders
        (plugins.describe): ``{plugins: [{name, version, type, path,
        personal}], folders, install, warnings, version}``. Needs no open
        capture."""
        tshark = self._require_tshark()
        res = run([str(tshark.path), "-G", "plugins"], ctx.token)
        if res.returncode != 0:
            raise tshark.error(res.stderr.strip(), res.returncode, "tshark -G plugins failed")
        as_root = hasattr(os, "geteuid") and os.geteuid() == 0
        out = plugins.describe(
            res.stdout.decode("utf-8", "replace"), tshark.folders(ctx.token), as_root
        )
        return {**out, "version": tshark.version()}

    def edit_capture(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Write an edited copy of the open capture with editcap (editing.py):
        ``operation`` (timeShift, dedup, keep, truncate, injectSecrets or split)
        and its parameters. The result goes to ``dest`` (pcapng, appears once
        complete) or, for split, into the existing folder ``dir`` as several
        files (never overwriting one). Unsaved comment edits are not included.
        Returns ``{path | files, packets, removed?}``.
        """
        f = self._require_file()
        self._require_indexed()  # (a live capture is still writing the file)
        operation = param(params, "operation", str)
        options, selections = editing.editcap_options(operation, params, f.info.frames)
        try:
            editcap = find_tool("editcap", sibling_of=f.tshark.path)
        except ToolNotFoundError as exc:
            raise ToolError("editing captures needs editcap (part of Wireshark)") from exc
        ctx.progress({"phase": "edit", "fraction": None})
        if operation == "split":
            return self._split_capture(f, editcap, options, params, ctx)
        dest = check_destination(param(params, "dest", str), f.path)
        with atomic_output(dest) as tmp:
            argv = [str(editcap), "-F", "pcapng", *options, str(f.path), str(tmp), *selections]
            res = run(argv, ctx.token)
            if res.returncode != 0 or not tmp.exists():
                raise ToolError(res.stderr.strip() or "editcap failed", res.stderr, res.returncode)
        result: dict[str, Any] = {"path": str(dest), "packets": comments.packet_count(dest)}
        if operation == "dedup":
            result["removed"] = editing.skipped_packets(res.stderr) or 0
        return result

    def _split_capture(
        self,
        f: _Open,
        editcap: Path,
        options: list[str],
        params: dict[str, Any],
        ctx: RequestContext,
    ) -> dict[str, Any]:
        """editcap -c/-i into a scratch folder inside ``dir``, then each piece
        moved next to it under a name not taken yet."""
        folder = Path(param(params, "dir", str)).expanduser()
        if not folder.is_absolute() or not folder.is_dir():
            raise InvalidParamsError(f"folder does not exist: {folder}")
        name = param(params, "name", str, "") or f"{f.path.name.split('.')[0]}.pcapng"
        name = objects.safe_name(Path(name).name)
        if not name.lower().endswith(".pcapng"):
            name += ".pcapng"
        scratch = Path(tempfile.mkdtemp(prefix=".pcapviewer-split-", dir=folder))
        try:
            res = run([str(editcap), "-F", "pcapng", *options, str(f.path), str(scratch / name)],
                      ctx.token)  # fmt: skip
            pieces = sorted(scratch.iterdir())
            if res.returncode != 0 or not pieces:
                raise ToolError(res.stderr.strip() or "editcap failed", res.stderr, res.returncode)
            taken: set[str] = set()
            files = []
            for piece in pieces:
                target = objects.unique_path(folder, piece.name, taken)
                piece.replace(target)
                files.append(str(target))
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
        return {"files": files, "packets": f.info.frames}
