"""Export Objects (HTTP, SMB, TFTP, IMF, DICOM, FTP-DATA)."""

from __future__ import annotations

import shutil
import time
from pathlib import Path
from typing import Any

from pcap_backend import objects
from pcap_backend.export import atomic_output, check_destination
from pcap_backend.objects import ExportedObject
from pcap_backend.protocol import InvalidParamsError, NotOpenError, RequestContext, param
from pcap_backend.tshark import StreamResult, ToolError, stream_lines

from .base import ServiceBase
from .helpers import _fields_args, _rejected_fields, sniff_format
from .state import _RECORD_OVERHEAD, _Open


class ObjectsMixin(ServiceBase):
    """Export Objects (HTTP, SMB, TFTP, IMF, DICOM, FTP-DATA)."""

    def export_objects(self, _params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Files carried by HTTP, SMB, TFTP, IMF, DICOM and FTP-DATA (see
        objects.py): ``objects`` with ``id``, ``protocol``, ``name``, ``size``,
        and when known the ``frame`` that carried it, ``host`` and ``contentType``.
        One tshark pass (two passes over the file) the first time, then cached;
        works while a streaming open is still indexing."""
        f = self._require_file()
        with self._objects_lock:
            if self._objects is None or self._objects[0] is not f:
                self._objects = (f, self._extract_objects(f, ctx))
            found = self._objects[1]
        return {"objects": [o.to_json(i) for i, o in enumerate(found)]}

    def _extract_objects(self, f: _Open, ctx: RequestContext) -> list[ExportedObject]:
        with self._lock:
            if self._work_dir is None:
                raise NotOpenError
            folder = self._work_dir / "objects"
        shutil.rmtree(folder, ignore_errors=True)  # (a cancelled earlier run)
        folder.mkdir()
        wanted = list(objects.FIELDS)
        size = max(1, f.info.size)
        overhead = _RECORD_OVERHEAD.get(sniff_format(f.path) or "")
        for _attempt in range(len(wanted)):
            eo = [a for p in objects.PROTOCOLS for a in ("--export-objects", f"{p},{folder / p}")]
            argv = f.tshark.argv(
                "-2", *eo, *_fields_args(wanted), "-E", f"aggregator={objects.AGGREGATOR}",
                capture=str(f.path),
            )  # fmt: skip
            linker = objects.Linker()
            result = StreamResult()
            seen, last = 0, 0.0
            # The first pass prints nothing; the second prints a line per packet.
            ctx.progress({"phase": "objects", "fraction": None})
            for line in stream_lines(argv, result, ctx.token):
                values = dict(
                    zip(wanted, line.decode("utf-8", "replace").split("\t"), strict=False)
                )
                linker.add(values)
                if overhead is not None and values.get("frame.len", "").isdigit():
                    seen += int(values["frame.len"]) + overhead
                    now = time.monotonic()
                    if now - last > 0.2:
                        last = now
                        ctx.progress({"phase": "objects", "fraction": min(1.0, seen / size)})
            if result.returncode not in (0, None) and result.lines == 0:
                rejected = [r for r in _rejected_fields(result.stderr) if r in wanted[2:]]
                if rejected:  # (an older tshark without one of the linking fields)
                    wanted = [w for w in wanted if w not in rejected]
                    shutil.rmtree(folder, ignore_errors=True)
                    folder.mkdir()
                    continue
                raise f.tshark.error(result.stderr, result.returncode, "extracting objects failed")
            return objects.collect(folder, linker)
        raise ToolError("tshark rejected the fields that link objects to packets")

    def save_objects(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Save exported objects (``ids`` from export_objects): one object to the
        file ``dest``, or any number into the folder ``dir`` under their own
        names (made safe; ``name (1).ext`` instead of overwriting). Each file
        only appears once complete."""
        f = self._require_file()
        with self._objects_lock:
            found = self._objects[1] if self._objects and self._objects[0] is f else None
        if found is None:
            raise InvalidParamsError("list the objects first (export_objects)")
        ids = params.get("ids")
        if not isinstance(ids, list) or not ids or not all(isinstance(i, int) for i in ids):
            raise InvalidParamsError("ids must be a non-empty list of object ids")
        if any(not 0 <= i < len(found) for i in ids):
            raise InvalidParamsError("unknown object id")
        chosen = [found[i] for i in dict.fromkeys(ids)]
        if "dest" in params:
            if len(chosen) != 1:
                raise InvalidParamsError("dest takes one object; use dir for several")
            targets = [check_destination(param(params, "dest", str), f.path)]
        else:
            folder = Path(param(params, "dir", str)).expanduser()
            if not folder.is_absolute() or not folder.is_dir():
                raise InvalidParamsError(f"not an existing folder: {folder}")
            taken: set[str] = set()
            targets = [
                check_destination(
                    str(objects.unique_path(folder, objects.safe_name(o.name), taken)), f.path
                )
                for o in chosen
            ]
        for i, (obj, dest) in enumerate(zip(chosen, targets, strict=True)):
            ctx.token.raise_if_cancelled()
            ctx.progress({"phase": "save", "fraction": i / len(chosen)})
            with atomic_output(dest) as tmp:
                shutil.copyfile(obj.path, tmp)
        return {"saved": [str(t) for t in targets]}
