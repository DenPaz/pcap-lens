"""Packet detail: the exact dissection and the quick (windowed) one."""

from __future__ import annotations

import re
import sys
from collections.abc import Callable
from concurrent.futures import wait
from pathlib import Path
from typing import Any

from pcap_backend import pdml
from pcap_backend.cancellation import CancelledError
from pcap_backend.protocol import InvalidParamsError, RequestContext, RpcError, param
from pcap_backend.tshark import ToolError, ToolNotFoundError, Tshark, find_tool, run

from .dissection import DissectionMixin
from .helpers import _stderr_warnings
from .state import _TIME_IDX, _Open

# Quick detail: packets dissected before the one asked for (see _quick_detail).
QUICK_WINDOW = 300


MIN_QUICK_WINDOW = 2


MAX_QUICK_WINDOW = 5000


# FT_FRAMENUM fields by name, while the field catalogue is still loading.
_FRAMENUM_HINT = re.compile(
    r"\.(?:request_in|response_in|response_to|prev_request_in|next_request_in|reassembled_in"
    r"|segment|fragment|acks_frame|duplicate_ack_frame|retransmitted_in|retransmission_of)$"
)


class DetailMixin(DissectionMixin):
    """Packet detail: the exact dissection and the quick (windowed) one."""

    def packet_detail(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Detail tree and byte sources of frame ``number``.

        ``mode``: ``exact`` (default) dissects the capture up to the frame
        (``-c N``), so its cost grows with N. ``quick`` dissects only the
        ``window`` packets up to it (cut out with editcap): fast anywhere in
        the file, but approximate (``approximate: true``, ``window: [first,
        last]``), since state from earlier packets (reassembly, TCP analysis,
        conversations) is missing. A quick request answers with the exact
        detail when that is cached or the window starts at frame 1, and with
        ``{"unavailable": reason}`` without editcap.
        """
        number = param(params, "number", int)
        mode = param(params, "mode", str, "exact")
        if mode not in ("exact", "quick"):
            raise InvalidParamsError("mode must be exact or quick")
        f = self._require_file()
        if not 1 <= number <= f.frame_count():
            raise InvalidParamsError(f"frame {number} out of range 1..{f.frame_count()}")
        cached = self._details.get(number)
        if cached is not None:
            return cached
        if mode == "quick":
            window = param(params, "window", int, QUICK_WINDOW)
            if not MIN_QUICK_WINDOW <= window <= MAX_QUICK_WINDOW:
                raise InvalidParamsError(
                    f"window must be {MIN_QUICK_WINDOW}..{MAX_QUICK_WINDOW} packets"
                )
            if number > window:
                return self._quick_detail(f, number, window, ctx)
        detail = {"number": number, **self._dissect(f.tshark, f.path, number, ctx)}
        self._details.put(number, detail)
        return detail

    def _dissect(
        self, tshark: Tshark, capture: Path, number: int, ctx: RequestContext
    ) -> dict[str, Any]:
        """PDML tree and ``-x`` byte sources of frame ``number`` of ``capture``."""
        select = ["-c", str(number), "-Y", f"frame.number=={number}"]
        pdml_argv = tshark.argv(*select, "-T", "pdml", capture=str(capture))
        hex_argv = tshark.argv(*select, "-x", capture=str(capture))
        hex_future = self._pool.submit(run, hex_argv, ctx.token)
        try:
            pdml_res = run(pdml_argv, ctx.token)
        except BaseException:
            # (A cancel.) Don't return while the -x run still reads the capture
            # (a quick window is deleted right after): it stops at the same token.
            if not hex_future.cancel():
                wait([hex_future])
            raise
        hex_res = hex_future.result()
        if not pdml_res.stdout.strip():
            raise tshark.error(
                pdml_res.stderr,
                pdml_res.returncode,
                f"tshark returned no detail for frame {number}",
            )
        sources = pdml.parse_hexdump(hex_res.stdout.decode("utf-8", "replace"))
        tree = pdml.parse_pdml(pdml_res.stdout, source_count=max(1, len(sources)))
        return {
            "tree": tree,
            "sources": [s.to_json() for s in sources],
            "warnings": _stderr_warnings(pdml_res.stderr),
        }

    def _quick_detail(
        self, f: _Open, number: int, window: int, ctx: RequestContext
    ) -> dict[str, Any]:
        """Dissect only packets ``number - window + 1 .. number``: editcap copies
        them into a small pcapng (it reads records without dissecting them),
        and the tree is renumbered to the capture's frame numbers."""
        key = (number, window)
        cached = self._quick.get(key)
        if cached is not None:
            return cached
        try:
            editcap = find_tool("editcap", sibling_of=f.tshark.path)
        except ToolNotFoundError:
            return {"number": number, "unavailable": "editcap (part of Wireshark) was not found"}
        assert self._work_dir is not None
        first = number - window + 1
        part = self._work_dir / f"quick-{number}-{next(self._quick_seq)}.pcapng"
        try:
            res = run(
                [str(editcap), "-F", "pcapng", "-r", str(f.path), str(part), f"{first}-{number}"],
                ctx.token,
            )
            if res.returncode != 0 or not part.exists():
                raise ToolError(
                    res.stderr or f"editcap exited with code {res.returncode}",
                    res.stderr,
                    res.returncode,
                )
            detail = self._dissect(f.tshark, part, window, ctx)
        finally:
            part.unlink(missing_ok=True)
        pdml.renumber_tree(
            detail["tree"],
            offset=first - 1,
            window=window,
            is_framenum=self._framenum_check(),
            time_relative=f.base.rows.get(number)[_TIME_IDX] or None,
        )
        detail = {"number": number, **detail, "approximate": True, "window": [first, number]}
        self._quick.put(key, detail)
        return detail

    def _framenum_check(self) -> Callable[[str], bool]:
        """Whether a field is FT_FRAMENUM: from the field catalogue when it is
        loaded (the webview warms it after open), else known names, while the
        catalogue loads in the background (a quick view must not wait for it)."""
        tshark = self._file.tshark if self._file else self._require_tshark()
        catalog = self._field_index.get(tshark.options.lua_scripts)
        if catalog is None:
            if not self._catalog_warming.is_set():
                self._catalog_warming.set()
                self._warm_future = self._pool.submit(self._warm_catalog)
            return lambda name: bool(_FRAMENUM_HINT.search(name))

        def check(name: str) -> bool:
            entry = catalog.lookup(name)
            return entry is not None and entry.get("type") == "FT_FRAMENUM"

        return check

    def _warm_catalog(self) -> None:
        try:
            self._catalog(RequestContext(token=self._background))
        except CancelledError:
            pass  # shutdown
        except (RpcError, ToolError, OSError) as exc:  # a real request reports it
            print(f"pcap-viewer: field catalogue not loaded: {exc}", file=sys.stderr)  # noqa: T201
        finally:
            self._catalog_warming.clear()
