"""Coloring rules evaluated by tshark (set_coloring)."""

from __future__ import annotations

import os
import tempfile
import time
from array import array
from concurrent.futures import wait
from pathlib import Path
from typing import Any

from pcap_backend import coloring
from pcap_backend.cancellation import CancelledError
from pcap_backend.index_cache import rules_key
from pcap_backend.protocol import InvalidParamsError, NotOpenError, RequestContext
from pcap_backend.tshark import StreamResult, failed, stream_lines

from .base import ServiceBase
from .helpers import _parse_rules
from .state import PROGRESS_INTERVAL_S, _Open

# How long a coloring waits for its capture's index entry to be saved.
INDEX_SAVE_WAIT_S = 30.0


class ColoringMixin(ServiceBase):
    """Coloring rules evaluated by tshark (set_coloring)."""

    def set_coloring(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Evaluate coloring rules (first match wins) for every frame in one pass.

        ``rules``: ``[{filter, foreground?, background?}]`` in priority order; an
        empty list turns coloring off. Returns ``coloringId`` (echoed by
        ``list_packets``) and per-rule ``errors`` (index → message) for rules
        that were skipped because they don't compile or are malformed.
        """
        raw = params.get("rules") or []
        if not isinstance(raw, list):
            raise InvalidParamsError("parameter 'rules' must be a list")
        f = self._require_file()
        self._require_indexed()
        with self._lock:
            self._coloring_seq += 1
            seq = self._coloring_seq
        rules, errors = _parse_rules(raw)
        valid = sum(isinstance(r, coloring.ColorRule) for r in rules)
        colors: array[int] | None = None
        colored = 0
        rules_id = rules_key(raw)
        saved = (
            f.cache.load_colors(f.cache_key, rules_id, f.info.frames)
            if valid and f.cache is not None and f.cache_key is not None
            else None
        )
        if saved is not None:
            colors, extra = saved
            colored = int(extra.get("colored", 0))
            errors.update({int(i): str(m) for i, m in extra.get("errors", {}).items()})
        elif valid:
            colors, colored, compile_errors = self._coloring_pass(f, rules, ctx)
            errors.update(compile_errors)
            if f.cache is not None and f.cache_key is not None:
                # The index entry is written in the background after the pass,
                # and colors only join a complete one: wait for it (hard
                # links, quick), or a capture colored at once keeps no colors.
                pending = self._last_index
                if pending is not None and not pending.done():
                    wait([pending], timeout=INDEX_SAVE_WAIT_S)
                extra = {"colored": colored, "errors": {str(i): m for i, m in errors.items()}}
                f.cache.save_colors(f.cache_key, rules_id, colors, extra)
        with self._lock:
            if seq != self._coloring_seq:
                raise CancelledError("superseded by newer coloring rules")
            if self._file is not f:
                raise NotOpenError
            self._coloring_id += 1
            self._colors = colors
            coloring_id = self._coloring_id
        return {
            "coloringId": coloring_id,
            "colored": colored,
            "errors": {str(i): msg for i, msg in sorted(errors.items())},
        }

    def _coloring_pass(
        self, f: _Open, rules: list[coloring.ColorRule | str], ctx: RequestContext
    ) -> tuple[array[int], int, dict[int, str]]:
        """One ``--color`` pass: (rule index + 1 per frame, frames colored, compile errors)."""
        colors = array("B", bytes(f.info.frames + 1))
        colored = 0
        result = StreamResult()
        argv = f.tshark.argv(
            "--color", "-T", "fields", "-e", "frame.number", "-e", "frame.coloring_rule.name",
            capture=str(f.path),
        )  # fmt: skip
        personal = coloring.personal_config_dir(f.tshark.folders(ctx.token))
        total = max(1, f.info.frames)
        last_emit = 0.0
        with tempfile.TemporaryDirectory(prefix="pcapviewer-colors-") as tmp:
            coloring.prepare_config_dir(
                Path(tmp), rules, personal, f.tshark.profile_config(ctx.token)
            )
            env = {**os.environ, "WIRESHARK_CONFIG_DIR": tmp}
            for line in stream_lines(argv, result, ctx.token, env=env):
                number, _, rule = line.partition(b"\t")
                try:
                    n, idx = int(number), int(rule)
                except ValueError:
                    continue
                if 0 < n < len(colors) and 0 <= idx < len(rules):
                    colors[n] = idx + 1
                    colored += 1
                now = time.monotonic()
                if now - last_emit >= PROGRESS_INTERVAL_S:
                    last_emit = now
                    ctx.progress({"phase": "color", "fraction": min(0.99, n / total)})
        if failed(result.returncode, result.stderr) and result.lines == 0:
            raise f.tshark.error(result.stderr, result.returncode, "tshark coloring pass failed")
        return colors, colored, coloring.parse_compile_errors(result.stderr)
