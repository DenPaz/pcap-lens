"""Comparing captures: a capture's profile and the diff of two (compare.py)."""

from __future__ import annotations

import sys
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from pcap_backend import compare
from pcap_backend.protocol import FilterError, InvalidParamsError, RequestContext
from pcap_backend.tshark import ToolError

from .opening import OpeningMixin
from .statistics import StatisticsMixin


class ComparingMixin(OpeningMixin, StatisticsMixin):
    """A capture's profile, and what changed between two profiles."""

    def capture_profile(self, _params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """The capture's profile for comparisons (``compare.profile``): its
        properties, protocol hierarchy, TCP/UDP conversations, IP endpoints,
        triage counts and expert messages, the tshark passes in parallel. A
        table tshark can't compute is left out and named in ``missing``.
        Needs the capture completely indexed."""
        self._require_indexed()
        info = self.capture_info({}, ctx)
        ctx.progress({"phase": "stats", "fraction": None})
        quiet = RequestContext(token=ctx.token)  # (one progress report for all the passes)
        parts: dict[str, Callable[[], dict[str, Any]]] = {
            "protocol hierarchy": lambda: self.stats({"kind": "phs"}, quiet),
            "TCP conversations": lambda: self.stats(
                {"kind": "conversations", "type": "tcp"}, quiet
            ),
            "UDP conversations": lambda: self.stats(
                {"kind": "conversations", "type": "udp"}, quiet
            ),
            "IPv4 endpoints": lambda: self.stats({"kind": "endpoints", "type": "ip"}, quiet),
            "IPv6 endpoints": lambda: self.stats({"kind": "endpoints", "type": "ipv6"}, quiet),
            "triage checks": lambda: self.triage({}, quiet),
            "expert information": lambda: self.stats({"kind": "expert"}, quiet),
        }
        results: dict[str, dict[str, Any] | None] = {}
        with ThreadPoolExecutor(max_workers=4, thread_name_prefix="profile") as pool:
            futures = {name: pool.submit(run_part) for name, run_part in parts.items()}
            for name, future in futures.items():
                try:
                    results[name] = future.result()
                except (ToolError, FilterError) as exc:
                    print(f"pcap-viewer: capture profile: {name}: {exc}", file=sys.stderr)  # noqa: T201
                    results[name] = None
        ctx.token.raise_if_cancelled()
        return compare.profile(
            info,
            results["protocol hierarchy"],
            [("tcp", results["TCP conversations"]), ("udp", results["UDP conversations"])],
            [results["IPv4 endpoints"], results["IPv6 endpoints"]],
            results["triage checks"],
            results["expert information"],
            [name for name, table in results.items() if table is None],
        )

    def compare_profiles(self, params: dict[str, Any], _ctx: RequestContext) -> dict[str, Any]:
        """What changed between two profiles (``capture_profile`` results;
        ``compare.diff``), with optional ``names`` for them. Needs no capture."""
        before, after = params.get("before"), params.get("after")
        if not isinstance(before, dict) or not isinstance(after, dict):
            raise InvalidParamsError("before and after must be capture profiles")
        names = params.get("names") or ["before", "after"]
        if not (
            isinstance(names, list) and len(names) == 2 and all(isinstance(n, str) for n in names)
        ):
            raise InvalidParamsError("names must be two strings")
        try:
            return compare.diff(before, after, (names[0], names[1]))
        except (KeyError, TypeError, ValueError) as exc:
            raise InvalidParamsError(f"not a capture profile: {exc}") from exc
