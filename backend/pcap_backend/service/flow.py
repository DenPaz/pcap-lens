"""The flow graph of the current view."""

from __future__ import annotations

from typing import Any

from pcap_backend.protocol import RequestContext, param

from .packets import PacketsMixin
from .state import _TIME_IDX, BASE_COLUMNS, MAX_PAGE, _Open, _View

# Flow graph: columns (endpoints) shown; the others share an "other" column.
MAX_FLOW_NODES = 200


class FlowGraphMixin(PacketsMixin):
    """The flow graph of the current view."""

    def flow_graph(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """A sequence diagram of the displayed packets, in capture order:
        ``nodes`` (Source/Destination values in order of first appearance, at
        most MAX_FLOW_NODES; ``more`` counts the rest) and the arrows of packets
        ``[offset, offset + limit)``: ``number``, ``time``, ``from``/``to`` (node
        index, -1 for a node past the limit), ``protocol`` and ``info``. The
        nodes are computed once per view."""
        offset = param(params, "offset", int, 0)
        limit = min(max(0, param(params, "limit", int, 200)), MAX_PAGE)
        f, view = self._require_view()
        self._require_complete()
        nodes, index = self._flow_nodes(f, view, ctx)
        frames = view.matched.slice(offset, limit)
        arrows = []
        for n, cells in zip(frames, f.base.rows.get_many(frames), strict=True):
            src, dst = cells[2], cells[3]
            arrows.append(
                {
                    "number": n,
                    "time": cells[_TIME_IDX],
                    "from": index.get(src, -1),
                    "to": index.get(dst, -1),
                    "protocol": cells[4],
                    "info": cells[6],
                }
            )
        return {
            "filterId": view.filter_id,
            "total": len(view.matched),
            "nodes": nodes[:MAX_FLOW_NODES],
            "more": max(0, len(nodes) - MAX_FLOW_NODES),
            "rows": arrows,
        }

    def _flow_nodes(
        self, f: _Open, view: _View, ctx: RequestContext
    ) -> tuple[list[str], dict[str, int]]:
        with self._lock:
            cached = self._flow
        if cached is not None and cached[0] == view.filter_id:
            return cached[1], cached[2]
        ctx.progress({"phase": "flow", "fraction": None})
        columns = []
        for fld in (BASE_COLUMNS[2].field, BASE_COLUMNS[3].field):
            values = self._sort_columns.get(fld)
            if values is None:
                loc = self._locate(f, fld)
                assert loc is not None
                values = loc[0].column(loc[1])
                self._sort_columns.put(fld, values)
            columns.append(values)
        src, dst = columns
        nodes: list[str] = []
        index: dict[str, int] = {}
        for i, n in enumerate(view.matched.frames()):
            if i % 65536 == 0:
                ctx.token.raise_if_cancelled()
            for name in (src[n - 1], dst[n - 1]):
                if name not in index:
                    index[name] = len(nodes)
                    nodes.append(name)
        # Only the first MAX_FLOW_NODES get a column; the others are "-1".
        index = {name: i for name, i in index.items() if i < MAX_FLOW_NODES}
        with self._lock:
            self._flow = (view.filter_id, nodes, index)
        return nodes, index
