"""Follow stream and TCP stream graphs."""

from __future__ import annotations

from typing import Any

from pcap_backend import stats
from pcap_backend.protocol import InvalidParamsError, RequestContext, param
from pcap_backend.tshark import StreamResult, run, stream_lines

from .helpers import _fields_args
from .packets import PacketsMixin
from .state import _Open

_TCP_GRAPH_FIELDS = (
    "frame.number",
    "frame.time_relative",
    "ip.src",
    "ipv6.src",
    "tcp.srcport",
    "tcp.seq",
    "tcp.len",
    "tcp.ack",
    "tcp.window_size",
    "tcp.analysis.ack_rtt",
    "tcp.analysis.retransmission",
    "tcp.flags.syn",
)


TCP_GRAPH_POINT = ("frame", "time", "dir", "seq", "len", "ack", "win", "rtt", "retrans", "syn")


def _last(cell: str) -> str:
    """The innermost value of a field repeated by tunnelling (tshark joins them with ",")."""
    return cell.rsplit(",", 1)[-1]


def parse_tcp_graph(text: str) -> dict[str, Any]:
    """Points of a TCP stream from tshark's ``_TCP_GRAPH_FIELDS`` output."""
    endpoints: list[str] = []
    points: list[list[Any]] = []

    def number(cell: str) -> int:
        value = _last(cell)
        return int(value) if value.isdigit() else 0

    for line in text.split("\n"):
        cells = line.removesuffix("\r").split("\t")  # tshark on Windows writes \r\n
        if len(cells) < len(_TCP_GRAPH_FIELDS) or not cells[0].isdigit():
            continue
        address = _last(cells[2]) or _last(cells[3])
        endpoint = (
            f"[{address}]:{_last(cells[4])}" if ":" in address else f"{address}:{_last(cells[4])}"
        )
        if endpoint not in endpoints:
            endpoints.append(endpoint)
        try:
            rtt: float | None = float(_last(cells[9])) if cells[9] else None
        except ValueError:
            rtt = None
        points.append(
            [
                int(cells[0]),
                float(cells[1] or 0),
                0 if endpoint == endpoints[0] else 1,
                number(cells[5]),
                number(cells[6]),
                number(cells[7]),
                number(cells[8]),
                rtt,
                1 if cells[10] else 0,
                1 if _last(cells[11]) in ("1", "True") else 0,
            ]
        )
    return {"endpoints": endpoints[:2], "fields": list(TCP_GRAPH_POINT), "points": points}


class StreamsMixin(PacketsMixin):
    """Follow stream and TCP stream graphs."""

    def follow_stream(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Reassembled payload of one TCP/UDP/TLS/HTTP stream (``-z follow,<proto>,raw``).

        Give ``stream`` (the ``tcp.stream``/``udp.stream`` number) or ``frame``
        (a packet in the stream). Returns ``segments`` of ``{dir, hex}`` where
        ``dir`` 0 is the side that sent first (node 0) and 1 the other side.
        Output beyond ``maxBytes`` of payload is cut off (``truncated``).
        """
        proto = param(params, "proto", str).lower()
        if proto not in stats.FOLLOW_PROTOCOLS:
            raise InvalidParamsError(f"proto must be one of {', '.join(stats.FOLLOW_PROTOCOLS)}")
        f = self._require_file()
        max_bytes = max(1024, min(param(params, "maxBytes", int, 16 << 20), 256 << 20))
        if params.get("stream") is not None:
            stream = param(params, "stream", int)
            if stream < 0:
                raise InvalidParamsError("stream must be >= 0")
        else:
            stream = self._stream_of(f, proto, param(params, "frame", int), ctx)

        # -n: node addresses stay addresses, whatever the list's name resolution.
        argv = f.tshark.argv("-q", "-n", "-z", f"follow,{proto},raw,{stream}", capture=str(f.path))
        result = StreamResult()
        lines: list[str] = []
        size = 0
        truncated = False
        ctx.progress({"phase": "follow", "fraction": None})
        for raw in stream_lines(argv, result, ctx.token):
            line = raw.decode("utf-8", "replace")
            size += len(line) // 2
            if size > max_bytes:
                truncated = True
                break  # closing the generator kills tshark
            lines.append(line)
        if not lines and result.returncode not in (0, None):
            raise f.tshark.error(result.stderr, result.returncode, "tshark follow failed")
        followed = stats.parse_follow_raw("\n".join(lines))
        followed.update({"proto": proto, "stream": stream, "truncated": truncated})
        if not followed["segments"] and proto == "tls":
            followed["hint"] = (
                "No decrypted TLS data. Provide session keys via the "
                '"tls.keylog_file" preference (pcapViewer.prefs) to follow TLS.'
            )
        return followed

    def _stream_of(self, f: _Open, proto: str, frame: int, ctx: RequestContext) -> int:
        if not 1 <= frame <= f.frame_count():
            raise InvalidParamsError(f"frame {frame} out of range 1..{f.frame_count()}")
        fld = "udp.stream" if proto == "udp" else "tcp.stream"
        self._ensure_columns(f, [fld], ctx)  # one extra pass, then cached
        value = self._column_cells(f, fld, [frame])[0].split(",")[0]
        if not value.isdigit():
            label = "UDP" if proto == "udp" else "TCP"
            raise InvalidParamsError(f"packet {frame} is not part of a {label} stream")
        return int(value)

    def tcp_graph(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """The packets of TCP ``stream`` (or the stream of ``frame``) for the
        TCP stream graphs: ``endpoints`` [A, B] ("address:port", A = the first
        packet's source) and ``points``, one array per packet in the order of
        ``fields`` (``dir`` 0 = A→B; ``rtt`` in seconds or null; ``retrans``
        and ``syn`` 0/1). One tshark pass per stream, cached."""
        f = self._require_file()
        if params.get("stream") is not None:
            stream = param(params, "stream", int)
            if stream < 0:
                raise InvalidParamsError("stream must be >= 0")
        else:
            stream = self._stream_of(f, "tcp", param(params, "frame", int), ctx)
        cached = self._tcp_graphs.get(stream)
        if cached is not None:
            return cached
        ctx.progress({"phase": "tcp_graph", "fraction": None})
        argv = f.tshark.argv(
            "-Y", f"tcp.stream == {stream}", *_fields_args(_TCP_GRAPH_FIELDS), capture=str(f.path)
        )  # fmt: skip
        res = run(argv, ctx.token)
        if res.returncode != 0 and not res.stdout:
            raise f.tshark.error(res.stderr, res.returncode, "reading the TCP stream failed")
        result = {"stream": stream, **parse_tcp_graph(res.stdout.decode("utf-8", "replace"))}
        self._tcp_graphs.put(stream, result)
        return result
