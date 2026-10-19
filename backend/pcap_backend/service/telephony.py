"""VoIP: SIP calls, RTP stream analysis and audio."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from pcap_backend import voip
from pcap_backend.export import atomic_output, check_destination
from pcap_backend.protocol import InvalidParamsError, RequestContext, param
from pcap_backend.tshark import StreamResult, stream_lines

from .helpers import _fields_args
from .state import _Open
from .statistics import StatisticsMixin


def _heuristic_args(heuristic: bool) -> list[str]:
    """tshark options that make it find RTP no signalling set up."""
    return ["-o", "rtp.heuristic_rtp:TRUE"] if heuristic else []


class TelephonyMixin(StatisticsMixin):
    """VoIP: SIP calls, RTP stream analysis and audio."""

    def voip_calls(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """SIP calls and RTP streams of the capture (the VoIP panel): ``streams``
        from tshark's ``rtp,streams`` report plus a media pass over the RTP
        packets (payload types, DTMF events, gaps, E-model quality), and
        ``calls`` from one pass over the SIP messages (see voip.py), the three
        passes at once. ``heuristic`` also finds RTP that no SIP/SDP set up
        (tshark's rtp.heuristic_rtp). Cached per open capture, once it is
        completely indexed."""
        f = self._require_file()
        heuristic = param(params, "heuristic", bool, False)
        cached = self._voip.get(heuristic)
        if cached is not None:
            return cached
        ctx.progress({"phase": "voip", "fraction": None})
        sip_future = self._pool.submit(self._sip_lines, f, ctx)
        media_future = self._pool.submit(self._media_pass, f, heuristic, ctx)
        streams = voip.parse_rtp_streams(
            self._tap(f, "rtp,streams", ctx, _heuristic_args(heuristic))
        )
        media = media_future.result()
        for stream in streams:
            stream["heuristic"] = heuristic
            voip.stream_media(stream, media.get(voip.StreamKey.from_json(stream)))
        calls = voip.parse_sip_calls(sip_future.result(), streams)
        result = {"calls": calls, "streams": streams, "heuristic": heuristic}
        if self._indexing is None:  # (a capture still growing would change)
            self._voip.put(heuristic, result)
        return result

    def _sip_lines(self, f: _Open, ctx: RequestContext) -> list[str]:
        """The SIP pass's lines (voip.SIP_FIELDS), message bodies kept only for
        INFO requests (DTMF): an INVITE's SDP is read from its own fields."""
        fields = [
            "aggregator=" + voip.AGGREGATOR if a == "aggregator=," else a
            for a in _fields_args(voip.SIP_FIELDS)
        ]
        argv = f.tshark.argv("-n", "-Y", "sip", *fields, capture=str(f.path))
        method, body = voip.SIP_FIELDS.index("sip.Method"), voip.SIP_FIELDS.index("sip.msg_body")
        result = StreamResult()
        lines: list[str] = []
        for raw in stream_lines(argv, result, ctx.token):
            cells = raw.decode("utf-8", "replace").split("\t")
            if len(cells) > body and cells[method] != "INFO":
                cells[body] = ""
            lines.append("\t".join(cells))
        ctx.token.raise_if_cancelled()
        if not lines and result.returncode not in (0, None):
            raise f.tshark.error(
                result.stderr, result.returncode, "reading the SIP messages failed"
            )
        return lines

    def _media_pass(
        self, f: _Open, heuristic: bool, ctx: RequestContext
    ) -> dict[voip.StreamKey, Any]:
        """voip.parse_media over every RTP packet (streamed: it can be most of
        the capture). A failure only leaves the streams without its findings."""
        argv = f.tshark.argv(
            *_heuristic_args(heuristic), "-n", "-Y", "rtp", *_fields_args(voip.MEDIA_FIELDS),
            capture=str(f.path),
        )  # fmt: skip
        result = StreamResult()
        lines = (raw.decode("utf-8", "replace") for raw in stream_lines(argv, result, ctx.token))
        media = voip.parse_media(lines)
        ctx.token.raise_if_cancelled()
        return media

    def rtp_stream(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Packet-by-packet analysis of one RTP stream (``stream``: an entry
        of voip_calls' ``streams``): ``points`` (voip.POINT_FIELDS), a
        ``summary`` and the stream's ``filter``. One tshark pass, cached."""
        f = self._require_file()
        key, heuristic = self._stream_param(params)
        cached = self._rtp_streams.get((key, heuristic))
        if cached is not None:
            return cached
        ctx.progress({"phase": "rtp", "fraction": None})
        result = voip.analyse_stream(self._rtp_pass(f, key, heuristic, voip.RTP_FIELDS, ctx))
        result["stream"] = {**key.to_json(), "heuristic": heuristic}
        result["filter"] = key.filter()
        if self._indexing is None:
            self._rtp_streams.put((key, heuristic), result)
        return result

    def rtp_audio(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Save one RTP stream's audio to ``dest`` (an absolute path): a WAV
        file (``format`` "wav", the default: G.711 µ-law/A-law decoded, silence
        for lost packets) or the payload bytes as they are (``format`` "raw",
        in sequence order, for other codecs). Returns ``codec``, ``seconds``,
        ``packets``, ``silence`` (s) and ``skipped`` (packets of another type)."""
        f = self._require_file()
        key, heuristic = self._stream_param(params)
        fmt = param(params, "format", str, "wav")
        if fmt not in ("wav", "raw"):
            raise InvalidParamsError("format must be wav or raw")
        dest = check_destination(param(params, "dest", str), f.path)
        ctx.progress({"phase": "rtp", "fraction": None})
        packets = list(
            voip.audio_packets(self._rtp_pass(f, key, heuristic, voip.AUDIO_FIELDS, ctx))
        )
        if not packets:
            raise InvalidParamsError("no packets of this RTP stream were found")
        if fmt == "raw":
            ordered = voip.raw_payload(packets)
            with atomic_output(dest) as tmp:
                tmp.write_bytes(ordered)
            return {"format": "raw", "bytes": len(ordered), "packets": len(packets)}
        try:
            audio = voip.decode_audio(packets)
        except ValueError as exc:
            raise InvalidParamsError(str(exc), {"unsupported": True}) from exc
        with atomic_output(dest) as tmp:
            voip.write_wav(audio, tmp)
        return {
            "format": "wav",
            "codec": audio.codec,
            "seconds": round(len(audio.samples) / audio.rate, 3),
            "packets": audio.packets,
            "silence": round(audio.silence / audio.rate, 3),
            "skipped": audio.skipped,
        }

    @staticmethod
    def _stream_param(params: dict[str, Any]) -> tuple[voip.StreamKey, bool]:
        raw = params.get("stream")
        key = voip.StreamKey.from_json(raw)
        return key, bool(isinstance(raw, dict) and raw.get("heuristic"))

    def _rtp_pass(
        self,
        f: _Open,
        key: voip.StreamKey,
        heuristic: bool,
        fields: list[str],
        ctx: RequestContext,
    ) -> Iterator[str]:
        """The ``-T fields`` lines of one RTP stream's packets, as they come."""
        argv = f.tshark.argv(
            *_heuristic_args(heuristic), "-Y", key.filter(), *_fields_args(fields),
            capture=str(f.path),
        )  # fmt: skip
        result = StreamResult()
        lines = 0
        for raw in stream_lines(argv, result, ctx.token):
            lines += 1
            yield raw.decode("utf-8", "replace")
        if lines == 0 and result.returncode not in (0, None):
            raise f.tshark.error(result.stderr, result.returncode, "reading the RTP stream failed")
