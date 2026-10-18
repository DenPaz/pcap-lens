"""VoIP: SIP calls, RTP stream analysis and audio."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from pcap_backend import voip
from pcap_backend.export import atomic_output, check_destination
from pcap_backend.protocol import InvalidParamsError, RequestContext, param
from pcap_backend.tshark import StreamResult, run, stream_lines

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
        from tshark's ``rtp,streams`` report and ``calls`` from one pass over
        the SIP messages (see voip.py), both passes at once. ``heuristic``
        also finds RTP that no SIP/SDP set up (tshark's rtp.heuristic_rtp).
        Cached per open capture, once it is completely indexed."""
        f = self._require_file()
        heuristic = param(params, "heuristic", bool, False)
        cached = self._voip.get(heuristic)
        if cached is not None:
            return cached
        ctx.progress({"phase": "voip", "fraction": None})
        fields = [
            "aggregator=" + voip.AGGREGATOR if a == "aggregator=," else a
            for a in _fields_args(voip.SIP_FIELDS)
        ]
        sip_argv = f.tshark.argv("-n", "-Y", "sip", *fields, capture=str(f.path))
        sip_future = self._pool.submit(run, sip_argv, ctx.token)
        streams = voip.parse_rtp_streams(
            self._tap(f, "rtp,streams", ctx, _heuristic_args(heuristic))
        )
        for stream in streams:
            stream["heuristic"] = heuristic
        sip = sip_future.result()
        if sip.returncode != 0 and not sip.stdout:
            raise f.tshark.error(sip.stderr, sip.returncode, "reading the SIP messages failed")
        calls = voip.parse_sip_calls(sip.stdout.decode("utf-8", "replace"), streams)
        result = {"calls": calls, "streams": streams, "heuristic": heuristic}
        if self._indexing is None:  # (a capture still growing would change)
            self._voip.put(heuristic, result)
        return result

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
