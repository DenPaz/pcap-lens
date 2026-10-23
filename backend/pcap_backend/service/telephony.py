"""VoIP: SIP calls, RTP stream analysis and audio."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from pcap_backend import voip, voip_protocols
from pcap_backend.export import atomic_output, check_destination
from pcap_backend.protocol import InvalidParamsError, RequestContext, param
from pcap_backend.tshark import StreamResult, stream_lines

from .helpers import _fields_args, _rejected_fields
from .state import _Open
from .statistics import StatisticsMixin

# call_audio: at most this many streams (an SSRC change adds one) and
# waveform buckets per channel.
MAX_CALL_STREAMS = 16
MAX_PEAKS = 2000


def _heuristic_args(heuristic: bool) -> list[str]:
    """tshark options that make it find RTP no signalling set up."""
    return ["-o", "rtp.heuristic_rtp:TRUE"] if heuristic else []


class TelephonyMixin(StatisticsMixin):
    """VoIP: SIP calls, RTP stream analysis and audio."""

    def voip_calls(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Calls and RTP streams of the capture (the VoIP panel): ``streams``
        from tshark's ``rtp,streams`` report plus a media pass over the RTP
        packets (payload types, DTMF events, gaps, E-model quality), and
        ``calls`` (SIP, H.323, MGCP and IAX2, in order of their start: see
        voip.py and voip_protocols.py; IAX2 voice frames add streams of their
        own) from one pass over the signalling, the three passes at once.
        ``heuristic`` also finds RTP that no signalling set up (tshark's
        rtp.heuristic_rtp). Cached per open capture, once it is completely
        indexed."""
        f = self._require_file()
        heuristic = param(params, "heuristic", bool, False)
        cached = self._voip.get(heuristic)
        if cached is not None:
            return cached
        ctx.progress({"phase": "voip", "fraction": None})
        signalling_future = self._pool.submit(self._signalling_lines, f, ctx)
        media_future = self._pool.submit(self._media_pass, f, heuristic, ctx)
        streams = voip.parse_rtp_streams(
            self._tap(f, "rtp,streams", ctx, _heuristic_args(heuristic))
        )
        media = media_future.result()
        for stream in streams:
            stream["heuristic"] = heuristic
            key = voip.StreamKey.from_json(stream)
            voip.stream_media(stream, media.streams.get(key), media.rtcp.get(key.ssrc))
        lines, fields = signalling_future.result()
        calls = voip.parse_sip_calls(lines, streams)
        calls += voip_protocols.parse_other_calls(lines, fields, streams)
        calls.sort(key=lambda c: c["start"])
        for i, call in enumerate(calls):
            call["id"] = i
        result = {
            "calls": calls,
            "streams": streams,
            "registrations": voip.parse_registrations(lines),
            "heuristic": heuristic,
        }
        if self._indexing is None:  # (a capture still growing would change)
            self._voip.put(heuristic, result)
        return result

    def _signalling_lines(self, f: _Open, ctx: RequestContext) -> tuple[list[str], list[str]]:
        """The signalling pass's lines and fields: voip.SIP_FIELDS, then the
        voip_protocols.OTHER_FIELDS this tshark knows (one it refuses is left
        out and the pass run again; tshark checks fields before reading, and
        the capture remembers refused ones). SIP message bodies are kept only for
        INFO requests (DTMF): an INVITE's SDP is read from its own fields."""
        method, body = voip.SIP_FIELDS.index("sip.Method"), voip.SIP_FIELDS.index("sip.msg_body")
        others = [o for o in voip_protocols.OTHER_FIELDS if o not in f.rejected]
        while True:
            fields = voip.SIP_FIELDS + others
            args = [
                "aggregator=" + voip.AGGREGATOR if a == "aggregator=," else a
                for a in _fields_args(fields)
            ]
            argv = f.tshark.argv(
                "-n", "-Y", voip_protocols.SIGNALLING_FILTER, *args, capture=str(f.path)
            )
            result = StreamResult()
            lines: list[str] = []
            for raw in stream_lines(argv, result, ctx.token):
                cells = raw.decode("utf-8", "replace").split("\t")
                if len(cells) > body and cells[method] != "INFO":
                    cells[body] = ""
                lines.append("\t".join(cells))
            ctx.token.raise_if_cancelled()
            if not lines and result.returncode not in (0, None):
                rejected = [r for r in _rejected_fields(result.stderr) if r in others]
                if rejected:  # (an older or newer tshark without one of them)
                    f.rejected.update(rejected)
                    others = [o for o in others if o not in rejected]
                    continue
                raise f.tshark.error(
                    result.stderr, result.returncode, "reading the call signalling failed"
                )
            return lines, fields

    def _media_pass(self, f: _Open, heuristic: bool, ctx: RequestContext) -> voip.MediaPass:
        """voip.parse_media over every RTP and RTCP packet (streamed: it can be
        most of the capture). A failure only leaves the streams without its
        findings."""
        argv = f.tshark.argv(
            *_heuristic_args(heuristic), *voip.MEDIA_OPTIONS, "-n", "-Y", "rtp || rtcp",
            *_fields_args(voip.MEDIA_FIELDS), capture=str(f.path),
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
        file (``format`` "wav", the default: the voip.PLAYABLE codecs decoded,
        silence for lost packets; the stream's ``rtpmap`` names dynamic payload
        types) or the payload bytes as they are (``format`` "raw", in sequence
        order, for other codecs). Returns ``codec``, ``seconds``, ``packets``,
        ``silence`` (s) and ``skipped`` (packets of another type)."""
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
            audio = voip.decode_audio(packets, voip.rtpmap_param(params["stream"].get("rtpmap")))
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

    def call_audio(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """A whole call's audio as one stereo WAV at ``dest``: ``streams`` (the
        call's, as voip_calls lists them, each with ``channel`` 0 = left, the
        caller's, or 1, and the ``start`` voip_calls gave) decoded and placed
        in step by their first packet. Streams no codec decodes are left out
        (``skipped``: their indexes). Returns ``seconds``, ``rate``, ``codec``,
        ``silence`` (s) and ``peaks`` (voip.peaks, ``buckets`` per channel,
        default and cap MAX_PEAKS) for the waveform."""
        f = self._require_file()
        raw = params.get("streams")
        if not isinstance(raw, list) or not 0 < len(raw) <= MAX_CALL_STREAMS:
            raise InvalidParamsError(f"streams must list 1 to {MAX_CALL_STREAMS} streams")
        dest = check_destination(param(params, "dest", str), f.path)
        buckets = max(1, min(param(params, "buckets", int, MAX_PEAKS), MAX_PEAKS))
        parts: list[tuple[int, float, voip.Audio]] = []
        skipped: list[int] = []
        for i, item in enumerate(raw):
            key, heuristic = self._stream_param({"stream": item})
            channel, start = item.get("channel"), item.get("start")
            if channel not in (0, 1) or not isinstance(start, int | float):
                raise InvalidParamsError("each stream needs a channel (0 or 1) and a start")
            ctx.progress({"phase": "rtp", "fraction": i / len(raw)})
            lines = self._rtp_pass(f, key, heuristic, voip.AUDIO_FIELDS, ctx)
            try:
                audio = voip.decode_audio(
                    voip.audio_packets(lines), voip.rtpmap_param(item.get("rtpmap"))
                )
            except ValueError:
                skipped.append(i)
                continue
            parts.append((channel, float(start), audio))
        if not parts:
            raise InvalidParamsError(
                f"none of the call's streams can be played: only {voip.PLAYABLE} can",
                {"unsupported": True},
            )
        mixed = voip.mix_call(parts)
        with atomic_output(dest) as tmp:
            voip.write_wav(mixed, tmp)
        return {
            "seconds": round(len(mixed.samples) / 2 / mixed.rate, 3),
            "rate": mixed.rate,
            "codec": mixed.codec,
            "silence": round(mixed.silence / mixed.rate, 3),
            "skipped": skipped,
            "peaks": voip.peaks(mixed, buckets),
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
        """The ``-T fields`` lines of one RTP stream's packets, as they come
        (an IAX2 voice stream's frames made to look like them)."""
        if key.iax2 is not None:
            yield from self._iax2_pass(f, key, fields, ctx)
            return
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

    def _iax2_pass(
        self, f: _Open, key: voip.StreamKey, fields: list[str], ctx: RequestContext
    ) -> Iterator[str]:
        """An IAX2 voice stream's frames as an RTP pass's lines with ``fields``
        (voip_protocols.iax2_as_rtp)."""
        argv = f.tshark.argv(
            "-Y", key.filter(), *_fields_args(voip_protocols.IAX2_VOICE_FIELDS),
            capture=str(f.path),
        )  # fmt: skip
        result = StreamResult()
        raw_lines = (
            raw.decode("utf-8", "replace") for raw in stream_lines(argv, result, ctx.token)
        )
        lines = 0
        for line in voip_protocols.iax2_as_rtp(raw_lines, key.codec, fields):
            lines += 1
            yield line
        if lines == 0 and result.returncode not in (0, None):
            raise f.tshark.error(result.stderr, result.returncode, "reading the IAX2 voice failed")
