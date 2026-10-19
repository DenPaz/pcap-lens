"""Audio decoders (codecs.py) against reference vectors made with ffmpeg 6.1:

    ffmpeg -f lavfi -i sine=frequency=440:sample_rate=16000:duration=0.5
           -f lavfi -i sine=frequency=3000:sample_rate=16000:duration=0.5
           -filter_complex amix=inputs=2 -f s16le src16.pcm
    ffmpeg -f s16le -ar 16000 -ac 1 -i src16.pcm -c:a g722 -f g722 tone.g722
    ffmpeg -f g722 -i tone.g722 -f s16le ref-g722.pcm
    ffmpeg -f s16le -ar 16000 -ac 1 -i src16.pcm -ar 8000 -f s16le src8.pcm
    ffmpeg -f s16le -ar 8000 -ac 1 -i src8.pcm -c:a g726le -b:a 32k -f g726le tone.g726
    ffmpeg -f g726le -code_size 4 -ar 8000 -i tone.g726 -f s16le ref-g726.pcm

(``g726le`` is RFC 3551's packing, the one RTP's G726-32 uses.) G.722 decoders
follow the ITU reference bit for bit; ffmpeg's G.726 is its own reading of
the specification, ±1 in the last of 14 bits now and then, so that one is
compared by signal-to-noise ratio.
"""

from __future__ import annotations

import math
import struct
import sys
from array import array
from pathlib import Path

from pcap_backend import codecs, voip

VECTORS = Path(__file__).resolve().parents[1] / "fixtures" / "codecs"


def _pcm(name: str) -> array[int]:
    samples = array("h", (VECTORS / name).read_bytes())
    if sys.byteorder == "big":
        samples.byteswap()  # (s16le files)
    return samples


def _decode(decoder: codecs.Decoder, data: bytes, packet: int) -> array[int]:
    out = array("h")
    for i in range(0, len(data), packet):
        out.extend(decoder(data[i : i + packet]))
    return out


def _snr_db(signal: array[int], reference: array[int]) -> float:
    power = sum(v * v for v in reference)
    noise = sum((a - b) ** 2 for a, b in zip(signal, reference, strict=True))
    return 10 * math.log10(power / noise) if noise else math.inf


def test_g722_matches_the_reference_decoder_exactly() -> None:
    data = (VECTORS / "tone.g722").read_bytes()
    out = _decode(codecs.g722_decoder(), data, 160)  # 20 ms packets: the state carries over
    assert len(out) == 2 * len(data) == 8000
    assert out == _pcm("ref-g722.pcm")


def test_g726_32_tracks_the_reference_decoder() -> None:
    data = (VECTORS / "tone.g726").read_bytes()
    out = _decode(codecs.g726_32_decoder(), data, 80)
    ref = _pcm("ref-g726.pcm")
    assert len(out) == 2 * len(data) == len(ref)
    assert _snr_db(out, ref) > 35


def test_l16_is_big_endian_and_channels_are_averaged() -> None:
    mono = codecs.l16_decoder()(struct.pack(">3h", 1, -2, 300) + b"\x01")  # (odd byte dropped)
    assert list(mono) == [1, -2, 300]
    stereo = codecs.l16_decoder(2)(struct.pack(">4h", 100, 300, -10, -20))
    assert list(stereo) == [200, -15]


def test_codec_for_static_types_and_the_sdp_rtpmap() -> None:
    assert voip.codec_for(0).name == "G.711 µ-law"  # type: ignore[union-attr]
    g722 = voip.codec_for(9)
    assert g722 is not None and (g722.rate, g722.clock) == (16000, 8000)
    assert voip.codec_for(18) is None  # G.729: not decoded
    assert voip.codec_for(96) is None  # dynamic, no rtpmap
    g726 = voip.codec_for(96, {96: "G726-32/8000"})
    assert g726 is not None and g726.name == "G.726-32"
    l16 = voip.codec_for(97, {97: "L16/16000/2"})
    assert l16 is not None and (l16.name, l16.rate) == ("L16 (2 channels)", 16000)
    assert voip.codec_for(98, {98: "opus/48000/2"}) is None
    assert voip.codec_for(99, {99: "pcma/8000"}).name == "G.711 A-law"  # type: ignore[union-attr]
    # What the client sends back only picks a decoder, and is checked.
    assert voip.rtpmap_param(
        {"96": "G726-32/8000", "97": "x y", "x": "L16/8000", "200": "L16/8000"}
    ) == {96: "G726-32/8000"}
    assert voip.rtpmap_param("nope") == {}


def test_decoding_a_g722_stream_places_packets_by_timestamp() -> None:
    """G.722's RTP clock is 8 kHz for 16 kHz audio: a lost packet is 320 samples of silence."""
    data = (VECTORS / "tone.g722").read_bytes()
    packets = [(i, 160 * i, 9, data[160 * i : 160 * (i + 1)]) for i in range(25) if i != 3]
    audio = voip.decode_audio(packets)
    assert (audio.codec, audio.rate, audio.silence) == ("G.722", 16000, 320)
    assert len(audio.samples) == 8000
