"""Audio decoders for RTP payloads beyond G.711: G.722 (64 kbit/s), G.726
at 32 kbit/s (RFC 3551 packing) and L16. Pure Python (the backend is
stdlib-only), integer arithmetic as in the ITU reference implementations, so
the output matches other decoders sample for sample.

Each ``*_decoder()`` returns a function that decodes one packet's payload to
16-bit samples, keeping the codec's state between packets of a stream.
"""

from __future__ import annotations

import sys
from array import array
from collections.abc import Callable

Decoder = Callable[[bytes], "array[int]"]


def _sat(x: int) -> int:
    return max(-32768, min(x, 32767))


# ---------------------------------------------------------------------- G.722

_WL = (-60, -30, 58, 172, 334, 538, 1198, 3042)
_RL42 = (0, 7, 6, 5, 4, 3, 2, 1, 7, 6, 5, 4, 3, 2, 1, 0)
_ILB = (
    2048, 2093, 2139, 2186, 2233, 2282, 2332, 2383, 2435, 2489, 2543, 2599, 2656, 2714,
    2774, 2834, 2896, 2960, 3025, 3091, 3158, 3228, 3298, 3371, 3444, 3520, 3597, 3676,
    3756, 3838, 3922, 4008,
)  # fmt: skip
_WH = (0, -214, 798)
_RH2 = (2, 1, 2, 1)
_QM2 = (-7408, -1616, 7408, 1616)
_QM4 = (
    0, -20456, -12896, -8968, -6288, -4240, -2584, -1200,
    20456, 12896, 8968, 6288, 4240, 2584, 1200, 0,
)  # fmt: skip
_QM6 = (
    -136, -136, -136, -136, -24808, -21904, -19008, -16704, -14984, -13512, -12280, -11192,
    -10232, -9360, -8576, -7856, -7192, -6576, -6000, -5456, -4944, -4464, -4008, -3576,
    -3168, -2776, -2400, -2032, -1688, -1360, -1040, -728, 24808, 21904, 19008, 16704,
    14984, 13512, 12280, 11192, 10232, 9360, 8576, 7856, 7192, 6576, 6000, 5456, 4944,
    4464, 4008, 3576, 3168, 2776, 2400, 2032, 1688, 1360, 1040, 728, 432, 136, -432, -136,
)  # fmt: skip
_QMF = (3, -11, 12, 32, -210, 951, 3876, -805, 362, -156, 53, -11)


class _Band:
    """The adaptive predictor and quantizer state of one G.722 sub-band."""

    __slots__ = ("a", "ap", "b", "bp", "d", "det", "nb", "p", "r", "s", "sg", "sp", "sz")

    def __init__(self, det: int) -> None:
        self.s = self.sp = self.sz = self.nb = 0
        self.det = det
        self.r = [0, 0, 0]
        self.a = [0, 0, 0]
        self.ap = [0, 0, 0]
        self.p = [0, 0, 0]
        self.d = [0] * 7
        self.b = [0] * 7
        self.bp = [0] * 7
        self.sg = [0] * 7

    def update(self, d: int) -> None:
        """Block 4 of G.722: pole and zero predictor adaptation for difference ``d``."""
        a, b, p, r, dd, sg, bp, ap = (
            self.a,
            self.b,
            self.p,
            self.r,
            self.d,
            self.sg,
            self.bp,
            self.ap,
        )
        dd[0] = d
        r[0] = _sat(self.s + d)
        p[0] = _sat(self.sz + d)
        # UPPOL2
        for i in range(3):
            sg[i] = p[i] >> 15
        wd1 = _sat(a[1] << 2)
        wd2 = -wd1 if sg[0] == sg[1] else wd1
        wd2 = min(wd2, 32767)
        wd3 = (wd2 >> 7) + (128 if sg[0] == sg[2] else -128)
        wd3 += (a[2] * 32512) >> 15
        ap[2] = max(-12288, min(12288, wd3))
        # UPPOL1
        sg[0] = p[0] >> 15
        sg[1] = p[1] >> 15
        wd1 = 192 if sg[0] == sg[1] else -192
        wd2 = (a[1] * 32640) >> 15
        ap[1] = _sat(wd1 + wd2)
        wd3 = _sat(15360 - ap[2])
        if ap[1] > wd3:
            ap[1] = wd3
        elif ap[1] < -wd3:
            ap[1] = -wd3
        # UPZERO
        wd1 = 0 if d == 0 else 128
        sg[0] = d >> 15
        for i in range(1, 7):
            sg[i] = dd[i] >> 15
            wd2 = wd1 if sg[i] == sg[0] else -wd1
            bp[i] = _sat(wd2 + ((b[i] * 32640) >> 15))
        # DELAYA
        for i in range(6, 0, -1):
            dd[i] = dd[i - 1]
            b[i] = bp[i]
        for i in (2, 1):
            r[i] = r[i - 1]
            p[i] = p[i - 1]
            a[i] = ap[i]
        # FILTEP, FILTEZ, PREDIC
        sp = _sat(((a[1] * _sat(r[1] + r[1])) >> 15) + ((a[2] * _sat(r[2] + r[2])) >> 15))
        sz = 0
        for i in range(6, 0, -1):
            sz += (b[i] * _sat(dd[i] + dd[i])) >> 15
        self.sp, self.sz = sp, _sat(sz)
        self.s = _sat(sp + self.sz)


def g722_decoder() -> Decoder:
    """G.722 at 64 kbit/s: each byte gives two 16 kHz samples."""
    low, high = _Band(32), _Band(8)
    x = [0] * 24

    def decode(payload: bytes) -> array[int]:
        out = array("h")
        for code in payload:
            # Low band: 6 bits.
            wd1 = code & 0x3F
            ihigh = (code >> 6) & 0x03
            rlow = max(-16384, min(16383, low.s + ((low.det * _QM6[wd1]) >> 15)))
            wd1 >>= 2
            dlow = (low.det * _QM4[wd1]) >> 15
            nb = ((low.nb * 127) >> 7) + _WL[_RL42[wd1]]
            low.nb = nb = max(0, min(18432, nb))
            shift = 8 - (nb >> 11)
            ilb = _ILB[(nb >> 6) & 31]
            low.det = (ilb << -shift if shift < 0 else ilb >> shift) << 2
            low.update(dlow)
            # High band: 2 bits.
            dhigh = (high.det * _QM2[ihigh]) >> 15
            rhigh = max(-16384, min(16383, dhigh + high.s))
            nb = ((high.nb * 127) >> 7) + _WH[_RH2[ihigh]]
            high.nb = nb = max(0, min(22528, nb))
            shift = 10 - (nb >> 11)
            ilb = _ILB[(nb >> 6) & 31]
            high.det = (ilb << -shift if shift < 0 else ilb >> shift) << 2
            high.update(dhigh)
            # Receive QMF: two output samples.
            del x[:2]
            x.append(rlow + rhigh)
            x.append(rlow - rhigh)
            xout1 = xout2 = 0
            for i in range(12):
                xout2 += x[2 * i] * _QMF[i]
                xout1 += x[2 * i + 1] * _QMF[11 - i]
            out.append(_sat(xout1 >> 11))
            out.append(_sat(xout2 >> 11))
        return out

    return decode


# ---------------------------------------------------------------------- G.726

_POWER2 = (1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000)
# 32 kbit/s (4-bit codes): log quantizer, scale factor and speed control tables.
_DQLN = (-2048, 4, 135, 213, 273, 323, 373, 425, 425, 373, 323, 273, 213, 135, 4, -2048)
_WI = (-12, 18, 41, 64, 112, 198, 355, 1122, 1122, 355, 198, 112, 64, 41, 18, -12)
_FI = (0, 0, 0, 0x200, 0x200, 0x200, 0x600, 0xE00, 0xE00, 0x600, 0x200, 0x200, 0x200, 0, 0, 0)


def _quan(val: int) -> int:
    for i, limit in enumerate(_POWER2):
        if val < limit:
            return i
    return len(_POWER2)


def _fmult(an: int, srn: int) -> int:
    anmag = an if an > 0 else (-an) & 0x1FFF
    anexp = _quan(anmag) - 6
    anmant = 32 if anmag == 0 else (anmag >> anexp if anexp >= 0 else anmag << -anexp)
    wanexp = anexp + ((srn >> 6) & 0xF) - 13
    wanmant = (anmant * (srn & 0o77) + 0x30) >> 4
    retval = (wanmant << wanexp) & 0x7FFF if wanexp >= 0 else wanmant >> -wanexp
    return -retval if (an ^ srn) < 0 else retval


def _float(mag: int, negative: bool) -> int:
    """A magnitude as G.726's 4-bit exponent, 6-bit mantissa (minus 0x400 if negative)."""
    exp = _quan(mag)
    value = (exp << 6) + ((mag << 6) >> exp)
    return value - 0x400 if negative else value


class _G726:
    """The state of a G.726 decoder (the ITU-T reference's g72x_state)."""

    def __init__(self) -> None:
        self.yl = 34816
        self.yu = 544
        self.dms = self.dml = self.ap = self.td = 0
        self.a = [0, 0]
        self.pk = [0, 0]
        self.sr = [32, 32]
        self.b = [0] * 6
        self.dq = [32] * 6

    def step_size(self) -> int:
        if self.ap >= 256:
            return self.yu
        y = self.yl >> 6
        dif = self.yu - y
        al = self.ap >> 2
        if dif > 0:
            y += (dif * al) >> 6
        elif dif < 0:
            y += (dif * al + 0x3F) >> 6
        return y

    def decode(self, code: int) -> int:
        sezi = sum(_fmult(self.b[i] >> 2, self.dq[i]) for i in range(6))
        sez = sezi >> 1
        se = (sezi + _fmult(self.a[1] >> 2, self.sr[1]) + _fmult(self.a[0] >> 2, self.sr[0])) >> 1
        y = self.step_size()
        # Reconstruct the quantized difference.
        dql = _DQLN[code] + (y >> 2)
        if dql < 0:
            dq = -0x8000 if code & 0x08 else 0
        else:
            dex = (dql >> 7) & 15
            dqt = 128 + (dql & 127)
            dq = (dqt << 7) >> (14 - dex)
            if code & 0x08:
                dq -= 0x8000
        sr = se - (dq & 0x3FFF) if dq < 0 else se + dq
        self.update(y, _WI[code] << 5, _FI[code], dq, sr, sr - se + sez)
        return _sat(sr << 2)

    def update(self, y: int, wi: int, fi: int, dq: int, sr: int, dqsez: int) -> None:
        """The reference's update(): scale factor, predictor and speed control."""
        pk0 = 1 if dqsez < 0 else 0
        mag = dq & 0x7FFF
        ylint = self.yl >> 15
        ylfrac = (self.yl >> 10) & 0x1F
        thr1 = (32 + ylfrac) << ylint
        thr2 = 31 << 10 if ylint > 9 else thr1
        dqthr = (thr2 + (thr2 >> 1)) >> 1
        tr = 1 if self.td != 0 and mag > dqthr else 0  # (a modem signal)
        # Quantizer scale factor adaptation.
        self.yu = max(544, min(5120, y + ((wi - y) >> 5)))
        self.yl += self.yu + ((-self.yl) >> 6)
        a2p = 0
        if tr:
            self.a[:] = [0, 0]
            self.b[:] = [0] * 6
        else:
            a2p = self._poles(pk0, dqsez)
            for i in range(6):
                self.b[i] -= self.b[i] >> 8
                if mag:
                    self.b[i] += 128 if (dq ^ self.dq[i]) >= 0 else -128
        self.dq[1:] = self.dq[:5]
        self.dq[0] = (0x20 if dq >= 0 else -992) if mag == 0 else _float(mag, dq < 0)
        self.sr[1] = self.sr[0]
        if sr == 0:
            self.sr[0] = 0x20
        elif sr > 0:
            self.sr[0] = _float(sr, False)
        elif sr > -32768:
            self.sr[0] = _float(-sr, True)
        else:
            self.sr[0] = -992
        self.pk[1], self.pk[0] = self.pk[0], pk0
        self.td = 0 if tr else (1 if a2p < -11776 else 0)
        # Adaptation speed control.
        self.dms += (fi - self.dms) >> 5
        self.dml += ((fi << 2) - self.dml) >> 7
        if tr:
            self.ap = 256
        elif y < 1536 or self.td or abs((self.dms << 2) - self.dml) >= (self.dml >> 3):
            self.ap += (0x200 - self.ap) >> 4
        else:
            self.ap += (-self.ap) >> 4

    def _poles(self, pk0: int, dqsez: int) -> int:
        """Update the pole predictor coefficients (UPA2, UPA1, LIMC, LIMD); a2p."""
        a = self.a
        pks1 = pk0 ^ self.pk[0]
        a2p = a[1] - (a[1] >> 7)
        if dqsez != 0:
            fa1 = a[0] if pks1 else -a[0]
            if fa1 < -8191:
                a2p -= 0x100
            elif fa1 > 8191:
                a2p += 0xFF
            else:
                a2p += fa1 >> 5
            if pk0 ^ self.pk[1]:
                a2p = -12288 if a2p <= -12160 else 12288 if a2p >= 12416 else a2p - 0x80
            else:
                a2p = -12288 if a2p <= -12416 else 12288 if a2p >= 12160 else a2p + 0x80
        a[1] = a2p
        a[0] -= a[0] >> 8
        if dqsez != 0:
            a[0] += -192 if pks1 else 192
        a1ul = 15360 - a2p
        a[0] = max(-a1ul, min(a1ul, a[0]))
        return a2p


def g726_32_decoder() -> Decoder:
    """G.726 at 32 kbit/s, packed as RFC 3551 says (the first sample in the
    low four bits of each byte): two 8 kHz samples a byte."""
    state = _G726()

    def decode(payload: bytes) -> array[int]:
        out = array("h")
        for byte in payload:
            out.append(state.decode(byte & 0x0F))
            out.append(state.decode(byte >> 4))
        return out

    return decode


# ---------------------------------------------------------------------- L16


def l16_decoder(channels: int = 1) -> Decoder:
    """Linear 16-bit big-endian PCM (RFC 3551 L16); channels are averaged."""

    def decode(payload: bytes) -> array[int]:
        samples = array("h", payload[: len(payload) - len(payload) % 2])
        if sys.byteorder == "little":
            samples.byteswap()  # (network order to native)
        if channels == 1:
            return samples
        frames = len(samples) // channels
        return array(
            "h",
            (sum(samples[f * channels : (f + 1) * channels]) // channels for f in range(frames)),
        )

    return decode
