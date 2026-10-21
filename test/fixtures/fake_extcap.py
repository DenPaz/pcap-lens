"""A stand-in extcap helper for the capture tests (stdlib only).

Installed by the tests into tshark's personal extcap folder with a shebang
naming the test's Python. It offers one interface, ``fake-remote``, with
three options, and captures by writing a pcap of UDP packets carrying the
``--marker`` text into the FIFO tshark gives it: ``--packets N`` of them,
then it exits (the capture ends); ``--packets 0`` writes one every 0.1 s
until it is stopped.
"""

from __future__ import annotations

import argparse
import signal
import struct
import sys
import time

INTERFACE = "fake-remote"


def _udp_packet(marker: bytes, seq: int) -> bytes:
    payload = marker + b" #" + str(seq).encode()
    udp = struct.pack("!HHHH", 40000, 9999, 8 + len(payload), 0) + payload
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), seq & 0xFFFF, 0, 64, 17, 0,
        bytes([10, 9, 0, 1]), bytes([10, 9, 0, 2]),
    )  # fmt: skip
    eth = bytes.fromhex("020000000002020000000001") + b"\x08\x00"
    return eth + ip + udp


def capture(fifo: str, packets: int, marker: str) -> None:
    stop = False

    def on_signal(_sig: int, _frame: object) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    with open(fifo, "wb") as out:  # noqa: PTH123 - a FIFO
        out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        out.flush()
        seq = 0
        while not stop and (packets == 0 or seq < packets):
            seq += 1
            data = _udp_packet(marker.encode(), seq)
            now = time.time()
            out.write(struct.pack("<IIII", int(now), int(now % 1 * 1e6), len(data), len(data)))
            out.write(data)
            out.flush()
            if packets == 0:
                time.sleep(0.1)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--extcap-interfaces", action="store_true")
    p.add_argument("--extcap-interface")
    p.add_argument("--extcap-dlts", action="store_true")
    p.add_argument("--extcap-config", action="store_true")
    p.add_argument("--extcap-version")
    p.add_argument("--extcap-capture-filter")
    p.add_argument("--capture", action="store_true")
    p.add_argument("--fifo")
    p.add_argument("--packets", type=int, default=3)
    p.add_argument("--marker", default="")
    p.add_argument("--fast", action="store_true")
    args, _ = p.parse_known_args()
    if args.extcap_interfaces:
        print("extcap {version=1.0}{help=https://example.invalid/fake}")  # noqa: T201
        print(f"interface {{value={INTERFACE}}}{{display=Fake remote capture}}")  # noqa: T201
    elif args.extcap_dlts:
        print("dlt {number=1}{name=EN10MB}{display=Ethernet}")  # noqa: T201
    elif args.extcap_config:
        print(  # noqa: T201
            "arg {number=0}{call=--marker}{display=Marker text}{type=string}"
            "{tooltip=Put in every packet {really}}{required=true}{group=Server}\n"
            "arg {number=1}{call=--packets}{display=Packets}{type=unsigned}{default=3}"
            "{range=0,1000}\n"
            "arg {number=2}{call=--speed}{display=Speed}{type=selector}\n"
            "value {arg=2}{value=slow}{display=Slow}\n"
            "value {arg=2}{value=fast}{display=Fast}{default=true}\n"
            "arg {number=3}{call=--fast}{display=Hurry}{type=boolflag}"
        )
    elif args.capture and args.fifo:
        if not args.marker:
            print("fake-remote: --marker is required", file=sys.stderr)  # noqa: T201
            return 1
        capture(args.fifo, args.packets, args.marker)
    return 0


if __name__ == "__main__":
    sys.exit(main())
