"""Following a capture file another program is still writing (``open {follow}``).

tcpdump ``-w``, Wireshark or a collector append packets to a pcap or pcapng
file; the viewer shows them as they arrive, the way a live capture does. The
file is read from its start and its complete records (pcap) or blocks
(pcapng) go into the pipe the index pass reads (``tshark -r - -l``), so one
tshark pass reads it all; a record still being written waits for the next
look. The file itself is the capture: detail, filters and follow read it
while it grows (a half-written last record is something tshark already
handles, as in a cut-short capture). Following ends with ``stop`` (the rows
so far stay), when the file gets shorter (replaced or truncated) or when
something it holds isn't a record.
"""

from __future__ import annotations

import contextlib
import os
import struct
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import IO, Any

from .cancellation import CancelledError, CancelToken
from .capture import STATS_INTERVAL_S, _Blocks
from .tshark import ToolError

# How often the file is looked at for new data.
POLL_INTERVAL_S = 0.5
# How long a file may take to hold its header (a writer that just created it).
START_TIMEOUT_S = 20.0
# Bytes read from the file at a time.
READ_SIZE = 1 << 20
# A pcap record longer than this isn't one (Wireshark's largest is 256 MiB).
_MAX_RECORD = 1 << 28

# pcap magic numbers (as read little-endian) → (byte order, record header length).
_PCAP_MAGICS = {
    0xA1B2C3D4: ("<", 16),  # microseconds
    0xA1B23C4D: ("<", 16),  # nanoseconds
    0xA1B2CD34: ("<", 24),  # Kuznetsov's modified pcap: 8 more bytes per record
    0xD4C3B2A1: (">", 16),
    0x4D3CB2A1: (">", 16),
    0x34CDB2A1: (">", 24),
}
_PCAP_HEADER = 24
_PCAPNG_MAGIC = 0x0A0D0D0A


class _Records:
    """Cuts a pcap byte stream into its file header and complete records
    (and counts them); the counterpart of capture._Blocks for pcap."""

    def __init__(self) -> None:
        self.pending = bytearray()
        self.endian: str | None = None
        self.record_header = 16
        self.packets = 0

    def feed(self, chunk: bytes) -> bytes:
        """The header and complete records now available (b"" if none yet)."""
        buf = self.pending
        buf += chunk
        pos = 0
        if self.endian is None:
            if len(buf) < _PCAP_HEADER:
                return b""
            (magic,) = struct.unpack_from("<I", buf, 0)
            if magic not in _PCAP_MAGICS:
                raise ToolError("the file isn't a pcap capture any more (its header changed)")
            self.endian, self.record_header = _PCAP_MAGICS[magic]
            pos = _PCAP_HEADER
        while len(buf) - pos >= self.record_header:
            (incl_len,) = struct.unpack_from(self.endian + "I", buf, pos + 8)
            if incl_len > _MAX_RECORD:
                raise ToolError(f"the file holds something that isn't a pcap record ({incl_len} B)")
            end = pos + self.record_header + incl_len
            if len(buf) < end:
                break
            self.packets += 1
            pos = end
        done = bytes(buf[:pos])
        del buf[:pos]
        return done


def follow_format(path: Path) -> str:
    """``"pcap"`` or ``"pcapng"`` when the file can be followed (``"pending"``
    while it is still empty), else a ToolError saying why: compressed captures
    and other formats can't be, as they hold no complete record until the
    writer closes them."""
    try:
        with path.open("rb") as fh:
            head = fh.read(4)
    except OSError as exc:
        raise ToolError(f"cannot read {path.name}: {exc.strerror or exc}") from exc
    if len(head) < 4:
        return "pending"  # (just created: the writer hasn't written the header yet)
    (magic,) = struct.unpack("<I", head)
    if magic in _PCAP_MAGICS:
        return "pcap"
    if magic == _PCAPNG_MAGIC:
        return "pcapng"
    raise ToolError(
        f"{path.name} can't be followed: only uncompressed pcap and pcapng files grow "
        "a whole packet at a time"
    )


class FollowFile:
    """A capture file read as it grows into the pipe the index pass reads.
    Shaped like capture.LiveCapture (start, take_reader, stop, abort, join,
    describe…), so the open capture treats it as a capture in progress."""

    def __init__(
        self,
        path: Path,
        notify: Callable[[dict[str, Any]], None],
        poll_interval: float = POLL_INTERVAL_S,
    ) -> None:
        self.path = path
        self.notify = notify
        self.poll_interval = poll_interval
        self.started_at = 0.0
        self.ended_at: float | None = None
        self.packets = 0
        self.bytes = 0
        self.dropped: int | None = None  # (nothing is dropped: the file holds every packet)
        self.error: str | None = None
        self.started = threading.Event()  # the file's header went to the pipe
        self.ended = threading.Event()  # following ended; the rows so far stay
        self._stop = threading.Event()
        self._reader: int | None = None
        self._writer: int | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ lifecycle

    def start(self, token: CancelToken) -> None:
        """Start reading the file and wait until its header is in the pipe
        (ToolError when it can't be followed or holds no header in time)."""
        follow_format(self.path)  # (refuses compressed files and other formats now)
        fh = self.path.open("rb")
        self._reader, self._writer = os.pipe()
        self.started_at = time.time()
        self._thread = threading.Thread(target=self._copy, args=(fh,), daemon=True)
        self._thread.start()
        deadline = time.monotonic() + START_TIMEOUT_S
        while not self.started.wait(0.05):
            if self.ended.is_set():
                self.join()
                self.close_reader()
                raise ToolError(self.error or f"{self.path.name} can't be followed")
            if token.cancelled or time.monotonic() > deadline:
                self.abort()
                self.join()
                self.close_reader()
                if token.cancelled:
                    raise CancelledError("following cancelled")
                raise ToolError(f"{self.path.name} holds no capture header yet")

    def take_reader(self) -> int:
        """The read end of the pipe for the index pass (which then owns it)."""
        with self._lock:
            fd, self._reader = self._reader, None
        if fd is None:
            raise ToolError("the followed file's data was already taken")
        return fd

    def close_reader(self) -> None:
        with self._lock:
            fd, self._reader = self._reader, None
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)

    def stop(self) -> bool:
        """Stop following (the rows read so far stay). False if it had stopped."""
        with self._lock:
            if self.ended.is_set() or self._stop.is_set():
                return False
            self._stop.set()
        return True

    def abort(self) -> None:
        self._stop.set()

    def join(self, timeout: float | None = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout)

    @property
    def running(self) -> bool:
        return self._thread is not None and not self.ended.is_set()

    def describe(self) -> dict[str, Any]:
        """Like a live capture's description, with ``follow`` and no interfaces."""
        return {
            "follow": True,
            "file": self.path.name,
            "interfaces": [],
            "filter": "",
            "running": self.running,
            "startedAt": self.started_at,
            "endedAt": self.ended_at,
            "packets": self.packets,
            "bytes": self.bytes,
            "dropped": None,
            "error": self.error,
            "limits": {"packets": None, "seconds": None, "bytes": None},
        }

    # ------------------------------------------------------------------ the thread

    def _splitter(self, fh: IO[bytes]) -> _Blocks | _Records | None:
        """The splitter for the file's format, once its first bytes are there."""
        fh.seek(0)
        head = fh.read(4)
        if len(head) < 4:
            return None
        (magic,) = struct.unpack("<I", head)
        if magic == _PCAPNG_MAGIC:
            return _Blocks()
        if magic in _PCAP_MAGICS:
            return _Records()
        raise ToolError(f"{self.path.name} isn't a pcap or pcapng capture")

    def _copy(self, fh: IO[bytes]) -> None:
        splitter: _Blocks | _Records | None = None
        position = 0
        last_stats = time.monotonic()
        try:
            while not self._stop.is_set():
                size = self._size(fh, position)
                if splitter is None:
                    splitter = self._splitter(fh)
                    fh.seek(0)
                grew = False
                if splitter is not None and size > position:
                    fh.seek(position)
                    chunk = fh.read(min(READ_SIZE, size - position))
                    position += len(chunk)
                    grew = bool(chunk)
                    data = splitter.feed(chunk)
                    if data:
                        # Before writing: start() returns on it, and only then does
                        # the index pass read the pipe, which holds 64 KiB at most.
                        self.started.set()
                        if not self._send(data):
                            break  # nobody reads the rows any more
                        with self._lock:
                            self.bytes += len(data)
                            self.packets = splitter.packets
                now = time.monotonic()
                if self.started.is_set() and now - last_stats >= STATS_INTERVAL_S:
                    last_stats = now
                    self.notify({"event": "stats", **self._stats()})
                if not grew:
                    self._stop.wait(self.poll_interval)
        except (OSError, ToolError) as exc:
            self.error = str(exc)
        finally:
            fh.close()
            writer, self._writer = self._writer, None
            if writer is not None:
                with contextlib.suppress(OSError):
                    os.close(writer)  # the index pass sees the end of the file
            self.ended_at = time.time()
            self.ended.set()
            event = {"event": "stopped", **self._stats(), "dropped": None}
            if self.error:
                event["error"] = self.error
            self.notify(event)

    def _size(self, fh: IO[bytes], position: int) -> int:
        """The file's size now (ToolError when it got shorter than what was read,
        or when the path names another file: rotated by a rename, or removed)."""
        own = os.fstat(fh.fileno())
        try:
            now = self.path.stat()
        except FileNotFoundError:
            raise ToolError(f"{self.path.name} was removed or renamed") from None
        if own.st_ino and (now.st_dev, now.st_ino) != (own.st_dev, own.st_ino):
            raise ToolError(f"{self.path.name} was replaced by another file (rotated?)")
        if own.st_size < position:
            raise ToolError(f"{self.path.name} got shorter (it was replaced or truncated)")
        return own.st_size

    def _send(self, data: bytes) -> bool:
        """Write to the index pass's pipe; False once tshark is gone."""
        writer = self._writer
        if writer is None:
            return False
        view = memoryview(data)
        try:
            while view:
                n = os.write(writer, view)
                view = view[n:]
        except OSError:
            return False
        return True

    def _stats(self) -> dict[str, Any]:
        end = self.ended_at or time.time()
        with self._lock:
            return {
                "packets": self.packets,
                "bytes": self.bytes,
                "seconds": round(max(0.0, end - self.started_at), 3),
            }
