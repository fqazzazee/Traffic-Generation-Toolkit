"""Minimal libpcap (classic) file writer — pure stdlib.

Writing raw frames to a ``.pcap`` needs no root and no interface, so it is the
zero-privilege way to preview exactly what TGT would put on the wire, or to feed
``tcpreplay`` on a host that has a real SPAN port.
"""
from __future__ import annotations

import struct
import time

PCAP_MAGIC = 0xA1B2C3D4          # microsecond resolution, big-endian magic
LINKTYPE_ETHERNET = 1


class PcapWriter:
    """Append frames to a classic pcap.

    The file is flushed to disk at least every ``flush_interval`` seconds (and
    on close), so a run killed by SIGKILL/OOM still leaves a readable capture
    holding everything up to the last flush.
    """

    def __init__(self, path: str, snaplen: int = 65535,
                 flush_interval: float = 1.0):
        self._fh = open(path, "wb")
        self._fh.write(struct.pack(
            "!IHHiIII",
            PCAP_MAGIC, 2, 4, 0, 0, snaplen, LINKTYPE_ETHERNET,
        ))
        self.count = 0
        self.bytes = 0
        self.flush_interval = flush_interval
        self._last_flush = time.monotonic()
        self.flush()

    def flush(self) -> None:
        self._fh.flush()
        self._last_flush = time.monotonic()

    def write(self, frame: bytes, ts: float | None = None) -> None:
        if ts is None:
            ts = time.time()
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        self._fh.write(struct.pack("!IIII", sec, usec, len(frame), len(frame)))
        self._fh.write(frame)
        self.count += 1
        self.bytes += len(frame)
        if time.monotonic() - self._last_flush >= self.flush_interval:
            self.flush()

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
