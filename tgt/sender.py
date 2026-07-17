"""Frame transmission over an AF_PACKET raw socket + rate control + pcap output.

Sending needs root/CAP_NET_RAW but *no* scapy and *no* external tools.  When a
raw socket cannot be opened (no privilege, or a non-Linux host), callers can
fall back to pcap-only output, which needs nothing at all.
"""
from __future__ import annotations

import socket
import time
from typing import Optional


class RawSender:
    """Bind an AF_PACKET raw socket to ``iface`` and blast frames."""

    def __init__(self, iface: str):
        self.iface = iface
        self.sock: Optional[socket.socket] = None

    def open(self) -> None:
        if not hasattr(socket, "AF_PACKET"):
            raise OSError("AF_PACKET is Linux-only; use pcap output on this OS")
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                          socket.htons(0x0003))
        s.bind((self.iface, 0))
        self.sock = s

    def send(self, frame: bytes) -> int:
        assert self.sock is not None
        return self.sock.send(frame)

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def __enter__(self) -> "RawSender":
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class RateLimiter:
    """Simple pacing to approximate a target packets-per-second."""

    def __init__(self, pps: float):
        self.pps = pps
        self.interval = 1.0 / pps if pps and pps > 0 else 0.0
        self._next = time.perf_counter()

    def wait(self) -> None:
        if self.interval <= 0:
            return
        self._next += self.interval
        now = time.perf_counter()
        delay = self._next - now
        if delay > 0:
            time.sleep(delay)
        elif delay < -1.0:
            # fell badly behind (e.g. slow terminal) — resync
            self._next = now
