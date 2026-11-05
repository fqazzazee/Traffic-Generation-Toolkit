"""Frame transmission over AF_PACKET raw sockets + rate control + pcap output.

Sending needs root/CAP_NET_RAW but *no* scapy and *no* external tools.  When a
raw socket cannot be opened (no privilege, or a non-Linux host), callers can
fall back to pcap-only output, which needs nothing at all.
"""
from __future__ import annotations

import socket
import threading
import time
from typing import Dict, List, Optional


def split_ifaces(spec: str) -> List[str]:
    """``"a,b, c"`` -> ``["a", "b", "c"]`` (order kept, duplicates dropped)."""
    out: List[str] = []
    for name in (spec or "").split(","):
        name = name.strip()
        if name and name not in out:
            out.append(name)
    return out


class RawSender:
    """Bind an AF_PACKET raw socket to ``iface`` and blast frames.

    ``iface`` may name several interfaces (``"tgt0,tgt1"``): each gets its own
    socket and every frame is fanned out to all of them, so one run can feed
    several sensors side by side. A failing interface never stops the others:
    its sends are counted as errors in :attr:`counters` (per interface) and a
    socket that could not be opened is retried every :attr:`RETRY` seconds.
    :meth:`send` raises only when the frame left on *no* interface.
    """

    RETRY = 5.0                     # seconds between re-opens of a dead iface

    def __init__(self, iface: str):
        self.iface = iface
        self.ifaces = split_ifaces(iface) or [iface]
        self.sock: Optional[socket.socket] = None   # first socket (compat)
        self.socks: Dict[str, Optional[socket.socket]] = {}
        # per interface: packets, bytes, errors, last_error
        self.counters: Dict[str, dict] = {
            n: {"packets": 0, "bytes": 0, "errors": 0, "last_error": ""}
            for n in self.ifaces}
        self._retry_at: Dict[str, float] = {}

    @staticmethod
    def _open_one(name: str) -> socket.socket:
        if not hasattr(socket, "AF_PACKET"):
            raise OSError("AF_PACKET is Linux-only; use pcap output on this OS")
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                          socket.htons(0x0003))
        try:
            s.bind((name, 0))
        except OSError:
            s.close()
            raise
        return s

    def open(self) -> None:
        """Open every interface; raises OSError only if none could be."""
        errors: List[OSError] = []
        for name in self.ifaces:
            try:
                self.socks[name] = self._open_one(name)
            except OSError as e:
                self.socks[name] = None
                self._fail(name, f"open: {e}")
                self._retry_at[name] = time.monotonic() + self.RETRY
                errors.append(e)
        if not any(self.socks.values()):
            self.close()
            if len(errors) == 1:
                raise errors[0]
            raise OSError("; ".join(f"{n}: {e}" for n, e in
                                    zip(self.ifaces, errors)))
        self.sock = next(s for s in self.socks.values() if s is not None)

    @property
    def open_errors(self) -> List[str]:
        """Interfaces whose socket is not open, with the last error."""
        return [f"{n} ({self.counters[n]['last_error']})"
                for n, s in self.socks.items() if s is None]

    def _fail(self, name: str, err: str) -> None:
        c = self.counters[name]
        c["errors"] += 1
        c["last_error"] = err

    def send(self, frame: bytes) -> int:
        if not self.socks:
            raise OSError("sender not open")
        sent, last = 0, None
        for name, s in self.socks.items():
            c = self.counters[name]
            if s is None:
                if time.monotonic() < self._retry_at.get(name, 0.0):
                    c["errors"] += 1        # frame missed on this iface
                    continue
                try:
                    s = self.socks[name] = self._open_one(name)
                except OSError as e:
                    self._retry_at[name] = time.monotonic() + self.RETRY
                    self._fail(name, f"open: {e}")
                    last = e
                    continue
            try:
                n = s.send(frame)
            except OSError as e:
                self._fail(name, str(e))
                last = e
                continue
            c["packets"] += 1
            c["bytes"] += len(frame)
            sent = sent or n
        if not sent:
            raise last if last is not None else OSError("no interface open")
        return sent

    def close(self) -> None:
        for name, s in list(self.socks.items()):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
            self.socks[name] = None
        self.sock = None

    def __enter__(self) -> "RawSender":
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class RateLimiter:
    """Simple pacing to approximate a target packets-per-second."""

    # catch-up allowed after falling behind, in seconds of sends
    MAX_BACKLOG = 0.1

    def __init__(self, pps: float):
        self.pps = pps
        self.interval = 1.0 / pps if pps and pps > 0 else 0.0
        self._next = time.perf_counter()

    def set_rate(self, pps: float) -> None:
        """Change the pace of a running limiter (no burst to catch up)."""
        self.pps = pps
        self.interval = 1.0 / pps if pps and pps > 0 else 0.0
        self._next = time.perf_counter()

    def wait(self, stop: Optional[threading.Event] = None) -> None:
        """Block until the next send slot; with ``stop``, long waits (slow
        rates) return early once the event is set."""
        if self.interval <= 0:
            return
        self._next += self.interval
        now = time.perf_counter()
        delay = self._next - now
        if delay > 0:
            if stop is not None and delay > 0.05:
                stop.wait(delay)
            else:
                time.sleep(delay)
        elif delay < -self.MAX_BACKLOG:
            # fell behind (a stall, a slow rebuild): resync instead of
            # bursting the whole backlog onto the wire
            self._next = now
