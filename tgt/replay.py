"""Streamed pcap/pcapng replay as an engine frame source.

:class:`ReplaySource` is what the engine iterates instead of a built cycle on
``tgt run --replay FILE``: every pass re-reads the file record by record (so a
multi-gigabyte capture replays in constant memory), re-addresses each frame
through :class:`tgt.rewrite.Rewriter` when ``--remap-*`` / ``--vlan`` are
given (or onto a modeled environment by role with ``--remap-env``, see
:mod:`tgt.remapenv`), and — with ``--replay-realtime`` or ``--replay-speed
X`` — sleeps so frames leave with the capture's own spacing divided by
``X`` (2 = twice as fast, 0.5 = half speed). Idle gaps longer than
:data:`MAX_GAP` seconds (of capture time) are cut to it, and a source that
falls more than a second behind (a pause, a slow host) resynchronises
instead of bursting.
``--replay-loop N`` stops the run after N passes (0 = until stopped).
"""
from __future__ import annotations

import threading
import time
from typing import Iterator, Optional, Tuple

from . import pcapread
from .rewrite import Rewriter, RewriteError

MAX_GAP = 5.0


def rewriter_for(cfg) -> Optional[Rewriter]:
    """The run's Rewriter (None when nothing is remapped). Raises
    RewriteError on bad / conflicting options."""
    if getattr(cfg, "remap_env", None):
        if (getattr(cfg, "remap_ip", None) or getattr(cfg, "remap_subnet",
                                                      None)
                or getattr(cfg, "remap_mac", None)
                or getattr(cfg, "replay_vlan", None) is not None):
            raise RewriteError("--remap-env picks every address and VLAN "
                               "itself: drop --remap-ip/--remap-subnet/"
                               "--remap-mac/--vlan")
        from .remapenv import plan_for
        return plan_for(cfg).rewriter()
    return Rewriter.from_specs(
        getattr(cfg, "remap_ip", ()) or (),
        getattr(cfg, "remap_subnet", ()) or (),
        getattr(cfg, "remap_mac", ()) or (),
        getattr(cfg, "replay_vlan", None))


class ReplaySource:
    """Iterable of ``("replay", frame, "replay")``; each ``iter()`` is one
    pass over the file."""

    def __init__(self, cfg, stop: Optional[threading.Event] = None,
                 paced: bool = True):
        self.path = cfg.replay_path
        speed = float(getattr(cfg, "replay_speed", 0.0) or 0.0)
        if not speed and cfg.replay_realtime:
            speed = 1.0
        self.speed = speed
        self.realtime = bool(speed > 0 and paced)
        self.passes = int(getattr(cfg, "replay_loop", 0) or 0)
        self.resolution = getattr(cfg, "replay_tsresol", None)
        self.rewriter = rewriter_for(cfg)
        self.stop = stop
        self.done = 0                       # completed passes
        self.fmt, self._len = pcapread.probe(self.path)
        self.rate = cfg.rate

    def __len__(self) -> int:
        return self._len

    def describe(self) -> str:
        how = (f"original timing x{self.speed:g}" if self.realtime
               else f"@ {self.rate}pps")
        out = (f"replaying {self._len} packets from {self.path} "
               f"({self.fmt}, {how}")
        if self.passes:
            out += f", {self.passes} pass{'es' if self.passes > 1 else ''}"
        if self.rewriter is not None:
            out += f"; {self.rewriter.describe()}"
        return out + ")"

    def _wait(self, target: float) -> None:
        delay = target - time.perf_counter()
        if delay <= 0:
            return
        if self.stop is not None and delay > 0.05:
            self.stop.wait(delay)
        else:
            time.sleep(delay)

    def __iter__(self) -> Iterator[Tuple[str, bytes, str]]:
        rw = self.rewriter
        prev_ts: Optional[float] = None
        base = time.perf_counter()
        offset = 0.0
        for ts, frame in pcapread.iter_frames(self.path,
                                              resolution=self.resolution):
            if self.realtime:
                if prev_ts is not None:
                    offset += min(max(ts - prev_ts, 0.0), MAX_GAP) / self.speed
                prev_ts = ts
                target = base + offset
                if time.perf_counter() - target > 1.0:   # fell behind: resync
                    base = time.perf_counter() - offset
                    target = base + offset
                self._wait(target)
                if self.stop is not None and self.stop.is_set():
                    return
            if rw is None:
                yield "replay", frame, "replay"
            else:
                for out in rw.apply_all(frame):
                    yield "replay", out, "replay"
        self.done += 1
        if self.passes and self.done >= self.passes and self.stop is not None:
            self.stop.set()
