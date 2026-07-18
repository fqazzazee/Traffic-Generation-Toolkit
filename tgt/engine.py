"""Generation engine — builds flows and drives them onto the wire / into pcap.

Runs in a background thread so a TUI or the CLI can watch live stats and stop
cleanly.  Stats are exposed through a lock-free-enough :class:`Stats` snapshot
(plain ints updated by one writer thread, read by others — good enough for a
monitor).
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from . import protocols
from .config import RunConfig
from .pcap import PcapWriter
from .sender import RateLimiter, RawSender


@dataclass
class Stats:
    started: float = 0.0
    packets: int = 0
    bytes: int = 0
    errors: int = 0
    last_error: str = ""
    running: bool = False
    finished: bool = False
    per_profile: dict = field(default_factory=dict)

    @property
    def elapsed(self) -> float:
        if not self.started:
            return 0.0
        return time.perf_counter() - self.started

    @property
    def pps(self) -> float:
        e = self.elapsed
        return self.packets / e if e > 0 else 0.0

    @property
    def mbps(self) -> float:
        e = self.elapsed
        return (self.bytes * 8 / 1e6) / e if e > 0 else 0.0


def build_batch(cfg: RunConfig) -> List[tuple[str, bytes]]:
    """Build one interleaved cycle of frames tagged with their profile key.

    The base is a scenario/environment/incident/protocol mix; any ``sprinkle``
    incidents are then spread thinly through it so the malware rides on top of
    otherwise-normal traffic.
    """
    base = _build_base(cfg)
    if cfg.sprinkle or cfg.sprinkle_random:
        from . import incidents
        import random
        pool = [k for k in cfg.sprinkle if k in incidents.INCIDENTS]
        if cfg.sprinkle_random:
            pool = [random.choice(pool or list(incidents.INCIDENTS))]
        if not pool:
            return base

        def cycle(i):
            return incidents.get(pool[i % len(pool)]).build(cfg.sprinkle_messages)

        r = min(max(cfg.sprinkle_ratio, 0.0), 0.9)
        if r > 0 and base:
            first = cycle(0)
            c = max(1, len(first))
            target = len(base) * r / (1 - r)
            if target >= c:                 # base big enough: add malware cycles
                n = max(1, round(target / c))
                extras = [first] + [cycle(i) for i in range(1, n)]
            else:                           # base too small: grow it to hit ratio
                reps = max(1, -(-int(c * (1 - r) / r) // len(base)))
                base = base * reps
                extras = [first]
        else:                               # natural minority: one cycle per variant
            extras = [cycle(i) for i in range(len(pool))]
        base = _sprinkle(base, extras, randomize=cfg.sprinkle_random)
    return base


def _build_base(cfg: RunConfig) -> List[tuple[str, bytes]]:
    if cfg.incident:
        from . import incidents
        return incidents.get(cfg.incident).build(cfg.messages)
    if cfg.env:
        from . import enterprise
        return enterprise.get(cfg.env).build(cfg.messages)
    per_profile: List[List[tuple[str, bytes]]] = []
    for key in cfg.profiles:
        prof = protocols.get(key)
        frames = prof.build(cfg.endpoints, cfg.messages)
        per_profile.append([(key, f) for f in frames])
    # round-robin interleave so a mixed scenario looks concurrent on the wire
    batch: List[tuple[str, bytes]] = []
    i = 0
    while any(i < len(p) for p in per_profile):
        for p in per_profile:
            if i < len(p):
                batch.append(p[i])
        i += 1
    return batch


def _sprinkle(base: List[tuple[str, bytes]],
              extras: List[List[tuple[str, bytes]]],
              randomize: bool = False) -> List[tuple[str, bytes]]:
    """Spread `extras` frames through `base` (evenly, or jittered when random).

    Malware frames keep their relative order (so each attack's session stays
    ordered); only the spacing between injections changes.
    """
    flat = [item for e in extras for item in e]
    if not flat:
        return base
    if not base:
        return flat
    merged: List[tuple[str, bytes]] = []
    ei = 0
    if randomize:
        import random
        prob = len(flat) / len(base)
        for item in base:
            merged.append(item)
            if ei < len(flat) and random.random() < prob:
                merged.append(flat[ei])
                ei += 1
    else:
        interval = max(1, len(base) // (len(flat) + 1))
        for i, item in enumerate(base):
            merged.append(item)
            if (i + 1) % interval == 0 and ei < len(flat):
                merged.append(flat[ei])
                ei += 1
    merged.extend(flat[ei:])
    return merged


class Engine:
    def __init__(self, cfg: RunConfig,
                 on_log: Optional[Callable[[str], None]] = None):
        self.cfg = cfg
        self.stats = Stats()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._on_log = on_log or (lambda m: None)

    def log(self, msg: str) -> None:
        self._on_log(msg)

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def join(self, timeout: Optional[float] = None) -> None:
        if self._thread:
            self._thread.join(timeout)

    def is_alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    # -- internal ----------------------------------------------------------
    def _run(self) -> None:
        cfg = self.cfg
        sender: Optional[RawSender] = None
        pcap: Optional[PcapWriter] = None
        self.stats.running = True
        self.stats.started = time.perf_counter()
        try:
            if cfg.iface:
                sender = RawSender(cfg.iface)
                try:
                    sender.open()
                    self.log(f"raw socket bound to {cfg.iface}")
                except OSError as e:
                    self.log(f"cannot open raw socket on {cfg.iface}: {e}")
                    if not cfg.pcap_path:
                        self.stats.last_error = str(e)
                        self.stats.errors += 1
                        return
                    sender = None
            if cfg.pcap_path:
                pcap = PcapWriter(cfg.pcap_path)
                self.log(f"writing pcap -> {cfg.pcap_path}")

            limiter = RateLimiter(cfg.rate)
            delays = None
            if cfg.replay_path:
                from . import pcapread
                frames_ts = pcapread.read_frames(cfg.replay_path)
                batch = [("replay", f) for _, f in frames_ts]
                if cfg.replay_realtime and len(frames_ts) > 1:
                    delays = [0.0] + [frames_ts[i][0] - frames_ts[i - 1][0]
                                      for i in range(1, len(frames_ts))]
                self.log(f"replaying {len(batch)} packets from {cfg.replay_path}"
                         + (" (original timing)" if delays else
                            f" @ {cfg.rate}pps"))
            else:
                batch = build_batch(cfg)
                what = (f"incident {cfg.incident}" if cfg.incident else
                        f"env {cfg.env}" if cfg.env else ", ".join(cfg.profiles))
                if cfg.sprinkle_random:
                    what += " + malware:random"
                elif cfg.sprinkle:
                    what += f" + malware:{','.join(cfg.sprinkle)}"
                self.log(f"built {len(batch)} frames/cycle for [{what}]")

            while not self._stop.is_set():
                for idx, (key, frame) in enumerate(batch):
                    if self._stop.is_set():
                        break
                    if delays is not None:
                        if delays[idx] > 0:
                            time.sleep(min(delays[idx], 5.0))
                    else:
                        limiter.wait()
                    if sender is not None:
                        try:
                            sender.send(frame)
                        except OSError as e:
                            self.stats.errors += 1
                            self.stats.last_error = str(e)
                    if pcap is not None:
                        pcap.write(frame)
                    self.stats.packets += 1
                    self.stats.bytes += len(frame)
                    self.stats.per_profile[key] = \
                        self.stats.per_profile.get(key, 0) + 1

                    if cfg.count and self.stats.packets >= cfg.count:
                        self._stop.set()
                        break
                    if cfg.duration and self.stats.elapsed >= cfg.duration:
                        self._stop.set()
                        break
                if not cfg.loop:
                    break
                # random mode: re-roll the variant + placement for the next cycle
                if cfg.sprinkle_random and delays is None and not self._stop.is_set():
                    batch = build_batch(cfg)
        finally:
            if sender is not None:
                sender.close()
            if pcap is not None:
                pcap.close()
            self.stats.running = False
            self.stats.finished = True
            self.log(f"done: {self.stats.packets} pkts, "
                     f"{self.stats.bytes} bytes, {self.stats.errors} errors")
