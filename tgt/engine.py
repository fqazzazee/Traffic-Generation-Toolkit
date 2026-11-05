"""Generation engine — builds flows and drives them onto the wire / into pcap.

Runs in a background thread so a TUI or the CLI can watch live stats and stop
cleanly.  Stats are exposed through a lock-free-enough :class:`Stats` snapshot
(plain ints updated by one writer thread, read by others — good enough for a
monitor).
"""
from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

from . import protocols
from .config import RunConfig
from .pcap import PcapWriter
from .sender import RateLimiter, RawSender

# Inventory a sprinkle re-addresses onto when no environment preset is active —
# a full Purdue plant, so IT and OT malware both find realistic host matches.
DEFAULT_SPRINKLE_ENV = "industrial-site"


@dataclass
class Stats:
    started: float = 0.0
    packets: int = 0
    bytes: int = 0
    errors: int = 0
    last_error: str = ""
    running: bool = False
    finished: bool = False
    cycle_frames: int = 0          # frames in one built (or replayed) cycle
    cycles: int = 0                # cycles started
    seed: Optional[int] = None     # run seed (reproduces every cycle)
    sim_time: float = 0.0          # timed schedule: simulated seconds sent
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


# A built frame: (profile/attack key, frame bytes, source label) — the source
# is "baseline", "incident:<key>" or "sprinkle:<incident>".
Tagged = Tuple[str, bytes, str]


def build_batch(cfg: RunConfig, seed: Optional[int] = None, cycle: int = 0,
                sport_stride: int = 0) -> List[tuple[str, bytes]]:
    """Build one interleaved cycle of frames tagged with their profile key.

    The base is a scenario/environment/incident/protocol mix; any ``sprinkle``
    incidents are then spread thinly through it so the malware rides on top of
    otherwise-normal traffic. See :func:`build_cycle` for ``seed``/``cycle``.
    """
    return [(k, f) for k, f, _ in build_cycle(cfg, seed, cycle, sport_stride)]


def build_cycle(cfg: RunConfig, seed: Optional[int] = None, cycle: int = 0,
                sport_stride: int = 0) -> List[Tagged]:
    """Cycle ``cycle`` of a run as (key, frame, source) triples.

    Each cycle is fresh — new ephemeral ports (advancing by ``sport_stride``
    per cycle), random TCP ISNs, continuing app-level counters, drifting
    process values — yet a pure function of ``(cfg, seed, cycle)``: the same
    seed rebuilds identical frames. ``seed`` defaults to ``cfg.seed``; with
    neither set every build is different.
    """
    if seed is None:
        seed = cfg.seed
    rng = protocols.begin_build(seed, cycle, sport_stride).rng
    src = f"incident:{cfg.incident}" if cfg.incident else "baseline"
    base: List[Tagged] = [(k, f, src) for k, f in _build_base(cfg)]
    if cfg.sprinkle or cfg.sprinkle_random:
        from . import incidents
        pool = [k for k in cfg.sprinkle if k in incidents.INCIDENTS]
        if cfg.sprinkle_random:
            pool = [rng.choice(pool or list(incidents.INCIDENTS))]
        if not pool:
            return base

        from . import enterprise
        # Malware always rides on a real inventory so it looks like the same
        # machines are infected. An env preset is that inventory (frames placed
        # on its VLANs/trunk); otherwise a scenario/custom/protocol base has no
        # hosts of its own, so we re-address onto a representative plant — the
        # full Purdue site — keeping Windows→Windows and vendor-matched PLCs.
        if cfg.env:
            env, tagged = enterprise.get(cfg.env), True
        else:
            env, tagged = enterprise.get(DEFAULT_SPRINKLE_ENV), False

        def cycle(i):
            inc = incidents.get(pool[i % len(pool)])
            label = f"sprinkle:{inc.key}"
            if tagged:              # ride on the env's VLANs/trunk directly
                built = inc.build_on(cfg.sprinkle_messages, env, span=cfg.span)
            else:
                mapping = inc.map_onto(env)   # re-address only (base untagged)
                built = inc.build(cfg.sprinkle_messages, resolve=lambda n,
                                  m=mapping: m.get(n) or inc.host(n))
            return [(k, f, label) for k, f in built]

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
        base = _sprinkle(base, extras, randomize=cfg.sprinkle_random, rng=rng)
    return base


def sport_stride(used: int) -> int:
    """Per-cycle advance of the source-port allocator for a cycle that used
    ``used`` ports: headroom for cycles that vary in size (random sprinkle),
    rounded to 64."""
    return -(-(used * 5 // 4 + 32) // 64) * 64


class CycleBuilder:
    """Builds cycle N of a run — a pure function of ``(cfg, seed, N)``.

    The source-port stride comes from cycle 0's port use, so ports advance
    across cycles without 4-tuple reuse until the ephemeral range wraps.
    """

    def __init__(self, cfg: RunConfig, seed: Optional[int]):
        self.cfg, self.seed = cfg, seed
        self.stride: Optional[int] = None

    def build(self, cycle: int) -> List[Tagged]:
        if self.stride is None:
            first = build_cycle(self.cfg, self.seed, 0)
            self.stride = sport_stride(protocols.build_context().sports_used)
            if cycle == 0:
                return first
        return build_cycle(self.cfg, self.seed, cycle, self.stride)


def _build_base(cfg: RunConfig) -> List[tuple[str, bytes]]:
    if cfg.incident:
        from . import incidents
        return incidents.get(cfg.incident).build(cfg.messages)
    if cfg.env:
        from . import enterprise
        return enterprise.get(cfg.env).build(cfg.messages, span=cfg.span)
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


def _sprinkle(base: list, extras: List[list], randomize: bool = False,
              rng: Optional[random.Random] = None) -> list:
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
        roll = (rng or random).random
        prob = len(flat) / len(base)
        for item in base:
            merged.append(item)
            if ei < len(flat) and roll() < prob:
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


def replay_offsets(timestamps: List[float],
                   max_gap: float = 5.0) -> List[float]:
    """Send time of each replayed frame relative to the first.

    Gaps are clamped to ``[0, max_gap]`` so out-of-order timestamps or a long
    idle stretch in the capture do not stall the replay.
    """
    out = [0.0]
    for prev, cur in zip(timestamps, timestamps[1:]):
        out.append(out[-1] + min(max(cur - prev, 0.0), max_gap))
    return out


class Engine:
    # manifest rewrite period (seconds of wall time)
    MANIFEST_INTERVAL = 10.0

    def __init__(self, cfg: RunConfig,
                 on_log: Optional[Callable[[str], None]] = None,
                 argv: Optional[List[str]] = None):
        self.cfg = cfg
        self.argv = list(argv or [])
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
    def _sleep_until(self, target: float) -> None:
        """Sleep until ``perf_counter() >= target``; wakes early on stop()."""
        delay = target - time.perf_counter()
        if delay > 0.05:
            self._stop.wait(delay)
        elif delay > 0:
            time.sleep(delay)

    def _run(self) -> None:
        cfg = self.cfg
        sender: Optional[RawSender] = None
        pcap: Optional[PcapWriter] = None
        recorder = None
        pool = None
        self.stats.running = True
        self.stats.started = time.perf_counter()
        seed = cfg.seed if cfg.seed is not None else new_seed()
        self.stats.seed = seed
        synthetic = cfg.clock == "synthetic"
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
            # synthetic clock: frame i is stamped start + i/rate (1 ms apart at
            # --rate 0); with nothing to send there is no reason to pace
            t0 = (parse_start(cfg.start_time) if synthetic else 0.0)
            step = 1.0 / cfg.rate if cfg.rate and cfg.rate > 0 else 0.001
            pace = not (synthetic and sender is None)
            if cfg.manifest_path:
                from .manifest import Recorder
                recorder = Recorder(cfg, seed, self.argv, cfg.clock)
                self.log(f"manifest -> {cfg.manifest_path}")
            last_manifest = time.monotonic()
            if cfg.schedule == "timed" and not cfg.replay_path:
                self._run_timed(sender, pcap, recorder, seed, synthetic, pace)
                return

            limiter = RateLimiter(cfg.rate if pace else 0)
            offsets = None      # realtime replay: send time of each frame
            builder = None
            if cfg.replay_path:
                from . import pcapread
                frames_ts = pcapread.read_frames(cfg.replay_path)
                batch = [("replay", f, "replay") for _, f in frames_ts]
                if cfg.replay_realtime and len(frames_ts) > 1 and pace:
                    offsets = replay_offsets([t for t, _ in frames_ts])
                self.log(f"replaying {len(batch)} packets from {cfg.replay_path}"
                         + (" (original timing)" if offsets else
                            f" @ {cfg.rate}pps"))
            else:
                builder = CycleBuilder(cfg, seed)
                tb = time.perf_counter()
                batch = builder.build(0)
                what = (f"incident {cfg.incident}" if cfg.incident else
                        f"env {cfg.env}" if cfg.env else ", ".join(cfg.profiles))
                if cfg.sprinkle_random:
                    what += " + malware:random"
                elif cfg.sprinkle:
                    what += f" + malware:{','.join(cfg.sprinkle)}"
                self.log(f"built {len(batch)} frames/cycle for [{what}] in "
                         f"{time.perf_counter() - tb:.2f}s (seed {seed})")
            self.stats.cycle_frames = len(batch)

            cycle = 0
            while not self._stop.is_set():
                self.stats.cycles = cycle + 1
                # each cycle is rebuilt fresh (new ports/ISNs/counters/values);
                # the next one is built in the background while this one sends
                nxt = None
                if builder is not None and cfg.loop:
                    if pool is None:
                        from concurrent.futures import ThreadPoolExecutor
                        pool = ThreadPoolExecutor(1, "tgt-build")
                    nxt = pool.submit(builder.build, cycle + 1)
                # realtime replay is scheduled against absolute target times
                # from the cycle start, so per-packet overhead never accumulates
                cycle_start = time.perf_counter()
                for idx, (key, frame, source) in enumerate(batch):
                    if self._stop.is_set():
                        break
                    if offsets is not None:
                        self._sleep_until(cycle_start + offsets[idx])
                    else:
                        limiter.wait(self._stop)
                    if self._stop.is_set():
                        break
                    sent = True
                    if sender is not None:
                        try:
                            sender.send(frame)
                        except OSError as e:
                            sent = False
                            self.stats.errors += 1
                            self.stats.last_error = str(e)
                    # only frames that really left (or are file-only) count and
                    # land in the pcap, so the pcap stays ground truth
                    if sent:
                        ts = (t0 + self.stats.packets * step if synthetic
                              else time.time())
                        if pcap is not None:
                            pcap.write(frame, ts=ts)
                        if recorder is not None:
                            recorder.observe(ts, key, frame, source)
                        self.stats.packets += 1
                        self.stats.bytes += len(frame)
                        self.stats.per_profile[key] = \
                            self.stats.per_profile.get(key, 0) + 1
                    if (recorder is not None and time.monotonic()
                            - last_manifest >= self.MANIFEST_INTERVAL):
                        last_manifest = time.monotonic()
                        self._write_manifest(recorder)

                    # --count bounds attempts, so a dead interface still ends
                    if cfg.count and (self.stats.packets
                                      + self.stats.errors) >= cfg.count:
                        self._stop.set()
                        break
                    elapsed = (self.stats.packets * step if not pace
                               else self.stats.elapsed)
                    if cfg.duration and elapsed >= cfg.duration:
                        self._stop.set()
                        break
                if not cfg.loop or self._stop.is_set():
                    break
                cycle += 1
                if nxt is not None:
                    batch = nxt.result()
        finally:
            if pool is not None:
                pool.shutdown(wait=False)
            if sender is not None:
                sender.close()
            if pcap is not None:
                pcap.close()
            if recorder is not None:
                self._write_manifest(recorder)
            self.stats.running = False
            self.stats.finished = True
            self.log(f"done: {self.stats.packets} pkts, "
                     f"{self.stats.bytes} bytes, {self.stats.errors} errors")

    def _run_timed(self, sender, pcap, recorder, seed: int, synthetic: bool,
                   pace: bool) -> None:
        """The timed scheduler: phases (one, or a campaign's) of streams on
        their own periods, frames sent at their scheduled time — real time
        (``speed`` compressed) when pacing, else as fast as possible with
        synthetic timestamps. ``rate`` only caps the packet rate."""
        from . import campaign, schedule
        cfg = self.cfg
        tb = time.perf_counter()
        phases = campaign.phases_for(cfg)
        wall_epoch = time.time()
        epoch0 = parse_start(cfg.start_time) if synthetic else wall_epoch
        speed = cfg.speed if cfg.speed and cfg.speed > 0 else 1.0
        sched = schedule.Scheduler(seed, epoch0, cfg.day_profile,
                                   phases[0].utc_offset if phases else 0.0,
                                   min_period=cfg.min_period)
        if recorder is not None and cfg.campaign:
            recorder.campaign(phases)
        wall0 = time.perf_counter()

        def ts_of(t: float) -> float:
            return epoch0 + (t if synthetic else t / speed)

        t = 0.0
        last_manifest = time.monotonic()
        for i, ph in enumerate(phases):
            if self._stop.is_set():
                break
            self.stats.cycles = i + 1
            streams = campaign.phase_streams(ph, cfg)
            sched.day_profile = ph.day_profile or cfg.day_profile
            started, _ = sched.load(streams, t, ph.hosts, initial=(i == 0),
                                    soon=ph.soon)
            for delay, key, frames in ph.inject:
                sched.inject(t + delay, key, frames)
            if i == 0:
                self.log(f"timed schedule: {len(started)} streams for "
                         f"[{ph.label}] in {time.perf_counter() - tb:.2f}s "
                         f"(seed {seed})")
            elif cfg.campaign:
                self.log(f"phase {ph.id} '{ph.name}': {len(started)} new "
                         f"streams, {len(ph.events)} change events")
            if recorder is not None:
                recorder.begin_phase(ph, ts_of(t))
            cap = ph.rate if ph.rate is not None else cfg.rate
            limiter = RateLimiter(cap if pace and cap and cap > 0 else 0)
            t_end = t + ph.duration if ph.duration else float("inf")
            if cfg.duration and not cfg.campaign:
                t_end = min(t_end, cfg.duration)
            for ft, _, key, copies, source, occ in sched.run(t_end):
                if self._stop.is_set():
                    break
                if pace:
                    self._sleep_until(wall0 + ft / speed)
                    if limiter.interval:
                        limiter.wait(self._stop)
                    if self._stop.is_set():
                        break
                for frame in copies:
                    sent = True
                    if sender is not None:
                        try:
                            sender.send(frame)
                        except OSError as e:
                            sent = False
                            self.stats.errors += 1
                            self.stats.last_error = str(e)
                    if sent:
                        ts = epoch0 + ft if synthetic else time.time()
                        if pcap is not None:
                            pcap.write(frame, ts=ts)
                        if recorder is not None:
                            recorder.observe(ts, key, frame, source, occ)
                            occ = False
                        self.stats.packets += 1
                        self.stats.bytes += len(frame)
                        self.stats.per_profile[key] = \
                            self.stats.per_profile.get(key, 0) + 1
                    if cfg.count and (self.stats.packets
                                      + self.stats.errors) >= cfg.count:
                        self._stop.set()
                        break
                self.stats.sim_time = ft
                if (recorder is not None and time.monotonic()
                        - last_manifest >= self.MANIFEST_INTERVAL):
                    last_manifest = time.monotonic()
                    self._write_manifest(recorder)
            if self._stop.is_set():
                if recorder is not None:
                    recorder.end_phase(None)
                break
            t = t_end
            if t == float("inf"):
                break
            self.stats.sim_time = t
            if recorder is not None:
                recorder.end_phase(ts_of(t) if synthetic or not pace
                                   else time.time())
            if pace:
                self._sleep_until(wall0 + t / speed)
        self.stats.cycles = max(self.stats.cycles, 1)

    def _write_manifest(self, recorder) -> None:
        try:
            recorder.write(self.cfg.manifest_path, self.stats)
        except OSError as e:
            self.log(f"cannot write manifest {self.cfg.manifest_path}: {e}")


def new_seed() -> int:
    """A fresh random run seed (logged + recorded so the run can be redone)."""
    return random.SystemRandom().randrange(1 << 32)


def parse_start(text: Optional[str]) -> float:
    """--start-time for the synthetic clock (ISO-8601; default: now, whole
    seconds)."""
    if not text:
        return float(int(time.time()))
    from .manifest import parse_iso
    return parse_iso(text)
