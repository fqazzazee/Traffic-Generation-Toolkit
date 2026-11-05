"""Live control of a running engine: pause/resume, rate and timed injection.

Every :class:`tgt.engine.Engine` owns a :class:`RunControl` (``eng.control``).
The engine pulls frames through :meth:`RunControl.feed`, which

* blocks while the run is paused (``pause()`` / ``resume()``);
* splices *injected* incident traffic into the stream: ``inject(key,
  duration)`` sprinkles an existing incident (the same builders and host
  mapping as ``--sprinkle``: onto the ``--env`` inventory, else onto the
  default plant) at ``ratio`` of the frames for ``duration`` seconds of wall
  time. The incident pass in flight when the time is up is finished, so no
  TCP session is cut short. Injected frames carry the source label
  ``inject:<incident>#<id>`` and the manifest records each injection (requested
  time, first/last injected frame) plus the usual per-attack events.

``set_rate(pps)`` re-paces a rate-limited run. The control API
(:mod:`tgt.api`) is a thin HTTP layer over these methods.

Injection passes are built on a worker thread (the next pass prefetched), so
the send loop never waits on a build. Each injection pass is an isolated build
(:func:`tgt.protocols.isolated_build`: under the build lock, seeded from the
run seed, the injection id and the pass, the run's build context restored
afterwards), so a seeded run's own frames are the same with or without
injections; where the injected frames land depends on wall-clock timing (the
manifest's injection records say exactly what was added and when).
"""
from __future__ import annotations

import collections
import threading
import time
from typing import Deque, Dict, Iterable, Iterator, List, Optional, Tuple

DEFAULT_RATIO = 0.05            # injected share of frames while active
MAX_DURATION = 7 * 86400.0


class Injection:
    """One timed injection (also its manifest / status record)."""

    def __init__(self, ident: str, incident: str, duration: float,
                 ratio: float, via: str):
        self.id, self.incident, self.via = ident, incident, via
        self.duration, self.ratio = duration, ratio
        self.requested = time.time()
        self.state = "pending"          # pending | active | done | failed
        self.error = ""
        self.passes = 0
        self.frames_out = 0             # handed to the engine
        self.deadline = 0.0             # monotonic
        # filled by the manifest Recorder from the frames really sent
        self.record: Dict = {"id": ident, "incident": incident,
                             "duration": duration, "ratio": ratio, "via": via,
                             "requested_ts": self.requested,
                             "first_ts": None, "last_ts": None, "packets": 0}
        self._frames: List[tuple] = []
        self._pos = 0
        self._credit = 0.0
        self._next = None               # Future of the pass being built

    @property
    def label(self) -> str:
        """Frame source label — unique per injection, so two injections of
        one incident are two sets of manifest events."""
        return f"inject:{self.incident}#{self.id}"

    def to_dict(self) -> Dict:
        from .manifest import iso
        r = self.record
        out = {"id": self.id, "incident": self.incident, "state": self.state,
               "via": self.via, "duration": self.duration,
               "ratio": self.ratio, "requested": iso(self.requested),
               "start": iso(r["first_ts"]), "end": iso(r["last_ts"]),
               "packets": r["packets"], "passes": self.passes}
        if self.state == "active":
            out["remaining"] = round(max(0.0, self.deadline
                                         - time.monotonic()), 1)
        if self.error:
            out["error"] = self.error
        return out


def build_incident(cfg, key: str, messages: int,
                   label: Optional[str] = None, env=None) -> List[tuple]:
    """One pass of incident ``key`` as (key, frame, label) triples (label
    default ``inject:<key>``), addressed the way ``--sprinkle`` addresses it
    (see engine.build_cycle)."""
    from . import enterprise, incidents
    from .engine import DEFAULT_SPRINKLE_ENV
    inc = incidents.get(key)
    if env is None and cfg.env:
        env = enterprise.get(cfg.env)
    if env is not None:
        built = inc.build_on(messages, env, span=cfg.span)
    else:
        mapping = inc.map_onto(enterprise.get(DEFAULT_SPRINKLE_ENV))
        built = inc.build(messages, resolve=lambda n: mapping.get(n)
                          or inc.host(n))
    label = label or f"inject:{key}"
    return [(k, f, label) for k, f in built]


class RunControl:
    def __init__(self, engine=None):
        self.engine = engine
        self._go = threading.Event()
        self._go.set()
        self._lock = threading.Lock()
        self._pending: Deque[Injection] = collections.deque()
        self._active: Dict[str, Injection] = {}
        self.injections: List[Injection] = []
        self.paused_total = 0.0
        self._paused_at: Optional[float] = None
        self._pool = None               # injection pass builder (lazy)

    # -- pause / rate ----------------------------------------------------------
    @property
    def paused(self) -> bool:
        return not self._go.is_set()

    def pause(self) -> None:
        with self._lock:
            if self._go.is_set():
                self._paused_at = time.monotonic()
                self._go.clear()

    def resume(self) -> None:
        with self._lock:
            if not self._go.is_set():
                self.paused_total += time.monotonic() - (self._paused_at or
                                                         time.monotonic())
                self._paused_at = None
                self._go.set()

    def set_rate(self, pps: float) -> None:
        """Re-pace a rate-limited run; ValueError when the run's pacing is
        not rate based (realtime replay, synthetic-clock pcap-only)."""
        if pps < 0:
            raise ValueError("rate must be >= 0")
        eng = self.engine
        lim = getattr(eng, "limiter", None) if eng is not None else None
        if lim is None:
            raise ValueError("this run is not paced by --rate (realtime "
                             "replay or a synthetic-clock pcap-only run)")
        eng.cfg.rate = pps
        lim.set_rate(pps)

    # -- injection -----------------------------------------------------------
    def inject(self, incident: str, duration: float = 60.0,
               ratio: Optional[float] = None, via: str = "api") -> Injection:
        """Queue a timed injection; the engine starts it with its next frame.
        KeyError for an unknown incident, ValueError for a bad duration /
        ratio or when that incident is already being injected."""
        from . import incidents
        if incident not in incidents.INCIDENTS:
            raise KeyError(incident)
        if not 0 < duration <= MAX_DURATION:
            raise ValueError(f"duration must be in (0, {MAX_DURATION:g}] s")
        if ratio is None:
            cfg = getattr(self.engine, "cfg", None)
            ratio = (getattr(cfg, "sprinkle_ratio", 0.0) or DEFAULT_RATIO)
        if not 0 < ratio <= 0.9:
            raise ValueError("ratio must be in (0, 0.9]")
        with self._lock:
            busy = [i for i in list(self._pending) + list(self._active.values())
                    if i.incident == incident]
            if busy:
                raise ValueError(f"{incident} is already being injected "
                                 f"({busy[0].id})")
            inj = Injection(f"i{len(self.injections) + 1}", incident,
                            float(duration), float(ratio), via)
            self.injections.append(inj)
            self._pending.append(inj)
        return inj

    def status(self) -> List[Dict]:
        return [i.to_dict() for i in list(self.injections)]

    # -- engine side ------------------------------------------------------------
    def paused_for(self) -> float:
        """Seconds this run has spent paused so far (the current pause too)."""
        with self._lock:
            cur = (time.monotonic() - self._paused_at
                   if self._paused_at is not None else 0.0)
            return self.paused_total + cur

    def gate(self, stop: threading.Event) -> bool:
        """Block while paused; False once ``stop`` is set. The engine calls
        it right before a frame leaves too, so a frame it was already
        waiting to send (a long timed sleep, a slow ``--rate``) still waits
        out a pause that began in the meantime."""
        while not self._go.is_set():
            if self._go.wait(0.2):
                break
            if stop.is_set():
                return False
        return not stop.is_set()

    def feed(self, batch: Iterable[tuple], stop: threading.Event
             ) -> Iterator[Tuple[int, tuple]]:
        """``enumerate(batch)`` with pause gating and injected frames spliced
        in (an injected frame shares the index of the base frame before it)."""
        for idx, item in enumerate(batch):
            if not self.gate(stop):
                return
            yield idx, item
            if self._pending or self._active:
                for extra in self._extras():
                    yield idx, extra

    def close(self) -> None:
        if self._pool is not None:
            self._pool.shutdown(wait=False)

    def _submit(self, inj: Injection, n: int):
        """Build pass ``n`` of ``inj`` on the injection worker, so the send
        loop never waits on the build lock a cycle prebuild may hold."""
        if self._pool is None:
            from concurrent.futures import ThreadPoolExecutor
            self._pool = ThreadPoolExecutor(1, "tgt-inject")
        return self._pool.submit(self._build, inj, n)

    def _take(self, inj: Injection, fut) -> Optional[List[tuple]]:
        """A finished pass build, or None (``inj.error`` says why)."""
        try:
            frames = fut.result()
        except Exception as e:  # noqa: BLE001 - reported, run continues
            inj.error = f"{type(e).__name__}: {e}"
            return None
        if not frames:
            inj.error = "the incident builds no frames on this environment"
            return None
        return frames

    def _start(self, inj: Injection, frames: List[tuple]) -> None:
        eng = self.engine
        inj._frames = frames
        inj.passes, inj._pos, inj._credit = 1, 0, 1.0
        inj.deadline = time.monotonic() + inj.duration
        inj.state = "active"
        inj._next = self._submit(inj, 2)            # prefetch the next pass
        rec = getattr(eng, "recorder", None)
        if rec is not None:
            rec.add_injection(inj.incident, inj.label, inj.record)
        self._active[inj.id] = inj
        eng.log(f"injection {inj.id}: {inj.incident} for {inj.duration:g}s "
                f"at {inj.ratio:.0%} ({len(frames)} frames/pass)")

    def _build(self, inj: Injection, n: int) -> List[tuple]:
        """Pass ``n`` of ``inj``: an isolated build seeded from the run
        seed and the injection id, so it leaves the run's builds alone.
        Addressed onto the environment the engine is sending now (a
        campaign phase's, see Engine.env_now), as the manifest records it."""
        import zlib
        from . import protocols
        eng = self.engine
        run = getattr(getattr(eng, "stats", None), "seed", None)
        seed = zlib.crc32(f"inject:{run}:{inj.id}".encode())
        stride = getattr(inj, "_stride", 0)
        with protocols.isolated_build(seed, n, stride) as ctx:
            out = build_incident(eng.cfg, inj.incident,
                                 eng.cfg.sprinkle_messages, inj.label,
                                 env=getattr(eng, "env_now", None))
            if not stride:          # later passes: fresh ports (no reuse)
                from .engine import sport_stride
                inj._stride = sport_stride(ctx.sports_used)
        return out

    def _finish(self, inj: Injection, failed: bool = False) -> None:
        inj.state = "failed" if failed else "done"
        self._active.pop(inj.id, None)
        nxt = getattr(inj, "_next", None)
        if nxt is not None:
            nxt.cancel()
            inj._next = None
        if failed:
            self.engine.log(f"injection {inj.id} ({inj.incident}) failed: "
                            f"{inj.error}")
        else:
            self.engine.log(f"injection {inj.id} ({inj.incident}) done: "
                            f"{inj.frames_out} frames in {inj.passes} "
                            f"pass(es)")

    def _extras(self) -> List[tuple]:
        with self._lock:
            starting = list(self._pending)
        for inj in starting:
            fut = getattr(inj, "_next", None)
            if fut is None:
                inj._next = self._submit(inj, 1)
                continue
            if not fut.done():
                continue                     # still building: next frame
            with self._lock:
                self._pending.remove(inj)
            frames = self._take(inj, fut)
            if frames is None:
                inj._next = None
                self._finish(inj, failed=True)
            else:
                self._start(inj, frames)
        out: List[tuple] = []
        now = time.monotonic()
        for inj in list(self._active.values()):
            if inj._pos >= len(inj._frames):
                if now >= inj.deadline:
                    self._finish(inj)
                    continue
                fut = inj._next
                if fut is None or not fut.done():
                    continue                 # next pass still building
                frames = self._take(inj, fut)
                if frames is None:          # fresh ports / ISNs failed
                    inj._next = None
                    self._finish(inj, failed=True)
                    continue
                inj._frames, inj._pos = frames, 0
                inj.passes += 1
                inj._next = self._submit(inj, inj.passes + 1)
            inj._credit += inj.ratio / (1.0 - inj.ratio)
            while inj._credit >= 1.0 and inj._pos < len(inj._frames):
                out.append(inj._frames[inj._pos])
                inj._pos += 1
                inj._credit -= 1.0
                inj.frames_out += 1
            if inj._pos >= len(inj._frames) and now >= inj.deadline:
                self._finish(inj)
        return out
