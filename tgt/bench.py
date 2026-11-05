"""``tgt bench`` — a fixed, seeded evaluation suite and a vendor-neutral
scorecard.

A *suite* (``tgt/benches/*.json`` or your own file) is an ordered list of
stages played back to back on one environment, each a fixed-seed run on the
timed scheduler built from the existing campaign machinery
(:mod:`tgt.campaign`):

* ``baseline`` — normal traffic for ``duration`` (the monitor learns);
* ``incidents`` — normal traffic with incidents sprinkled in at fixed
  offsets (``inject``: ``{"at": "2m", "incident": "havex", "duration":
  "3m"}``; ``incident`` may be a list; overlapping windows are fine);
* ``campaign`` — a change campaign: a packaged / file plan (``"plan":
  "baseline-then-change"``, which must use the suite's environment) or
  inline ``phases`` in the campaign-plan format.

Every stage starts from the suite environment (a campaign's changes do not
carry into the next stage, so put campaigns last). Suite schema (JSON;
unknown keys are errors)::

    {"name": "quick", "description": "...", "env": "ot-plant",
     "start_time": "2026-11-02T08:00:00Z", "seed": 6500,
     "day_profile": "shift", "utc_offset": 0, "span": "access",
     "sprinkle_messages": 2, "min_period": "10s",       # all optional
     "stages": [{"id": "learn", "kind": "baseline", "duration": "20m"},
                {"id": "attack", "kind": "incidents", "duration": "15m",
                 "inject": [{"at": "2m", "incident": "havex",
                             "duration": "3m"}]},
                {"id": "change", "kind": "campaign", "phases": [...]}],
     "thresholds": {"discovery_recall": {"min": 0.9},
                    "attack_median_ttd_s": {"max": 300}}}

Stage keys: ``id``, ``kind``, ``description``, ``duration`` (baseline /
incidents), ``inject`` (incidents), ``plan`` or ``phases`` (campaign),
``seed`` (default: suite seed + stage index), ``day_profile``.

``tgt bench run`` writes a *bundle* directory: ``bench.json`` (index: suite,
seeds, stage windows, TGT version), ``stages/<id>.plan.json`` (the campaign
plan each stage ran), ``stages/<id>.manifest.json`` (its run manifest),
optional ``stages/<id>.pcap`` and ``manifest.json`` — every stage merged into
one ground truth (``tgt score --manifest BUNDLE/manifest.json`` works on it).

``tgt bench score`` grades one monitor against the bundle: the asset export
(discovery, field accuracy) against the merged truth — an export reflects the
monitor's state at the end of the bench — and its alerts against every
stage's events: change detection (campaign change events), attack detection
and time to detect, per-technique coverage (when the manifests carry ATT&CK
technique IDs), per stage, and the suite's pass/fail thresholds. ``tgt bench
compare`` puts two scorecards side by side. The product is named only by the
user's ``--label``.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import statistics
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import __version__, campaign, timing

SCHEMA = "tgt-bench/1"
CARD_SCHEMA = "tgt-scorecard/1"
BENCHES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "benches")
KINDS = ("baseline", "incidents", "campaign")
_SUITE_KEYS = {"name", "description", "env", "start_time", "seed",
               "day_profile", "utc_offset", "span", "sprinkle_messages",
               "min_period", "stages", "thresholds"}
_STAGE_KEYS = {"id", "kind", "description", "duration", "inject", "plan",
               "phases", "seed", "day_profile"}
_INJECT_KEYS = {"at", "incident", "duration"}
# scorecard metric -> (better: "min" = higher is better / "max" = lower is
# better, label, unit)
METRICS: Dict[str, Tuple[str, str, str]] = {
    "discovery_recall": ("min", "Discovery recall", "pct"),
    "discovery_precision": ("min", "Discovery precision", "pct"),
    "field_accuracy": ("min", "Field accuracy", "pct"),
    "protocol_recall": ("min", "Protocol recall", "pct"),
    "change_detection_rate": ("min", "Change detection", "pct"),
    "change_median_ttd_s": ("max", "Change TTD (median)", "s"),
    "attack_detection_rate": ("min", "Attack detection", "pct"),
    "attack_median_ttd_s": ("max", "Attack TTD (median)", "s"),
    "technique_coverage": ("min", "Technique coverage", "pct"),
    "false_alerts": ("max", "False alerts", "n"),
}


class BenchError(ValueError):
    """A malformed suite, bundle or scorecard (message names the path)."""


def _dur(v: Any, path: str) -> float:
    try:
        d = timing.parse_duration(v)
    except ValueError as e:
        raise BenchError(f"{path}: {e}") from None
    if d < 0:
        raise BenchError(f"{path}: must be >= 0")
    return d


def _fmt(sec: float) -> str:
    sec = float(sec)
    d, rem = divmod(int(round(sec)), 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    return (f"{d}d " if d else "") + f"{h:02d}:{m:02d}:{s:02d}"


def _iso(ts: float) -> str:
    from .manifest import iso
    return iso(ts)


# ---------------------------------------------------------------------------
# Suites
# ---------------------------------------------------------------------------
class Stage:
    def __init__(self, sid: str, kind: str, description: str, seed: int,
                 offset: float, plan_doc: Dict[str, Any], source: str):
        self.id, self.kind, self.description = sid, kind, description
        self.seed, self.offset = seed, offset
        self.plan_doc = plan_doc          # campaign plan (no start_time yet)
        self.source = source
        self.duration = sum(timing.parse_duration(p["duration"])
                            for p in plan_doc["phases"])

    def plan(self, start_time: Optional[str] = None) -> Dict[str, Any]:
        doc = dict(self.plan_doc)
        if start_time:
            doc["start_time"] = start_time
        return doc


class Suite:
    def __init__(self, doc: Any, source: str = "<suite>") -> None:
        self.source = source
        if not isinstance(doc, dict):
            raise BenchError(f"{source}: expected a JSON object")
        bad = sorted(set(doc) - _SUITE_KEYS)
        if bad:
            raise BenchError(f"{source}: unknown key(s) {', '.join(bad)} "
                             f"(allowed: {', '.join(sorted(_SUITE_KEYS))})")
        self.doc = doc
        self.name = str(doc.get("name") or os.path.splitext(
            os.path.basename(source))[0])
        self.description = str(doc.get("description", ""))
        self.env = doc.get("env")
        if not isinstance(self.env, str) or not self.env:
            raise BenchError(f"{source}: env: the environment key is "
                             "required")
        self.start_time = doc.get("start_time")
        if self.start_time is not None:
            from .manifest import parse_iso
            try:
                parse_iso(str(self.start_time))
            except ValueError:
                raise BenchError(f"{source}: start_time: not ISO-8601: "
                                 f"{self.start_time!r}") from None
        self.seed = doc.get("seed", 0)
        if not isinstance(self.seed, int) or isinstance(self.seed, bool):
            raise BenchError(f"{source}: seed: expected an integer")
        self.min_period = _dur(doc.get("min_period", 0), f"{source}: "
                               "min_period")
        self.thresholds = self._thresholds(doc.get("thresholds") or {})
        stages = doc.get("stages")
        if not isinstance(stages, list) or not stages:
            raise BenchError(f"{source}: stages: expected a non-empty list")
        self.stages: List[Stage] = []
        offset = 0.0
        ids = set()
        for i, raw in enumerate(stages):
            st = self._stage(raw, i, offset)
            if st.id in ids:
                raise BenchError(f"{source}: stages[{i}].id: duplicate "
                                 f"{st.id!r}")
            ids.add(st.id)
            self.stages.append(st)
            offset += st.duration

    @property
    def duration(self) -> float:
        return sum(st.duration for st in self.stages)

    def _thresholds(self, th: Any) -> Dict[str, Dict[str, float]]:
        path = f"{self.source}: thresholds"
        if not isinstance(th, dict):
            raise BenchError(f"{path}: expected an object")
        out = {}
        for k, v in th.items():
            if k not in METRICS:
                raise BenchError(f"{path}: unknown metric {k!r} (known: "
                                 f"{', '.join(METRICS)})")
            if not isinstance(v, dict) or not v or set(v) - {"min", "max"} \
                    or not all(isinstance(x, (int, float)) and
                               not isinstance(x, bool) for x in v.values()):
                raise BenchError(f"{path}.{k}: expected {{\"min\": N}} "
                                 "and/or {\"max\": N}")
            out[k] = {b: float(x) for b, x in v.items()}
        return out

    def _stage(self, raw: Any, i: int, offset: float) -> Stage:
        path = f"{self.source}: stages[{i}]"
        if not isinstance(raw, dict):
            raise BenchError(f"{path}: expected an object")
        bad = sorted(set(raw) - _STAGE_KEYS)
        if bad:
            raise BenchError(f"{path}: unknown key(s) {', '.join(bad)} "
                             f"(allowed: {', '.join(sorted(_STAGE_KEYS))})")
        sid = raw.get("id")
        if not isinstance(sid, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+",
                                                         sid):
            raise BenchError(f"{path}.id: required; letters, digits, "
                             "'_', '.', '-'")
        path = f"{path} ({sid})"
        kind = raw.get("kind")
        if kind not in KINDS:
            raise BenchError(f"{path}.kind: one of {', '.join(KINDS)}")
        seed = raw.get("seed", self.seed + i)
        if not isinstance(seed, int) or isinstance(seed, bool):
            raise BenchError(f"{path}.seed: expected an integer")
        desc = str(raw.get("description", ""))
        allowed = {"baseline": {"duration"}, "incidents": {"duration",
                                                            "inject"},
                   "campaign": {"plan", "phases"}}[kind]
        extra = sorted(set(raw) & {"duration", "inject", "plan", "phases"}
                       - allowed)
        if extra:
            raise BenchError(f"{path}: {', '.join(extra)} not allowed for "
                             f"a {kind} stage")
        if kind in ("baseline", "incidents"):
            if "duration" not in raw:
                raise BenchError(f"{path}.duration: required")
            dur = _dur(raw["duration"], f"{path}.duration")
            if dur <= 0:
                raise BenchError(f"{path}.duration: must be > 0")
            if kind == "baseline":
                phases = [{"name": sid, "duration": dur}]
            else:
                phases = self._inject_phases(raw.get("inject"), dur, path)
        else:
            if ("plan" in raw) == ("phases" in raw):
                raise BenchError(f"{path}: give exactly one of 'plan' or "
                                 "'phases'")
            if "plan" in raw:
                p = campaign.find(str(raw["plan"]))
                try:
                    plan = campaign.load(p)
                except campaign.CampaignError as e:
                    raise BenchError(f"{path}.plan: {e}") from None
                if plan.env_key != self.env:
                    raise BenchError(
                        f"{path}.plan: {raw['plan']!r} runs on "
                        f"{plan.env_key or plan.env_file!r}, the suite on "
                        f"{self.env!r} (every stage shares one environment)")
                phases = [dict(ph) for ph in plan.doc["phases"]]
                desc = desc or plan.description
            else:
                phases = raw["phases"]
                if not isinstance(phases, list) or not phases:
                    raise BenchError(f"{path}.phases: expected a non-empty "
                                     "list")
        doc: Dict[str, Any] = {
            "name": f"{self.name}-{sid}", "description": desc,
            "env": self.env, "seed": seed, "phases": phases}
        for k in ("day_profile", "utc_offset", "span", "sprinkle_messages"):
            if self.doc.get(k) is not None:
                doc[k] = self.doc[k]
        if raw.get("day_profile"):
            doc["day_profile"] = raw["day_profile"]
        try:
            campaign.Plan(doc, path)          # schema check of the phases
        except campaign.CampaignError as e:
            raise BenchError(str(e)) from None
        return Stage(sid, kind, desc, seed, offset, doc, path)

    @staticmethod
    def _inject_phases(inject: Any, dur: float, path: str) -> List[Dict]:
        from . import incidents
        if not isinstance(inject, list) or not inject:
            raise BenchError(f"{path}.inject: expected a non-empty list")
        wins = []
        for j, x in enumerate(inject):
            p = f"{path}.inject[{j}]"
            if not isinstance(x, dict):
                raise BenchError(f"{p}: expected an object")
            bad = sorted(set(x) - _INJECT_KEYS)
            if bad or not {"at", "incident", "duration"} <= set(x):
                raise BenchError(f"{p}: expected {{\"at\", \"incident\", "
                                 "\"duration\"}")
            keys = x["incident"] if isinstance(x["incident"], list) \
                else [x["incident"]]
            for k in keys:
                if k not in incidents.INCIDENTS:
                    raise BenchError(f"{p}.incident: unknown incident {k!r} "
                                     "(see 'tgt list')")
            at = _dur(x["at"], f"{p}.at")
            d = _dur(x["duration"], f"{p}.duration")
            if d <= 0 or at + d > dur:
                raise BenchError(f"{p}: window {_fmt(at)} + {_fmt(d)} must "
                                 f"be non-empty and end by {_fmt(dur)}")
            wins.append((at, at + d, [str(k) for k in keys]))
        cuts = sorted({0.0, dur} | {a for a, _, _ in wins} |
                      {b for _, b, _ in wins})
        phases = []
        for a, b in zip(cuts, cuts[1:]):
            active = sorted({k for s, e, ks in wins if s <= a < e
                             for k in ks})
            ph: Dict[str, Any] = {"name": ("inject-" + "+".join(active))
                                  if active else "quiet",
                                  "duration": b - a}
            if active:
                ph["sprinkle"] = active
            phases.append(ph)
        return phases

    def check(self, min_period: Optional[float] = None) -> List[str]:
        """Problems found building and validating every stage (env errors,
        phases too short to learn their changes)."""
        mp = self.min_period if min_period is None else min_period
        problems = []
        for st in self.stages:
            try:
                phases = campaign.build(campaign.Plan(st.plan(),
                                                      st.source))
            except Exception as e:  # noqa: BLE001 — CampaignError/EnvFile
                problems.append(f"stage {st.id}: {e}")
                continue
            problems += [f"stage {st.id}: {p}"
                         for p in campaign.validate(phases, mp)]
        return problems

    def fingerprint(self) -> str:
        """What fixes the traffic: the suite document and its seeds."""
        blob = json.dumps({"suite": self.doc,
                           "seeds": [st.seed for st in self.stages]},
                          sort_keys=True, default=str)
        return hashlib.sha256(blob.encode()).hexdigest()[:16]


def load(path: str) -> Suite:
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except OSError as e:
        raise BenchError(f"{path}: cannot read: {e.strerror or e}") from None
    except ValueError as e:
        raise BenchError(f"{path}: invalid JSON: {e}") from None
    return Suite(doc, path)


def packaged() -> List[str]:
    try:
        return sorted(os.path.join(BENCHES, f) for f in os.listdir(BENCHES)
                      if f.endswith(".json"))
    except OSError:
        return []


def find(name: str) -> str:
    """A suite path, or the name of a packaged suite."""
    if os.path.exists(name):
        return name
    for p in packaged():
        base = os.path.basename(p)
        if name in (base, os.path.splitext(base)[0]):
            return p
    return name


# ---------------------------------------------------------------------------
# Running a suite -> bundle
# ---------------------------------------------------------------------------
def _read_json(path: str, what: str = "file") -> Dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except OSError as e:
        raise BenchError(f"cannot read {what} {path}: "
                         f"{e.strerror or e}") from None
    except ValueError as e:
        raise BenchError(f"{path}: invalid JSON: {e}") from None
    if not isinstance(doc, dict):
        raise BenchError(f"{path}: not a JSON object")
    return doc


def _write_json(path: str, doc: Any) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, default=str)
        f.write("\n")
    os.replace(tmp, path)


def _window(m: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    ph = m.get("phases") or []
    if ph:
        return ph[0].get("start"), ph[-1].get("end")
    return m.get("start"), m.get("end")


def merge_manifests(stages: Sequence[Tuple[str, Dict[str, Any]]],
                    bench: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """One ``tgt-manifest/1`` ground truth for a whole bundle: the union of
    every stage's inventory (a host's latest values win — what the monitor
    saw last), earliest first-seen / latest last-seen, and every stage's
    flows, phases and events (ids prefixed ``<stage>/``)."""
    from .manifest import SCHEMA as MSCHEMA
    hosts: Dict[str, Dict] = {}
    new: Dict[str, Dict] = {}
    infra: Dict[tuple, Dict] = {}
    ext: Dict[str, Dict] = {}
    iflows: Dict[tuple, Dict] = {}
    segs: Dict[str, Dict] = {}
    first: Dict[str, str] = {}
    last: Dict[str, str] = {}
    flows, events, phases = [], [], []
    inv_meta: Dict[str, Any] = {}
    starts, ends = [], []
    packets = nbytes = errors = 0
    env = None
    for sid, m in stages:
        inv = m.get("inventory") or {}
        inv_meta = {k: v for k, v in inv.items() if k not in (
            "hosts", "new_assets", "infrastructure", "external", "flows",
            "segments", "phases")} or inv_meta
        env = env or m.get("env")
        for h in inv.get("hosts") or []:
            hosts[h.get("asset_id") or h.get("name")] = h
        for h in inv.get("new_assets") or []:
            new[h.get("asset_id") or h.get("name") or h.get("ip")] = h
        for x in inv.get("infrastructure") or []:
            infra[(x.get("ip"), x.get("mac"))] = x
        for x in inv.get("external") or []:
            ext[x.get("ip")] = x
        for f in inv.get("flows") or []:
            iflows.setdefault((f.get("client"), f.get("server"),
                               f.get("protocol")), f)
        for s in inv.get("segments") or []:
            segs.setdefault(s.get("name"), s)
        for k, v in (m.get("first_seen") or {}).items():
            if v and (k not in first or v < first[k]):
                first[k] = v
        for k, v in (m.get("last_seen") or {}).items():
            if v and (k not in last or v > last[k]):
                last[k] = v
        flows += [dict(f, stage=sid) for f in m.get("flows_seen") or []]
        events += [dict(e, id=f"{sid}/{e.get('id')}", stage=sid)
                   for e in m.get("events") or []]
        phases += [dict(p, id=f"{sid}/{p.get('id')}", stage=sid)
                   for p in m.get("phases") or []]
        a, b = _window(m)
        if a:
            starts.append(a)
        if b:
            ends.append(b)
        packets += int(m.get("packets") or 0)
        nbytes += int(m.get("bytes") or 0)
        errors += int(m.get("errors") or 0)
    inventory = dict(inv_meta)
    inventory.update({
        "segments": list(segs.values()), "hosts": list(hosts.values()),
        "flows": list(iflows.values()),
        "external": list(ext.values()),
        "infrastructure": list(infra.values()),
        "new_assets": [h for k, h in new.items() if k not in hosts]})
    return {
        "schema": MSCHEMA,
        "tool": {"name": "tgt", "version": __version__},
        "bench": {"suite": (bench.get("suite") or {}).get("name"),
                  "fingerprint": bench.get("fingerprint")} if bench else None,
        "env": env, "start": min(starts) if starts else None,
        "end": max(ends) if ends else None,
        "clock": (bench or {}).get("clock"),
        "packets": packets, "bytes": nbytes, "errors": errors,
        "inventory": inventory, "first_seen": first, "last_seen": last,
        "flows_seen": flows, "phases": phases, "events": events,
        "stages": [sid for sid, _ in stages],
    }


def run(suite: Suite, out: str, iface: Optional[str] = None,
        pcap_dir: Optional[str] = None, clock: Optional[str] = None,
        speed: float = 1.0, min_period: Optional[float] = None,
        rate: Optional[float] = None, start_time: Optional[str] = None,
        force: bool = False, overwrite: bool = False,
        argv: Sequence[str] = ()) -> int:
    """Play every stage of ``suite`` into the bundle directory ``out``."""
    from . import cli
    from .manifest import _git_sha, parse_iso
    index_path = os.path.join(out, "bench.json")
    if os.path.exists(index_path) and not overwrite:
        print(f"{out} already holds a bench bundle; pass --overwrite or "
              "choose another --out.", file=sys.stderr)
        return 2
    os.makedirs(os.path.join(out, "stages"), exist_ok=True)
    clock = clock or ("wall" if iface else "synthetic")
    if pcap_dir is None and not iface:
        pcap_dir = os.path.join(out, "stages")
    if pcap_dir:
        os.makedirs(pcap_dir, exist_ok=True)
    mp = suite.min_period if min_period is None else min_period
    t0 = None
    if clock == "synthetic":
        start = start_time or suite.start_time
        t0 = parse_iso(start) if start else float(int(time.time()))
    index: Dict[str, Any] = {
        "schema": SCHEMA,
        "suite": {"name": suite.name, "description": suite.description,
                  "source": suite.source, "doc": suite.doc},
        "fingerprint": suite.fingerprint(),
        "tool": {"name": "tgt", "version": __version__, "git": _git_sha()},
        "created": _iso(time.time()), "env": suite.env, "clock": clock,
        "speed": speed, "min_period": mp, "iface": iface,
        "duration_s": suite.duration, "status": "running",
        "thresholds": suite.thresholds, "manifest": "manifest.json",
        "stages": []}
    done: List[Tuple[str, Dict[str, Any]]] = []
    interrupted = [False]

    def _sigint(signum, frame):
        interrupted[0] = True
        raise KeyboardInterrupt

    import signal
    try:
        old_int = signal.signal(signal.SIGINT, _sigint)
    except (ValueError, OSError):         # not the main thread
        old_int = None
    rc = 0
    print(f"bench {suite.name}: env {suite.env}, {len(suite.stages)} stages, "
          f"{_fmt(suite.duration)} simulated, clock {clock}"
          + (f", speed {speed:g}x" if clock == "wall" else "")
          + f" -> {out}", flush=True)
    try:
        for st in suite.stages:
            start_iso = _iso(t0 + st.offset) if t0 is not None else None
            plan_rel = f"stages/{st.id}.plan.json"
            man_rel = f"stages/{st.id}.manifest.json"
            plan_path = os.path.join(out, plan_rel)
            man_path = os.path.join(out, man_rel)
            _write_json(plan_path, st.plan(start_iso))
            pcap = os.path.join(pcap_dir, f"{st.id}.pcap") if pcap_dir \
                else None
            print(f"\n== stage {st.id} ({st.kind}, {_fmt(st.duration)}, "
                  f"seed {st.seed})", flush=True)
            ns = argparse.Namespace(
                plan=plan_path, list=False, check=False, force=force,
                iface=iface, pcap=pcap, manifest=man_path, clock=clock,
                start_time=None, seed=None, rate=rate, count=0, speed=speed,
                min_period=mp, api=None, api_token=None,
                api_allow_remote=False,
                argv=list(argv) + ["--stage", st.id])
            stage_rc = cli.cmd_campaign(ns)
            row = {"id": st.id, "kind": st.kind,
                   "description": st.description, "seed": st.seed,
                   "offset_s": st.offset, "duration_s": st.duration,
                   "plan": plan_rel, "manifest": man_rel,
                   "pcap": (os.path.relpath(pcap, out)
                            if pcap and os.path.abspath(pcap).startswith(
                                os.path.abspath(out) + os.sep) else pcap),
                   "start": None, "end": None, "packets": 0, "events": 0,
                   "status": "failed"}
            if os.path.exists(man_path):
                m = _read_json(man_path, "stage manifest")
                row["start"], row["end"] = _window(m)
                row["packets"] = m.get("packets", 0)
                row["events"] = len(m.get("events") or [])
                complete = _complete(m, st, clock, speed)
                row["status"] = (
                    "complete" if complete and stage_rc == 0 else
                    # rc 0 but short: stopped by Ctrl-C / SIGTERM
                    "interrupted" if interrupted[0] or stage_rc == 0 else
                    "failed")
                done.append((st.id, m))
            index["stages"].append(row)
            _write_json(index_path, index)
            if done:
                _write_json(os.path.join(out, "manifest.json"),
                            merge_manifests(done, index))
            if row["status"] != "complete":
                rc = stage_rc or 1
                index["status"] = row["status"]
                break
        else:
            index["status"] = "complete"
    except KeyboardInterrupt:
        index["status"] = "interrupted"
        rc = 130
    finally:
        if old_int is not None:
            signal.signal(signal.SIGINT, old_int)
    _write_json(index_path, index)
    if done:
        _write_json(os.path.join(out, "manifest.json"),
                    merge_manifests(done, index))
    print(f"\nbench {suite.name}: {index['status']}, "
          f"{sum(r['packets'] for r in index['stages'])} packets, "
          f"{sum(r['events'] for r in index['stages'])} events -> "
          f"{index_path}")
    for r in index["stages"]:
        print(f"  {r['id']:12} {r['kind']:10} {r['start'] or '-'} .. "
              f"{r['end'] or '-'}  {r['status']}")
    return rc


def _complete(m: Dict[str, Any], st: Stage, clock: str, speed: float) -> bool:
    ph = m.get("phases") or []
    if len(ph) != len(st.plan_doc["phases"]) or not ph[-1].get("end"):
        return False
    from .manifest import parse_iso
    try:
        span = parse_iso(ph[-1]["end"]) - parse_iso(ph[0]["start"])
    except (KeyError, TypeError, ValueError):
        return False
    if clock == "wall":
        span *= speed if speed > 0 else 1.0
        return span >= st.duration - max(60.0, 0.05 * st.duration)
    return span >= st.duration - 1e-3


# ---------------------------------------------------------------------------
# Scoring a bundle -> scorecard
# ---------------------------------------------------------------------------
def load_bundle(path: str) -> Tuple[Dict[str, Any],
                                    List[Tuple[str, Dict[str, Any]]]]:
    """``bench.json`` and every stage manifest present in the bundle."""
    index_path = path if path.endswith(".json") else \
        os.path.join(path, "bench.json")
    root = os.path.dirname(os.path.abspath(index_path))
    index = _read_json(index_path, "bench index")
    if index.get("schema") != SCHEMA:
        raise BenchError(f"{index_path}: not a tgt bench index (schema "
                         f"{SCHEMA})")
    stages = []
    for r in index.get("stages") or []:
        mp = os.path.join(root, r["manifest"])
        if os.path.exists(mp):
            stages.append((r["id"], _read_json(mp, "stage manifest")))
    if not stages:
        raise BenchError(f"{index_path}: no stage manifests")
    return index, stages


def _median(xs: Sequence[float]) -> Optional[float]:
    xs = [x for x in xs if x is not None]
    return statistics.median(xs) if xs else None


def _rate(a: int, b: int) -> Optional[float]:
    return a / b if b else None


def _is_change(ev: Dict[str, Any]) -> bool:
    return str(ev.get("source", "")).startswith("campaign:")


def _det_block(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    det = [r for r in rows if r["detected"]]
    return {"events": len(rows), "detected": len(det),
            "rate": _rate(len(det), len(rows)),
            "median_ttd_s": _median([r["ttd_s"] for r in det])}


def _technique_names() -> Dict[str, str]:
    try:                     # the ATT&CK table, when this TGT ships one
        from . import techniques           # type: ignore[attr-defined]
        return {k: techniques.name(k) for k in techniques.load()}
    except Exception:  # noqa: BLE001
        return {}


def _per_technique(det: Dict[str, Any], truth_events: List[Dict[str, Any]]
                   ) -> Optional[Dict[str, Dict[str, Any]]]:
    """Per-technique detection: the scorer's ``by_technique`` when it has
    one, else from the events' ``techniques`` (None when neither exists)."""
    bt = det.get("by_technique")
    if isinstance(bt, dict):
        return {k: {"name": v.get("name", ""), "events": v.get("events", 0),
                    "detected": v.get("detected", 0),
                    "rate": v.get("rate"),
                    "median_ttd_s": v.get("median_ttd_s")}
                for k, v in sorted(bt.items())}
    tech = {e.get("id"): e.get("techniques") for e in truth_events
            if e.get("techniques")}
    if not tech:
        return None
    names = _technique_names()
    out: Dict[str, Dict[str, Any]] = {}
    acc: Dict[str, List[Dict]] = {}
    for r in det.get("events_detail") or []:
        for t in tech.get(r["id"]) or ():
            acc.setdefault(t, []).append(r)
    for t in sorted(acc):
        out[t] = dict(_det_block(acc[t]), name=names.get(t, ""))
    return out


def _field_accuracy(res: Dict[str, Any]) -> Tuple[Optional[float], int]:
    obs = [v["observable"] for v in res["fields"].values() if v["exported"]]
    n = sum(o["n"] for o in obs)
    return _rate(sum(o["correct"] for o in obs), n), n


def scorecard(index: Dict[str, Any],
              stages: List[Tuple[str, Dict[str, Any]]],
              res: Dict[str, Any], label: Optional[str] = None,
              inputs: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Aggregate a ``tgt score`` result on the merged bundle truth into the
    bench scorecard."""
    from . import score as sc
    d = res["discovery"]
    fa, fa_n = _field_accuracy(res)
    det = res.get("detections")
    if det and "note" in det:
        det = None
    metrics: Dict[str, Optional[float]] = {
        "discovery_recall": d["recall"],
        "discovery_precision": d["precision"],
        "field_accuracy": fa,
        "protocol_recall": (res["protocols"] or {}).get("recall"),
        "change_detection_rate": None, "change_median_ttd_s": None,
        "attack_detection_rate": None, "attack_median_ttd_s": None,
        "technique_coverage": None, "false_alerts": None}
    detections = None
    stage_of = {}
    for sid, m in stages:
        for e in m.get("events") or []:
            stage_of[f"{sid}/{e.get('id')}"] = sid
    rows = (det or {}).get("events_detail") or []
    if det is not None:
        change = [r for r in rows if _is_change(r)]
        attack = [r for r in rows if not _is_change(r)]
        cb, ab = _det_block(change), _det_block(attack)
        per_cat: Dict[str, Dict[str, Any]] = {}
        for kind, group in (("change", change), ("attack", attack)):
            cats: Dict[str, List[Dict]] = {}
            for r in group:
                cats.setdefault(r["category"], []).append(r)
            for c in sorted(cats):
                per_cat[f"{kind}:{c}"] = dict(_det_block(cats[c]),
                                              kind=kind, category=c)
        truth_events = [dict(e, id=f"{sid}/{e.get('id')}")
                        for sid, m in stages for e in m.get("events") or []]
        pt = _per_technique(det, truth_events)
        metrics.update({
            "change_detection_rate": cb["rate"],
            "change_median_ttd_s": cb["median_ttd_s"],
            "attack_detection_rate": ab["rate"],
            "attack_median_ttd_s": ab["median_ttd_s"],
            "technique_coverage": _rate(
                sum(1 for v in pt.values() if v["detected"]), len(pt))
            if pt else None,
            "false_alerts": len(det["false_alerts"])})
        detections = {
            "events": det["events"], "detected": det["detected"],
            "rate": det["rate"], "median_ttd_s": det["median_ttd_s"],
            "change": cb, "attack": ab, "per_category": per_cat,
            "per_technique": pt,
            "alerts": det["alerts"], "mapped_alerts": det["mapped_alerts"],
            "matched_alerts": det["matched_alerts"],
            "false_alerts": len(det["false_alerts"]),
            "unmapped_alerts": det["unmapped_alerts"],
            "tolerance_s": det["tolerance_s"], "skew_s": det["skew_s"],
            "missed": [{"id": r["id"], "stage": stage_of.get(r["id"]),
                        "kind": "change" if _is_change(r) else "attack",
                        "category": r["category"], "t_start": r["t_start"],
                        "hosts": r["hosts"], "detail": r["detail"]}
                       for r in rows if not r["detected"]]}
    found = {a["id"] for a in res["assets"] if a["status"] != "missed"}
    srows = []
    by_id = {r["id"]: r for r in index.get("stages") or []}
    for sid, m in stages:
        pop = [a["id"] for a in sc.Truth(m, sid).population()]
        mine = [r for r in rows if stage_of.get(r["id"]) == sid]
        start, end = _window(m)
        ir = by_id.get(sid, {})
        srows.append({
            "id": sid, "kind": ir.get("kind"), "seed": ir.get("seed"),
            "status": ir.get("status"), "start": start, "end": end,
            "population": len(pop),
            "found": sum(1 for a in pop if a in found),
            "recall": _rate(sum(1 for a in pop if a in found), len(pop)),
            "events": len(m.get("events") or []),
            "detection": dict(
                _det_block(mine),
                change=_det_block([r for r in mine if _is_change(r)]),
                attack=_det_block([r for r in mine if not _is_change(r)]))
            if det is not None else None})
    checks = []
    for k, bounds in (index.get("thresholds") or {}).items():
        v = metrics.get(k)
        for b, lim in sorted(bounds.items()):
            ok = None if v is None else (v >= lim if b == "min" else
                                         v <= lim)
            checks.append({"metric": k, "bound": b, "limit": lim,
                           "value": v, "pass": ok})
    verdict = None
    if checks:
        verdict = "fail" if any(c["pass"] is False for c in checks) else \
            "incomplete" if any(c["pass"] is None for c in checks) else \
            "pass"
    return {
        "schema": CARD_SCHEMA,
        "label": label or None,
        "created": _iso(time.time()),
        "tool": {"name": "tgt", "version": __version__},
        "bench": {"suite": (index.get("suite") or {}).get("name"),
                  "description": (index.get("suite") or {}).get(
                      "description"),
                  "fingerprint": index.get("fingerprint"),
                  "tgt_version": (index.get("tool") or {}).get("version"),
                  "env": index.get("env"), "clock": index.get("clock"),
                  "speed": index.get("speed"), "status": index.get("status"),
                  "stages": len(stages),
                  "seeds": [r.get("seed") for r in index.get("stages") or []]},
        "inputs": inputs or {},
        "metrics": metrics,
        "discovery": {k: d[k] for k in (
            "population", "found", "recall", "matched_assets", "duplicates",
            "false_positives", "precision", "missed")},
        "fields": {f: dict(v["observable"], exported=v["exported"])
                   for f, v in res["fields"].items()},
        "field_values_scored": fa_n,
        "protocols": res["protocols"],
        "time_to_discover": res["time_to_discover"],
        "detections": detections,
        "stages": srows,
        "thresholds": checks,
        "verdict": verdict,
    }


def score_bundle(path: str, assets: str, amap: str,
                 alerts: Optional[str] = None,
                 alert_map: Optional[str] = None, label: Optional[str] = None,
                 tolerance: float = 300.0, skew: float = 5.0,
                 fuzzy: float = 0.85) -> Tuple[Dict[str, Any], Dict]:
    """(scorecard, full ``tgt score`` result on the merged bundle truth)."""
    from . import score as sc
    index, stages = load_bundle(path)
    truth = sc.Truth(merge_manifests(stages, index), path)
    mapping = sc.load_json_spec(amap, "map")
    rows, info = sc.read_export(assets, mapping)
    info["source"] = assets
    info["map"] = os.path.basename(mapping["_path"])
    al = None
    if alerts:
        if not alert_map:
            raise sc.ScoreError("--alerts needs --alert-map")
        al = sc.read_alerts(alerts, sc.load_json_spec(alert_map,
                                                      "alert map"))
    res = sc.score(truth, rows, info, alerts=al, tolerance=tolerance,
                   skew=skew, fuzzy=fuzzy)
    inputs = {"assets": os.path.basename(assets), "map": info["map"],
              "alerts": os.path.basename(alerts) if alerts else None,
              "alert_map": os.path.basename(alert_map) if alert_map
              else None}
    return scorecard(index, stages, res, label, inputs), res


def write_self_test(path: str, out_dir: str) -> Tuple[int, int]:
    """What a perfect monitor would export for the bundle: ``assets.csv``
    (``tgt score --self-test-export`` on the merged truth), ``alerts.csv``
    (one alert per event, at its start) and ``alert-map.json``."""
    from . import score as sc
    index, stages = load_bundle(path)
    merged = merge_manifests(stages, index)
    os.makedirs(out_dir, exist_ok=True)
    n_assets = sc.write_perfect_export(sc.Truth(merged, path),
                                       os.path.join(out_dir, "assets.csv"))
    cats = sorted({e.get("category", "") for e in merged["events"]})
    with open(os.path.join(out_dir, "alerts.csv"), "w", newline="",
              encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["time", "src", "dst", "title", "category"])
        for e in merged["events"]:
            w.writerow([e.get("t_start") or "", e.get("src") or "",
                        e.get("dst") or "", f"tgt {e.get('category')}",
                        e.get("category") or ""])
    amap = {"_comment": "alert map for the bench self-test alerts",
            "format": "csv",
            "columns": {"time": "time", "src": "src", "dst": "dst",
                        "title": "title", "category": "category"},
            "categories": {f"^tgt {re.escape(c)}$": c for c in cats if c}}
    with open(os.path.join(out_dir, "alert-map.json"), "w",
              encoding="utf-8") as f:
        json.dump(amap, f, indent=1)
        f.write("\n")
    return n_assets, len(merged["events"])


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
def _val(k: str, v: Optional[float]) -> str:
    if v is None:
        return "n/a"
    unit = METRICS[k][2] if k in METRICS else "pct"
    if unit == "pct":
        return f"{100 * v:.1f}%"
    if unit == "s":
        return f"{v:.1f}s"
    return f"{v:g}"


def summary(card: Dict[str, Any]) -> str:
    b = card["bench"]
    lines = [f"tgt bench scorecard — suite {b['suite']} ({b['env']}, "
             f"{b['stages']} stages, fingerprint {b['fingerprint']})"
             + (f" — {card['label']}" if card.get("label") else "")]
    for k, v in card["metrics"].items():
        lines.append(f"  {METRICS[k][1]:22} {_val(k, v):>9}")
    for s in card["stages"]:
        dt = s["detection"]
        lines.append(f"  stage {s['id']:12} assets {s['found']}/"
                     f"{s['population']}"
                     + (f"  events {dt['detected']}/{dt['events']}"
                        if dt else ""))
    for c in card["thresholds"]:
        st = {True: "pass", False: "FAIL", None: "n/a"}[c["pass"]]
        op = ">=" if c["bound"] == "min" else "<="
        lines.append(f"  threshold {c['metric']} {op} "
                     f"{_val(c['metric'], c['limit'])}: "
                     f"{_val(c['metric'], c['value'])} {st}")
    if card.get("verdict"):
        lines.append(f"verdict: {card['verdict'].upper()}")
    return "\n".join(lines)


_EXTRA_CSS = """
.pass{color:var(--ok)}.fail{color:var(--bad)}.na{color:var(--muted)}
.tile.pass{border-color:var(--ok)}.tile.fail{border-color:var(--bad)}
.up{color:var(--ok)}.down{color:var(--bad)}
"""


def _page(title: str, body: List[str]) -> str:
    from . import score as sc
    return ("<!doctype html><html lang=en><head><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width,"
            f"initial-scale=1'><title>{sc._h(title)}</title><style>"
            f"{sc._CSS}{_EXTRA_CSS}</style></head><body><main>"
            f"{''.join(body)}</main></body></html>\n")


def to_html(card: Dict[str, Any]) -> str:
    from . import score as sc
    h, table = sc._h, sc._table
    b = card["bench"]
    passed = {}
    for c in card["thresholds"]:
        prev = passed.get(c["metric"], True)
        passed[c["metric"]] = None if c["pass"] is None or prev is None \
            else prev and c["pass"]
    title = f"TGT bench — {b['suite']}" + (
        f" — {card['label']}" if card.get("label") else "")
    body = [f"<h1>{h(title)}</h1>",
            f"<p class=sub>Suite <code>{h(b['suite'])}</code> on "
            f"<code>{h(b['env'])}</code> · {b['stages']} stages · "
            f"fingerprint <code>{h(b['fingerprint'])}</code> · TGT "
            f"{h(b['tgt_version'])} · clock {h(b['clock'])}"
            + (f" · verdict <b class={'pass' if card['verdict'] == 'pass' else 'fail' if card['verdict'] == 'fail' else 'na'}>"
               f"{h(card['verdict'].upper())}</b>" if card.get("verdict")
               else "") + "</p>",
            "<div class=tiles>"]
    for k, v in card["metrics"].items():
        cls = {True: " pass", False: " fail", None: ""}[passed.get(k)] \
            if k in passed else ""
        body.append(f"<div class='tile{cls}'><span>{h(METRICS[k][1])}"
                    f"</span><b>{h(_val(k, v))}</b><span>"
                    f"{'lower is better' if METRICS[k][0] == 'max' else ''}"
                    "</span></div>")
    body.append("</div>")
    if b.get("description"):
        body.append(f"<p class=sub style='margin-top:12px'>"
                    f"{h(b['description'])}</p>")
    if card["thresholds"]:
        body.append("<h2>Thresholds</h2>")
        body.append(table(("Metric", "Bound", "Value", "Result"), [
            (METRICS[c["metric"]][1],
             f"{'≥' if c['bound'] == 'min' else '≤'} "
             f"{_val(c['metric'], c['limit'])}",
             _val(c["metric"], c["value"]),
             ({True: "pass", False: "fail", None: "n/a"}[c["pass"]],
              {True: "pass", False: "fail", None: "na"}[c["pass"]]))
            for c in card["thresholds"]]))
    body.append("<h2>Stages</h2>")
    srows = []
    for s in card["stages"]:
        dt = s["detection"]
        srows.append((s["id"], s["kind"] or "", s["start"] or "",
                       s["end"] or "", f"{s['found']}/{s['population']}",
                       _val("discovery_recall", s["recall"]),
                       f"{dt['detected']}/{dt['events']}" if dt else "n/a",
                       _val("discovery_recall", dt["rate"]) if dt else "n/a",
                       _val("attack_median_ttd_s", dt["median_ttd_s"])
                       if dt else "n/a"))
    body.append(table(("Stage", "Kind", "Start", "End", "Assets", "Recall",
                       "Detected", "Rate", "Median TTD"), srows,
                      numeric=(4, 5, 6, 7, 8)))
    det = card["detections"]
    if det:
        body.append("<h2>Detections by category</h2>")
        body.append(table(("Kind", "Category", "Events", "Detected", "Rate",
                           "Median TTD"),
                          [(v["kind"], v["category"], v["events"],
                            v["detected"], _val("discovery_recall",
                                                v["rate"]),
                            _val("attack_median_ttd_s", v["median_ttd_s"]))
                           for v in det["per_category"].values()],
                          numeric=(2, 3, 4, 5)))
        body.append("<h2>ATT&amp;CK techniques</h2>")
        if det["per_technique"] is None:
            body.append("<p class=sub>The bundle's events carry no technique "
                        "IDs.</p>")
        else:
            body.append(table(("Technique", "Name", "Events", "Detected",
                               "Rate", "Median TTD"),
                              [(t, v["name"], v["events"], v["detected"],
                                _val("discovery_recall", v["rate"]),
                                _val("attack_median_ttd_s",
                                     v["median_ttd_s"]))
                               for t, v in det["per_technique"].items()],
                              numeric=(2, 3, 4, 5)))
        body.append("<h2>Missed events</h2>")
        body.append(table(("Event", "Kind", "Category", "Start", "Hosts",
                           "Detail"),
                          [(e["id"], e["kind"], e["category"], e["t_start"],
                            ", ".join(e["hosts"]), e["detail"])
                           for e in det["missed"]]))
        body.append(f"<p class=sub>{det['alerts']} alerts, "
                    f"{det['mapped_alerts']} mapped, {det['matched_alerts']}"
                    f" matched, {det['false_alerts']} false, "
                    f"{det['unmapped_alerts']} unmapped · tolerance "
                    f"{det['tolerance_s']:g}s, skew {det['skew_s']:g}s</p>")
    else:
        body.append("<p class=sub>No alerts given: detection metrics "
                    "n/a.</p>")
    body.append("<h2>Field accuracy</h2>")
    body.append(table(("Field", "Observable", "Correct", "Partial", "Wrong",
                       "Missing", "Accuracy"),
                      [(f, v["n"], v["correct"], v["partial"], v["wrong"],
                        v["missing"], _val("field_accuracy", v["accuracy"]))
                       if v["exported"] else (f, ("not exported", "dim"), "",
                                              "", "", "", "")
                       for f, v in card["fields"].items()],
                      numeric=(1, 2, 3, 4, 5, 6)))
    body.append("<h2>Missed assets</h2>")
    body.append(table(("Asset",), [(a,) for a in
                                   card["discovery"]["missed"]]))
    inp = card.get("inputs") or {}
    body.append("<p class=sub>Inputs: " + " · ".join(
        f"{h(k)} <code>{h(v)}</code>" for k, v in inp.items() if v)
        + "</p>")
    return _page("TGT bench", body)


# ---------------------------------------------------------------------------
# Comparing two scorecards
# ---------------------------------------------------------------------------
def load_card(path: str) -> Dict[str, Any]:
    doc = _read_json(path, "scorecard")
    if doc.get("schema") != CARD_SCHEMA:
        raise BenchError(f"{path}: not a tgt bench scorecard (schema "
                         f"{CARD_SCHEMA})")
    return doc


def _delta(k: str, a: Optional[float], b: Optional[float]
           ) -> Tuple[Optional[float], Optional[str]]:
    if a is None or b is None:
        return None, None
    dv = b - a
    if abs(dv) < 1e-12:
        return 0.0, "same"
    better = dv > 0 if METRICS.get(k, ("min",))[0] == "min" else dv < 0
    return dv, "better" if better else "worse"


def compare(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """B relative to A: every metric, per-category / per-technique /
    per-stage detection rate, and whether the traffic was the same."""
    warn = []
    ba, bb = a["bench"], b["bench"]
    if ba.get("fingerprint") != bb.get("fingerprint"):
        warn.append(f"different suites or seeds (fingerprint "
                    f"{ba.get('fingerprint')} vs {bb.get('fingerprint')}): "
                    "the traffic was not identical")
    if ba.get("tgt_version") != bb.get("tgt_version"):
        warn.append(f"bundles made by different TGT versions "
                    f"({ba.get('tgt_version')} vs {bb.get('tgt_version')})")
    metrics = []
    for k in METRICS:
        va, vb = a["metrics"].get(k), b["metrics"].get(k)
        dv, how = _delta(k, va, vb)
        metrics.append({"metric": k, "a": va, "b": vb, "delta": dv,
                        "change": how})

    def rates(card, key):
        det = card.get("detections") or {}
        return {k: v.get("rate") for k, v in (det.get(key) or {}).items()}

    def side(ra, rb, k="change_detection_rate"):
        out = []
        for key in sorted(set(ra) | set(rb)):
            dv, how = _delta(k, ra.get(key), rb.get(key))
            out.append({"key": key, "a": ra.get(key), "b": rb.get(key),
                        "delta": dv, "change": how})
        return out

    st_a = {s["id"]: (s["detection"] or {}).get("rate")
            for s in a.get("stages") or []}
    st_b = {s["id"]: (s["detection"] or {}).get("rate")
            for s in b.get("stages") or []}
    verdicts = {"a": a.get("verdict"), "b": b.get("verdict")}
    return {"a": {"label": a.get("label"), "suite": ba.get("suite"),
                  "fingerprint": ba.get("fingerprint")},
            "b": {"label": b.get("label"), "suite": bb.get("suite"),
                  "fingerprint": bb.get("fingerprint")},
            "warnings": warn, "verdicts": verdicts, "metrics": metrics,
            "per_category": side(rates(a, "per_category"),
                                 rates(b, "per_category")),
            "per_technique": side(rates(a, "per_technique"),
                                  rates(b, "per_technique")),
            "stages": side(st_a, st_b)}


def _side_label(cmp: Dict[str, Any], which: str) -> str:
    return cmp[which]["label"] or which.upper()


def compare_text(cmp: Dict[str, Any]) -> str:
    la, lb = _side_label(cmp, "a"), _side_label(cmp, "b")
    lines = [f"tgt bench compare — A: {la}  B: {lb}  (suite "
             f"{cmp['a']['suite']})"]
    lines += [f"warning: {w}" for w in cmp["warnings"]]
    lines.append(f"  {'metric':22} {'A':>9} {'B':>9} {'B-A':>9}")
    for m in cmp["metrics"]:
        k = m["metric"]
        dv = "" if m["delta"] is None else (
            f"{100 * m['delta']:+.1f}pp" if METRICS[k][2] == "pct" else
            f"{m['delta']:+.1f}" + ("s" if METRICS[k][2] == "s" else ""))
        lines.append(f"  {METRICS[k][1]:22} {_val(k, m['a']):>9} "
                     f"{_val(k, m['b']):>9} {dv:>9} {m['change'] or ''}")
    for title, key in (("category", "per_category"),
                       ("technique", "per_technique"), ("stage", "stages")):
        rows = [r for r in cmp[key] if r["change"] not in (None, "same")]
        for r in rows:
            lines.append(f"  {title} {r['key']}: {_val('x', r['a'])} -> "
                         f"{_val('x', r['b'])} ({r['change']})")
    v = cmp["verdicts"]
    if v["a"] or v["b"]:
        lines.append(f"verdict: A {v['a'] or '-'}  B {v['b'] or '-'}")
    return "\n".join(lines)


def compare_html(cmp: Dict[str, Any]) -> str:
    from . import score as sc
    h, table = sc._h, sc._table
    la, lb = _side_label(cmp, "a"), _side_label(cmp, "b")
    body = [f"<h1>TGT bench — {h(la)} vs {h(lb)}</h1>",
            f"<p class=sub>Suite <code>{h(cmp['a']['suite'])}</code> · "
            f"A fingerprint <code>{h(cmp['a']['fingerprint'])}</code> · "
            f"B fingerprint <code>{h(cmp['b']['fingerprint'])}</code></p>"]
    for w in cmp["warnings"]:
        body.append(f"<p class=fail>warning: {h(w)}</p>")

    def cls(ch):
        return {"better": "up", "worse": "down"}.get(ch or "", "dim")

    def delta(k, m):
        if m["delta"] is None:
            return ("", "dim")
        u = METRICS.get(k, ("min", "", "pct"))[2]
        txt = (f"{100 * m['delta']:+.1f} pp" if u == "pct" else
               f"{m['delta']:+.1f}" + ("s" if u == "s" else ""))
        return (txt, cls(m["change"]))

    body.append("<h2>Metrics</h2>")
    body.append(table(("Metric", la, lb, "B − A"), [
        (METRICS[m["metric"]][1], _val(m["metric"], m["a"]),
         _val(m["metric"], m["b"]), delta(m["metric"], m))
        for m in cmp["metrics"]], numeric=(1, 2, 3)))
    for title, key in (("Detection rate by category", "per_category"),
                       ("Detection rate by ATT&CK technique",
                        "per_technique"),
                       ("Detection rate by stage", "stages")):
        body.append(f"<h2>{h(title)}</h2>")
        body.append(table(("", la, lb, "B − A"), [
            (r["key"], _val("x", r["a"]), _val("x", r["b"]), delta("x", r))
            for r in cmp[key]], numeric=(1, 2, 3)))
    v = cmp["verdicts"]
    if v["a"] or v["b"]:
        body.append(f"<p class=sub>Verdict: {h(la)} {h(v['a'] or '-')} · "
                    f"{h(lb)} {h(v['b'] or '-')}</p>")
    return _page("TGT bench compare", body)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def add_arguments(p) -> None:
    bs = p.add_subparsers(dest="bench_cmd", required=True)
    pl = bs.add_parser("list", help="list the packaged suites")
    pl.add_argument("--check", action="store_true",
                    help="also build and validate every stage")
    pr = bs.add_parser("run", help="play a suite into a bundle directory")
    pr.add_argument("suite", help="suite file or packaged name "
                                  "(see 'tgt bench list')")
    pr.add_argument("--out", "-o", metavar="DIR",
                    help="bundle directory (bench.json, stage manifests, "
                         "pcaps)")
    pr.add_argument("--check", action="store_true",
                    help="validate the suite and print its stages; send "
                         "nothing")
    pr.add_argument("--iface", "-i", help="send live on this interface "
                                          "(needs root)")
    pr.add_argument("--pcap-dir", metavar="DIR",
                    help="write one pcap per stage here (default with no "
                         "--iface: the bundle's stages/)")
    pr.add_argument("--clock", choices=["wall", "synthetic"], default=None,
                    help="default: wall with --iface, else synthetic")
    pr.add_argument("--speed", type=float, default=1.0, metavar="X",
                    help="wall clock: run X times faster than real time")
    pr.add_argument("--min-period", type=_duration_arg, default=None,
                    metavar="SECONDS",
                    help="no conversation recurs faster than this "
                         "(default: the suite's)")
    pr.add_argument("--rate", type=float, default=None,
                    help="packet-rate cap (default: none)")
    pr.add_argument("--start-time", metavar="ISO",
                    help="synthetic clock start (default: the suite's)")
    pr.add_argument("--force", action="store_true",
                    help="run even if a phase is too short to learn its "
                         "change")
    pr.add_argument("--overwrite", action="store_true",
                    help="replace an existing bundle in --out")
    ps = bs.add_parser("score", help="score a monitor's exports against a "
                                     "bundle -> one scorecard")
    ps.add_argument("bundle", help="bundle directory (or its bench.json)")
    ps.add_argument("--assets", metavar="EXPORT",
                    help="the monitor's asset export, taken at the end of "
                         "the bench")
    ps.add_argument("--map", metavar="MAP",
                    help="column map (path or bundled name, see tgt score)")
    ps.add_argument("--alerts", metavar="FILE",
                    help="the monitor's alert export for the whole bench")
    ps.add_argument("--alert-map", metavar="MAP",
                    help="alert columns + title regex -> generic category")
    ps.add_argument("--label", metavar="NAME",
                    help="how the scorecard names the monitor under test")
    ps.add_argument("--tolerance", type=float, default=300.0, metavar="SEC",
                    help="alert may trail the event end by this much")
    ps.add_argument("--skew", type=float, default=5.0, metavar="SEC",
                    help="alert may precede the event start by this much")
    ps.add_argument("--fuzzy", type=float, default=0.85, metavar="RATIO",
                    help="name-similarity threshold for name matching")
    ps.add_argument("--out", "-o", metavar="SCORECARD.json",
                    help="write the scorecard here")
    ps.add_argument("--html", metavar="FILE",
                    help="write a self-contained HTML scorecard here")
    ps.add_argument("--detail", metavar="FILE",
                    help="also write the full 'tgt score' JSON here")
    ps.add_argument("--self-test-export", metavar="DIR",
                    help="write what a perfect monitor would export "
                         "(assets.csv, alerts.csv, alert-map.json) and exit")
    pc = bs.add_parser("compare", help="side-by-side deltas of two "
                                       "scorecards")
    pc.add_argument("a", help="scorecard A (baseline)")
    pc.add_argument("b", help="scorecard B")
    pc.add_argument("--json", metavar="FILE", help="write the comparison")
    pc.add_argument("--html", metavar="FILE",
                    help="write a self-contained HTML comparison")


def _duration_arg(text: str) -> float:
    try:
        return timing.parse_duration(text)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from None


def _print_stages(suite: Suite) -> None:
    for st in suite.stages:
        n = len(st.plan_doc["phases"])
        extra = ""
        if st.kind == "incidents":
            extra = ", ".join(p["name"][7:] for p in st.plan_doc["phases"]
                              if p.get("sprinkle"))
        print(f"  {st.id:12} {st.kind:10} +{_fmt(st.offset)} "
              f"{_fmt(st.duration):>12}  {n} phases, seed {st.seed}"
              + (f"; {extra}" if extra else ""))


def main(args) -> int:
    from . import score as sc
    cmd = args.bench_cmd
    try:
        if cmd == "list":
            bad = 0
            print("Packaged bench suites (tgt/benches/):")
            for p in packaged():
                try:
                    s = load(p)
                except BenchError as e:
                    print(f"  {os.path.basename(p):16} (invalid: {e})")
                    bad += 1
                    continue
                print(f"  {s.name:16} {s.env:18} {len(s.stages)} stages, "
                      f"{_fmt(s.duration)} simulated")
                if s.description:
                    print(f"    {s.description}")
                if args.check:
                    probs = s.check()
                    for pr in probs:
                        print(f"    error: {pr}")
                    print(f"    check: {'OK' if not probs else 'FAILED'}")
                    bad += bool(probs)
            return 1 if bad else 0
        if cmd == "run":
            suite = load(find(args.suite))
            print(f"suite {suite.name}: env {suite.env}, "
                  f"{len(suite.stages)} stages, {_fmt(suite.duration)} "
                  f"simulated, fingerprint {suite.fingerprint()}")
            _print_stages(suite)
            probs = suite.check(args.min_period)
            for pr in probs:
                print(f"  {'warning' if args.force else 'error'}: {pr}",
                      file=sys.stderr)
            if probs and not args.force:
                return 2
            if args.check:
                print("suite OK")
                return 0
            if not args.out:
                print("tgt bench run: --out DIR is required", file=sys.stderr)
                return 2
            if args.speed <= 0:
                print("--speed must be > 0.", file=sys.stderr)
                return 2
            return run(suite, args.out, iface=args.iface,
                       pcap_dir=args.pcap_dir, clock=args.clock,
                       speed=args.speed, min_period=args.min_period,
                       rate=args.rate, start_time=args.start_time,
                       force=args.force, overwrite=args.overwrite,
                       argv=getattr(args, "argv", ()))
        if cmd == "score":
            if args.self_test_export:
                na, ne = write_self_test(args.bundle, args.self_test_export)
                d = args.self_test_export
                print(f"wrote {d}/assets.csv ({na} assets), alerts.csv ({ne} "
                      f"alerts), alert-map.json; score with --assets "
                      f"{d}/assets.csv --map generic --alerts {d}/alerts.csv "
                      f"--alert-map {d}/alert-map.json", file=sys.stderr)
                return 0
            if not args.assets or not args.map:
                raise BenchError("--assets and --map are required (or "
                                 "--self-test-export)")
            card, res = score_bundle(
                args.bundle, args.assets, args.map, args.alerts,
                args.alert_map, args.label, args.tolerance, args.skew,
                args.fuzzy)
            print(summary(card))
            for path, doc in ((args.out, card), (args.detail, res)):
                if path:
                    with open(path, "w", encoding="utf-8") as f:
                        json.dump(doc, f, indent=2, default=str)
                        f.write("\n")
                    print(f"wrote {path}", file=sys.stderr)
            if args.html:
                with open(args.html, "w", encoding="utf-8") as f:
                    f.write(to_html(card))
                print(f"wrote {args.html}", file=sys.stderr)
            return 0
        if cmd == "compare":
            cmp = compare(load_card(args.a), load_card(args.b))
            print(compare_text(cmp))
            if args.json:
                with open(args.json, "w", encoding="utf-8") as f:
                    json.dump(cmp, f, indent=2)
                    f.write("\n")
                print(f"wrote {args.json}", file=sys.stderr)
            if args.html:
                with open(args.html, "w", encoding="utf-8") as f:
                    f.write(compare_html(cmp))
                print(f"wrote {args.html}", file=sys.stderr)
            return 0
    except (BenchError, sc.ScoreError) as e:
        print(f"tgt bench: {e}", file=sys.stderr)
        return 2
    return 2

