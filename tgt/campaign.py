"""Phased campaigns — ``tgt campaign plan.json``.

A campaign runs an environment through a sequence of phases on the timed
scheduler (:mod:`tgt.schedule`) to test baselining and change detection: a
quiet baseline, then a new device, a firmware change, a contractor laptop
talking across zones, a device going silent... Each phase applies its
changes on top of the previous phase (host and flow changes accumulate;
``sprinkle`` is per phase), rebuilds the environment through the env-file
format (:mod:`tgt.envfile`, so every change is validated like an env file)
and the manifest records each phase's inventory diff plus one generic event
per change for ``tgt score``.

Plan schema (JSON; TOML on Python 3.11+; unknown keys are errors)::

    {
      "name": "baseline-then-change", "description": "...",
      "env": "industrial-site",            # or "env_file": "site.json"
                                           # (relative to the plan)
      "start_time": "2026-11-02T06:00:00Z",  # optional synthetic start
      "seed": 42, "day_profile": "shift", "utc_offset": 0,   # optional
      "span": "access", "rate": 0, "sprinkle_messages": 2,   # optional
      "phases": [
        {"name": "baseline", "duration": "4h"},
        {"name": "new-plc", "duration": "2h",
         "add_host": [{"name": "PLC-PK9", "ip": "10.100.10.29",
                       "model": "rockwell-1756-l83e", "dhcp": false}],
         "add_flow": [{"client": "HMI-PK1", "server": "PLC-PK9",
                       "proto": "enip"}]},
        {"name": "fw", "duration": "2h",
         "set": [{"host": "PLC-PK9", "firmware": "33.011"}]},
        {"name": "gone", "duration": "2h", "offline": ["PLC-PK2"]}
      ]
    }

Phase keys: ``name``, ``description``, ``duration`` (required: seconds or
"30m"/"4h"/"2d"), ``add_host`` (env-file host entries; ``"dhcp": true``
also gives the host a DHCP flow to the site's DHCP server — it arrives with a
DORA and a gratuitous ARP), ``remove_host`` (names: decommissioned, its flows
go too), ``offline`` / ``online`` (names: the host goes silent — its clients
keep retrying — or comes back), ``set`` (``{"host": NAME, field: value}``
for ip, mac, firmware, model, serial, vendor, product, os, role, fqdn — the
identity traffic follows; an IP change re-ARPs), ``add_flow`` (env-file flow
entries, selectors allowed), ``remove_flow`` (``{"client", "server",
"proto"?}``), ``sprinkle`` (incident keys for this phase), ``rate`` (pps cap)
and ``day_profile``.

Events: ``new-asset``, ``asset-offline`` (offline or removed),
``ip-change``, ``firmware-change``, ``asset-change`` (model / serial / vendor
/ OS), ``new-conversation`` (between existing hosts), ``cross-zone`` (a new
flow that skips a Purdue layer - IT straight into OT - or links two adjacent
zones that did not talk before), plus the sprinkled attacks' own events. Each change event spans its phase (``t_start`` = phase start).

Validation: a phase must last at least 3x the slowest period among the steady
(OT polling / infrastructure) conversations its changes touch, and so must
the phase before it (so the baseline saw them) — unless ``--force``.
"""
from __future__ import annotations

import copy
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from . import enterprise, envfile, schedule, timing

_PLAN_KEYS = {"name", "description", "env", "env_file", "start_time", "seed",
              "day_profile", "utc_offset", "span", "rate",
              "sprinkle_messages", "phases"}
_PHASE_KEYS = {"name", "description", "duration", "add_host", "remove_host",
               "offline", "online", "set", "add_flow", "remove_flow",
               "sprinkle", "rate", "day_profile"}
_SET_FIELDS = {"ip", "mac", "firmware", "model", "serial", "vendor",
               "product", "os", "role", "fqdn"}
_IDENTITY_FIELDS = {"model", "serial", "vendor", "product", "os"}
# conversations a phase must be long enough to show: steady classes only
# (human / occasional activity cannot be baselined in a few periods)
_STEADY = {"ot", "infra"}
_NOT_RELEVANT = {"dhcp", "netbios"}
MIN_PERIODS = 3
# zones that may talk directly (IT <-> DMZ <-> supervisory <-> cell)
_ADJACENT = {frozenset(p) for p in (("IT", "DMZ"), ("DMZ", "OT-SUPERVISORY"),
                                    ("OT-SUPERVISORY", "OT-CELL"))}


class CampaignError(ValueError):
    """A malformed or unrunnable plan (message names the offending path)."""


@dataclass
class Phase:
    """One phase as the engine runs it (also used for a plain timed run)."""
    id: str
    name: str
    duration: float                       # simulated seconds; 0 = unbounded
    env: Optional[enterprise.Environment] = None
    offline: Set[str] = field(default_factory=set)
    sprinkle: List[str] = field(default_factory=list)
    rate: Optional[float] = None
    day_profile: Optional[str] = None
    utc_offset: float = 0.0
    description: str = ""
    changes: Dict[str, Any] = field(default_factory=dict)   # as planned
    diff: Dict[str, Any] = field(default_factory=dict)      # inventory diff
    events: List[Dict[str, Any]] = field(default_factory=list)
    soon: Dict[tuple, float] = field(default_factory=dict)  # sid -> delay
    inject: List[tuple] = field(default_factory=list)  # (delay, key, frames)
    label: str = ""
    plan: Any = None

    @property
    def hosts(self):
        return self.env.hosts if self.env is not None else ()


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------
class Plan:
    def __init__(self, doc: Any, source: str = "<plan>") -> None:
        self.source = source
        if not isinstance(doc, dict):
            raise CampaignError(f"{source}: expected a JSON object")
        bad = sorted(set(doc) - _PLAN_KEYS)
        if bad:
            raise CampaignError(f"{source}: unknown key(s) {', '.join(bad)} "
                                f"(allowed: {', '.join(sorted(_PLAN_KEYS))})")
        self.doc = doc
        self.name = str(doc.get("name") or os.path.splitext(
            os.path.basename(source))[0])
        self.description = str(doc.get("description", ""))
        if bool(doc.get("env")) == bool(doc.get("env_file")):
            raise CampaignError(f"{source}: give exactly one of 'env' or "
                                "'env_file'")
        self.env_key = doc.get("env")
        self.env_file = doc.get("env_file")
        if self.env_file and not os.path.isabs(self.env_file):
            self.env_file = os.path.join(
                os.path.dirname(os.path.abspath(source)), self.env_file)
        self.start_time = doc.get("start_time")
        self.seed = doc.get("seed")
        if self.seed is not None and not isinstance(self.seed, int):
            raise CampaignError(f"{source}: seed: expected an integer")
        self.day_profile = doc.get("day_profile")
        if self.day_profile and self.day_profile not in timing.DAY_PROFILES:
            raise CampaignError(f"{source}: day_profile: "
                                f"{self.day_profile!r} is not one of "
                                f"{', '.join(timing.DAY_PROFILES)}")
        self.utc_offset = float(doc.get("utc_offset", 0.0))
        self.span = doc.get("span", "access")
        if self.span not in enterprise.SPAN_VIEWS:
            raise CampaignError(f"{source}: span: {self.span!r} is not one "
                                f"of {', '.join(enterprise.SPAN_VIEWS)}")
        self.rate = doc.get("rate")
        self.sprinkle_messages = int(doc.get("sprinkle_messages", 2))
        phases = doc.get("phases")
        if not isinstance(phases, list) or not phases:
            raise CampaignError(f"{source}: phases: expected a non-empty "
                                "list")
        self.phases: List[Dict[str, Any]] = []
        for i, p in enumerate(phases):
            path = f"{source}: phases[{i}]"
            if not isinstance(p, dict):
                raise CampaignError(f"{path}: expected an object")
            bad = sorted(set(p) - _PHASE_KEYS)
            if bad:
                raise CampaignError(f"{path}: unknown key(s) {', '.join(bad)}"
                                    f" (allowed: "
                                    f"{', '.join(sorted(_PHASE_KEYS))})")
            if "duration" not in p:
                raise CampaignError(f"{path}: duration is required")
            try:
                dur = timing.parse_duration(p["duration"])
            except ValueError as e:
                raise CampaignError(f"{path}.duration: {e}") from None
            if dur <= 0:
                raise CampaignError(f"{path}.duration: must be > 0")
            if p.get("day_profile") and \
                    p["day_profile"] not in timing.DAY_PROFILES:
                raise CampaignError(f"{path}.day_profile: unknown profile "
                                    f"{p['day_profile']!r}")
            for k in ("add_host", "remove_host", "offline", "online", "set",
                      "add_flow", "remove_flow", "sprinkle"):
                if k in p and not isinstance(p[k], list):
                    raise CampaignError(f"{path}.{k}: expected a list")
            self.phases.append(dict(p, duration=dur))

    def base_env(self) -> enterprise.Environment:
        if self.env_file:
            try:
                return envfile.load(self.env_file)
            except envfile.EnvFileError as e:
                raise CampaignError(f"{self.source}: env_file: {e}") from None
        if self.env_key not in enterprise.ENVIRONMENTS:
            raise CampaignError(f"{self.source}: env: unknown environment "
                                f"{self.env_key!r} (see 'tgt list')")
        return enterprise.get(self.env_key)

    @property
    def duration(self) -> float:
        return sum(p["duration"] for p in self.phases)


def load(path: str) -> Plan:
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        raise CampaignError(f"{path}: cannot read: {e.strerror or e}") \
            from None
    if path.lower().endswith(".toml"):
        if sys.version_info < (3, 11):
            raise CampaignError(f"{path}: TOML plans need Python 3.11+ "
                                "(tomllib); use JSON")
        import tomllib
        try:
            doc = tomllib.loads(text)
        except tomllib.TOMLDecodeError as e:
            raise CampaignError(f"{path}: invalid TOML: {e}") from None
    else:
        try:
            doc = json.loads(text)
        except ValueError as e:
            raise CampaignError(f"{path}: invalid JSON: {e}") from None
    return Plan(doc, path)


def packaged() -> List[str]:
    """Example plans shipped in ``tgt/campaigns/``."""
    d = os.path.join(os.path.dirname(os.path.abspath(__file__)), "campaigns")
    try:
        return sorted(os.path.join(d, f) for f in os.listdir(d)
                      if f.endswith((".json", ".toml")))
    except OSError:
        return []


def find(name: str) -> str:
    """A plan path, or the name of a packaged example (with or without
    extension)."""
    if os.path.exists(name):
        return name
    for p in packaged():
        base = os.path.basename(p)
        if name in (base, os.path.splitext(base)[0]):
            return p
    return name


# ---------------------------------------------------------------------------
# Phases
# ---------------------------------------------------------------------------
def _aid(env, name: str) -> str:
    return f"{env.key}:{name}"


def _host_doc(doc: Dict, name: str, path: str) -> Dict:
    for h in doc["hosts"]:
        if h.get("name") == name:
            return h
    raise CampaignError(f"{path}: no host {name!r} in the environment "
                        "(at this phase)")


def _dhcp_server(env) -> Optional[str]:
    servers: Dict[str, int] = {}
    for c, s, p in env.conversations:
        if p == "dhcp":
            servers[s] = servers.get(s, 0) + 1
    return max(servers, key=servers.get) if servers else None


def _apply(doc: Dict, spec: Dict, prev_env, offline: Set[str],
           path: str) -> Tuple[Dict, Set[str], Set[str]]:
    """Apply one phase's host/flow changes to an env-file document."""
    doc = copy.deepcopy(doc)
    offline = set(offline)
    dhcp_hosts: Set[str] = set()
    names = {h.get("name") for h in doc["hosts"]}
    for i, raw in enumerate(spec.get("add_host") or ()):
        if not isinstance(raw, dict) or "name" not in raw:
            raise CampaignError(f"{path}.add_host[{i}]: expected a host "
                                "object with a name")
        h = dict(raw)
        if h.pop("dhcp", False):
            dhcp_hosts.add(h["name"])
        if h["name"] in names:
            raise CampaignError(f"{path}.add_host[{i}]: host {h['name']!r} "
                                "already exists")
        doc["hosts"].append(h)
        names.add(h["name"])
    if dhcp_hosts:
        server = _dhcp_server(prev_env)
        if server is None:
            raise CampaignError(f"{path}.add_host: dhcp requested but the "
                                "environment has no DHCP server")
        doc["flows"] += [{"client": n, "server": server, "proto": "dhcp"}
                         for n in sorted(dhcp_hosts)]
    for i, name in enumerate(spec.get("remove_host") or ()):
        _host_doc(doc, name, f"{path}.remove_host[{i}]")
        doc["hosts"] = [h for h in doc["hosts"] if h.get("name") != name]
        doc["flows"] = [f for f in doc["flows"]
                        if name not in (f.get("client"), f.get("server"))]
        if doc.get("field_devices"):     # the serial / LoRa devices behind it
            doc["field_devices"] = [d for d in doc["field_devices"]
                                    if d.get("behind") != name]
        offline.discard(name)
    for i, s in enumerate(spec.get("set") or ()):
        p = f"{path}.set[{i}]"
        if not isinstance(s, dict) or "host" not in s:
            raise CampaignError(f"{p}: expected {{\"host\": NAME, ...}}")
        bad = sorted(set(s) - _SET_FIELDS - {"host"})
        if bad:
            raise CampaignError(f"{p}: cannot set {', '.join(bad)} (allowed: "
                                f"{', '.join(sorted(_SET_FIELDS))})")
        h = _host_doc(doc, s["host"], p)
        if "model" in s:
            # a different device: identity from the catalog unless given
            for k in ("vendor", "product", "firmware", "serial"):
                if k not in s:
                    h.pop(k, None)
            from . import devices
            if devices.find(s["model"]) is None:
                raise CampaignError(f"{p}.model: unknown model "
                                    f"{s['model']!r} (see tgt/devices.py)")
            if "mac" not in s:            # new hardware, new NIC
                h.pop("mac", None)
        h.update({k: v for k, v in s.items() if k != "host"})
    for i, f in enumerate(spec.get("add_flow") or ()):
        if not isinstance(f, dict):
            raise CampaignError(f"{path}.add_flow[{i}]: expected an object")
        doc["flows"].append(dict(f))
    for i, f in enumerate(spec.get("remove_flow") or ()):
        if not isinstance(f, dict) or not {"client", "server"} <= set(f):
            raise CampaignError(f"{path}.remove_flow[{i}]: expected "
                                "{\"client\", \"server\", \"proto\"?}")
        before = len(doc["flows"])
        doc["flows"] = [x for x in doc["flows"] if not (
            x.get("client") == f["client"] and x.get("server") == f["server"]
            and f.get("proto") in (None, x.get("proto")))]
        if len(doc["flows"]) == before:
            raise CampaignError(f"{path}.remove_flow[{i}]: no such flow "
                                f"{f}")
    for k, add in (("offline", True), ("online", False)):
        for i, name in enumerate(spec.get(k) or ()):
            _host_doc(doc, name, f"{path}.{k}[{i}]")
            (offline.add if add else offline.discard)(name)
    return doc, offline, dhcp_hosts


def _zone(env, name: str) -> str:
    """A host's zone; every OT cell is a zone of its own (cell-to-cell
    traffic crosses zones, as a per-cell monitor sees it)."""
    seg = env.segment_of(env.host(name))
    return f"OT-CELL/{seg.name}" if seg.zone == "OT-CELL" else seg.zone


def _adjacent(a: str, b: str) -> bool:
    return frozenset((a.split("/")[0], b.split("/")[0])) in _ADJACENT


def _diff(prev, env, prev_off: Set[str], off: Set[str]) -> Dict[str, Any]:
    """Inventory + flow differences between two consecutive phases."""
    pn = {h.name: h for h in prev.hosts} if prev is not None else {}
    nn = {h.name: h for h in env.hosts}
    changed = []
    for name in sorted(set(pn) & set(nn)):
        a, b = pn[name], nn[name]
        for f in ("ip", "mac", "firmware", "model", "serial", "vendor",
                  "product", "os", "role", "fqdn"):
            if getattr(a, f) != getattr(b, f):
                changed.append({"asset_id": _aid(env, name), "name": name,
                                "field": f, "old": getattr(a, f),
                                "new": getattr(b, f)})
    pc = set(prev.conversations) if prev is not None else set()
    nc = set(env.conversations)
    order = {c: i for i, c in enumerate(env.conversations)}
    porder = {c: i for i, c in enumerate(prev.conversations)} \
        if prev is not None else {}
    return {
        "added": [_aid(env, n) for n in nn if n not in pn],
        "removed": [_aid(prev, n) for n in pn if n not in nn],
        "offline": [_aid(env, n) for n in sorted(off - prev_off) if n in nn],
        "online": [_aid(env, n) for n in sorted(prev_off - off) if n in nn],
        "changed": changed,
        "flows_added": [{"client": c, "server": s, "protocol": p}
                        for c, s, p in sorted(nc - pc, key=order.get)],
        "flows_removed": [{"client": c, "server": s, "protocol": p}
                          for c, s, p in sorted(pc - nc, key=porder.get)],
    }


def _events(prev, env, diff: Dict[str, Any], label: str) -> List[Dict]:
    """Generic change events of one phase (times filled in by the run)."""
    ev: List[Dict[str, Any]] = []
    nn = {h.name: h for h in env.hosts}
    pn = {h.name: h for h in prev.hosts} if prev is not None else {}

    def add(cat, names, src, dst=None, proto=None, detail=""):
        ev.append({"category": cat, "hosts": [_aid(env, n) for n in names],
                   "src": src, "dst": dst, "protocol": proto,
                   "detail": detail, "source": f"campaign:{label}"})

    new_hosts = {a.split(":", 1)[1] for a in diff["added"]}
    for n in sorted(new_hosts, key=list(nn).index):
        h = nn[n]
        add("new-asset", [n], h.ip, detail=f"new asset {n} ({h.ip}, "
            f"{h.model or h.vendor or h.role}) joins "
            f"{env.segment_of(h).name}")
    for a in diff["removed"]:
        n = a.split(":", 1)[1]
        add("asset-offline", [n], pn[n].ip,
            detail=f"{n} decommissioned (removed)")
    for a in diff["offline"]:
        n = a.split(":", 1)[1]
        add("asset-offline", [n], nn[n].ip, detail=f"{n} goes offline")
    by_host: Dict[str, Dict[str, tuple]] = {}
    for c in diff["changed"]:
        by_host.setdefault(c["name"], {})[c["field"]] = (c["old"], c["new"])
    for n, f in by_host.items():
        h = nn[n]
        if "ip" in f:
            add("ip-change", [n], f["ip"][1], f["ip"][0],
                detail=f"{n} changes IP {f['ip'][0]} -> {f['ip'][1]}")
        if "firmware" in f and "model" not in f:
            add("firmware-change", [n], h.ip,
                detail=f"{n} firmware {f['firmware'][0]} -> "
                       f"{f['firmware'][1]}")
        ident = sorted(set(f) & _IDENTITY_FIELDS)
        if ident:
            add("asset-change", [n], h.ip, detail=f"{n} " + ", ".join(
                f"{k} {f[k][0]!r} -> {f[k][1]!r}" for k in ident))
    # a new flow is a cross-zone event when it skips a Purdue layer (e.g.
    # IT straight into a cell, bypassing the DMZ) or joins two adjacent
    # zones that did not talk before
    pairs = {(_zone(prev, c), _zone(prev, s))
             for c, s, _ in (prev.conversations if prev is not None else ())}
    pairs = {p for p in pairs if _adjacent(*p)}
    for fl in diff["flows_added"]:
        c, s, p = fl["client"], fl["server"], fl["protocol"]
        if c in new_hosts or s in new_hosts:
            pass
        elif c != s:
            add("new-conversation", [c, s], nn[c].ip, nn[s].ip, p,
                detail=f"new {p} conversation {c} -> {s}")
        zc, zs = _zone(env, c), _zone(env, s)
        if c != s and zc != zs and (zc, zs) not in pairs:
            pairs.add((zc, zs))
            add("cross-zone", [c, s], nn[c].ip, nn[s].ip, p,
                detail=f"{p} {c} ({zc}) -> {s} ({zs})" + (
                    "" if _adjacent(zc, zs) else ": cell to cell"
                    if zc.startswith("OT-CELL/") and zs.startswith("OT-CELL/")
                    else ": skips a Purdue layer"))
    return ev


def build(plan: Plan) -> List[Phase]:
    """Every phase of ``plan``: its environment, offline set, inventory diff
    and change events (validated through the env-file loader)."""
    base = plan.base_env()
    doc = envfile.to_dict(base)
    prev, offline = base, set()
    phases: List[Phase] = []
    for i, spec in enumerate(plan.phases):
        path = f"{plan.source}: phases[{i}]"
        name = str(spec.get("name") or f"phase{i + 1}")
        changes = {k: v for k, v in spec.items()
                   if k not in ("name", "description", "duration")}
        prev_off = set(offline)
        doc, offline, dhcp_hosts = _apply(doc, spec, prev, offline, path)
        if i == 0 and doc == envfile.to_dict(base):
            env = base
        else:
            try:
                env = envfile.from_dict(doc, path)
            except envfile.EnvFileError as e:
                raise CampaignError(str(e)) from None
        diff = _diff(prev if i else None, env, prev_off, offline) if i else \
            {"added": [], "removed": [], "offline": sorted(
                _aid(env, n) for n in offline), "online": [], "changed": [],
             "flows_added": [], "flows_removed": []}
        events = _events(prev, env, diff, name) if i else [
            e for e in _events(None, env, diff, name)
            if e["category"] == "asset-offline"]
        ph = Phase(f"p{i + 1}", name, spec["duration"], env, offline,
                   list(spec.get("sprinkle") or ()), spec.get("rate",
                                                              plan.rate),
                   spec.get("day_profile") or plan.day_profile or
                   env.options.get("day_profile"),
                   plan.utc_offset or float(env.options.get("utc_offset",
                                                            0.0)),
                   str(spec.get("description", "")),
                   changes, diff, events, label=f"{name} ({env.key})",
                   plan=plan)
        _arrivals(ph, prev, dhcp_hosts)
        for k in ph.sprinkle:
            from . import incidents
            if k not in incidents.INCIDENTS:
                raise CampaignError(f"{path}.sprinkle: unknown incident "
                                    f"{k!r}")
        phases.append(ph)
        prev = env
    return phases


def _arrivals(ph: Phase, prev, dhcp_hosts: Set[str]) -> None:
    """What happens the moment a phase starts: an arriving host DHCPs (if it
    does) and announces itself with gratuitous ARPs, a host with a new IP or
    back online re-announces; identity polls of a changed device come
    soon."""
    env = ph.env
    pn = {h.name: h for h in prev.hosts} if prev is not None else {}
    announce = [a.split(":", 1)[1] for a in ph.diff.get("added", [])]
    announce += [c["name"] for c in ph.diff.get("changed", [])
                 if c["field"] in ("ip", "mac")]
    announce += [a.split(":", 1)[1] for a in ph.diff.get("online", [])]
    seen = set()
    for n in announce:
        if n in seen or n in ph.offline:
            continue
        seen.add(n)
        h = env.host(n)
        delay = 0.2
        if n in dhcp_hosts:
            for c, s, p in env.conversations:
                if c == n and p == "dhcp":
                    ph.soon[("conv", c, s, p)] = 0.05
            delay = 0.5
        g = schedule.gratuitous_arp(env, h)
        ph.inject.append((delay, "arp", [[g], [g]]))
    for c in ph.diff.get("changed", []):
        if c["field"] in ("firmware", "model", "serial"):
            for cv in env.conversations:
                if c["name"] in (cv[0], cv[1]):
                    ph.soon.setdefault(("conv",) + tuple(cv),
                                       5.0 + 5.0 * len(ph.soon))


def validate(phases: List[Phase], min_period: float = 0.0) -> List[str]:
    """Phases too short to learn or show their changes (see module doc)."""
    problems = []

    def periods(env, convs) -> List[Tuple[float, tuple]]:
        out = []
        for cv in convs:
            if cv not in set(env.conversations) or cv[2] in _NOT_RELEVANT:
                continue
            c, s = env.host(cv[0]), env.host(cv[1])
            if timing.activity_class(cv[2], c.role, s.role) not in _STEADY:
                continue
            p = max(timing.conversation_timing(env, cv)["period"],
                    min_period)
            out.append((p, cv))
        return out

    for i, ph in enumerate(phases):
        if i == 0:
            continue
        prev = phases[i - 1]
        touched = set()
        names = {a.split(":", 1)[1] for k in ("added", "removed", "offline",
                                              "online")
                 for a in ph.diff.get(k, [])}
        ident = {c["name"] for c in ph.diff.get("changed", [])
                 if c["field"] in _IDENTITY_FIELDS | {"firmware"}}
        moved = {c["name"] for c in ph.diff.get("changed", [])
                 if c["field"] in ("ip", "mac")}
        for env in (prev.env, ph.env):
            for cv in env.conversations:
                ends = {cv[0], cv[1]}
                if ends & (names | moved):
                    touched.add(cv)
                elif ends & ident and _carries_identity(cv[2]):
                    touched.add(cv)
        for f in ph.diff.get("flows_added", []) + \
                ph.diff.get("flows_removed", []):
            touched.add((f["client"], f["server"], f["protocol"]))
        for which, env in ((prev, prev.env), (ph, ph.env)):
            ps = periods(env, touched)
            if not ps:
                continue
            p, cv = max(ps)
            need = MIN_PERIODS * p
            if which.duration < need:
                role = "its change" if which is ph else \
                    f"the change in phase {ph.id} '{ph.name}'"
                problems.append(
                    f"phase {which.id} '{which.name}' lasts "
                    f"{_fmt(which.duration)} but {role} involves "
                    f"{cv[2]} {cv[0]} -> {cv[1]} every {_fmt(p)}: needs "
                    f">= {_fmt(need)} ({MIN_PERIODS}x)")
    return list(dict.fromkeys(problems))


def _carries_identity(proto: str) -> bool:
    from .inventory import _ANNOUNCES, _FROM_SERVER
    return "firmware" in (_FROM_SERVER.get(proto, ()) +
                          _ANNOUNCES.get(proto, ())) or proto in ("snmp",
                                                                  "snmpv3")


def _fmt(s: float) -> str:
    if s >= 3600:
        return f"{s / 3600:.3g}h"
    if s >= 60:
        return f"{s / 60:.3g}m"
    return f"{s:.3g}s"


# ---------------------------------------------------------------------------
# Engine glue
# ---------------------------------------------------------------------------
_PLAN_CACHE: Dict[str, List[Phase]] = {}


def phases_for(cfg) -> List[Phase]:
    """The phases a timed run executes: the campaign's, else one phase from
    the run config (``duration`` 0 = unbounded)."""
    if cfg.campaign:
        cached = _PLAN_CACHE.get(cfg.campaign)
        if cached is not None:
            return cached
        return build(load(cfg.campaign))
    env = enterprise.get(cfg.env) if cfg.env else None
    sprinkle = list(cfg.sprinkle)
    if cfg.sprinkle_random:
        from . import incidents
        import random
        pool = sprinkle or list(incidents.INCIDENTS)
        sprinkle = [random.Random(f"tgt:{cfg.seed}:sprinkle").choice(pool)]
    what = (f"incident {cfg.incident}" if cfg.incident else
            f"env {cfg.env}" if cfg.env else ", ".join(cfg.profiles))
    if sprinkle:
        what += f" + malware:{','.join(sprinkle)}"
    return [Phase("main", "main", cfg.duration, env, set(), sprinkle,
                  None, cfg.day_profile or (env.options.get("day_profile")
                                            if env is not None else None),
                  float((env.options.get("utc_offset", 0.0)
                         if env is not None else 0.0) or 0.0),
                  label=what)]


def phase_streams(ph: Phase, cfg) -> List[schedule.Stream]:
    """The streams of one phase."""
    if ph.env is not None:
        return schedule.env_streams(ph.env, cfg.span, ph.offline,
                                    ph.sprinkle, cfg.sprinkle_messages)
    if cfg.incident:
        out = schedule.incident_streams(cfg.incident, cfg.messages)
    else:
        out = schedule.profile_streams(cfg.profiles, cfg.endpoints)
    if ph.sprinkle:
        from .engine import DEFAULT_SPRINKLE_ENV
        out += schedule.sprinkle_streams(
            enterprise.get(DEFAULT_SPRINKLE_ENV), ph.sprinkle,
            cfg.sprinkle_messages, tagged=False)
    return out


def union_env(phases: List[Phase]):
    """One environment holding every host and conversation any phase had
    (a host's latest values win) — the campaign's inventory."""
    envs = [ph.env for ph in phases if ph.env is not None]
    if not envs:
        return None
    if all(e is envs[0] for e in envs):
        return envs[0]
    hosts: Dict[str, Dict] = {}
    flows: Dict[tuple, Dict] = {}
    doc: Dict[str, Any] = {}
    for env in envs:
        d = envfile.to_dict(env)
        doc = dict(d)
        for h in d["hosts"]:
            hosts[h["name"]] = h          # first position, latest values
        for f in d["flows"]:
            flows.setdefault((f["client"], f["server"], f["proto"]), f)
    doc["hosts"] = list(hosts.values())
    doc["flows"] = list(flows.values())
    try:
        return envfile.from_dict(doc, "<campaign union>")
    except envfile.EnvFileError:
        return envs[-1]          # e.g. an IP reused by another host


def remember(path: str, phases: List[Phase]) -> None:
    """Hand already-built phases to the engine (the CLI validated them)."""
    _PLAN_CACHE[path] = phases
