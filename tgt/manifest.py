"""Run manifest — machine-readable ground truth of what a run put on the wire.

``tgt run --manifest PATH`` writes one JSON document (schema
``tgt-manifest/1``): the seed and config that reproduce the run, the
environment's inventory, when each asset first/last sent a frame, every flow
seen (client, server, protocol), and one event per injected attack flow with a
vendor-neutral category, so a scorer (``tgt score``) can match sensor alerts
against it. The engine rewrites the file every ~10 s and on exit, atomically,
so a killed or long run still leaves a valid manifest.
"""
from __future__ import annotations

import datetime
import json
import os
import subprocess
from dataclasses import asdict
from typing import Dict, List, Optional, Sequence, Tuple

from . import __version__
from .packet import bytes_to_mac

SCHEMA = "tgt-manifest/1"

# Generic (vendor-neutral) category of each attack builder in
# ``incidents.ATTACKS`` — what a sensor alert on that traffic should map to.
ATTACK_CATEGORY: Dict[str, str] = {
    "port-scan": "scan",
    "eternalblue": "exploit-attempt",
    "log4shell": "exploit-attempt",
    "c2-beacon": "c2",
    "https-c2": "c2",
    "dga-dns": "c2",
    "dns-tunnel": "c2",
    "telnet-brute": "default-credentials",
    "rdp-brute": "lateral-movement",
    "smb-lateral": "lateral-movement",
    "modbus-write": "ot-write",
    "iec104-command": "ot-write",
    "s7-control": "plc-mode-change",     # CPU STOP (PI service P_PROGRAM)
    "tristation": "plc-program",         # TRITON: program download to the SIS
}


def iso(ts: Optional[float]) -> Optional[str]:
    """ISO-8601 UTC with microseconds and ``Z``."""
    if ts is None:
        return None
    dt = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_iso(text: str) -> float:
    """``2026-11-05T14:00:00Z`` (or with an offset / no zone = UTC) -> epoch."""
    t = text.strip()
    if t.endswith(("Z", "z")):
        t = t[:-1] + "+00:00"
    dt = datetime.datetime.fromisoformat(t)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.timestamp()


def _git_sha() -> Optional[str]:
    try:
        out = subprocess.run(
            ["git", "-C", os.path.dirname(os.path.abspath(__file__)),
             "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=2)
        return out.stdout.strip() or None if out.returncode == 0 else None
    except Exception:
        return None


def _ip(b: bytes) -> str:
    return ".".join(map(str, b))


class Recorder:
    """Accumulates per-frame ground truth for one run and renders the manifest.

    Each sent frame is fed to :meth:`observe` with its send (or virtual)
    timestamp, its profile/attack key and its source label (``baseline``,
    ``incident:<key>``, ``sprinkle:<incident>``). Hosts resolve to inventory
    asset ids (``<env>:<HOSTNAME>``) on env runs, else to their IP; flow
    direction comes from the modeled conversations, else the first sender.
    """

    def __init__(self, cfg, seed: Optional[int], argv: Sequence[str] = (),
                 clock: str = "wall"):
        from . import enterprise, incidents
        self.cfg, self.seed, self.argv, self.clock = cfg, seed, list(argv), clock
        self.git = _git_sha()
        self.env = enterprise.get(cfg.env) if cfg.env else None
        self.addr_aid: Dict[str, str] = {}      # ip / mac -> asset id
        self.aid_ip: Dict[str, str] = {}
        # (key, addr a, addr b) -> (client aid, server aid, client ip, server ip)
        self.flowidx: Dict[Tuple[str, str, str], tuple] = {}
        self.l2src: Dict[Tuple[str, str], tuple] = {}
        self.new_assets: Dict[str, Tuple[str, List[str]]] = {}  # aid -> ip, incs
        self.attack_desc = {k: v[1] for k, v in incidents.ATTACKS.items()}
        self.attack_proto = dict(incidents.ATTACK_PROTOCOLS)
        self.sprinkle = list(cfg.sprinkle) or (
            list(incidents.INCIDENTS) if cfg.sprinkle_random else [])
        self.inventory = None
        if self.env is not None:
            from . import inventory
            self.inventory = inventory.to_json(self.env, self.sprinkle)
        self._index()
        self._cache: Dict[tuple, tuple] = {}
        self._pairs: Dict[tuple, str] = {}
        self.first_ts: Optional[float] = None
        self.last_ts: Optional[float] = None
        self.packets = self.bytes = 0
        self.first_seen: Dict[str, float] = {}
        self.last_seen: Dict[str, float] = {}
        self.flows: Dict[tuple, list] = {}
        self.events: Dict[tuple, list] = {}

    # -- index of who talks to whom ---------------------------------------
    def _aid(self, host) -> str:
        if self.env is not None:
            return f"{self.env.key}:{host.name}"
        return host.ip

    def _host(self, host, aid: Optional[str] = None) -> str:
        aid = aid or self._aid(host)
        self.addr_aid.setdefault(host.ip, aid)
        self.addr_aid.setdefault(host.mac.lower(), aid)
        self.aid_ip.setdefault(aid, host.ip)
        return aid

    def _add(self, key: str, c, s, caid: Optional[str] = None,
             said: Optional[str] = None) -> None:
        rec = (caid or self._aid(c), said or self._aid(s), c.ip, s.ip)
        for a, b in ((c.ip, s.ip), (c.mac.lower(), s.mac.lower())):
            self.flowidx.setdefault((key, a, b), rec)
        self.l2src.setdefault((key, c.mac.lower()), rec)
        self.l2src.setdefault((key, s.mac.lower()), rec)

    def _index(self) -> None:
        from . import enterprise, incidents
        from .engine import DEFAULT_SPRINKLE_ENV
        cfg, env = self.cfg, self.env
        if env is not None:
            for h in env.hosts:
                self._host(h)
            for c, s, proto in env.conversations:
                ch, sh = env.host(c), env.host(s)
                self._add(proto, ch, sh)
                vc, vs = env.nat_view(ch, sh)    # as seen through NAT
                if vc is not ch or vs is not sh:
                    self._add(proto, vc, vs, self._aid(ch), self._aid(sh))
            for h, ip, fqdn, _ in env.edr_plan():
                cloud = enterprise._cs_cloud_host(ip, fqdn)
                self._add("edr", h, cloud, said=ip)
        elif cfg.incident:
            inc = incidents.get(cfg.incident)
            for a, v, atk, _ in inc.flows:
                self._add(atk, inc.host(a), inc.host(v))
        elif not cfg.replay_path:
            ep = cfg.endpoints

            class _H:                       # the two --client/--server hosts
                def __init__(self, ip, mac):
                    self.ip, self.mac, self.name = ip, mac, ip
            c, s = _H(ep.client_ip, ep.client_mac), _H(ep.server_ip, ep.server_mac)
            for key in cfg.profiles:
                self._add(key, c, s)
        if self.sprinkle and not cfg.replay_path:
            senv = env or enterprise.get(DEFAULT_SPRINKLE_ENV)
            for key in self.sprinkle:
                inc = incidents.get(key)
                mapping = inc.map_onto(senv)
                if env is not None:
                    for h in inc.unmapped_hosts(env):
                        aid = self._host(h)
                        ip, incs = self.new_assets.setdefault(aid, (h.ip, []))
                        incs.append(key)
                for a, v, atk, _ in inc.flows:
                    ah = mapping.get(a) or inc.host(a)
                    vh = mapping.get(v) or inc.host(v)
                    self._add(atk, ah, vh, self._known(ah), self._known(vh))

    def _known(self, host) -> str:
        """Asset id of an incident host: its inventory/new-asset id if it has
        one, else (external adversary infrastructure) its IP."""
        return self.addr_aid.get(host.ip) or host.ip

    # -- per frame -----------------------------------------------------------
    def _resolve(self, key: str, source: str, s: str, d: str,
                 smac: str, dmac: str) -> tuple:
        """(source asset, flow key, event key, flow record) of a frame from
        address ``s`` to ``d`` (IPs, or MACs for non-IP frames). IP frames
        that do not resolve by address (DHCP from 0.0.0.0, broadcasts) fall
        back to their MACs."""
        src_aid = (self.addr_aid.get(s) or self.addr_aid.get(smac)
                   or (smac if s == "0.0.0.0" else s))
        rec = None
        for a, b in ((s, d), (smac, dmac)):
            rec = self.flowidx.get((key, a, b))
            if rec is None:
                rec = self.flowidx.get((key, b, a))
            if rec is not None or a == smac:
                break
        if rec is None:
            rec = self.l2src.get((key, smac))
        if rec is None:                     # unmodeled: first sender = client
            pair = (key, source) + tuple(sorted((s, d)))
            first = self._pairs.setdefault(pair, s)
            c, sv = (s, d) if first == s else (d, s)
            rec = (self.addr_aid.get(c, c), self.addr_aid.get(sv, sv), c, sv)
        fkey = (rec[0], rec[1], key, source)
        ekey = fkey if source.startswith(("sprinkle:", "incident:")) else None
        return src_aid, fkey, ekey, rec

    def observe(self, ts: float, key: str, frame: bytes, source: str) -> None:
        if self.first_ts is None:
            self.first_ts = ts
        self.last_ts = ts
        self.packets += 1
        self.bytes += len(frame)
        off = 18 if frame[12:14] == b"\x81\x00" else 14
        ipb = b""
        if frame[off - 2:off] == b"\x08\x00" and len(frame) >= off + 20:
            ipb = frame[off + 12:off + 20]
        ck = (key, source, frame[0:12], ipb)
        hit = self._cache.get(ck)
        if hit is None:
            smac, dmac = bytes_to_mac(frame[6:12]), bytes_to_mac(frame[0:6])
            s, d = (_ip(ipb[:4]), _ip(ipb[4:])) if ipb else (smac, dmac)
            hit = self._cache[ck] = self._resolve(key, source, s, d,
                                                  smac, dmac)
        src_aid, fkey, ekey, rec = hit
        if src_aid not in self.first_seen:
            self.first_seen[src_aid] = ts
        self.last_seen[src_aid] = ts
        fl = self.flows.get(fkey)
        if fl is None:
            self.flows[fkey] = [ts, ts, 1]
        else:
            fl[1] = ts
            fl[2] += 1
        if ekey is not None:
            ev = self.events.get(ekey)
            if ev is None:
                self.events[ekey] = [ts, ts, 1, rec]
            else:
                ev[1] = ts
                ev[2] += 1

    # -- output --------------------------------------------------------------
    def _proto(self, key: str) -> str:
        return self.attack_proto.get(key) or key

    def to_dict(self, stats=None) -> Dict:
        cfg = self.cfg
        flows = []
        for (c, s, key, source), (t0, t1, n) in self.flows.items():
            row = {"client": c, "server": s, "protocol": self._proto(key),
                   "first": iso(t0), "last": iso(t1), "packets": n,
                   "source": source}
            if key in self.attack_desc:
                row["attack"] = key
            flows.append(row)
        events = []
        for (c, s, key, source), (t0, t1, n, rec) in self.events.items():
            events.append({
                "id": f"e{len(events) + 1}",
                "category": ATTACK_CATEGORY.get(key, "unknown"),
                "t_start": iso(t0), "t_end": iso(t1),
                "hosts": [c] if c == s else [c, s],
                "src": rec[2], "dst": rec[3], "protocol": self._proto(key),
                "detail": f"{key}: {self.attack_desc.get(key, key)}",
                "source": source, "attack": key, "packets": n})
        for aid, (ip, incs) in self.new_assets.items():
            if aid in self.first_seen:
                events.append({
                    "id": f"e{len(events) + 1}", "category": "new-asset",
                    "t_start": iso(self.first_seen[aid]),
                    "t_end": iso(self.last_seen[aid]),
                    "hosts": [aid], "src": ip, "dst": None, "protocol": None,
                    "detail": "host not in the inventory, introduced by "
                              f"sprinkle: {', '.join(incs)}",
                    "source": f"sprinkle:{incs[0]}"})
        packets = self.packets
        return {
            "schema": SCHEMA,
            "tool": {"name": "tgt", "version": __version__, "git": self.git},
            "seed": self.seed,
            "argv": self.argv,
            "config": json.loads(json.dumps(asdict(cfg), default=str)),
            "env": cfg.env,
            "span": cfg.span if cfg.env else None,
            "iface": cfg.iface,
            "pcap": cfg.pcap_path,
            "start": iso(self.first_ts),
            "end": iso(self.last_ts),
            "clock": self.clock,
            "packets": packets,
            "bytes": self.bytes,
            "errors": stats.errors if stats is not None else 0,
            "cycles": stats.cycles if stats is not None else 0,
            "inventory": self.inventory,
            "first_seen": {k: iso(v) for k, v in self.first_seen.items()},
            "last_seen": {k: iso(v) for k, v in self.last_seen.items()},
            "flows_seen": flows,
            "phases": [{"id": "main", "start": iso(self.first_ts),
                        "end": iso(self.last_ts), "packets": packets}],
            "events": events,
        }

    def write(self, path: str, stats=None) -> None:
        """Write atomically (temp file + rename) so readers never see a
        half-written manifest."""
        doc = self.to_dict(stats)
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1)
            f.write("\n")
        os.replace(tmp, path)
