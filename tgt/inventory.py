"""Ground-truth asset inventory of a modeled environment.

What a sensor *should* discover when fed ``tgt run --env KEY``: every host with
its addressing, vendor/product, OS fingerprint, segment/VLAN/zone, risk notes,
and the services it serves and uses. Diff it against the analyser's asset list
(Claroty CTD, Nozomi, Zeek ``known_hosts``, …) to measure discovery coverage.

CSV holds one row per host; JSON adds the segments and the expected flows (the
communication baseline).
"""
from __future__ import annotations

import csv
import json
from typing import Dict, List, Sequence, TextIO

from . import protocols
from .enterprise import OUI_VENDORS, Environment

COLUMNS = ["name", "ip", "mac", "mac_vendor", "vendor", "product", "role",
           "os", "segment", "vlan", "subnet", "zone", "gateway", "legacy",
           "risk", "serves", "uses"]


def _service(proto: str) -> str:
    """'modbus 502/tcp', or just 'arp' / 'icmp' for portless protocols."""
    p = protocols.get(proto)
    return proto if p.port == "-" else f"{proto} {p.port}/{p.transport}"


def hosts(env: Environment) -> List[Dict]:
    serves: Dict[str, set] = {h.name: set() for h in env.hosts}
    uses: Dict[str, set] = {h.name: set() for h in env.hosts}
    for client, server, proto in env.conversations:
        uses[client].add(proto)
        # self-announcements and ARP replies are not services
        if server != client and protocols.get(proto).transport != "l2":
            serves[server].add(_service(proto))
    # Falcon-covered Windows hosts beacon EDR telemetry to the CrowdStrike cloud
    for h in env.edr_hosts():
        uses[h.name].add("edr")
    rows = []
    for h in env.hosts:
        seg = env.segment_of(h)
        rows.append({
            "name": h.name, "ip": h.ip, "mac": h.mac,
            "mac_vendor": OUI_VENDORS.get(h.mac[:8], ""),
            "vendor": h.vendor, "product": h.product, "role": h.role,
            "os": h.fp.label, "segment": seg.name, "vlan": seg.vlan,
            "subnet": seg.subnet, "zone": seg.zone, "gateway": seg.gateway,
            "legacy": h.fp.legacy, "risk": h.fp.risk,
            "serves": sorted(serves[h.name]), "uses": sorted(uses[h.name]),
        })
    return rows


def to_json(env: Environment, sprinkle: Sequence[str] = ()) -> Dict:
    doc = {
        "env": env.key, "name": env.name, "category": env.category,
        "segments": [{"name": s.name, "vlan": s.vlan, "subnet": s.subnet,
                      "zone": s.zone, "gateway": s.gateway,
                      "gateway_mac": s.gateway_mac} for s in env.segments],
        "hosts": hosts(env),
        "flows": [{"client": c, "server": sv, "protocol": p,
                   "service": _service(p)} for c, sv, p in env.conversations],
    }
    if sprinkle:
        doc["new_assets"] = new_assets(env, sprinkle)
        doc["sprinkle"] = sprinkle_mapping(env, sprinkle)
    return doc


def write_csv(env: Environment, out: TextIO,
              sprinkle: Sequence[str] = ()) -> None:
    w = csv.DictWriter(out, fieldnames=COLUMNS, lineterminator="\n")
    w.writeheader()
    for row in hosts(env) + (new_assets(env, sprinkle) if sprinkle else []):
        row["legacy"] = "yes" if row["legacy"] else "no"
        row["serves"] = "; ".join(row["serves"])
        row["uses"] = "; ".join(row["uses"])
        w.writerow(row)


def write_json(env: Environment, out: TextIO,
               sprinkle: Sequence[str] = ()) -> None:
    json.dump(to_json(env, sprinkle), out, indent=2)
    out.write("\n")


def new_assets(env: Environment, sprinkle: Sequence[str]) -> List[Dict]:
    """Rows (``COLUMNS``) for the hosts the ``sprinkle`` incidents bring that
    have no compatible asset in ``env`` (see ``Incident.unmapped_hosts``): they
    keep their own addressing, so a sensor should report each as a new asset.
    ``segment`` is the env segment whose subnet holds the host's IP, if any;
    ``risk`` names the incidents that introduce it."""
    from . import incidents
    rows: Dict[tuple, Dict] = {}
    for key in sprinkle:
        inc = incidents.get(key)
        need = inc.served()
        for h in inc.unmapped_hosts(env):
            row = rows.get((h.name, h.ip))
            if row is None:
                seg = next((s for s in env.segments if s.contains(h.ip)), None)
                row = rows[(h.name, h.ip)] = {
                    "name": h.name, "ip": h.ip, "mac": h.mac,
                    "mac_vendor": OUI_VENDORS.get(h.mac[:8], ""),
                    "vendor": h.vendor, "product": h.product, "role": h.role,
                    "os": h.fp.label, "segment": seg.name if seg else "",
                    "vlan": seg.vlan if seg else "",
                    "subnet": seg.subnet if seg else "",
                    "zone": seg.zone if seg else "",
                    "gateway": seg.gateway if seg else "",
                    "legacy": h.fp.legacy, "risk": [], "serves": set(),
                    "uses": []}
            row["risk"].append(key)
            for svc in need.get(h.name, ()):
                try:
                    row["serves"].add(_service(svc))
                except KeyError:          # attack-only service (tristation, …)
                    row["serves"].add(svc)
    for row in rows.values():
        row["risk"] = f"new asset (sprinkle: {', '.join(row['risk'])})"
        row["serves"] = sorted(row["serves"])
    return list(rows.values())


def sprinkle_mapping(env: Environment, sprinkle: Sequence[str]) -> Dict:
    """Where each ``sprinkle`` incident lands on ``env``:
    {incident: {"mapped": {incident host: env host}, "new_assets": [host]}}."""
    from . import incidents
    out = {}
    for key in sprinkle:
        inc = incidents.get(key)
        out[key] = {
            "mapped": {k: v.name for k, v in sorted(inc.map_onto(env).items())},
            "new_assets": [h.name for h in inc.unmapped_hosts(env)]}
    return out
