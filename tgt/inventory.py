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
from typing import Dict, List, TextIO

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


def to_json(env: Environment) -> Dict:
    return {
        "env": env.key, "name": env.name, "category": env.category,
        "segments": [{"name": s.name, "vlan": s.vlan, "subnet": s.subnet,
                      "zone": s.zone, "gateway": s.gateway,
                      "gateway_mac": s.gateway_mac} for s in env.segments],
        "hosts": hosts(env),
        "flows": [{"client": c, "server": sv, "protocol": p,
                   "service": _service(p)} for c, sv, p in env.conversations],
    }


def write_csv(env: Environment, out: TextIO) -> None:
    w = csv.DictWriter(out, fieldnames=COLUMNS, lineterminator="\n")
    w.writeheader()
    for row in hosts(env):
        row["legacy"] = "yes" if row["legacy"] else "no"
        row["serves"] = "; ".join(row["serves"])
        row["uses"] = "; ".join(row["uses"])
        w.writerow(row)


def write_json(env: Environment, out: TextIO) -> None:
    json.dump(to_json(env), out, indent=2)
    out.write("\n")
