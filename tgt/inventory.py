"""Ground-truth asset inventory of a modeled environment.

What a sensor *should* discover when fed ``tgt run --env KEY``: every host with
its addressing, vendor/product, OS fingerprint, segment/VLAN/zone, risk notes,
and the services it serves and uses. Diff it against the analyser's asset list
(Claroty CTD, Nozomi, Zeek ``known_hosts``, …) to measure discovery coverage.

CSV holds one row per host; JSON adds the segments, the expected flows (the
communication baseline), per-field observability (can a passive monitor learn
this field from the traffic the host actually exchanges?), the external
endpoints the environment talks to, and network infrastructure that is on the
wire but is not an asset (HSRP gateway MACs).
"""
from __future__ import annotations

import csv
import ipaddress
import json
from typing import Dict, List, Sequence, Set, TextIO

from . import packet, protocols
from .enterprise import (CROWDSTRIKE_CLOUD_IPS, OUI_VENDORS, Environment,
                         Host)

COLUMNS = ["name", "ip", "mac", "mac_vendor", "vendor", "product", "role",
           "os", "segment", "vlan", "subnet", "zone", "gateway", "legacy",
           "risk", "serves", "uses",
           # appended (keep the original order for existing consumers)
           "asset_id", "model", "firmware", "serial", "purdue_level", "fqdn"]

# Which host fields a protocol carries, by the side that sends them. A field
# is observable iff some flow the host takes part in carries it today.
_FROM_SERVER = {
    "enip-id": ("vendor", "product", "model", "firmware", "serial", "os"),
    "s7-id": ("vendor", "product", "model", "firmware", "serial", "os"),
    "http": ("os",),             # Server: banner
    "https": ("fqdn",),          # the client's SNI names the server
    "ldap": ("fqdn",),           # rootDSE search names the DC
}
_FROM_CLIENT = {
    "http": ("os",),             # User-Agent
    "smb": ("os",),              # dialect set (SMBv1 = legacy Windows)
    "dhcp": ("os",),             # vendor class + option-55 fingerprint
}
OBSERVABLE_FIELDS = ("vendor", "product", "model", "firmware", "serial", "os",
                     "fqdn")


def _service(proto: str) -> str:
    """'modbus 502/tcp', or just 'arp' / 'icmp' for portless protocols."""
    p = protocols.get(proto)
    return proto if p.port == "-" else f"{proto} {p.port}/{p.transport}"


def _asset_id(env: Environment, h: Host) -> str:
    return f"{env.key}:{h.name}"


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
            "asset_id": _asset_id(env, h), "model": h.model,
            "firmware": h.firmware, "serial": h.serial,
            "purdue_level": env.purdue_level(h), "fqdn": h.fqdn,
        })
    return rows


def _evidence(env: Environment) -> Dict[str, Dict[str, Set[str]]]:
    """host -> field -> protocols (or "oui"/"ttl") that reveal it."""
    ev: Dict[str, Dict[str, Set[str]]] = {
        h.name: {f: set() for f in OBSERVABLE_FIELDS} for h in env.hosts}

    def emits(name: str, proto: str) -> None:
        ev[name]["vendor"].add("oui")          # every frame shows the MAC
        if protocols.get(proto).transport != "l2":
            ev[name]["os"].add("ttl")          # every IP packet shows the TTL

    for client, server, proto in env.conversations:
        emits(client, proto)
        emits(server, proto)                    # every builder has replies
        for f in _FROM_CLIENT.get(proto, ()):
            ev[client][f].add(proto)
        if server != client:
            for f in _FROM_SERVER.get(proto, ()):
                ev[server][f].add(proto)
    for h in env.edr_hosts():
        emits(h.name, "edr")
    return ev


def _observability(h: Host, row: Dict, ev: Dict[str, Set[str]]) -> Dict:
    dev = h.device
    values = {
        "vendor": row["vendor"] or (dev.vendor if dev else "") or
        row["mac_vendor"],
        "product": row["product"] or (dev.product if dev else ""),
        "model": h.model, "firmware": h.firmware, "serial": h.serial,
        "os": row["os"], "fqdn": h.fqdn,
    }
    # When the MAC OUI is the only vendor evidence on the wire, what a monitor
    # can observe is the NIC vendor (e.g. VMware for a Windows VM), not the
    # software vendor.
    if ev["vendor"] == {"oui"} and row["mac_vendor"]:
        values["vendor"] = row["mac_vendor"]
    out = {}
    for f in OBSERVABLE_FIELDS:
        seen = sorted(ev[f]) if values[f] else []
        out[f] = {"value": values[f], "observable": bool(seen),
                  "evidence": seen}
    return out


def external(env: Environment) -> List[Dict]:
    """Public (non-RFC1918) endpoints the environment's traffic reaches: the
    CrowdStrike cloud and anything else found on the wire. They are not
    assets — a monitor listing them as such scores a false positive."""
    plan: Dict[str, Dict] = {}
    for h, ip, fqdn, _ in env.edr_plan():
        e = plan.setdefault(ip, {"ip": ip, "fqdns": set(), "talkers": set(),
                                 "kind": "edr-cloud", "vendor": "CrowdStrike"})
        e["fqdns"].add(fqdn)
        e["talkers"].add(h.name)
    by_ip = {h.ip: h.name for h in env.hosts}
    for _, frame in env.build(1):
        ips = packet.frame_ips(frame)
        if not ips:
            continue
        for a, b in (ips, ips[::-1]):
            if a in by_ip or a in plan or not ipaddress.ip_address(a).is_global:
                continue
            plan[a] = {"ip": a, "fqdns": set(), "talkers": set(),
                       "kind": "unknown", "vendor": ""}
            if b in by_ip:
                plan[a]["talkers"].add(by_ip[b])
    order = {ip: i for i, ip in enumerate(CROWDSTRIKE_CLOUD_IPS)}
    return [{**e, "fqdns": sorted(e["fqdns"]), "talkers": sorted(e["talkers"])}
            for e in sorted(plan.values(),
                            key=lambda e: (order.get(e["ip"], len(order)),
                                           e["ip"]))]


def infrastructure(env: Environment) -> List[Dict]:
    """Network devices whose addresses appear on the wire but are not modeled
    hosts: each segment's HSRP virtual gateway (routed frames carry its MAC)."""
    return [{"kind": "hsrp-gateway", "segment": s.name, "vlan": s.vlan,
             "ip": s.gateway, "mac": s.gateway_mac,
             "mac_vendor": "Cisco (HSRP virtual MAC)"}
            for s in env.segments]


def _flow(c: str, sv: str, p: str) -> Dict:
    prof = protocols.get(p)
    return {"client": c, "server": sv, "protocol": p, "service": _service(p),
            "dport": int(prof.port) if prof.port.isdigit() else None,
            "transport": prof.transport}


def to_json(env: Environment, sprinkle: Sequence[str] = ()) -> Dict:
    rows = hosts(env)
    ev = _evidence(env)
    edr = {h.name for h in env.edr_hosts()}
    for h, row in zip(env.hosts, rows):
        dev = h.device
        row.update({
            "embedded": h.embedded, "edr": h.name in edr,
            "modules": [{"rack": m.rack, "slot": m.slot,
                         "catalog": m.catalog, "desc": m.desc}
                        for m in h.modules],
            "known_cves": list(dev.known_cves) if dev else [],
            "observability": _observability(h, row, ev[h.name]),
        })
    doc = {
        "env": env.key, "name": env.name, "category": env.category,
        "segments": [{"name": s.name, "vlan": s.vlan, "subnet": s.subnet,
                      "zone": s.zone, "gateway": s.gateway,
                      "gateway_mac": s.gateway_mac} for s in env.segments],
        "hosts": rows,
        "flows": [_flow(c, sv, p) for c, sv, p in env.conversations],
        "external": external(env),
        "infrastructure": infrastructure(env),
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
                    "asset_id": f"{env.key}:{h.name}", "name": h.name, "ip": h.ip, "mac": h.mac,
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
