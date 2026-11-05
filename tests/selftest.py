"""Dependency-free self-test — validates packet construction end to end.

Run on the target host to confirm TGT builds correct frames before you rely on
it:  ``python3 tests/selftest.py`` or ``python3 -m tests.selftest``
(exit 0 = all good).
"""
from __future__ import annotations

import os
import struct
import sys
import tempfile

# `python3 tests/selftest.py` from the repo root puts tests/ (not the repo) on
# sys.path; add the repo so `import tgt` works without PYTHONPATH.
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from tgt import packet as P  # noqa: E402
from tgt import protocols, scenarios
from tgt.config import RunConfig
from tgt.engine import build_batch
from tgt.packet import Endpoints
from tgt.pcap import PcapWriter

_failures: list[str] = []
_skipped: list[str] = []


def check(cond: bool, msg: str) -> None:
    if not cond:
        _failures.append(msg)


def verify_ip_l4(frame: bytes, label: str) -> None:
    """IP and TCP/UDP checksums must re-sum to zero when correct."""
    eth_type = struct.unpack("!H", frame[12:14])[0]
    off = 14
    if eth_type == P.ETH_P_VLAN:
        eth_type = struct.unpack("!H", frame[16:18])[0]
        off = 18
    if eth_type != P.ETH_P_IP:
        return
    ihl = (frame[off] & 0x0F) * 4
    ip_hdr = frame[off:off + ihl]
    check(P.checksum16(ip_hdr) == 0, f"{label}: IP checksum invalid")
    proto = frame[off + 9]
    src = frame[off + 12:off + 16]
    dst = frame[off + 16:off + 20]
    seg = frame[off + ihl:]
    if proto in (P.IPPROTO_TCP, P.IPPROTO_UDP):
        pseudo = src + dst + struct.pack("!BBH", 0, proto, len(seg))
        check(P.checksum16(pseudo + seg) == 0,
              f"{label}: L4 checksum invalid (proto {proto})")


def test_addressing() -> None:
    check(P.mac_to_bytes("aa:bb:cc:dd:ee:ff") == b"\xaa\xbb\xcc\xdd\xee\xff",
          "mac_to_bytes")
    check(P.ip_to_bytes("10.0.0.1") == b"\x0a\x00\x00\x01", "ip_to_bytes")
    check(P.checksum16(b"\x00\x00") == 0xFFFF, "checksum of zeros")


def test_all_profiles_build_and_checksum() -> None:
    ep = Endpoints()
    for prof in protocols.all_profiles():
        frames = prof.build(ep, 4)
        check(len(frames) > 0, f"{prof.key}: produced no frames")
        for f in frames:
            check(len(f) >= 14, f"{prof.key}: runt frame")
            verify_ip_l4(f, prof.key)


def test_tcp_session_sequences() -> None:
    ep = Endpoints()
    frames = protocols.modbus_flow(ep, 3)
    # first three frames must be SYN, SYN|ACK, ACK
    def flags(fr):
        ihl = (fr[14] & 0x0F) * 4
        return fr[14 + ihl + 13]
    check(flags(frames[0]) == P.SYN, "handshake SYN")
    check(flags(frames[1]) == (P.SYN | P.ACK), "handshake SYN|ACK")
    check(flags(frames[2]) == P.ACK, "handshake ACK")
    check(flags(frames[-1]) == P.ACK, "teardown final ACK")


def test_modbus_signature() -> None:
    ep = Endpoints()
    for f in protocols.modbus_flow(ep, 1):
        ihl = (f[14] & 0x0F) * 4
        if f[14 + 9] == P.IPPROTO_TCP:
            dport = struct.unpack("!H", f[14 + ihl + 2:14 + ihl + 4])[0]
            payload = f[14 + ihl + (f[14 + ihl + 12] >> 4) * 4:]
            if dport == 502 and len(payload) >= 8:
                tid, proto, length, unit, fc = struct.unpack("!HHHBB",
                                                             payload[:8])
                check(proto == 0, "modbus MBAP protocol id != 0")
                check(fc == 0x03, "modbus function code != 0x03")
                return
    _failures.append("modbus: no request-to-502 frame found")


def test_batch_interleave() -> None:
    cfg = RunConfig(profiles=["modbus", "s7comm"], messages=2)
    batch = build_batch(cfg)
    keys = {k for k, _ in batch}
    check(keys == {"modbus", "s7comm"}, "batch missing a profile")
    check(len(batch) > 0, "empty batch")


def test_scenarios_reference_real_profiles() -> None:
    for s in scenarios.all_scenarios():
        for key in s.profiles:
            check(key in protocols.PROFILES,
                  f"scenario {s.key} references unknown profile {key}")


def test_environments_build_and_checksum() -> None:
    from tgt import enterprise
    for env in enterprise.all_environments():
        batch = env.build(2)
        check(len(batch) > 0, f"env {env.key} produced no frames")
        for _, f in batch:
            verify_ip_l4(f, f"env:{env.key}")
        check(len(env.hosts) >= 10, f"env {env.key} has too few hosts")


def _vlan(frame: bytes) -> int | None:
    if struct.unpack("!H", frame[12:14])[0] != P.ETH_P_VLAN:
        return None
    return struct.unpack("!H", frame[14:16])[0] & 0x0FFF


def test_every_host_has_a_segment() -> None:
    from tgt import enterprise
    for env in enterprise.all_environments():
        check(len(env.segments) >= 2, f"env {env.key}: not segmented")
        for h in env.hosts:
            seg = env.segment_of(h)
            check(seg.contains(h.ip), f"{env.key}: {h.name} outside {seg.name}")
            check(h.ip != seg.gateway, f"{env.key}: {h.name} uses gateway IP")
        for _, f in env.build(1):
            check(_vlan(f) in {s.vlan for s in env.segments},
                  f"env {env.key}: frame without a segment VLAN tag")


def _one_flow(env_key: str, conv, span: str):
    from tgt import enterprise
    base = enterprise.get(env_key)
    env = enterprise.Environment("t", "t", base.category, "", base.hosts,
                                 [conv], base.segments)
    # the flow's own frames, without the start-of-cycle ARP
    return env, [f for k, f in env.build(1, span=span, edr=False) if k != "arp"]


def test_cross_subnet_uses_gateway_and_tags() -> None:
    env, frames = _one_flow("it-org", ("WS20", "DC01", "kerberos"), "access")
    ws, dc = env.host("WS20"), env.host("DC01")
    users, servers = env.segment_of(ws), env.segment_of(dc)
    check(users is not servers, "WS20 and DC01 should be on different segments")
    seen = set()
    for f in frames:
        src, dst = P.frame_ips(f)
        if src == ws.ip:
            seen.add("c2s")
            check(_vlan(f) == users.vlan, "client frame not on users VLAN")
            check(f[0:6] == P.mac_to_bytes(users.gateway_mac),
                  "client frame not addressed to its gateway")
            check(f[6:12] == P.mac_to_bytes(ws.mac), "client src MAC wrong")
        else:
            seen.add("s2c")
            check(_vlan(f) == servers.vlan, "server frame not on servers VLAN")
            check(f[0:6] == P.mac_to_bytes(servers.gateway_mac),
                  "server frame not addressed to its gateway")
    check(seen == {"c2s", "s2c"}, f"cross-subnet flow missing a direction: {seen}")


def test_same_subnet_is_switched() -> None:
    env, frames = _one_flow("ot-plant", ("HMI-RW", "PLC-RW1", "enip"), "access")
    hmi, plc = env.host("HMI-RW"), env.host("PLC-RW1")
    seg = env.segment_of(hmi)
    for f in frames:
        check(_vlan(f) == seg.vlan, "same-subnet frame on wrong VLAN")
        macs = {f[0:6], f[6:12]}
        check(macs == {P.mac_to_bytes(hmi.mac), P.mac_to_bytes(plc.mac)},
              "same-subnet frame not addressed peer-to-peer")


def test_span_core_adds_routed_hop() -> None:
    conv = ("WS20", "DC01", "kerberos")
    env, access = _one_flow("it-org", conv, "access")
    _, core = _one_flow("it-org", conv, "core")
    check(len(core) == 2 * len(access), "core view should double routed frames")
    ws, dc = env.host("WS20"), env.host("DC01")
    users, servers = env.segment_of(ws), env.segment_of(dc)
    for ingress, egress in zip(core[0::2], core[1::2]):
        verify_ip_l4(egress, "span-core")
        check(P.frame_ips(ingress) == P.frame_ips(egress),
              "routed hop changed the IP addresses")
        check(egress[18 + 8] == ingress[18 + 8] - 1, "routed hop TTL not -1")
        check(egress[18 + 20:] == ingress[18 + 20:], "routed hop changed L4")
        if P.frame_ips(ingress)[0] == ws.ip:
            check(_vlan(egress) == servers.vlan, "egress not on servers VLAN")
            check(egress[6:12] == P.mac_to_bytes(servers.gateway_mac)
                  and egress[0:6] == P.mac_to_bytes(dc.mac),
                  "egress not gateway -> server")
        else:
            check(_vlan(egress) == users.vlan, "egress not on users VLAN")
            check(egress[6:12] == P.mac_to_bytes(users.gateway_mac)
                  and egress[0:6] == P.mac_to_bytes(ws.mac),
                  "egress not gateway -> client")
    # same-subnet traffic is not routed, so core adds nothing
    _, a = _one_flow("ot-plant", ("HMI-RW", "PLC-RW1", "enip"), "access")
    _, c = _one_flow("ot-plant", ("HMI-RW", "PLC-RW1", "enip"), "core")
    check([f[:18] for f in a] == [f[:18] for f in c],   # ports/seqs are random
          "core view duplicated switched (same-subnet) traffic")


def test_industrial_site_is_a_full_purdue_plant() -> None:
    from tgt import enterprise
    site = enterprise.get("industrial-site")
    check(len(site.hosts) >= 90, f"industrial-site has only {len(site.hosts)} hosts")
    zones = {s.zone for s in site.segments}
    check(zones == {"IT", "DMZ", "OT-SUPERVISORY", "OT-CELL"},
          f"industrial-site zones incomplete: {zones}")
    protos = {p for _, _, p in site.conversations}
    for need in ("enip", "enip-id", "s7comm", "s7-id", "modbus", "dnp3",
                 "iec104", "bacnet", "opcua"):
        check(need in protos, f"industrial-site never speaks {need}")
    vendors = {h.vendor for h in site.hosts if h.vendor}
    check(len(vendors) >= 5, f"industrial-site has few OT vendors: {vendors}")
    blob = b"".join(f for _, f in site.build(1))
    check(b"PowerFlex 755" in blob, "industrial-site: no drive identity")
    check(b"6ES7 516" in blob, "industrial-site: no S7-1500 order number")
    # IT and OT meet only in the DMZ ... except the one planted violation
    zone = {h.name: site.segment_of(h).zone for h in site.hosts}
    bypass = [(c, sv) for c, sv, _ in site.conversations
              if {zone[c], zone[sv]} & {"IT"} and
              {zone[c], zone[sv]} & {"OT-SUPERVISORY", "OT-CELL"}]
    check(bypass == [("WS-CONTRACTOR", "METER-UT1")],
          f"unexpected IT<->OT flows bypassing the DMZ: {bypass}")


def test_l2_protocols_cannot_cross_segments() -> None:
    from tgt import enterprise
    it = enterprise.get("it-org")
    try:
        enterprise.Environment("t", "t", "IT", "", it.hosts,
                               [("WS20", "DC01", "arp")], it.segments)
    except ValueError:
        return
    _failures.append("ARP between segments was accepted")


def test_inventory_export() -> None:
    import contextlib
    import csv
    import io
    import json
    import os
    from tgt import cli, enterprise, inventory
    for env in enterprise.all_environments():
        buf = io.StringIO()
        inventory.write_csv(env, buf)
        rows = list(csv.DictReader(io.StringIO(buf.getvalue())))
        check(len(rows) == len(env.hosts), f"inventory {env.key}: row count")
        check(all(r["segment"] and r["vlan"] and r["zone"] for r in rows),
              f"inventory {env.key}: host without segment/VLAN/zone")
        doc = json.loads(json.dumps(inventory.to_json(env)))
        check(len(doc["flows"]) == len(env.conversations),
              f"inventory {env.key}: flow count")
        check(not any(s.startswith("arp") for h in doc["hosts"]
                      for s in h["serves"]), f"inventory {env.key}: ARP as service")
    site = {h["name"]: h for h in inventory.hosts(enterprise.get("industrial-site"))}
    check("enip 44818/tcp" in site["PLC-PK1"]["serves"], "PLC-PK1 not serving ENIP")
    check(site["PLC-PK1"]["mac_vendor"] == "Rockwell Automation",
          "PLC-PK1 MAC vendor wrong")
    check("modbus" in site["WS-CONTRACTOR"]["uses"],
          "contractor laptop's Modbus use missing")
    check(site["OT-DC01"]["legacy"], "Server 2012 R2 DC not flagged legacy")
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "inv.json")
        with contextlib.redirect_stderr(io.StringIO()):
            rc = cli.main(["inventory", "-e", "ot-plant", "-f", "json",
                           "-o", out])
        check(rc == 0 and json.load(open(out))["env"] == "ot-plant",
              "tgt inventory CLI did not write JSON")


# tshark protocol layer each builder must produce (frame.protocols names)
_DISSECTS_AS = {
    "modbus": "mbtcp", "dnp3": "dnp3", "enip": "cip", "s7comm": "s7comm",
    "iec104": "iec60870_asdu", "bacnet": "bacapp", "opcua": "opcua",
    "enip-id": "enip", "s7-id": "s7comm", "arp": "arp", "icmp": "icmp",
    "dns": "dns", "http": "http", "https": "tls", "edr": "tls", "smb": "smb2",
    "kerberos": "kerberos", "ldap": "ldap", "dhcp": "dhcp", "netbios": "nbns",
    "ntp": "ntp",
    # industrial L2 / substation (tgt/protocols_ind.py)
    "pn-dcp": "pn_dcp", "pn-dcp-set": "pn_dcp", "pn-rt": "pn_io",
    "goose": "goose", "sv": "sv", "mms": "mms", "ptp": "ptp", "ptp-l2": "ptp",
}


def test_tshark_dissects_every_builder() -> None:
    """Optional: with tshark on PATH, every builder (plus the SMB1 dialect and
    a full industrial-site cycle) must decode as its protocol with no
    malformed-packet or other expert warnings."""
    import shutil
    import subprocess
    from tgt import enterprise
    if not shutil.which("tshark"):
        _skipped.append("test_tshark_dissects_every_builder")
        return
    # plugin protocols (tgt.plugins) declare their own tshark layer
    from tgt import plugins
    check(set(_DISSECTS_AS) | set(plugins.DISSECTORS)
          == set(protocols.PROFILES),
          "_DISSECTS_AS out of sync with the protocol registry")
    dissects = dict(_DISSECTS_AS)
    dissects.update({k: v for k, v in plugins.DISSECTORS.items() if v})
    groups = {k: protocols.get(k).build(Endpoints(), 3) for k in dissects}
    groups["smb1"] = protocols.smb_flow(Endpoints(meta={"smb": "smb1"}), 3)
    site = [f for _, f in enterprise.get("industrial-site").build(2)]
    # the site cycle gets its own capture: its ARP would otherwise flag the
    # default Endpoints() addresses as duplicates of real site hosts
    layers, expert = [], ""
    with tempfile.TemporaryDirectory() as d:
        for name, chunk in (("all", list(groups.values())), ("site", [site])):
            path = f"{d}/{name}.pcap"
            with PcapWriter(path) as w:
                for frames in chunk:
                    for f in frames:
                        w.write(f)
            layers += subprocess.run(
                ["tshark", "-r", path, "-T", "fields", "-e", "frame.protocols"],
                capture_output=True, text=True).stdout.splitlines()
            expert += subprocess.run(
                ["tshark", "-r", path, "-q", "-z", "expert,warn"],
                capture_output=True, text=True).stdout
    seen = {x for line in layers for x in line.split(":")}
    for key, layer in list(dissects.items()) + [("smb1", "smb")]:
        check(layer in seen, f"tshark: {key} never dissected as {layer}")
    # deliberate RST closes (aborted browser sessions) are the only
    # warnings allowed
    warns = [ln for ln in expert.splitlines()
             if ln.strip() and ln.strip()[0].isdigit()
             and "Connection reset (RST)" not in ln]
    if "Errors (" in expert or warns:
        detail = [ln.strip() for ln in expert.splitlines()
                  if "Malformed" in ln or "Warning" in ln or "incorrect" in ln]
        real = [ln for ln in detail if not _tshark_dissector_bug(ln)]
        if real or not detail:
            _failures.append("tshark expert warnings: " + "; ".join(
                (real or detail)[:5]))


def _tshark_version() -> tuple:
    import re
    import subprocess
    out = subprocess.run(["tshark", "--version"], capture_output=True,
                         text=True).stdout
    m = re.search(r"TShark \(Wireshark\) (\d+)\.(\d+)", out)
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def _tshark_dissector_bug(line: str) -> bool:
    """Wireshark < 4.4's BER-based GOOSE/MMS dissectors trip an internal
    ``failed assertion "recursion_depth <= 100"`` on valid frames (fixed in
    later releases; 4.6 decodes the same bytes cleanly). That is a dissector
    bug, not a malformed frame, so it is not held against the builder."""
    return ("failed assertion" in line and "recursion_depth" in line
            and _tshark_version() < (4, 4))


def test_tshark_incidents_not_malformed() -> None:
    """Optional: with tshark on PATH, no incident's synthetic signature traffic
    dissects as a malformed packet (guards the attack-builder framing)."""
    import shutil
    import subprocess
    from tgt import incidents
    if not shutil.which("tshark"):
        _skipped.append("test_tshark_incidents_not_malformed")
        return
    with tempfile.TemporaryDirectory() as d:
        bad = []
        for key in incidents.INCIDENTS:
            path = f"{d}/{key}.pcap"
            with PcapWriter(path) as w:
                for _, f in incidents.get(key).build(3):
                    w.write(f)
            expert = subprocess.run(
                ["tshark", "-r", path, "-q", "-z", "expert,warn"],
                capture_output=True, text=True).stdout
            if "Malformed" in expert or "ERR" in expert:
                bad.append(key)
        check(not bad, f"incidents dissect as malformed: {', '.join(bad)}")


def test_sprinkle_maps_incident_hosts_onto_env_by_role() -> None:
    from tgt import enterprise, incidents

    env = enterprise.get("it-org")
    env_ips = {h.ip for h in env.hosts}

    inc = incidents.get("wannacry")
    mapping = inc.map_onto(env)
    # patient zero (Win7 ws) must land on a real legacy Win7 workstation
    p0 = mapping["WANNACRY-PATIENT0"]
    check(p0 in env.hosts and p0.os == "win7" and p0.role == "ws",
          f"wannacry patient-zero not mapped to a Win7 workstation: {p0.name}")
    check(len({h.name for h in mapping.values()}) == len(mapping),
          "wannacry mapping reused one env host for several incident hosts")

    # every sprinkled frame's IPs are real inventory hosts or kept-external ones
    ext_ips = {h.ip for h in inc.hosts if incidents._is_external(h)}
    for _, f in inc.build_on(2, env):
        ips = P.frame_ips(f)
        if ips:
            for ip in ips:
                check(ip in env_ips or ip in ext_ips,
                      f"wannacry sprinkle has phantom host {ip}")
        check(_vlan(f) in {s.vlan for s in env.segments},
              "wannacry sprinkle frame not tagged on an env VLAN")

    # external C2 / public attackers are never remapped
    for key in ("sunburst", "log4shell", "mirai"):
        ic = incidents.get(key)
        m = ic.map_onto(env if key != "mirai"
                        else enterprise.get("enterprise-mixed"))
        for h in ic.hosts:
            if incidents._is_external(h):
                check(h.name not in m, f"{key}: external {h.name} was remapped")

    # vendor-aware: embedded devices only land on the same vendor's devices,
    # an exact role beats its family, and a family fills in when it's missing
    site, plant = enterprise.get("industrial-site"), enterprise.get("ot-plant")
    for e in enterprise.all_environments():
        for ic in incidents.all_incidents():
            for name, tgt in ic.map_onto(e).items():
                v = incidents._device_vendor(ic.host(name))
                check(v is None or incidents._device_vendor(tgt) == v,
                      f"{ic.key}->{e.key}: {name} mapped across vendors "
                      f"onto {tgt.name}")
    check(incidents.get("industroyer").map_onto(site)["RTU-104"].name ==
          "RTU-104", "industroyer RTU not mapped onto the site's IEC-104 RTU")
    # no environment has a Triconex SIS: never a Modicon stand-in
    for e in (site, plant):
        tri = incidents.get("triton")
        check("SIS-TRICONEX" not in tri.map_onto(e) and "SIS-TRICONEX" in
              {h.name for h in tri.unmapped_hosts(e)},
              f"triton SIS not reported as a new asset on {e.key}")
    # ot-plant has no IEC-104 RTU: an S7-315 is no substitute
    ind = incidents.get("industroyer")
    check("RTU-104" not in ind.map_onto(plant) and
          [h.name for h in ind.unmapped_hosts(plant)] == ["RTU-104"],
          "industroyer RTU-104 landed on a non-IEC-104 device in ot-plant")

    # whole sprinkle path still hits its target ratio with the env base
    cfg = RunConfig(env="it-org", sprinkle=["wannacry"], messages=2,
                    sprinkle_ratio=0.2)
    batch = build_batch(cfg)
    atk = {"eternalblue", "port-scan", "dga-dns"}
    got = sum(1 for k, _ in batch if k in atk) / len(batch)
    check(abs(got - 0.2) < 0.08, f"env sprinkle ratio off: {got:.2f}")
    for _, f in batch:
        verify_ip_l4(f, "env-sprinkle")


def test_preset_protocols_match_generated_traffic() -> None:
    """Each preset's advertised protocol list is exactly what it generates,
    and selecting a preset in the TUI puts those protocols on the Traffic
    tab."""
    from tgt import enterprise, incidents, tui

    amap = incidents.ATTACK_PROTOCOLS
    check(set(amap) == set(incidents.ATTACKS),
          "ATTACK_PROTOCOLS must cover every attack exactly")
    for atk, proto in amap.items():
        check(proto is None or proto in protocols.PROFILES,
              f"attack {atk} maps to unknown protocol {proto}")

    for env in enterprise.all_environments():
        made = {k for k, _ in env.build(1)}
        check(set(env.protocols()) == made,
              f"env {env.key}: protocols() {sorted(env.protocols())} != "
              f"generated {sorted(made)}")
    for inc in incidents.all_incidents():
        made = {k for k, _ in inc.build(1)}
        check(set(inc.protocols()) == {amap[k] for k in made} - {None},
              f"incident {inc.key}: protocols() disagree with its traffic")
        check(set(inc.attack_only()) == {k for k in made if amap[k] is None},
              f"incident {inc.key}: attack_only() disagrees with its traffic")
    for sc in scenarios.all_scenarios():
        made = {k for k, _ in build_batch(RunConfig(profiles=sc.profiles,
                                                    messages=1))}
        check(made == set(sc.profiles),
              f"scenario {sc.key}: generates {sorted(made)}")

    ui = tui.UI()
    ui.engine = None
    for _group, choice, _label, _desc in tui._preset_items(ui):
        kind, key = choice
        if kind not in ("s", "e", "i"):
            continue
        tui._apply_preset(None, ui, choice)
        want = {"s": lambda k: list(scenarios.get(k).profiles),
                "e": lambda k: enterprise.get(k).protocols(),
                "i": lambda k: incidents.get(k).protocols()}[kind](key)
        check(ui.selected == want == ui.preset_protocols(),
              f"tui: preset {key} selected {ui.selected}, want {want}")
    # picking custom after a preset starts from that preset's protocols, and
    # toggling one on the Traffic tab switches to a custom mix without it
    tui._apply_preset(None, ui, ("e", "ot-plant"))
    plant = enterprise.get("ot-plant").protocols()
    tui._apply_preset(None, ui, ("c", None))
    check(ui.mode() == "custom" and ui.selected == plant,
          "tui: custom after env lost the env's protocols")
    tui._apply_preset(None, ui, ("e", "ot-plant"))
    ui.toggle_proto("modbus")
    check(ui.mode() == "custom" and "modbus" not in ui.selected
          and len(ui.selected) == len(plant) - 1,
          "tui: toggling a protocol under a preset did not start a custom mix")


def test_net_interface_kinds() -> None:
    """veth detection from sysfs: a veth's iflink is its peer's ifindex and
    the peer points back; a VLAN's iflink is its parent, which does not."""
    import os
    from tgt import net

    def mk(base, name, ifindex, iflink, device=False, devtype=""):
        d = os.path.join(base, name)
        os.makedirs(d)
        for attr, val in (("ifindex", ifindex), ("iflink", iflink),
                          ("operstate", "up"), ("address", "02:00:00:00:00:01"),
                          ("mtu", "1500"),
                          ("uevent", f"INTERFACE={name}\n" +
                           (f"DEVTYPE={devtype}\n" if devtype else ""))):
            with open(os.path.join(d, attr), "w") as fh:
                fh.write(val + "\n")
        if device:
            os.makedirs(os.path.join(d, "device"))

    with tempfile.TemporaryDirectory() as base:
        mk(base, "tgt0", "10", "11")
        mk(base, "tgt0-mon", "11", "10")
        mk(base, "eth0", "2", "2", device=True)
        mk(base, "eth0.10", "12", "2", devtype="vlan")
        mk(base, "vethc", "13", "99")                 # peer in another netns
        mk(base, "br0", "14", "14", devtype="bridge")
        got = {i["name"]: (i["kind"], i["peer"])
               for i in net.list_interfaces(base)}
    want = {"tgt0": ("veth", "tgt0-mon"), "tgt0-mon": ("veth", "tgt0"),
            "eth0": ("nic", None), "eth0.10": ("nic", None),
            "vethc": ("veth", None), "br0": ("nic", None)}
    for name, kind in want.items():
        check(got.get(name) == kind,
              f"net: {name} classified {got.get(name)}, want {kind}")


def test_tui_panel_model() -> None:
    """The TUI's data-driven rows, without a terminal: every visible row has
    help, ←/→ never prompts or raises, and config/service args follow the
    selected mode."""
    from tgt import tui
    ui = tui.UI()
    ui.engine = None
    for preset in (("c", None), ("s", "ot-baseline"), ("e", "industrial-site"),
                   ("i", "stuxnet")):
        tui._apply_preset(None, ui, preset)
        for sprinkle in (False, True):
            ui.sprinkle_on = sprinkle
            for focus in range(len(tui.PANELS)):
                ui.focus = focus
                for f in tui._fields(ui):
                    check(bool(f.help(ui)),
                          f"tui: {tui.PANELS[focus]}/{f.label} has no help")
                    f.value(ui)
                    if f.act and f.label not in (
                            "Create veth pair", "Delete veth pair",
                            "Save config", "Start service", "Stop service",
                            "Restart service", "Sensor label", "PCAP output",
                            "Client IP", "Server IP"):
                        for step in (1, -1):
                            f.act(None, ui, step)   # stdscr=None: no prompts
                            tui._apply_preset(None, ui, preset)
                            ui.sprinkle_on = sprinkle
    ui.focus = 0
    tui._apply_preset(None, ui, ("e", "industrial-site"))
    labels = [f.label for f in tui._fields(ui)]
    check("SPAN view" in labels and "Client IP" not in labels,
          "tui: env preset shows the wrong Run rows")
    ui.span = "core"
    check(ui.build_config().span == "core" and "--span core" in ui.run_args(),
          "tui: SPAN view not carried into config / service args")
    tui._apply_preset(None, ui, ("c", None))
    labels = [f.label for f in tui._fields(ui)]
    check("SPAN view" not in labels and "Client IP" in labels,
          "tui: custom preset shows the wrong Run rows")

    # Interfaces: a veth shows its peer + delete; a real NIC hides both
    ui.focus = tui.PANELS.index("Interfaces")
    ui.ifaces = {
        "eth0": {"name": "eth0", "state": "up", "kind": "nic", "peer": None},
        "tgt0": {"name": "tgt0", "state": "up", "kind": "veth",
                 "peer": "tgt0-mon"},
        "tgt0-mon": {"name": "tgt0-mon", "state": "up", "kind": "veth",
                     "peer": "tgt0"}}
    ui.send_iface = "eth0"
    labels = [f.label for f in tui._fields(ui)]
    check(ui.link_kind() == "nic" and "Monitor (peer)" not in labels
          and "Delete veth pair" not in labels,
          "tui: real interface shows veth rows / delete")
    ui.send_iface = "tgt0"
    labels = [f.label for f in tui._fields(ui)]
    check(ui.link_kind() == "veth" and ui.mon_iface == "tgt0-mon"
          and "Monitor (peer)" in labels and "Delete veth pair" in labels,
          "tui: veth hides its peer / delete rows")
    ui.send_iface, ui.pcap = None, "x.pcap"
    check(ui.link_kind() == "pcap", "tui: pcap-only not detected")


def test_it_org_has_servers_and_users() -> None:
    from tgt import enterprise
    it = enterprise.get("it-org")
    servers = [h for h in it.hosts if h.role in
               ("dc", "dns", "file", "db", "web", "mail", "proxy")]
    users = [h for h in it.hosts if h.role == "ws"]
    check(len(servers) >= 10, f"it-org has only {len(servers)} servers (need 10+)")
    check(len(users) >= 12, f"it-org has only {len(users)} users (need 12+)")
    roles = {h.role for h in it.hosts}
    for need in ("dc", "dns", "file"):
        check(need in roles, f"it-org missing role {need}")


def test_legacy_fingerprints_on_the_wire() -> None:
    from tgt import enterprise
    env = enterprise.get("enterprise-mixed")
    blob = b"".join(f for _, f in env.build(2))
    check(b"NT LM 0.12" in blob, "no SMBv1 dialect (legacy Windows) present")
    check(b"MSIE 6.0" in blob or b"Windows NT 5.1" in blob,
          "no Windows XP User-Agent present")
    check(b"6ES7" in blob, "no Siemens order number present")
    check(b"LOGIX" in blob, "no Rockwell product string present")
    check(len(env.legacy_hosts()) >= 5, "too few legacy/at-risk hosts modeled")


def test_incidents_build_and_checksum() -> None:
    from tgt import incidents
    for inc in incidents.all_incidents():
        batch = inc.build(2)
        check(len(batch) > 0, f"incident {inc.key} produced no frames")
        for _, f in batch:
            verify_ip_l4(f, f"incident:{inc.key}")
        check(inc.category in ("IT", "OT"), f"{inc.key} bad category")


def test_incident_signatures_present() -> None:
    from tgt import incidents

    def blob(k):
        return b"".join(f for _, f in incidents.get(k).build(2))

    check(b"NT LM 0.12" in blob("wannacry"), "wannacry: no SMBv1 signature")
    check(b"iuqerfsodp9ifjaposdfjhgosurijfae" in blob("wannacry"),
          "wannacry: no kill-switch domain")
    check(b"avsvmcloud.com" in blob("sunburst"), "sunburst: no DGA domain")
    check(b"jndi:ldap" in blob("log4shell"), "log4shell: no JNDI string")
    check(b"TRISTATION" in blob("triton"), "triton: no TriStation payload")
    check(b"P_PROGRAM" in blob("stuxnet"), "stuxnet: no S7 PLC STOP (P_PROGRAM)")
    check(b"NT LM 0.12" in blob("notpetya"), "notpetya: no SMBv1 signature")
    check(b"mstshash=" in blob("colonial"), "colonial: no RDP mstshash cookie")
    check(b"cdn.darkside-c2.example" in blob("colonial"),
          "colonial: no TLS C2 SNI")
    check(b"emotet-c2" in blob("emotet"),   # DNS labels are length-prefixed
          "emotet: no DNS-tunnel C2 domain")
    check(b"\xde\xad" in blob("pipedream"),
          "pipedream: no Modbus Write Multiple Registers payload")
    utf16_admin = "ADMIN$".encode("utf-16-le")
    check(utf16_admin in blob("ekans") or utf16_admin in blob("colonial"),
          "no SMB admin-share (ADMIN$) lateral-movement signature")


def test_sprinkle_mixes_malware_into_base() -> None:
    # a normal IT organization base with wannacry sprinkled on top
    cfg = RunConfig(env="it-org", sprinkle=["wannacry"], messages=2,
                    sprinkle_messages=2)
    batch = build_batch(cfg)
    labels = {k for k, _ in batch}
    check("smb" in labels or "dns" in labels, "sprinkle: base traffic missing")
    check("eternalblue" in labels, "sprinkle: malware traffic missing")
    mal = sum(1 for k, _ in batch if k in
              ("eternalblue", "port-scan", "dga-dns"))
    check(mal < len(batch) / 2, "sprinkle: malware not a minority of a real base")
    for _, f in batch:
        verify_ip_l4(f, "sprinkle")


def test_sprinkle_ratio_hits_target_on_tiny_base() -> None:
    atk = {"eternalblue", "port-scan", "dga-dns"}
    for r in (0.1, 0.25):
        cfg = RunConfig(profiles=["http", "dns"], sprinkle=["wannacry"],
                        messages=3, sprinkle_ratio=r)
        batch = build_batch(cfg)
        got = sum(1 for k, _ in batch if k in atk) / len(batch)
        check(abs(got - r) < 0.08, f"ratio {r}: got {got:.2f} (base grew to hit it)")


def test_sprinkle_random_picks_varied_incidents() -> None:
    seen = set()
    atk = {"eternalblue", "telnet-brute", "s7-control", "iec104-command",
           "tristation", "log4shell", "c2-beacon", "dga-dns", "port-scan"}
    for _ in range(20):
        batch = build_batch(RunConfig(env="it-org", sprinkle_random=True,
                                      messages=1))
        seen |= {k for k, _ in batch} & atk
    check(len(seen) >= 3, f"random sprinkle not varied enough: {seen}")


def test_crowdstrike_edr_on_windows_and_linux_hosts() -> None:
    from tgt import enterprise
    pool = set(enterprise.CROWDSTRIKE_CLOUD_IPS)
    for env in enterprise.all_environments():
        covered = {h.name for h in env.edr_hosts()}
        # Falcon-supported Windows + Linux are covered; EOL XP/2000 and embedded
        # OT devices (by vendor MAC OUI) are not.
        for h in env.hosts:
            want = (h.os in enterprise.EDR_OS
                    and h.mac[:8].lower() not in enterprise._EMBEDDED_OUIS)
            check((h.name in covered) == want,
                  f"{env.key}: {h.name} ({h.os}) EDR coverage wrong")
        if not covered:
            continue
        check("edr" in env.protocols(), f"{env.key}: edr not advertised")
        labels = {k for k, _ in env.build(1)}
        check("edr" in labels, f"{env.key}: no EDR frames on the wire")
        dst = set()
        for k, f in env.build(1):
            if k != "edr":
                continue
            # EDR egresses via the gateway on the host's own VLAN (never left raw)
            check(_vlan(f) in {s.vlan for s in env.segments},
                  f"{env.key}: EDR frame not tagged on an env VLAN")
            dst.update(P.frame_ips(f) or ())
        cloud = dst & pool
        check(cloud, f"{env.key}: EDR traffic never reached a CrowdStrike cloud IP")
        blob = b"".join(f for k, f in env.build(1) if k == "edr")
        check(b"cloudsink.net" in blob,
              f"{env.key}: EDR traffic missing the CrowdStrike cloud SNI")


def test_sprinkle_rides_inventory_without_an_env() -> None:
    # a scenario/protocol base has no hosts, so the sprinkle is re-addressed
    # onto the default full-Purdue plant rather than the incident's own IPs
    from tgt import enterprise, incidents
    site = enterprise.get("industrial-site")
    site_ips = {h.ip for h in site.hosts}
    inc = incidents.get("stuxnet")
    own_internal = {h.ip for h in inc.hosts if not incidents._is_external(h)}
    cfg = RunConfig(profiles=["modbus", "s7comm"], sprinkle=["stuxnet"],
                    messages=2, sprinkle_messages=2)
    atk = set(incidents.ATTACKS)
    hit = False
    for k, f in build_batch(cfg):
        if k not in atk:
            continue
        for ip in P.frame_ips(f) or ():
            check(ip not in own_internal,
                  f"sprinkle still uses the incident's own IP {ip}")
            if ip in site_ips:
                hit = True
    check(hit, "sprinkle without an env did not land on the default inventory")


def test_map_onto_descends_the_purdue_model() -> None:
    from tgt import enterprise, incidents
    site = enterprise.get("industrial-site")
    # a two-PLC attack keeps its field devices together in one cell
    # a two-PLC attack keeps its field devices together in one cell
    two = incidents.Incident(
        "two-plc", "t", "OT", "-", "-",
        [incidents._h("ENG", "172.16.0.9", "eng", "win7"),
         incidents._h("MB-A", "172.16.1.8", "plc", "schneider",
                      incidents.OUI_SCHNEIDER),
         incidents._h("MB-B", "172.16.1.9", "plc", "schneider",
                      incidents.OUI_SCHNEIDER)],
        [("ENG", "MB-A", "modbus-write", {}),
         ("ENG", "MB-B", "modbus-write", {})]).map_onto(site)
    segs = {site.segment_of(two[n]).name for n in ("MB-A", "MB-B")}
    check(len(segs) == 1, f"two-PLC attack scattered across cells: {segs}")
    # and the engineering stage stays up in supervisory, the PLCs down in a cell
    st = incidents.get("stuxnet").map_onto(site)
    pd = incidents.get("pipedream").map_onto(site)
    check(site.segment_of(pd["PIPEDREAM-ENGWS"]).zone == "OT-SUPERVISORY" and
          site.segment_of(pd["PLC-MODICON"]).zone == "OT-CELL" and
          site.segment_of(st["STEP7-ENGWS"]).zone == "OT-SUPERVISORY" and
          site.segment_of(st["PLC-S7-417"]).zone == "OT-CELL",
          "pipedream/stuxnet did not descend supervisory -> cell")


def test_sprinkle_servers_serve_their_protocol() -> None:
    """Every incident host an attack connects to lands on an inventory host
    that serves that protocol in the env (OT control protocols: observed in
    the env's own flows; SMB/RDP: a Windows host; Telnet: not Windows), or is
    reported by unmapped_hosts() as an expected new asset."""
    import csv
    import io
    from tgt import enterprise, incidents, inventory
    svc_of = {"eternalblue": "smb", "smb-lateral": "smb", "rdp-brute": "rdp",
              "telnet-brute": "telnet", "s7-control": "s7comm",
              "iec104-command": "iec104", "tristation": "tristation",
              "modbus-write": "modbus"}
    alias = {"s7-id": "s7comm", "enip-id": "enip"}
    for env in enterprise.all_environments():
        serves = {r["name"]: {alias.get(s.split()[0], s.split()[0])
                              for s in r["serves"]}
                  for r in inventory.hosts(env)}
        env_ips = {h.ip for h in env.hosts}
        for inc in incidents.all_incidents():
            m = inc.map_onto(env)
            new = {h.name for h in inc.unmapped_hosts(env)}
            internal = {h.name for h in inc.hosts
                        if not incidents._is_external(h)}
            check(new == internal - set(m),
                  f"{inc.key}->{env.key}: unmapped_hosts {sorted(new)} != "
                  f"internal hosts left unmapped")
            for _, vname, atk, _ in inc.flows:
                svc = svc_of.get(atk)
                if svc is None or vname not in internal:
                    continue
                t = m.get(vname)
                if t is None:
                    check(vname in new, f"{inc.key}->{env.key}: {vname} "
                          "neither mapped nor reported as a new asset")
                elif svc == "smb" or svc == "rdp":
                    check(t.os.startswith("win"), f"{inc.key}->{env.key}: "
                          f"{vname} ({svc}) on non-Windows {t.name}")
                elif svc == "telnet":
                    check(not t.os.startswith("win"), f"{inc.key}->{env.key}:"
                          f" {vname} (telnet) on Windows {t.name}")
                else:
                    check(svc in serves[t.name], f"{inc.key}->{env.key}: "
                          f"{vname} ({svc}) on {t.name}, which does not "
                          f"serve it ({sorted(serves[t.name])})")
            # the wire only carries inventory, new-asset or external hosts
            ok = env_ips | {h.ip for h in inc.hosts
                            if h.name in new or incidents._is_external(h)}
            for _, f in inc.build_on(1, env):
                for ip in P.frame_ips(f) or ():
                    check(ip in ok, f"{inc.key}->{env.key}: unreported "
                          f"host {ip} on the wire")

    site, plant = enterprise.get("industrial-site"), enterprise.get("ot-plant")
    mixed, it = enterprise.get("enterprise-mixed"), enterprise.get("it-org")
    # TriStation never lands on a Modicon; Triconex is a new asset everywhere
    for env in enterprise.all_environments():
        check("SIS-TRICONEX" in {h.name for h in
                                 incidents.get("triton").unmapped_hosts(env)},
              f"triton SIS not a new asset on {env.key}")
    # PIPEDREAM: Modicon M580 onto the M580, Omron is no Modicon
    pd = incidents.get("pipedream")
    check(pd.map_onto(site)["PLC-MODICON"].product.startswith("BME P58"),
          "pipedream M580 not mapped onto the site's M580")
    check("PLC-OMRON" in {h.name for h in pd.unmapped_hosts(site)},
          "pipedream Omron PLC landed on a Schneider Modicon")
    # IEC-104 RTU never on an S7-315 (ot-plant / enterprise-mixed)
    for env in (plant, mixed):
        for key in ("industroyer", "blackenergy"):
            r = incidents.get(key).map_onto(env).get("RTU-104")
            check(r is None or "iec104" in serves_of(env, r.name),
                  f"{key}->{env.key}: RTU-104 on {r and r.name}")
    check(incidents.get("industroyer").map_onto(site)["RTU-104"].product
          .startswith("SICAM"), "industroyer RTU not on the site's SICAM RTU")
    # it-org has no plant: OT incident hosts are all reported new assets
    for inc in incidents.all_incidents():
        if inc.category == "OT" and inc.key != "vpnfilter":
            check(not inc.map_onto(it), f"{inc.key}->it-org: OT host mapped")
            check(len(inc.unmapped_hosts(it)) ==
                  sum(not incidents._is_external(h) for h in inc.hosts),
                  f"{inc.key}->it-org: OT hosts not reported as new assets")

    # tgt inventory --sprinkle lists the new assets after the inventory
    buf = io.StringIO()
    inventory.write_csv(plant, buf, ["triton", "industroyer"])
    rows = list(csv.DictReader(io.StringIO(buf.getvalue())))
    extra = {r["name"]: r for r in rows[len(plant.hosts):]}
    check(set(extra) == {"SIS-TRICONEX", "RTU-104"} and
          extra["RTU-104"]["serves"] == "iec104 2404/tcp" and
          extra["RTU-104"]["segment"] == "OT-CELL-RW" and
          "new asset" in extra["SIS-TRICONEX"]["risk"],
          f"inventory --sprinkle new-asset rows wrong: {sorted(extra)}")
    doc = inventory.to_json(plant, ["triton"])
    check(doc["sprinkle"]["triton"] == {
        "mapped": {"TRITON-ENGWS": "ENGWS01"},
        "new_assets": ["SIS-TRICONEX"],
        "techniques": ["T0843", "T0846", "T0868", "T1046"]},
        "inventory JSON sprinkle mapping")


def serves_of(env, name: str) -> set:
    from tgt import inventory
    row = next(r for r in inventory.hosts(env) if r["name"] == name)
    return {s.split()[0] for s in row["serves"]}


def test_replay_roundtrip() -> None:
    from tgt import pcapread
    ep = Endpoints()
    frames = protocols.dns_flow(ep, 4)
    with tempfile.NamedTemporaryFile(suffix=".pcap") as tf:
        with PcapWriter(tf.name) as w:
            for f in frames:
                w.write(f)
        got = pcapread.read_frames(tf.name)
    check(len(got) == len(frames), "replay: wrong packet count")
    check(all(g[1] == f for g, f in zip(got, frames)),
          "replay: frame bytes changed")


def test_new_protocols_registered() -> None:
    for key in ("smb", "https", "kerberos", "ldap", "dhcp", "netbios",
                "enip-id", "s7-id"):
        check(key in protocols.PROFILES, f"protocol {key} not registered")


def test_pcap_roundtrip() -> None:
    ep = Endpoints()
    frames = protocols.enip_flow(ep, 3)
    with tempfile.NamedTemporaryFile(suffix=".pcap") as tf:
        with PcapWriter(tf.name) as w:
            for f in frames:
                w.write(f)
        data = open(tf.name, "rb").read()
    magic = struct.unpack("!I", data[:4])[0]
    check(magic == 0xA1B2C3D4, "pcap magic wrong")
    # walk records
    off, n = 24, 0
    while off < len(data):
        _, _, incl, orig = struct.unpack("!IIII", data[off:off + 16])
        check(incl == orig, "pcap incl/orig mismatch")
        off += 16 + incl
        n += 1
    check(off == len(data), "pcap did not parse cleanly to EOF")
    check(n == len(frames), f"pcap record count {n} != {len(frames)}")


def _ber_fields(buf: bytes) -> dict:
    """Top-level BER TLVs of ``buf`` -> {tag: value} (short/long lengths)."""
    out, i = {}, 0
    while i + 2 <= len(buf):
        tag, ln = buf[i], buf[i + 1]
        i += 2
        if ln & 0x80:
            k = ln & 0x7F
            ln = int.from_bytes(buf[i:i + k], "big")
            i += k
        out[tag] = buf[i:i + ln]
        i += ln
    return out


def test_industrial_l2_protocols() -> None:
    """PROFINET DCP/RT, GOOSE, SV, MMS and PTP: EtherTypes, multicast MACs,
    priority tags, GOOSE stNum/sqNum semantics and endpoint-meta identity."""
    meta = {"host": "BAY1IED", "station": "ET200SP-Line3", "vendor": "ABB",
            "model": "REF615", "revision": "5.0 FP1"}
    ep = Endpoints(meta=meta)
    for key in ("pn-dcp", "pn-dcp-set", "pn-rt", "goose", "sv", "ptp-l2"):
        check(protocols.get(key).transport == "l2",
              f"{key} must register as l2 so envs keep it on one segment")
        for f in protocols.get(key).build(ep, 4):
            check(len(f) >= 60, f"{key}: frame shorter than Ethernet minimum")
            check(P.frame_ips(f) is None, f"{key}: L2 frame carries IPv4")

    dcp = protocols.get("pn-dcp").build(ep, 1)
    check(dcp[0][:6] == P.mac_to_bytes("01:0e:cf:00:00:00") and
          dcp[0][12:16] == b"\x88\x92\xfe\xfe", "DCP Identify All framing")
    check(b"et200sp-line3" in dcp[1] and b"\x00\x2a\x01\x0e" in dcp[1],
          "DCP response lacks NameOfStation / Siemens vendor+device ID")
    sets = protocols.get("pn-dcp-set").build(ep, 2)
    check(any(f[16:18] == b"\x04\x00" for f in sets), "DCP Set request missing")

    goose = protocols.get("goose").build(ep, 8)
    seen = []
    for f in goose:
        check(f[12:14] == b"\x81\x00" and f[14] >> 5 == 4 and
              f[16:18] == b"\x88\xb8", "GOOSE not 802.1Q prio 4 / 0x88b8")
        check(f[:3] == b"\x01\x0c\xcd", "GOOSE dst not 01:0c:cd multicast")
        pdu = _ber_fields(_ber_fields(f[26:])[0x61])
        seen.append((int.from_bytes(pdu[0x85], "big"),
                     int.from_bytes(pdu[0x86], "big"), pdu[0xAB]))
        check(pdu[0x80].startswith(b"BAY1IEDLD0/LLN0$GO$"), "GOOSE gocbRef")
    for (st0, sq0, d0), (st1, sq1, d1) in zip(seen, seen[1:]):
        if st1 == st0:
            check(sq1 == sq0 + 1 and d1 == d0, "GOOSE retransmission broke "
                  "sqNum++ / same data")
        else:
            check(st1 == st0 + 1 and sq1 == 0 and d1 != d0,
                  "GOOSE state change must bump stNum, reset sqNum")

    sv = protocols.get("sv").build(ep, 3)
    check(all(f[16:18] == b"\x88\xba" and f[:3] == b"\x01\x0c\xcd"
              for f in sv), "SV framing")

    mms = b"".join(protocols.get("mms").build(ep, 2))
    for needle in (b"ABB", b"REF615", b"5.0 FP1", b"BAY1IEDLD0",
                   b"MMXU1$MX$TotW", b"\x28\xca\x22\x02\x03"):
        check(needle in mms, f"MMS flow missing {needle!r}")

    for f in protocols.get("ptp").build(ep, 2):
        verify_ip_l4(f, "ptp")
        check(P.frame_ips(f)[1] == "224.0.1.129" and f[14 + 8] == 1,
              "PTP must be link-local multicast with TTL 1")
        check(struct.unpack("!H", f[36:38])[0] in (319, 320), "PTP port")


def test_substation_scenarios_build() -> None:
    for key in ("substation", "profinet-cell"):
        sc = scenarios.get(key)
        batch = build_batch(RunConfig(profiles=sc.profiles, messages=2))
        check({k for k, _ in batch} == set(sc.profiles),
              f"scenario {key} did not emit every profile")


def _l4(frame: bytes):
    """(ip_proto, src_ip, dst_ip, sport, dport, l4_bytes) of an IPv4 frame."""
    off = 18 if frame[12:14] == b"\x81\x00" else 14
    if frame[off - 2:off] != b"\x08\x00":
        return None
    ihl = (frame[off] & 0x0F) * 4
    l4 = frame[off + ihl:]
    sport, dport = struct.unpack("!HH", l4[:4])
    return (frame[off + 9], ".".join(map(str, frame[off + 12:off + 16])),
            ".".join(map(str, frame[off + 16:off + 20])), sport, dport, l4)


def test_udp_replies_return_to_the_request_port() -> None:
    from tgt import incidents
    ep = Endpoints()
    builders = {"dns": protocols.dns_flow, "ntp": protocols.ntp_flow,
                "bacnet": protocols.bacnet_flow}
    for k in ("dga-dns", "dns-tunnel", "tristation"):
        builders[k] = incidents.ATTACKS[k][0]
    for key, build in builders.items():
        frames = [_l4(f) for f in build(ep, 4)]
        for req, rsp in zip(frames[0::2], frames[1::2]):
            check(rsp[1] == req[2] and rsp[2] == req[1],
                  f"{key}: reply not addressed back to the client")
            check((rsp[3], rsp[4]) == (req[4], req[3]),
                  f"{key}: reply {rsp[3]}->{rsp[4]} does not answer "
                  f"request {req[3]}->{req[4]}")


def test_tcp_syn_has_zero_ack() -> None:
    from tgt import enterprise
    syns = 0
    for _, f in enterprise.get("industrial-site").build(1):
        t = _l4(f)
        if t and t[0] == P.IPPROTO_TCP and t[5][13] == P.SYN:
            syns += 1
            check(struct.unpack("!I", t[5][8:12])[0] == 0,
                  "bare SYN carries a non-zero acknowledgement number")
    check(syns > 0, "no SYNs found")


def test_bacnet_readproperty_complexack() -> None:
    frames = [_l4(f)[5][8:] for f in protocols.bacnet_flow(Endpoints(), 3)]
    invokes = set()
    for req, ack in zip(frames[0::2], frames[1::2]):
        r, a = req[6:], ack[6:]               # past BVLC (4) + NPDU (2)
        check(req[5] == 0x04, "bacnet: request NPDU not expecting a reply")
        check(r[0] == 0x00 and r[3] == 0x0C and r[4] == 0x0C,
              "bacnet: request is not Confirmed-REQ ReadProperty(objectId)")
        check(a[0] == 0x30 and a[2] == 0x0C, "bacnet: reply is not ComplexACK")
        check(a[1] == r[2], "bacnet: ComplexACK invoke ID != request's")
        check(a[-1] == 0x3F, "bacnet: ComplexACK value not closed")
        invokes.add(r[2])
    check(len(invokes) == 3, "bacnet: invoke ID does not vary")


def test_iec104_command_sequence_numbers() -> None:
    from tgt import incidents
    ep = Endpoints()
    sent = {True: 0, False: 0}        # I-frames sent by client / server
    for f in incidents.iec104_command(ep, 4):
        t = _l4(f)
        seg = t[5]
        data = seg[(seg[12] >> 4) * 4:]
        from_client = t[1] == ep.client_ip
        while len(data) >= 6 and data[0] == 0x68:
            c1, c2 = struct.unpack("<HH", data[2:6])
            if not c1 & 1:                                 # I-format
                check(c1 >> 1 == sent[from_client],
                      f"iec104: N(S) {c1 >> 1} != {sent[from_client]}")
                check(c2 >> 1 == sent[not from_client],
                      f"iec104: N(R) {c2 >> 1} != {sent[not from_client]}")
                sent[from_client] += 1
            elif c1 & 3 == 1:                              # S-format
                check(c2 >> 1 == sent[not from_client], "iec104: S-frame N(R)")
            data = data[2 + data[1]:]
    check(sent[True] == 4 and sent[False] == 8,
          f"iec104: unexpected I-frame counts {sent}")


def test_industroyer_c2_is_outbound() -> None:
    from tgt import incidents
    inc = incidents.get("industroyer")
    c2 = inc.host("INDUSTROYER-C2")
    for _, f in inc.build(1):
        t = _l4(f)
        if t and t[0] == P.IPPROTO_TCP and t[5][13] == P.SYN and c2.ip in t[1:3]:
            check(t[2] == c2.ip and t[4] == 80,
                  "industroyer: C2 connection not initiated by the inside host")
            return
    _failures.append("industroyer: no C2 SYN found")


def test_modbus_writes_are_a_minority() -> None:
    fcs = []
    for f in protocols.modbus_flow(Endpoints(), 16):
        t = _l4(f)
        seg = t[5]
        pdu = seg[(seg[12] >> 4) * 4:]
        if t[4] == 502 and len(pdu) >= 8:
            fcs.append(pdu[7])
    check(fcs.count(0x06) == 2 and fcs.count(0x03) == 8
          and {fcs.count(fc) for fc in (0x01, 0x02, 0x04)} == {2},
          f"modbus: expected 2 FC6 writes, 8 FC3 and 2 each of FC1/2/4 in "
          f"16 requests, got {fcs}")
    resp = [f for f in protocols.modbus_flow(Endpoints(), 5)]
    pay = [_l4(f)[5][20:] for f in resp]
    w = [p for p in pay if len(p) > 7 and p[7] == 0x06]
    check(len(w) == 2 and w[0] == w[1], "modbus: FC6 response is not an echo")
    from tgt import incidents
    check("download" not in incidents.ATTACKS["s7-control"][1],
          "s7-control still claims a program download")


def test_dhcp_dora_ntp_and_dns_realism() -> None:
    from tgt import enterprise
    ep = Endpoints(meta={"nbname": "WS42"})
    frames = protocols.dhcp_flow(ep, 2)
    types = []
    for f in frames:
        t = _l4(f)
        body = t[5][8:]
        opts, k = {}, 240
        while k < len(body) and body[k] != 0xFF:
            opts[body[k]] = body[k + 2:k + 2 + body[k + 1]]
            k += 2 + body[k + 1]
        types.append(opts[53][0])
        if opts[53][0] in (1, 3) and body[12:16] == bytes(4):  # DORA broadcast
            check(f[:6] == b"\xff" * 6 and t[1:5] == ("0.0.0.0",
                  "255.255.255.255", 68, 67), "dhcp: Discover/Request not broadcast")
            check(opts.get(12) == b"WS42" and 61 in opts and 50 in opts and
                  55 in opts and opts.get(60) == b"MSFT 5.0",
                  "dhcp: request lacks options 12/61/50/55/60")
        if opts[53][0] in (2, 5):
            check(body[16:20] == P.ip_to_bytes(ep.client_ip),
                  "dhcp: Offer/ACK without yiaddr")
            check(all(o in opts for o in (54, 51, 1, 3, 6)),
                  "dhcp: Offer/ACK lacks options 54/51/1/3/6")
    check(types == [1, 2, 3, 5, 3, 5], f"dhcp: not DORA + renewal: {types}")
    xids = {f[-300:][4:8] for f in frames}
    check(len(xids) == 2, "dhcp: xid does not vary per transaction")
    # NTP: stratum 2, origin echoes the client's transmit time, real era
    req, rsp = (_l4(f)[5][8:] for f in protocols.ntp_flow(Endpoints(), 1))
    check(rsp[1] == 2, "ntp: server not stratum 2")
    check(rsp[24:32] == req[40:48], "ntp: origin != client transmit")
    check(struct.unpack("!I", rsp[40:44])[0] > 3900000000,
          "ntp: transmit timestamp not a real date")
    # DNS: an env resolves the real inventory names to their real IPs
    env = enterprise.get("it-org")
    ips = {f"{h.name.lower()}.{enterprise.DNS_DOMAIN}": h.ip for h in env.hosts}
    seen = 0
    for proto, f in env.build(5):
        t = _l4(f)
        if proto == "dns" and t[3] == 53:
            msg, k, labels = t[5][8:], 12, []
            while msg[k]:
                labels.append(msg[k + 1:k + 1 + msg[k]].decode())
                k += 1 + msg[k]
            name = ".".join(labels)
            check(name in ips and msg[-4:] == P.ip_to_bytes(ips[name]),
                  f"dns: {name} not answered with its inventory IP")
            seen += 1
    check(seen > 0, "dns: no responses in it-org")


def test_tshark_dns_responses_matched() -> None:
    """Optional: with tshark on PATH, every DNS response in an industrial-site
    cycle (plus the incident DNS builders) is paired with its query."""
    import shutil
    import subprocess
    from tgt import enterprise, incidents
    if not shutil.which("tshark"):
        _skipped.append("test_tshark_dns_responses_matched")
        return
    frames = [f for _, f in enterprise.get("industrial-site").build(3)]
    for k in ("dga-dns", "dns-tunnel"):
        frames += incidents.ATTACKS[k][0](Endpoints(), 3)
    with tempfile.TemporaryDirectory() as d:
        path = f"{d}/dns.pcap"
        with PcapWriter(path) as w:
            for f in frames:
                w.write(f)

        def count(flt):
            return len(subprocess.run(["tshark", "-r", path, "-Y", flt],
                                      capture_output=True, text=True
                                      ).stdout.splitlines())
        total = count("dns.flags.response == 1")
        check(total > 0 and count("dns.response_to") == total,
              "tshark: DNS responses not matched to their queries")

# --- OT identity + engineering operations (tgt/protocols_ot.py, #44/#45) ---
_DISSECTS_AS.update({
    "modbus-id": "mbtcp", "modbus-write": "mbtcp", "bacnet-id": "bacapp",
    "enip-list": "enip", "enip-io": "cipio", "enip-eng": "cip",
    "s7-eng": "s7comm", "dnp3-id": "dnp3", "dnp3-time": "dnp3",
    "iec104-time": "iec60870_asdu",
})

# --- IT / infrastructure protocols (tgt/protocols_infra.py, issue #46) ------
_DISSECTS_AS.update({
    "snmp": "snmp", "snmpv3": "snmp", "lldp": "lldp", "cdp": "cdp",
    "syslog": "syslog", "mdns": "mdns", "ssdp": "ssdp", "llmnr": "llmnr",
    "nbns": "nbns", "mqtt": "mqtt", "sparkplug": "sparkplugb",
})


def _udp_tcp_payload(frame: bytes) -> bytes:
    """L4 payload of an untagged IPv4 TCP/UDP frame."""
    ihl = (frame[14] & 0x0F) * 4
    l4 = frame[14 + ihl:]
    return l4[8:] if frame[23] == P.IPPROTO_UDP else l4[(l4[12] >> 4) * 4:]


def _ber_walk(data: bytes) -> bool:
    """True when ``data`` is a sequence of well-formed BER TLVs, recursing
    into constructed ones (SEQUENCE, SNMP PDUs)."""
    off = 0
    while off < len(data):
        if off + 2 > len(data):
            return False
        tag, n = data[off], data[off + 1]
        off += 2
        if n & 0x80:
            k = n & 0x7F
            n = int.from_bytes(data[off:off + k], "big")
            off += k
        if off + n > len(data):
            return False
        if tag & 0x20 and not _ber_walk(data[off:off + n]):
            return False
        off += n
    return off == len(data)


def _pb_fields(data: bytes) -> list:
    """Minimal protobuf decoder: [(field, wiretype, value)], raising on any
    truncation so a malformed hand-encoding fails the test."""
    def varint(i):
        v = s = 0
        while True:
            b = data[i]
            v |= (b & 0x7F) << s
            i, s = i + 1, s + 7
            if not b & 0x80:
                return v, i
    out, i = [], 0
    while i < len(data):
        key, i = varint(i)
        f, wt = key >> 3, key & 7
        if wt == 0:
            v, i = varint(i)
        elif wt == 1:
            v, i = data[i:i + 8], i + 8
        elif wt == 5:
            v, i = data[i:i + 4], i + 4
        elif wt == 2:
            n, i = varint(i)
            v, i = data[i:i + n], i + n
        else:
            raise ValueError(f"wire type {wt}")
        if i > len(data):
            raise ValueError("truncated")
        out.append((f, wt, v))
    return out


def test_infra_protocols_registered() -> None:
    for key in ("snmp", "snmpv3", "lldp", "cdp", "syslog", "mdns", "ssdp",
                "llmnr", "nbns", "mqtt", "sparkplug"):
        check(key in protocols.PROFILES, f"protocol {key} not registered")
    check(protocols.get("lldp").transport == "l2"
          and protocols.get("cdp").transport == "l2", "LLDP/CDP must be l2")
    check("infra" in scenarios.SCENARIOS and "iiot" in scenarios.SCENARIOS,
          "infra / iiot scenarios missing")


def test_snmp_ber_and_meta_identity() -> None:
    ep = Endpoints(meta={"snmp_community": "s3cret", "host": "ups01",
                         "snmp_sysdescr": "APC Web/SNMP Management Card",
                         "snmp_sysobjectid": "1.3.6.1.4.1.318.1.3.27"})
    frames = protocols.get("snmp").build(ep, 3)
    blobs = [_udp_tcp_payload(f) for f in frames]
    for b in blobs + [_udp_tcp_payload(f) for f in
                      protocols.get("snmpv3").build(Endpoints(), 3)]:
        check(_ber_walk(b), "snmp: malformed BER message")
    check(all(b"s3cret" in b for b in blobs), "snmp: community not on wire")
    rsp = blobs[1]
    check(b"APC Web/SNMP Management Card" in rsp and b"ups01" in rsp,
          "snmp: sysDescr/sysName not taken from meta")
    # 1.3.6.1.4.1.318.1.3.27 -> 2b 06 01 04 01 82 3e 01 03 1b
    check(b"\x06\x0a\x2b\x06\x01\x04\x01\x82\x3e\x01\x03\x1b" in rsp,
          "snmp: sysObjectID OID encoding wrong")
    dports = [struct.unpack("!H", f[36:38])[0] for f in frames]
    check(dports.count(162) == 2, "snmp: expected v1 trap + inform to 162")


def test_lldp_cdp_frames() -> None:
    ep = Endpoints(vlan=30, meta={"host": "sw12"})
    lldp = protocols.get("lldp").build(ep, 1)[0]
    check(lldp[:6] == b"\x01\x80\xc2\x00\x00\x0e" and lldp[12:14] == b"\x88\xcc",
          "lldp: wrong dst MAC / EtherType (or tagged)")
    off, types = 14, []
    while off < len(lldp):
        hdr = struct.unpack("!H", lldp[off:off + 2])[0]
        types.append(hdr >> 9)
        off += 2 + (hdr & 0x1FF)
    check(off == len(lldp) and types[:3] == [1, 2, 3] and types[-1] == 0,
          f"lldp: bad TLV chain {types}")
    # CDP checksum with Cisco's odd-length quirk (vector validated by tshark)
    cdp = protocols.get("cdp").build(
        Endpoints(server_ip="10.10.10.200", meta={"host": "sw12"}), 1)[0]
    check(cdp[:6] == b"\x01\x00\x0c\xcc\xcc\xcc"
          and struct.unpack("!H", cdp[12:14])[0] == len(cdp) - 14
          and cdp[14:22] == b"\xaa\xaa\x03\x00\x00\x0c\x20\x00",
          "cdp: wrong 802.3/SNAP framing")
    check((len(cdp) - 22) % 2 == 1 and cdp[24:26] == b"\xac\xd8",
          "cdp: odd-length checksum quirk regressed")


def test_discovery_multicast_addressing() -> None:
    def mc_mac(ip: bytes) -> bytes:
        return b"\x01\x00\x5e" + bytes([ip[1] & 0x7F]) + ip[2:]
    for key, group, ttl in (("mdns", "224.0.0.251", 255),
                            ("ssdp", "239.255.255.250", 2),
                            ("llmnr", "224.0.0.252", 1)):
        g = P.ip_to_bytes(group)
        mc = [f for f in protocols.get(key).build(Endpoints(), 2)
              if f[30:34] == g]
        check(len(mc) >= 2, f"{key}: no frames to {group}")
        for f in mc:
            check(f[:6] == mc_mac(g) and f[22] == ttl,
                  f"{key}: multicast MAC/TTL wrong")
    ssdp = b"".join(_udp_tcp_payload(f)
                    for f in protocols.get("ssdp").build(
                        Endpoints(meta={"ssdp_server": "X/1 UPnP/1.0 Y/2"}), 1))
    check(b"M-SEARCH" in ssdp and b"ssdp:alive" in ssdp
          and ssdp.count(b"SERVER: X/1 UPnP/1.0 Y/2") == 2,
          "ssdp: M-SEARCH/NOTIFY/SERVER banner missing")
    nb = protocols.get("nbns").build(Endpoints(), 2)
    check(nb[0][:6] == b"\xff" * 6 and nb[0][30:34] == b"\x0a\x0a\x0a\xff",
          "nbns: name query not broadcast")
    check(P.mac_to_bytes(Endpoints().server_mac) in nb[3],
          "nbns: NBSTAT response lacks the MAC (unit ID)")


def test_syslog_formats() -> None:
    lines = [_udp_tcp_payload(f).decode() for f in
             protocols.get("syslog").build(Endpoints(meta={"nbname": "rtac1"}), 4)]
    check(lines[0].startswith("<") and " rtac1 " in lines[0]
          and not lines[0].split(">", 1)[1].startswith("1 "),
          "syslog: first message is not RFC 3164")
    check(lines[1].split(">", 1)[1].startswith("1 2025-")
          and "[meta sequenceId=" in lines[1], "syslog: second not RFC 5424")


def test_mqtt_and_sparkplug_encoding() -> None:
    from tgt import protocols_infra as I
    check(I._mqtt(0x30, bytes(200))[:3] == b"\x30\xc8\x01",
          "mqtt: remaining-length varint wrong")
    pay = [_udp_tcp_payload(f) for f in protocols.get("mqtt").build(
        Endpoints(meta={"mqtt_client_id": "gw7", "mqtt_user": "u"}), 4)]
    pay = [p for p in pay if p]
    check(pay[0][0] == 0x10 and b"gw7" in pay[0] and pay[0][9] & 0x80,
          "mqtt: CONNECT client id / username flag")
    types = [p[0] >> 4 for p in pay]
    for t in (1, 2, 3, 4, 8, 9, 12, 13, 14):
        check(t in types, f"mqtt: control packet type {t} missing")
    check(any(p[0] == 0x32 for p in pay), "mqtt: no QoS 1 PUBLISH")

    pubs = []
    for f in protocols.get("sparkplug").build(Endpoints(), 3):
        p = _udp_tcp_payload(f)
        if p and p[0] >> 4 == 3:
            n, i, s = 0, 1, 0
            while True:                        # remaining length varint
                n |= (p[i] & 0x7F) << s
                i, s = i + 1, s + 7
                if not p[i - 1] & 0x80:
                    break
            tl = struct.unpack("!H", p[i:i + 2])[0]
            topic = p[i + 2:i + 2 + tl].decode()
            body = p[i + 2 + tl + (2 if p[0] & 0x06 else 0):]
            pubs.append((topic, body))
    kinds = [t.split("/")[2] for t, _ in pubs]
    check(kinds == ["NBIRTH", "NDATA", "NDATA", "NDATA", "NDEATH"]
          and all(t.startswith("spBv1.0/Plant1/") for t, _ in pubs),
          f"sparkplug: topic sequence {kinds}")
    try:
        seqs = []
        for topic, body in pubs:
            fields = _pb_fields(body)
            for f, wt, v in fields:
                if f == 2:
                    _pb_fields(v)              # each Metric decodes cleanly
            seqs += [v for f, _, v in fields if f == 3]
        check(seqs == [0, 1, 2, 3], f"sparkplug: seq numbers {seqs}")
    except (ValueError, IndexError) as e:
        check(False, f"sparkplug: protobuf payload malformed ({e})")

# ---------------------------------------------------------------------------
# Device-profile catalog + ground-truth enrichment (#43, #53)
# ---------------------------------------------------------------------------
_EMBEDDED_FPS = {"rockwell", "siemens", "schneider", "bacnet", "sel"}
_FIELD_ROLES = {"plc", "drive", "meter", "relay", "rtu"}


def _looks_embedded(h) -> bool:
    from tgt import devices
    return (h.os in _EMBEDDED_FPS or h.role in _FIELD_ROLES
            or h.mac[:8].lower() in devices.EMBEDDED_OUIS)


def test_device_catalog_complete() -> None:
    import shutil
    import subprocess
    from tgt import devices, enterprise
    for env in enterprise.all_environments():
        for h in env.hosts:
            dev = h.device
            check(dev is not None, f"{env.key}: {h.name} has no catalog model")
            if dev is None:
                continue
            if _looks_embedded(h):
                check(dev.embedded, f"{env.key}: {h.name} model {h.model} "
                      "is not an embedded device")
                check(h.mac[:8].lower() in dev.ouis,
                      f"{env.key}: {h.name} MAC OUI not one of {h.model}'s")
            check(h.firmware in dev.firmware,
                  f"{env.key}: {h.name} firmware {h.firmware!r} not offered")
            check(bool(env.purdue_level(h)),
                  f"{env.key}: {h.name} has no Purdue level")
    for m in devices.CATALOG.values():
        check(bool(m.firmware), f"{m.model_id}: no firmware choices")
        check(bool(m.ouis) and all(o == o.lower() and len(o) == 8
                                   for o in m.ouis), f"{m.model_id}: bad OUIs")
        check(all(c.startswith("CVE-") for c in m.known_cves),
              f"{m.model_id}: malformed CVE id")
        if not m.embedded:
            continue
        check(bool(m.serial_format) and bool(m.purdue_level),
              f"{m.model_id}: embedded model without serial format/level")
        check(not m.edr_capable, f"{m.model_id}: embedded but EDR-capable")
    # IT OS families agree with the EDR coverage rule
    for os_key, mid in devices.OS_DEFAULT_MODEL.items():
        check(devices.get(mid).edr_capable == (os_key in enterprise.EDR_OS),
              f"{mid}: edr_capable disagrees with EDR_OS")
    # compatibility shims still answer like the old tables
    check(enterprise.OUI_VENDORS.get(enterprise.OUI_ROCKWELL)
          == "Rockwell Automation", "OUI_VENDORS shim lost Rockwell")
    check(enterprise.OUI_WIN not in enterprise._EMBEDDED_OUIS,
          "_EMBEDDED_OUIS shim includes the VMware OUI")
    if not shutil.which("tshark"):
        _skipped.append("test_device_catalog_complete")
        return
    manuf = subprocess.run(["tshark", "-G", "manuf"], capture_output=True,
                           text=True).stdout
    known = {ln.split()[0].lower() for ln in manuf.splitlines()
             if ln[:1].isalnum() and len(ln.split()[0]) == 8}
    for m in devices.CATALOG.values():
        for o in m.ouis:
            check(o in known, f"{m.model_id}: OUI {o} not in Wireshark manuf")


def test_device_firmware_serial_deterministic() -> None:
    import re
    from tgt import devices, enterprise
    m = devices.get("siemens-cpu-315-2pndp")
    check(devices.pick_firmware(m, "PLC-X") == devices.pick_firmware(m, "PLC-X"),
          "firmware pick not deterministic")
    check(re.fullmatch(r"S C-[A-Z]\d[A-Z]\d{9}", devices.make_serial(m, "PLC-X"))
          is not None, "S7 serial does not follow its format")
    a = enterprise.Host("PLC-X", "10.0.0.1", "00:0e:8c:00:00:01", "plc",
                        "siemens", "Siemens", "6ES7 315-2EH14-0AB0")
    b = enterprise.Host("PLC-X", "10.0.0.2", "00:0e:8c:00:00:02", "plc",
                        "siemens", "Siemens", "6ES7 315-2EH14-0AB0")
    check(a.model == "siemens-cpu-315-2pndp", "product did not resolve to model")
    check((a.firmware, a.serial) == (b.firmware, b.serial),
          "same host name gave different firmware/serial")
    c = enterprise.Host("PLC-X", "10.0.0.1", "00:0e:8c:00:00:01", "plc",
                        "siemens", "Siemens", "6ES7 315-2EH14-0AB0",
                        firmware="V3.2.8", serial="S C-A1B000000001")
    check((c.firmware, c.serial) == ("V3.2.8", "S C-A1B000000001"),
          "explicit firmware/serial overridden")
    # rebuilt environments report the same values (stable ground truth)
    again = {h.name: (h.firmware, h.serial) for h in enterprise._site_hosts()}
    site = enterprise.get("industrial-site")
    check(all(again[h.name] == (h.firmware, h.serial) for h in site.hosts),
          "industrial-site firmware/serial not stable across builds")
    serials = [h.serial for h in site.hosts if h.serial]
    check(len(serials) == len(set(serials)), "duplicate serial numbers")
    check(devices.cip_revision("33.011") == (33, 11)
          and devices.s7_version("V3.2.17") == (3, 2, 17),
          "firmware -> protocol revision parsing")


def test_inventory_ground_truth_fields() -> None:
    import csv
    import io
    import ipaddress
    from tgt import enterprise, inventory
    old = ["name", "ip", "mac", "mac_vendor", "vendor", "product", "role",
           "os", "segment", "vlan", "subnet", "zone", "gateway", "legacy",
           "risk", "serves", "uses"]
    check(inventory.COLUMNS[:len(old)] == old, "CSV columns reordered")
    for col in ("asset_id", "model", "firmware", "serial", "purdue_level"):
        check(col in inventory.COLUMNS, f"CSV missing {col}")
    site = enterprise.get("industrial-site")
    buf = io.StringIO()
    inventory.write_csv(site, buf)
    rows = {r["name"]: r for r in csv.DictReader(io.StringIO(buf.getvalue()))}
    pk1 = site.host("PLC-PK1")
    check(rows["PLC-PK1"]["asset_id"] == "industrial-site:PLC-PK1",
          "asset_id not env:name")
    check(rows["PLC-PK1"]["firmware"] == pk1.firmware != "", "CSV firmware")
    check(rows["PLC-PK1"]["purdue_level"] == "1"
          and rows["WS20"]["purdue_level"] == "4"
          and rows["JUMP01"]["purdue_level"] == "3.5"
          and rows["HMI-PK1"]["purdue_level"] == "2", "Purdue levels wrong")
    doc = inventory.to_json(site)
    hosts = {h["name"]: h for h in doc["hosts"]}
    ob = hosts["PLC-PK1"]["observability"]
    check(ob["firmware"] == {"value": pk1.firmware, "observable": True,
                             "evidence": ["enip-id", "enip-list"]},
          f"PLC-PK1 firmware observability: {ob['firmware']}")
    check(ob["serial"]["observable"] and ob["vendor"]["observable"],
          "PLC-PK1 serial/vendor not observable")
    check(hosts["PLC-PR1"]["observability"]["serial"]["evidence"] == ["s7-id"],
          "S7 serial not observable via s7-id")
    meter = hosts["METER-UT1"]["observability"]
    # Modbus device ID carries the revision but no serial number
    check(meter["firmware"]["evidence"] == ["modbus-id"]
          and not meter["serial"]["observable"]
          and meter["vendor"]["evidence"] == ["modbus-id", "oui"],
          f"Modbus meter observability: {meter}")
    ws = hosts["WS20"]["observability"]["os"]
    check(ws["observable"] and {"dhcp", "http", "smb"} <= set(ws["evidence"]),
          f"WS20 OS evidence: {ws['evidence']}")
    check(hosts["WS48"]["known_cves"] and "CVE-2017-0144" in
          hosts["WS48"]["known_cves"], "WinXP host lost its MS17-010 CVE")
    check(hosts["PLC-PK1"]["modules"] and hosts["PLC-PK1"]["embedded"]
          and not hosts["PLC-PK1"]["edr"], "PLC-PK1 modules/embedded/edr")
    # flows gain dport + transport
    f = next(x for x in doc["flows"] if x["protocol"] == "enip-id")
    check(f["dport"] == 44818 and f["transport"] == "tcp", "flow dport/transport")
    check(next(x for x in doc["flows"] if x["protocol"] == "arp")["dport"]
          is None, "ARP flow has a dport")
    # externals: every public IP on the wire, CrowdStrike annotated
    ext = {e["ip"]: e for e in doc["external"]}
    host_ips = {h.ip for h in site.hosts}
    wire = {ip for _, fr in site.build(1) for ip in (P.frame_ips(fr) or ())
            if ip not in host_ips and ipaddress.ip_address(ip).is_global}
    check(wire and wire == set(ext), "external list != public IPs on the wire")
    check(all(e["kind"] == "edr-cloud" and e["vendor"] == "CrowdStrike"
              and e["fqdns"] and e["talkers"] for e in ext.values()),
          "CrowdStrike externals not annotated")
    fq = {f for e in ext.values() for f in e["fqdns"]}
    check(fq == set(enterprise.CROWDSTRIKE_FQDNS.values()),
          f"external FQDNs incomplete: {fq}")
    infra = doc["infrastructure"]
    check(len(infra) == len(site.segments) and all(
        i["kind"] == "hsrp-gateway" and i["mac"].startswith("00:00:0c:07:ac:")
        for i in infra), "HSRP gateways missing from infrastructure")
    # an env without EDR hosts has no externals
    check(inventory.to_json(enterprise.get("ot-plant"))["external"],
          "ot-plant: Falcon externals missing")


def test_identity_wire_matches_inventory() -> None:
    """ENIP List Identity and S7 SZL replies carry each device's own catalog
    revision/serial (different PLCs differ) and agree with ``tgt inventory``;
    decoded by tshark when present."""
    import shutil
    import subprocess
    from tgt import devices, enterprise, inventory
    site = enterprise.get("industrial-site")
    inv = {h["ip"]: h for h in inventory.hosts(site)}
    # meta path: each identity server's endpoint carries its own identity
    revs, s7fw = set(), set()
    for c, sv, proto in site.conversations:
        h = site.host(sv)
        meta = site._endpoints(site.host(c), h).meta
        if proto == "enip-id":
            check(meta["cip_revision"] == devices.cip_revision(h.firmware)
                  and meta["cip_serial"] == int(h.serial, 16),
                  f"{sv}: enip-id meta does not carry its identity")
            revs.add(meta["cip_revision"])
        elif proto == "s7-id":
            check(meta["s7_serial"] == h.serial, f"{sv}: s7-id meta serial")
            s7fw.add(meta["s7_firmware"])
    check(len(revs) > 1, f"every ENIP device reports one revision: {revs}")
    check(len(s7fw) > 1, f"every S7 CPU reports one firmware: {s7fw}")
    if not shutil.which("tshark"):
        _skipped.append("test_identity_wire_matches_inventory")
        return
    with tempfile.TemporaryDirectory() as d:
        path = f"{d}/site.pcap"
        with PcapWriter(path) as w:
            for k, f in site.build(1):
                if k in ("enip-id", "s7-id"):
                    w.write(f)
        enip = subprocess.run(
            ["tshark", "-r", path, "-Y", "enip.lir.name", "-T", "fields",
             "-e", "ip.src", "-e", "enip.lir.revision", "-e", "enip.lir.serial",
             "-e", "enip.lir.vendor"],
            capture_output=True, text=True).stdout.splitlines()
        s7 = subprocess.run(
            ["tshark", "-r", path, "-Y",
             "s7comm.szl.xy11.0001.ausbg || s7comm.szl.001c.0005.serialn",
             "-T", "fields", "-e", "ip.src", "-e", "s7comm.szl.xy11.0001.ausbg",
             "-e", "s7comm.szl.xy11.0001.ausbe",
             "-e", "s7comm.szl.001c.0005.serialn"],
            capture_output=True, text=True).stdout.splitlines()
    seen_enip, seen_s7fw, seen_s7sn = set(), set(), set()
    for ln in enip:
        ip, rev, serial, vendor = ln.split("\t")
        h = inv[ip]
        major, minor = devices.cip_revision(h["firmware"])
        check(int(rev) == (major << 8 | minor),
              f"{h['name']}: wire revision {rev} != inventory {h['firmware']}")
        check(int(serial, 16) == int(h["serial"], 16),
              f"{h['name']}: wire serial {serial} != inventory {h['serial']}")
        check(int(vendor, 16) == 1, f"{h['name']}: CIP vendor not Rockwell")
        seen_enip.add(ip)
    for ln in s7:
        ip, ausbg, ausbe, serial = ln.split("\t")
        h = inv[ip]
        if ausbg:
            ma, mi, pa = devices.s7_version(h["firmware"])
            g, e = ausbg.split(",")[-1], ausbe.split(",")[-1]   # index 0x0007
            check((int(g), int(e)) == (0x5600 | ma, mi << 8 | pa),
                  f"{h['name']}: wire firmware != inventory {h['firmware']}")
            seen_s7fw.add(ip)
        if serial:
            check(serial == h["serial"],
                  f"{h['name']}: wire serial {serial} != inventory {h['serial']}")
            seen_s7sn.add(ip)
    want_enip = {site.host(sv).ip for _, sv, p in site.conversations
                 if p == "enip-id"}
    want_s7 = {site.host(sv).ip for _, sv, p in site.conversations
               if p == "s7-id"}
    check(seen_enip == want_enip, "tshark: not every ENIP device identified")
    check(seen_s7fw == want_s7 == seen_s7sn,
          "tshark: not every S7 CPU reported firmware + serial")

# -- engine / ops robustness ------------------------------------------------
def _pcap_records(path: str) -> list:
    from tgt import pcapread
    try:
        return pcapread.read_frames(path, wrap=False)
    except (OSError, pcapread.PcapError):
        return []


def _run_engine(cfg, timeout: float = 10.0):
    from tgt.engine import Engine
    eng = Engine(cfg)
    eng.start()
    eng.join(timeout)
    return eng


def test_engine_loop_count_duration_stop() -> None:
    import time
    from tgt.engine import Engine
    with tempfile.TemporaryDirectory() as d:
        # --count: exactly N frames, all of them in the pcap
        path = os.path.join(d, "count.pcap")
        eng = _run_engine(RunConfig(profiles=["modbus", "dnp3"], rate=0,
                                    count=37, pcap_path=path))
        check(not eng.is_alive(), "engine: count run did not finish")
        check(eng.stats.packets == 37, f"engine: count gave {eng.stats.packets}")
        check(len(_pcap_records(path)) == 37, "engine: count pcap != 37 frames")
        check(eng.stats.finished and not eng.stats.running,
              "engine: stats not marked finished")
        # --duration: stops on time
        path = os.path.join(d, "dur.pcap")
        t0 = time.perf_counter()
        eng = _run_engine(RunConfig(profiles=["modbus"], rate=200,
                                    duration=0.3, pcap_path=path))
        took = time.perf_counter() - t0
        check(not eng.is_alive() and 0.25 <= took < 1.5,
              f"engine: duration=0.3 took {took:.2f}s")
        check(len(_pcap_records(path)) == eng.stats.packets > 0,
              "engine: duration pcap != packets")
        # stop(): prompt even at a very slow rate (5 s between frames)
        path = os.path.join(d, "stop.pcap")
        eng = Engine(RunConfig(profiles=["modbus"], rate=0.2, pcap_path=path))
        eng.start()
        time.sleep(0.2)
        t0 = time.perf_counter()
        eng.stop()
        eng.join(3)
        took = time.perf_counter() - t0
        check(not eng.is_alive() and took < 1.0,
              f"engine: stop() at 0.2pps took {took:.2f}s")
        check(len(_pcap_records(path)) == eng.stats.packets,
              "engine: stopped pcap != packets")
        # --once: a single cycle
        path = os.path.join(d, "once.pcap")
        eng = _run_engine(RunConfig(profiles=["modbus"], rate=0, loop=False,
                                    pcap_path=path))
        check(eng.stats.packets == eng.stats.cycle_frames > 0,
              "engine: --once did not send exactly one cycle")


def test_engine_failed_sends_not_counted_or_written() -> None:
    from tgt import engine as E

    class FlakySender:                      # every 3rd send fails
        def __init__(self, iface):
            self.n = 0

        def open(self):
            pass

        def send(self, frame):
            self.n += 1
            if self.n % 3 == 0:
                raise OSError(100, "Network is down")
            return len(frame)

        def close(self):
            pass

    real = E.RawSender
    E.RawSender = FlakySender
    try:
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "flaky.pcap")
            eng = _run_engine(RunConfig(profiles=["modbus"], rate=0, count=30,
                                        iface="fake0", pcap_path=path))
            recs = _pcap_records(path)
    finally:
        E.RawSender = real
    st = eng.stats
    check(st.errors == 10 and st.packets == 20,
          f"failed sends: packets={st.packets} errors={st.errors} "
          "(want 20 sent + 10 errors)")
    check(len(recs) == st.packets,
          "failed sends: pcap holds frames that never left")
    check(sum(st.per_profile.values()) == st.packets,
          "failed sends: per-profile counts include failures")
    check("Network is down" in st.last_error, "failed sends: last_error unset")


def test_replay_realtime_keeps_original_timing() -> None:
    import time
    from tgt.replay import gap
    ts = [10.0, 10.5, 10.4, 30.0]
    check([gap(a, b) for a, b in zip(ts, ts[1:])] == [0.5, 0.0, 5.0],
          "replay gap: not clamped to [0, 5]")
    frame = protocols.dns_flow(Endpoints(), 1)[0]
    span, n = 0.6, 1200                     # 0.5 ms gaps: drift would show
    with tempfile.TemporaryDirectory() as d:
        src = os.path.join(d, "src.pcap")
        with PcapWriter(src) as w:
            for i in range(n):
                w.write(frame, ts=1000.0 + span * i / (n - 1))
        out = os.path.join(d, "out.pcap")
        t0 = time.perf_counter()
        eng = _run_engine(RunConfig(replay_path=src, replay_realtime=True,
                                    loop=False, pcap_path=out))
        took = time.perf_counter() - t0
    check(eng.stats.packets == n, "realtime replay: lost packets")
    check(span * 0.95 <= took <= span + 0.25,
          f"realtime replay of a {span}s capture took {took:.2f}s")


def test_rate_limiter_accuracy() -> None:
    import threading
    import time
    from tgt.sender import RateLimiter
    rl = RateLimiter(200)
    t0 = time.perf_counter()
    for _ in range(40):                     # 40 slots @ 200 pps = 0.2 s
        rl.wait()
    took = time.perf_counter() - t0
    check(0.17 <= took <= 0.35, f"RateLimiter 200pps x40 took {took:.3f}s")
    check(RateLimiter(0).interval == 0, "RateLimiter(0) should not pace")
    stop = threading.Event()
    stop.set()
    rl = RateLimiter(0.5)                   # 2 s slot, but stop is set
    t0 = time.perf_counter()
    rl.wait(stop)
    check(time.perf_counter() - t0 < 0.2, "RateLimiter.wait ignores stop")


def _cli(args: list):
    import subprocess
    env = dict(os.environ, PYTHONPATH=_REPO)
    return subprocess.Popen([sys.executable, "-m", "tgt"] + args, cwd=_REPO,
                            env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, universal_newlines=True)


def test_cli_run_pcap_count_end_to_end() -> None:
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "cli.pcap")
        p = _cli(["run", "-p", "modbus,s7comm", "--pcap", path,
                  "--count", "25", "--rate", "0"])
        out, _ = p.communicate(timeout=30)
        recs = _pcap_records(path)
    check(p.returncode == 0, f"cli run: rc={p.returncode}: {out[-300:]}")
    check(len(recs) == 25, f"cli run: pcap has {len(recs)} frames, not 25")
    check("summary: 25 packets" in out, "cli run: no summary line")
    check("\r" not in out, "cli run: \\r progress line on a non-TTY stdout")


def test_cli_sigterm_flushes_pcap() -> None:
    import signal
    import time
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "term.pcap")
        p = _cli(["run", "-s", "ot-baseline", "--rate", "100",
                  "--pcap", path])
        time.sleep(1.2)
        p.send_signal(signal.SIGTERM)
        out, _ = p.communicate(timeout=10)
        recs = _pcap_records(path)
    check(p.returncode == 0, f"SIGTERM: rc={p.returncode}: {out[-300:]}")
    check(len(recs) > 20, f"SIGTERM: pcap has {len(recs)} frames")
    check("stopping on SIGTERM" in out and "summary:" in out,
          "SIGTERM: no clean stop / summary")


def test_pcapread_byte_orders_and_nanos() -> None:
    from tgt import pcapread
    frame = protocols.modbus_flow(Endpoints(), 1)[0]

    def pcap(endian: str, magic: int, linktype: int, recs) -> bytes:
        out = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535,
                          linktype)
        for sec, frac, data in recs:
            out += struct.pack(endian + "IIII", sec, frac, len(data),
                               len(data)) + data
        return out

    sll = struct.pack("!HHH8sH", 0, 1, 6, b"\x02" * 8, P.ETH_P_IP) + frame[14:]
    cases = [
        ("big-endian usec", ">", 0xA1B2C3D4, 1, 500000, 1.5, frame),
        ("little-endian usec", "<", 0xA1B2C3D4, 1, 250000, 1.25, frame),
        ("big-endian nsec", ">", 0xA1B23C4D, 1, 500000000, 1.5, frame),
        ("little-endian nsec", "<", 0xA1B23C4D, 1, 125000000, 1.125, frame),
        ("little-endian SLL", "<", 0xA1B2C3D4, 113, 0, 1.0, sll),
    ]
    with tempfile.TemporaryDirectory() as d:
        for label, endian, magic, lt, frac, want_ts, data in cases:
            path = os.path.join(d, "t.pcap")
            with open(path, "wb") as fh:
                fh.write(pcap(endian, magic, lt, [(1, frac, data),
                                                  (2, frac, data)]))
            try:
                got = pcapread.read_frames(path)
            except pcapread.PcapError as e:
                check(False, f"pcapread {label}: {e}")
                continue
            check(len(got) == 2, f"pcapread {label}: {len(got)} records")
            check(abs(got[0][0] - want_ts) < 1e-6,
                  f"pcapread {label}: ts {got[0][0]} != {want_ts}")
            check(got[0][1][12:] == frame[12:],
                  f"pcapread {label}: frame payload changed")


def test_build_run_args_round_trip() -> None:
    import shlex
    import shutil
    import subprocess
    from tgt import cli, service
    with tempfile.TemporaryDirectory() as d:
        evil = os.path.join(d, "my caps", "it's $(touch PWNED) `x`.pcap")
        out = os.path.join(d, "out dir", "o.pcap")
        args = service.build_run_args(
            None, [], 37.5, 7, replay=evil, replay_realtime=True, pcap=out,
            once=True, client_ip="192.0.2.1", server_ip="192.0.2.2")
        ns = cli.build_parser().parse_args(["run"] + shlex.split(args))
        check(ns.replay == evil and ns.replay_realtime and ns.pcap == out
              and ns.once and ns.rate == 37.5 and ns.messages == 7
              and ns.client_ip == "192.0.2.1" and ns.server_ip == "192.0.2.2",
              f"build_run_args round trip lost options: {args}")
        args2 = service.build_run_args(
            "ot-baseline", ["modbus"], 50, 5, sprinkle=["wannacry", "triton"],
            sprinkle_ratio=0.05, client_ip="10.10.10.10")
        ns = cli.build_parser().parse_args(["run"] + shlex.split(args2))
        check(ns.scenario == "ot-baseline"
              and ns.sprinkle == ["wannacry,triton"]
              and ns.sprinkle_ratio == 0.05 and not ns.once
              and ns.pcap is None and ns.client_ip == "10.10.10.10",
              f"build_run_args scenario round trip: {args2}")
        check("--client-ip" not in args2, "default client IP should be omitted")
        # the config file is shell-sourced: values must stay data
        conf = os.path.join(d, "etc tgt", "tgt.conf")
        ok, msg = service.write_config("tgt0", args, path=conf)
        check(ok, f"write_config: {msg}")
        rc = service.read_config(conf)
        check(rc.get("TGT_IFACE") == "tgt0" and rc.get("TGT_RUN_ARGS") == args,
              "read_config does not undo write_config quoting")
        sh = shutil.which("sh")
        if sh:      # what tgtctl.sh / the systemd unit do with the file
            r = subprocess.run(
                [sh, "-c", '. "$1" && eval "set -- $TGT_RUN_ARGS" && '
                 'printf "%s\\n" "$TGT_IFACE" "$@"', "sh", conf],
                cwd=d, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True, timeout=10)
            got = r.stdout.splitlines()
            check(r.returncode == 0 and got == ["tgt0"] + shlex.split(args),
                  f"sourced config argv mismatch: {got} {r.stderr}")
            check(not os.path.exists(os.path.join(d, "PWNED")),
                  "sourcing the config executed a $(...) in a value")


def test_version_single_source() -> None:
    import re
    import tgt
    from tgt import cli
    check(cli.VERSION == tgt.__version__, "cli VERSION != tgt.__version__")
    try:
        with open(os.path.join(_REPO, "pyproject.toml")) as fh:
            toml = fh.read()
    except OSError:
        return                              # installed without the sdist
    check(not re.search(r'^version\s*=\s*"', toml, re.M)
          and 'dynamic = ["version"]' in toml
          and 'attr = "tgt.__version__"' in toml,
          "pyproject.toml must take its version from tgt.__version__")


# --- tgt score (W2-F, #55) ------------------------------------------------
_SCORE_FIX = os.path.join(_REPO, "tests", "fixtures", "score")


def _score_fixture(mode: str, **kw):
    from tgt import score as S
    truth = S.load_truth(os.path.join(
        _SCORE_FIX, "manifest.json" if mode == "manifest"
        else "truth-inventory.json"))
    rows, info = S.read_export(os.path.join(_SCORE_FIX, "export-ctd.csv"),
                               S.load_json_spec("claroty-ctd"))
    info.update(source="export-ctd.csv", map="claroty-ctd.json")
    alerts = S.read_alerts(os.path.join(_SCORE_FIX, "alerts.csv"),
                           S.load_json_spec("alerts-generic"))
    return S.score(truth, rows, info, zeek=os.path.join(_SCORE_FIX, "zeek"),
                   alerts=alerts, **kw)


def test_score_normalisation_helpers() -> None:
    from tgt import score as S
    for raw in ("00-1D-9C-00-70-21", "001d.9c00.7021", "001D9C007021"):
        check(S.norm_mac(raw) == "00:1d:9c:00:70:21", f"norm_mac {raw}")
    check(S.norm_ip("10.1.2.3/24") == "10.1.2.3" and S.norm_ip("x") is None,
          "norm_ip")
    for raw, want in (("EtherNet/IP", "enip"), ("CIP", "enip"),
                      ("enip-id 44818/tcp", "enip"), ("S7Comm", "s7comm"),
                      ("s7-id", "s7comm"), ("Modbus/TCP", "modbus"),
                      ("IEC 60870-5-104", "iec104"), ("TLS", "https"),
                      ("edr", "https"), ("OPC UA", "opcua")):
        check(S.norm_protocol(raw) == want,
              f"norm_protocol({raw!r}) = {S.norm_protocol(raw)!r}")
    cases = (("vendor", "Siemens AG", ["Siemens"], "correct"),
             ("vendor", "Rockwell Automation", ["Rockwell"], "partial"),
             ("model", "1756-L83E/B", ["1756-L83E"], "partial"),
             ("model", " 1756-l83e ", ["1756-L83E"], "correct"),
             ("firmware", "3.2.8", ["V3.2.8"], "correct"),
             ("firmware", "V3.2.6", ["V3.2.8"], "wrong"),
             ("serial", "0x9b6bd709", ["9B6BD709"], "correct"),
             ("os", "Windows 10 Pro", ["Windows 10"], "partial"))
    for f, got, cands, want in cases:
        check(S.compare(f, got, cands) == want,
              f"compare {f} {got!r} vs {cands}: {S.compare(f, got, cands)}")
    t = S.parse_time("2026-11-05T14:00:00.5Z")
    check(t is not None and t.microsecond == 500000 and
          S._iso(t) == "2026-11-05T14:00:00.500000Z", f"parse_time iso {t}")
    check(S.parse_time("2026-11-05 16:00:00+02:00") ==
          S.parse_time("2026-11-05T14:00:00Z") ==
          S.parse_time(1793887200) == S.parse_time("1793887200000") ==
          S.parse_time("11/05/2026 14:00:00"), "parse_time formats")
    check(S.parse_time("2026-11-05 15:00:00", S._offset("+01:00")) ==
          S.parse_time("2026-11-05T14:00:00Z"), "parse_time utc_offset")


def test_score_inventory_truth_exact() -> None:
    r = _score_fixture("inventory")
    d = r["discovery"]
    check((d["population"], d["found"], d["recall"]) == (9, 8, 0.8889),
          f"score inv recall: {d['population']} {d['found']} {d['recall']}")
    check((d["matched_assets"], d["duplicates"], d["false_positives"],
           d["precision"], d["infrastructure"], d["external"]) ==
          (8, 1, 1, 0.8, 2, 1), f"score inv precision/buckets: {d}")
    check(d["by_method"] == {"mac": 4, "vlan-ip": 2, "ip": 1, "name": 1},
          f"score match methods: {d['by_method']}")
    check(d["missed"] == ["industrial-site:ENG02"], f"missed {d['missed']}")
    check([x["row"] for x in d["duplicate_rows"]] == [5] and
          [x["row"] for x in d["false_positive_rows"]] == [12] and
          [x["row"] for x in d["infrastructure_rows"]] == [9, 10] and
          [x["row"] for x in d["external_rows"]] == [11],
          "score bucket rows")
    want = {"vendor": ((7, 6, 0, 1, 0), (1, 1, 1, 0, 0)),
            "model": ((2, 1, 1, 0, 0), (6, 3, 1, 2, 0)),
            "firmware": ((2, 1, 0, 1, 0), (5, 1, 1, 0, 0)),
            "serial": ((2, 1, 0, 0, 1), (2, 0, 0, 0, 0)),
            "os": ((7, 1, 1, 1, 4), (1, 0, 0, 0, 0))}
    for f, (ob, inf) in want.items():
        o, i = r["fields"][f]["observable"], r["fields"][f]["inferred"]
        got = ((o["n"], o["correct"], o["partial"], o["wrong"],
                o["missing"]),
               (i["n"], i["reported"], i["correct"], i["partial"],
                i["wrong"]))
        check(got == (ob, inf), f"score field {f}: {got} != {(ob, inf)}")
    check(r["fields"]["vendor"]["observable"]["accuracy"] == 0.8571 and
          r["fields"]["model"]["observable"]["accuracy_with_partial"] == 1.0,
          "score field accuracy ratios")
    p = r["protocols"]
    check((p["assets"], p["tp"], p["exported"], p["truth"], p["precision"],
           p["recall"]) == (8, 15, 16, 25, 0.9375, 0.6),
          f"score protocols {p}")
    pk1 = next(a for a in r["assets"] if a["name"] == "PLC-PK1")
    check(pk1["protocols"]["extra"] == ["modbus"] and
          pk1["protocols"]["missing"] == ["icmp"] and pk1["rows"] == [4, 5]
          and pk1["fields"]["model"]["outcome"] == "partial",
          f"score PLC-PK1 detail {pk1}")
    check(r["new_assets"] == {"total": 1, "missed": [], "detected":
                              ["industrial-site:SIS-TRICONEX"]},
          f"score new assets {r['new_assets']}")
    check(r["time_to_discover"] is None, "inventory truth has no ttd")
    b = r["baseline"]
    check((b["expected"], b["seen"], b["coverage"], b["conn_records"]) ==
          (8, 6, 0.75, 9), f"score baseline {b['expected']} {b['seen']}")
    check(sorted((m["client"], m["server"], m["protocol"])
                 for m in b["missed"]) ==
          [("WS20", "3.122.135.178", "edr"), ("WS20", "DC01", "ntp")],
          f"score baseline missed {b['missed']}")
    check([(u["orig"], u["resp"], u["dport"], u["conns"])
           for u in b["unexpected"]] ==
          [("10.10.20.20", "10.100.10.21", 44818, 2),
           ("10.100.10.10", "10.100.10.99", 502, 1)],
          f"score unexpected {b['unexpected']}")
    check("note" in r["detections"], "inventory truth cannot score alerts")


def test_score_manifest_truth_exact() -> None:
    r = _score_fixture("manifest")
    d = r["discovery"]
    check((d["population"], d["found"], d["recall"], d["precision"]) ==
          (8, 7, 0.875, 0.8), f"score manifest discovery {d}")
    rtu = next(a for a in r["assets"] if a["name"] == "RTU-104")
    check(rtu["status"] == "found (not emitted)", f"RTU-104 {rtu['status']}")
    check(r["time_to_discover"] == {"n": 5, "median_s": 30.0,
                                    "min_s": 10.0, "max_s": 80.0},
          f"score ttd {r['time_to_discover']}")
    b = r["baseline"]
    check((b["basis"], b["expected"], b["seen"], len(b["unexpected"])) ==
          ("manifest flows_seen", 5, 4, 4), f"score manifest baseline {b}")
    det = r["detections"]
    check((det["events"], det["detected"], det["rate"], det["median_ttd_s"],
           det["alerts"], det["mapped_alerts"], det["matched_alerts"],
           det["unmapped_alerts"]) == (5, 3, 0.6, 30.0, 6, 5, 3, 1),
          f"score detections {det}")
    check([e["id"] for e in det["missed"]] == ["e3", "e5"] and
          [a["row"] for a in det["false_alerts"]] == [3, 6],
          "score detection misses / false alerts")
    pc = det["per_category"]
    check(pc["plc-program"]["median_ttd_s"] == 55.0 and
          pc["scan"]["rate"] == 0.0 and pc["ot-write"]["detected"] == 1,
          f"score per-category {pc}")
    # a longer tolerance lets the late scan alert count
    r2 = _score_fixture("manifest", tolerance=600.0)
    check(r2["detections"]["detected"] == 4 and
          r2["detections"]["per_category"]["scan"]["median_ttd_s"] == 600.0,
          "score tolerance widens the detection window")


def test_score_inventory_self_score_is_perfect() -> None:
    import io
    import json
    from tgt import enterprise, inventory
    from tgt import score as S
    env = enterprise.get("industrial-site")
    buf = io.StringIO()
    inventory.write_csv(env, buf, ["triton"])
    with tempfile.TemporaryDirectory() as d:
        csv_path = os.path.join(d, "inv.csv")
        with open(csv_path, "w") as f:
            f.write(buf.getvalue())
        truth = S.Truth(json.loads(json.dumps(
            inventory.to_json(env, ["triton"]))), "live")
        rows, info = S.read_export(csv_path, S.load_json_spec("generic"))
        info.update(source=csv_path, map="generic.json")
        r = S.score(truth, rows, info)
    d = r["discovery"]
    check(d["recall"] == 1.0 and d["precision"] == 1.0 and
          d["population"] == len(env.hosts) + 1,
          f"self-score discovery {d['recall']} {d['precision']}")
    for f, v in r["fields"].items():
        o = v["observable"]
        check(o["wrong"] == 0 and o["partial"] == 0,
              f"self-score field {f}: {o}")
    check(r["new_assets"]["missed"] == [], "self-score new assets")


def test_score_zeek_json_and_known_hosts() -> None:
    import json
    from tgt import score as S
    truth = S.load_truth(os.path.join(_SCORE_FIX, "truth-inventory.json"))
    tsv = S.read_zeek(os.path.join(_SCORE_FIX, "zeek", "conn.log"))
    check(len(tsv) == 9 and tsv[2]["duration"] is None and
          tsv[0]["id.resp_p"] == "88", "read_zeek TSV unset/fields")
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "conn.log"), "w") as f:
            for row in tsv:
                f.write(json.dumps(row) + "\n")
        check(S.baseline(truth, d)["seen"] == 6, "baseline from JSON conn.log")
        kh = os.path.join(d, "known_hosts.log")
        with open(kh, "w") as f:
            f.write("#separator \\x09\n#fields\tts\thost\n"
                    "#types\ttime\taddr\n"
                    "1793887205.000000\t10.10.10.10\n"
                    "1793887212.500000\t10.100.10.21\n"
                    "1793887213.000000\t10.100.10.99\n")
        rows, info = S.read_export(kh, S.load_json_spec("zeek-known-hosts"))
        info.update(source=kh, map="zeek-known-hosts.json")
        man = S.load_truth(os.path.join(_SCORE_FIX, "manifest.json"))
        r = S.score(man, rows, info)
        check((r["discovery"]["found"], r["discovery"]["false_positives"])
              == (2, 1), f"known_hosts discovery {r['discovery']}")
        check(r["time_to_discover"]["median_s"] == 5.25 and
              r["fields"]["vendor"]["exported"] is False and
              r["protocols"] is None, f"known_hosts ttd {r['time_to_discover']}")
        # JSON export through a json_path
        js = os.path.join(d, "assets.json")
        with open(js, "w") as f:
            json.dump({"result": [{"ip": ["10.100.10.21"], "vendor":
                                   "Rockwell Automation",
                                   "protocols": ["CIP", "NTP"]}]}, f)
        m = {"format": "json", "json_path": "result",
             "columns": {"ip": "ip", "vendor": "vendor",
                         "protocols": "protocols"},
             "normalize": {"vendor": {"rockwell automation": "Rockwell"}}}
        rows, info = S.read_export(js, m)
        check(rows[0]["ips"] == ["10.100.10.21"] and
              rows[0]["vendor"] == "Rockwell" and
              rows[0]["protocols"] == ["enip", "ntp"],
              f"json export rows {rows}")


def test_score_cli_reports() -> None:
    with tempfile.TemporaryDirectory() as d:
        js, ht = os.path.join(d, "r.json"), os.path.join(d, "r.html")
        p = _cli(["score", "--manifest",
                  os.path.join(_SCORE_FIX, "manifest.json"), "--assets",
                  os.path.join(_SCORE_FIX, "export-ctd.csv"), "--map",
                  "claroty-ctd", "--zeek", os.path.join(_SCORE_FIX, "zeek"),
                  "--alerts", os.path.join(_SCORE_FIX, "alerts.csv"),
                  "--alert-map", "alerts-generic", "--json", js,
                  "--html", ht])
        out, _ = p.communicate(timeout=30)
        check(p.returncode == 0, f"tgt score rc={p.returncode}: {out[-400:]}")
        check("recall 7/8 87.5%" in out and "3/5 events (60.0%)" in out,
              f"tgt score summary: {out}")
        import json
        with open(js) as f:
            r = json.load(f)
        with open(ht) as f:
            page = f.read()
        check(r["schema"] == "tgt-score/1" and
              r["discovery"]["precision"] == 0.8, "tgt score --json")
        check(page.startswith("<!doctype html>") and "<script" not in page
              and "prefers-color-scheme:dark" in page and
              "industrial-site:ENG02" in page and "Missed events" in page,
              "tgt score --html")
        bad = _cli(["score", "--truth", os.path.join(d, "nope.json"),
                    "--assets", "x.csv", "--map", "generic"])
        out, _ = bad.communicate(timeout=30)
        check(bad.returncode == 2 and "tgt score:" in out,
              f"tgt score bad input rc={bad.returncode}")

# ---- per-cycle variation, --seed, run manifest (#24, #54) -------------------
def _syns(batch) -> list:
    """(src ip, dst ip, sport, dport, seq) of every bare TCP SYN in a batch."""
    out = []
    for item in batch:
        f = item[1]
        off = 18 if f[12:14] == b"\x81\x00" else 14
        if f[off - 2:off] != b"\x08\x00" or f[off + 9] != P.IPPROTO_TCP:
            continue
        t = off + (f[off] & 0x0F) * 4
        if f[t + 13] == P.SYN:
            sp, dp, seq = struct.unpack("!HHI", f[t:t + 8])
            out.append((f[off + 12:off + 16], f[off + 16:off + 20], sp, dp, seq))
    return out


def test_seeded_cycles_are_deterministic() -> None:
    from tgt.engine import CycleBuilder
    cfg = RunConfig(env="ot-plant", sprinkle=["triton"], messages=3, seed=7)
    a, b = CycleBuilder(cfg, 7), CycleBuilder(cfg, 7)
    for c in (0, 2, 1):                       # order of builds must not matter
        check(a.build(c) == b.build(c), f"seed 7 cycle {c} not reproducible")
    check(CycleBuilder(cfg, 8).build(2) != a.build(2),
          "different seeds built identical cycles")
    check(build_batch(cfg) == build_batch(cfg),
          "build_batch with cfg.seed not deterministic")


def test_cycles_vary_ports_isns_and_values() -> None:
    from tgt.engine import CycleBuilder
    cb = CycleBuilder(RunConfig(env="ot-plant", messages=3), 11)
    one, two = cb.build(1), cb.build(2)
    s1, s2 = _syns(one), _syns(two)
    check(len(s1) == len(s2) > 0, "cycles differ in shape")
    check(not {x[2] for x in s1} & {x[2] for x in s2},
          "cycles 1 and 2 reuse source ports")
    check(not {x[4] for x in s1} & {x[4] for x in s2},
          "cycles 1 and 2 reuse TCP ISNs")
    check(len({x[4] for x in s1}) == len(s1), "ISNs repeat within a cycle")
    # the SYN|ACK ISN is random too (not the old fixed 5000)
    check(all(seq not in (1000, 5000) for *_, seq in s1), "fixed ISN left")
    # app-level counters continue across cycles: Modbus TIDs differ
    def tids(batch):
        out = set()
        for k, f, _ in batch:
            if k == "modbus" and len(f) > 70:
                off = 18 if f[12:14] == b"\x81\x00" else 14
                t = off + 20 + (f[off + 32] >> 4) * 4
                out.add(struct.unpack("!H", f[t:t + 2])[0])
        return out
    t1, t2 = tids(one), tids(two)
    check(t1 and t2 and not t1 & t2, f"modbus TIDs repeat across cycles {t1}")


def test_no_tcp_4tuple_reuse_across_cycles() -> None:
    from tgt.engine import CycleBuilder
    cb = CycleBuilder(RunConfig(env="industrial-site", sprinkle=["wannacry"],
                                messages=2), 3)
    tuples = []
    for c in range(3):
        tuples += [x[:4] for x in _syns(cb.build(c))]
    check(len(tuples) == len(set(tuples)),
          f"{len(tuples) - len(set(tuples))} TCP 4-tuples reused in 3 cycles")


def _manifest_run(d: str, name: str, cfg: RunConfig, count: int) -> dict:
    import json
    from tgt.engine import Engine
    cfg.pcap_path = os.path.join(d, name + ".pcap")
    cfg.manifest_path = os.path.join(d, name + ".json")
    cfg.rate, cfg.count = 1000.0, count
    cfg.clock, cfg.start_time = "synthetic", "2026-11-05T14:00:00Z"
    eng = Engine(cfg, argv=["run", "--test"])
    eng.start()
    eng.join(60)
    with open(cfg.manifest_path) as fh:
        return json.load(fh)


def test_run_manifest_contract() -> None:
    from tgt import enterprise, incidents, manifest
    from tgt.engine import build_batch as bb
    env = enterprise.get("it-org")
    n = len(bb(RunConfig(env="it-org", sprinkle=["wannacry"], messages=2)))
    with tempfile.TemporaryDirectory() as d:
        cfg = RunConfig(env="it-org", sprinkle=["wannacry"], messages=2,
                        seed=5)
        m = _manifest_run(d, "a", cfg, 2 * n)
        want = {"schema", "tool", "seed", "argv", "config", "env", "span",
                "iface", "pcap", "start", "end", "clock", "packets", "bytes",
                "errors", "cycles", "inventory", "first_seen", "last_seen",
                "flows_seen", "phases", "events"}
        check(want <= set(m), f"manifest missing {want - set(m)}")
        check(m["schema"] == "tgt-manifest/1" and m["seed"] == 5
              # cycle sizes vary (per-OS stacks: RST closes, delayed ACKs), so
              # 2n packets may spill into a third cycle
              and m["clock"] == "synthetic" and m["cycles"] in (2, 3)
              and m["packets"] == 2 * n and m["argv"] == ["run", "--test"],
              "manifest header fields wrong")
        check(m["start"] == "2026-11-05T14:00:00.000000Z", m["start"])
        check(m["inventory"] and m["inventory"]["env"] == "it-org",
              "manifest inventory missing")
        ids = {f"it-org:{h.name}" for h in env.hosts}
        seen = set(m["first_seen"])
        check(seen & ids and len(seen & ids) >= len(ids) - 2,
              f"first_seen misses hosts: {sorted(ids - seen)}")
        check(all(m["first_seen"][k] <= m["last_seen"][k] for k in seen),
              "first_seen after last_seen")
        f0 = m["flows_seen"][0]
        check({"client", "server", "protocol", "first", "last", "packets"}
              <= set(f0), "flows_seen row keys")
        check(any(f["protocol"] == "smb" and f["source"] == "baseline"
                  for f in m["flows_seen"]), "no baseline SMB flow")
        # every sprinkled attack flow is one event, on the mapped hosts
        mp = incidents.get("wannacry").map_onto(env)
        inc = incidents.get("wannacry")
        evs = [e for e in m["events"] if e["source"] == "sprinkle:wannacry"
               and e["category"] != "new-asset"]
        check(len(evs) == len(inc.flows), f"{len(evs)} wannacry events")
        for (a, v, atk, _), e in zip(inc.flows, evs):
            ah, vh = mp.get(a) or inc.host(a), mp.get(v) or inc.host(v)
            check(e["category"] == manifest.ATTACK_CATEGORY[atk]
                  and e["hosts"] == [f"it-org:{ah.name}", f"it-org:{vh.name}"]
                  and e["src"] == ah.ip and e["dst"] == vh.ip
                  and e["t_start"] <= e["t_end"],
                  f"event for {atk} {a}->{v} wrong: {e}")
        check(m["events"][0]["id"] == "e1", "event ids")
        # a second run with the same seed: identical pcap and ground truth
        m2 = _manifest_run(d, "b", RunConfig(env="it-org", messages=2,
                           sprinkle=["wannacry"], seed=5), 2 * n)
        with open(os.path.join(d, "a.pcap"), "rb") as x, \
                open(os.path.join(d, "b.pcap"), "rb") as y:
            check(x.read() == y.read(), "same seed: pcaps differ")
        check(m2["events"] == m["events"]
              and m2["flows_seen"] == m["flows_seen"],
              "same seed: manifests differ")


def test_attack_categories_cover_every_attack() -> None:
    from tgt import incidents, manifest
    allowed = {"new-asset", "asset-offline", "ip-change", "firmware-change",
               "new-conversation", "cross-zone", "new-protocol", "ot-write",
               "plc-mode-change", "plc-program", "scan", "c2",
               "exploit-attempt", "lateral-movement", "remote-access",
               "legacy-os", "default-credentials", "cleartext-credentials"}
    missing = set(incidents.ATTACKS) - set(manifest.ATTACK_CATEGORY)
    check(not missing, f"manifest.ATTACK_CATEGORY lacks {sorted(missing)}")
    check(set(manifest.ATTACK_CATEGORY.values()) <= allowed,
          "non-generic manifest category")


def test_seed_flags_and_default_seed() -> None:
    from tgt import cli
    from tgt.engine import Engine
    ns = cli.build_parser().parse_args(
        ["run", "--seed", "9", "--manifest", "m.json", "--clock",
         "synthetic", "--start-time", "2026-11-05T14:00:00Z"])
    check(ns.seed == 9 and ns.manifest == "m.json" and ns.clock == "synthetic",
          "run --seed/--manifest/--clock not parsed")
    with tempfile.TemporaryDirectory() as d:
        cfg = RunConfig(profiles=["modbus"], messages=1, loop=False, rate=0,
                        pcap_path=os.path.join(d, "x.pcap"))
        logs: list = []
        eng = Engine(cfg, on_log=logs.append)
        eng.start()
        eng.join(20)
        check(eng.stats.seed is not None
              and any(f"seed {eng.stats.seed}" in m for m in logs),
              "unseeded run did not pick + log a seed")


def test_score_recall_ignores_external_first_seen() -> None:
    """Manifest first_seen keys for the EDR cloud / C2 (public IPs) are not
    assets: they must not inflate the recall denominator."""
    from tgt import inventory as inv, score
    from tgt import enterprise as ent
    doc = inv.to_json(ent.get("ot-plant"))
    fs = {h["asset_id"]: "2026-11-05T00:00:00.000000Z" for h in doc["hosts"]}
    fs["3.121.6.180"] = fs["198.51.100.7"] = "2026-11-05T00:00:01.000000Z"
    m = {"schema": "tgt-manifest/1", "inventory": doc, "first_seen": fs,
         "start": "2026-11-05T00:00:00Z", "end": "2026-11-05T00:01:00Z"}
    t = score.Truth(m, "test")
    emitted = [a for a in t.assets if a.get("emitted")]
    check(len(emitted) == len(doc["hosts"]),
          f"external first_seen counted as assets: {len(emitted)}")
    v = {h["name"]: h["observability"]["vendor"] for h in doc["hosts"]}
    dc = next(n for n, o in v.items() if o["evidence"] == ["oui"])
    row = next(h for h in doc["hosts"] if h["name"] == dc)
    check(v[dc]["value"] == row["mac_vendor"],
          "OUI-only vendor truth should be the NIC vendor")

# --- remote access / file transfer / vendor engineering (protocols_eng) ----
_ENG_KEYS = ("ftp", "tftp", "http-fw", "ssh", "rdp", "vnc", "telnet",
             "s7plus", "fins", "slmp", "hart-ip", "srtp")
# s7plus / slmp / srtp have no stock Wireshark dissector: the carrier layer
_DISSECTS_AS.update({
    "ftp": "ftp-data", "tftp": "tftp", "http-fw": "mime_multipart",
    "ssh": "ssh", "rdp": "rdp", "vnc": "vnc", "telnet": "telnet",
    "s7plus": "cotp", "fins": "omron", "slmp": "tcp", "hart-ip": "hart_ip",
    "srtp": "tcp",
})


def _payloads(frames, from_port=None, to_port=None) -> list:
    """Non-empty TCP/UDP payloads of untagged IPv4 frames, optionally
    filtered by source / destination port."""
    out = []
    for f in frames:
        ihl = (f[14] & 0x0F) * 4
        sp, dp = struct.unpack("!HH", f[14 + ihl:18 + ihl])
        if from_port is not None and sp != from_port:
            continue
        if to_port is not None and dp != to_port:
            continue
        pl = _udp_tcp_payload(f)
        if pl:
            out.append(pl)
    return out


def test_eng_protocols_registered_and_framed() -> None:
    for key in _ENG_KEYS:
        check(key in protocols.PROFILES, f"protocol {key} not registered")
    check(protocols.get("tftp").transport == "udp"
          and protocols.get("fins").transport == "udp", "tftp/fins not udp")
    for key in ("remote-access", "firmware-update", "multi-vendor-ot"):
        check(key in scenarios.SCENARIOS, f"scenario {key} missing")
        for p in scenarios.get(key).profiles if key in scenarios.SCENARIOS else ():
            check(p in protocols.PROFILES, f"{key}: unknown profile {p}")
    for key in _ENG_KEYS:
        frames = protocols.get(key).build(Endpoints(), 5)
        check(bool(frames), f"{key}: no frames")
        for f in frames:
            verify_ip_l4(f, key)
            check(len(f) <= 1514, f"{key}: {len(f)}-byte frame exceeds MTU")


def test_eng_file_transfer_and_remote_access_wire() -> None:
    ep = Endpoints()
    # FTP: cleartext login; each PASV port carries a data connection
    fr = protocols.get("ftp").build(ep, 2)
    ctl = b"".join(_payloads(fr, to_port=21) + _payloads(fr, from_port=21))
    check(b"USER admin\r\n" in ctl and b"PASS " in ctl and b"SYST" in ctl,
          "ftp: login/SYST missing")
    import re
    ports = [int(a) * 256 + int(b) for a, b in
             re.findall(rb"227 Entering Passive Mode \(\d+,\d+,\d+,\d+,"
                        rb"(\d+),(\d+)\)", ctl)]
    syn_ports = {struct.unpack("!H", f[36:38])[0] for f in fr
                 if f[47] == P.SYN}
    check(len(ports) == 2 and set(ports) <= syn_ports,
          "ftp: PASV ports have no data connection")
    check(b"STOR " in ctl and b"RETR " in ctl, "ftp: RETR/STOR missing")
    # TFTP: RRQ to 69, answered from a new TID, ends in a short block
    fr = protocols.get("tftp").build(ep, 2)
    rrq = _payloads(fr, to_port=69)
    check(rrq and rrq[0][:2] == b"\x00\x01" and b"octet" in rrq[0]
          and _payloads(fr, to_port=69)[1][:2] == b"\x00\x02",
          "tftp: RRQ/WRQ missing")
    data = [p for p in _payloads(fr) if p[:2] == b"\x00\x03"]
    check(data and len(data[0]) == 516 and any(len(d) < 516 for d in data),
          "tftp: DATA blocks not 512 bytes + short final block")
    check(not _payloads(fr, from_port=69), "tftp: server answered from 69")
    # HTTP firmware upload with Basic auth
    req = b"".join(_payloads(protocols.get("http-fw").build(ep, 2), to_port=80))
    check(b"POST /cgi-bin/firmware_upgrade.cgi" in req and b"PUT " in req
          and b"Authorization: Basic " in req and b"FWUP" in req,
          "http-fw: upload request incomplete")
    # SSH: per-side KEXINIT, server implementation follows the meta
    for meta, banner in (({}, b"OpenSSH_8.9p1"),
                         ({"vendor": "Cisco Systems"}, b"Cisco-1.25"),
                         ({"vendor": "Moxa"}, b"dropbear_"),
                         ({"server": "Microsoft-IIS/10.0"},
                          b"OpenSSH_for_Windows")):
        fr = protocols.get("ssh").build(Endpoints(meta=meta), 2)
        srv = b"".join(_payloads(fr, from_port=22))
        cli = b"".join(_payloads(fr, to_port=22))
        check(srv.startswith(b"SSH-2.0-") and banner in srv.split(b"\r\n")[0],
              f"ssh {meta}: server banner not {banner!r}")
        check(b"\x14" in srv and b"\x14" in cli and
              srv[srv.index(b"\r\n") + 7:][:1] == b"\x14",
              f"ssh {meta}: KEXINIT missing")
    # RDP: CR with cookie + NEG_REQ(SSL|HYBRID), CC selecting HYBRID, TLS
    fr = protocols.get("rdp").build(Endpoints(meta={"host": "HMI01"}), 2)
    cr = _payloads(fr, to_port=3389)[0]
    cc = _payloads(fr, from_port=3389)[0]
    check(cr[5] == 0xE0 and b"Cookie: mstshash=" in cr and
          cr[-8:] == struct.pack("<BBHI", 1, 0, 8, 3), "rdp: X.224 CR wrong")
    check(cc[5] == 0xD0 and cc[-8] == 0x02 and
          struct.unpack("<I", cc[-4:])[0] == 2, "rdp: NEG_RSP not HYBRID")
    srv = b"".join(_payloads(fr, from_port=3389)[1:])
    check(srv[:1] == b"\x16" and b"HMI01" in srv, "rdp: no TLS cert flight")
    # VNC: RFB 3.8 both ways, ServerInit desktop name
    fr = protocols.get("vnc").build(Endpoints(meta={"host": "HMI-7"}), 2)
    s_pl, c_pl = _payloads(fr, from_port=5900), _payloads(fr, to_port=5900)
    check(s_pl[0] == c_pl[0] == b"RFB 003.008\n", "vnc: version exchange")
    check(any(p.endswith(b"\x00\x00\x00\x05HMI-7") for p in s_pl),
          "vnc: ServerInit desktop name missing")
    # Telnet: IAC negotiation, cleartext login
    fr = protocols.get("telnet").build(ep, 2)
    s_pl, c_pl = _payloads(fr, from_port=23), _payloads(fr, to_port=23)
    check(s_pl[0][:2] == b"\xff\xfd" and c_pl[0][:2] == b"\xff\xfb",
          "telnet: DO/WILL negotiation missing")
    check(b"login: " in b"".join(s_pl) and b"admin\r\n" in c_pl,
          "telnet: login exchange missing")


def test_eng_vendor_protocols_wire() -> None:
    from tgt import devices
    # S7CommPlus: 0x72 header length matches, trailer follows
    fr = protocols.get("s7plus").build(Endpoints(), 3)
    pdus = [p for p in _payloads(fr) if p[4] == 0x02 and p[7] == 0x72]
    check(len(pdus) >= 6, "s7plus: too few 0x72 PDUs")
    for p in pdus:
        ver, ln = p[8], struct.unpack("!H", p[9:11])[0]
        check(p[11 + ln:] == bytes([0x72, ver, 0, 0]) and
              struct.unpack("!H", p[2:4])[0] == len(p),
              "s7plus: PDU length / trailer mismatch")
    check(b"6ES7 516-3AN01-0AB0" in b"".join(pdus),
          "s7plus: CreateObject response lacks the order number")
    # catalog identity flows into FINS / SLMP / HART-IP
    for mid, key, needle in (("omron-nj501-1500", "fins", b"NJ501-1500"),
                             ("mitsubishi-r04cpu", "slmp", b"R04CPU"),
                             ("mitsubishi-q03udvcpu", "slmp",
                              b"Q03UDVCPU       \x66\x03")):
        m = devices.get(mid)
        meta = devices.identity_meta(m, m.firmware[0], "1234567890")
        wire = b"".join(_payloads(protocols.get(key).build(
            Endpoints(meta=meta), 2)))
        check(needle in wire, f"{key}: {mid} identity not on the wire")
    m = devices.get("emerson-1410s-gateway")
    meta = devices.identity_meta(m, m.firmware[0], "7654321")
    check(meta.get("hart_manufacturer_id") == 0x26
          and meta.get("hart_device_id") == 7654321 % (1 << 24),
          "hart: identity_meta keys missing")
    # FINS: response ICF / swapped nodes / same SID
    fr = protocols.get("fins").build(Endpoints(), 4)
    pl = _payloads(fr)
    for req, rsp in zip(pl[::2], pl[1::2]):
        check(req[0] == 0x80 and rsp[0] == 0xC0 and req[9] == rsp[9] and
              req[4] == rsp[7] and req[7] == rsp[4] and req[10:12] == rsp[10:12]
              and rsp[12:14] == b"\x00\x00", "fins: request/response mismatch")
    # SLMP 3E: subheaders and request-data length
    for p in _payloads(protocols.get("slmp").build(Endpoints(), 6)):
        check(p[:2] in (b"\x50\x00", b"\xd0\x00") and
              struct.unpack("<H", p[7:9])[0] == len(p) - 9,
              "slmp: 3E header length wrong")
    # HART-IP: message length, HART checksum (XOR of the PDU is 0)
    for p in _payloads(protocols.get("hart-ip").build(Endpoints(), 6)):
        check(p[0] == 1 and struct.unpack("!H", p[6:8])[0] == len(p),
              "hart-ip: header length wrong")
        if p[2] == 3:
            x = 0
            for b in p[8:]:
                x ^= b
            check(x == 0, "hart-ip: HART PDU checksum wrong")
    # SRTP: 56-byte header, sequence at 2 and 30, text length at 4
    pl = _payloads(protocols.get("srtp").build(Endpoints(), 4))
    check(pl[0] == bytes(56) and pl[1][0] == 0x01, "srtp: init exchange")
    for p in pl[2:]:
        check(len(p) == 56 + struct.unpack("<H", p[4:6])[0] and p[2] == p[30]
              and p[31] in (0xC0, 0x94, 0xD4), "srtp: header fields wrong")


def test_tshark_eng_protocols_clean() -> None:
    """Optional: no per-packet Warn/Error expert info on the new builders
    (some dissectors, e.g. omron, do not report through ``-z expert``)."""
    import shutil
    import subprocess
    if not shutil.which("tshark"):
        _skipped.append("test_tshark_eng_protocols_clean")
        return
    with tempfile.TemporaryDirectory() as d:
        path = f"{d}/eng.pcap"
        with PcapWriter(path) as w:
            for key in _ENG_KEYS:
                for f in protocols.get(key).build(Endpoints(), 6):
                    w.write(f)
            for meta in ({"vendor": "Cisco Systems"}, {"vendor": "Moxa"},
                         {"ssh_client": "linux"}):
                for f in protocols.get("ssh").build(Endpoints(meta=meta), 2):
                    w.write(f)
        out = subprocess.run(
            ["tshark", "-r", path, "-2", "-Y",
             "_ws.expert.severity >= 6291456", "-T", "fields",
             "-e", "_ws.expert.message"],
            capture_output=True, text=True).stdout.split()
    check(not out, "eng protocols: tshark expert warnings: " +
          " ".join(out[:8]))

# ---------------------------------------------------------------------------
# W2-D: data-defined environments (#50) + topology realism (#52)
# ---------------------------------------------------------------------------
def _seeded_build(env, span="access"):
    """One deterministic cycle (ephemeral ports restart from a fixed value)."""
    protocols.begin_build(7, 0)      # same seed + cycle -> identical build
    return env.build(2, span=span)


def test_env_file_export_load_parity() -> None:
    """export -> load -> build gives the same frames and inventory for every
    built-in env; the shipped example files load and build."""
    import glob
    import json
    from tgt import enterprise, envfile, inventory
    for env in [e for e in enterprise.all_environments()
                if e.key in envfile.BUILTIN_KEYS]:
        text = envfile.export(env)
        back = envfile.loads(text, source=f"{env.key}.json")
        for span in ("access", "core"):
            check(_seeded_build(env, span) == _seeded_build(back, span),
                  f"env-file parity: {env.key} {span} frames differ")
        check(json.dumps(inventory.to_json(env)) ==
              json.dumps(inventory.to_json(back)),
              f"env-file parity: {env.key} inventory differs")
        check(envfile.to_dict(back) == envfile.to_dict(env),
              f"env-file parity: {env.key} re-export differs")
        check(back.protocols() == env.protocols(),
              f"env-file parity: {env.key} protocols differ")
    try:
        import tomllib  # noqa: F401
        exts = ("json", "toml")
    except ImportError:
        exts = ("json",)
    shipped = [f for x in exts for f in
               glob.glob(os.path.join(_REPO, "tgt", "envs", f"*.{x}"))]
    check(len(shipped) >= 5, f"tgt/envs/ examples missing: {shipped}")
    for path in shipped:
        env = envfile.load(path)
        check(len(env.build(1)) > 0, f"{path}: builds no frames")


def test_env_file_selectors_templates_timing() -> None:
    from tgt import devices, envfile
    doc = {
        "key": "t-sel", "category": "OT",
        "segments": [
            {"name": "OPS", "vlan": 100, "subnet": "10.9.0.0/24",
             "zone": "OT-SUPERVISORY"},
            {"name": "CELL", "vlan": 110, "subnet": "10.9.1.0/24",
             "zone": "OT-CELL", "gateway": "10.9.1.254"}],
        "hosts": [
            {"name": "HIST", "ip": "10.9.0.10", "role": "hist", "os": "linux"},
            {"name": "HMI{n}", "count": 2, "ip_start": "10.9.1.10",
             "role": "hmi", "os": "win10", "meta": {"ua": "X"}},
            {"name": "PLC-{n:02}", "count": 3, "start": 7,
             "ip_start": "10.9.1.21", "model": "rockwell-1756-l71"},
            {"name": "SW", "ip": "10.9.1.2", "model": "moxa-eds-508a",
             "mac": "00-90-E8-00-00-01"}],
        "flows": [
            {"from": "role:hmi@CELL", "to": "role:plc", "proto": "enip",
             "mode": "round-robin", "period": "1s±5%"},
            {"from": "HIST", "to": "PLC-*", "proto": "enip-id",
             "period": "500ms", "jitter": 0.1},
            {"from": "zone:OT-CELL", "to": "HIST", "proto": "ntp"},
            {"from": "model:moxa-eds-508a", "proto": "lldp"},
            {"from": "@OPS", "to": "SW", "proto": "snmp"}]}
    env = envfile.from_dict(doc, "t.json")
    names = [h.name for h in env.hosts]
    check(names == ["HIST", "HMI1", "HMI2", "PLC-07", "PLC-08", "PLC-09", "SW"],
          f"env-file host expansion: {names}")
    plc = env.host("PLC-08")
    dev = devices.get("rockwell-1756-l71")
    check((plc.ip, plc.role, plc.os, plc.vendor, plc.product, plc.model)
          == ("10.9.1.22", "plc", "rockwell", dev.vendor, dev.aliases[0],
              "rockwell-1756-l71"), "env-file model defaults wrong")
    check(plc.mac == "00:1d:9c:09:01:16", f"auto MAC {plc.mac}")
    check(env.host("SW").mac == "00:90:e8:00:00:01" and
          env.host("SW").role == "switch" and env.host("SW").os == "moxa",
          "explicit MAC / switch defaults")
    check(env.segments[1].gateway == "10.9.1.254" and
          env.segments[0].gateway == "10.9.0.1", "segment gateway default")
    conv = env.conversations
    rr = [c for c in conv if c[2] == "enip"]
    check(rr == [("HMI1", "PLC-07", "enip"), ("HMI2", "PLC-08", "enip"),
                 ("HMI1", "PLC-09", "enip")], f"round-robin pairs: {rr}")
    check(len([c for c in conv if c[2] == "enip-id"]) == 3, "glob selector")
    check({c[0] for c in conv if c[2] == "ntp"} ==
          {"HMI1", "HMI2", "PLC-07", "PLC-08", "PLC-09", "SW"}, "zone selector")
    check(("SW", "SW", "lldp") in conv and ("HIST", "SW", "snmp") in conv,
          "self / @segment selectors")
    check(env.timing[("HMI2", "PLC-08", "enip")] ==
          {"jitter": 0.05, "period": 1.0}, "period±jitter not parsed")
    check(env.timing[("HIST", "PLC-09", "enip-id")] ==
          {"period": 0.5, "jitter": 0.1}, "period/jitter not parsed")
    check(env.host_meta["HMI2"] == {"server": {"ua": "X"}}, "host meta")
    check(all(len(c) == 3 for c in conv), "Conversation tuple shape changed")
    again = envfile.loads(envfile.export(env), source="re")
    check(again.timing == env.timing and envfile.to_dict(again) ==
          envfile.to_dict(env), "timing/meta lost on re-export")
    check(_seeded_build(again) == _seeded_build(env), "re-export frames")


def test_env_file_schema_errors_are_clear() -> None:
    import copy
    import sys as _sys
    from tgt import envfile
    base = {"key": "t-err", "segments": [
        {"name": "A", "vlan": 10, "subnet": "10.8.0.0/24", "zone": "IT"}],
        "hosts": [{"name": "H1", "ip": "10.8.0.10", "role": "ws",
                   "os": "win10"},
                  {"name": "H2", "ip": "10.8.0.11", "role": "ws",
                   "os": "win10"}],
        "flows": [{"client": "H1", "server": "H2", "proto": "smb"}]}
    envfile.from_dict(copy.deepcopy(base), "ok.json")       # valid baseline
    cases = [
        (lambda d: d["hosts"][1].update(ip="10.8.0.300"), "hosts[1].ip"),
        (lambda d: d["hosts"][1].update(ip="10.7.0.5"), "hosts[1].ip"),
        (lambda d: d["hosts"][0].update(os="beos"), "hosts[0].os"),
        (lambda d: d["hosts"][0].update(model="nope"), "hosts[0].model"),
        (lambda d: d["hosts"][0].update(colour="red"), "hosts[0].colour"),
        (lambda d: d["hosts"][1].update(name="H1"), "duplicate host name"),
        (lambda d: d["hosts"][1].pop("role"), "hosts[1]: missing required"),
        (lambda d: d["segments"][0].update(vlan=5000), "segments[0].vlan"),
        (lambda d: d["segments"][0].update(zone="LAN"), "segments[0].zone"),
        (lambda d: d["segments"][0].update(subnet="10.8.0.5/24"),
         "segments[0].subnet"),
        (lambda d: d["segments"][0].update(gateway="10.9.0.1"),
         "segments[0].gateway"),
        (lambda d: d["flows"][0].update(proto="smtp"), "flows[0].proto"),
        (lambda d: d["flows"][0].update(server="H9"), "flows[0].server"),
        (lambda d: d["flows"].append({"from": "role:plc", "to": "H1",
                                      "proto": "modbus"}), "flows[1].from"),
        (lambda d: d["flows"].append({"from": "kind:x", "proto": "arp"}),
         "flows[1].from"),
        (lambda d: d["flows"][0].update(period="soon"), "flows[0].period"),
        (lambda d: d["hosts"].append({"name": "P", "count": 2,
                                      "ip_start": "10.8.0.40", "role": "plc",
                                      "os": "rockwell"}), "hosts[2].name"),
        (lambda d: d.update(options={"flat": "yes"}), "options.flat"),
        (lambda d: d.update(options={"dual_homed": [{"host": "H9",
                                                     "ip": "10.8.0.99"}]}),
         "options.dual_homed[0].host"),
        (lambda d: d.update(key="bad key"), "key"),
        (lambda d: d.update(category="ICS"), "category"),
    ]
    for mutate, want in cases:
        d = copy.deepcopy(base)
        mutate(d)
        try:
            envfile.from_dict(d, "site.json")
        except envfile.EnvFileError as e:
            check(str(e).startswith("site.json: ") and want in str(e),
                  f"schema error for {want!r} unclear: {e}")
        else:
            _failures.append(f"schema error not raised for {want!r}")
    # the Environment checks still apply (a link-local protocol across
    # segments), reported with the file name
    d = copy.deepcopy(base)
    d["segments"].append({"name": "B", "vlan": 20, "subnet": "10.8.1.0/24",
                          "zone": "IT"})
    d["hosts"][1]["ip"] = "10.8.1.11"
    d["flows"] = [{"client": "H1", "server": "H2", "proto": "lldp"}]
    try:
        envfile.from_dict(d, "site.json")
        _failures.append("cross-segment LLDP in an env file accepted")
    except envfile.EnvFileError as e:
        check("site.json" in str(e) and "link-local" in str(e), str(e))
    for bad, want in (("{\n  \"key\": ,", "line 2"), ("[]", "expected an object")):
        try:
            envfile.loads(bad, source="x.json")
            _failures.append(f"bad JSON accepted: {bad!r}")
        except envfile.EnvFileError as e:
            check(want in str(e), f"bad JSON message: {e}")
    # TOML without tomllib (Python 3.9/3.10) fails gracefully
    saved = _sys.modules.get("tomllib", "missing")
    _sys.modules["tomllib"] = None          # makes `import tomllib` fail
    try:
        envfile.loads("key = 'x'", "toml", source="x.toml")
        _failures.append("TOML without tomllib did not raise")
    except envfile.EnvFileError as e:
        check("Python 3.11" in str(e), f"TOML fallback message: {e}")
    finally:
        if saved == "missing":
            del _sys.modules["tomllib"]
        else:
            _sys.modules["tomllib"] = saved


def test_env_file_directories_cli_and_tui() -> None:
    import io
    import json
    import shutil
    import subprocess
    from tgt import enterprise, envfile, tui
    src = os.path.join(_REPO, "tgt", "envs", "example-site.json")
    with tempfile.TemporaryDirectory() as d:
        envdir = os.path.join(d, "envs")
        os.makedirs(envdir)
        shutil.copy(src, envdir)
        with open(os.path.join(envdir, "bad.json"), "w") as f:
            f.write('{"key": "x"}')
        shadow = json.loads(open(src).read())
        shadow["key"] = "it-org"
        with open(os.path.join(envdir, "shadow.json"), "w") as f:
            json.dump(shadow, f)
        old = os.environ.get("TGT_ENV_PATH")
        os.environ["TGT_ENV_PATH"] = envdir
        warnings: list = []
        try:
            got = envfile.load_user_envs(warn=warnings.append, force=True)
        finally:
            if old is None:
                del os.environ["TGT_ENV_PATH"]
            else:
                os.environ["TGT_ENV_PATH"] = old
        sites = sorted(os.path.splitext(f)[0]
                       for f in os.listdir(envfile.SITES_DIR)
                       if f.endswith(".json")) \
            if os.path.isdir(envfile.SITES_DIR) else []
        try:
            # packaged sites (tgt/envs/sites/<key>.json) load first
            check(got == sites + ["example-site"],
                  f"user envs loaded: {got}")
            check(len(warnings) == 2 and any("bad.json" in w for w in warnings)
                  and any("'it-org'" in w for w in warnings),
                  f"env dir warnings: {warnings}")
            check(enterprise.get("it-org") is not None and
                  envfile.source_of(enterprise.get("it-org")) is None,
                  "a directory file shadowed a built-in")
            ui = tui.UI()
            ui.engine = None
            keys = [c[1] for _, c, _, _ in tui._preset_items(ui) if c[0] == "e"]
            check("example-site" in keys, "TUI preset list misses a file env")
        finally:
            for k in got:            # leave the registry as the built-ins
                enterprise.ENVIRONMENTS.pop(k, None)
        # CLI: list / run / inventory / env export through a subprocess
        penv = dict(os.environ, PYTHONPATH=_REPO, TGT_ENV_PATH=envdir)

        def run(args):
            return subprocess.run([sys.executable, "-m", "tgt"] + args,
                                  cwd=_REPO, env=penv, capture_output=True,
                                  text=True, timeout=60)
        out = run(["list"])
        check(out.returncode == 0 and "example-site" in out.stdout and
              "file: " in out.stdout, "tgt list misses the env-dir file")
        pcap = os.path.join(d, "f.pcap")
        out = run(["run", "--env-file", src, "--pcap", pcap, "--once",
                   "--rate", "0"])
        check(out.returncode == 0 and len(_pcap_records(pcap)) > 100,
              f"run --env-file: {out.stdout[-300:]}{out.stderr[-300:]}")
        out = run(["run", "--env", "example-site", "--pcap", pcap, "--once",
                   "--rate", "0"])
        check(out.returncode == 0, "run --env <dir file key> failed")
        out = run(["inventory", "--env-file", src, "-f", "json"])
        check(out.returncode == 0 and
              json.loads(out.stdout)["env"] == "example-site",
              "inventory --env-file")
        exp = os.path.join(d, "ot.json")
        out = run(["env", "export", "ot-plant", "-o", exp])
        check(out.returncode == 0 and
              envfile.load(exp).key == "ot-plant", "env export -o")
        bad = os.path.join(d, "bad.json")
        with open(bad, "w") as f:
            f.write('{"key": "b", "segments": [], "hosts": []}')
        out = run(["run", "--env-file", bad, "--pcap", pcap])
        check(out.returncode == 2 and "segments" in out.stderr,
              f"bad --env-file not reported: {out.stderr}")
        check(run(["env"]).returncode == 0, "plain 'tgt env' broke")


def _gw_macs(env) -> set:
    return {P.mac_to_bytes(s.gateway_mac) for s in env.segments}


def test_arp_for_gateway_and_peers_every_host() -> None:
    from tgt import enterprise
    for env in enterprise.all_environments():
        batch = env.build(1)
        n_arp = 0
        while n_arp < len(batch) and batch[n_arp][0] == "arp":
            n_arp += 1
        arps = [f for k, f in batch if k == "arp"]
        # hosts behind NAT (not local) are not on this capture
        seen_hosts = [h for h in env.hosts if not env.hidden(h)]
        check(len(arps) > 0 and n_arp >= 2 * len(seen_hosts),
              f"{env.key}: ARP does not open the cycle")
        req, rep, grat = set(), set(), set()
        for f in arps:
            if struct.unpack("!H", f[16:18])[0] != P.ETH_P_ARP:
                continue
            op = struct.unpack("!H", f[18 + 6:18 + 8])[0]
            spa, tpa = f[18 + 14:18 + 18], f[18 + 24:18 + 28]
            sha = f[18 + 8:18 + 14]
            vlan = _vlan(f)
            if op == 1 and f[0:6] == b"\xff" * 6:
                (grat if spa == tpa else req).add((spa, tpa, vlan))
            elif op == 2:
                rep.add((spa, tpa, sha, vlan))
        for h in seen_hosts:
            seg = env.segment_of(h)
            ip, gw = P.ip_to_bytes(h.ip), P.ip_to_bytes(seg.gateway)
            check((ip, gw, seg.vlan) in req,
                  f"{env.key}: {h.name} never ARPs for its gateway")
            check((gw, ip, P.mac_to_bytes(env.gateway_mac(seg)), seg.vlan)
                  in rep,
                  f"{env.key}: gateway never answers {h.name}")
        check(grat, f"{env.key}: no gratuitous ARP")
    plant = enterprise.get("ot-plant")
    hmi, plc = plant.host("HMI-RW"), plant.host("PLC-RW1")
    blob = b"".join(f for k, f in plant.build(1) if k == "arp")
    check(P.arp(1, hmi.mac, hmi.ip, "00:00:00:00:00:00", plc.ip) in blob and
          P.arp(2, plc.mac, plc.ip, hmi.mac, hmi.ip) in blob,
          "HMI-RW does not ARP for its same-segment PLC")
    check(P.ip_to_bytes(enterprise.get("it-org").host("DC01").ip) not in
          b"".join(f[18 + 24:18 + 28] for k, f in
                   enterprise.get("it-org").build(1) if k == "arp"
                   and P.frame_ips(f) is None and
                   f[18 + 14:18 + 18] == P.ip_to_bytes(
                       enterprise.get("it-org").host("WS20").ip)),
          "WS20 ARPs for DC01 across segments")
    off = enterprise.Environment("t", "t", "IT", "", plant.hosts,
                                 plant.conversations, plant.segments,
                                 options={"arp": False})
    check("arp" not in {k for k, _ in off.build(1)} and
          "arp" not in off.protocols(), "options.arp=False still ARPs")


def test_enterprise_mixed_has_a_dmz() -> None:
    from tgt import enterprise
    mixed = enterprise.get("enterprise-mixed")
    zone = {h.name: mixed.segment_of(h).zone for h in mixed.hosts}
    check("DMZ" in set(zone.values()), "enterprise-mixed: no DMZ segment")
    roles = {h.role for h in mixed.hosts if zone[h.name] == "DMZ"}
    check({"hist", "jump", "patch"} <= roles, f"DMZ roles: {roles}")
    ot = {"OT-SUPERVISORY", "OT-CELL"}
    pairs = [(zone[c], zone[s], (c, s, p)) for c, s, p in mixed.conversations]
    check(any(a == "IT" and b == "DMZ" for a, b, _ in pairs), "no IT -> DMZ")
    check(any(a == "DMZ" and b in ot for a, b, _ in pairs), "no DMZ -> OT")
    check(any(a in ot and b == "DMZ" for a, b, _ in pairs), "no OT -> DMZ")
    bypass = [x for a, b, x in pairs if {a, b} & {"IT"} and {a, b} & ot]
    check(bypass == [enterprise.MIXED_DMZ_BYPASS],
          f"enterprise-mixed IT<->OT bypassing the DMZ: {bypass}")


def test_rewrite_l2_preserves_pcp() -> None:
    from tgt import enterprise
    from tgt.protocols_ind import goose_flow
    frame = goose_flow(Endpoints(), 1)[0]           # priority-tagged, PCP 4
    check(frame[12:14] == b"\x81\x00" and frame[14] >> 5 == 4,
          "GOOSE builder lost its priority tag")
    re_tag = P.rewrite_l2(frame, "02:00:00:00:00:09", "01:0c:cd:01:00:01", 150)
    tci = struct.unpack("!H", re_tag[14:16])[0]
    check(tci >> 13 == 4 and tci & 0x0FFF == 150, f"re-tag TCI {tci:#06x}")
    check(re_tag[16:] == frame[16:], "re-tag changed the payload")
    untagged = P.rewrite_l2(frame, "02:00:00:00:00:09", "01:0c:cd:01:00:01",
                            None)
    check(struct.unpack("!H", untagged[14:16])[0] == 0x8000,
          "vlan=None dropped the priority tag")
    plain = P.ethernet("02:00:00:00:00:02", "02:00:00:00:00:01", 0x0800,
                       b"x" * 40)
    check(struct.unpack("!H", P.rewrite_l2(plain, "02:00:00:00:00:01",
                                           "02:00:00:00:00:02", 7)[14:16])[0]
          == 7, "untagged frame gained a PCP")
    site = enterprise.get("industrial-site")
    env = enterprise.Environment(
        "t", "t", "OT", "", site.hosts,
        [("RELAY1", "RELAY2", "goose"), ("RELAY1", "RELAY2", "sv"),
         ("PLC-PK1", "PLC-PK2", "pn-rt")], site.segments,
        options={"arp": False})
    for k, f in env.build(2, span="core", edr=False):
        tci = struct.unpack("!H", f[14:16])[0]
        want = 6 if k == "pn-rt" else 4
        check(f[12:14] == b"\x81\x00" and tci >> 13 == want,
              f"{k}: placed frame PCP {tci >> 13}, want {want}")
        check(tci & 0x0FFF == env.segment_of(env.host("RELAY1" if k != "pn-rt"
                                                      else "PLC-PK1")).vlan,
              f"{k}: placed frame not on its segment VLAN")


def test_link_local_frames_never_routed() -> None:
    from tgt import enterprise
    check(all(protocols.get(k).link_local for k in
              ("ptp", "lldp", "cdp", "arp", "goose", "mdns", "llmnr")),
          "link_local flag missing on a link-local profile")
    check(not protocols.get("snmp").link_local, "snmp marked link-local")
    plant = enterprise.get("ot-plant")
    for proto in ("ptp", "mdns", "llmnr", "nbns", "ssdp"):
        try:
            enterprise.Environment("t", "t", "OT", "", plant.hosts,
                                   [("HMI-RW", "PLC-S7-1", proto)],
                                   plant.segments)
            _failures.append(f"{proto} across segments was accepted")
        except ValueError:
            pass
    conv = [("HMI-RW", "PLC-RW1", "ptp"), ("SW-CELL-RW", "SW-CELL-RW", "lldp"),
            ("OT-SW01", "OT-SW01", "cdp"), ("HMI-RW", "PLC-RW1", "mdns"),
            ("HMI-RW", "PLC-RW1", "llmnr"), ("HMI-RW", "PLC-RW1", "ptp-l2")]
    env = enterprise.Environment("t", "t", "OT", "", plant.hosts, conv,
                                 plant.segments, options={"arp": False})
    access = env.build(2, span="access", edr=False)
    core = env.build(2, span="core", edr=False)
    check(len(access) == len(core), "core view routed link-local frames")
    gws = _gw_macs(env)
    for k, f in core:
        check(f[0:6] not in gws and f[6:12] not in gws,
              f"{k}: link-local frame carries a gateway MAC")
        if k == "ptp":
            check(f[18 + 8] == 1, "PTP TTL changed from 1")
    # and in every built-in env's core view
    for e in enterprise.all_environments():
        gws = _gw_macs(e)
        for k, f in e.build(1, span="core"):
            if protocols.get(k).link_local and k != "arp":
                check(f[0:6] not in gws and f[6:12] not in gws,
                      f"{e.key}: {k} frame routed via a gateway")


def test_managed_switches_lldp_snmp_syslog() -> None:
    from tgt import devices, enterprise, inventory
    # the built-in envs' conventions (a switch per VLAN, the n0c-r3ad
    # community); packaged sites model their own (tests per site below)
    for env in enterprise.all_environments():
        if env.key not in enterprise.BUILTIN_KEYS:
            continue
        sws = [h for h in env.hosts if h.role == "switch"]
        check(len(sws) >= len(env.segments) - 1,
              f"{env.key}: {len(sws)} switches for {len(env.segments)} VLANs")
        conv = set(env.conversations)
        for sw in sws:
            dev = sw.device
            check(dev is not None and dev.device_type == "switch" and
                  sw.mac[:8] in dev.ouis, f"{env.key}: {sw.name} catalog/OUI")
            check((sw.name, sw.name, "lldp") in conv,
                  f"{env.key}: {sw.name} sends no LLDP")
            check(((sw.name, sw.name, "cdp") in conv) == (sw.os == "ios"),
                  f"{env.key}: {sw.name} CDP only on Cisco")
            nms = [c for c, s, p in conv if s == sw.name and p == "snmp"]
            check(nms and all(env.host(n).role == "nms" for n in nms) and
                  any(c == sw.name and env.host(s).role == "nms"
                      and p == "syslog" for c, s, p in conv),
                  f"{env.key}: {sw.name} not polled / not logging")
        blob = b"".join(f for k, f in env.build(1)
                        if k in ("snmp", "lldp", "cdp"))
        for sw in sws:
            descr = devices.banner(sw.device, "snmp_sysdescr", sw.name,
                                   sw.firmware, sw.serial).encode()
            check(descr in blob, f"{env.key}: {sw.name} sysDescr not on wire")
        if env.options.get("default_snmp_community"):   # planted finding
            check(all(env.snmp_community(sw).encode() in blob for sw in sws),
                  f"{env.key}: default SNMP community not on the wire")
        else:
            check(b"n0c-r3ad" in blob and b"public" not in blob,
                  f"{env.key}: SNMP community not the site's")
        rows = {r["name"]: r for r in inventory.hosts(env)}
        for sw in sws:
            check("snmp 161/udp" in rows[sw.name]["serves"] and
                  rows[sw.name]["purdue_level"] == env.purdue_level(sw) and
                  bool(rows[sw.name]["purdue_level"]),
                  f"{env.key}: {sw.name} inventory row")
    site = enterprise.get("industrial-site")
    lv = {h.name: site.purdue_level(h) for h in site.hosts}
    check(lv["CORE-SW01"] == "4" and lv["DMZ-SW01"] == "3.5" and
          lv["OT-CORE01"] == "3" and lv["SW-PK"] == "2",
          "switch Purdue level should follow its zone")
    doc = inventory.to_json(site)
    ob = {h["name"]: h["observability"] for h in doc["hosts"]}
    check(ob["SW-PR"]["firmware"]["observable"] and
          {"snmp", "lldp"} <= set(ob["SW-PR"]["firmware"]["evidence"]),
          "switch firmware not observable via SNMP/LLDP")
    if shutil_which("tshark"):
        _tshark_clean(site.build(1, span="core"), "industrial-site core")


def shutil_which(name: str):
    import shutil
    return shutil.which(name)


def _tshark_clean(batch, label: str) -> None:
    import subprocess
    with tempfile.TemporaryDirectory() as d:
        path = f"{d}/x.pcap"
        with PcapWriter(path) as w:
            for _, f in batch:
                w.write(f)
        expert = subprocess.run(["tshark", "-r", path, "-q", "-z",
                                 "expert,warn"], capture_output=True,
                                text=True).stdout
    bad = [ln for ln in expert.splitlines()
           if ("Malformed" in ln or "Duplicate IP" in ln or "incorrect" in ln
               or "Bad checksum" in ln)]
    check(not bad, f"tshark {label}: {bad[:3]}")


def test_misconfiguration_knobs() -> None:
    from tgt import enterprise, envfile, inventory
    base = enterprise.get("enterprise-mixed")

    def mk(**opts):
        return enterprise.Environment("t-knob", "t", "mixed", "",
                                      base.spec[0], base.spec[1],
                                      base.spec[2], options=opts)
    flat = mk(flat=True)
    vlans = {_vlan(f) for _, f in flat.build(1)}
    check(vlans == {base.segments[0].vlan}, f"flat: VLANs on wire {vlans}")
    check(len({s.subnet for s in flat.segments}) == len(base.segments),
          "flat: subnets lost")
    dual = mk(dual_homed=[{"host": "WS25", "ip": "172.16.0.99",
                           "flows": [["HISTORIAN", "smb"]]}])
    twin = dual.host("WS25/nic2")
    ws = dual.host("WS25")
    check(dual.segment_of(twin).zone == "OT-SUPERVISORY" and
          dual.segment_of(ws).zone == "IT", "dual-homed: zones")
    check((twin.fqdn, twin.serial, twin.model) == (ws.fqdn, ws.serial,
                                                   ws.model)
          and twin.mac != ws.mac, "dual-homed twin identity")
    nb = [f for k, f in dual.build(1) if k == "netbios"]
    srcs = {P.frame_ips(f)[0] for f in nb if b"FHFDDCDFCA" in f}  # "WS25"
    check({ws.ip, twin.ip} <= srcs, f"dual-homed: NetBIOS name from {srcs}")
    check(("WS25/nic2", "HISTORIAN", "smb") in dual.conversations,
          "dual-homed flows")
    check(len(base.hosts) + 1 == len(dual.hosts) and
          len(dual.spec[0]) == len(base.hosts), "dual-homed spec")
    rt = envfile.loads(envfile.export(dual), source="d")
    check(_seeded_build(rt) == _seeded_build(dual) and
          [h.name for h in rt.hosts] == [h.name for h in dual.hosts],
          "dual-homed env-file round trip")
    pub = mk(default_snmp_community=True)
    blob = b"".join(f for k, f in pub.build(1) if k == "snmp")
    check(b"public" not in blob and b"private" in blob, "switch community")
    plc = enterprise.Environment("t", "t", "OT", "", base.hosts,
                                 [("OT-NMS", "PLC-RW1", "snmp")],
                                 base.segments,
                                 options={"default_snmp_community": True})
    check(b"public" in b"".join(f for k, f in plc.build(1) if k == "snmp"),
          "default community on a PLC")
    check(mk(snmp_community="s3cret").snmp_community(base.host("CORE-SW01"))
          == "s3cret", "snmp_community option")
    try:
        mk(dual_homed=[{"host": "NOPE", "ip": "172.16.0.99"}])
        _failures.append("dual_homed with an unknown host accepted")
    except ValueError:
        pass
    inv = {r["name"]: r for r in inventory.hosts(flat)}
    check(len({r["vlan"] for r in inv.values()}) == 1, "flat inventory VLAN")


def test_netbios_announce_is_not_a_service() -> None:
    from tgt import enterprise, inventory
    rows = {r["name"]: r for r in inventory.hosts(enterprise.get("ot-plant"))}
    check(not any(s.startswith("netbios") for s in rows["HISTORIAN"]["serves"]),
          f"HISTORIAN serves {rows['HISTORIAN']['serves']}")
    check("netbios" in rows["HMI-XP"]["uses"], "HMI-XP netbios use lost")
    check("arp" in rows["PLC-RW1"]["uses"], "ARP use not in inventory")

# ---------------------------------------------------------------------------
# W2-B: per-OS TCP/IP stack fingerprints (#40) and TLS templates (#41)
# ---------------------------------------------------------------------------
def _tcp_view(frame: bytes):
    """(src_ip, ip_id, df, flags, window, options, payload, seq) of a TCP
    frame, else None."""
    t = _l4(frame)
    if not t or t[0] != P.IPPROTO_TCP:
        return None
    off = 18 if frame[12:14] == b"\x81\x00" else 14
    ip_id, frag = struct.unpack("!HH", frame[off + 4:off + 8])
    seg = t[5]
    doff = (seg[12] >> 4) * 4
    return (t[1], ip_id, bool(frag & 0x4000), seg[13],
            struct.unpack("!H", seg[14:16])[0], seg[20:doff], seg[doff:],
            struct.unpack("!I", seg[4:8])[0])


def _stack_flow(client: str, server: str, count: int = 3, proto=None):
    ep = Endpoints(stack_client=client, stack_server=server)
    return [_tcp_view(f) for f in (proto or protocols.modbus_flow)(ep, count)]


def test_tcp_syn_options_per_os() -> None:
    want = {  # stack -> (SYN option bytes w/o timestamps, SYN window)
        "win10": ("020405b40103030801010402", 64240),
        "win2012": ("020405b40103030801010402", 8192),
        "win7": ("020405b40103030201010402", 8192),
        "winxp": ("020405b401010402", 64240),
        "win2000": ("020405b401010402", 65535),
        "siemens": ("020405b4", 8192),
        "rockwell": ("020405b4", 8192),
        "sel": ("02040218", 2144),
    }
    for key, (opts, win) in want.items():
        syn = _stack_flow(key, "win10")[0]
        check(syn[3] == P.SYN and syn[5].hex() == opts and syn[4] == win,
              f"{key}: SYN options/window {syn[5].hex()} / {syn[4]}")
    # Linux: mss,sok,ts,nop,ws7 with TSecr 0; SYN+ACK from Linux has IP ID 0
    lin = _stack_flow("linux", "linux")
    o = lin[0][5]
    check(o[:6].hex() == "020405b40402" and o[6:8] == b"\x08\x0a"
          and o[12:16] == bytes(4) and o[16:].hex() == "01030307"
          and lin[0][4] == 64240, f"linux SYN options {o.hex()}")
    check(lin[1][1] == 0 and lin[1][4] == 65160, "linux SYN+ACK id/window")
    # timestamps on every later segment, TSecr echoing the peer's last TSval
    last = {}
    for v in lin[2:]:
        ts = v[5]
        check(len(ts) == 12 and ts[2:4] == b"\x08\x0a",
              "linux data segment lacks the timestamp option")
        tsval, tsecr = struct.unpack("!II", ts[4:12])
        peer = [k for k in last if k != v[0]]
        if peer:
            check(tsecr == last[peer[0]], "TSecr does not echo the peer TSval")
        last[v[0]] = tsval
    # SYN+ACK answers only what the SYN offered; DF per stack
    sa = _stack_flow("siemens", "win10")[1]
    check(sa[5].hex() == "020405b4", "win10 SYN+ACK to a bare-MSS SYN")
    sa = _stack_flow("win10", "linux")[1]
    check(sa[5].hex() == "020405b401010402" "01030307",
          f"linux SYN+ACK without timestamps {sa[5].hex()}")
    check(not _stack_flow("win10", "siemens")[1][2], "Siemens sets DF")
    check(_stack_flow("win10", "rockwell")[0][2], "Windows clears DF")
    # established windows: scaled when both scale, raw otherwise
    w = _stack_flow("win10", "win10")
    check(w[2][4] == 1026, f"win10 scaled window {w[2][4]}")
    w = _stack_flow("win10", "siemens")
    srv = next(v for v in w[2:] if v[0] == "10.10.10.20")
    check(w[2][4] == 65535 and srv[4] == 8192,
          "unscaled windows win10<->siemens")


def test_tcp_ip_id_and_defaults() -> None:
    from tgt import enterprise
    # per-session counter for Windows: +1 per datagram
    ids = [v[1] for v in _stack_flow("win10", "win10") if v[0] == "10.10.10.10"]
    check(all((b - a) & 0xFFFF == 1 for a, b in zip(ids, ids[1:])),
          "Windows IP ID does not increment by one")
    # profile-only defaults: Windows client, port-typical embedded server
    flow = [_tcp_view(f) for f in protocols.s7comm_flow(Endpoints(), 1)]
    check(flow[0][5].hex() == "020405b40103030801010402"
          and flow[1][5].hex() == "020405b4" and not flow[1][2],
          "default s7comm stacks are not Windows client / Siemens server")
    flow = [_tcp_view(f) for f in protocols.modbus_flow(Endpoints(), 1)]
    check(flow[1][4] == 4380, "default Modbus server is not a Modicon stack")
    # environment: one IP-ID counter per Windows/embedded host, rising in
    # wire order across all of its flows; routed copies keep the ID
    env = enterprise.get("industrial-site")
    hosts = {h.ip: h for h in env.hosts}
    seen: dict = {}
    bad = []
    for _, f in env.build(2):
        ips = P.frame_ips(f)
        h = hosts.get(ips[0]) if ips else None
        if h is None or env.host(h.name).stack == "linux":
            continue
        off = 18 if f[12:14] == b"\x81\x00" else 14
        ident = struct.unpack("!H", f[off + 4:off + 6])[0]
        prev = seen.get(h.ip)
        if prev is not None and (ident - prev) & 0xFFFF != 1:
            bad.append(h.name)
        seen[h.ip] = ident
    check(seen and not bad, f"per-host IP ID not sequential: {sorted(set(bad))[:5]}")
    core = env.build(1, span="core")
    pairs = 0
    for (_, a), (_, b) in zip(core, core[1:]):
        if P.frame_ips(a) and P.frame_ips(a) == P.frame_ips(b) and \
                a[-20:] == b[-20:] and a[12:14] == b[12:14] == b"\x81\x00":
            pairs += 1
            check(a[22:24] == b[22:24], "routed copy changed the IP ID")
    check(pairs > 0, "no routed copies found in the core view")


def test_tcp_segmentation_acks_and_rst() -> None:
    from tgt import enterprise
    # pure delayed ACKs between polls; FIN close for OT pollers
    flow = _stack_flow("win10", "rockwell", 4)
    pure = [v for v in flow[3:-3] if v[3] == P.ACK and not v[6]]
    check(len(pure) >= 3, "no delayed pure ACKs between Modbus polls")
    # no segment exceeds the MSS; large TLS flights are split
    env = enterprise.get("industrial-site")
    batch = env.build(2)
    rst, https = set(), set()
    for k, f in batch:
        v = _tcp_view(f)
        if not v:
            continue
        check(len(v[6]) <= 1460, f"{k}: TCP payload {len(v[6])} > MSS")
        if v[3] & P.RST:
            rst.add(k)
            check(k in ("http", "https"), f"{k} session closed with RST")
        if k == "https" and v[3] == P.SYN:
            https.add(v[0])
    check("http" in rst or "https" in rst, "no aborted (RST) web sessions")
    ep = Endpoints(client_ip="10.9.9.9")
    check(protocols._aborts(ep, 41000, 443) == protocols._aborts(ep, 41000, 443),
          "RST choice is not deterministic")
    n = sum(protocols._aborts(Endpoints(client_ip=f"10.9.{i}.1"), 41000, 443)
            for i in range(240))
    check(20 <= n <= 60, f"RST fraction off: {n}/240")


def _hello(frames):
    for f in frames:
        v = _tcp_view(f)
        if v and v[6][:1] == b"\x16" and v[6][5:6] == b"\x01":
            return v[6]
    return b""


def test_tls_client_hello_templates() -> None:
    from tgt import enterprise, tls

    def ep(t, ip="10.5.5.5", srv="openssl"):
        return Endpoints(client_ip=ip, meta={"sni": "app.corp.local",
                                             "tls_client": t, "tls_server": srv})
    for key in tls.TEMPLATES:
        h = _hello(protocols.https_flow(ep(key), 1))
        check(h and h[11:43] != bytes(32), f"{key}: zero/absent client random")
        check(h != _hello(protocols.https_flow(ep(key, "10.5.5.6"), 1)),
              f"{key}: identical ClientHello on two connections")
    xp = _hello(protocols.https_flow(ep("schannel-xp"), 1))
    check(xp[9:11] == b"\x03\x01" and b"app.corp.local" not in xp
          and len(xp) == 5 + 4 + 2 + 32 + 1 + 2 + 22 + 2,
          "XP ClientHello is not TLS 1.0 without extensions")
    w7 = _hello(protocols.https_flow(ep("schannel7"), 1))
    n = struct.unpack("!H", w7[44:46])[0]          # no session id
    suites = struct.unpack(f"!{n // 2}H", w7[46:46 + n])
    check(w7[9:11] == b"\x03\x03" and not any(0x1300 < c < 0x1310
                                               for c in suites),
          "Windows 7 offers TLS 1.3 suites")
    # one ClientHello per TCP connection across a whole site cycle
    per_conn: dict = {}
    for k, f in enterprise.get("industrial-site").build(3):
        v = _tcp_view(f)
        if v and k in ("https", "edr") and v[6][:1] == b"\x16" \
                and v[6][5:6] == b"\x01":
            key = (v[0], _l4(f)[3])
            per_conn[key] = per_conn.get(key, 0) + 1
    check(per_conn and max(per_conn.values()) == 1,
          "more than one ClientHello on a TCP connection")


def test_tls_server_flights_consistent() -> None:
    def flight(t, srv):
        e = Endpoints(meta={"sni": "app.corp.local", "tls_client": t,
                            "tls_server": srv})
        return b"".join(_tcp_view(f)[6] for f in protocols.https_flow(e, 2)
                        if _tcp_view(f)[0] == e.server_ip)

    def records(blob):
        out, i = [], 0
        while i + 5 <= len(blob):
            ln = struct.unpack("!H", blob[i + 3:i + 5])[0]
            out.append((blob[i], blob[i + 1:i + 3], blob[i + 5:i + 5 + ln]))
            i += 5 + ln
        return out
    r = records(flight("chrome", "openssl"))       # TLS 1.3
    sh = r[0][2]
    check(r[0][0] == 22 and sh[0] == 2 and b"\x00\x2b\x00\x02\x03\x04" in sh
          and r[1][0] == 20 and r[2][0] == 23, "TLS 1.3 server flight shape")
    check(struct.unpack("!H", sh[4 + 2 + 32 + 33:4 + 2 + 32 + 35])[0]
          in (0x1301, 0x1302, 0x1303), "TLS 1.3 ServerHello suite")
    r = records(flight("chrome", "schannel"))      # TLS 1.2
    types = [x[2][0] for x in r if x[0] == 22]
    check(types[:4] == [2, 11, 12, 14] and 20 in [x[0] for x in r],
          f"TLS 1.2 server flight {types}")
    sh = r[0][2]
    check(sh[4:6] == b"\x03\x03" and
          struct.unpack("!H", sh[4 + 2 + 32 + 33:4 + 2 + 32 + 35])[0]
          not in (0x1301, 0x1302, 0x1303),
          "TLS 1.2 ServerHello picked a TLS 1.3 suite")
    r = records(flight("schannel-xp", "schannel"))  # XP: TLS 1.0, RSA
    types = [x[2][0] for x in r if x[0] == 22]
    check(r[0][1] == b"\x03\x01" and types[:3] == [2, 11, 14],
          f"XP server flight {types}")
    r = records(flight("schannel-2000", "schannel"))  # SSL 3.0 refused
    check(len(r) == 1 and r[0][0] == 21 and r[0][2] == b"\x02\x46",
          "SSL 3.0 client not refused with protocol_version")


def test_tshark_tls_ja3_and_certificates() -> None:
    """Optional: tshark computes a distinct JA3/JA4 per client family (stable
    within a family), parses every certificate with CN = SAN = SNI, and finds
    nothing malformed."""
    import shutil
    import subprocess
    from tgt import enterprise, tls
    if not shutil.which("tshark"):
        _skipped.append("test_tshark_tls_ja3_and_certificates")
        return
    with tempfile.TemporaryDirectory() as d:
        path = f"{d}/tls.pcap"
        with PcapWriter(path) as w:
            n = 0
            for key in tls.TEMPLATES:
                for srv in ("schannel", "openssl", "schannel-legacy"):
                    for rep in range(2):
                        n += 1
                        e = Endpoints(client_ip=f"10.7.{n}.10",
                                      server_ip=f"10.7.{n}.20",
                                      meta={"sni": f"h{n}.corp.local",
                                            "tls_client": key,
                                            "tls_server": srv})
                        for f in protocols.https_flow(e, 2):
                            w.write(f)
            for _, f in enterprise.get("industrial-site").build(1):
                w.write(f)
        rows = subprocess.run(
            ["tshark", "-r", path, "-Y", "tls.handshake.type==1", "-T",
             "fields", "-e", "ip.src", "-e", "tls.handshake.ja3",
             "-e", "tls.handshake.ja4"],
            capture_output=True, text=True).stdout.splitlines()
        certs = subprocess.run(
            ["tshark", "-r", path, "-T", "fields", "-E", "separator=|",
             "-e", "tcp.stream", "-e", "tls.handshake.extensions_server_name",
             "-e", "x509sat.uTF8String", "-e", "x509ce.dNSName",
             "-Y", "tls.handshake.type==1 || tls.handshake.type==11"],
            capture_output=True, text=True).stdout.splitlines()
        expert = subprocess.run(["tshark", "-r", path, "-q", "-z", "expert"],
                                capture_output=True, text=True).stdout
    ja3: dict = {}
    keys = list(tls.TEMPLATES)
    for line in rows:
        ip, j3, j4 = (line.split("\t") + ["", ""])[:3]
        o = ip.split(".")
        if o[:2] != ["10", "7"]:
            continue
        key = keys[(int(o[2]) - 1) // 6]
        ja3.setdefault(key, set()).add((j3, j4))
    check(set(ja3) == set(keys), f"no ClientHello seen for {set(keys) - set(ja3)}")
    for key, vals in ja3.items():
        check(len(vals) == 1, f"{key}: JA3/JA4 not stable: {vals}")
    flat = [next(iter(v)) for v in ja3.values()]
    check(len({a for a, _ in flat}) == len(flat)
          and len({b for _, b in flat}) == len(flat),
          "two client families share a JA3/JA4")
    sni, ncert = {}, 0
    for line in certs:
        stream, name, utf8, dns = (line.split("|") + [""] * 3)[:4]
        if name:
            sni[stream] = name
        elif dns:
            ncert += 1
            want = sni.get(stream, dns)
            check(dns == want and utf8.split(",")[-1] == want,
                  f"certificate CN/SAN {utf8}/{dns} != SNI {want}")
    check(ncert >= 10, f"only {ncert} certificates parsed by tshark")
    check("Malformed" not in expert and "Errors (" not in expert,
          "tshark reports malformed TLS")
    warn = expert.split("Warns (")[1].split("Notes (")[0] if "Warns (" in expert else ""
    check(all("Connection reset" in ln for ln in warn.splitlines()[3:]
              if ln.strip()), "tshark TLS warnings besides deliberate RSTs")


# -- OT device identity on the wire + engineering baseline (#44, #45) -------
_IDENTITY_PROFILES = {"enip-id", "enip-list", "s7-id", "modbus-id",
                      "bacnet-id", "dnp3-id", "snmp"}


def test_every_embedded_device_identifies_itself() -> None:
    """Every embedded device in the OT environments is the server of at
    least one identity flow, and the identity meta it is built from comes
    from its own catalog entry (so it matches ``tgt inventory``)."""
    from tgt import enterprise
    for key in ("industrial-site", "ot-plant", "enterprise-mixed"):
        env = enterprise.get(key)
        served = {sv for _, sv, p in env.conversations
                  if p in _IDENTITY_PROFILES}
        missing = [h.name for h in env.hosts if h.embedded
                   and h.name not in served]
        check(not missing, f"{key}: embedded hosts without identity: {missing}")
    site = enterprise.get("industrial-site")
    seen_dnp3 = set()
    for c, sv, p in site.conversations:
        h = site.host(sv)
        m = site._endpoints(site.host(c), h).meta
        if p == "modbus-id":
            check(m["modbus_revision"] == h.firmware
                  and m["modbus_vendor"] == h.device.vendor,
                  f"{sv}: modbus-id meta != catalog")
        elif p == "bacnet-id":
            check(m["bacnet_firmware"] == h.firmware
                  and m["bacnet_serial"] == h.serial
                  and m["bacnet_instance"] % 1000 == int(h.ip.split(".")[3]),
                  f"{sv}: bacnet-id meta != catalog")
        elif p in ("dnp3", "dnp3-id", "dnp3-time"):
            check(m["dnp3_outstation"] != m["dnp3_master"],
                  f"{c}->{sv}: DNP3 master == outstation address")
            seen_dnp3.add(m["dnp3_outstation"])
    check(len(seen_dnp3) == 5, f"DNP3 outstations share addresses: {seen_dnp3}")


def test_engineering_ops_from_engineering_hosts() -> None:
    """S7/CIP engineering flows come only from engineering workstations,
    Modbus writes from operator HMIs and time sync from the SCADA master —
    always toward embedded devices — and ground truth labels them."""
    from tgt import enterprise, inventory
    from tgt.protocols_ot import ENGINEERING, OPERATIONS
    roles = {"s7-eng": {"eng"}, "enip-eng": {"eng"}, "modbus-write": {"hmi"},
             "dnp3-time": {"scada"}, "iec104-time": {"scada"},
             "sel-telnet": {"eng"}}
    check(set(roles) == set(OPERATIONS), "OPERATIONS out of sync with test")
    used = set()
    for env in enterprise.all_environments() + _utility_sites():
        planted = {(f["client"], f["server"], f["proto"])
                   for x in env.findings for f in x["flows"]}
        for c, sv, p in env.conversations:
            if p in OPERATIONS and (c, sv, p) not in planted:
                used.add(p)
                check(env.host(c).role in roles[p] and env.host(sv).embedded,
                      f"{env.key}: {p} from {c} ({env.host(c).role}) to {sv}")
        for f in inventory.to_json(env)["flows"]:
            if f["protocol"] in OPERATIONS:
                want = "engineering" if f["protocol"] in ENGINEERING \
                    else "operations"
                check(f.get("activity") == want and f.get("note"),
                      f"{env.key}: flow {f} not labelled {want}")
            else:
                check("activity" not in f, f"{env.key}: {f} labelled")
    check(used == set(OPERATIONS), f"ops profiles unused: {set(OPERATIONS) - used}")
    # one operation per build, whatever the message count
    for k in OPERATIONS:
        check(len(protocols.get(k).build(Endpoints(), 1)) ==
              len(protocols.get(k).build(Endpoints(), 9)),
              f"{k}: frame count grows with messages")


def test_ot_identity_builders_wire_format() -> None:
    """Byte-level checks of the new identity / operations builders."""
    ep = Endpoints(meta={"bcast": "10.10.10.255", "bacnet_instance": 4242,
                         "bacnet_vendor_id": 36})
    f = protocols.get("bacnet-id").build(ep, 1)
    check(f[0][:6] == b"\xff" * 6 and _l4(f[0])[2] == "10.10.10.255",
          "bacnet-id: Who-Is not broadcast")
    iam = _l4(f[1])[5][8:]
    check(iam[4:8] == b"\x01\x00\x10\x00"
          and struct.unpack("!I", iam[9:13])[0] == (8 << 22) | 4242
          and iam.endswith(b"\x21\x24"), "bacnet-id: I-Am device/vendor wrong")
    uni = protocols.get("enip-list").build(Endpoints(meta={"bcast": ""}), 1)
    check(uni[0][:6] != b"\xff" * 6, "enip-list: bcast='' still broadcast")
    io = [_l4(x) for x in protocols.get("enip-io").build(Endpoints(), 3)]
    udp = [t for t in io if t[0] == P.IPPROTO_UDP]
    check(len(udp) == 6 and all(t[3] == t[4] == 2222 for t in udp),
          "enip-io: class-1 I/O not on UDP 2222")
    check(all(struct.unpack("<HHH", t[5][8:14]) == (2, 0x8002, 8)
              for t in udp), "enip-io: no sequenced address item")
    s7 = b"".join(_l4(x)[5][20:] for x in protocols.get("s7-eng")
                  .build(Endpoints(), 1))
    for fn in (0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x28):
        check(bytes([fn]) in s7, f"s7-eng: function 0x{fn:02x} missing")
    check(b"_INSE" in s7 and b"_0A00010P" in s7, "s7-eng: DB10 not inserted")
    ua = b"".join(_l4(x)[5][20:] for x in protocols.get("opcua")
                  .build(Endpoints(meta={"host": "OPC1"}), 1))
    check(b"SecurityPolicy#Basic256Sha256" in ua and b"urn:OPC1:UA:Server"
          in ua and b"Anonymous" in ua, "opcua: endpoints/session identity")
    seg = max(len(_l4(x)[5]) - 20 for x in protocols.get("opcua")
              .build(Endpoints(meta={"host": "OPC1"}), 1))
    check(seg <= 1460 + 40, f"opcua: {seg}-byte TCP segment")  # MSS + options


def test_tshark_ot_identity_matches_inventory() -> None:
    """Optional: tshark decodes each new identity protocol from a full
    industrial-site cycle and the values agree with ``tgt inventory``."""
    import shutil
    import subprocess
    from tgt import devices, enterprise, inventory
    if not shutil.which("tshark"):
        _skipped.append("test_tshark_ot_identity_matches_inventory")
        return
    site = enterprise.get("industrial-site")
    inv = {h["ip"]: h for h in inventory.hosts(site)}
    from tgt import protocols_ot
    keep = _IDENTITY_PROFILES | set(protocols_ot.OPERATIONS) | {"enip-io"}

    def run(path, *args):
        return subprocess.run(["tshark", "-r", path, *args],
                              capture_output=True, text=True).stdout

    with tempfile.TemporaryDirectory() as d:
        path = f"{d}/site.pcap"
        with PcapWriter(path) as w:
            for k, fr in site.build(1):
                if k in keep:
                    w.write(fr)
        expert = run(path, "-q", "-z", "expert,warn")
        mb = run(path, "-Y", "modbus.object_str_value && tcp.srcport == 502",
                 "-T", "fields", "-E", "aggregator=|", "-e", "ip.src",
                 "-e", "modbus.object_id", "-e", "modbus.object_str_value")
        dnp = run(path, "-Y", "dnp3.al.da.value", "-T", "fields", "-E",
                  "aggregator=|", "-e", "ip.src", "-e", "dnp3.al.da.value")
        bac = run(path, "-Y", "bacapp.confirmed_service == 14 && "
                  "bacapp.type == 3", "-V", "-O", "bacapp")
        cip = run(path, "-Y", "cip.id.serial_number || enip.lir.serial",
                  "-T", "fields", "-e", "ip.src", "-e", "cip.id.major_rev",
                  "-e", "cip.id.minor_rev", "-e", "cip.id.serial_number",
                  "-e", "enip.lir.revision", "-e", "enip.lir.serial")
        snmp = run(path, "-Y", "snmp.name == 1.3.6.1.2.1.1.1.0 && "
                   "udp.srcport == 161", "-T", "fields", "-e", "ip.src",
                   "-e", "snmp.value.octets")
        io = run(path, "-Y", "cipio", "-T", "fields", "-e", "ip.src")
        eng = run(path, "-Y", "s7comm.param.func == 0x1b || "
                  "s7comm.param.func == 0x1d", "-T", "fields", "-e", "ip.src")
    check("Errors (" not in expert and "Warns (" not in expert,
          "tshark expert warnings in identity/operations traffic")
    seen = set()
    mb_objs: dict = {}
    for ln in mb.splitlines():           # one row per FC 43 response
        ip, ids, vals = ln.split("\t")
        mb_objs.setdefault(ip, {}).update(zip(ids.split("|"),
                                              vals.split("|")))
    for ip, objs in mb_objs.items():     # basic + regular objects
        h = inv[ip]
        check(objs.get("2") == h["firmware"] and objs.get("0") ==
              site.host(h["name"]).device.vendor
              and objs.get("4", "?") in h["product"],
              f"{h['name']}: Modbus device ID {objs} != inventory")
        seen.add(ip)
    for ln in dnp.splitlines():
        ip, vals = ln.split("\t")
        h, v = inv[ip], vals.split("|")
        check(v[1] == h["product"] and v[2] == h["firmware"]
              and v[3] == h["serial"] and v[4] == h["name"],
              f"{h['name']}: DNP3 attributes {v} != inventory")
        seen.add(ip)
    ip = None
    for ln in bac.splitlines():
        if ln.startswith("Internet Protocol"):
            ip = ln.split("Src: ")[1].split(",")[0]
            seen.add(ip)
        for prop, col in (("firmware-revision", "firmware"),
                          ("serial-number", "serial")):
            if ln.strip().startswith(prop + ":"):
                got = ln.split("'")[1]
                check(got == inv[ip][col],
                      f"{inv[ip]['name']}: BACnet {prop} {got} != inventory")
    for ln in cip.splitlines():
        ip, ma, mi, sn, rev, lsn = ln.split("\t")
        h = inv[ip]
        major, minor = devices.cip_revision(h["firmware"])
        if sn:
            check((int(ma), int(mi)) == (major, minor)
                  and int(sn, 16) == int(h["serial"], 16),
                  f"{h['name']}: CIP Get_Attribute_All != inventory")
        if lsn:
            check(int(rev) == major << 8 | minor
                  and int(lsn, 16) == int(h["serial"], 16),
                  f"{h['name']}: List Identity != inventory")
        seen.add(ip)
    for ln in snmp.splitlines():
        ip, descr = ln.split("\t")
        text = bytes.fromhex(descr.split(",")[0]).decode()
        check(inv[ip]["firmware"] in text,
              f"{inv[ip]['name']}: sysDescr {text!r} lacks firmware")
        seen.add(ip)
    # every embedded device was decoded with its identity (S7 CPUs are
    # covered by test_identity_wire_matches_inventory)
    want = {h.ip for h in site.hosts if h.embedded
            and h.device.identity.get("s7") is None}
    check(want <= seen, "tshark: no decoded identity for "
          f"{sorted(inv[i]['name'] for i in want - seen)}")
    drives = {h.ip for h in site.hosts if h.role == "drive"}
    check(drives <= set(io.split()), "tshark: drives without CIP I/O")
    check({h.ip for h in site.hosts if h.name.startswith("PLC-PR")}
          <= set(eng.split()), "tshark: S7 upload/download not seen")


# -- utility & energy sites (tgt/envs/sites, #51) + remote sites / NAT (#52) --
_DISSECTS_AS.update({"sel-telnet": "telnet"})

UTILITY_SITES = ("water-utility", "electric-substation", "oil-gas-pipeline")
# identity on the wire: the W2-C set plus IEC 61850 MMS Identify, the SEL
# ASCII ID command and a panel HMI's VNC desktop name
_UTIL_ID_PROFILES = _IDENTITY_PROFILES | {"mms", "sel-telnet", "vnc"}
_UTIL_CACHE: dict = {}


def _utility_sites() -> list:
    """The packaged utility sites, loaded straight from their files (so the
    registry stays as the built-ins whatever the test order)."""
    from tgt import envfile
    if not _UTIL_CACHE:
        for k in UTILITY_SITES:
            _UTIL_CACHE[k] = envfile.load(
                os.path.join(envfile.SITES_DIR, f"{k}.json"))
    return [_UTIL_CACHE[k] for k in UTILITY_SITES]


def _tcp_payload(frame: bytes) -> bytes:
    t = _l4(frame)
    if t is None or t[0] != P.IPPROTO_TCP:
        return b""
    off = 18 if frame[12:14] == b"\x81\x00" else 14
    total = struct.unpack("!H", frame[off + 2:off + 4])[0]
    ihl = (frame[off] & 0x0F) * 4
    seg = frame[off + ihl:off + total]
    return seg[(seg[12] >> 4) * 4:]


def _vid(frame: bytes):
    return (struct.unpack("!H", frame[14:16])[0] & 0x0FFF
            if frame[12:14] == b"\x81\x00" else None)


def _expert_warns(batch) -> list:
    """tshark Warn/Error summary lines of a batch (empty without tshark)."""
    import subprocess
    if not shutil_which("tshark"):
        return []
    with tempfile.TemporaryDirectory() as d:
        path = f"{d}/x.pcap"
        with PcapWriter(path) as w:
            for _, f in batch:
                w.write(f)
        out = subprocess.run(["tshark", "-r", path, "-q", "-z",
                              "expert,warn"], capture_output=True,
                             text=True).stdout
    bad, on = [], False
    for ln in out.splitlines():
        if ln.startswith(("Warns", "Errors")):
            on = True
        elif ln.startswith(("Notes", "Chats")):
            on = False
        elif on and ln.strip()[:1].isdigit():
            bad.append(ln.split(None, 3)[-1].strip())
    return bad


def test_utility_sites_load_build_and_catalog() -> None:
    """The packaged water / substation / pipeline sites load, round-trip
    through env export, build in both SPAN views with valid checksums and
    no tshark warnings beyond browser RSTs, give every host a catalog model
    (planted unknown devices excepted), every flow a period, and show up in
    the registry once the site directory is loaded."""
    from tgt import envfile
    for env in _utility_sites():
        check(bool(env.findings), f"{env.key}: no planted findings")
        check(any(s.options.get("wan_rtt_ms") for s in env.segments),
              f"{env.key}: no WAN latency hint")
        for h in env.hosts:
            dev = h.device
            check(dev is not None, f"{env.key}: {h.name} has no catalog model")
            if dev is None:
                continue
            if h.embedded or _looks_embedded(h):
                check(dev.embedded, f"{env.key}: {h.name} not embedded")
                check(h.mac[:8] in dev.ouis,
                      f"{env.key}: {h.name} MAC OUI not one of {h.model}'s")
            check(h.firmware in dev.firmware,
                  f"{env.key}: {h.name} firmware {h.firmware!r} not offered")
            check(bool(env.purdue_level(h)),
                  f"{env.key}: {h.name} has no Purdue level")
        check(all(env.timing.get(c, {}).get("period")
                  for c in env.conversations),
              f"{env.key}: flows without a period for the time model")
        again = envfile.from_dict(envfile.to_dict(env))
        check(again.conversations == env.conversations
              and again.findings == env.findings
              and [s.options for s in again.segments] ==
              [s.options for s in env.segments]
              and again.timing == env.timing,
              f"{env.key}: env export/load not lossless")
        for span in ("access", "core"):
            protocols.begin_build(11, 0)
            batch = env.build(2, span)
            check(len(batch) > 500, f"{env.key}/{span}: tiny build")
            for k, f in batch:
                verify_ip_l4(f, f"{env.key}/{span}/{k}")
            if span == "access":
                bad = [w for w in _expert_warns(batch)
                       if "Connection reset (RST)" not in w]
                check(not bad, f"{env.key}: tshark warnings {bad[:3]}")
    keys = set(envfile.load_user_envs(warn=lambda m: None, force=True))
    try:
        from tgt import enterprise
        check(set(UTILITY_SITES) <= keys and all(
            envfile.source_of(enterprise.get(k)) for k in UTILITY_SITES),
            f"packaged sites not registered: {sorted(keys)}")
    finally:
        from tgt import enterprise
        for k in keys:
            enterprise.ENVIRONMENTS.pop(k, None)


def test_utility_sites_identity_on_wire() -> None:
    """Every embedded device is the server of an identity flow, and what
    tshark decodes from it (Modbus device ID, DNP3 attributes, MMS Identify,
    SNMP sysDescr, SEL ID, CIP List Identity, VNC desktop) matches
    ``tgt inventory`` — through the NAT'd address for remote-site devices."""
    import shutil
    import subprocess
    from tgt import inventory
    sites = _utility_sites()
    for env in sites:
        served = {sv for _, sv, p in env.conversations
                  if p in _UTIL_ID_PROFILES}
        missing = [h.name for h in env.hosts if h.embedded
                   and h.name not in served]
        check(not missing, f"{env.key}: embedded hosts without identity: "
              f"{missing}")
    if not shutil.which("tshark"):
        _skipped.append("test_utility_sites_identity_on_wire")
        return

    def run(path, *args):
        return subprocess.run(["tshark", "-r", path, *args],
                              capture_output=True, text=True).stdout

    for env in sites:
        rows = {r["name"]: r for r in inventory.to_json(env)["hosts"]}
        at: dict = {}                     # wire IP -> host names
        for h in env.hosts:
            at.setdefault(h.ip, []).append(h.name)
            if env.nat_address(h):
                at.setdefault(env.nat_address(h), []).append(h.name)
        seen: dict = {}                   # host -> wire IP it was seen at

        def match(ip, ok, what):
            hit = [n for n in at.get(ip, []) if ok(env.host(n))]
            check(bool(hit), f"{env.key}: {what} from {ip} matches no host "
                  f"of {at.get(ip)}")
            for n in hit:
                seen[n] = ip
        with tempfile.TemporaryDirectory() as d:
            path = f"{d}/site.pcap"
            protocols.begin_build(3, 0)
            with PcapWriter(path) as w:
                for k, fr in env.build(1):
                    if k in _UTIL_ID_PROFILES:
                        w.write(fr)
            mb = run(path, "-Y", "modbus.object_str_value && tcp.srcport == "
                     "502", "-T", "fields", "-E", "aggregator=|", "-e",
                     "ip.src", "-e", "tcp.stream", "-e", "modbus.object_id",
                     "-e", "modbus.object_str_value")
            dnp = run(path, "-Y", "dnp3.al.da.value", "-T", "fields", "-E",
                      "aggregator=|", "-e", "ip.src", "-e",
                      "dnp3.al.da.value")
            mms = run(path, "-Y", "mms.vendorName", "-T", "fields", "-e",
                      "ip.src", "-e", "mms.vendorName", "-e",
                      "mms.modelName", "-e", "mms.revision")
            snmp = run(path, "-Y", "snmp.name == 1.3.6.1.2.1.1.1.0 && "
                       "udp.srcport == 161", "-T", "fields", "-e", "ip.src",
                       "-e", "snmp.value.octets")
            sel = run(path, "-Y", "telnet.data contains \"SERIALNO=\" && "
                      "tcp.srcport == 23", "-T", "fields", "-e", "ip.src",
                      "-e", "telnet.data")
            cip = run(path, "-Y", "enip.lir.serial", "-T", "fields", "-e",
                      "ip.src", "-e", "enip.lir.revision", "-e",
                      "enip.lir.serial")
            vnc = run(path, "-Y", "vnc.desktop_name", "-T", "fields", "-e",
                      "ip.src", "-e", "vnc.desktop_name")
        objs: dict = {}
        for ln in mb.splitlines():
            ip, stream, ids, vals = ln.split("\t")
            objs.setdefault((ip, stream), {}).update(
                zip(ids.split("|"), vals.split("|")))
        for (ip, _), o in objs.items():
            match(ip, lambda h, o=o: h.device and o.get("2") == h.firmware
                  and o.get("0") == h.device.identity["modbus"].get(
                      "vendor", h.device.vendor), f"Modbus ID {o}")
        for ln in dnp.splitlines():
            ip, vals = ln.split("\t")
            v = vals.split("|")
            match(ip, lambda h, v=v: v[1] == rows[h.name]["product"]
                  and v[2] == h.firmware and v[3] == h.serial
                  and v[4] == h.name, f"DNP3 attributes {v}")
        for ln in mms.splitlines():
            ip, vendor, model, rev = ln.split("\t")
            match(ip, lambda h, x=(vendor, model, rev): h.device and
                  "mms" in h.device.identity and x == (
                      h.device.identity["mms"]["vendor"],
                      h.device.identity["mms"]["model"], h.firmware),
                  f"MMS Identify {vendor}/{model}/{rev}")
        for ln in snmp.splitlines():
            ip, descr = ln.split("\t")
            text = bytes.fromhex(descr.split(",")[0]).decode()
            match(ip, lambda h, t=text: bool(h.firmware) and h.firmware in t,
                  f"sysDescr {text!r}")
        for ln in sel.splitlines():
            ip, data = ln.split("\t")
            match(ip, lambda h, t=data: f"-{h.firmware}-" in t
                  and f"SERIALNO={h.serial}" in t, "SEL ID")
        for ln in cip.splitlines():
            ip, rev, serial = ln.split("\t")
            match(ip, lambda h, r=rev, s=serial: h.device is not None and
                  "cip" in h.device.identity and
                  int(s, 16) == int(h.serial, 16) and
                  int(r) == _cip_rev(h.firmware), "CIP List Identity")
        for ln in vnc.splitlines():
            ip, desk = ln.split("\t")
            match(ip, lambda h, x=desk: h.embedded and h.name in x,
                  f"VNC desktop {desk!r}")
        want = {h.name for h in env.hosts if h.embedded}
        check(want <= set(seen), f"{env.key}: tshark decoded no identity "
              f"for {sorted(want - set(seen))}")
        for n, ip in seen.items():          # the wire address is the truth's
            r = rows[n]
            check(ip in (r["ip"], r.get("nat_ip")),
                  f"{env.key}: {n} seen at {ip}, inventory {r['ip']} / "
                  f"{r.get('nat_ip')}")
            if r.get("nat_hidden"):
                check(ip == r["nat_ip"], f"{env.key}: hidden {n} at {ip}")


def _cip_rev(firmware: str) -> int:
    from tgt import devices
    major, minor = devices.cip_revision(firmware)
    return major << 8 | minor


def _flow_frames(env, batch, client, server, proto) -> list:
    """Frames of one modeled flow, found by its (NAT-translated) addresses —
    by MAC for Layer-2 protocols."""
    c, s = env.nat_view(env.host(client), env.host(server))
    out = []
    for k, f in batch:
        if k != proto:
            continue
        ips = P.frame_ips(f)
        if ips and set(ips) == {c.ip, s.ip}:
            out.append(f)
        elif not ips and P.bytes_to_mac(f[6:12]) in (c.mac, s.mac):
            out.append(f)
    return out


def test_utility_sites_planted_findings() -> None:
    """Every planted finding's flows are on the wire (as the capture point
    sees them), with the evidence a monitor keys on."""
    from tgt import inventory
    sites = {e.key: e for e in _utility_sites()}
    batches = {}
    for key, env in sites.items():
        protocols.begin_build(5, 0)
        batches[key] = b = env.build(2)
        inv = inventory.to_json(env)
        check([f["id"] for f in inv.get("findings", [])] ==
              [f["id"] for f in env.findings],
              f"{key}: inventory JSON lacks the findings")
        for fd in env.findings:
            for fl in fd["flows"]:
                check(bool(_flow_frames(env, b, fl["client"], fl["server"],
                                        fl["proto"])),
                      f"{key}: finding {fd['id']}: {fl} not on the wire")
    # water: unauthenticated VNC, Telnet creds, public community, legacy HMI
    w, b = sites["water-utility"], batches["water-utility"]
    vnc = _flow_frames(w, b, "OPS-WS2", "LS04-HMI", "vnc")
    check(any(_tcp_payload(f) == b"\x01\x01" and _l4(f)[1] == "10.250.0.14"
              for f in vnc), "water: LS04 VNC does not offer security None")
    tel = b"".join(_tcp_payload(f) for f in
                   _flow_frames(w, b, "ENG01", "LS07-MODEM", "telnet"))
    check(b"moxa\r\n" in tel and b"admin\r\n" in tel,
          "water: Telnet login to LS07 not in cleartext")
    for n in range(1, 9):
        snmp = _flow_frames(w, b, "OT-NMS", f"LS0{n}-MODEM", "snmp")
        check(any(b"public" in _l4(f)[5] for f in snmp),
              f"water: LS0{n} modem not polled with 'public'")
    check(not any(b"public" in _l4(f)[5] for f in
                  _flow_frames(w, b, "OT-NMS", "SW-PLANT", "snmp")),
          "water: plant switch also answers 'public'")
    check(w.host("HMI-FILTER").fp.legacy, "water: HMI-FILTER not legacy")
    check(not any(P.frame_ips(f) and any(ip.startswith("192.168.")
                                         for ip in P.frame_ips(f))
                  for _, f in b), "water: a station LAN address leaked")
    # substation: rogue GOOSE publisher, rogue PTP GM, corporate engineering
    s, b = sites["electric-substation"], batches["electric-substation"]
    ts = s.host("TESTSET-01").mac
    check(any(k == "goose" and P.bytes_to_mac(f[6:12]) == ts for k, f in b),
          "substation: no GOOSE from the test set")
    appids = {struct.unpack("!H", f[18:20])[0] for k, f in b if k == "goose"}
    check(len(appids) == 6, f"substation: GOOSE APPIDs {sorted(appids)}")
    rogue = s.host("PTP-ROGUE").mac
    check(any(k == "ptp-l2" and P.bytes_to_mac(f[6:12]) == rogue
              and f[18] & 0x0F == 0x0B for k, f in b),
          "substation: rogue grandmaster sends no Announce")
    sess = b"".join(_tcp_payload(f) for f in _flow_frames(
        s, b, "CORP-ENG-LT", "L1-SEL451", "sel-telnet"))
    check(b"ACC\r\n" in sess and b"OTTER" in sess and b"SET 1" in sess,
          "substation: corporate SEL session lacks login / settings change")
    check(s.rtt_ms(s.host("CORP-ENG-LT"), s.host("L1-SEL451")) == 34,
          "substation: WAN latency hint not applied")
    # pipeline: vendor access, metering write, flat MS5, EOL HMI
    o, b = sites["oil-gas-pipeline"], batches["oil-gas-pipeline"]
    check(any(_l4(f)[4] == 3389 and _l4(f)[2] == "10.200.0.11" for f in
              _flow_frames(o, b, "VENDOR-JUMP", "CS1-HMI", "rdp")),
          "pipeline: vendor RDP not to CS1's VSAT address")
    check(any(_l4(f)[4] == 22 and _l4(f)[2] == "10.200.0.12" for f in
              _flow_frames(o, b, "VENDOR-JUMP", "CS2-TURB", "ssh")),
          "pipeline: vendor SSH not to CS2's VSAT address")
    fcs = {_tcp_payload(f)[7] for f in _flow_frames(
        o, b, "MEAS-WS01", "MS4-FC", "modbus-write")
        if _l4(f)[4] == 502 and len(_tcp_payload(f)) > 7}
    check(fcs & {5, 6, 15, 16}, f"pipeline: metering write FCs {fcs}")
    ms5 = [f for _, f in b if _vid(f) == 215]
    check(any(P.frame_ips(f) == ("192.168.15.50", "192.168.15.23")
              for f in ms5) and any(f[12:14] == b"\x81\x00" and
                                    f[16:18] == b"\x08\x06" for f in ms5),
          "pipeline: MS5 flat LAN (office PC -> flow computer, ARP) unseen")
    check(not any(_vid(f) in (211, 212, 213, 214) for _, f in b),
          "pipeline: a hidden station VLAN is on the wire")
    check(o.host("CS2-HMI").fp.legacy, "pipeline: CS2-HMI not legacy")


_NAT_ENV = {
    "key": "nat-test", "name": "NAT test", "category": "OT",
    "segments": [
        {"name": "HQ", "vlan": 10, "subnet": "10.1.0.0/24",
         "zone": "OT-SUPERVISORY"},
        {"name": "WAN", "vlan": 20, "subnet": "10.2.0.0/24", "zone": "OT-CELL",
         "wan_rtt_ms": 100},
        {"name": "SITE", "vlan": 30, "subnet": "192.168.50.0/24",
         "zone": "OT-CELL", "wan_rtt_ms": 120,
         "nat": {"outside_ip": "10.2.0.5"}},
        {"name": "SITE2", "vlan": 40, "subnet": "192.168.60.0/24",
         "zone": "OT-CELL", "gateway_mac": "00:a0:d5:00:00:99",
         "nat": {"outside_ip": "203.0.113.9", "local": True}},
    ],
    "hosts": [
        {"name": "SCADA", "ip": "10.1.0.10", "role": "scada", "os": "win2019"},
        {"name": "MODEM", "ip": "10.2.0.5", "role": "router",
         "os": "embedded-linux", "model": "sierra-airlink-rv50x"},
        {"name": "RTU", "ip": "192.168.50.21",
         "model": "schneider-scadapack-474"},
        {"name": "HMI", "ip": "192.168.50.30", "role": "hmi", "os": "win10"},
        {"name": "RTU2", "ip": "192.168.60.21",
         "model": "schneider-scadapack-474"},
    ],
    "flows": [
        {"client": "SCADA", "server": "RTU", "proto": "dnp3"},
        {"client": "SCADA", "server": "MODEM", "proto": "snmp"},
        {"client": "HMI", "server": "RTU", "proto": "modbus"},
        {"client": "SCADA", "server": "RTU2", "proto": "modbus"},
    ],
    "findings": [{"id": "x", "title": "t", "hosts": ["HMI"],
                  "flows": [{"client": "HMI", "server": "RTU",
                             "proto": "modbus"}]}],
}


def test_nat_remote_sites() -> None:
    """Segment ``nat`` (#52): remote-site hosts appear as the router's
    outside IP/MAC on the HQ capture (checksums recomputed, TTL -1 on the
    way out), site-internal frames vanish unless ``local``, a carrier
    outside address rides the HQ gateway, and inventory / manifest / env
    export carry the translation; plus the schema errors."""
    import copy
    import json
    from tgt import envfile, inventory
    env = envfile.from_dict(copy.deepcopy(_NAT_ENV))
    h = {n: env.host(n) for n in ("SCADA", "MODEM", "RTU", "HMI", "RTU2")}
    check(env.nat_address(h["RTU"]) == "10.2.0.5" and env.hidden(h["RTU"])
          and not env.hidden(h["RTU2"]) and not env.nat_address(h["MODEM"]),
          "nat_address / hidden wrong")
    v = env.nat_view(h["SCADA"], h["RTU"])
    check(v[0] is h["SCADA"] and (v[1].ip, v[1].mac) ==
          ("10.2.0.5", h["MODEM"].mac), f"nat_view: {v[1]}")
    check(env.nat_view(h["HMI"], h["RTU"]) == (h["HMI"], h["RTU"]),
          "nat_view translated a site-internal flow")
    check(env.rtt_ms(h["SCADA"], h["RTU"]) == 120
          and env.rtt_ms(h["SCADA"], h["MODEM"]) == 100
          and env.rtt_ms(h["HMI"], h["RTU"]) == 0, "rtt_ms wrong")
    for span in ("access", "core"):
        protocols.begin_build(1, 0)
        b = env.build(2, span)
        for k, f in b:
            verify_ip_l4(f, f"nat/{span}/{k}")
        ips = [P.frame_ips(f) for _, f in b if P.frame_ips(f)]
        check(not any(ip.startswith("192.168.50.") for p in ips for ip in p),
              f"nat/{span}: a hidden site address leaked")
        check(not any(k == "modbus" and P.frame_ips(f) and "10.2.0.5" in
                      P.frame_ips(f) for k, f in b),
              f"nat/{span}: the site-internal Modbus flow is on the wire")
        check(not any(_vid(f) == 30 for _, f in b),
              f"nat/{span}: hidden site VLAN on the wire (ARP?)")
        up = [f for k, f in b if k == "dnp3" and _vid(f) == 20
              and P.frame_ips(f) == ("10.2.0.5", "10.1.0.10")]
        down = [f for k, f in b if k == "dnp3"
                and P.frame_ips(f) == ("10.1.0.10", "10.2.0.5")]
        check(bool(up) and bool(down), f"nat/{span}: DNP3 not translated")
        off = 18
        check(all(f[off + 8] == 63 and P.bytes_to_mac(f[6:12]) ==
                  h["MODEM"].mac and _vid(f) == 20 for f in up),
              f"nat/{span}: outbound frames not from the modem, TTL 63")
        check(any(_vid(f) == 10 for f in down) and (span == "access") ==
              (not any(_vid(f) == 20 and P.frame_ips(f) ==
                       ("10.1.0.10", "10.2.0.5") for _, f in b)),
              f"nat/{span}: inbound placement / core copy wrong")
        rtu2 = [f for k, f in b if k == "modbus" and P.frame_ips(f) ==
                ("203.0.113.9", "10.1.0.10")]
        gw = env.segment_of(h["SCADA"]).gateway_mac
        check(bool(rtu2) and all(_vid(f) == 10 and P.bytes_to_mac(f[6:12])
                                 == gw for f in rtu2),
              f"nat/{span}: carrier-address site not via the HQ gateway")
        check(any(_vid(f) == 40 and f[16:18] == b"\x08\x06" for _, f in b),
              f"nat/{span}: local site's ARP missing")
    # inventory, manifest, export
    inv = inventory.to_json(env)
    rows = {r["name"]: r for r in inv["hosts"]}
    check(rows["RTU"].get("nat_ip") == "10.2.0.5" and rows["RTU"]["nat_hidden"]
          and rows["RTU2"]["nat_hidden"] is False and "nat_ip" not in
          rows["SCADA"], "inventory nat_ip / nat_hidden")
    check(not rows["RTU"]["observability"]["vendor"]["evidence"] or
          "oui" not in rows["RTU"]["observability"]["vendor"]["evidence"],
          "inventory: hidden host credited with its MAC OUI")
    segs = {s["name"]: s for s in inv["segments"]}
    check(segs["SITE"].get("nat") == {"outside_ip": "10.2.0.5"}
          and segs["WAN"].get("wan_rtt_ms") == 100
          and segs["SITE2"]["gateway_mac"] == "00:a0:d5:00:00:99"
          and segs["SITE"]["gateway_mac"] == h["MODEM"].mac,
          "inventory segments lack nat / wan_rtt_ms / gateway_mac")
    infra = {i["segment"]: i for i in inv["infrastructure"]}
    check("SITE" not in infra and infra["SITE2"]["kind"] == "gateway"
          and infra["HQ"]["kind"] == "hsrp-gateway",
          f"inventory infrastructure for NAT sites: {infra}")
    check(inv["findings"][0]["id"] == "x", "inventory findings")
    check(json.loads(json.dumps(envfile.to_dict(env)))["segments"][2]["nat"]
          == {"outside_ip": "10.2.0.5"}, "env export drops nat")
    envfile.register(env)
    try:
        with tempfile.TemporaryDirectory() as d:
            protocols.begin_build(1, 0)
            n = len(env.build(1))
            m = _manifest_run(d, "nat", RunConfig(env="nat-test", seed=2),
                              n)
        flows = {(f["client"], f["server"], f["protocol"])
                 for f in m["flows_seen"]}
        check(("nat-test:SCADA", "nat-test:RTU", "dnp3") in flows,
              f"manifest: translated DNP3 flow not attributed: {flows}")
    finally:
        from tgt import enterprise
        enterprise.ENVIRONMENTS.pop("nat-test", None)
    # schema errors
    for mut, want in (
            (lambda d: d["segments"][2]["nat"].update(
                outside_ip="192.168.50.9"), "inside the NAT'd subnet"),
            (lambda d: d["segments"][2]["nat"].update(port=1), "unknown key"),
            (lambda d: d["segments"][1].update(wan_rtt_ms=-5), "wan_rtt_ms"),
            (lambda d: d["segments"][3].update(gateway_mac="xx"),
             "gateway_mac"),
            (lambda d: d["segments"][3]["nat"].update(outside_ip="10.2.0.0"),
             None),
            (lambda d: d["findings"][0]["flows"][0].update(proto="dnp3"),
             "not one of the flows"),
            (lambda d: d["findings"].append(dict(d["findings"][0])),
             "duplicate finding id"),
            (lambda d: d["findings"][0].update(severity="urgent"),
             "severity")):
        doc = copy.deepcopy(_NAT_ENV)
        mut(doc)
        try:
            envfile.from_dict(doc, "nat.json")
            check(want is None, f"env file accepted: {want}")
        except envfile.EnvFileError as e:
            check(want is not None and want in str(e) and "nat.json" in str(e),
                  f"unexpected env-file error: {e}")
    # a NAT outside address inside another NAT segment is refused
    doc = copy.deepcopy(_NAT_ENV)
    doc["segments"][3]["nat"]["outside_ip"] = "192.168.50.99"
    try:
        envfile.from_dict(doc, "nat.json")
        check(False, "outside_ip inside another NAT segment accepted")
    except envfile.EnvFileError as e:
        check("inside NAT segment" in str(e), f"wrong error: {e}")
    # packet.rewrite_ips keeps UDP/TCP checksums valid and Ethernet padding
    ep = Endpoints(client_ip="192.168.1.5", server_ip="10.0.0.1")
    for f in protocols.get("modbus").build(ep, 1) + \
            protocols.get("snmp").build(ep, 1):
        g = P.rewrite_ips(f + b"\x00" * 4, src_ip="198.51.100.7",
                          ttl_delta=-1)
        verify_ip_l4(g[:-4], "rewrite_ips")
        check(g.endswith(b"\x00" * 4) and P.frame_ips(g)[0] ==
              "198.51.100.7" and g[22] == f[22] - 1, "rewrite_ips fields")


# --- W3-C sites: redundancy rings, healthcare, BMS, batch (protocols_site) --
_DISSECTS_AS.update({
    "mrp": "pn_mrp", "dlr": "dlr", "dicom": "dicom", "hl7": "hl7",
    "knxip": "kip", "bacnet-cov": "bacapp", "enip-write": "cipcm",
    "smb-logon": "ntlmssp",
})
_W3C_SITES = ("auto-assembly", "hospital-iomt", "smart-building-dc",
              "pharma-batch")


def _l2_payload(frame: bytes):
    """(ethertype, vlan, payload) of a VLAN-tagged or untagged frame."""
    if frame[12:14] == b"\x81\x00":
        return (struct.unpack("!H", frame[16:18])[0],
                struct.unpack("!H", frame[14:16])[0] & 0x0FFF, frame[18:])
    return struct.unpack("!H", frame[12:14])[0], None, frame[14:]


def _tcp_data(l4: bytes) -> bytes:
    """TCP payload of a TCP header + data (honours the data offset)."""
    return l4[(l4[12] >> 4) * 4:]


def test_site_builders_wire_format() -> None:
    """Byte-level checks of the ring, DICOM, HL7, KNX, COV, recipe-write and
    NTLM logon builders."""
    f = protocols.get("mrp").build(Endpoints(meta={
        "mrp_prio": 0x8000, "mrp_domain_uuid": "ab" * 16}), 2)
    et, vid, pl = _l2_payload(f[0])
    check(f[0][:6] == bytes.fromhex("01154e000001") and et == 0x88E3
          and vid is not None and f[0][14] >> 5 == 7,
          "mrp: not a PCP-7 tagged MRP_Test to 01:15:4e:00:00:01")
    check(pl[:4] == b"\x00\x01\x02\x12" and pl[4:6] == b"\x80\x00"
          and pl[6:12] == f[0][6:12] and b"\xab" * 16 in pl,
          "mrp: MRP_Test TLV / priority / SA / domain UUID wrong")
    check({fr[6:12] for fr in f} == {f[0][6:12]} and len(f) == 4,
          "mrp: test frames should leave both ring ports of one manager")
    f = protocols.get("dlr").build(Endpoints(meta={
        "dlr_precedence": 200, "dlr_beacon_interval": 400}), 2)
    et, vid, pl = _l2_payload(f[0])
    check(f[0][:6] == bytes.fromhex("01216c000001") and et == 0x80E1
          and pl[:3] == b"\x02\x01\x01" and pl[3] in (1, 2),
          "dlr: not a beacon to 01:21:6c:00:00:01")
    check(pl[13] == 200 and struct.unpack("!I", pl[14:18])[0] == 400,
          "dlr: precedence / beacon interval not stated")
    ep = Endpoints(meta={"dicom_ae": "PACS_AE", "client_dicom_ae": "CT_AE",
                         "client_dicom_impl_uid": "1.2.3.4",
                         "client_dicom_impl_version": "CT_SW_1",
                         "client_dicom_software": "SP4",
                         "client_dicom_serial": "123456CN7"})
    tcp = [_l4(x) for x in protocols.get("dicom").build(ep, 2)]
    to_scp = b"".join(_tcp_data(t[5]) for t in tcp if t[4] == 104)
    from_scp = b"".join(_tcp_data(t[5]) for t in tcp if t[3] == 104)
    check(to_scp[:1] == b"\x01" and to_scp[10:26] == b"PACS_AE".ljust(16)
          and to_scp[26:42] == b"CT_AE".ljust(16),
          "dicom: A-ASSOCIATE-RQ called/calling AE titles")
    check(b"1.2.3.4" in to_scp and b"CT_SW_1" in to_scp,
          "dicom: implementation class UID / version name missing")
    check(from_scp[:1] == b"\x02" and b"\x06\x00\x00\x00\x00\x04" in from_scp,
          "dicom: no A-ASSOCIATE-AC / A-RELEASE-RP")
    check(b"ANON^TEST" in to_scp and b"SP4" in to_scp
          and b"123456CN7" in to_scp, "dicom: C-STORE data set identity")
    ep = Endpoints(meta={"hl7_app": "ENGINE", "hl7_facility": "HOSP",
                         "client_hl7_app": "EHR", "client_hl7_facility": "H1",
                         "hl7_events": "mixed"})
    tcp = [_l4(x) for x in protocols.get("hl7").build(ep, 2)]
    msgs = [_tcp_data(t[5]) for t in tcp if _tcp_data(t[5])]
    check(all(m[:1] == b"\x0b" and m.endswith(b"\x1c\r") for m in msgs),
          "hl7: MLLP framing")
    req = [m for m in msgs if b"|ACK^" not in m]
    check(req and all(m[1:].startswith(b"MSH|^~\\&|EHR|H1|ENGINE|HOSP|")
                      for m in req), "hl7: MSH sending/receiving app")
    check(any(b"ADT^A01" in m for m in req) and any(b"ORU^R01" in m
                                                    for m in req),
          "hl7: ADT^A01 / ORU^R01 missing")
    check(sum(b"MSA|AA|" in m for m in msgs) == len(req),
          "hl7: every message needs an AA acknowledgement")
    f = protocols.get("knxip").build(Endpoints(), 2)
    knx = [_l4(x) for x in f]
    check(knx[0][2] == "224.0.23.12" and knx[0][5][8:12] ==
          b"\x06\x10\x02\x01", "knxip: SEARCH_REQUEST not multicast")
    check(any(t[5][8:12] == b"\x06\x10\x05\x30" for t in knx),
          "knxip: no ROUTING_INDICATION")
    cov = [_l4(x)[5][8:] for x in protocols.get("bacnet-cov")
           .build(Endpoints(), 2)]
    check(cov[0][6:10] == b"\x00\x05\x01\x05" or cov[0][7] == 0x05,
          "bacnet-cov: no SubscribeCOV")
    check(any(c[6:8] == b"\x10\x02" for c in cov),
          "bacnet-cov: no UnconfirmedCOVNotification")
    wr = b"".join(_tcp_data(_l4(x)[5]) for x in protocols.get("enip-write").build(
        Endpoints(meta={"recipe_unit": "GR102"}), 1))
    check(b"\x52\x02\x20\x06\x24\x01" in wr and b"\x4d" in wr
          and b"\x91\x09GR102_RCP\x00\x91\x07Temp_SP\x00" in wr
          and b"\xcd\x00\x00\x00" in wr,
          "enip-write: no Write Tag (0x4D) inside an Unconnected Send")
    sm = b"".join(_tcp_data(_l4(x)[5]) for x in protocols.get("smb-logon").build(
        Endpoints(meta={"smb_user": "svc_x", "smb_domain": "DOM"}), 1))
    check(b"NTLMSSP\x00\x03\x00\x00\x00" in sm and "svc_x".encode(
        "utf-16-le") in sm and "DOM".encode("utf-16-le") in sm,
          "smb-logon: NTLMSSP AUTHENTICATE without domain\\user")


def test_w3c_sites_load_and_plant_findings() -> None:
    """The four W3-C sites load from tgt/envs/sites, build, keep L2 ring /
    KNX traffic on one segment, never ARP for external endpoints, and carry
    their planted findings on the wire."""
    from tgt import enterprise, envfile, inventory
    # other tests register/unregister env dirs: reload the packaged sites
    envfile.load_user_envs(warn=lambda m: None, force=True)
    for key in _W3C_SITES:
        env = enterprise.ENVIRONMENTS.get(key)
        check(env is not None, f"site {key} not auto-loaded")
        if env is None:
            continue
        batch = env.build(1)
        mac_seg = {P.mac_to_bytes(h.mac): env.segment_of(h).vlan
                   for h in env.hosts}
        for k, fr in batch:
            if k in ("mrp", "dlr", "knxip"):
                check(_vlan(fr) is not None and
                      mac_seg.get(fr[6:12]) == _vlan(fr),
                      f"{key}: {k} frame left its segment / was routed")
        ext_ips = {h.ip for h in env.external}
        for k, fr in batch:
            et, _, pl = _l2_payload(fr)
            if et == 0x0806:
                spa, tpa = (".".join(map(str, pl[a:a + 4]))
                            for a in (14, 24))
                check(spa not in ext_ips and tpa not in ext_ips,
                      f"{key}: ARP for an external endpoint")
        doc = inventory.to_json(env)
        inv_ips = {h["ip"] for h in doc["hosts"]}
        listed = {e["ip"]: e for e in doc["external"]}
        for h in env.external:
            check(h.ip in listed and h.ip not in inv_ips and
                  listed[h.ip]["kind"] == h.role and
                  (not h.fqdn or h.fqdn in listed[h.ip]["fqdns"]),
                  f"{key}: external {h.name} not listed as external")
        check(not any(e["kind"] == "unknown" for e in doc["external"]),
              f"{key}: unexplained public address on the wire")
        if key == "hospital-iomt":
            rows = {h["ip"]: h for h in doc["hosts"]}
            for c, s, p in env.conversations:
                if p != "dicom":
                    continue
                h = env.host(c)
                blob = b"".join(fr for k, fr in batch if k == "dicom"
                                and _l4(fr)[1] == h.ip)
                row = rows[h.ip]
                check(row["firmware"].encode() in blob and
                      row["serial"].encode() in blob and
                      h.device.identity["dicom"]["model"].encode() in blob,
                      f"{key}: {c} DICOM identity != inventory")
    conv = {k: set(enterprise.ENVIRONMENTS.get(k).conversations) for k in _W3C_SITES
            if enterprise.ENVIRONMENTS.get(k) is not None}
    aa = conv.get("auto-assembly", set())
    check(("LAPTOP-INTEG", "ET-BIW-05", "pn-dcp-set") in aa and
          ("ENG-TIA", "ROB-BIW-04", "vnc") in aa and
          ("EDGE-GW01", "CLOUD-MQTT", "sparkplug") in aa and
          ("PLC-BIW-R1", "PLC-BIW-R2", "pn-rt") in aa,
          "auto-assembly: planted findings / redundant pair missing")
    env = enterprise.ENVIRONMENTS.get("auto-assembly")
    if env is not None:
        who = {fr[6:12] for k, fr in env.build(1) if k == "pn-dcp"
               and b"et-biw-03" in fr and fr[:6] != b"\x01\x0e\xcf\x00\x00\x00"}
        check(len(who) == 2, "auto-assembly: duplicate NameOfStation "
              f"answered by {len(who)} devices")
    env = enterprise.ENVIRONMENTS.get("hospital-iomt")
    if env is not None:
        check(env.host("CR-LEGACY") in env.legacy_hosts() and
              ("PUMP-017", "PUMP-VENDOR-CLOUD", "https")
              in conv["hospital-iomt"], "hospital-iomt: findings missing")
    env = enterprise.ENVIRONMENTS.get("smart-building-dc")
    if env is not None:
        check(("GUEST-03", "JACE-01", "bacnet-id") in conv["smart-building-dc"]
              and ("CAM-10", "HIK-CLOUD", "https") in conv["smart-building-dc"]
              and env.snmp_community(env.host("UPS-01")) == "public",
              "smart-building-dc: findings missing")
    env = enterprise.ENVIRONMENTS.get("pharma-batch")
    if env is not None:
        batch = env.build(1)
        writers = {_l4(fr)[1] for k, fr in batch if k == "enip-write"}
        check(env.host("LIMS01").ip in writers,
              "pharma-batch: no recipe write from the LIMS host")
        svc = "svc_batch".encode("utf-16-le")
        users = {_l4(fr)[1] for k, fr in batch if k == "smb-logon"
                 and svc in fr}
        check(len(users) >= 5, f"pharma-batch: svc_batch from {len(users)} "
              "hosts")


def test_tshark_w3c_sites_clean() -> None:
    """Optional: each W3-C site decodes with no tshark warnings or errors
    beyond deliberate RST closes, and the new dissectors see their layers."""
    import shutil
    import subprocess
    from tgt import enterprise, envfile
    envfile.load_user_envs()
    if not shutil.which("tshark"):
        _skipped.append("test_tshark_w3c_sites_clean")
        return
    want = {"auto-assembly": ("pn_mrp", "dlr", "pn_dcp", "mqtt"),
            "hospital-iomt": ("dicom", "hl7"),
            "smart-building-dc": ("kip", "bacapp", "snmp"),
            "pharma-batch": ("cipcm", "ntlmssp", "syslog")}
    for key, layers in want.items():
        env = enterprise.ENVIRONMENTS.get(key)
        if env is None:
            continue
        with tempfile.TemporaryDirectory() as d:
            path = f"{d}/{key}.pcap"
            with PcapWriter(path) as w:
                for _, f in env.build(1):
                    w.write(f)
            seen = subprocess.run(
                ["tshark", "-r", path, "-T", "fields", "-e",
                 "frame.protocols"], capture_output=True, text=True).stdout
            expert = subprocess.run(
                ["tshark", "-r", path, "-q", "-z", "expert,warn"],
                capture_output=True, text=True).stdout
        seen_set = {x for ln in seen.split() for x in ln.split(":")}
        for layer in layers:
            check(layer in seen_set, f"tshark {key}: no {layer} layer")
        warns = [ln.strip() for ln in expert.splitlines()
                 if ln.strip() and ln.strip()[0].isdigit()
                 and "Connection reset (RST)" not in ln]
        check("Errors (" not in expert and not warns,
              f"tshark {key}: {warns[:3]}")


def test_env_file_external_endpoints() -> None:
    """``external[]``: parsed, selectable by exact name / role only, kept out
    of segments, exported and reloaded."""
    import copy
    from tgt import envfile, inventory
    base = {"key": "t-ext", "segments": [
        {"name": "A", "vlan": 10, "subnet": "10.8.0.0/24", "zone": "OT-CELL"},
        {"name": "B", "vlan": 20, "subnet": "10.8.1.0/24", "zone": "IT"}],
        "hosts": [{"name": "GW-1", "ip": "10.8.0.10", "role": "gateway",
                   "os": "linux"},
                  {"name": "DNS", "ip": "10.8.1.10", "role": "dc",
                   "os": "win2019"}] +
                 [{"name": f"WS{i}", "ip": f"10.8.1.{20 + i}", "role": "ws",
                   "os": "win10"} for i in range(8)],
        "external": [{"name": "GW-CLOUD", "ip": "203.0.113.50",
                      "role": "mqtt-broker", "os": "linux",
                      "fqdn": "broker.example.net"}],
        "flows": [{"from": "GW-*", "to": "role:mqtt-broker",
                   "proto": "mqtt"},
                  {"client": "GW-1", "server": "DNS", "proto": "dns"}]}
    env = envfile.from_dict(copy.deepcopy(base), "x.json")
    check(set(env.conversations) == {("GW-1", "GW-CLOUD", "mqtt"),
                                     ("GW-1", "DNS", "dns")},
          f"external selectors: {env.conversations}")
    check(env.is_external("GW-CLOUD") and env.host("GW-CLOUD").ip ==
          "203.0.113.50" and env.segment_or_none(env.host("GW-CLOUD")) is None,
          "external endpoint lookup")
    dns = b"".join(f for k, f in env.build(1) if k == "dns")
    check(b"\x06broker\x07example\x03net" in dns,
          "DNS does not resolve the external FQDN")
    again = envfile.from_dict(envfile.to_dict(env), "y.json")
    check([h.ip for h in again.external] == ["203.0.113.50"] and
          set(again.conversations) == set(env.conversations),
          "external endpoints lost on export/reload")
    check([e["ip"] for e in inventory.to_json(env)["external"]
           if e["kind"] != "edr-cloud"] == ["203.0.113.50"],
          "inventory external list")
    for mutate, want in (
            (lambda d: d["external"][0].update(ip="10.8.0.99"),
             "inside a segment"),
            (lambda d: d["external"][0].update(name="DNS"),
             "duplicate host name"),
            (lambda d: d["external"][0].update(ip="10.8.1.10"),
             "already used"),
            (lambda d: d["flows"].append({"from": "WS0", "to": "@A",
                                          "proto": "https"}), None)):
        d = copy.deepcopy(base)
        mutate(d)
        try:
            e2 = envfile.from_dict(d, "x.json")
        except envfile.EnvFileError as e:
            check(want is not None and want in str(e),
                  f"external schema error for {want!r}: {e}")
        else:
            if want is not None:
                _failures.append(f"external error not raised: {want!r}")
            else:       # "@A" picks segment hosts, never the external
                check(all(s != "GW-CLOUD" for _, s, p in e2.conversations
                          if p == "https"), "@SEG matched an external")

# ---- time model: timed scheduler, persistent sessions, campaigns (#39 #56) --
def _timed_run(d: str, name: str, **kw) -> tuple:
    """A synthetic-clock timed run -> (records [(ts, frame)], manifest)."""
    import json
    from tgt.engine import Engine
    cfg = RunConfig(**dict(dict(schedule="timed", clock="synthetic",
                                start_time="2026-11-02T08:00:00Z", rate=0,
                                seed=11), **kw))
    cfg.pcap_path = os.path.join(d, name + ".pcap")
    cfg.manifest_path = os.path.join(d, name + ".json")
    eng = Engine(cfg)
    eng.start()
    eng.join(120)
    check(not eng.is_alive(), f"timed run {name} did not finish")
    with open(cfg.manifest_path) as fh:
        return _pcap_records(cfg.pcap_path), json.load(fh)


def _tcp_rows(records, port: int) -> list:
    """(ts, src ip, dst ip, sport, dport, flags, seq, ack, payload len) of
    every TCP segment to/from ``port``."""
    out = []
    for ts, f in records:
        off = 18 if f[12:14] == b"\x81\x00" else 14
        if f[off - 2:off] != b"\x08\x00" or f[off + 9] != P.IPPROTO_TCP:
            continue
        ihl = (f[off] & 15) * 4
        tot = struct.unpack("!H", f[off + 2:off + 4])[0]
        l4 = off + ihl
        sp, dp, seq, ack = struct.unpack("!HHII", f[l4:l4 + 12])
        if port not in (sp, dp):
            continue
        doff = (f[l4 + 12] >> 4) * 4
        out.append((ts, ".".join(map(str, f[off + 12:off + 16])),
                    ".".join(map(str, f[off + 16:off + 20])), sp, dp,
                    f[l4 + 13], seq, ack, tot - ihl - doff))
    return out


def test_timed_parse_duration_and_tables() -> None:
    from tgt import timing
    for text, want in (("90", 90), ("500ms", 0.5), ("30m", 1800),
                       ("4h", 14400), ("7d", 604800), ("1h30m", 5400),
                       (12, 12)):
        check(timing.parse_duration(text) == want, f"duration {text!r}")
    for bad in ("", "4x", "h", "10 parsecs"):
        try:
            timing.parse_duration(bad)
            check(False, f"duration {bad!r} accepted")
        except ValueError:
            pass
    # every registered protocol has a sane table row (or the default)
    for key in protocols.PROFILES:
        lo, hi, jit, n, cls = timing.spec(key)
        check(0 < lo <= hi and 0 <= jit < 1 and n >= 1 and cls in (
            "ot", "infra", "office", "eng", "operator"), f"timing {key}")
    for prof, classes in timing.DAY_PROFILES.items():
        for cls, (wd, we) in classes.items():
            check(len(wd) == 24 and len(we) == 24, f"{prof}/{cls} hours")
    # a conversation's period is stable and env-file timing wins
    from tgt import enterprise, envfile
    env = enterprise.get("ot-plant")
    conv = next(c for c in env.conversations if c[2] == "modbus")
    a = timing.conversation_timing(env, conv)
    check(a == timing.conversation_timing(env, conv)
          and 0.5 <= a["period"] <= 2.0, f"modbus period {a}")
    doc = envfile.to_dict(env)
    for f in doc["flows"]:
        if (f["client"], f["server"], f["proto"]) == conv:
            f["period"], f["jitter"] = "250ms", "10%"
    env2 = envfile.from_dict(doc)
    check(timing.conversation_timing(env2, conv) ==
          {"period": 0.25, "jitter": 0.1}, "env-file period/jitter ignored")


def test_timed_persistent_table_matches_builders() -> None:
    """Each PERSISTENT entry's setup/teardown counts cut the builder's
    session at the right places: polls grow with count, the first exchange
    opens TCP (SYN), the last closes it (FIN)."""
    from tgt import enterprise, schedule, timing
    site = enterprise.get("industrial-site")
    eps = {}
    for c, s, p in site.conversations:
        eps.setdefault(p, site.conv_endpoints(site.host(c), site.host(s), p))
    for proto, (setup, teardown, _) in timing.PERSISTENT.items():
        ep = eps.get(proto) or Endpoints()
        cm = P.mac_to_bytes(ep.client_mac)
        n = []
        for k in (3, 6):
            protocols.begin_build(1, 1)
            g = schedule.exchanges(protocols.get(proto).build(ep, k), cm)
            n.append(len(g))
            if protocols.get(proto).transport == "tcp" or proto == "enip-io":
                first = schedule.view(g[0][0], cm)
                check(first[5] and first[1] == schedule.SYN,
                      f"{proto}: first exchange is not the handshake")
            if teardown:
                last = [schedule.view(f, cm)[1] for f in g[-1]]
                check(any(x & schedule.FIN for x in last),
                      f"{proto}: last exchange does not close")
        check(n[0] > setup + teardown and n[1] > n[0],
              f"{proto}: {n} exchanges for 3/6 polls (setup {setup}, "
              f"teardown {teardown})")


def test_timed_periods_rtt_and_persistent_sessions() -> None:
    from tgt import enterprise, timing
    env = enterprise.get("ot-plant")
    with tempfile.TemporaryDirectory() as d:
        recs, m = _timed_run(d, "plant", env="ot-plant", duration=600.0)
    check(len(recs) > 5000, f"timed ot-plant 10 min: {len(recs)} frames")
    t0 = recs[0][0]
    check(recs[-1][0] - t0 > 590 and all(
        b[0] >= a[0] for a, b in zip(recs, recs[1:])),
        "timed pcap does not span 10 minutes in time order")
    for _, f in recs[:3000]:
        verify_ip_l4(f, "timed")
    # Modbus: one connection per poller, polls every period (+-5 %)
    rows = _tcp_rows(recs, 502)
    hosts = {h.ip: h.name for h in env.hosts}
    by_pair = {}
    for r in rows:
        key = (r[1], r[2]) if r[4] == 502 else (r[2], r[1])
        by_pair.setdefault(key, []).append(r)
    check(len(by_pair) == 2, f"modbus pollers: {sorted(by_pair)}")
    for (cip, sip), rs in by_pair.items():
        syns = [r for r in rs if r[5] == P.SYN]
        reqs = [r for r in rs if r[8] > 0 and r[4] == 502]
        ports = {r[3] if r[4] == 502 else r[4] for r in rs}
        check(len(syns) == 1 and len(ports) == 1,
              f"modbus {cip}->{sip}: {len(syns)} SYNs, ports {sorted(ports)}")
        check(len(reqs) > 250, f"modbus {cip}->{sip}: {len(reqs)} polls")
        # client byte stream is contiguous across chunks (no gaps/overlap)
        for a, b in zip(reqs, reqs[1:]):
            if b[6] != (a[6] + a[8]) & 0xFFFFFFFF:
                check(False, f"modbus {cip}->{sip}: seq gap {a[6]}+{a[8]} "
                             f"-> {b[6]}")
                break
        gaps = sorted(b[0] - a[0] for a, b in zip(reqs, reqs[1:]))
        want = timing.conversation_timing(
            env, (hosts[cip], hosts[sip], "modbus"))["period"]
        med = gaps[len(gaps) // 2]
        check(abs(med - want) / want < 0.05,
              f"modbus {cip}->{sip}: median poll gap {med:.3f}s, "
              f"period {want:.3f}s")
        fl = next(f for f in m["flows_seen"] if f["protocol"] == "modbus"
                  and f["client"] == f"ot-plant:{hosts[cip]}")
        check(abs(fl["period_s"] - want) / want < 0.05
              and fl["jitter"] < 0.05 and fl["occurrences"] > 250,
              f"manifest modbus period {fl}")
    # RTT: switched < routed (to the same PLC) < WAN (EDR cloud)
    def resp_gap(rs):
        out, last = [], None
        for r in rs:
            if r[8] > 0 and r[4] == 502:
                last = r
            elif r[8] > 0 and r[3] == 502 and last is not None:
                out.append(r[0] - last[0])
                last = None
        return sorted(out)[len(out) // 2]
    same = {k: v for k, v in by_pair.items()
            if env.segment_of(env.host(hosts[k[0]])) is
            env.segment_of(env.host(hosts[k[1]]))}
    routed = {k: v for k, v in by_pair.items() if k not in same}
    check(same and routed, "need a switched and a routed Modbus poller")
    s_rtt = resp_gap(next(iter(same.values())))
    r_rtt = resp_gap(next(iter(routed.values())))
    hs = [r for r in _tcp_rows(recs, 443)
          if r[5] in (P.SYN, P.SYN | P.ACK)]
    wan = []
    for a, b in zip(hs, hs[1:]):
        if a[5] == P.SYN and b[5] == P.SYN | P.ACK and a[3] == b[4] and \
                not b[1].startswith("172.16."):
            wan.append(b[0] - a[0])
    w_rtt = sorted(wan)[len(wan) // 2] if wan else 0
    check(s_rtt < r_rtt < w_rtt and w_rtt >= 0.02,
          f"RTT ordering switched {s_rtt:.5f} < routed {r_rtt:.5f} < WAN "
          f"{w_rtt:.5f}")
    # the inventory carries each flow's nominal period
    inv = {(f["client"], f["server"], f["protocol"]): f
           for f in m["inventory"]["flows"]}
    check(all("period_s" in f for f in inv.values()), "inventory period_s")


def test_timed_seed_determinism_and_cycle_default() -> None:
    from tgt import cli
    with tempfile.TemporaryDirectory() as d:
        a, ma = _timed_run(d, "a", env="it-org", duration=120.0,
                           sprinkle=["wannacry"])
        b, mb = _timed_run(d, "b", env="it-org", duration=120.0,
                           sprinkle=["wannacry"])
        c, _ = _timed_run(d, "c", env="it-org", duration=120.0, seed=12,
                          sprinkle=["wannacry"])
    check(a == b and len(a) > 1000, "timed: same seed, different pcaps")
    check(ma["flows_seen"] == mb["flows_seen"]
          and ma["events"] == mb["events"], "timed: manifests differ")
    check(a != c, "timed: different seeds give identical pcaps")
    check(any(e["source"] == "sprinkle:wannacry" for e in ma["events"]),
          "timed sprinkle: no attack events")
    ns = cli.build_parser().parse_args(["run", "-e", "it-org", "--pcap", "x"])
    check(ns.schedule == "cycle" and ns.rate is None and ns.speed == 1.0,
          "cycle must stay the default schedule")
    ns = cli.build_parser().parse_args(
        ["run", "-e", "it-org", "--schedule", "timed", "--duration", "7d",
         "--speed", "60", "--day-profile", "shift", "--min-period", "2s"])
    check(ns.duration == 604800 and ns.min_period == 2 and ns.speed == 60,
          "timed CLI flags")


def test_timed_day_profile_shapes_volume() -> None:
    from tgt import enterprise, schedule, timing
    env = enterprise.get("it-org")
    office = [s for s in schedule.env_streams(env)
              if s.cls == "office" and s.key in ("dns", "https")][:6]
    ot = schedule.profile_streams(["modbus"], Endpoints())
    check(len(office) == 6, "it-org office streams")
    # Mon 2026-11-02 00:00 UTC .. Sun 2026-11-08: weekday vs weekend, hour
    sch = schedule.Scheduler(5, 1793577600.0, "shift")
    for s in office + ot:
        s.period = 300.0 if s.key != "modbus" else 60.0
    sch.load(office + ot, 0.0, initial=True)
    hours = {}
    for t, _, key, _, _, occ in sch.run(6 * 86400.0):
        if occ:
            h = int(t // 3600)
            hours.setdefault(key == "modbus", {}).setdefault(h, 0)
            hours[key == "modbus"][h] += 1
    off, mb = hours.get(False, {}), hours.get(True, {})

    def tot(d, days, hrs):
        return sum(d.get(24 * day + h, 0) for day in days for h in hrs)
    night = tot(off, range(5), range(0, 5))
    morning = tot(off, range(5), range(8, 12))
    lunch = tot(off, range(5), [12])
    weekend = tot(off, [5], range(8, 12))
    check(morning > 8 * max(night, 1) and lunch < morning / 4 * 0.8
          and weekend < morning / 5 / 5,
          f"shift profile: night {night}, 08-12 {morning}, lunch {lunch}, "
          f"weekend 08-12 {weekend}")
    logon = tot(off, range(5), [7])
    check(logon > morning / 4 * 1.5, f"no 07:00 logon peak: {logon}")
    mb_day, mb_night = tot(mb, range(5), range(8, 12)), \
        tot(mb, range(5), range(0, 4))
    check(abs(mb_day - mb_night) <= 0.05 * mb_day,
          f"OT polling not steady: {mb_day} vs {mb_night}")
    check(timing.factor("shift", "ot", 1793577600.0) == 1.0, "ot factor")


def test_campaign_plans_events_and_validation() -> None:
    from tgt import campaign
    plans = campaign.packaged()
    check(len(plans) >= 3, f"example campaigns: {plans}")
    for p in plans:
        plan = campaign.load(p)
        phases = campaign.build(plan)
        check(not campaign.validate(phases),
              f"{p}: {campaign.validate(phases)}")
    ph = campaign.build(campaign.load(campaign.find("baseline-then-change")))
    cats = [[e["category"] for e in p.events] for p in ph]
    check(cats == [[], ["new-asset"], ["firmware-change"],
                   ["new-asset", "cross-zone"],
                   ["asset-offline", "asset-offline"]],
          f"baseline-then-change events {cats}")
    check(ph[2].diff["changed"] == [{
        "asset_id": "industrial-site:PLC-PK2", "name": "PLC-PK2",
        "field": "firmware", "old": "20.055", "new": "20.058"}],
        f"firmware diff {ph[2].diff['changed']}")
    check("industrial-site:PLC-UT2" in ph[4].diff["offline"]
          and "industrial-site:LAPTOP-VENDOR" in ph[4].diff["removed"],
          "offline/removed diff")
    drift = campaign.build(campaign.load(campaign.find("ot-plant-drift")))
    check([e["category"] for p in drift for e in p.events] ==
          ["asset-change", "ip-change", "new-conversation", "asset-offline"],
          "ot-plant-drift events")
    # validation: a phase too short for the conversations it changes
    short = campaign.Plan({"env": "ot-plant", "phases": [
        {"name": "b", "duration": "10m"},
        {"name": "c", "duration": "5m",
         "set": [{"host": "PLC-RW1", "firmware": "20.056"}]}]}, "t.json")
    probs = campaign.validate(campaign.build(short))
    check(len(probs) == 2 and "enip-" in probs[0], f"validation {probs}")
    for bad, msg in (
            ({"env": "ot-plant", "phases": []}, "phases"),
            ({"env": "nope", "phases": [{"duration": 1}]}, "unknown"),
            ({"env": "ot-plant", "phases": [{"duration": "1h",
                                             "frobnicate": 1}]}, "frobnicate"),
            ({"env": "ot-plant", "phases": [{"duration": "1h", "set": [
                {"host": "NOPE", "ip": "172.16.1.99"}]}]}, "NOPE"),
            ({"env": "ot-plant", "phases": [{"duration": "1h", "add_host": [
                {"name": "X", "ip": "8.8.8.8", "role": "ws",
                 "os": "win10"}]}]}, "8.8.8.8")):
        try:
            campaign.build(campaign.Plan(bad, "t.json"))
            check(False, f"bad plan accepted: {bad}")
        except campaign.CampaignError as e:
            check(msg in str(e), f"bad plan message {e}")


def test_campaign_run_manifest_and_score() -> None:
    import json
    import subprocess
    from tgt import campaign
    plan = {"env": "ot-plant", "seed": 3, "phases": [
        {"name": "baseline", "duration": "4m"},
        {"name": "arrive", "duration": "3m",
         "add_host": [{"name": "LAPTOP-X", "ip": "172.16.0.77", "role": "ws",
                       "os": "win10", "mac": "3c:52:82:4a:10:96"}],
         "add_flow": [{"client": "LAPTOP-X", "server": "PLC-S7-1",
                       "proto": "s7comm"},
                      {"client": "ENGWS01", "server": "PLC-S7-2",
                       "proto": "modbus"},
                      {"client": "PLC-RW1", "server": "PLC-S7-1",
                       "proto": "s7comm"}]},
        {"name": "changes", "duration": "3m",
         "set": [{"host": "PLC-RW1", "firmware": "20.056"},
                 {"host": "PLC-S7-1", "ip": "172.16.2.41"}]},
        {"name": "gone", "duration": "3m", "offline": ["PLC-RW2"],
         "sprinkle": ["triton"]}]}
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "plan.json")
        with open(path, "w") as f:
            json.dump(plan, f)
        check(campaign.validate(campaign.build(campaign.load(path))),
              "4-minute phases should fail validation")
        recs, m = _timed_run(d, "camp", env="ot-plant", campaign=path,
                             seed=3)
        ph = {p["id"]: p for p in m["phases"]}
        check([p["name"] for p in m["phases"]] ==
              ["baseline", "arrive", "changes", "gone"]
              and ph["p2"]["start"] == "2026-11-02T08:04:00.000000Z"
              and ph["p4"]["end"] == "2026-11-02T08:13:00.000000Z"
              and sum(p["packets"] for p in m["phases"]) == m["packets"],
              f"campaign phases {[(p['id'], p['start'], p['end']) for p in m['phases']]}")
        ev = {}
        for e in m["events"]:
            ev.setdefault(e["category"], []).append(e)
        for cat in ("new-asset", "new-conversation", "firmware-change",
                    "ip-change", "asset-offline", "cross-zone"):
            check(cat in ev, f"campaign: no {cat} event")
        check(any(e["source"] == "sprinkle:triton" for e in m["events"]),
              "campaign: no sprinkle event in the last phase")
        na = next(e for e in ev["new-asset"]
                  if e["source"].startswith("campaign:"))
        check(na["hosts"] == ["ot-plant:LAPTOP-X"]
              and na["t_start"] == ph["p2"]["start"]
              and na["t_end"] == ph["p2"]["end"]
              and m["first_seen"].get("ot-plant:LAPTOP-X", "") >=
              ph["p2"]["start"], f"new-asset event {na}")
        ipc = ev["ip-change"][0]
        check(ipc["src"] == "172.16.2.41" and ipc["dst"] == "172.16.2.21",
              f"ip-change {ipc}")
        inv = {h["name"]: h for h in m["inventory"]["hosts"]}
        check("LAPTOP-X" in inv and inv["LAPTOP-X"]["phases"] ==
              ["p2", "p3", "p4"] and inv["PLC-RW2"]["online_phases"] ==
              ["p1", "p2", "p3"] and inv["PLC-S7-1"]["ip_history"] ==
              ["172.16.2.21", "172.16.2.41"], "campaign union inventory")
        # the offline PLC is silent; its pollers retry with SYNs
        gone = P.mac_to_bytes(inv["PLC-RW2"]["mac"])
        t_off = recs[0][0] + 600
        late = [f for ts, f in recs if ts > t_off + 1 and f[6:12] == gone]
        check(not late, f"offline PLC-RW2 sent {len(late)} frames")
        rw2 = inv["PLC-RW2"]["ip"]
        retries = [r for r in _tcp_rows(recs, 44818)
                   if r[0] > t_off and r[2] == rw2 and r[5] == P.SYN]
        check(len(retries) >= 3, f"no SYN retries to PLC-RW2: {retries}")
        # announcements: gratuitous ARP on arrival and IP change
        garp = {(ts, f[32:36]) for ts, f in recs
                if f[12:14] == b"\x81\x00" and f[16:18] == b"\x08\x06"
                and f[32:36] == f[42:46] and f[24:26] == b"\x00\x01"}
        for ip, t in (("172.16.0.77", 240), ("172.16.2.41", 420)):
            check(any(abs(ts - recs[0][0] - t) < 5 and a == P.ip_to_bytes(ip)
                      for ts, a in garp), f"no gratuitous ARP for {ip}")
        # tgt score runs against the campaign manifest
        alerts = os.path.join(d, "alerts.csv")
        assets = os.path.join(d, "assets.csv")
        with open(alerts, "w") as f:
            f.write("time,src,dst,title,category\n")
            f.write(f"{na['t_start'][:19]}Z,172.16.0.77,,New Asset Detected,"
                    "Asset\n")
            f.write(f"{ipc['t_start'][:19]}Z,172.16.2.41,,IP Address Change,"
                    "Asset\n")
        with open(assets, "w") as f:
            f.write("name,ip,mac\n")
            for h in m["inventory"]["hosts"]:
                f.write(f"{h['name']},{h['ip']},{h['mac']}\n")
        p = _cli(["score", "--manifest", os.path.join(d, "camp.json"),
                  "--assets", assets, "--map", "generic", "--alerts", alerts,
                  "--alert-map", "alerts-generic", "--json",
                  os.path.join(d, "s.json")])
        out, _ = p.communicate(timeout=60)
        check(p.returncode == 0, f"tgt score on campaign rc={p.returncode} "
                                 f"{out[-300:]}")
        with open(os.path.join(d, "s.json")) as f:
            r = json.load(f)
        det = r["detections"]["per_category"]
        check(det.get("new-asset", {}).get("detected") == 1
              and det.get("ip-change", {}).get("detected") == 1
              and r["discovery"]["recall"] > 0.9,
              f"score on campaign: {det} recall {r['discovery']['recall']}")
        if shutil_which("tshark"):
            out = subprocess.run(
                ["tshark", "-r", os.path.join(d, "camp.pcap"), "-q", "-z",
                 "expert,warn"], capture_output=True, text=True).stdout
            bad = [ln for ln in out.splitlines() if any(
                w in ln for w in ("Malformed", "retransmission", "Duplicate",
                                  "out-of-order", "not captured",
                                  "Bad checksum", "incorrect"))]
            check(not bad, f"tshark campaign: {bad[:3]}")


def test_build_run_args_timed_flags() -> None:
    import shlex
    from tgt import cli, service
    args = service.build_run_args(
        None, [], 0, 5, env="industrial-site", seed=42,
        manifest="/var/lib/tgt/run manifest.json", schedule="timed",
        speed=60, day_profile="shift", min_period=1.0, duration=86400)
    ns = cli.build_parser().parse_args(["run"] + shlex.split(args))
    check(ns.seed == 42 and ns.manifest == "/var/lib/tgt/run manifest.json"
          and ns.schedule == "timed" and ns.speed == 60
          and ns.day_profile == "shift" and ns.min_period == 1.0
          and ns.duration == 86400 and ns.rate == 0,
          f"build_run_args timed round trip: {args}")
    plain = service.build_run_args(None, ["modbus"], 20, 5)
    check("--schedule" not in plain and "--seed" not in plain,
          f"cycle args grew: {plain}")



# -- structured findings[] on every packaged site (#51) --
def _finding_on_wire(env, batch, client, server, proto) -> bool:
    """True when one build carries the flow: an IP flow by its (NAT-view)
    addresses, client -> server, with a reply from the port the client
    targeted (a one-way UDP flow needs only the request); a Layer-2 flow
    by a frame the server sends or receives."""
    c, s = env.nat_view(env.host(client), env.host(server))
    if c.ip == s.ip:                    # self-flow (broadcast announces)
        return any(k == proto and _l4(f) and _l4(f)[1] == c.ip
                   for k, f in batch)
    reqs, reps, l2 = [], [], False
    for k, f in batch:
        if k != proto:
            continue
        t = _l4(f)
        if t is None:
            l2 = l2 or s.mac in (P.bytes_to_mac(f[0:6]),
                                 P.bytes_to_mac(f[6:12]))
        elif (t[1], t[2]) == (c.ip, s.ip):
            reqs.append(t)
        elif (t[1], t[2]) == (s.ip, c.ip):
            reps.append(t)
    if l2:
        return True
    if not reqs:
        return False
    if reqs[0][0] not in (P.IPPROTO_TCP, P.IPPROTO_UDP):
        return True
    ports = {(t[3], t[4]) for t in reqs}
    if not reps:
        return reqs[0][0] == P.IPPROTO_UDP
    return any((t[4], t[3]) in ports for t in reps)


def test_every_site_has_wire_backed_findings() -> None:
    """Every packaged site declares >= 3 structured findings whose hosts
    exist, whose flows are env flows, which `tgt inventory -f json` lists,
    and whose every flow is on the wire in one build."""
    from tgt import envfile, inventory
    names = sorted(f[:-5] for f in os.listdir(envfile.SITES_DIR)
                   if f.endswith(".json"))
    check(len(names) >= 7, f"packaged sites: {names}")
    for key in names:
        env = envfile.load(os.path.join(envfile.SITES_DIR, f"{key}.json"))
        check(len(env.findings) >= 3,
              f"{key}: only {len(env.findings)} findings")
        known = {h.name for h in env.hosts} | {h.name for h in env.external}
        conv = set(env.conversations)
        for fd in env.findings:
            check(fd.get("severity") in envfile.SEVERITIES and
                  fd.get("category") and fd["flows"],
                  f"{key}: finding {fd['id']} lacks severity/category/flows")
            for h in fd["hosts"]:
                check(h in known, f"{key}: finding {fd['id']}: no host {h}")
            for fl in fd["flows"]:
                check((fl["client"], fl["server"], fl["proto"]) in conv,
                      f"{key}: finding {fd['id']}: {fl} not an env flow")
        check([f["id"] for f in inventory.to_json(env).get("findings", [])]
              == [f["id"] for f in env.findings],
              f"{key}: inventory JSON lacks the findings")
        protocols.begin_build(11, 0)
        batch = env.build(1)
        for fd in env.findings:
            for fl in fd["flows"]:
                check(_finding_on_wire(env, batch, fl["client"],
                                       fl["server"], fl["proto"]),
                      f"{key}: finding {fd['id']}: {fl} not on the wire")


# ---------------------------------------------------------------------------
# W3-D: multi-interface fan-out, control API, pcapng replay + rewrite, plugins
# ---------------------------------------------------------------------------
class _FakeSock:
    """Stands in for an AF_PACKET socket: records frames, optionally fails."""

    def __init__(self, name: str, fail: bool = False):
        self.name, self.fail, self.sent = name, fail, []

    def send(self, frame):
        if self.fail:
            raise OSError(100, f"Network is down ({self.name})")
        self.sent.append(frame)
        return len(frame)

    def close(self):
        pass


def test_fanout_sender_counts_per_interface() -> None:
    """--iface a,b,c: every frame goes to each socket; an interface that
    cannot open or send is counted per interface and never stops the
    others; the manifest carries the per-interface counters."""
    import json
    from tgt import sender as S
    socks = {}

    def fake_open(name):
        if name == "gone0":
            raise OSError(19, "No such device")
        socks[name] = _FakeSock(name, fail=(name == "down0"))
        return socks[name]

    real = S.RawSender._open_one
    S.RawSender._open_one = staticmethod(fake_open)
    try:
        check(S.split_ifaces(" a, b,a,,c ") == ["a", "b", "c"],
              "split_ifaces: order/dedupe")
        with tempfile.TemporaryDirectory() as d:
            cfg = RunConfig(profiles=["modbus"], rate=0, count=24,
                            iface="t1,down0,t2,gone0",
                            pcap_path=os.path.join(d, "f.pcap"),
                            manifest_path=os.path.join(d, "f.json"))
            eng = _run_engine(cfg)
            man = json.load(open(cfg.manifest_path))
            recs = _pcap_records(cfg.pcap_path)
        st = eng.stats
        check(st.packets == 24 and st.errors == 0,
              f"fan-out: packets={st.packets} errors={st.errors}")
        check(socks["t1"].sent == socks["t2"].sent and
              len(socks["t1"].sent) == 24, "fan-out: t1/t2 frames differ")
        check(len(recs) == 24, "fan-out: pcap != frames sent")
        pi = st.per_iface
        check(pi["t1"]["packets"] == pi["t2"]["packets"] == 24 and
              pi["down0"]["errors"] == 24 and pi["down0"]["packets"] == 0 and
              pi["gone0"]["errors"] >= 1 and "No such device" in
              pi["gone0"]["last_error"],
              f"fan-out: per-interface counters {pi}")
        check(man["interfaces"] == json.loads(json.dumps(pi)),
              "fan-out: manifest interfaces != stats")
        # all interfaces dead -> a send error per frame, nothing recorded
        S.RawSender._open_one = staticmethod(
            lambda n: _FakeSock(n, fail=True))
        with tempfile.TemporaryDirectory() as d:
            eng = _run_engine(RunConfig(profiles=["modbus"], rate=0, count=6,
                                        iface="x,y",
                                        pcap_path=os.path.join(d, "x.pcap")))
            check(eng.stats.packets == 0 and eng.stats.errors == 6 and
                  not _pcap_records(os.path.join(d, "x.pcap")),
                  "fan-out: all-down run recorded frames")
    finally:
        S.RawSender._open_one = real


_FANOUT_NS = r'''
import json, os, socket, subprocess, sys, time
sys.path.insert(0, sys.argv[1])
from tgt.config import RunConfig
from tgt.engine import Engine
for n in ("w3a", "w3b"):
    subprocess.run(["ip", "link", "add", n, "type", "veth", "peer", "name",
                    n + "-mon"], check=True)
    for x in (n, n + "-mon"):
        subprocess.run(["ip", "link", "set", x, "up"], check=True)
rx = {}
for n in ("w3a-mon", "w3b-mon"):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.bind((n, 0))
    s.setblocking(False)
    rx[n] = s
cfg = RunConfig(profiles=["modbus", "dns", "arp"], rate=0, count=60,
                iface="w3a,w3b", pcap_path=sys.argv[2])
eng = Engine(cfg)
eng.start()
eng.join(30)
time.sleep(0.3)
got = {}
for n, s in rx.items():
    frames = []
    while True:
        try:
            frames.append(s.recv(65535).hex())
        except BlockingIOError:
            break
    got[n] = frames
print(json.dumps({"got": got, "per_iface": eng.stats.per_iface,
                  "packets": eng.stats.packets}))
'''


def test_fanout_two_veths_in_netns() -> None:
    """Optional (needs `unshare -rn` + iproute2): fan-out to two real veths
    in a private network namespace; both peers receive exactly the frames
    written to the pcap, in order."""
    import json
    import shutil
    import subprocess
    if not (shutil.which("unshare") and shutil.which("ip")):
        _skipped.append("test_fanout_two_veths_in_netns")
        return
    with tempfile.TemporaryDirectory() as d:
        pcap = os.path.join(d, "ns.pcap")
        r = subprocess.run(["unshare", "-rn", sys.executable, "-c",
                            _FANOUT_NS, _REPO, pcap],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0 or not r.stdout.strip():
            _skipped.append("test_fanout_two_veths_in_netns")
            return
        res = json.loads(r.stdout.strip().splitlines()[-1])
        sent = [f.hex() for _, f in _pcap_records(pcap)]
    check(res["packets"] == 60 == len(sent), "netns fan-out: packet count")
    for n, frames in res["got"].items():
        mine = [f for f in frames if f in set(sent)]
        check(mine == sent, f"netns fan-out: {n} got {len(mine)}/{len(sent)}"
              " frames (or out of order)")
    check(all(c["packets"] == 60 and c["errors"] == 0
              for c in res["per_iface"].values()),
          f"netns fan-out: counters {res['per_iface']}")


def test_control_api_endpoints_and_injection() -> None:
    """--api: status/pause/resume/rate/inject/manifest/stop over HTTP, the
    security checks, and a timed injection recorded in the manifest with
    its exact first/last frame and per-attack events."""
    import contextlib
    import io
    import json
    import time
    import urllib.request
    from tgt import api, cli
    from tgt.engine import Engine
    with tempfile.TemporaryDirectory() as d:
        cfg = RunConfig(profiles=["modbus", "dns"], rate=400, duration=20,
                        pcap_path=os.path.join(d, "api.pcap"),
                        manifest_path=os.path.join(d, "api.json"), seed=9)
        eng = Engine(cfg)
        eng.record = True
        for host, remote, tok in (("0.0.0.0", False, None),
                                  ("0.0.0.0", True, None)):
            try:
                api.ControlServer(eng, host, 0, token=tok,
                                  allow_remote=remote).close()
                check(False, f"api: bound {host} remote={remote} tok={tok}")
            except api.ApiError:
                pass
        srv = api.ControlServer(eng, "127.0.0.1", 0).start()
        tsrv = api.ControlServer(eng, "127.0.0.1", 0, token="s3cret").start()
        a, ta = f"127.0.0.1:{srv.port}", f"127.0.0.1:{tsrv.port}"
        eng.start()
        try:
            time.sleep(0.2)
            code, st = api.request(a, "GET", "/status")
            check(code == 200 and st["running"] and st["seed"] == 9 and
                  st["config"]["rate"] == 400 and "uptime" in st,
                  f"api: /status {code} {st.get('error')}")
            check(api.request(ta, "GET", "/status")[0] == 401 and
                  api.request(ta, "GET", "/status", token="nope")[0] == 401
                  and api.request(ta, "GET", "/status",
                                  token="s3cret")[0] == 200,
                  "api: bearer token not enforced")
            check(api.request(a, "GET", "/stop")[0] == 405,
                  "api: GET /stop not refused")
            for hdr in ({"Origin": "http://evil.example"},
                        {"Host": "evil.example"}):
                req = urllib.request.Request(f"http://{a}/status",
                                             headers=hdr)
                try:
                    urllib.request.urlopen(req, timeout=5)
                    check(False, f"api: accepted {hdr}")
                except urllib.error.HTTPError as e:
                    check(e.code == 403, f"api: {hdr} -> {e.code}")
            check(api.request(a, "POST", "/inject",
                              {"incident": "nosuch"})[0] == 404,
                  "api: unknown incident not 404")
            # paused, the engine cannot start (or finish) i1, so the
            # second request meets it deterministically on a loaded box
            api.request(a, "POST", "/pause")
            code, r = api.request(a, "POST", "/inject",
                                  {"incident": "wannacry", "duration": 0.6,
                                   "ratio": 0.3})
            check(code == 202 and r["injection"]["id"] == "i1",
                  f"api: inject -> {code} {r}")
            check(api.request(a, "POST", "/inject",
                              {"incident": "wannacry"})[0] == 409,
                  "api: concurrent injection of one incident not refused")
            api.request(a, "POST", "/resume")
            check(api.request(a, "POST", "/rate", {"pps": 600})[0] == 200
                  and eng.cfg.rate == 600 and eng.limiter.pps == 600,
                  "api: /rate not applied")
            check(api.request(a, "POST", "/rate")[0] == 400,
                  "api: /rate without pps not 400")
            time.sleep(1.2)
            api.request(a, "POST", "/pause")
            time.sleep(0.15)
            n0 = eng.stats.packets
            time.sleep(0.3)
            code, st = api.request(a, "GET", "/status")
            check(st["paused"] and eng.stats.packets == n0,
                  "api: pause did not hold sending")
            api.request(a, "POST", "/resume")
            time.sleep(0.2)
            check(eng.stats.packets > n0, "api: resume did not continue")
            code, live = api.request(a, "GET", "/manifest")
            check(code == 200 and live["schema"] == "tgt-manifest/1",
                  "api: /manifest")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = cli.main(["ctl", "--api", a, "status"])
            check(rc == 0 and "injection i1 wannacry: done" in out.getvalue(),
                  f"tgt ctl status: {out.getvalue()[-300:]}")
            with contextlib.redirect_stdout(io.StringIO()):
                rc = cli.main(["ctl", "--api", a, "stop"])
            check(rc == 0, "tgt ctl stop failed")
            eng.join(5)
            check(not eng.is_alive(), "api: /stop did not stop the run")
        finally:
            eng.stop()
            eng.join(5)
            srv.close()
            tsrv.close()
        man = json.load(open(cfg.manifest_path))
        frames = _pcap_records(cfg.pcap_path)
    inj = man["injections"]
    check(len(inj) == 1 and inj[0]["incident"] == "wannacry" and
          inj[0]["packets"] > 0 and inj[0]["start"] and inj[0]["end"] and
          inj[0]["requested"] <= inj[0]["start"] <= inj[0]["end"],
          f"manifest injections: {inj}")
    evs = [e for e in man["events"] if e["source"] == "inject:wannacry#i1"
           and e.get("attack")]
    check({e["attack"] for e in evs} >= {"eternalblue", "port-scan"},
          f"manifest: injected attack events {[e.get('attack') for e in evs]}")
    check(sum(e["packets"] for e in evs) == inj[0]["packets"] and
          all(inj[0]["start"] <= e["t_start"] <= e["t_end"] <= inj[0]["end"]
              for e in evs), "manifest: events outside the injection window")
    check(man["packets"] == len(frames), "api run: manifest != pcap")
    # 0.6 s window at ~30% of 400-600 pps: one or a few incident passes
    check(20 <= inj[0]["packets"] <= 400,
          f"injection size {inj[0]['packets']}")


def _pcapng(sections) -> bytes:
    """Hand-built pcapng: sections = [(endian, [(btype, body), ...])]."""
    out = b""
    for e, blocks in sections:
        shb = struct.pack(e + "IHHq", 0x1A2B3C4D, 1, 0, -1)
        out += struct.pack(e + "II", 0x0A0D0D0A, 8 + len(shb) + 4) + shb + \
            struct.pack(e + "I", 8 + len(shb) + 4)
        for btype, body in blocks:
            body += b"\0" * (-len(body) % 4)
            n = 12 + len(body)
            out += struct.pack(e + "II", btype, n) + body + \
                struct.pack(e + "I", n)
    return out


def _ng_opt(e, code, val) -> bytes:
    return struct.pack(e + "HH", code, len(val)) + val + \
        b"\0" * (-len(val) % 4)


def test_pcapng_reader_sections_interfaces_resolution() -> None:
    from tgt import pcapread
    eth = protocols.modbus_flow(Endpoints(), 1)[0]
    raw = protocols.dns_flow(Endpoints(), 1)[0][14:]

    def epb(e, ifid, ticks, data):
        return struct.pack(e + "IIIII", ifid, ticks >> 32, ticks & 0xFFFFFFFF,
                           len(data), len(data)) + data

    le, be = "<", ">"
    ns_idb = struct.pack(le + "HHI", 101, 0, 0) + _ng_opt(le, 9, b"\x09") + \
        _ng_opt(le, 14, struct.pack(le + "q", 100)) + _ng_opt(le, 0, b"")
    data = _pcapng([
        (le, [(1, struct.pack(le + "HHI", 1, 0, 0)),          # if0 eth, usec
              (1, ns_idb),                                    # if1 raw, ns
              (4, b"\x01\x00\x08\x00junkjunk"),               # NRB: skipped
              (6, epb(le, 0, 1_500_000, eth)),
              (6, epb(le, 1, 2_250_000_000, raw)),
              (3, struct.pack(le + "I", len(eth)) + eth),     # SPB on if0
              (2, struct.pack(le + "HHIIII", 0, 0, 0, 3_000_000, len(eth),
                              len(eth)) + eth),               # obsolete PB
              (5, b"\0" * 12)]),                              # ISB: skipped
        (be, [(1, struct.pack(be + "HHI", 1, 0, 0) +
               _ng_opt(be, 9, b"\x8a") + _ng_opt(be, 0, b"")),  # 2^-10 s
              (6, epb(be, 0, 4096, eth))]),
    ])
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "t.pcapng")
        with open(path, "wb") as fh:
            fh.write(data)
        pk = list(pcapread.iter_packets(path))
        check(pcapread.probe(path) == ("pcapng", 5),
              f"pcapng probe {pcapread.probe(path)}")
        with open(path, "wb") as fh:          # truncated final block
            fh.write(data[:-7])
        check(len(list(pcapread.iter_packets(path))) == 4,
              "pcapng: truncated last block not dropped")
    check(len(pk) == 5, f"pcapng: {len(pk)} packets")
    if len(pk) == 5:
        check([p.interface for p in pk] == [0, 1, 0, 0, 0] and
              [p.linktype for p in pk] == [1, 101, 1, 1, 1],
              "pcapng: interfaces / link types")
        want = [1.5, 102.25, 102.25, 3.0, 4.0]
        check(all(abs(p.ts - w) < 1e-9 for p, w in zip(pk, want)),
              f"pcapng ts {[p.ts for p in pk]} != {want}")
        check(pk[0].frame == eth and pk[1].frame[14:] == raw and
              pk[1].frame[12:14] == b"\x08\x00" and pk[4].frame == eth,
              "pcapng: frame bytes / raw-IP wrap")
    # tshark/editcap conversion of a TGT pcap: same frames and timestamps
    editcap = shutil_which("editcap")
    if editcap:
        import subprocess
        frames = protocols.http_flow(Endpoints(), 2)
        with tempfile.TemporaryDirectory() as d:
            src, ng = os.path.join(d, "s.pcap"), os.path.join(d, "s.pcapng")
            with PcapWriter(src) as w:
                for i, f in enumerate(frames):
                    w.write(f, ts=1700000000 + i * 0.125)
            subprocess.run([editcap, "-F", "pcapng", src, ng], check=True,
                           capture_output=True)
            a = pcapread.read_frames(src)
            b = pcapread.read_frames(ng)
        check(a == b, "pcapng (editcap) != pcap frames/timestamps")


def test_replay_streams_speed_loop_and_rewrite() -> None:
    import time
    from tgt.replay import ReplaySource
    frames = protocols.dns_flow(Endpoints(), 3)       # 6 frames
    with tempfile.TemporaryDirectory() as d:
        src = os.path.join(d, "r.pcap")
        with PcapWriter(src) as w:
            for i, f in enumerate(frames):
                w.write(f, ts=1000.0 + i * 0.1)        # 0.5 s span
        out = os.path.join(d, "o.pcap")
        cfg = RunConfig(replay_path=src, replay_speed=2.5, replay_loop=2,
                        rate=20, pcap_path=out, remap_ip=["10.10.10.20=10.9.9.9"],
                        replay_vlan=7)
        t0 = time.perf_counter()
        eng = _run_engine(cfg)
        took = time.perf_counter() - t0
        recs = [f for _, f in _pcap_records(out)]
        # streamed: the source is an iterator, not a list of the file
        rs = ReplaySource(RunConfig(replay_path=src), paced=False)
        check(len(rs) == 6 and not isinstance(rs, list) and
              iter(rs) is not iter(rs), "ReplaySource not a streamed source")
    check(eng.stats.packets == 12 and len(recs) == 12,
          f"replay-loop 2: {eng.stats.packets} packets")
    check(0.3 <= took < 1.5, f"replay x2.5 of 2x0.5 s took {took:.2f}s")
    check(all(r[12:16] == b"\x81\x00\x00\x07" for r in recs),
          "replay: --vlan retag missing")
    check(all(P.ip_to_bytes("10.9.9.9") in r[30:38] for r in recs),
          "replay: --remap-ip not applied")
    for i, r in enumerate(recs):
        verify_ip_l4(r, f"replayed frame {i}")


def test_rewrite_remaps_and_fixes_checksums() -> None:
    from tgt.rewrite import Rewriter, RewriteError
    ep = Endpoints(client_ip="192.168.1.10", server_ip="192.168.1.20")
    tcp = protocols.modbus_flow(ep, 2)
    udp = protocols.dns_flow(ep, 1)
    arp = protocols.arp_flow(ep, 1)
    rw = Rewriter.from_specs(remap_ip=["192.168.1.20=10.0.0.99"],
                             remap_subnet=["192.168.1.0/24=10.100.10.0/24"],
                             remap_mac=["02:00:00:00:00:01=00:1d:9c:00:00:01"])
    for i, f in enumerate(tcp + udp):
        g = rw.apply(f)
        verify_ip_l4(g, f"rewrite {i}")
        ips = P.frame_ips(g)
        check(ips is not None and set(ips) == {"10.100.10.10", "10.0.0.99"},
              f"rewrite {i}: addresses {ips}")
    g = rw.apply(arp[0])
    check(P.ip_to_bytes("10.100.10.10") in g[28:] or
          P.ip_to_bytes("10.0.0.99") in g[28:], "rewrite: ARP not remapped")
    check(b"\x00\x1d\x9c\x00\x00\x01" in rw.apply(tcp[0])[:12],
          "rewrite: MAC not remapped")
    # a snaplen-truncated segment gets the same (incremental) checksum
    full, cut = rw.apply(tcp[2]), rw.apply(tcp[2][:60])
    check(full[:60] == cut, "rewrite: incremental checksum != recomputed")
    # an offloaded (wrong) TCP checksum comes out valid
    bad = bytearray(tcp[2])
    bad[50:52] = b"\xbe\xef"
    verify_ip_l4(rw.apply(bytes(bad)), "rewrite of offloaded checksum")
    # UDP sent without a checksum keeps none
    z = bytearray(udp[0])
    z[40:42] = b"\0\0"
    check(rw.apply(bytes(z))[40:42] == b"\0\0", "rewrite: UDP csum 0 changed")
    # VLAN: add, replace (PCP kept), strip
    tag = Rewriter(vlan=30).apply(tcp[0])
    check(tag[12:16] == b"\x81\x00\x00\x1e" and tag[16:] == tcp[0][12:],
          "rewrite: VLAN add")
    pcp = bytearray(tag)
    pcp[14] |= 0xA0
    re = Rewriter(vlan=40).apply(bytes(pcp))
    check(re[14:16] == bytes([0xA0, 40]), "rewrite: VLAN replace lost PCP")
    check(Rewriter(vlan=0).apply(tag) == tcp[0], "rewrite: VLAN strip")
    check(Rewriter.from_specs() is None, "rewrite: empty spec not None")
    for kw in ({"remap_ip": ["1.2.3.4"]},
               {"remap_subnet": ["10.0.0.0/24=10.1.0.0/16"]},
               {"remap_mac": ["zz=00:00:00:00:00:01"]}, {"vlan": 5000}):
        try:
            Rewriter.from_specs(**kw)
            check(False, f"rewrite: {kw} accepted")
        except RewriteError:
            pass
    if shutil_which("tshark"):
        import subprocess
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "rw.pcap")
            with PcapWriter(path) as w:
                for f in tcp + udp + [bytes(bad)]:
                    w.write(rw.apply(Rewriter(vlan=12).apply(f)))
            out = subprocess.run(
                ["tshark", "-r", path, "-o", "ip.check_checksum:TRUE",
                 "-o", "tcp.check_checksum:TRUE", "-o",
                 "udp.check_checksum:TRUE", "-T", "fields", "-e",
                 "ip.checksum.status", "-e", "tcp.checksum.status", "-e",
                 "udp.checksum.status", "-e", "vlan.id"],
                capture_output=True, text=True).stdout.split("\n")
        rows = [ln.split("\t") for ln in out if ln.strip()]
        check(len(rows) == len(tcp) + len(udp) + 1 and
              all(r[0] == "1" and "1" in (r[1], r[2]) and r[3] == "12"
                  for r in rows), f"tshark: rewritten checksums {rows[:3]}")


def test_plugins_example_registers_everything() -> None:
    """examples/plugins/acme_plant.py: discovered + loaded, every kind of
    registration usable (list/run/env/incident/score map), dissected by
    tshark like a built-in, its own self-test passes; a broken plugin is
    reported and rolled back; unloading restores the registries."""
    import contextlib
    import io
    import subprocess
    from tgt import (devices, enterprise, incidents, manifest, plugins,
                     score)
    ex = os.path.join(_REPO, "examples", "plugins")
    before = (set(protocols.PROFILES), set(scenarios.SCENARIOS),
              set(enterprise.ENVIRONMENTS), set(incidents.INCIDENTS),
              set(incidents.ATTACKS), set(devices.CATALOG),
              set(manifest.ATTACK_CATEGORY), dict(plugins.DISSECTORS))
    with tempfile.TemporaryDirectory() as d:
        bad = os.path.join(d, "bad")
        os.mkdir(bad)
        with open(os.path.join(bad, "half.py"), "w") as f:
            f.write("from tgt import plugins\n"
                    "plugins.register_scenario('half-scn', 'H', ['modbus'],"
                    " 'd')\nraise RuntimeError('boom')\n")
        with open(os.path.join(bad, "_private.py"), "w") as f:
            f.write("raise SystemExit('must not be imported')\n")
        warns = []
        plugins.unload_all()
        try:
            got = plugins.load_plugins([bad, ex], force=True,
                                       warn=warns.append)
            check(len(got) == 1 and len(plugins.ERRORS) == 1 and
                  "boom" in plugins.ERRORS[0][1] and warns,
                  f"plugins: load {got} errors {plugins.ERRORS}")
            check("half-scn" not in scenarios.SCENARIOS,
                  "plugins: failed plugin's registration not rolled back")
            check("coap" in protocols.PROFILES and "acme-iiot" in
                  scenarios.SCENARIOS and "acme-plant" in
                  enterprise.ENVIRONMENTS and "acme-valve-tamper" in
                  incidents.INCIDENTS and "acme-sx1" in devices.CATALOG and
                  manifest.ATTACK_CATEGORY.get("coap-put") == "ot-write" and
                  plugins.DISSECTORS.get("coap") == "coap",
                  "plugins: example registrations missing")
            check(score.load_json_spec("acme-siem")["format"] == "csv",
                  "plugins: score map not resolvable by name")
            try:
                plugins.register_protocol("modbus", "x", "OT", "1", "tcp",
                                          lambda ep, n: [], "clash")
                check(False, "plugins: clash with a built-in accepted")
            except plugins.PluginError:
                pass
            mod = sys.modules[got[0]]
            with contextlib.redirect_stdout(io.StringIO()) as out:
                rc = mod.selftest()
            check(rc == 0, f"example plugin self-test: {out.getvalue()}")
            # a sprinkled plugin incident on the plugin env, through the
            # engine + manifest (attack category from the plugin)
            with tempfile.TemporaryDirectory() as d2:
                man = _manifest_run(d2, "acme", RunConfig(
                    env="acme-plant", sprinkle=["acme-valve-tamper"],
                    loop=False), 400)
            check(any(e.get("attack") == "coap-put" and
                      e["category"] == "ot-write" for e in man["events"]),
                  "plugins: plugin attack event missing from manifest")
            # selftest's own registry checks accept the plugin protocol
            if shutil_which("tshark"):
                n = len(_failures)
                test_tshark_dissects_every_builder()
                check(len(_failures) == n, "tshark registry check with a "
                      "plugin loaded failed")
        finally:
            plugins.unload_all()
    after = (set(protocols.PROFILES), set(scenarios.SCENARIOS),
             set(enterprise.ENVIRONMENTS), set(incidents.INCIDENTS),
             set(incidents.ATTACKS), set(devices.CATALOG),
             set(manifest.ATTACK_CATEGORY), dict(plugins.DISSECTORS))
    check(after == before, "plugins: unload_all left registrations behind")
    # CLI discovery through TGT_PLUGIN_PATH (fresh process); TGT_NO_PLUGINS
    env = dict(os.environ, TGT_PLUGIN_PATH=ex, PYTHONPATH=_REPO)
    env.pop("TGT_NO_PLUGINS", None)
    out = subprocess.run([sys.executable, "-m", "tgt", "list"], env=env,
                         capture_output=True, text=True, cwd=_REPO).stdout
    check("acme-plant" in out and "coap" in out and "acme_plant.py" in out,
          "plugins: tgt list does not show the example plugin")
    env["TGT_NO_PLUGINS"] = "1"
    out = subprocess.run([sys.executable, "-m", "tgt", "list"], env=env,
                         capture_output=True, text=True, cwd=_REPO).stdout
    check("acme-plant" not in out, "plugins: TGT_NO_PLUGINS ignored")


# ---------------------------------------------------------------------------
# W4-C correctness polish
# ---------------------------------------------------------------------------
def _w4c_envs() -> list:
    """The four built-in environments plus every packaged site, the sites
    loaded straight from their files."""
    from tgt import enterprise, envfile
    out = [enterprise.get(k) for k in ("it-org", "ot-plant",
                                       "enterprise-mixed", "industrial-site")]
    for f in sorted(os.listdir(envfile.SITES_DIR)):
        if f.endswith(".json"):
            out.append(envfile.load(os.path.join(envfile.SITES_DIR, f)))
    return out


def test_w4c_netbios_broadcast_announcements() -> None:
    """NetBIOS: B-node broadcasts (ff:ff:ff:ff:ff:ff, the sender's subnet
    broadcast, its own VLAN) — a name registration on 137 and a Browser host
    announcement on 138 with the host name and OS version; nobody answers
    and no host 'serves' netbios in the inventory."""
    import ipaddress
    from tgt import enterprise, inventory
    for env in _w4c_envs():
        protocols.begin_build(3, 0)
        nb = [f for k, f in env.build(1) if k == "netbios"]
        talkers = {c for c, _, p in env.conversations if p == "netbios"
                   and not env.hidden(env.host(c))}
        check(bool(nb) == bool(talkers), f"{env.key}: netbios frames")
        by_ip = {h.ip: h for h in env.hosts}
        seen = set()
        for f in nb:
            src, dst = P.frame_ips(f)
            h = by_ip.get(src)
            seg = env.segment_of(h) if h else None
            vlan = struct.unpack("!H", f[14:16])[0] & 0xFFF \
                if f[12:14] == b"\x81\x00" else None
            ok = (h is not None and f[0:6] == b"\xff" * 6 and
                  dst == str(ipaddress.ip_network(seg.subnet)
                             .broadcast_address) and vlan == seg.vlan)
            if not ok:
                check(False, f"{env.key}: netbios frame {src}->{dst} "
                             f"vlan {vlan} not a subnet broadcast")
                break
            seen.add(h.name)
        check(seen == talkers, f"{env.key}: announcers {sorted(seen)} "
                               f"!= {sorted(talkers)}")
        rows = inventory.hosts(env)
        bad = [r["name"] for r in rows
               if any(s.startswith("netbios") for s in r["serves"])]
        check(not bad, f"{env.key}: hosts 'serve' netbios: {bad}")
    # the host announcement: name, OS version, mailslot; HMI-XP is XP (5.1)
    env = enterprise.get("ot-plant")
    protocols.begin_build(3, 0)
    nb = [f for k, f in env.build(1) if k == "netbios"]
    ann = [f for f in nb if b"\\MAILSLOT\\BROWSE\x00" in f]
    reg = [f for f in nb if f not in ann]
    check(ann and reg, "netbios: registration + host announcement")
    for f in ann:
        i = f.index(b"\\MAILSLOT\\BROWSE\x00") + 17
        name, major, minor = f[i + 6:i + 22], f[i + 22], f[i + 23]
        check(f[i] == 0x01 and name.rstrip(b"\x00") == b"HMI-XP" and
              (major, minor) == (5, 1), f"host announcement {f[i:i + 30]!r}")
        check(struct.unpack("!HH", f[38:42]) == (138, 138),
              "host announcement ports")
    # a netbios flow "to" a host: that host sends nothing for it
    ev = inventory._evidence(enterprise.Environment(
        "t", "t", "OT", "", env.hosts, [("HMI-XP", "PLC-RW1", "netbios")],
        env.segments, options={"arp": False}))
    check(not ev["PLC-RW1"]["vendor"] and ev["HMI-XP"]["os"] >=
          {"netbios"}, "netbios evidence")
    # profile-only run: /24 broadcast of the client
    fr = protocols.get("netbios").build(Endpoints(client_ip="10.1.2.3"), 2)
    check(all(P.frame_ips(f) == ("10.1.2.3", "10.1.2.255") for f in fr),
          "netbios: profile-only broadcast address")
    if shutil_which("tshark"):
        import subprocess
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nb.pcap")
            with PcapWriter(path) as w:
                for f in nb:
                    w.write(f)
            out = subprocess.run(
                ["tshark", "-r", path, "-T", "fields", "-e",
                 "browser.command", "-e", "browser.os_major", "-e",
                 "browser.os_minor", "-e", "nbns.flags.opcode"],
                capture_output=True, text=True).stdout.split("\n")
            check(any(ln.startswith("0x01\t5\t1") for ln in out),
                  f"tshark: host announcement not decoded: {out[:3]}")
            check(any(ln.strip() == "5" for ln in out),
                  f"tshark: NBNS registration not decoded: {out[:3]}")


def test_w4c_list_columns_aligned() -> None:
    """tgt list sizes each column to its longest value (modbus-write,
    firmware-update, electric-substation...)."""
    import contextlib
    import io
    from tgt import cli
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cli.cmd_list(None)
    lines = buf.getvalue().splitlines()
    head = lines.index("Protocols:") + 1
    hdr = lines[head]
    cols = [(hdr + " ").index(f" {c} ") + 1
            for c in ("name", "cat", "port", "xport", "desc")]
    for p in protocols.all_profiles():
        ln = next(x for x in lines[head + 1:] if x.startswith(f"  {p.key} "))
        vals = (p.name, p.category, p.port, p.transport, p.desc)
        check(all(ln[c - 1] == " " and ln[c:].startswith(v)
                  for c, v in zip(cols, vals)),
              f"tgt list: misaligned protocol row {ln!r}")
    # scenario / environment / incident rows: the '[' column lines up
    for title in ("Scenarios", "Environments", "Incidents"):
        i = next(n for n, x in enumerate(lines) if x.startswith(title))
        rows = []
        for x in lines[i + 1:]:
            if not x.strip():
                break
            if x.startswith("  ") and not x.startswith("    "):
                rows.append(x)
        check(len(rows) > 2 and len({x.index(" [") for x in rows}) == 1,
              f"tgt list: {title} columns misaligned")


def _iec104_apdus(frames, cmac: bytes) -> list:
    """(time, from client?, ctrl1, ctrl2, type id, cot) of every APDU."""
    from tgt import schedule
    out = []
    for t, f in frames:
        frm, _, plen, _, l4, tcp = schedule.view(f, cmac)
        if not tcp or plen <= 0:
            continue
        p = l4 + (f[l4 + 12] >> 4) * 4
        end = p + plen
        while p + 6 <= end and f[p] == 0x68:
            c1, c2 = struct.unpack_from("<HH", f, p + 2)
            asdu = f[p + 1] > 4
            out.append((t, frm, c1, c2, f[p + 6] if asdu else None,
                        f[p + 8] & 0x3F if asdu else None))
            p += 2 + f[p + 1]
    return out


def test_w4c_iec104_timed_gi_and_sequence() -> None:
    """IEC 104 under the timed scheduler: one persistent connection, a
    station interrogation at connect and then every REFRESH period (15 min),
    and N(S)/N(R) that continue across the 256-poll build chunks."""
    from tgt import schedule, timing
    ep = Endpoints()
    st = schedule.profile_streams(["iec104"], ep)
    st[0].period = 2.0
    sch = schedule.Scheduler(7)
    sch.load(st, 0.0, initial=True)
    frames = [(t, c[0]) for t, _, _, c, _, _ in sch.run(3700.0)]
    apdus = _iec104_apdus(frames, P.mac_to_bytes(ep.client_mac))
    gi = [a[0] for a in apdus if a[1] and a[4] == 100 and a[5] == 6]
    per = timing.REFRESH["iec104"][0]
    check(len(gi) == 5 and all(abs((b - a) - per) < 15
                               for a, b in zip(gi, gi[1:])),
          f"iec104: GI activations at {[round(x) for x in gi]}")
    term = [a for a in apdus if not a[1] and a[4] == 100 and a[5] == 10]
    check(len(term) == len(gi), "iec104: every GI terminated")
    syn = [f for _, f in frames if schedule.view(
        f, P.mac_to_bytes(ep.client_mac))[1] == 0x02]
    check(len(syn) == 1, f"iec104: {len(syn)} connections")
    nxt, rcv, bad = {True: 0, False: 0}, {True: 0, False: 0}, []
    for t, frm, c1, c2, _, _ in apdus:
        if c1 & 1 == 0:                              # I-format
            if (c1 >> 1, c2 >> 1) != (nxt[frm], rcv[frm]):
                bad.append((round(t, 1), frm, c1 >> 1, c2 >> 1))
            nxt[frm] = (nxt[frm] + 1) & 0x7FFF
            rcv[not frm] += 1
        elif c1 & 3 == 1 and c2 >> 1 != rcv[frm]:   # S-format
            bad.append((round(t, 1), frm, "S", c2 >> 1))
    check(not bad and nxt[False] > 3 * timing.CHUNK,
          f"iec104: sequence breaks {bad[:4]} (server N(S) {nxt[False]})")
    # the counters wrap at 2^15
    conn = schedule.Connection()
    conn.apci = {True: [5, 0x7FFF], False: [0x7FFF, 5]}
    srv = protocols._iec104_i(0, 0, b"\x0d\x01\x03\x00\x01\x00" + bytes(8))
    sess = protocols._tcp_flow(ep, 40000, 2404,
                               [(protocols._iec104_s(0), srv)])
    f = next(x for x in sess if not schedule.view(
        x, P.mac_to_bytes(ep.client_mac))[0] and schedule.view(
        x, P.mac_to_bytes(ep.client_mac))[2] > 0)
    out = schedule.renumber_iec104(conn, f, P.mac_to_bytes(ep.client_mac))
    i = out.index(srv[:2])
    check(struct.unpack_from("<HH", out, i + 2) == (0x7FFF << 1, 5 << 1)
          and conn.apci[False][0] == 0 and conn.apci[True][1] == 0,
          "iec104: N(S)/N(R) do not wrap at 2^15")


def _w4c_ratio_run(env_key: str, inc: str, ratio: float,
                   dur: float = 600.0) -> float:
    from tgt import campaign, schedule
    cfg = RunConfig(env=env_key, sprinkle=[inc], sprinkle_ratio=ratio,
                    schedule="timed", duration=dur, seed=3)
    ph = campaign.phases_for(cfg)[0]
    sch = schedule.Scheduler(3)
    sch.ratio = ratio
    sch.load(campaign.phase_streams(ph, cfg), 0.0, ph.hosts, initial=True)
    n = {False: 0, True: 0}
    for _, _, _, copies, source, _ in sch.run(dur):
        n[source.startswith("sprinkle:")] += len(copies)
    return n[True] / max(1, sum(n.values()))


def test_w4c_sprinkle_ratio_timed() -> None:
    """--sprinkle-ratio under --schedule timed: sprinkle streams recur so
    that they make up the requested fraction of wire frames; 0 keeps their
    natural periods. The engine honours it end to end."""
    natural = _w4c_ratio_run("it-org", "wannacry", 0.0)
    check(natural < 0.02, f"timed natural sprinkle share {natural:.3f}")
    for r in (0.05, 0.2):
        got = _w4c_ratio_run("it-org", "wannacry", r)
        check(abs(got - r) / r < 0.2,
              f"timed --sprinkle-ratio {r}: observed {got:.4f}")
    got = _w4c_ratio_run("industrial-site", "industroyer", 0.1, 300.0)
    check(abs(got - 0.1) / 0.1 < 0.25,
          f"timed --sprinkle-ratio 0.1 on industrial-site: {got:.4f}")
    with tempfile.TemporaryDirectory() as d:
        recs, m = _timed_run(d, "r", env="it-org", duration=300.0,
                             sprinkle=["wannacry"], sprinkle_ratio=0.3)
    spr = sum(e.get("packets", 0) for e in m["events"]
              if e["source"].startswith("sprinkle:"))
    check(recs and 0.2 < spr / len(recs) < 0.4,
          f"engine timed sprinkle share {spr}/{len(recs)}")


def test_w4c_injection_keeps_seeded_baseline() -> None:
    """Injections build in isolation: a seeded run's own frames are the
    same with and without a (heavy) injection, and the injected frames are
    themselves reproducible."""
    from tgt.engine import Engine

    def run(inject: bool):
        cfg = RunConfig(env="it-org", seed=21, messages=2, rate=0,
                        clock="synthetic", start_time="2026-11-05T14:00:00Z")
        cfg.count = 5000
        eng = Engine(cfg)
        seen = []
        feed = eng.control.feed

        def spy(batch, stop):
            for idx, item in feed(batch, stop):
                seen.append(item)
                yield idx, item
        eng.control.feed = spy
        if inject:
            eng.control.inject("wannacry", duration=600.0, ratio=0.5)
        eng.start()
        eng.join(120)
        return ([f for _, f, s in seen if not s.startswith("inject:")],
                [f for _, f, s in seen if s.startswith("inject:")])
    base, _ = run(False)
    b1, inj1 = run(True)
    b2, inj2 = run(True)
    # passes build on the injection worker, so how many injected frames
    # an unpaced run interleaves depends on timing; what they are does not
    check(len(inj1) > 50 and len(inj2) > 50 and len(b1) > 1000,
          f"injection run sizes {len(b1)}/{len(inj1)}")
    check(base[:len(b1)] == b1 and base[:len(b2)] == b2,
          "seeded baseline frames changed by an injection")
    m = min(len(inj1), len(inj2))
    check(inj1[:m] == inj2[:m],
          "injected frames not reproducible from the seed")
    # isolated_build restores the caller's build context
    ctx = protocols.begin_build(9, 4)
    with protocols.isolated_build(1, 1):
        protocols._rand32()
    check(protocols.build_context() is ctx, "isolated_build leaked context")


def test_w4c_os_fingerprint_aliases() -> None:
    """One embedded-OS pair: rtos / linux-embedded; the older embedded /
    embedded-linux keys still load (hosts, os: selectors) as aliases."""
    from tgt import enterprise, envfile, stacks
    check(not set(enterprise.OS_ALIASES) & set(enterprise.FINGERPRINTS),
          "alias keys still in FINGERPRINTS")
    h = enterprise.Host("X", "10.0.0.9", "00:11:22:33:44:55", "rtu",
                        "embedded")
    check(h.os == "rtos" and h.fp.label == "Embedded RTOS firmware",
          f"embedded alias -> {h.os}")
    check(stacks.for_os("rtos") == "embedded" and
          stacks.for_os("linux-embedded") == "linux", "embedded OS stacks")
    doc = {"key": "alias-t", "name": "t", "segments": [
        {"name": "S", "vlan": 10, "subnet": "10.9.0.0/24", "zone": "OT-CELL",
         "gateway": "10.9.0.1"}],
        "hosts": [{"name": "A", "ip": "10.9.0.10", "role": "rtu",
                   "os": "embedded"},
                  {"name": "B", "ip": "10.9.0.11", "role": "hmi",
                   "os": "embedded-linux"}],
        "flows": [{"from": "os:embedded-linux", "to": "os:embedded",
                   "proto": "modbus"}]}
    import json
    env = envfile.loads(json.dumps(doc), source="t")
    check([x.os for x in env.hosts] == ["rtos", "linux-embedded"] and
          env.conversations == [("B", "A", "modbus")],
          f"alias env file: {[x.os for x in env.hosts]} "
          f"{env.conversations}")
    check('"embedded"' not in envfile.export(env), "export keeps alias")
    for f in os.listdir(envfile.SITES_DIR):
        txt = open(os.path.join(envfile.SITES_DIR, f)).read()
        check('"os": "embedded"' not in txt and "embedded-linux" not in txt,
              f"site {f} uses an alias OS key")
    labels = {x.fp.label for e in _w4c_envs() for x in e.hosts}
    check(not {"Embedded device firmware (RTOS)",
               "Embedded Linux (vendor firmware)"} & labels,
          "inventory still shows the old embedded OS labels")


def test_w4c_score_self_test_is_perfect() -> None:
    """A perfect monitor's export (score.perfect_export) scores 100 % on
    every built-in env and packaged site: discovery, observable fields
    (vendor included, with the map's normalize table applied to both sides)
    and protocols; NAT-hidden hosts are not in the population, as in a run
    manifest."""
    import json
    from tgt import cli, envfile, inventory, score
    mapping = score.load_json_spec("generic", "map")

    def grade(truth, d, name):
        path = os.path.join(d, name + ".csv")
        score.write_perfect_export(truth, path)
        rows, info = score.read_export(path, mapping)
        return score.score(truth, rows, info)

    def perfect(res, what):
        disc, pr = res["discovery"], res["protocols"]
        acc = {f: res["fields"][f]["observable"]["accuracy"]
               for f in score.FIELDS}
        check(disc["recall"] == 1.0 and disc["precision"] == 1.0 and
              all(v in (None, 1.0) for v in acc.values()) and
              pr["precision"] == 1.0 and pr["recall"] == 1.0,
              f"self-score {what}: recall {disc['recall']} precision "
              f"{disc['precision']} fields {acc} protocols "
              f"{pr['precision']}/{pr['recall']}")
    pops = {}
    with tempfile.TemporaryDirectory() as d:
        for env in _w4c_envs():
            truth = score.Truth(inventory.to_json(env), env.key)
            res = grade(truth, d, env.key)
            perfect(res, env.key)
            pops[env.key] = {a["id"] for a in truth.population()}
            check(res["fields"]["vendor"]["observable"]["n"] > 0,
                  f"{env.key}: no vendor scored")
        # manifest truth: same population (who really emitted) and 100 %
        envfile.load_user_envs(warn=lambda m: None, force=True)
        for key in ("it-org", "oil-gas-pipeline"):
            m = _manifest_run(d, key, RunConfig(env=key, seed=4,
                                                loop=False), 0)
            truth = score.Truth(m, key)
            perfect(grade(truth, d, key + "-m"), key + " (manifest)")
            check({a["id"] for a in truth.population()} == pops[key],
                  f"{key}: inventory and manifest populations differ")
        # the CLI writes the same export
        nat = next(e for e in _w4c_envs() if e.key == "oil-gas-pipeline")
        inv = os.path.join(d, "inv.json")
        with open(inv, "w") as f:
            json.dump(inventory.to_json(nat), f)
        out = os.path.join(d, "self.csv")
        import contextlib
        import io
        with contextlib.redirect_stderr(io.StringIO()):
            rc = cli.main(["score", "--truth", inv, "--self-test-export",
                           out])
        rows, _ = score.read_export(out, mapping)
        check(rc == 0 and len(rows) == len(pops[nat.key]) <
              len(nat.hosts), "tgt score --self-test-export")


def test_w4c_tshark_expert_every_env() -> None:
    """Optional: one seeded cycle of every built-in env and packaged site
    has no tshark expert errors and no warnings but deliberate RSTs."""
    import subprocess
    if not shutil_which("tshark"):
        _skipped.append("test_w4c_tshark_expert_every_env")
        return
    with tempfile.TemporaryDirectory() as d:
        for env in _w4c_envs():
            path = os.path.join(d, env.key + ".pcap")
            protocols.begin_build(8, 0)
            with PcapWriter(path) as w:
                for _, f in env.build(2):
                    w.write(f)
            ex = subprocess.run(["tshark", "-r", path, "-q", "-z",
                                 "expert,warn"], capture_output=True,
                                text=True).stdout
            bad = [ln.strip() for ln in ex.splitlines()
                   if ln.strip()[:1].isdigit()
                   and "Connection reset (RST)" not in ln
                   and not _tshark_dissector_bug(ln)]
            check("Errors (" not in ex and not bad,
                  f"tshark expert {env.key}: {bad[:4]}")


# -- W4-A: TUI toggles + service wiring for the new run options (#62) --
def _tui_labels(tui, ui, panel="Run"):
    ui.focus = tui.PANELS.index(panel)
    return [f.label.strip() for f in tui._fields(ui)]


def _tui_ui(tui):
    ui = tui.UI()
    ui.engine = None
    ui.ifaces = {}
    ui.send_iface, ui.extra_ifaces, ui.pcap = None, [], None
    return ui


def _tui_exercise(tui, ui, label: str) -> None:
    """Every visible row of every panel has help, a value, and ←/→ that
    neither prompts nor raises (stdscr=None)."""
    skip = {"Create veth pair", "Delete veth pair", "Save config",
            "Start service", "Stop service", "Restart service"}
    for focus in range(len(tui.PANELS)):
        ui.focus = focus
        for f in tui._fields(ui):
            check(bool(f.help(ui)),
                  f"tui[{label}]: {tui.PANELS[focus]}/{f.label} has no help")
            f.value(ui)
            if f.act and f.label not in skip:
                for step in (1, -1, 0):       # 0: prompt/pick cancel (None)
                    f.act(None, ui, step)
                    f.act(None, ui, -step if step else 0)


def test_tui_run_rows_follow_mode() -> None:
    """Run-panel visibility: timed-only rows, synthetic start time, env
    findings + inventory export, campaign mode, replay extras; each mode's
    rows all have help and survive ←/→."""
    from tgt import campaign, enterprise, envfile, tui
    before = set(enterprise.ENVIRONMENTS)
    envfile.load_user_envs(warn=lambda m: None, force=True)
    try:
        ui = _tui_ui(tui)
        labels = _tui_labels(tui, ui)
        for want in ("Preset", "Campaign", "Schedule", "Rate", "Loop",
                     "Clock", "Seed", "Manifest", "API", "PCAP output"):
            check(want in labels, f"tui: custom Run rows miss {want}")
        for hide in ("speed", "day profile", "min period", "duration",
                     "start time", "Findings", "Export inventory",
                     "replay speed", "remap IP", "skip checks"):
            check(hide not in labels, f"tui: custom Run rows show {hide}")
        _tui_exercise(tui, ui, "custom")

        # timed: its rows appear, Loop goes, the rate becomes a cap
        ui = _tui_ui(tui)
        ui.set_schedule("timed")
        labels = _tui_labels(tui, ui)
        check(all(x in labels for x in ("speed", "day profile",
                                        "min period", "duration"))
              and "Loop" not in labels and ui.rate == 0,
              f"tui: timed rows {labels} rate {ui.rate}")
        ui.speed, ui.duration, ui.min_period = 60.0, 3600.0, 2.0
        ui.day_profile = "shift"
        cfg = ui.build_config()
        check(cfg.schedule == "timed" and cfg.speed == 60 and
              cfg.duration == 3600 and cfg.min_period == 2 and
              cfg.day_profile == "shift" and cfg.rate == 0,
              f"tui: timed config {cfg}")
        _tui_exercise(tui, ui, "timed")
        ui.set_schedule("cycle")
        check(ui.rate == 20 and ui.build_config().duration == 0,
              "tui: leaving timed did not restore the cycle rate")
        ui.clock = "synthetic"
        check("start time" in _tui_labels(tui, ui),
              "tui: synthetic clock hides the start time")
        ui.start_time = "2026-11-05T14:00:00Z"
        check(ui.build_config().start_time == ui.start_time,
              "tui: start time not in the config")
        tui._act_start(None, ui, 1)
        check(ui.start_time == "2026-11-05T15:00:00Z",
              f"tui: start time ±1h gave {ui.start_time}")

        # an environment with planted findings: count, list, export
        ui = _tui_ui(tui)
        tui._apply_preset(None, ui, ("e", "water-utility"))
        env = enterprise.get("water-utility")
        labels = _tui_labels(tui, ui)
        check("Findings" in labels and "Export inventory" in labels,
              f"tui: site rows {labels}")
        row = next(f for f in tui._fields(ui) if f.label == "Findings")
        text = row.help(ui)
        check(str(len(env.findings)) in row.value(ui)[0] and
              all(f["title"] in text for f in env.findings) and
              row.long_help,
              "tui: findings row does not list the site's findings")
        with tempfile.TemporaryDirectory() as d:
            paths = ui.export_inventory(os.path.join(d, "gt", "water.csv"))
            check([os.path.basename(p) for p in paths] ==
                  ["water.csv", "water.json"] and
                  all(os.path.getsize(p) > 1000 for p in paths),
                  f"tui: inventory export {paths}")
            import json
            doc = json.load(open(paths[1]))
            check(doc.get("env") == "water-utility" and
                  len(doc.get("findings", [])) == len(env.findings),
                  "tui: exported JSON lacks the findings")
        _tui_exercise(tui, ui, "site")

        # preset picker: environments grouped built-in / sites / files
        groups = {}
        for grp, choice, _l, _d in tui._preset_items(ui):
            if choice[0] == "e":
                groups.setdefault(grp, []).append(choice[1])
        sites = sorted(os.path.splitext(f)[0] for f in
                       os.listdir(envfile.SITES_DIR) if f.endswith(".json"))
        check(sorted(groups.get("Environments · sites", [])) == sites and
              len(sites) >= 7 and set(before) <= set(
                  groups.get("Environments · built-in", [])) | set(
                  sum(groups.values(), [])),
              f"tui: preset groups {sorted(groups)}")
        check(set(groups.get("Environments · built-in", [])) >=
              {"it-org", "ot-plant", "enterprise-mixed", "industrial-site"},
              "tui: built-in envs not grouped as built-in")

        # campaign mode
        plans = campaign.packaged()
        check(len(plans) >= 3, "campaign examples missing")
        ui = _tui_ui(tui)
        ui.pcap = os.path.join(tempfile.gettempdir(), "tgt-w4a.pcap")
        check(ui.set_campaign(plans[0]) and ui.mode() == "campaign" and
              ui.rate == 0, "tui: campaign mode not entered")
        labels = _tui_labels(tui, ui)
        check("skip checks" in labels and "speed" in labels and
              "Schedule" not in labels and "duration" not in labels and
              "Malware sprinkle" not in labels and "Loop" not in labels,
              f"tui: campaign rows {labels}")
        ui.seed, ui.speed, ui.api = 7, 120.0, "127.0.0.1:8799"
        cfg = ui.build_config()
        plan = campaign.load(plans[0])
        check(cfg.campaign == plans[0] and cfg.schedule == "timed" and
              cfg.env == plan.base_env().key and cfg.seed == 7 and
              ui.phases and len(ui.phases) == len(plan.phases),
              f"tui: campaign config {cfg}")
        check(ui.service_command() == "campaign", "tui: service command")
        _tui_exercise(tui, ui, "campaign")
        ui.set_campaign(plans[0])
        ui.set_campaign(None)
        check(ui.mode() == "env" and ui.rate == 20,
              f"tui: leaving campaign mode gave {ui.mode()} rate {ui.rate}")
        ui.set_campaign(plans[0])
        tui._apply_preset(None, ui, ("c", None))
        check(ui.mode() == "custom" and ui.rate == 20,
              "tui: a preset did not leave campaign mode cleanly")

        # replay extras
        with tempfile.TemporaryDirectory() as d:
            cap = os.path.join(d, "in.pcap")
            with PcapWriter(cap) as w:
                for _k, fr in build_batch(RunConfig(profiles=["modbus"],
                                                    messages=1)):
                    w.write(fr)
            ui = _tui_ui(tui)
            ui.set_replay(cap)
            labels = _tui_labels(tui, ui)
            check(all(x in labels for x in (
                "replay speed", "passes", "VLAN retag", "remap IP",
                "remap subnet", "remap MAC")) and "Schedule" not in labels
                and "Seed" not in labels and "Campaign" not in labels,
                f"tui: replay rows {labels}")
            ui.replay_speed, ui.replay_loop, ui.replay_vlan = 2.0, 3, 0
            ui.remap["ip"] = "10.10.10.10=192.0.2.10"
            ui.remap["mac"] = "02:00:00:00:00:01=02:00:00:00:00:99"
            cfg = ui.build_config()
            check(cfg.replay_speed == 2 and cfg.replay_loop == 3 and
                  cfg.replay_vlan == 0 and cfg.remap_ip ==
                  ["10.10.10.10=192.0.2.10"] and cfg.remap_mac and
                  ui._check_start(cfg) is None,
                  f"tui: replay config {cfg}")
            ui.remap["subnet"] = "nonsense"
            check(ui._check_start(ui.build_config()) is not None,
                  "tui: a bad remap is not refused before start")
            ui.remap["subnet"] = ""
            _tui_exercise(tui, ui, "replay")
    finally:
        for k in set(enterprise.ENVIRONMENTS) - before:
            enterprise.ENVIRONMENTS.pop(k, None)


def test_tui_traffic_families_fanout_quit_log() -> None:
    """Traffic tab grouped by family (fold, filter); fan-out interfaces;
    q asks first while generating; the log is safe from other threads."""
    import threading
    from tgt import protocols as PR, tui
    ui = _tui_ui(tui)
    names = [f for f, _ in tui.FAMILIES]
    fams = {PR.get(k).key: tui.proto_family(PR.get(k)) for k in PR.PROFILES}
    check(all(f in names for f in fams.values()),
          f"tui: protocols outside the families: {fams}")
    for fam in ("OT/ICS", "Substation/L2", "Building", "Medical", "IT",
                "Infra/Discovery", "Remote access", "Vendor engineering"):
        check(fam in fams.values(), f"tui: family {fam} is empty")
    ui.set_scenario(None)
    ui.selected = ["modbus"]
    ui.focus = tui.PANELS.index("Traffic")
    fields = tui._fields(ui)
    heads = [f for f in fields if f.ident.startswith("family:")]
    protos = [f for f in fields if f.ident.startswith("proto:")]
    check(len(heads) >= 8 and [f.ident for f in protos] ==
          [f"proto:{k}" for k in PR.PROFILES if fams[k] == "OT/ICS"],
          "tui: only the family holding a selected protocol starts open")
    ot = heads[0]
    ui.row = 0
    tui._activate(None, ui, 0)                     # fold OT/ICS
    check(not any(f.ident.startswith("proto:") for f in tui._fields(ui))
          and tui._fields(ui)[ui.row].ident == ot.ident,
          "tui: folding a family failed / lost the cursor")
    tui._activate(None, ui, +1)                    # → opens it again
    row = next(i for i, f in enumerate(tui._fields(ui))
               if f.ident == "proto:dnp3")
    ui.row = row
    tui._activate(None, ui, 0)                     # toggle dnp3 on
    check("dnp3" in ui.selected and
          tui._fields(ui)[ui.row].ident == "proto:dnp3",
          "tui: toggling a protocol moved the cursor")
    ui.proto_filter = "goose"
    got = [f.ident for f in tui._fields(ui)]
    check(got == ["family:Substation/L2", "proto:goose"],
          f"tui: filter 'goose' shows {got}")
    ui.proto_filter = ""

    # fan-out: a second interface, counters per interface in the config
    ui.focus = tui.PANELS.index("Interfaces")
    ui.ifaces = {n: {"name": n, "state": "up", "kind": "veth",
                     "peer": n + "-mon"} for n in ("tgt0", "tgt1")}
    ui.ifaces.update({n + "-mon": {"name": n + "-mon", "state": "up",
                                   "kind": "veth", "peer": n}
                      for n in ("tgt0", "tgt1")})
    ui.send_iface = "tgt0"
    check("Fan-out" in [f.label for f in tui._fields(ui)],
          "tui: fan-out row hidden with two interfaces")
    ui.extra_ifaces = ["tgt1"]
    check(ui.iface_spec() == "tgt0,tgt1" and
          ui.build_config().iface == "tgt0,tgt1",
          f"tui: fan-out spec {ui.iface_spec()}")
    tui._act_send(None, ui, +1)                    # primary -> tgt1
    check(ui.send_iface == "tgt1" and ui.extra_ifaces == [],
          "tui: the new primary stays in the fan-out list")

    # q while generating asks first; any other key cancels
    class _Live:
        def is_alive(self):
            return True
    ui.engine = _Live()
    check(tui._handle_key(None, ui, ord("q")) and ui.quit_armed,
          "tui: q quit a live run without asking")
    check(tui._handle_key(None, ui, ord("x")) and not ui.quit_armed,
          "tui: another key did not cancel the quit")
    tui._handle_key(None, ui, ord("q"))
    check(not tui._handle_key(None, ui, ord("y")), "tui: y did not confirm")
    ui.engine = None
    check(not tui._handle_key(None, ui, ord("q")),
          "tui: q must quit at once when idle")

    # log: concurrent writers + a reader never raise, stay capped
    ui.clear_log()
    errors = []

    def writer(n):
        try:
            for i in range(2000):
                ui.add_log(f"w{n} {i}")
        except Exception as e:  # noqa: BLE001
            errors.append(e)
    threads = [threading.Thread(target=writer, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    while any(t.is_alive() for t in threads):
        lines = ui.log_lines()
        check(len(lines) <= 300, "tui: log grew past its cap")
    for t in threads:
        t.join()
    check(not errors and len(ui.log_lines()) == 300,
          f"tui: concurrent log writes: {errors} {len(ui.log_lines())}")


def test_rolling_pps_shows_stalls() -> None:
    """Stats.rolling: the recent rate drops to 0 in a stall while the
    lifetime average barely moves; RateLimiter resyncs instead of
    bursting the backlog."""
    import time
    from tgt.engine import Stats
    from tgt.sender import RateLimiter
    s = Stats()
    t0 = time.perf_counter()
    s.started = t0 - 100.0
    s.packets, s.bytes = 10000, 1000000
    check(abs(s.rolling(now=t0)[0] - 100.0) < 1.0,
          "rolling: first sample should be the lifetime average")
    s.packets += 500
    s.bytes += 50000
    pps, mbps = s.rolling(now=t0 + 1.0)
    check(abs(pps - 500.0) < 1e-6 and abs(mbps - 0.4) < 1e-6,
          f"rolling: 500 frames in 1 s gave {pps} pps {mbps} Mb/s")
    pps, _ = s.rolling(now=t0 + 10.0)              # nothing sent for 9 s
    check(pps == 0.0 and s.pps > 50, f"rolling: stall shows {pps} pps")
    for i in range(1, 11):                         # back to 100 pps
        s.packets += 50
        pps, _ = s.rolling(now=t0 + 10.0 + 0.5 * i)
    check(abs(pps - 100.0) < 1e-6, f"rolling: recovery gave {pps} pps")
    lim = RateLimiter(100)
    lim._next -= 1.0                               # a 1 s stall
    start, n = time.perf_counter(), 0
    while time.perf_counter() - start < 0.1:
        lim.wait()
        n += 1
    check(n <= 25, f"rate limiter burst {n} frames in 100 ms at 100 pps")


def test_tui_inject_api_and_manifest() -> None:
    """A TUI-started run (pcap only): seed + manifest + control API; the
    TUI's injection lands in the traffic, the ENGINE box and the manifest;
    the API serves while it runs and closes after."""
    import json
    import time
    from tgt import api, incidents, tui
    tui_cattr = tui._cattr
    tui._cattr = lambda color, extra=0: extra      # no curses screen here
    try:
        with tempfile.TemporaryDirectory() as d:
            ui = _tui_ui(tui)
            ok, msg = ui.inject("wannacry", 5)
            check(not ok and "start" in msg, "tui: inject while idle")
            ui.set_scenario(None)
            ui.selected = ["modbus"]
            ui.pcap = os.path.join(d, "run.pcap")
            ui.manifest = os.path.join(d, "run.json")
            ui.seed, ui.rate, ui.api = 4242, 400.0, "127.0.0.1:0"
            ui.start_stop()
            check(ui.running() and ui.api_server is not None,
                  "tui: run / API did not start")
            port = ui.api_server.port
            code, doc = api.request(f"127.0.0.1:{port}", "GET", "/status")
            check(code == 200 and doc.get("seed") == 4242,
                  f"tui: API status {code} {doc}")
            ok, msg = ui.inject("wannacry", 1.0)
            check(ok, f"tui: inject failed: {msg}")
            ok2, msg2 = ui.inject("wannacry", 1.0)
            check(not ok2 and "already" in msg2,
                  "tui: a second inject of the same incident was accepted")
            seen_box = False
            deadline = time.time() + 15
            attacks = {k for k, _ in incidents.get("wannacry").build(1)}
            while time.time() < deadline:
                lines = [t for t, _ in tui._engine_extra_lines(ui)]
                seen_box = seen_box or any("wannacry" in t for t in lines)
                st = ui.engine.control.status()
                if st and st[0]["state"] == "done":
                    break
                time.sleep(0.05)
            check(seen_box, "tui: active injection not in the ENGINE box")
            check(st and st[0]["state"] == "done" and st[0]["packets"] > 0
                  and st[0]["via"] == "tui",
                  f"tui: injection status {st}")
            mal = set(incidents.ATTACKS)
            counts = dict(ui.stats().per_profile)
            check(any(k in mal for k in counts),
                  f"tui: no attack frames in the mix {counts}")
            check(bool(attacks & set(counts)), "tui: wannacry frames missing")
            check(ui.stats().recent_pps >= 0, "tui: recent pps")
            ui.start_stop()                        # stop
            ui.engine.join(5)
            ui.refresh()
            check(ui.api_server is None, "tui: API kept serving after stop")
            man = json.load(open(ui.manifest))
            check(man.get("seed") == 4242 and man.get("injections") and
                  man["injections"][0]["incident"] == "wannacry",
                  f"tui: manifest {sorted(man)}")
    finally:
        tui._cattr = tui_cattr


def test_build_run_args_every_tui_option() -> None:
    """Every run option the TUI sets reaches `tgt run` / `tgt campaign`
    through the service config (sourced like tgtctl.sh does, multi-iface
    TGT_IFACE and TGT_CMD included)."""
    import shlex
    import shutil
    import subprocess
    from tgt import campaign, cli, service, tui
    args = service.build_run_args(
        None, [], 0, 5, env="water-utility", seed=99,
        manifest="/var/lib/tgt/m 1.json", schedule="timed", speed=60,
        day_profile="flat", min_period=2, duration=7200, clock="synthetic",
        start_time="2026-11-05T14:00:00Z", api="127.0.0.1:8787")
    ns = cli.build_parser().parse_args(["run"] + shlex.split(args))
    check(ns.env == "water-utility" and ns.seed == 99 and
          ns.manifest == "/var/lib/tgt/m 1.json" and ns.schedule == "timed"
          and ns.speed == 60 and ns.day_profile == "flat" and
          ns.min_period == 2 and ns.duration == 7200 and
          ns.clock == "synthetic" and ns.start_time ==
          "2026-11-05T14:00:00Z" and ns.api == "127.0.0.1:8787",
          f"build_run_args timed/clock/api: {args}")
    rargs = service.build_run_args(
        None, [], 50, 5, replay="/caps/a b.pcapng", replay_speed=2,
        replay_loop=3, remap_ip=["10.0.0.1=192.0.2.1,10.0.0.2=192.0.2.2"],
        remap_subnet=["10.1.0.0/16=10.9.0.0/16"],
        remap_mac=["00:11:22:33:44:55=02:00:00:00:00:09"], vlan=0)
    ns = cli.build_parser().parse_args(["run"] + shlex.split(rargs))
    check(ns.replay == "/caps/a b.pcapng" and ns.replay_speed == 2 and
          ns.replay_loop == 3 and ns.remap_ip ==
          ["10.0.0.1=192.0.2.1,10.0.0.2=192.0.2.2"] and
          ns.remap_subnet == ["10.1.0.0/16=10.9.0.0/16"] and
          ns.remap_mac == ["00:11:22:33:44:55=02:00:00:00:00:09"] and
          ns.vlan == 0 and not ns.replay_realtime,
          f"build_run_args replay: {rargs}")
    plain = service.build_run_args(None, ["modbus"], 20, 5, vlan=5,
                                   replay_speed=2, start_time="x")
    check("--vlan" not in plain and "--replay-speed" not in plain and
          "--start-time" not in plain, f"replay/clock args leaked: {plain}")
    plan = campaign.packaged()[0]
    cargs = service.build_campaign_args(
        plan, rate=100, seed=5, manifest="/tmp/c m.json", clock="synthetic",
        start_time="2026-11-05T00:00:00Z", speed=30, min_period=1,
        pcap="/tmp/c.pcap", api="127.0.0.1:8788", force=True)
    ns = cli.build_parser().parse_args(["campaign"] + shlex.split(cargs))
    check(ns.plan == plan and ns.rate == 100 and ns.seed == 5 and
          ns.manifest == "/tmp/c m.json" and ns.clock == "synthetic" and
          ns.start_time == "2026-11-05T00:00:00Z" and ns.speed == 30 and
          ns.min_period == 1 and ns.pcap == "/tmp/c.pcap" and
          ns.api == "127.0.0.1:8788" and ns.force,
          f"build_campaign_args: {cargs}")
    # the TUI's own selection round-trips the same way
    ui = _tui_ui(tui)
    ui.set_campaign(plan)
    ui.seed, ui.api = 11, "127.0.0.1:8790"
    ns = cli.build_parser().parse_args(
        [ui.service_command()] + shlex.split(ui.run_args()))
    check(ns.command == "campaign" and ns.plan == plan and ns.seed == 11 and
          ns.api == "127.0.0.1:8790", f"tui campaign args: {ui.run_args()}")
    with tempfile.TemporaryDirectory() as d:
        conf = os.path.join(d, "tgt.conf")
        ok, msg = service.write_config("tgt0,tgt1", cargs, path=conf,
                                       command="campaign")
        rc = service.read_config(conf)
        check(ok and rc.get("TGT_CMD") == "campaign" and
              rc.get("TGT_IFACE") == "tgt0,tgt1",
              f"write_config campaign: {msg} {rc}")
        check(not service.write_config("x", "", path=conf,
                                       command="rm -rf")[0],
              "write_config accepted an unknown command")
        unit = os.path.join(d, "tgt.service")
        with open(unit, "w") as f:
            f.write("ExecStart=/bin/sh -c 'exec tgt run'\n")
        check(not service.unit_runs_command(unit) and
              service.unit_runs_command(os.path.join(d, "none")),
              "unit_runs_command")
        sh = shutil.which("sh")
        if sh:                  # as the systemd unit / daemon expand it
            r = subprocess.run(
                [sh, "-c", '. "$1" && eval "set -- $TGT_RUN_ARGS" && '
                 'printf "%s\\n" "${TGT_CMD:-run}" --iface "$TGT_IFACE" "$@"',
                 "sh", conf], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True, timeout=10)
            argv = r.stdout.splitlines()
            ns = cli.build_parser().parse_args(argv)
            check(ns.command == "campaign" and ns.iface == "tgt0,tgt1" and
                  ns.plan == plan and ns.force,
                  f"sourced campaign config argv: {argv} {r.stderr}")
    script = open(os.path.join(_REPO, "scripts", "tgtctl.sh")).read()
    check("TGT_CMD:-run" in script and 'tr , " "' in script,
          "tgtctl.sh does not honour TGT_CMD / multi-interface TGT_IFACE")


# -- wave-4 follow-ups: pause shift, no self-flows on remapped incidents ------
def test_timed_pause_shifts_schedule() -> None:
    """A paused timed run picks the schedule up where it left off: every
    later sleep target moves by the paused time, so resuming does not burst
    the backlog."""
    import time
    from tgt.engine import Engine
    with tempfile.TemporaryDirectory() as d:
        cfg = RunConfig(env="it-org", schedule="timed", speed=600, rate=0,
                        seed=5, count=40,
                        pcap_path=os.path.join(d, "p.pcap"))
        eng = Engine(cfg)
        targets = []
        eng._sleep_until = targets.append      # record, never sleep
        eng.control.paused_total = 1000.0      # as if paused for 1000 s
        t0 = time.perf_counter()
        eng.start()
        eng.join(60)
        check(not eng.is_alive(), "pause-shift run did not finish")
        check(targets and min(targets) >= t0 + 1000.0,
              f"timed sleeps ignore the paused time: {targets[:3]}")


def test_incident_mapping_never_self_flows() -> None:
    """map_onto never places both ends of an incident flow on one host
    (WannaCry's patient zero and its victims on a single-workstation site)."""
    from tgt import enterprise, envfile, incidents
    envfile.load_user_envs(warn=lambda m: None, force=True)
    bad = []
    for ek in sorted(enterprise.ENVIRONMENTS):
        env = enterprise.get(ek)
        for ik in sorted(incidents.INCIDENTS):
            inc = incidents.get(ik)
            m = inc.map_onto(env)
            bad += [(ek, ik, a, v) for a, v, _, _ in inc.flows
                    if a in m and v in m and m[a].name == m[v].name]
    check(not bad, f"incident flows mapped onto one host: {bad[:4]}")
    if "electric-substation" in enterprise.ENVIRONMENTS:
        m = incidents.get("wannacry").map_onto(
            enterprise.get("electric-substation"))
        check(len({h.name for h in m.values()}) == len(m),
              "wannacry hosts collapse onto one substation host")


# -- PR #63 review fixes: pause gate, injection worker, API, sender ---------
def test_review_pause_gate_and_paused_time() -> None:
    """RunControl.gate holds a frame through a pause that began while the
    engine was waiting to send it, and paused_for counts the current
    pause (cycle-mode --duration excludes paused time)."""
    import threading
    import time
    from tgt.control import RunControl
    rc, stop = RunControl(), threading.Event()
    check(rc.gate(stop), "gate: blocks while running")
    rc.pause()
    out = []
    t = threading.Thread(target=lambda: out.append(rc.gate(stop)))
    t.start()
    time.sleep(0.35)
    check(not out and t.is_alive(), "gate: did not hold during a pause")
    check(rc.paused_for() >= 0.3, f"paused_for {rc.paused_for():.2f}")
    rc.resume()
    t.join(2)
    check(out == [True], f"gate after resume: {out}")
    check(rc.paused_total >= 0.3, "paused_total not accumulated")
    rc.pause()
    out.clear()
    t = threading.Thread(target=lambda: out.append(rc.gate(stop)))
    t.start()
    stop.set()
    t.join(2)
    check(out == [False], f"gate after stop while paused: {out}")


def test_review_injection_worker() -> None:
    """Injection passes build on a worker; a pass that builds no frames
    fails the injection (no rebuild per base frame), and the build is
    addressed onto the engine's current environment (a campaign phase)."""
    import threading
    from tgt import control, enterprise
    from tgt.engine import Engine
    cfg = RunConfig(env="it-org", seed=3, rate=0, count=3000,
                    clock="synthetic", start_time="2026-11-05T14:00:00Z")
    eng = Engine(cfg)
    calls = []

    def empty(inj, n):
        calls.append(n)
        return []
    eng.control._build = empty
    inj = eng.control.inject("wannacry", duration=60.0)
    eng.start()
    eng.join(60)
    check(inj.state == "failed" and "no frames" in inj.error,
          f"empty injection: {inj.state} {inj.error!r}")
    check(len(calls) == 1, f"empty injection rebuilt {len(calls)} times")
    # env_now: the injection lands on the environment the engine sends now
    ot = enterprise.get("ot-plant")
    fr = control.build_incident(cfg, "industroyer", 1, env=ot)
    ips = {h.ip for h in ot.hosts}
    seen = set()
    for _, f, _ in fr:
        off = 18 if f[12:14] == b"\x81\x00" else 14
        if f[off - 2:off] == b"\x08\x00":
            seen.add(".".join(map(str, f[off + 12:off + 16])))
    check(seen & ips, "build_incident(env=) ignored the given environment")


def test_review_api_rejects_close_connection() -> None:
    """A rejected request closes the connection (its unread body is never
    parsed as the next request); a negative Content-Length is a 400."""
    import http.client
    from tgt import api
    from tgt.engine import Engine
    eng = Engine(RunConfig(profiles=["modbus"], rate=10))
    srv = api.ControlServer(eng, "127.0.0.1", 0, token="t0k").start()
    try:
        c = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=5)
        c.request("POST", "/inject", body="incident=wannacry",
                  headers={"Content-Type":
                           "application/x-www-form-urlencoded"})
        r = c.getresponse()
        r.read()
        check(r.status == 401 and r.getheader("Connection") == "close",
              f"api: rejected POST {r.status} {r.getheader('Connection')}")
        c.close()
        c = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=5)
        c.putrequest("POST", "/rate?pps=5")
        c.putheader("Authorization", "Bearer t0k")
        c.putheader("Content-Length", "-1")
        c.endheaders()
        r = c.getresponse()
        r.read()
        check(r.status == 400, f"api: negative Content-Length -> {r.status}")
        c.close()
    finally:
        srv.close()


def test_review_sender_reopens_deleted_iface() -> None:
    """A send that fails because the interface is gone drops that socket
    and reopens the interface by name on the retry schedule."""
    import errno as _errno
    from tgt.sender import RawSender

    class Gone:
        closed = False

        def send(self, frame):
            raise OSError(_errno.ENXIO, "No such device or address")

        def close(self):
            Gone.closed = True

    class Fine:
        def send(self, frame):
            return len(frame)

        def close(self):
            pass
    s = RawSender("a,b")
    s.socks = {"a": Fine(), "b": Gone()}
    s.send(b"x" * 60)
    check(s.socks["b"] is None and Gone.closed and s._retry_at.get("b"),
          "sender: dead-ifindex socket kept")
    check(s.counters["a"]["packets"] == 1 and s.counters["b"]["errors"] == 1,
          f"sender counters {s.counters}")
    s.socks = {"a": Fine(), "b": Fine()}
    s.socks["b"] = type("Down", (), {
        "send": lambda self, f: (_ for _ in ()).throw(
            OSError(_errno.ENETDOWN, "Network is down")),
        "close": lambda self: None})()
    s.send(b"x" * 60)
    check(s.socks["b"] is not None, "sender: link-down socket dropped")

# ---- W5-A: MITRE ATT&CK technique tags (#64) --------------------------------
def test_w5a_attack_techniques_cover_attacks() -> None:
    """Every built-in attack builder maps onto techniques that exist in
    tgt/attack_ics.json; the table is well formed and fully used; incident
    extras name real incidents/flows; label parsing and ID matching."""
    import json
    from tgt import incidents, plugins
    from tgt import techniques as T
    tab = T.load()
    raw = json.load(open(T.TABLE_PATH, encoding="utf-8"))
    check(set(tab) == {k for k in raw if not k.startswith("_")} and
          len(tab) >= 20, "attack_ics.json: table not loaded")
    tactics = {"initial-access", "execution", "persistence",
               "privilege-escalation", "evasion", "defense-evasion",
               "discovery", "lateral-movement", "collection",
               "command-and-control", "inhibit-response-function",
               "impair-process-control", "impact", "reconnaissance",
               "credential-access", "exfiltration"}
    for tid, v in tab.items():
        ok = (v.get("name") and v.get("tactic") and
              set(v["tactic"]) <= tactics and
              v.get("matrix") in ("ics", "enterprise") and
              T.parse_ids(tid) == [tid] and
              (tid.startswith("T08")) == (v["matrix"] == "ics"))
        check(bool(ok), f"attack_ics.json: bad entry {tid} {v}")
    builtin = [k for k, (b, _) in incidents.ATTACKS.items()
               if b.__module__ == "tgt.incidents"]
    check(len(builtin) >= 14, "built-in attacks missing")
    for k in builtin:
        ids = T.for_attack(k)
        check(bool(ids) and all(t in tab for t in ids) and
              ids == sorted(set(ids)),
              f"techniques: attack {k} -> {ids} (missing / not in table)")
    probs = [p for p in T.validate()
             if not p.startswith("attack ") or p.split()[1] in builtin]
    check(not probs, f"techniques.validate: {probs}")
    used = set()
    for ik in incidents.INCIDENTS:
        ids = T.for_incident(ik)
        check(ids == sorted(set(ids)) and all(t in tab for t in ids),
              f"techniques: incident {ik} -> {ids}")
        used.update(ids)
    check(set(tab) <= used, f"attack_ics.json lists techniques no incident "
          f"shows: {sorted(set(tab) - used)}")
    # spot checks the issue names
    check("T0846" in T.for_attack("port-scan") and
          "T0855" in T.for_attack("modbus-write") and
          "T0855" in T.for_attack("iec104-command") and
          "T0843" in T.for_attack("tristation") and
          "T0886" in T.for_attack("smb-lateral") and
          "T0869" in T.for_attack("c2-beacon"),
          "techniques: issue examples not mapped")
    check(T.for_flow("iec104-command", "industroyer") == ["T0806", "T0855"]
          and T.for_flow("iec104-command") == ["T0855"] and
          "T1568.002" in T.for_incident("sunburst") and
          "T1568.002" not in T.for_incident("wannacry"),
          "techniques: per-incident extras")
    check(T.name("T0855") == "Unauthorized Command Message" and
          T.name("T9999") == "" and T.for_attack("nope") == [] and
          T.for_incident("nope") == [], "techniques: name / unknown keys")
    check(T.incident_of("inject:wannacry#3") == "wannacry" and
          T.incident_of("sprinkle:triton") == "triton" and
          T.incident_of("incident:stuxnet") == "stuxnet" and
          T.incident_of("baseline") is None and T.incident_of("") is None,
          "techniques: source label parsing")
    check(T.for_event("dga-dns", "inject:conficker#1") ==
          ["T0869", "T1071.004", "T1568.002"], "techniques: for_event")
    check(T.parse_ids("MITRE t0855; T1071.001,T0855 x") ==
          ["T0855", "T1071.001"], "techniques: parse_ids")
    check(T.shares(["T1071"], ["T1071.001"]) and
          T.shares(["T1071.004"], ["T1071"]) and
          not T.shares(["T1110.001"], ["T1110.003"]) and
          not T.shares([], ["T0855"]) and T.shares(["T0855"], ["T0855"]),
          "techniques: shares (parent / sub-technique)")
    # plugins: techniques= on register_attack, validated and rolled back
    try:
        plugins.register_attack("w5a-x", lambda ep, n: [], "x",
                                category="ot-write", techniques=["T9999"])
        check(False, "plugins: unknown technique accepted")
    except plugins.PluginError:
        pass
    plugins.unload_all()
    plugins.register_attack("w5a-y", lambda ep, n: [], "y",
                            category="ot-write", techniques=["T0855"])
    check(T.for_attack("w5a-y") == ["T0855"], "plugins: attack techniques")
    plugins.unload_all()
    check("w5a-y" not in T.ATTACK_TECHNIQUES and
          "w5a-y" not in incidents.ATTACKS,
          "plugins: attack techniques not rolled back")


def test_w5a_manifest_events_carry_techniques() -> None:
    """Attack events of sprinkle, --incident and injection runs carry the
    sorted technique IDs of their attack (+ incident extras); new-asset
    events carry none; tgt inventory --sprinkle / tgt list show them."""
    import contextlib
    import io
    from tgt import cli, enterprise, manifest
    from tgt import techniques as T
    from tgt.engine import build_batch as bb
    cfg = RunConfig(env="it-org", sprinkle=["industroyer"], messages=2)
    n = len(bb(cfg))
    with tempfile.TemporaryDirectory() as d:
        m = _manifest_run(d, "spr", RunConfig(
            env="it-org", sprinkle=["industroyer"], messages=2, seed=3),
            n + 50)
        m2 = _manifest_run(d, "inc", RunConfig(
            incident="triton", messages=2, seed=3), 60)
    atk = [e for e in m["events"] if e.get("attack")]
    check(atk and all(e["techniques"] == T.for_event(e["attack"],
                                                      e["source"])
                      and e["techniques"] for e in atk),
          f"manifest: sprinkle events lack techniques "
          f"{[(e['attack'], e.get('techniques')) for e in atk]}")
    iec = [e for e in atk if e["attack"] == "iec104-command"]
    check(iec and iec[0]["techniques"] == ["T0806", "T0855"],
          f"manifest: industroyer extras {iec}")
    check(all("techniques" not in e for e in m["events"]
              if e["category"] == "new-asset"),
          "manifest: new-asset event carries techniques")
    atk2 = [e for e in m2["events"] if e.get("attack")]
    check({e["attack"] for e in atk2} == {"tristation", "port-scan"} and
          all(e["source"] == "incident:triton" and
              e["techniques"] == T.for_attack(e["attack"]) for e in atk2),
          f"manifest: --incident events {atk2}")
    # an injection's events (control API / tgt ctl inject source label)
    rec = manifest.Recorder(RunConfig(env="it-org"), 1, clock="synthetic")
    rec.events[("a", "b", "dga-dns", "inject:sunburst#2")] = [
        0.0, 1.0, 3, ("a", "b", "10.0.0.1", "10.0.0.2")]
    ev = rec.to_dict()["events"][0]
    check(ev["techniques"] == ["T0869", "T1071.004", "T1568.002"],
          f"manifest: injection event techniques {ev}")
    # tgt inventory --sprinkle (JSON inline, CSV on stderr) and tgt list
    from tgt import inventory
    doc = inventory.to_json(enterprise.get("it-org"), ["colonial"])
    check(doc["sprinkle"]["colonial"]["techniques"] ==
          T.for_incident("colonial"), "inventory JSON: sprinkle techniques")

    class A:
        env, env_file, format, output = "it-org", None, "csv", None
        sprinkle = ["colonial"]
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        cli.cmd_inventory(A())
    check("sprinkle colonial: ATT&CK T0869" in err.getvalue(),
          f"inventory CSV: techniques note {err.getvalue()!r}")
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cli.cmd_list(None)
    txt = buf.getvalue()
    check("techniques: " + ", ".join(T.for_incident("triton")) in txt and
          "T0855     Unauthorized Command Message" in txt,
          "tgt list: incident techniques / technique table missing")


def _w5a_truth():
    from tgt import score
    hosts = [{"asset_id": "s:ENG", "name": "ENG", "ip": "10.0.0.1"},
             {"asset_id": "s:PLC", "name": "PLC", "ip": "10.0.0.2"},
             {"asset_id": "s:WS", "name": "WS", "ip": "10.0.0.3"}]

    def ev(i, cat, atk, t0, src, dst, tech=None):
        e = {"id": f"e{i}", "category": cat, "attack": atk,
             "t_start": f"2026-11-05T14:{t0}Z",
             "t_end": f"2026-11-05T14:{t0}Z", "src": src, "dst": dst,
             "hosts": [], "source": "sprinkle:x", "detail": atk}
        if tech is not None:
            e["techniques"] = tech
        return e
    events = [
        ev(1, "scan", "port-scan", "00:00", "10.0.0.1", "10.0.0.2",
           ["T0846", "T1046"]),
        ev(2, "ot-write", "modbus-write", "01:00", "10.0.0.1", "10.0.0.2",
           ["T0836", "T0855"]),
        ev(3, "ot-write", "modbus-write", "02:00", "10.0.0.3", "10.0.0.2",
           ["T0836", "T0855"]),
        ev(4, "c2", "https-c2", "03:00", "10.0.0.3", "198.51.100.9",
           ["T0869", "T1071.001", "T1573"]),
        # an old manifest without "techniques": derived from the attack
        ev(5, "c2", "dga-dns", "04:00", "10.0.0.1", "10.0.0.3"),
        {"id": "e6", "category": "new-asset", "t_start":
         "2026-11-05T14:05:00Z", "t_end": "2026-11-05T14:05:00Z",
         "hosts": ["10.0.0.9"], "src": "10.0.0.9", "dst": None,
         "source": "sprinkle:x"}]
    doc = {"schema": "tgt-manifest/1", "start": "2026-11-05T14:00:00Z",
           "end": "2026-11-05T14:10:00Z", "inventory": {"hosts": hosts},
           "first_seen": {}, "events": events}
    return score.Truth(doc, "w5a")


def test_w5a_score_by_technique_and_strict() -> None:
    """tgt score: detections.by_technique counts (an event counts toward
    each of its techniques), median TTD, tagged alerts via a technique
    column and title regexes, --strict-technique, rendering."""
    import json
    from tgt import score
    truth = _w5a_truth()
    amap = {"format": "csv",
            "columns": {"time": "time", "src": "src", "dst": "dst",
                        "title": "title", "technique": "mitre"},
            "categories": {"scan": "scan", "modbus write": "ot-write",
                           "c2|beacon": "c2"},
            "techniques": {"beacon": ["T1071.001"]}}
    rows = ("time,src,dst,title,mitre\n"
            # e1 scan, 10 s late, untagged
            "2026-11-05T14:00:10Z,10.0.0.1,10.0.0.2,Port scan,\n"
            # e2 modbus write, tagged with a shared technique
            "2026-11-05T14:01:20Z,10.0.0.1,10.0.0.2,Modbus write,T0855\n"
            # e3 modbus write, tagged with an unrelated technique
            "2026-11-05T14:02:30Z,10.0.0.3,10.0.0.2,Modbus write,T0843\n"
            # e4 c2: regex adds T1071.001 (shared)
            "2026-11-05T14:03:40Z,10.0.0.3,198.51.100.9,TLS beacon,\n"
            # e5 dga: column says T1071 (parent of T1071.004)
            "2026-11-05T14:04:50Z,10.0.0.1,10.0.0.3,C2 lookup,T1071\n")
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "alerts.csv")
        with open(p, "w") as f:
            f.write(rows)
        alerts = score.read_alerts(p, amap)
        plain = score.read_alerts(p, dict(amap, techniques={},
                                          columns=dict(amap["columns"],
                                                       technique="nope")))
    check([a["techniques"] for a in alerts] ==
          [[], ["T0855"], ["T0843"], ["T1071.001"], ["T1071"]],
          f"read_alerts techniques {[a['techniques'] for a in alerts]}")
    check(all(a["techniques"] is None for a in plain),
          "read_alerts: untagged map must give techniques None")
    det = score.detections(truth, alerts, 300.0, 5.0)
    bt = det["by_technique"]
    want = {"T0836": (2, 2), "T0855": (2, 2), "T0846": (1, 1),
            "T1046": (1, 1), "T0869": (2, 2), "T1071.001": (1, 1),
            "T1573": (1, 1), "T1071.004": (1, 1)}
    check({t: (v["events"], v["detected"]) for t, v in bt.items()} == want,
          f"by_technique counts {bt}")
    check(list(bt) == sorted(bt) and
          set(bt["T0855"]) == {"name", "events", "detected", "rate",
                               "median_ttd_s"} and
          bt["T0855"]["name"] == "Unauthorized Command Message" and
          bt["T0855"]["rate"] == 1.0 and
          bt["T0855"]["median_ttd_s"] == 25.0 and
          bt["T0846"]["median_ttd_s"] == 10.0,
          f"by_technique shape {bt.get('T0855')}")
    check(det["detected"] == 5 and det["strict_technique"] is False and
          det["tagged_alerts"] == 4, f"detections {det['detected']}")
    # strict: e3's alert (T0843) no longer matches; parent T1071 still does
    sd = score.detections(truth, alerts, 300.0, 5.0, strict_technique=True)
    sbt = sd["by_technique"]
    check(sd["detected"] == 4 and sbt["T0855"]["detected"] == 1 and
          sbt["T0855"]["rate"] == 0.5 and
          sbt["T0855"]["median_ttd_s"] == 20.0 and
          sbt["T1071.004"]["detected"] == 1 and
          sbt["T0846"]["detected"] == 1 and sd["strict_technique"] and
          len(sd["false_alerts"]) == 1,
          f"strict technique: {sd['detected']} {sbt}")
    nd = score.detections(truth, plain, 300.0, 5.0, strict_technique=True)
    check(nd["detected"] == 5, "strict with an untagged map changed results")
    # through score(): JSON-serialisable, summary + HTML tables; absent
    # without alerts
    res = score.score(truth, [], {"rows": 0, "columns": {}, "source": "x",
                                  "map": "m", "protocol_ignore": [],
                                  "normalize": lambda f, v: v},
                      alerts=alerts, strict_technique=True)
    check(res["detections"]["by_technique"]["T0855"]["detected"] == 1,
          "score(): strict_technique not passed through")
    json.dumps(res, default=str)
    txt = score.summary(res)
    check("techniques  ATT&CK coverage" in txt and "T0855" in txt and
          "Unauthorized Command Message" in txt, f"summary: {txt}")
    page = score.to_html(res)
    check("Detections by ATT&amp;CK technique" in page and
          "<td>T1071.004</td>" in page and "impair-process-control" in page,
          "html: technique table missing")
    res2 = score.score(truth, [], {"rows": 0, "columns": {}, "source": "x",
                                   "map": "m", "protocol_ignore": [],
                                   "normalize": lambda f, v: v})
    check(res2["detections"] is None, "detections without alerts")
    # the generic alert map's optional technique column and rules
    gen = score.load_json_spec("alerts-generic")
    check(gen["columns"].get("technique") and gen.get("techniques"),
          "alerts-generic: optional technique fields missing")


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        before = len(_failures)
        try:
            t()
        except Exception as e:  # noqa: BLE001
            _failures.append(f"{t.__name__} raised {e!r}")
        status = ("FAIL" if len(_failures) != before else
                  "skip" if t.__name__ in _skipped else "ok")
        print(f"  {t.__name__:42} {status}")
    print("-" * 50)
    if _failures:
        print(f"FAILED ({len(_failures)}):")
        for f in _failures:
            print(f"  - {f}")
        return 1
    print(f"OK — {len(tests)} test groups passed, all checksums valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
