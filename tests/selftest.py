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
            payload = f[14 + ihl + 20:]
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
    return env, [f for _, f in env.build(1, span=span, edr=False)]


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
    check(set(_DISSECTS_AS) == set(protocols.PROFILES),
          "_DISSECTS_AS out of sync with the protocol registry")
    groups = {k: protocols.get(k).build(Endpoints(), 3) for k in _DISSECTS_AS}
    groups["smb1"] = protocols.smb_flow(Endpoints(meta={"smb": "smb1"}), 3)
    site = [f for _, f in enterprise.get("industrial-site").build(2)]
    with tempfile.TemporaryDirectory() as d:
        path = f"{d}/all.pcap"
        with PcapWriter(path) as w:
            for frames in list(groups.values()) + [site]:
                for f in frames:
                    w.write(f)
        layers = subprocess.run(
            ["tshark", "-r", path, "-T", "fields", "-e", "frame.protocols"],
            capture_output=True, text=True).stdout.splitlines()
        expert = subprocess.run(["tshark", "-r", path, "-q", "-z", "expert,warn"],
                                capture_output=True, text=True).stdout
    seen = {x for line in layers for x in line.split(":")}
    for key, layer in list(_DISSECTS_AS.items()) + [("smb1", "smb")]:
        check(layer in seen, f"tshark: {key} never dissected as {layer}")
    if "Errors (" in expert or "Warns (" in expert:
        detail = [ln.strip() for ln in expert.splitlines()
                  if "Malformed" in ln or "Warning" in ln or "incorrect" in ln]
        _failures.append("tshark expert warnings: " + "; ".join(detail[:5]))


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
        "new_assets": ["SIS-TRICONEX"]}, "inventory JSON sprinkle mapping")


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
    from tgt.engine import replay_offsets
    check(replay_offsets([10.0, 10.5, 10.4, 30.0]) == [0.0, 0.5, 0.5, 5.5],
          "replay_offsets: gaps not clamped to [0, 5]")
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
             "dnp3-time": {"scada"}, "iec104-time": {"scada"}}
    check(set(roles) == set(OPERATIONS), "OPERATIONS out of sync with test")
    used = set()
    for env in enterprise.all_environments():
        for c, sv, p in env.conversations:
            if p in OPERATIONS:
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
    check(seg <= protocols.TcpSession.mss, f"opcua: {seg}-byte TCP segment")


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
