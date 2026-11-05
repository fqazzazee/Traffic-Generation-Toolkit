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
    check(incidents.get("industroyer").map_onto(site)["RTU-104"].role == "rtu",
          "industroyer RTU not mapped onto the site's RTU")
    check(incidents.get("triton").map_onto(site)["SIS-TRICONEX"].os ==
          "schneider", "triton SIS not mapped onto a Schneider controller")
    check("SIS-TRICONEX" not in incidents.get("triton").map_onto(plant),
          "triton SIS mapped although ot-plant has no Schneider device")
    rtu = incidents.get("industroyer").map_onto(plant).get("RTU-104")
    check(rtu is not None and rtu.role == "plc" and rtu.os == "siemens",
          "industroyer RTU did not fall back to a Siemens field device")

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
    check(b"P_PROGRAM" in blob("stuxnet"), "stuxnet: no S7 program download")
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
    pd = incidents.get("pipedream").map_onto(site)
    segs = {site.segment_of(pd[n]).name
            for n in ("PLC-MODICON", "PLC-OMRON")}
    check(len(segs) == 1, f"pipedream PLCs scattered across cells: {segs}")
    # and the engineering stage stays up in supervisory, the PLCs down in a cell
    check(site.segment_of(pd["PIPEDREAM-ENGWS"]).zone == "OT-SUPERVISORY" and
          all(site.segment_of(pd[n]).zone == "OT-CELL"
              for n in ("PLC-MODICON", "PLC-OMRON")),
          "pipedream did not descend supervisory -> cell")


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
