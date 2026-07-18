"""Dependency-free self-test — validates packet construction end to end.

Run on the target host to confirm TGT builds correct frames before you rely on
it:  ``python3 -m tests.selftest``  (exit 0 = all good).
"""
from __future__ import annotations

import struct
import sys
import tempfile

from tgt import packet as P
from tgt import protocols, scenarios
from tgt.config import RunConfig
from tgt.engine import build_batch
from tgt.packet import Endpoints
from tgt.pcap import PcapWriter

_failures: list[str] = []


def check(cond: bool, msg: str) -> None:
    if not cond:
        _failures.append(msg)


def verify_ip_l4(frame: bytes, label: str) -> None:
    """IP and TCP/UDP checksums must re-sum to zero when correct."""
    eth_type = struct.unpack("!H", frame[12:14])[0]
    if eth_type != P.ETH_P_IP:
        return
    ihl = (frame[14] & 0x0F) * 4
    ip_hdr = frame[14:14 + ihl]
    check(P.checksum16(ip_hdr) == 0, f"{label}: IP checksum invalid")
    proto = frame[14 + 9]
    src = frame[14 + 12:14 + 16]
    dst = frame[14 + 16:14 + 20]
    seg = frame[14 + ihl:]
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


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        before = len(_failures)
        try:
            t()
        except Exception as e:  # noqa: BLE001
            _failures.append(f"{t.__name__} raised {e!r}")
        status = "ok" if len(_failures) == before else "FAIL"
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
