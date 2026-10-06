"""Modeled organizations — realistic IT and OT networks with fingerprinted hosts.

An :class:`Environment` is a named inventory of :class:`Host` objects (each with
a role, IP, MAC and OS/device fingerprint) plus a generator that emits a
realistic mix of conversations between them: DNS/Kerberos/LDAP to the DC, SMB to
the file server, HTTP/HTTPS browsing, DHCP/NetBIOS fingerprint chatter, and — on
the OT side — Rockwell EtherNet/IP and Siemens S7comm PLC polling with vendor
identity. Legacy hosts (Windows 2000/XP/7) advertise SMBv1 and old User-Agents so
an analyser (Zeek, Suricata, Claroty CTD, …) can inventory assets and flag the risky ones.

Hosts sit in segments (:class:`Segment`) — one VLAN + subnet + security zone each, routed
by a core L3 switch. Same-segment flows are switched (peer MACs); cross-segment
flows go via the gateway MAC and carry each segment's 802.1Q tag. The default
``access`` view shows every frame once, on its sender's VLAN; the ``core`` view
adds the routed copy on the receiver's VLAN, as a SPAN on the core switch sees.

Everything is synthetic and self-contained; it reuses the byte-accurate builders
in :mod:`tgt.protocols`, driving them between arbitrary host pairs.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Tuple

from . import protocols
from .packet import Endpoints, bytes_to_mac, mac_to_bytes, rewrite_l2

# Vendor OUIs — an analyser also fingerprints assets by MAC prefix.
OUI_WIN = "00:50:56"        # VMware-hosted Windows/Linux
OUI_ROCKWELL = "00:1d:9c"   # Rockwell Automation / Allen-Bradley
OUI_SIEMENS = "00:0e:8c"    # Siemens
OUI_DELL = "00:06:5b"       # Dell — physical workstations
OUI_SCHNEIDER = "00:80:f4"  # Telemecanique / Schneider Electric (Modicon)
OUI_JCI = "00:10:8d"        # Johnson Controls (Metasys BMS)
OUI_TRIDIUM = "00:01:f0"    # Tridium (Niagara JACE)
OUI_SEL = "00:30:a7"        # Schweitzer Engineering Laboratories

OUI_VENDORS: Dict[str, str] = {
    OUI_WIN: "VMware", OUI_ROCKWELL: "Rockwell Automation",
    OUI_SIEMENS: "Siemens", OUI_DELL: "Dell", OUI_SCHNEIDER: "Schneider Electric",
    OUI_JCI: "Johnson Controls", OUI_TRIDIUM: "Tridium",
    OUI_SEL: "Schweitzer Engineering Laboratories",
}


@dataclass
class OSFingerprint:
    key: str
    label: str
    ttl: int
    ua: str = ""
    smb: str = "smb2"          # "smb1" (legacy, MS17-010) or "smb2"
    dhcp_vendor: str = "MSFT 5.0"
    legacy: bool = False
    risk: str = ""             # human note on why it's flagged


FINGERPRINTS: Dict[str, OSFingerprint] = {
    "win2019": OSFingerprint("win2019", "Windows Server 2019", 128,
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120", "smb2"),
    "win10": OSFingerprint("win10", "Windows 10", 128,
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/120", "smb2"),
    "linux": OSFingerprint("linux", "Linux (Ubuntu)", 64,
        "Mozilla/5.0 (X11; Linux x86_64; rv:120) Firefox/120", "smb2",
        dhcp_vendor="Linux dhclient"),
    "win7": OSFingerprint("win7", "Windows 7", 128,
        "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)", "smb1",
        legacy=True, risk="EOL; SMBv1 enabled → MS17-010 (EternalBlue)"),
    "winxp": OSFingerprint("winxp", "Windows XP", 128,
        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)", "smb1",
        legacy=True, risk="EOL 2014; SMBv1 → MS17-010, unsupported TLS"),
    "win2000": OSFingerprint("win2000", "Windows 2000", 128,
        "Mozilla/4.0 (compatible; MSIE 5.0; Windows NT 5.0)", "smb1",
        legacy=True, risk="EOL 2010; SMBv1 → MS08-067 / MS17-010"),
    "win2012": OSFingerprint("win2012", "Windows Server 2012 R2", 128,
        "Mozilla/5.0 (Windows NT 6.3; Win64; x64) Trident/7.0", "smb2",
        legacy=True, risk="EOL Oct 2023; no security updates"),
    "rockwell": OSFingerprint("rockwell", "Rockwell Automation firmware", 64,
        smb="none", dhcp_vendor="", legacy=False,
        risk="OT asset — patch cadence slow; expose CIP/ENIP"),
    "siemens": OSFingerprint("siemens", "Siemens SIMATIC firmware", 30,
        smb="none", dhcp_vendor="", legacy=False,
        risk="OT asset — S7comm (legacy families) / IEC-104 unauthenticated"),
    "schneider": OSFingerprint("schneider", "Schneider Electric firmware", 64,
        smb="none", dhcp_vendor="",
        risk="OT asset — Modbus/TCP has no authentication"),
    "bacnet": OSFingerprint("bacnet", "BACnet controller firmware", 64,
        smb="none", dhcp_vendor="",
        risk="BMS asset — BACnet/IP unauthenticated; common pivot into OT"),
    "sel": OSFingerprint("sel", "SEL device firmware", 64,
        smb="none", dhcp_vendor="",
        risk="Electrical asset — DNP3 without Secure Authentication"),
}


@dataclass
class Host:
    name: str
    ip: str
    mac: str
    role: str          # dc, dns, file, web, mail, db, proxy, ws, plc, hmi, hist, eng, …
    os: str            # fingerprint key
    vendor: str = ""
    product: str = ""  # OT: model / order number

    @property
    def fp(self) -> OSFingerprint:
        return FINGERPRINTS[self.os]


@dataclass(frozen=True)
class Segment:
    """One L2 broadcast domain: a VLAN carrying one IPv4 subnet.

    ``gateway`` is the segment's SVI on the core L3 switch. Its MAC is the HSRP
    virtual MAC for group = VLAN (0000.0c07.acXX), which is what hosts ARP for.
    """
    name: str
    vlan: int
    subnet: str        # CIDR, e.g. "10.20.10.0/24"
    zone: str          # IT | DMZ (L3.5) | OT-SUPERVISORY (L3) | OT-CELL (L1-2)
    gateway: str       # default-gateway IP

    @property
    def gateway_mac(self) -> str:
        return f"00:00:0c:07:ac:{self.vlan & 0xFF:02x}"

    def contains(self, ip: str) -> bool:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(self.subnet)


SPAN_VIEWS = ("access", "core")


# A conversation: client drives `proto` toward server.
Conversation = Tuple[str, str, str]   # (client_name, server_name, proto_key)


def _mac(oui: str, n: int) -> str:
    return f"{oui}:{(n >> 16) & 0xFF:02x}:{(n >> 8) & 0xFF:02x}:{n & 0xFF:02x}"


# ---------------------------------------------------------------------------
# IT organization: 11 servers + 12 users
# ---------------------------------------------------------------------------
def _it_hosts() -> List[Host]:
    h: List[Host] = []
    srv = [
        ("DC01", "dc", "win2019"), ("DC02", "dc", "win2019"),
        ("DNS01", "dns", "win2019"), ("FILE01", "file", "win2019"),
        ("SQL01", "db", "win2019"), ("APP01", "web", "win2019"),
        ("WEB01", "web", "linux"), ("MAIL01", "mail", "linux"),
        ("PROXY01", "proxy", "linux"), ("BACKUP01", "file", "linux"),
        ("FS-LEGACY", "file", "win2000"),   # legacy file server (vulnerable)
    ]
    for i, (name, role, os_) in enumerate(srv, start=10):
        h.append(Host(name, f"10.20.10.{i}", _mac(OUI_WIN, 0x100 + i), role, os_))
    # 12 users: mostly Win10, plus legacy Win7 and WinXP
    user_os = ["win10"] * 9 + ["win7", "winxp", "win10"]
    for i, os_ in enumerate(user_os, start=20):
        h.append(Host(f"WS{i:02d}", f"10.20.20.{i}", _mac(OUI_WIN, 0x200 + i),
                      "ws", os_))
    return h


def _it_segments() -> List[Segment]:
    return [
        Segment("IT-SERVERS", 10, "10.20.10.0/24", "IT", "10.20.10.1"),
        Segment("IT-USERS", 20, "10.20.20.0/24", "IT", "10.20.20.1"),
    ]


def _office_conversations(users: List[str], dc: str, dns: str, file: str,
                          proxy: str, app: str) -> List[Conversation]:
    """The daily chatter of a domain-joined Windows user."""
    conv: List[Conversation] = []
    for u in users:
        conv += [
            (u, dns, "dhcp"),          # address + fingerprint
            (u, u, "netbios"),         # self-announce (broadcast)
            (u, dns, "dns"),
            (u, dc, "kerberos"),
            (u, dc, "ldap"),
            (u, file, "smb"),          # SMBv1 vs SMB2 depends on the user OS
            (u, proxy, "http"),        # browsing
            (u, app, "https"),         # encrypted app
            (u, dc, "ntp"),
        ]
    return conv


def _it_conversations(hosts: List[Host]) -> List[Conversation]:
    by = {x.name: x for x in hosts}
    users = [x.name for x in hosts if x.role == "ws"]
    conv = _office_conversations(users, "DC01", "DNS01", "FILE01", "PROXY01",
                                 "APP01")
    # server-to-server
    conv += [
        ("DC01", "DC02", "ldap"), ("DC02", "DC01", "kerberos"),
        ("WEB01", "SQL01", "https"), ("MAIL01", "DC01", "ldap"),
        ("BACKUP01", "FILE01", "smb"), ("FS-LEGACY", "DC01", "smb"),
    ]
    return [c for c in conv if c[0] in by and c[1] in by]


# ---------------------------------------------------------------------------
# OT plant: Rockwell + Siemens networks, PLCs, HMIs, legacy stations
# ---------------------------------------------------------------------------
def _ot_hosts() -> List[Host]:
    h: List[Host] = []
    # Supervisory / IT-in-OT (172.16.0.0/24)
    h += [
        Host("HISTORIAN", "172.16.0.10", _mac(OUI_WIN, 0x300), "hist", "win2019"),
        Host("SCADA01", "172.16.0.11", _mac(OUI_WIN, 0x301), "web", "win10"),
        Host("ENGWS01", "172.16.0.20", _mac(OUI_WIN, 0x302), "eng", "win7"),
        Host("HMI-XP", "172.16.0.30", _mac(OUI_WIN, 0x303), "hmi", "winxp"),
        Host("HMI-2000", "172.16.0.31", _mac(OUI_WIN, 0x304), "hmi", "win2000"),
    ]
    # Rockwell cell (172.16.1.0/24)
    h += [
        Host("HMI-RW", "172.16.1.10", _mac(OUI_WIN, 0x310), "hmi", "win10"),
        Host("PLC-RW1", "172.16.1.21", _mac(OUI_ROCKWELL, 0x21), "plc",
             "rockwell", "Rockwell", "1756-L71/B LOGIX5571"),
        Host("PLC-RW2", "172.16.1.22", _mac(OUI_ROCKWELL, 0x22), "plc",
             "rockwell", "Rockwell", "1769-L36ERM CompactLogix"),
    ]
    # Siemens cell (172.16.2.0/24)
    h += [
        Host("HMI-S7", "172.16.2.10", _mac(OUI_WIN, 0x320), "hmi", "win7"),
        Host("PLC-S7-1", "172.16.2.21", _mac(OUI_SIEMENS, 0x21), "plc",
             "siemens", "Siemens", "6ES7 315-2EH14-0AB0"),
        Host("PLC-S7-2", "172.16.2.22", _mac(OUI_SIEMENS, 0x22), "plc",
             "siemens", "Siemens", "6ES7 151-8AB01-0AB0"),
    ]
    return h


def _ot_segments() -> List[Segment]:
    return [
        Segment("OT-SUPERVISORY", 100, "172.16.0.0/24", "OT-SUPERVISORY",
                "172.16.0.1"),
        Segment("OT-CELL-RW", 110, "172.16.1.0/24", "OT-CELL", "172.16.1.1"),
        Segment("OT-CELL-S7", 120, "172.16.2.0/24", "OT-CELL", "172.16.2.1"),
    ]


def _ot_conversations(hosts: List[Host]) -> List[Conversation]:
    by = {x.name: x for x in hosts}
    conv: List[Conversation] = [
        # Rockwell HMI polls PLCs; engineering + identity
        ("HMI-RW", "PLC-RW1", "enip"), ("HMI-RW", "PLC-RW2", "enip"),
        ("HMI-RW", "PLC-RW1", "modbus"),
        ("ENGWS01", "PLC-RW1", "enip-id"), ("ENGWS01", "PLC-RW2", "enip-id"),
        # Siemens HMI polls PLCs; engineering + identity
        ("HMI-S7", "PLC-S7-1", "s7comm"), ("HMI-S7", "PLC-S7-2", "s7comm"),
        ("ENGWS01", "PLC-S7-1", "s7-id"), ("ENGWS01", "PLC-S7-2", "s7-id"),
        # Historian collects from everything
        ("HISTORIAN", "PLC-RW1", "modbus"), ("HISTORIAN", "PLC-S7-1", "s7comm"),
        ("HISTORIAN", "SCADA01", "opcua"),
        # Legacy Windows HMIs — fingerprint + vulnerable services
        ("HMI-XP", "HISTORIAN", "smb"), ("HMI-XP", "SCADA01", "http"),
        ("HMI-XP", "HISTORIAN", "netbios"),
        ("HMI-2000", "HISTORIAN", "smb"), ("HMI-2000", "SCADA01", "http"),
        # supervisory IT chatter
        ("SCADA01", "HISTORIAN", "https"), ("ENGWS01", "HISTORIAN", "dns"),
    ]
    return [c for c in conv if c[0] in by and c[1] in by]


# ---------------------------------------------------------------------------
# Environment object + build
# ---------------------------------------------------------------------------
@dataclass
class Environment:
    key: str
    name: str
    category: str      # IT | OT | mixed
    desc: str
    hosts: List[Host]
    conversations: List[Conversation]
    segments: List[Segment]

    def __post_init__(self) -> None:
        vlans = [s.vlan for s in self.segments]
        if len(set(vlans)) != len(vlans):
            raise ValueError(f"{self.key}: duplicate VLAN in {vlans}")
        for s in self.segments:
            if not s.contains(s.gateway):
                raise ValueError(f"{self.key}: gateway {s.gateway} outside "
                                 f"{s.name} {s.subnet}")
        self._seg: Dict[str, Segment] = {}
        for h in self.hosts:
            hit = [s for s in self.segments if s.contains(h.ip)]
            if len(hit) != 1:
                raise ValueError(f"{self.key}: host {h.name} ({h.ip}) is in "
                                 f"{len(hit)} segments, expected 1")
            self._seg[h.name] = hit[0]
        for c, sv, proto in self.conversations:
            if (protocols.get(proto).transport == "l2"
                    and self._seg[c] is not self._seg[sv]):
                raise ValueError(f"{self.key}: {proto} is L2-only but "
                                 f"{c} -> {sv} crosses segments")

    def host(self, name: str) -> Host:
        return next(h for h in self.hosts if h.name == name)

    def segment_of(self, host: Host) -> Segment:
        return self._seg[host.name]

    def _endpoints(self, client: Host, server: Host) -> Endpoints:
        meta = {
            "ua": client.fp.ua,
            "smb": client.fp.smb if client.fp.smb != "none" else "smb2",
            "dhcp_vendor": client.fp.dhcp_vendor or "MSFT 5.0",
            "nbname": client.name,
            "host": server.name,
            "sni": f"{server.name.lower()}.corp.local",
            "realm": "CORP.LOCAL",
            "dn": f"CN={client.name},DC=corp,DC=local",
            "product": server.product or "1756-L71/B LOGIX5571",
            "device_type": 0x02 if server.role == "drive" else 0x0E,  # CIP
            "order": server.product or "6ES7 315-2EH14-0AB0",
            "server": "Microsoft-IIS/10.0" if server.os.startswith("win") else "Apache",
        }
        # Built untagged, host to host; _place() puts each frame on its VLAN.
        return Endpoints(
            client_mac=client.mac, client_ip=client.ip,
            server_mac=server.mac, server_ip=server.ip,
            ttl_client=client.fp.ttl, ttl_server=server.fp.ttl, meta=meta)

    def _place(self, frame: bytes, client: Host, server: Host,
               span: str) -> List[bytes]:
        return self.place(frame, client, server, span, self.segment_of)

    def place(self, frame: bytes, client: Host, server: Host, span: str,
              seg_of) -> List[bytes]:
        """A host-built frame as it appears on the trunk (one or two copies).

        ``seg_of(host)`` gives the host's :class:`Segment`, or ``None`` when the
        host is foreign to this environment (e.g. an external C2/attacker a
        sprinkle injected). Same internal segment: switched, tagged with the
        segment VLAN. Cross internal segments: the sender addresses its gateway
        on its own VLAN and, in the ``core`` view, the router's egress copy
        follows on the receiver's VLAN with TTL-1. When exactly one side is
        foreign the frame is tagged with the internal host's VLAN and reaches
        it via that segment's gateway MAC; when both are foreign it is left
        untouched.
        """
        from_client = frame[6:12] == mac_to_bytes(client.mac)
        src, dst = (client, server) if from_client else (server, client)
        sseg, dseg = seg_of(src), seg_of(dst)
        if sseg is None and dseg is None:
            return [frame]
        if sseg is dseg:
            return [rewrite_l2(frame, bytes_to_mac(frame[6:12]),
                               bytes_to_mac(frame[0:6]), sseg.vlan)]
        if sseg is None or dseg is None:            # one side foreign
            iseg = sseg or dseg
            if sseg is None:                        # foreign -> internal dst
                return [rewrite_l2(frame, iseg.gateway_mac,
                                   bytes_to_mac(frame[0:6]), iseg.vlan)]
            return [rewrite_l2(frame, bytes_to_mac(frame[6:12]),
                               iseg.gateway_mac, iseg.vlan)]
        out = [rewrite_l2(frame, src.mac, sseg.gateway_mac, sseg.vlan)]
        if span == "core":
            out.append(rewrite_l2(frame, dseg.gateway_mac, dst.mac, dseg.vlan,
                                  ttl=frame[14 + 8] - 1))
        return out

    def segment_or_none(self, host: Host):
        """Like :meth:`segment_of`, but ``None`` for a host not in this env."""
        return self._seg.get(host.name)

    def build(self, messages: int,
              span: str = "access") -> List[Tuple[str, bytes]]:
        """One cycle: interleave every modeled conversation once.

        ``span`` is the capture point: ``access`` (each frame once, on its
        sender's VLAN) or ``core`` (routed frames also on the receiver's VLAN).
        """
        if span not in SPAN_VIEWS:
            raise ValueError(f"unknown span view {span!r}; use {SPAN_VIEWS}")
        # each stream item is the group of copies one host frame produces;
        # a group stays contiguous so ingress/egress hops sit side by side
        streams: List[List[Tuple[str, List[bytes]]]] = []
        for cname, sname, proto in self.conversations:
            client, server = self.host(cname), self.host(sname)
            ep = self._endpoints(client, server)
            frames = protocols.get(proto).build(ep, max(1, messages))
            streams.append([(proto, self._place(f, client, server, span))
                            for f in frames])
        out: List[Tuple[str, bytes]] = []
        i = 0
        while any(i < len(s) for s in streams):
            for s in streams:
                if i < len(s):
                    proto, group = s[i]
                    out.extend((proto, g) for g in group)
            i += 1
        return out

    def protocols(self) -> List[str]:
        """Protocols this environment's conversations use, in registry order."""
        used = {proto for _, _, proto in self.conversations}
        return [k for k in protocols.PROFILES if k in used]

    def legacy_hosts(self) -> List[Host]:
        return [h for h in self.hosts if h.fp.legacy]

    def summary(self) -> str:
        cats: Dict[str, int] = {}
        for h in self.hosts:
            cats[h.role] = cats.get(h.role, 0) + 1
        roles = ", ".join(f"{v} {k}" for k, v in sorted(cats.items()))
        leg = len(self.legacy_hosts())
        return (f"{len(self.hosts)} hosts ({roles}); "
                f"{len(self.segments)} segments; "
                f"{len(self.conversations)} conversations; {leg} legacy/at-risk")


def _mixed_hosts() -> List[Host]:
    return _it_hosts() + _ot_hosts()


def _mixed_segments() -> List[Segment]:
    return _it_segments() + _ot_segments()


def _mixed_conversations(hosts: List[Host]) -> List[Conversation]:
    return _it_conversations(hosts) + _ot_conversations(hosts)


# ---------------------------------------------------------------------------
# Industrial site: a large Purdue-model plant, corporate IT down to cells
# ---------------------------------------------------------------------------
def _site_segments() -> List[Segment]:
    return [
        Segment("CORP-SERVERS", 10, "10.10.10.0/24", "IT", "10.10.10.1"),
        Segment("CORP-USERS", 20, "10.10.20.0/24", "IT", "10.10.20.1"),
        Segment("IT-OT-DMZ", 50, "10.10.50.0/24", "DMZ", "10.10.50.1"),
        Segment("OT-OPS", 100, "10.100.0.0/24", "OT-SUPERVISORY",
                "10.100.0.1"),
        Segment("AREA-PACKAGING", 110, "10.100.10.0/24", "OT-CELL",
                "10.100.10.1"),
        Segment("AREA-PROCESS", 120, "10.100.20.0/24", "OT-CELL",
                "10.100.20.1"),
        Segment("AREA-UTILITIES", 130, "10.100.30.0/24", "OT-CELL",
                "10.100.30.1"),
        Segment("BMS", 140, "10.100.40.0/24", "OT-CELL", "10.100.40.1"),
        Segment("SUBSTATION", 150, "10.100.50.0/24", "OT-CELL",
                "10.100.50.1"),
    ]


def _site_hosts() -> List[Host]:
    h: List[Host] = []

    def add(name, ip, oui, n, role, os_, vendor="", product=""):
        h.append(Host(name, ip, _mac(oui, n), role, os_, vendor, product))

    # L4 corporate servers (virtualised) + 30 office users
    for i, (name, role, os_) in enumerate([
            ("DC01", "dc", "win2019"), ("DC02", "dc", "win2019"),
            ("DNS01", "dns", "win2019"), ("FILE01", "file", "win2019"),
            ("ERP01", "db", "win2019"), ("MAIL01", "mail", "linux"),
            ("WEB01", "web", "linux"), ("PROXY01", "proxy", "linux")],
            start=10):
        add(name, f"10.10.10.{i}", OUI_WIN, 0x1000 + i, role, os_)
    user_os = ["win10"] * 26 + ["win7", "win7", "winxp", "win10"]
    for i, os_ in enumerate(user_os, start=20):
        add(f"WS{i:02d}", f"10.10.20.{i}", OUI_DELL, 0x2000 + i, "ws", os_)
    # a contractor laptop that talks straight to the plant floor (see below)
    add("WS-CONTRACTOR", "10.10.20.99", OUI_DELL, 0x2099, "ws", "win10")

    # L3.5 IT/OT DMZ — the only sanctioned path between IT and OT
    add("JUMP01", "10.10.50.10", OUI_WIN, 0x5010, "jump", "win2019")
    add("HIST-DMZ", "10.10.50.11", OUI_WIN, 0x5011, "hist", "win2019")
    add("WSUS01", "10.10.50.12", OUI_WIN, 0x5012, "patch", "win2019")
    add("AV01", "10.10.50.13", OUI_WIN, 0x5013, "av", "win2019")

    # L3 site operations
    add("OT-DC01", "10.100.0.10", OUI_WIN, 0x6010, "dc", "win2012")
    add("HIST01", "10.100.0.11", OUI_WIN, 0x6011, "hist", "win2019")
    add("SCADA01", "10.100.0.12", OUI_WIN, 0x6012, "scada", "win2019")
    add("SCADA02", "10.100.0.13", OUI_WIN, 0x6013, "scada", "win2019")
    add("OPCUA01", "10.100.0.14", OUI_WIN, 0x6014, "opc", "win2019")
    add("BMS-SUP", "10.100.0.15", OUI_WIN, 0x6015, "bms", "linux")
    add("OT-NTP", "10.100.0.16", OUI_WIN, 0x6016, "ntp", "linux")
    add("ENG01", "10.100.0.20", OUI_DELL, 0x6020, "eng", "win10")
    add("ENG02", "10.100.0.21", OUI_DELL, 0x6021, "eng", "win7")

    # Packaging area — Rockwell lines: HMIs, Logix PLCs, PowerFlex drives
    add("HMI-PK1", "10.100.10.10", OUI_DELL, 0x7010, "hmi", "win10")
    add("HMI-PK2", "10.100.10.11", OUI_DELL, 0x7011, "hmi", "win7")
    for i, prod in enumerate(["1756-L83E ControlLogix 5580",
                              "1756-L71/B LOGIX5571",
                              "1769-L36ERM CompactLogix",
                              "5069-L320ER CompactLogix 5380"], start=1):
        add(f"PLC-PK{i}", f"10.100.10.{20 + i}", OUI_ROCKWELL, 0x7020 + i,
            "plc", "rockwell", "Rockwell", prod)
    for i in range(1, 7):
        add(f"DRV-PK{i}", f"10.100.10.{40 + i}", OUI_ROCKWELL, 0x7040 + i,
            "drive", "rockwell", "Rockwell", "PowerFlex 755")

    # Process area — Siemens S7 cells
    add("HMI-PR1", "10.100.20.10", OUI_DELL, 0x8010, "hmi", "win10")
    add("HMI-PR2", "10.100.20.11", OUI_DELL, 0x8011, "hmi", "win7")
    for i, prod in enumerate(["6ES7 516-3AN01-0AB0", "6ES7 317-2EK14-0AB0",
                              "6ES7 315-2EH14-0AB0", "6ES7 151-8AB01-0AB0",
                              "6ES7 315-2EH14-0AB0", "6ES7 516-3AN01-0AB0"],
                             start=1):
        add(f"PLC-PR{i}", f"10.100.20.{20 + i}", OUI_SIEMENS, 0x8020 + i,
            "plc", "siemens", "Siemens", prod)

    # Utilities — Schneider Modicon PLCs + Modbus power meters
    add("HMI-UT1", "10.100.30.10", OUI_DELL, 0x9010, "hmi", "winxp")
    for i, prod in enumerate(["BMX P34 2020 Modicon M340",
                              "BME P58 2040 Modicon M580",
                              "BMX P34 2020 Modicon M340"], start=1):
        add(f"PLC-UT{i}", f"10.100.30.{20 + i}", OUI_SCHNEIDER, 0x9020 + i,
            "plc", "schneider", "Schneider Electric", prod)
    for i in range(1, 7):
        add(f"METER-UT{i}", f"10.100.30.{40 + i}", OUI_SCHNEIDER,
            0x9040 + i, "meter", "schneider", "Schneider Electric",
            "PowerLogic PM5560")

    # Building management — Niagara JACE polling Metasys BACnet controllers
    add("BMS-JACE", "10.100.40.10", OUI_TRIDIUM, 0xA010, "bms", "linux",
        "Tridium", "JACE-8000")
    for i in range(1, 9):
        add(f"BAC-AHU{i}", f"10.100.40.{20 + i}", OUI_JCI, 0xA020 + i,
            "bms", "bacnet", "Johnson Controls", "Metasys FEC2611")

    # Substation — SEL RTAC concentrating protection relays
    add("RTAC01", "10.100.50.10", OUI_SEL, 0xB010, "rtu", "sel", "SEL",
        "SEL-3530 RTAC")
    for i, prod in enumerate(["SEL-751", "SEL-751", "SEL-487E", "SEL-351S"],
                             start=1):
        add(f"RELAY{i}", f"10.100.50.{20 + i}", OUI_SEL, 0xB020 + i,
            "relay", "sel", "SEL", prod)
    add("RTU-104", "10.100.50.30", OUI_SIEMENS, 0xB030, "rtu", "siemens",
        "Siemens", "SICAM A8000 CP-8050")
    return h


def _site_conversations(hosts: List[Host]) -> List[Conversation]:
    by = {x.name: x for x in hosts}

    def named(prefix):
        return [x.name for x in hosts if x.name.startswith(prefix)]

    users = [x.name for x in hosts if x.role == "ws"]
    conv = _office_conversations(users, "DC01", "DNS01", "FILE01", "PROXY01",
                                 "ERP01")
    conv += [
        ("DC01", "DC02", "ldap"), ("DC02", "DC01", "kerberos"),
        ("WEB01", "ERP01", "https"), ("MAIL01", "DC01", "ldap"),
        # IT <-> DMZ: business users read the replica, admins hop in
        ("WS20", "HIST-DMZ", "https"), ("WS21", "HIST-DMZ", "https"),
        ("WS22", "JUMP01", "https"), ("JUMP01", "DC01", "kerberos"),
        ("WSUS01", "PROXY01", "http"), ("AV01", "PROXY01", "https"),
        # DMZ <-> L3: historian replication, remote access, patches, AV
        ("HIST01", "HIST-DMZ", "https"), ("JUMP01", "ENG01", "https"),
        ("JUMP01", "ENG02", "smb"),
        ("SCADA01", "WSUS01", "http"), ("HIST01", "WSUS01", "http"),
        ("ENG01", "AV01", "https"), ("ENG02", "AV01", "https"),
    ]
    # L3: OT domain, DNS and time
    for x in ("HIST01", "SCADA01", "SCADA02", "OPCUA01", "ENG01", "ENG02",
              "HMI-PK1", "HMI-PK2", "HMI-PR1", "HMI-PR2", "HMI-UT1"):
        conv += [(x, "OT-DC01", "kerberos"), (x, "OT-DC01", "dns")]
    for x in named("PLC-") + ["RTAC01", "BMS-JACE"]:
        conv.append((x, "OT-NTP", "ntp"))
    conv += [
        ("SCADA01", "HIST01", "opcua"), ("SCADA02", "HIST01", "opcua"),
        ("HIST01", "OPCUA01", "opcua"), ("BMS-SUP", "BMS-JACE", "https"),
        ("ENG02", "HIST01", "smb"), ("HMI-UT1", "HIST01", "smb"),
        ("HMI-UT1", "SCADA01", "http"),
    ]
    # Packaging: HMIs poll their line's PLCs, PLCs drive the PowerFlexes
    for i, plc in enumerate(named("PLC-PK")):
        conv.append((("HMI-PK1", "HMI-PK2")[i % 2], plc, "enip"))
        conv.append(("HIST01", plc, "enip"))
        conv.append(("ENG01", plc, "enip-id"))
    for i, drv in enumerate(named("DRV-PK")):
        conv.append((f"PLC-PK{i % 4 + 1}", drv, "enip"))
        conv.append(("ENG01", drv, "enip-id"))
    conv.append(("SCADA01", "PLC-PK1", "icmp"))
    # Process: Siemens HMIs, historian and engineering
    for i, plc in enumerate(named("PLC-PR")):
        conv.append((("HMI-PR1", "HMI-PR2")[i % 2], plc, "s7comm"))
        conv.append(("HIST01", plc, "s7comm"))
        conv.append(("ENG02", plc, "s7-id"))
    conv.append(("SCADA01", "PLC-PR1", "icmp"))
    # Utilities: HMI + historian over Modbus/TCP
    for plc in named("PLC-UT"):
        conv += [("HMI-UT1", plc, "modbus"), ("HIST01", plc, "modbus")]
    for m in named("METER-UT"):
        conv.append(("HIST01", m, "modbus"))
    # BMS: JACE polls the controllers, SCADA reads a few points
    for ahu in named("BAC-AHU"):
        conv.append(("BMS-JACE", ahu, "bacnet"))
    conv += [("SCADA02", "BAC-AHU1", "bacnet"), ("BMS-JACE", "BAC-AHU1", "arp")]
    # Substation: RTAC polls relays locally; SCADA polls RTAC + IEC-104 RTU
    for r in named("RELAY"):
        conv.append(("RTAC01", r, "dnp3"))
    conv += [("SCADA02", "RTAC01", "dnp3"), ("SCADA02", "RTU-104", "iec104"),
             ("HIST01", "RTAC01", "dnp3"), ("RTAC01", "RELAY1", "arp")]
    # Policy violation an analyser should flag: an IT laptop polling a
    # utilities meter directly (L4 -> L1), bypassing the DMZ.
    conv.append(("WS-CONTRACTOR", "METER-UT1", "modbus"))
    return [c for c in conv if c[0] in by and c[1] in by]


ENVIRONMENTS: Dict[str, Environment] = {}


def _reg_env(key, name, category, desc, hosts_fn, conv_fn, seg_fn):
    hosts = hosts_fn()
    ENVIRONMENTS[key] = Environment(key, name, category, desc, hosts,
                                    conv_fn(hosts), seg_fn())


_reg_env("it-org", "IT Organization", "IT",
         "Enterprise IT: DC/DNS/file/web/mail servers + 12 users with DHCP, "
         "Kerberos, LDAP, SMB, HTTP/HTTPS and OS-fingerprint chatter "
         "(incl. a legacy Windows 2000 file server, Win7 and WinXP users).",
         _it_hosts, _it_conversations, _it_segments)
_reg_env("ot-plant", "OT Plant", "OT",
         "Rockwell + Siemens cells: ControlLogix/CompactLogix over EtherNet/IP, "
         "S7-300/1500 over S7comm, HMIs, historian, engineering WS, and legacy "
         "Windows XP/2000 HMIs with vendor-identity and fingerprint traffic.",
         _ot_hosts, _ot_conversations, _ot_segments)
_reg_env("enterprise-mixed", "Mixed IT + OT Site", "mixed",
         "The full site: the IT organization and the OT plant together — the "
         "realistic converged network an analyser sees at an industrial site.",
         _mixed_hosts, _mixed_conversations, _mixed_segments)
_reg_env("industrial-site", "Industrial Site", "mixed",
         "A large Purdue-model plant: corporate IT, an IT/OT DMZ, L3 site "
         "operations, Rockwell packaging, Siemens process, Schneider "
         "utilities, a BACnet BMS and an SEL/DNP3 substation, across 9 "
         "VLANs, plus one IT laptop talking straight to the plant floor.",
         _site_hosts, _site_conversations, _site_segments)


def get(key: str) -> Environment:
    return ENVIRONMENTS[key]


def all_environments() -> List[Environment]:
    return list(ENVIRONMENTS.values())
