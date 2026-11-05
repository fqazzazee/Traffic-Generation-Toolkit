"""Remap a captured pcap's hosts onto a TGT environment by role.

``tgt run --replay FILE --remap-env ENV`` puts a customer capture on the wire
as if it came from the modeled environment ``ENV``: each internal host of
the capture is matched to an environment host of a compatible role (and,
where possible, the same vendor), and every frame is re-addressed to it —
IPv4 address, MAC, and the 802.1Q tag of the environment segment the host
sits on. External (public) hosts keep their addresses. The mapping is
printed, written with ``--remap-report F.json`` and recorded in the run
manifest, so ``tgt score`` grades a monitor against the hosts the replay
really showed.

How it works:

1. **Profile** (one streamed pass over the file, :func:`profile`): per
   internal address (RFC 1918 / CGNAT / link-local, IPv6 ULA / link-local)
   the TCP/UDP ports it serves (SYN-ACK, else the well-known side) and uses,
   its own MAC (ARP, else the most common source MAC that is not a router's
   — a MAC that sources an external or 3+ internal addresses is a router),
   the vendor of that MAC's OUI, its initial TTL / hop limit and the L2
   protocols it sends (GOOSE, SV, PROFINET, LLDP...). A small passive
   classifier turns that into a role (``plc``, ``rtu``, ``relay``, ``hmi``,
   ``dc``, ``ws``, ``switch``…) and a class (field / supervisory /
   it-server / it-client / network).
2. **Assign** (:func:`assign`): hosts with the most specific evidence first,
   each to the best-scoring free environment host of a compatible class.
   An OT service the capture host serves must be one the environment host
   serves (its conversations, or its product family — the same capability
   notion as ``tgt.incidents``); exact role, role family
   (``incidents._role_tier``), vendor, served/used ports and TTL family add
   to the score. Ties are broken by a seeded shuffle (``--seed``, default
   0), so the same capture, environment and seed always map the same way.
3. **Place** (:class:`EnvRewriter`): like the generator's own placement
   (``Environment.place``) — same segment: switched, tagged with the
   segment VLAN; across segments: sender's VLAN to its gateway MAC, and in
   the ``--span core`` view also the routed copy on the receiver's VLAN
   (hop count - 1); one side external or unmapped: through the internal
   side's gateway; broadcasts / multicasts / non-IP frames stay on the
   sender's VLAN. Frames between two unmapped/external hosts pass as
   captured.

Unmappable hosts — no compatible environment host left, a router, an
IPv6-only host (the environments have no IPv6 addressing), a host that
never sends — keep their identity and are listed. IPv6 addresses whose
interface id is the EUI-64 of a remapped MAC (link-local / SLAAC) follow the
new MAC; other IPv6 addresses are kept.
"""
from __future__ import annotations

import ipaddress
import json
import os
import random
import struct
import threading
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

from . import packet as P
from . import pcapread
from .rewrite import ETH_P_IPV6, Rewriter, RewriteError, _V6_EXT, _VLAN_TPIDS

SCHEMA = "tgt-remap/1"

_INTERNAL = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
    "169.254.0.0/16", "fc00::/7", "fe80::/10")]

Port = Tuple[str, int]          # ("tcp", 502)

# Well-known service ports -> service (TGT protocol key where there is one).
SERVICES: Dict[Port, str] = {
    ("tcp", 502): "modbus", ("tcp", 102): "s7comm", ("tcp", 44818): "enip",
    ("udp", 44818): "enip", ("udp", 2222): "enip-io", ("tcp", 20000): "dnp3",
    ("udp", 20000): "dnp3", ("tcp", 2404): "iec104", ("udp", 47808): "bacnet",
    ("tcp", 4840): "opcua", ("tcp", 1911): "fox", ("tcp", 4911): "fox",
    ("tcp", 9600): "fins", ("udp", 9600): "fins", ("tcp", 5007): "slmp",
    ("udp", 5007): "slmp", ("tcp", 5094): "hart-ip", ("udp", 5094): "hart-ip",
    ("tcp", 18245): "srtp", ("udp", 34964): "profinet", ("udp", 3671): "knxip",
    ("tcp", 1883): "mqtt", ("tcp", 8883): "mqtt", ("tcp", 104): "dicom",
    ("tcp", 2575): "hl7",
    ("tcp", 88): "kerberos", ("udp", 88): "kerberos", ("tcp", 389): "ldap",
    ("udp", 389): "ldap", ("tcp", 636): "ldap", ("tcp", 3268): "ldap",
    ("udp", 53): "dns", ("tcp", 53): "dns", ("tcp", 445): "smb",
    ("tcp", 139): "smb", ("udp", 137): "netbios", ("udp", 138): "netbios",
    ("tcp", 80): "http", ("tcp", 8080): "http", ("tcp", 443): "https",
    ("tcp", 8443): "https", ("tcp", 25): "smtp", ("tcp", 587): "smtp",
    ("tcp", 143): "imap", ("tcp", 993): "imap", ("tcp", 110): "pop3",
    ("tcp", 1433): "sql", ("tcp", 3306): "sql", ("tcp", 5432): "sql",
    ("tcp", 1521): "sql", ("tcp", 3128): "proxy", ("tcp", 3389): "rdp",
    ("tcp", 22): "ssh", ("tcp", 23): "telnet", ("tcp", 5900): "vnc",
    ("udp", 161): "snmp", ("udp", 162): "snmp-trap", ("udp", 514): "syslog",
    ("udp", 123): "ntp", ("udp", 67): "dhcp", ("tcp", 21): "ftp",
    ("udp", 69): "tftp", ("udp", 319): "ptp", ("udp", 320): "ptp",
}
# OT control services: an environment host must really serve them
OT_SERVICES = {"modbus", "s7comm", "enip", "enip-io", "dnp3", "iec104",
               "bacnet", "opcua", "fox", "fins", "slmp", "hart-ip", "srtp",
               "profinet", "knxip", "dicom", "hl7"}
# role of a server by the OT service it serves (first hit wins)
_OT_ROLE = [("iec104", "rtu"), ("dnp3", "rtu"), ("s7comm", "plc"),
            ("enip", "plc"), ("enip-io", "plc"), ("modbus", "plc"),
            ("fins", "plc"), ("slmp", "plc"), ("srtp", "plc"),
            ("profinet", "plc"), ("hart-ip", "plc"), ("bacnet", "bms"),
            ("fox", "bms"), ("knxip", "bms"), ("dicom", "modality"),
            ("hl7", "hl7-engine"), ("opcua", "opc")]
_IT_ROLE = [("kerberos", "dc"), ("ldap", "dc"), ("sql", "db"),
            ("smtp", "mail"), ("imap", "mail"), ("pop3", "mail"),
            ("proxy", "proxy"), ("dns", "dns"), ("http", "web"),
            ("https", "web"), ("ntp", "ntp"), ("syslog", "syslog")]
# L2 EtherTypes -> protocol
_L2 = {0x88B8: "goose", 0x88BA: "sv", 0x8892: "profinet", 0x88CC: "lldp",
       0x88E3: "mrp", 0x88F7: "ptp", 0x80E1: "dlr"}

# Coarse role classes: a capture host only maps onto an environment host of
# a compatible class.
_CLASS = {}
for _c, _roles in (
        ("field", "plc rtu relay drive meter io robot merging-unit analyzer "
                  "leak meas clock test-set bms hvac pdu ups access-control "
                  "camera infusion-pump patient-monitor modality"),
        ("supervisory", "scada hmi hist eng opc mes batch dcs lims "
                        "central-station pump-server nurse-call vms acs"),
        ("it-server", "dc dns file web mail db proxy ntp syslog nms patch "
                      "av ehr lis ris pacs hl7-engine"),
        ("it-client", "ws jump guest vendor"),
        ("network", "switch router firewall gateway")):
    for _r in _roles.split():
        _CLASS[_r] = _c
# (capture class, env class) pairs allowed besides an exact class match
_CLASS_COMPAT = {("it-client", "it-server"), ("it-server", "it-client"),
                 ("supervisory", "it-client")}


def is_internal(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.is_multicast or a.is_unspecified or str(a) == "255.255.255.255":
        return False
    return any(a in n for n in _INTERNAL if n.version == a.version)


def _ttl_family(ttl: int) -> int:
    """Initial TTL / hop limit a received value most likely started at."""
    for base in (32, 64, 128, 255):
        if ttl <= base:
            return base
    return 255


def _oui_vendor(mac: Optional[str]) -> str:
    from .devices import OUI_VENDORS
    return OUI_VENDORS.get((mac or "")[:8].lower(), "") if mac else ""


# --------------------------------------------------------------------------
# profiling

@dataclass
class HostProfile:
    """What the capture shows about one internal host."""
    key: str                         # its IPv4, else IPv6, else MAC
    ip: Optional[str] = None         # IPv4
    ip6: List[str] = field(default_factory=list)
    mac: Optional[str] = None        # its own MAC (None: only seen routed)
    vendor: str = ""                 # OUI vendor of ``mac``
    ttl: Optional[int] = None        # initial TTL / hop limit family
    serves: Counter = field(default_factory=Counter)    # Port -> frames
    uses: Counter = field(default_factory=Counter)
    l2: Set[str] = field(default_factory=set)
    sent: int = 0
    received: int = 0
    role: str = "unknown"
    cls: str = "unknown"

    def services(self, ports: Iterable[Port]) -> List[str]:
        return sorted({SERVICES[p] for p in ports if p in SERVICES})

    def ports(self, c: Counter) -> List[str]:
        return [f"{p}/{t}" + (f" ({SERVICES[(t, p)]})"
                              if (t, p) in SERVICES else "")
                for t, p in sorted(c, key=lambda x: (x[1], x[0]))]

    def to_json(self) -> Dict:
        return {"ip": self.ip, "ip6": list(self.ip6), "mac": self.mac,
                "vendor": self.vendor, "ttl": self.ttl, "role": self.role,
                "class": self.cls, "serves": self.ports(self.serves),
                "uses": self.ports(self.uses), "l2": sorted(self.l2),
                "packets_sent": self.sent, "packets_received": self.received}


class _IPStat:
    __slots__ = ("macs", "serves", "uses", "ttls", "sent", "received", "l2")

    def __init__(self):
        self.macs: Counter = Counter()
        self.serves: Counter = Counter()
        self.uses: Counter = Counter()
        self.ttls: Counter = Counter()
        self.sent = self.received = 0


def _walk(etype: int, frame: bytes) -> Tuple[int, int]:
    """(payload EtherType, offset) past any VLAN tags."""
    off = 12
    while etype in _VLAN_TPIDS and len(frame) >= off + 8:
        off += 4
        etype = struct.unpack_from("!H", frame, off)[0]
    return etype, off + 2


def _l4(frame: bytes, off: int, v6: bool):
    """(src, dst, ttl, proto, l4 offset) of an IP packet, or None."""
    if v6:
        if len(frame) < off + 40:
            return None
        src = str(ipaddress.IPv6Address(frame[off + 8:off + 24]))
        dst = str(ipaddress.IPv6Address(frame[off + 24:off + 40]))
        nh, p, ttl = frame[off + 6], off + 40, frame[off + 7]
        while nh in _V6_EXT:
            if len(frame) < p + 8:
                return src, dst, ttl, None, None
            if nh == 44:
                if struct.unpack_from("!H", frame, p + 2)[0] >> 3:
                    return src, dst, ttl, None, None   # non-first fragment
                hl = 8
            elif nh == 51:
                hl = (frame[p + 1] + 2) * 4
            else:
                hl = (frame[p + 1] + 1) * 8
            nh, p = frame[p], p + hl
        return src, dst, ttl, nh, p
    if len(frame) < off + 20 or frame[off] >> 4 != 4:
        return None
    ihl = (frame[off] & 0x0F) * 4
    src = ".".join(map(str, frame[off + 12:off + 16]))
    dst = ".".join(map(str, frame[off + 16:off + 20]))
    first = not struct.unpack_from("!H", frame, off + 6)[0] & 0x1FFF
    return (src, dst, frame[off + 8], frame[off + 9] if first else None,
            off + ihl)


def _server_side(t: str, sp: int, dp: int) -> Optional[str]:
    """'d' / 's' — which side of a mid-stream TCP or a UDP datagram is the
    server, by well-known port; None when it cannot be told."""
    ks, kd = (t, sp) in SERVICES, (t, dp) in SERVICES
    if kd and (not ks or sp == dp):
        return "d"
    if ks and not kd:
        return "s"
    if dp < 1024 <= sp:
        return "d"
    if sp < 1024 <= dp:
        return "s"
    return None


def profile(path: str, resolution: Optional[float] = None
            ) -> Tuple[List[HostProfile], Dict]:
    """Profile the internal hosts of a capture in one streamed pass.

    Returns ``(profiles, extra)`` where ``extra`` holds ``routers`` (MACs),
    ``external`` (addresses), ``silent`` (internal addresses that never
    send), ``ipv6_only`` and ``frames``."""
    ips: Dict[str, _IPStat] = {}
    mac_ips: Dict[str, Set[str]] = {}       # src MAC -> src IPs it carried
    mac_l2: Dict[str, Set[str]] = {}        # src MAC -> L2 protocols sent
    mac_sent: Counter = Counter()
    arp: Dict[str, str] = {}                # IP -> MAC from ARP
    external: Set[str] = set()
    frames = 0

    def st(ip: str) -> _IPStat:
        s = ips.get(ip)
        if s is None:
            s = ips[ip] = _IPStat()
        return s

    for _, f in pcapread.iter_frames(path, resolution=resolution):
        frames += 1
        if len(f) < 14:
            continue
        smac = P.bytes_to_mac(f[6:12])
        mac_sent[smac] += 1
        etype, off = _walk(struct.unpack_from("!H", f, 12)[0], f)
        if etype == 0x0806 and len(f) >= off + 28:
            if f[off + 4:off + 6] == b"\x06\x04":
                sip = ".".join(map(str, f[off + 14:off + 18]))
                if sip != "0.0.0.0" and is_internal(sip):
                    arp.setdefault(sip, P.bytes_to_mac(f[off + 8:off + 14]))
            continue
        if etype not in (P.ETH_P_IP, ETH_P_IPV6):
            name = _L2.get(etype)
            if name is None and etype <= 1500 and len(f) >= off + 3:
                llc = f[off:off + 2]
                name = ("stp" if llc == b"\x42\x42" else
                        "cdp" if f[off + 6:off + 8] == b"\x20\x00" else None)
            if name:
                mac_l2.setdefault(smac, set()).add(name)
            continue
        r = _l4(f, off, etype == ETH_P_IPV6)
        if r is None:
            continue
        src, dst, ttl, proto, l4 = r
        sint, dint = is_internal(src), is_internal(dst)
        mac_ips.setdefault(smac, set()).add(src)
        if not sint and src not in ("0.0.0.0", "::"):
            external.add(src)
        if not dint and not (f[0] & 1):
            external.add(dst)
        if sint:
            s = st(src)
            s.sent += 1
            s.macs[smac] += 1
            s.ttls[_ttl_family(ttl)] += 1
        if dint:
            st(dst).received += 1
        if proto not in (P.IPPROTO_TCP, P.IPPROTO_UDP) or l4 is None \
                or len(f) < l4 + 4:
            continue
        t = "tcp" if proto == P.IPPROTO_TCP else "udp"
        sp, dp = struct.unpack_from("!HH", f, l4)
        side = None
        if t == "tcp" and len(f) >= l4 + 14:
            flags = f[l4 + 13]
            if flags & 0x12 == 0x02:
                side = "d"                          # SYN: to the server
            elif flags & 0x12 == 0x12:
                side = "s"                          # SYN-ACK: from it
        side = side or _server_side(t, sp, dp)
        mcast = bool(f[0] & 1)
        if side == "d":
            if dint and not mcast:
                st(dst).serves[(t, dp)] += 1
            if sint:
                st(src).uses[(t, dp)] += 1
        elif side == "s":
            if sint:
                st(src).serves[(t, sp)] += 1
            if dint and not mcast:
                st(dst).uses[(t, sp)] += 1

    # routers: a MAC that sources an external or several internal addresses
    routers = set()
    for mac, srcs in mac_ips.items():
        ext = [x for x in srcs if not is_internal(x)
               and x not in ("0.0.0.0", "::")]
        v4 = [x for x in srcs if ":" not in x and is_internal(x)]
        if ext or len(v4) >= 3:
            routers.add(mac)
    for ip, mac in arp.items():         # a router's own ARP is not routing
        if mac in routers and len([x for x in mac_ips.get(mac, ())
                                   if ":" not in x]) < 3 \
                and not any(not is_internal(x) and x != "0.0.0.0"
                            for x in mac_ips.get(mac, ())):
            routers.discard(mac)

    def own_mac(ip: str, s: _IPStat) -> Optional[str]:
        m = arp.get(ip)
        if m is not None:
            return m
        for m, _ in sorted(s.macs.items(), key=lambda kv: (-kv[1], kv[0])):
            if m not in routers and not int(m[:2], 16) & 1:
                return m
        return None

    hosts: Dict[str, HostProfile] = {}
    by_mac: Dict[str, HostProfile] = {}
    silent: List[str] = []
    v6: List[Tuple[str, _IPStat]] = []
    for ip in sorted(ips, key=_ip_sort):
        s = ips[ip]
        if ":" in ip:
            v6.append((ip, s))
            continue
        if not s.sent:
            silent.append(ip)
            continue
        h = HostProfile(ip, ip=ip, mac=own_mac(ip, s))
        _merge(h, s)
        hosts[ip] = h
        if h.mac and h.mac not in by_mac:
            by_mac[h.mac] = h
    ipv6_only: List[HostProfile] = []
    for ip, s in v6:
        if not s.sent:
            silent.append(ip)
            continue
        m = own_mac(ip, s)
        h = by_mac.get(m) if m else None
        if h is None:                   # IPv6-only host (grouped by MAC)
            h = next((x for x in ipv6_only if m and x.mac == m), None)
            if h is None:
                h = HostProfile(ip, mac=m)
                ipv6_only.append(h)
        h.ip6.append(ip)
        _merge(h, s)
    l2_only: List[HostProfile] = []
    for mac in sorted(mac_l2):
        h = by_mac.get(mac) or next((x for x in ipv6_only if x.mac == mac),
                                    None)
        if h is not None:
            h.l2 |= mac_l2[mac]
        elif mac not in routers and not int(mac[:2], 16) & 1:
            h = HostProfile(mac, mac=mac, l2=set(mac_l2[mac]),
                            sent=mac_sent[mac])
            l2_only.append(h)
    out = list(hosts.values()) + l2_only + ipv6_only
    for h in out:
        h.vendor = _oui_vendor(h.mac)
        h.role, h.cls = classify(h)
    extra = {"routers": sorted(routers), "external": sorted(external,
                                                            key=_ip_sort),
             "silent": silent, "ipv6_only": [h.key for h in ipv6_only],
             "frames": frames}
    return out, extra


def _ip_sort(ip: str):
    try:
        a = ipaddress.ip_address(ip)
        return (a.version, int(a))
    except ValueError:
        return (9, 0)


def _merge(h: HostProfile, s: _IPStat) -> None:
    h.serves.update(s.serves)
    h.uses.update(s.uses)
    h.sent += s.sent
    h.received += s.received
    if s.ttls and h.ttl is None:
        h.ttl = s.ttls.most_common(1)[0][0]


def classify(h: HostProfile) -> Tuple[str, str]:
    """(role, class) of a profiled host — a small passive classifier on the
    services it serves and uses, the L2 protocols it sends and its TTL."""
    served = set(h.services(h.serves))
    used = set(h.services(h.uses))
    role = None
    if "sv" in h.l2:
        role = "merging-unit"
    elif "goose" in h.l2:
        role = "relay"
    if role is None:
        for svc, r in _OT_ROLE:
            if svc in served:
                role = r
                break
    if role is None and "profinet" in h.l2 and not used & OT_SERVICES:
        role = "io"
    mgmt = {"snmp", "snmp-trap", "syslog", "ntp", "dns", "ssh", "telnet",
            "http", "https"}
    if role is None and h.l2 & {"lldp", "cdp", "stp", "mrp", "dlr"} and \
            served <= mgmt and used <= mgmt:
        role = "switch"                 # announces itself, only managed
    if role is None and used & OT_SERVICES:     # an OT client
        if used & {"opcua", "mqtt"} or served & {"sql", "opcua"}:
            role = "hist"
        elif used & {"ftp", "tftp"} or len(used & OT_SERVICES) > 1:
            role = "eng"
        else:
            role = "hmi"
    if role is None and "snmp" in used and served <= mgmt:
        role = "nms"                    # polls agents, collects logs/traps
    if role is None:
        it = [r for svc, r in _IT_ROLE if svc in served]
        winbox = h.ttl == 128 and served <= {"smb", "netbios", "rdp", "vnc",
                                             "http", "https"}
        if it and not (winbox and used & {"kerberos", "ldap", "smb"}):
            role = it[0]
        elif "smb" in served and not used & {"kerberos", "ldap", "smb"}:
            role = "file"
    if role is None and (used or "smb" in served or "netbios" in served):
        role = "ws"
    role = role or "unknown"
    return role, _CLASS.get(role, "unknown")


# --------------------------------------------------------------------------
# environment side

@dataclass
class _EnvHost:
    host: object                    # enterprise.Host
    seg: object                     # enterprise.Segment
    cls: str
    serves: Set[Port]
    uses: Set[Port]
    can: Set[Port]                  # implied by its product family
    vendors: Set[str]
    ttl: int
    windows: bool


def _port_of(proto: str) -> Optional[Port]:
    from . import protocols
    try:
        p = protocols.get(proto)
    except KeyError:
        return None
    if not p.port.isdigit() or p.transport not in ("tcp", "udp"):
        return None
    return p.transport, int(p.port)


def _env_hosts(env) -> List[_EnvHost]:
    from . import incidents
    serves: Dict[str, Set[Port]] = {}
    uses: Dict[str, Set[Port]] = {}
    for c, s, proto in env.conversations:
        port = _port_of(proto)
        if port is None or c == s:
            continue
        serves.setdefault(s, set()).add(port)
        uses.setdefault(c, set()).add(port)
    out = []
    for h in env.hosts:
        if env.nat_of(h) is not None or env.hidden(h):
            continue                    # behind NAT: not on this capture
        seg = env.segment_of(h)
        cls = _CLASS.get(h.role)
        if cls is None:
            lvl = env.purdue_level(h)
            cls = ("field" if h.embedded or lvl in ("0", "1", "2") else
                   "supervisory" if lvl == "3" else
                   "it-server" if serves.get(h.name) else "it-client")
        _, svcs = incidents._product_entry(h)
        can = {p for p in (_port_of(x) for x in svcs) if p}
        vend = {v for v in (h.vendor, _oui_vendor(h.mac)) if v}
        dev = h.device
        if dev is not None and dev.vendor:
            vend.add(dev.vendor)
        out.append(_EnvHost(h, seg, cls, serves.get(h.name, set()),
                            uses.get(h.name, set()), can, vend,
                            _ttl_family(h.fp.ttl), h.os.startswith("win")))
    return out


# NIC vendors of general-purpose PCs / VMs: a match says little
_GENERIC_VENDORS = {"vmware", "dell", "raspberry"}
# supervisory roles that stand in for one another (besides the
# incidents._ROLE_FAMILIES)
_SUPERVISORY = {"scada", "hmi", "hist", "eng", "opc"}


def _tier(want: str, have: str) -> int:
    """2 = same role, 1 = same role family, 0 = not a substitute."""
    from . import incidents
    t = incidents._role_tier(want, have)
    if not t and want in _SUPERVISORY and have in _SUPERVISORY:
        t = 1
    return t


def _vendor_key(v: str) -> str:
    return "".join(ch for ch in v.lower() if ch.isalnum())[:8]


def score(p: HostProfile, e: _EnvHost) -> Optional[float]:
    """How well environment host ``e`` stands in for capture host ``p``
    (None = incompatible)."""
    if p.cls == "network" or e.cls == "network":
        if p.cls != e.cls:
            return None
    elif p.cls != "unknown" and p.cls != e.cls and \
            (p.cls, e.cls) not in _CLASS_COMPAT:
        return None
    s = 0.0
    tier = _tier(p.role, e.host.role)
    s += 6 if tier == 2 else 3 if tier == 1 else 0
    s += 2 if p.cls == e.cls else 0
    ot = hit = 0
    for port in p.serves:
        svc = SERVICES.get(port)
        ot += svc in OT_SERVICES
        if port in e.serves or port in e.can:
            s += 2
            hit += svc in OT_SERVICES
        elif svc in OT_SERVICES:
            s -= 3                      # replay shows a service it lacks
        elif svc in ("smb", "rdp", "netbios") and not e.windows:
            s -= 2
        elif svc == "telnet" and e.windows:
            s -= 2
    if ot and not hit:
        return None                     # serves none of its OT services
    s += min(5, sum(1 for port in p.uses if port in e.uses))
    if p.vendor and any(_vendor_key(p.vendor) == _vendor_key(v)
                        for v in e.vendors):
        s += 1 if _vendor_key(p.vendor) in {
            _vendor_key(g) for g in _GENERIC_VENDORS} else 4
    if p.ttl is not None and p.ttl == e.ttl:
        s += 1
    return s


def assign(profiles: List[HostProfile], env, seed: int = 0
           ) -> Tuple[Dict[str, Tuple[object, float]],
                      List[Tuple[HostProfile, str]]]:
    """Map capture hosts onto environment hosts: ``({profile key: (host,
    score)}, [(profile, why unmapped)])``. Deterministic for a seed."""
    cands = _env_hosts(env)
    rng = random.Random(seed)
    cands.sort(key=lambda e: e.host.name)
    rng.shuffle(cands)                  # seeded tie-break order
    free = list(cands)
    mapped: Dict[str, Tuple[object, float]] = {}
    unmapped: List[Tuple[HostProfile, str]] = []

    def order(p: HostProfile):
        ot = sum(1 for x in p.serves if SERVICES.get(x) in OT_SERVICES)
        return (p.cls == "unknown", -ot, -len(p.serves), -p.sent,
                _ip_sort(p.ip or p.key))
    for p in sorted(profiles, key=order):
        if p.ip is None and p.ip6:
            unmapped.append((p, "IPv6-only host (environments have no "
                                "IPv6 addressing)"))
            continue
        best, best_s = None, None
        for e in free:
            sc = score(p, e)
            if sc is not None and (best_s is None or sc > best_s):
                best, best_s = e, sc
        if best is None:
            ot = [x for x in p.services(p.serves) if x in OT_SERVICES]
            unmapped.append((p, f"no free {p.cls} host in the environment"
                                + (" serving " + " or ".join(ot)
                                   if ot else "")))
            continue
        free.remove(best)
        mapped[p.key] = (best, best_s)
    return mapped, unmapped


# --------------------------------------------------------------------------
# the plan + rewriter

class RemapPlan:
    """Profile + assignment of one capture onto one environment."""

    def __init__(self, path: str, env, span: str = "access", seed: int = 0,
                 resolution: Optional[float] = None):
        from .enterprise import SPAN_VIEWS
        if span not in SPAN_VIEWS:
            raise RewriteError(f"unknown span view {span!r}; use "
                               f"{', '.join(SPAN_VIEWS)}")
        self.path, self.env, self.span, self.seed = path, env, span, seed
        self.profiles, self.extra = profile(path, resolution)
        assigned, self.unmapped = assign(self.profiles, env, seed)
        self.mapped: List[Tuple[HostProfile, object, object, float]] = []
        by_key = {p.key: p for p in self.profiles}
        for key, (e, sc) in assigned.items():
            self.mapped.append((by_key[key], e.host, e.seg, sc))
        self.mapped.sort(key=lambda m: _ip_sort(m[0].ip or m[0].key))
        self.unmapped.sort(key=lambda u: _ip_sort(u[0].ip or u[0].key))
        self._rewriter: Optional[EnvRewriter] = None

    def asset_id(self, host) -> str:
        return f"{self.env.key}:{host.name}"

    def rewriter(self) -> "EnvRewriter":
        """A fresh rewriter for one run (its ``unparsed`` count is the
        run's)."""
        self._rewriter = EnvRewriter(self)
        return self._rewriter

    def describe(self) -> str:
        return (f"remap onto env {self.env.key} ({self.span}): "
                f"{len(self.mapped)} hosts mapped, {len(self.unmapped)} kept")

    def to_json(self) -> Dict:
        hosts = []
        for p, h, seg, sc in self.mapped:
            row = p.to_json()
            row["mapped_to"] = {
                "asset_id": self.asset_id(h), "name": h.name, "ip": h.ip,
                "mac": h.mac, "role": h.role, "vendor": h.vendor,
                "segment": seg.name, "vlan": seg.vlan, "score": sc}
            hosts.append(row)
        unmapped = []
        for p, why in self.unmapped:
            row = p.to_json()
            row["reason"] = why
            unmapped.append(row)
        for ip in self.extra["silent"]:
            unmapped.append({"ip": ip, "reason": "never sends (only "
                             "addressed)"})
        return {"schema": SCHEMA, "pcap": self.path, "env": self.env.key,
                "span": self.span, "seed": self.seed,
                "frames": self.extra["frames"], "hosts": hosts,
                "unmapped": unmapped, "routers": self.extra["routers"],
                "external": self.extra["external"],
                "unparsed_frames": (self._rewriter.unparsed
                                    if self._rewriter is not None else 0)}

    def write_report(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_json(), f, indent=1)
            f.write("\n")

    def table(self) -> List[str]:
        out = []
        for p, h, seg, _ in self.mapped:
            was = p.ip or p.key
            out.append(f"{was:15} {p.role:12} -> {h.name:16} {h.ip:15} "
                       f"{h.mac}  vlan {seg.vlan} ({h.role})")
        for p, why in self.unmapped:
            out.append(f"{p.ip or p.key:15} {p.role:12} kept: {why}")
        if self.extra["silent"]:
            out.append(f"{len(self.extra['silent'])} silent address(es) "
                       "kept (never send)")
        if self.extra["external"]:
            out.append(f"{len(self.extra['external'])} external address(es) "
                       "kept")
        return out

    def annotate(self, inventory: Dict) -> None:
        """Mark the inventory rows of the hosts the replay stands in for:
        ``replay`` = the capture host it carries; identity fields the
        environment would have shown are not on the wire (the capture's
        own device is), so only the MAC-OUI vendor stays observable."""
        rows = {r.get("name"): r for r in inventory.get("hosts", [])}
        for p, h, seg, sc in self.mapped:
            row = rows.get(h.name)
            if row is None:
                continue
            row["replay"] = {"ip": p.ip, "ip6": list(p.ip6), "mac": p.mac,
                             "role": p.role, "vendor": p.vendor}
            for f, ob in (row.get("observability") or {}).items():
                keep = [x for x in ob.get("evidence", []) if x == "oui"]
                ob["evidence"] = keep
                ob["observable"] = bool(keep)
                if keep and f == "vendor":
                    ob["value"] = row.get("mac_vendor") or ob.get("value")


class EnvRewriter(Rewriter):
    """Rewriter that re-addresses capture hosts to their environment hosts
    and places each frame on the environment's segments."""

    def __init__(self, plan: RemapPlan):
        ip_map, mac_map = {}, {}
        for p, h, _, _ in plan.mapped:
            if p.ip:
                ip_map[p.ip] = h.ip
            if p.mac:
                mac_map[p.mac] = h.mac
        super().__init__(ip_map, (), mac_map, None)
        self.plan = plan
        self.env = plan.env
        self.core = plan.span == "core"
        self.by_ip: Dict[bytes, Tuple[object, object]] = {}
        self.by_mac: Dict[bytes, Tuple[object, object]] = {}
        for _, h, seg, _ in plan.mapped:
            self.by_ip[P.ip_to_bytes(h.ip)] = (h, seg)
            self.by_mac[P.mac_to_bytes(h.mac)] = (h, seg)
        self._gw: Dict[str, bytes] = {}

    def describe(self) -> str:
        return self.plan.describe()

    def gw(self, seg) -> bytes:
        m = self._gw.get(seg.name)
        if m is None:
            m = self._gw[seg.name] = P.mac_to_bytes(self.env.gateway_mac(seg))
        return m

    def apply_all(self, frame: bytes) -> List[bytes]:
        return self.place(self.apply(frame))

    def place(self, f: bytes) -> List[bytes]:
        if len(f) < 14:
            return [f]
        tpid = struct.unpack_from("!H", f, 12)[0]
        prio = (struct.unpack_from("!H", f, 14)[0] & 0xF000
                if tpid in _VLAN_TPIDS and len(f) >= 18 else 0)
        etype, off = _walk(tpid, f)
        body = f[off:]
        smac, dmac = f[6:12], f[0:6]
        S = D = None
        ip = etype in (P.ETH_P_IP, ETH_P_IPV6)
        if etype == P.ETH_P_IP and len(body) >= 20:
            S = self.by_ip.get(body[12:16])
            D = self.by_ip.get(body[16:20])
            if S is None and body[12:16] == b"\0\0\0\0":
                S = self.by_mac.get(smac)       # DHCP from 0.0.0.0
        elif etype == 0x0806 and len(body) >= 28:
            S = self.by_ip.get(body[14:18]) or self.by_mac.get(smac)
            D = None if dmac[0] & 1 else self.by_mac.get(dmac)
        else:
            S = self.by_mac.get(smac)
            D = None if dmac[0] & 1 else self.by_mac.get(dmac)
        sseg = S[1] if S else None
        dseg = D[1] if D else None
        if sseg is None and dseg is None:
            return [f]                  # both external / unmapped
        smac2 = P.mac_to_bytes(S[0].mac) if S else smac
        dmac2 = P.mac_to_bytes(D[0].mac) if D else dmac
        if not ip or dmac[0] & 1:
            seg = sseg or dseg
            return [_l2(dmac2, smac2, seg.vlan, prio, etype, body)]
        if sseg is dseg:
            return [_l2(dmac2, smac2, sseg.vlan, prio, etype, body)]
        if dseg is None:                # internal -> external / unmapped
            return [_l2(self.gw(sseg), smac2, sseg.vlan, prio, etype, body)]
        if sseg is None:                # external / unmapped -> internal
            return [_l2(dmac2, self.gw(dseg), dseg.vlan, prio, etype, body)]
        out = [_l2(self.gw(sseg), smac2, sseg.vlan, prio, etype, body)]
        if self.core:                   # the router's egress copy
            out.append(_l2(dmac2, self.gw(dseg), dseg.vlan, prio, etype,
                           _hop(etype, body)))
        return out


def _l2(dst: bytes, src: bytes, vlan: Optional[int], prio: int, etype: int,
        body: bytes) -> bytes:
    if vlan or prio:
        return dst + src + struct.pack("!HHH", 0x8100,
                                       prio | ((vlan or 0) & 0x0FFF),
                                       etype) + body
    return dst + src + struct.pack("!H", etype) + body


def _hop(etype: int, body: bytes) -> bytes:
    """``body`` one routed hop later (TTL / hop limit - 1)."""
    b = bytearray(body)
    if etype == P.ETH_P_IP and len(b) >= 20:
        ihl = (b[0] & 0x0F) * 4
        b[8] = max(1, b[8] - 1)
        b[10:12] = b"\0\0"
        struct.pack_into("!H", b, 10, P.checksum16(bytes(b[:ihl])))
    elif etype == ETH_P_IPV6 and len(b) >= 40:
        b[7] = max(1, b[7] - 1)
    return bytes(b)


# --------------------------------------------------------------------------
# run integration

_CACHE: Dict[tuple, RemapPlan] = {}
_LOCK = threading.Lock()


def plan_for(cfg) -> Optional[RemapPlan]:
    """The run's remap plan (None without ``--remap-env``), computed once
    per capture file / environment / span / seed and shared by the replay
    source and the manifest recorder."""
    key = getattr(cfg, "remap_env", None)
    if not key or not getattr(cfg, "replay_path", None):
        return None
    from . import enterprise
    if key not in enterprise.ENVIRONMENTS:
        raise RewriteError(f"unknown environment for --remap-env: {key}")
    path = cfg.replay_path
    st = os.stat(path)
    seed = getattr(cfg, "remap_seed", None) or 0
    ck = (os.path.abspath(path), st.st_size, st.st_mtime_ns, key,
          cfg.span, seed, getattr(cfg, "replay_tsresol", None))
    with _LOCK:
        plan = _CACHE.get(ck)
        if plan is None:
            plan = RemapPlan(path, enterprise.get(key), cfg.span, seed,
                             getattr(cfg, "replay_tsresol", None))
            _CACHE.clear()
            _CACHE[ck] = plan
    return plan
