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
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import devices, protocols, stacks, tls
from .packet import (ETH_P_ARP, Endpoints, arp, bytes_to_mac, ethernet,
                     frame_ips, mac_to_bytes, rewrite_ips, rewrite_l2,
                     set_ip_id)

# Vendor OUIs — an analyser also fingerprints assets by MAC prefix.
OUI_WIN = "00:50:56"        # VMware-hosted Windows/Linux
OUI_ROCKWELL = "00:1d:9c"   # Rockwell Automation / Allen-Bradley
OUI_SIEMENS = "00:0e:8c"    # Siemens
OUI_DELL = "00:06:5b"       # Dell — physical workstations
OUI_SCHNEIDER = "00:80:f4"  # Telemecanique / Schneider Electric (Modicon)
OUI_JCI = "00:10:8d"        # Johnson Controls (Metasys BMS)
OUI_TRIDIUM = "00:01:f0"    # Tridium (Niagara JACE)
OUI_SEL = "00:30:a7"        # Schweitzer Engineering Laboratories

# OUI -> vendor and the embedded-device OUIs now come from the device catalog
# (tgt.devices); these names stay for modules that import them.
OUI_VENDORS: Dict[str, str] = devices.OUI_VENDORS

# DNS domain every modeled host is named in (what SNI / LDAP carry)
DOMAIN = "corp.local"


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
    # managed switches (network infrastructure)
    "ios": OSFingerprint("ios", "Cisco IOS / IOS XE", 255,
        smb="none", dhcp_vendor="",
        risk="Network device — SNMP/CDP expose model + firmware"),
    "hios": OSFingerprint("hios", "Hirschmann HiOS", 64,
        smb="none", dhcp_vendor="",
        risk="Network device — SNMP/LLDP expose model + firmware"),
    "moxa": OSFingerprint("moxa", "Moxa switch firmware", 64,
        smb="none", dhcp_vendor="",
        risk="Network device — SNMP/LLDP expose model + firmware"),
    # vendor firmware without a dedicated fingerprint: IEDs, flow computers,
    # analyzers, medical devices, robots (RTOS) and cellular / VSAT routers,
    # panel HMIs, cameras, PDUs (Linux-based)
    "linux-embedded": OSFingerprint("linux-embedded", "Embedded Linux", 64,
        smb="none", dhcp_vendor="udhcp 1.36.1",
        risk="Appliance / edge firmware — vendor-patched only, no EDR agent; "
             "exposed management services"),
    "rtos": OSFingerprint("rtos", "Embedded RTOS firmware", 64,
        smb="none", dhcp_vendor="",
        risk="Embedded device — vendor-patched only, no EDR agent; "
             "cleartext OT protocols"),
}

# Older fingerprint keys still accepted (env files, Host(os=...)); a host
# carries the canonical key.
OS_ALIASES: Dict[str, str] = {
    "embedded": "rtos",
    "embedded-linux": "linux-embedded",
}


def os_key(key: str) -> str:
    """The canonical OS-fingerprint key for ``key`` (see OS_ALIASES)."""
    return OS_ALIASES.get(key, key)


@dataclass
class Host:
    name: str
    ip: str
    mac: str
    role: str          # dc, dns, file, web, mail, db, proxy, ws, plc, hmi, hist, eng, …
    os: str            # fingerprint key
    vendor: str = ""
    product: str = ""  # OT: model / order number
    # Device-catalog identity (tgt.devices). Left empty, ``model`` resolves
    # from ``product`` (embedded devices) or the OS fingerprint (general-
    # purpose hosts), and firmware/serial are picked deterministically from
    # the host name, so the same host always reports the same values.
    model: str = ""
    firmware: str = ""
    serial: str = ""
    modules: Tuple[devices.Module, ...] = ()
    fqdn: str = ""

    def __post_init__(self) -> None:
        self.os = os_key(self.os)
        if not self.model:
            self.model = devices.resolve(self.product) or (
                "" if self.vendor else devices.os_default(self.os))
        dev = self.device
        if dev is not None:
            self.firmware = self.firmware or devices.pick_firmware(dev, self.name)
            self.serial = self.serial or devices.make_serial(dev, self.name)
            self.modules = self.modules or dev.modules
        self.fqdn = self.fqdn or f"{self.name.lower()}.{DOMAIN}"

    @property
    def fp(self) -> OSFingerprint:
        return FINGERPRINTS[self.os]

    @property
    def device(self) -> Optional[devices.DeviceModel]:
        """This host's catalog entry, or ``None`` if it has no model."""
        return devices.find(self.model)

    @property
    def embedded(self) -> bool:
        """An embedded OT device (PLC/RTU/relay/drive/meter/BMS firmware) —
        by catalog model, else by its vendor MAC OUI."""
        dev = self.device
        if dev is not None:
            return dev.embedded
        return self.mac[:8].lower() in devices.EMBEDDED_OUIS

    @property
    def stack(self) -> str:
        """TCP/IP stack fingerprint (:mod:`tgt.stacks` key): the catalog
        model's hint, else the OS fingerprint's family."""
        dev = self.device
        if dev is not None and dev.stack:
            return dev.stack
        return stacks.for_os(self.os)


# ---------------------------------------------------------------------------
# CrowdStrike Falcon EDR — the cloud every Windows host beacons to
# ---------------------------------------------------------------------------
# The sensor reaches the Security Cloud by FQDN — the SNI is the authoritative
# EDR tell — and each name resolves to many AWS IPs. These are CrowdStrike's
# EU-1 cloud (AWS eu-central-1 / Frankfurt): the FQDNs below and the published
# egress IP set the fleet's beacons are spread across.
CROWDSTRIKE_FQDNS = {
    "ts": "ts01-lanner-lion.cloudsink.net",        # sensor channel (C2)
    "up": "lfoup01-lanner-lion.cloudsink.net",     # telemetry upload
    "down": "lfodown01-lanner-lion.cloudsink.net",  # content / policy download
    "api": "api.eu-1.crowdstrike.com",             # OAuth2 API / console
}

CROWDSTRIKE_CLOUD_IPS = [
    "18.158.187.80", "18.198.53.88", "3.121.187.176", "3.121.238.86",
    "3.121.6.180", "3.125.15.130", "18.194.222.197", "18.197.35.253",
    "3.122.135.178", "35.157.198.104", "63.179.114.102", "63.179.203.249",
    "18.196.94.202", "3.121.28.37", "52.29.26.172", "18.158.141.230",
    "18.184.139.200", "18.195.129.87", "3.64.87.158", "3.73.169.253",
    "3.79.224.18", "52.28.120.115", "52.57.246.231", "3.123.89.179",
    "3.126.96.195", "3.69.129.49", "18.184.114.155", "18.194.8.224",
    "3.121.13.180", "3.123.240.202", "3.78.32.129", "35.156.219.65",
    "3.69.184.79", "3.76.143.53", "3.77.82.22",
]

# Falcon runs on modern Windows (Win7 SP1+ / Server 2012+) and Linux servers;
# the EOL Win2000/XP hosts and embedded OT devices (PLC/RTU/relay/drive/meter
# and BACnet/JACE firmware, identified by their tgt.devices model) cannot, so they
# stay deliberately uncovered — a gap an analyser should flag.
EDR_OS = {"win7", "win10", "win2012", "win2019", "linux"}
_EMBEDDED_OUIS = devices.EMBEDDED_OUIS     # compatibility alias


def _cs_cloud_host(ip: str, fqdn: str) -> Host:
    """An on-the-fly CrowdStrike cloud endpoint for one (IP, FQDN) pair; its MAC
    is cosmetic (``place`` rewrites it to the gateway as it egresses)."""
    o = [int(x) for x in ip.split(".")]
    return Host(f"CS-FALCON-{ip}", ip, "02:00:5c:%02x:%02x:%02x" % tuple(o[1:]),
                "edr", "linux", "CrowdStrike", fqdn, fqdn=fqdn)


@dataclass(frozen=True)
class Segment:
    """One L2 broadcast domain: a VLAN carrying one IPv4 subnet.

    ``gateway`` is the segment's SVI on the core L3 switch. Its MAC is the HSRP
    virtual MAC for group = VLAN (0000.0c07.acXX), which is what hosts ARP for.

    ``options`` (not part of equality/hash) holds per-segment knobs:

    * ``gateway_mac``: the gateway's MAC when it is not the HSRP virtual MAC
      (e.g. a remote site's cellular router).
    * ``nat``: ``{"outside_ip": IP, "outside_mac"?: MAC, "local"?: bool}`` —
      the segment is a remote site behind a NAT router whose outside (WAN)
      address is ``outside_ip``; see :meth:`Environment.place`.
    * ``wan_rtt_ms``: round-trip latency of the WAN link that reaches this
      segment (a hint for the time model; see :meth:`Environment.rtt_ms`).
    """
    name: str
    vlan: int
    subnet: str        # CIDR, e.g. "10.20.10.0/24"
    zone: str          # IT | DMZ (L3.5) | OT-SUPERVISORY (L3) | OT-CELL (L1-2)
    gateway: str       # default-gateway IP
    options: Dict[str, Any] = field(default_factory=dict, compare=False,
                                    hash=False)

    @property
    def gateway_mac(self) -> str:
        return (self.options.get("gateway_mac") or
                f"00:00:0c:07:ac:{self.vlan & 0xFF:02x}")

    @property
    def nat(self) -> Optional[Dict[str, Any]]:
        """The segment's NAT spec (``options["nat"]``), or ``None``."""
        return self.options.get("nat") or None

    def contains(self, ip: str) -> bool:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(self.subnet)


SPAN_VIEWS = ("access", "core")

# DNS suffix of every modeled host (matches the TLS SNI / LDAP names)
DNS_DOMAIN = "corp.local"
# Purdue level by zone for general-purpose hosts (OT-CELL splits L1/L2 by role)
_ZONE_LEVEL = {"IT": "4", "DMZ": "3.5", "OT-SUPERVISORY": "3"}
_FIELD_ROLES = {"plc", "drive", "meter", "relay", "rtu"}
# Modbus/TCP Security role a client's certificate carries, by host role
_MBSEC_ROLE = {"eng": "Engineer", "hist": "Monitor", "scada": "Operator",
               "hmi": "Operator", "nms": "Monitor"}


def _ot_addressing(client: "Host", server: "Host") -> dict:
    """Per-device OT protocol addresses, derived from the IPs so every device
    differs: the BACnet device instance (third octet * 1000 + host octet,
    e.g. 10.100.40.21 -> 40021) and the DNP3 link addresses (each side's
    host octet: master = client, outstation = server)."""
    s3, s4 = (int(x) for x in server.ip.split(".")[2:])
    return {"bacnet_instance": s3 * 1000 + s4,
            "dnp3_master": int(client.ip.rsplit(".", 1)[1]),
            "dnp3_outstation": s4}


# A conversation: client drives `proto` toward server.
Conversation = Tuple[str, str, str]   # (client_name, server_name, proto_key)


def _mac(oui: str, n: int) -> str:
    return f"{oui}:{(n >> 16) & 0xFF:02x}:{(n >> 8) & 0xFF:02x}:{n & 0xFF:02x}"


# ---------------------------------------------------------------------------
# Managed network infrastructure: switches announce themselves (LLDP, plus
# CDP on Cisco), answer the NMS's SNMP polls and log to its syslog collector
# ---------------------------------------------------------------------------
_SWITCH_OS = {"cisco-c9300-48p": "ios", "cisco-ie-4000-8gt4g-e": "ios",
              "hirschmann-rsp35": "hios", "moxa-eds-508a": "moxa"}


def _switch_host(name: str, ip: str, model: str, n: int) -> Host:
    """A managed switch at ``ip`` (its management SVI) with a burned-in MAC
    from its catalog model's first OUI."""
    dev = devices.get(model)
    return Host(name, ip, _mac(dev.ouis[0], n), "switch", _SWITCH_OS[model],
                dev.vendor, dev.product, model=model)


def _infra_conversations(switches: List[str], nms: str,
                         hosts: List[Host]) -> List[Conversation]:
    """LLDP (+ CDP on Cisco) self-announcements, NMS SNMP polls and syslog
    for each switch in ``switches`` (missing names are skipped)."""
    by = {x.name: x for x in hosts}
    conv: List[Conversation] = []
    for sw in switches:
        h = by.get(sw)
        if h is None:
            continue
        conv.append((sw, sw, "lldp"))
        if h.os == "ios":
            conv.append((sw, sw, "cdp"))
        conv += [(nms, sw, "snmp"), (sw, nms, "syslog")]
    return conv


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
    # network management + the core/access switches it watches
    h.append(Host("NMS01", "10.20.10.30", _mac(OUI_WIN, 0x130), "nms", "linux"))
    h.append(_switch_host("CORE-SW01", "10.20.10.2", "cisco-c9300-48p", 0x1002))
    h.append(_switch_host("ACC-SW01", "10.20.20.2", "cisco-c9300-48p", 0x2002))
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
    conv += _infra_conversations(["CORE-SW01", "ACC-SW01"], "NMS01", hosts)
    return [c for c in conv if c[0] in by and c[1] in by]


# ---------------------------------------------------------------------------
# OT plant: Rockwell + Siemens networks, PLCs, HMIs, legacy stations
# ---------------------------------------------------------------------------
def _ot_hosts() -> List[Host]:
    h: List[Host] = []
    # Supervisory / IT-in-OT (172.16.0.0/24)
    h += [
        Host("HISTORIAN", "172.16.0.10", _mac(OUI_WIN, 0x300), "hist", "win2019"),
        Host("SCADA01", "172.16.0.11", _mac(OUI_WIN, 0x301), "scada", "win10"),
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
    # OT network management + an industrial switch per segment
    h += [
        Host("OT-NMS", "172.16.0.40", _mac(OUI_WIN, 0x305), "nms", "linux"),
        _switch_host("OT-SW01", "172.16.0.2", "cisco-ie-4000-8gt4g-e", 0x0002),
        _switch_host("SW-CELL-RW", "172.16.1.2", "hirschmann-rsp35", 0x0102),
        _switch_host("SW-CELL-S7", "172.16.2.2", "moxa-eds-508a", 0x0202),
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
        # RSLinx-style browse from the cell HMI; engineering baseline:
        # controller mode/program reads, S7 block upload + planned download
        ("HMI-RW", "PLC-RW1", "enip-list"), ("HMI-RW", "PLC-RW2", "enip-list"),
        ("ENGWS01", "PLC-RW1", "enip-eng"), ("ENGWS01", "PLC-RW2", "enip-eng"),
        ("ENGWS01", "PLC-S7-1", "s7-eng"), ("ENGWS01", "PLC-S7-2", "s7-eng"),
    ]
    conv += _infra_conversations(["OT-SW01", "SW-CELL-RW", "SW-CELL-S7"],
                                 "OT-NMS", hosts)
    return [c for c in conv if c[0] in by and c[1] in by]


# ---------------------------------------------------------------------------
# Environment object + build
# ---------------------------------------------------------------------------
@dataclass
class Environment:
    """A modeled organization.

    ``options`` holds topology switches and misconfiguration knobs (all
    optional; built-ins leave them off unless noted):

    * ``arp`` (default ``True``): each cycle starts with every host ARPing
      for its gateway (HSRP virtual MAC answers) and for the same-segment
      peers it talks to, plus an occasional gratuitous ARP.
    * ``flat``: no segmentation — every segment rides the first segment's
      VLAN (one broadcast domain, subnets multinetted on one SVI).
    * ``dual_homed``: list of ``{"host": NAME, "ip": IP, "mac": MAC?,
      "flows": [[SERVER, PROTO], ...]?}`` — the host gets a second NIC (a
      twin asset ``NAME/nic2`` with the same name/FQDN/model/serial) in the
      segment holding ``IP``, announcing itself and running ``flows``.
    * ``snmp_community``: the v1/v2c community every SNMP poll uses
      (default ``"n0c-r3ad"``); ``default_snmp_community: true`` sets it to
      ``"public"`` (write-capable devices answer ``"private"``) — the
      cleartext-credential finding a monitor should raise.

    ``host_meta`` maps a host name to ``{"server": {...}, "client": {...}}``
    endpoint-meta overrides applied when the host is that side of a flow.
    ``timing`` maps a conversation to its optional ``period`` / ``jitter``
    (parsed from env files, kept for a time model; not yet used by build).

    ``findings`` lists the deliberately planted issues a monitor should flag
    (``{"id", "title", "severity"?, "category"?, "hosts": [...],
    "flows": [{"client", "server", "proto"}, ...], "detail"?}``), carried
    into ``tgt inventory`` JSON as ground truth.

    Remote sites behind NAT: a segment whose ``options["nat"]`` is set (see
    :class:`Segment`) sits behind a router whose outside address is
    ``outside_ip``. Frames between such a host and anything outside its site
    are seen as the HQ SPAN sees them — the remote host's address translated
    to ``outside_ip`` (static port forwarding inbound, port-preserving
    source NAT outbound; TCP/UDP checksums recomputed, TTL -1 for the router
    hop on the way out) and its MAC replaced by the router's
    (``outside_mac``, else the MAC of the host that owns ``outside_ip``, else
    the segment's ``gateway_mac``). The translated endpoint is placed in the
    segment that holds ``outside_ip`` (a WAN transit VLAN at HQ), or, when no
    segment does (a carrier / internet address), reaches the HQ peer through
    its gateway like any foreign host. Segments sharing an ``outside_ip``
    form one site and talk untranslated. Frames that never leave the site
    (its LAN traffic, ARP, broadcasts) are invisible from HQ and dropped,
    unless ``local: true`` keeps them on the site VLAN as a site-side sensor
    would see them.

    ``external`` lists endpoints outside every segment (a cloud MQTT broker,
    a vendor's remote-service portal): conversations may name them, their
    frames egress via the internal host's gateway like EDR beacons, and the
    inventory lists them as external, not as assets.

    ``field_devices`` lists devices with no IP of their own that sit behind
    a gateway host — serial slaves on a device server's RS-485 drop, LoRaWAN
    sensors heard by a LoRa gateway (``{"name", "behind": HOST, "via":
    PROTO, "port", "address", "protocol", "model", "vendor", "product",
    "role", "firmware", "serial"}``, see :mod:`tgt.protocols_iiot`). The
    gateway's flows over ``via`` poll them; the inventory lists them as
    known assets ``behind`` the gateway that are not observable as IP
    assets.
    """
    key: str
    name: str
    category: str      # IT | OT | mixed
    desc: str
    hosts: List[Host]
    conversations: List[Conversation]
    segments: List[Segment]
    options: Dict[str, Any] = field(default_factory=dict)
    host_meta: Dict[str, Dict[str, Dict[str, Any]]] = field(default_factory=dict)
    timing: Dict[Conversation, Dict[str, Any]] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    external: List[Host] = field(default_factory=list)
    field_devices: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        # what was declared, before options rewrite it (env export uses this)
        self.spec = (list(self.hosts), list(self.conversations),
                     list(self.segments))
        self._alias: Dict[str, str] = {}       # second-NIC twin -> host name
        self._apply_options()
        vlans = [s.vlan for s in self.segments]
        if len(set(vlans)) != len(vlans) and not self.options.get("flat"):
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
        self._ext: Dict[str, Host] = {}
        for h in self.external:
            if h.name in self._seg or h.name in self._ext:
                raise ValueError(f"{self.key}: external {h.name} duplicates "
                                 "a host name")
            if any(s.contains(h.ip) for s in self.segments):
                raise ValueError(f"{self.key}: external {h.name} ({h.ip}) is "
                                 "inside a segment")
            self._ext[h.name] = h
        for c, sv, proto in self.conversations:
            for n in (c, sv):
                if n not in self._seg and n not in self._ext:
                    raise ValueError(f"{self.key}: conversation {c} -> {sv} "
                                     f"({proto}) names unknown host {n}")
            if (protocols.get(proto).link_local
                    and (self._seg.get(c) is None
                         or self._seg.get(c) is not self._seg.get(sv))):
                raise ValueError(f"{self.key}: {proto} is link-local but "
                                 f"{c} -> {sv} crosses segments")
        self._init_nat()

    # -- remote sites behind NAT ------------------------------------------
    def _init_nat(self) -> None:
        """Resolve each NAT segment's outside address, MAC and segment."""
        self._nat: Dict[str, Dict[str, Any]] = {}
        self._nat_twins: Dict[Tuple[str, str], Host] = {}
        nat_segs = [s for s in self.segments if s.nat]
        for s in nat_segs:
            nat = s.nat or {}
            out = str(nat.get("outside_ip", ""))
            try:
                ipaddress.IPv4Address(out)
            except ValueError:
                raise ValueError(f"{self.key}: segment {s.name}: nat needs an "
                                 f"IPv4 outside_ip, got {out!r}") from None
            inside = [x for x in nat_segs if x.contains(out)]
            if inside:
                raise ValueError(f"{self.key}: segment {s.name}: nat "
                                 f"outside_ip {out} is inside NAT segment "
                                 f"{inside[0].name}")
            outseg = next((x for x in self.segments if x.contains(out)), None)
            owner = next((h for h in self.hosts if h.ip == out), None)
            mac = (nat.get("outside_mac") or (owner.mac if owner else "")
                   or s.gateway_mac).lower()
            self._nat[s.name] = {"outside_ip": out, "outside_mac": mac,
                                 "outside_seg": outseg,
                                 "local": bool(nat.get("local", False)),
                                 "site": out}

    def nat_of(self, host: Host) -> Optional[Dict[str, Any]]:
        """The resolved NAT spec of ``host``'s segment (``None`` when it is
        not behind NAT, or not in this environment)."""
        if not self._nat:
            return None
        seg = self._seg.get(host.name)
        if seg is None or not seg.contains(host.ip):
            return None
        return self._nat.get(seg.name)

    def _nat_twin(self, host: Host, nat: Dict[str, Any]) -> Host:
        """``host`` as seen from outside its NAT site."""
        key = (host.name, nat["site"])
        twin = self._nat_twins.get(key)
        if twin is None:
            twin = self._nat_twins[key] = replace(
                host, ip=nat["outside_ip"], mac=nat["outside_mac"])
        return twin

    def nat_view(self, a: Host, b: Host) -> Tuple[Host, Host]:
        """The two ends of an ``a`` <-> ``b`` flow as the wire outside any
        NAT site shows them (translated hosts carry the outside IP/MAC)."""
        na, nb = self.nat_of(a), self.nat_of(b)
        if (na is None and nb is None) or (
                na is not None and nb is not None
                and na["site"] == nb["site"]):
            return a, b
        return (self._nat_twin(a, na) if na else a,
                self._nat_twin(b, nb) if nb else b)

    def gateway_mac(self, seg: Segment) -> str:
        """MAC that answers for ``seg``'s gateway: its ``gateway_mac``
        option, else (a NAT site) the NAT router's, else the HSRP MAC."""
        if not seg.options.get("gateway_mac") and seg.name in self._nat:
            return self._nat[seg.name]["outside_mac"]
        return seg.gateway_mac

    def nat_address(self, host: Host) -> str:
        """The address ``host`` appears as outside its site ("" if none)."""
        nat = self.nat_of(host)
        return nat["outside_ip"] if nat else ""

    def hidden(self, host: Host) -> bool:
        """True when ``host``'s own LAN frames are not on the capture (it is
        behind NAT without ``local: true``)."""
        nat = self.nat_of(host)
        return nat is not None and not nat["local"]

    def rtt_ms(self, a: Host, b: Host) -> float:
        """WAN round-trip hint for an ``a`` <-> ``b`` flow: the
        ``wan_rtt_ms`` of each end's segment the path leaves (0 within one
        segment or one NAT site). A time model can stretch request/response
        gaps by it."""
        sa, sb = self._seg.get(a.name), self._seg.get(b.name)
        if sa is sb:
            return 0.0
        na, nb = self.nat_of(a), self.nat_of(b)
        if na is not None and nb is not None and na["site"] == nb["site"]:
            return 0.0
        return float(sum((s.options.get("wan_rtt_ms") or 0)
                         for s in (sa, sb) if s is not None))

    def _apply_options(self) -> None:
        """Rewrite segments/hosts/conversations for the topology knobs."""
        opts = self.options
        if opts.get("flat") and self.segments:
            vlan = self.segments[0].vlan
            self.segments = [replace(s, vlan=vlan) for s in self.segments]
        twins: List[Host] = []
        conv: List[Conversation] = []
        for d in opts.get("dual_homed") or ():
            base = next((h for h in self.hosts if h.name == d["host"]), None)
            if base is None:
                raise ValueError(f"{self.key}: dual_homed host {d['host']!r} "
                                 "is not in the environment")
            mac = d.get("mac") or "%s:%02x:%s" % (
                base.mac[:8], int(base.mac[9:11], 16) ^ 0x80, base.mac[12:])
            twin = Host(f"{base.name}/nic2", d["ip"], mac, base.role, base.os,
                        base.vendor, base.product, model=base.model,
                        firmware=base.firmware, serial=base.serial,
                        modules=base.modules, fqdn=base.fqdn)
            twins.append(twin)
            self._alias[twin.name] = base.name
            conv.append((twin.name, twin.name, "netbios"))
            conv += [(twin.name, sv, p) for sv, p in d.get("flows") or ()]
        if twins:
            self.hosts = list(self.hosts) + twins
            self.conversations = list(self.conversations) + conv

    @property
    def arp_enabled(self) -> bool:
        return bool(self.options.get("arp", True))

    def snmp_community(self, server: Host) -> str:
        """The community an SNMP poll of ``server`` carries."""
        if self.options.get("default_snmp_community"):
            dev = server.device
            return "private" if dev is not None and dev.device_type == "switch" \
                else "public"
        return str(self.options.get("snmp_community", "n0c-r3ad"))

    def host(self, name: str) -> Host:
        """A host (or an ``external`` endpoint) by name."""
        for h in self.hosts:
            if h.name == name:
                return h
        return self._ext[name]

    def is_external(self, name: str) -> bool:
        return name in self._ext

    def segment_of(self, host: Host) -> Segment:
        return self._seg[host.name]

    def _endpoints(self, client: Host, server: Host) -> Endpoints:
        dflt_cip = devices.get("rockwell-1756-l71").identity["cip"]
        dflt_s7 = devices.get("siemens-cpu-315-2pndp").identity["s7"]
        meta = {
            "ua": client.fp.ua,
            "smb": client.fp.smb if client.fp.smb != "none" else "smb2",
            "dhcp_vendor": client.fp.dhcp_vendor,   # "" = no option 60
            "nbname": self._alias.get(client.name, client.name),
            "host": self._alias.get(server.name, server.name),
            "sni": server.fqdn,
            "realm": "CORP.LOCAL",
            "dn": f"CN={client.name},DC=corp,DC=local",
            "product": server.product or dflt_cip["product_name"],
            "device_type": 0x02 if server.role == "drive" else 0x0E,  # CIP
            "order": server.product or dflt_s7["order"],
            "server": "Microsoft-IIS/10.0" if server.os.startswith("win") else "Apache",
            "tls_client": tls.client_for(client.os, client.role),
            "tls_server": tls.server_for(server.os, server.embedded),
        }
        # the server's own identity: CIP vendor/product code/revision/serial,
        # S7 firmware + serial — so each device reports its own values
        meta.update(devices.identity_meta(server.device, server.firmware,
                                          server.serial, server.name))
        meta.update(_ot_addressing(client, server))
        # Built untagged, host to host; _place() puts each frame on its VLAN.
        return Endpoints(
            client_mac=client.mac, client_ip=client.ip,
            server_mac=server.mac, server_ip=server.ip,
            ttl_client=client.fp.ttl, ttl_server=server.fp.ttl, meta=meta,
            stack_client=client.stack, stack_server=server.stack)

    def _place(self, frame: bytes, client: Host, server: Host,
               span: str) -> List[bytes]:
        return self.place(frame, client, server, span, self.segment_or_none)

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
        untouched. A frame that crosses a NAT site boundary is translated
        first (see the class docstring); one that stays inside a NAT site is
        dropped (``[]``) unless the site is ``local``.
        """
        from_client = frame[6:12] == mac_to_bytes(client.mac)
        src, dst = (client, server) if from_client else (server, client)
        if self._nat:
            ns, nd = self.nat_of(src), self.nat_of(dst)
            if ns is not None or nd is not None:
                inside = ns is not None and (
                    frame[0] & 0x01 or (nd is not None
                                        and nd["site"] == ns["site"]))
                if inside:              # never leaves the remote site
                    if not ns["local"]:
                        return []
                elif not (frame[0] & 0x01):
                    frame, src, dst, seg_of = self._nat_translate(
                        frame, src, dst, ns, nd, seg_of)
        return self._route(frame, src, dst, span, seg_of)

    def _nat_translate(self, frame: bytes, src: Host, dst: Host,
                       ns: Optional[Dict[str, Any]],
                       nd: Optional[Dict[str, Any]], seg_of):
        """Rewrite a frame crossing NAT site boundaries: inside addresses
        become the site's outside IP/MAC; returns the frame, the translated
        ends and a ``seg_of`` that places them where the outside IP lives."""
        s2 = self._nat_twin(src, ns) if ns else src
        d2 = self._nat_twin(dst, nd) if nd else dst
        frame = rewrite_ips(frame, s2.ip if ns else None,
                            d2.ip if nd else None, ttl_delta=-1 if ns else 0)
        frame = rewrite_l2(frame, s2.mac, d2.mac, None)

        def seg2(h: Host):
            if ns is not None and h is s2:
                return ns["outside_seg"]
            if nd is not None and h is d2:
                return nd["outside_seg"]
            return seg_of(h)
        return frame, s2, d2, seg2

    def _route(self, frame: bytes, src: Host, dst: Host, span: str,
               seg_of) -> List[bytes]:
        """Placement of a frame from ``src`` to ``dst`` (see :meth:`place`)."""
        sseg, dseg = seg_of(src), seg_of(dst)
        if sseg is None and dseg is None:
            return [frame]
        if frame[0] & 0x01 and sseg is not None:
            # L2 broadcast / multicast (DHCP Discover, LLDP, PTP, GOOSE, mDNS):
            # stays in the sender's VLAN — never routed, no gateway MAC, no
            # TTL decrement
            return [rewrite_l2(frame, bytes_to_mac(frame[6:12]),
                               bytes_to_mac(frame[0:6]), sseg.vlan)]
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

    def _proto_meta(self, proto: str, client: Host, server: Host) -> dict:
        """Per-protocol endpoint meta that needs the inventory: DNS resolves
        the real names of the hosts the client talks to, DHCP leases from the
        client's own segment (relayed by its gateway when the server is
        elsewhere)."""
        if proto == "dns":
            peers: List[Host] = []
            for c, sv, _ in self.conversations:
                h = self.host(sv)
                if c == client.name and sv != c and h not in peers:
                    peers.append(h)
            # internet names first: a client resolves its cloud endpoint
            # before connecting, whatever the message count
            peers.sort(key=lambda h: h.name not in self._ext)
            return {"dns_names": [(h.fqdn if h.name in self._ext else
                                   f"{h.name.lower()}.{DNS_DOMAIN}", h.ip)
                                  for h in peers or [server]]}
        if proto in ("bacnet-id", "enip-list", "codesys-disc"):
            # discovery broadcast to the client's subnet when the device
            # shares it; a routed device is browsed by unicast
            seg = self.segment_of(client)
            same = self.segment_or_none(server) is seg
            return {"bcast": str(ipaddress.ip_network(seg.subnet)
                                 .broadcast_address) if same else ""}
        if proto == "netbios":
            # B-node broadcasts to the announcer's own subnet; the host
            # announcement states its OS version
            seg = self.segment_of(client)
            return {"bcast": str(ipaddress.ip_network(seg.subnet)
                                 .broadcast_address), "nb_os": client.os}
        if proto == "dhcp":
            seg = self.segment_of(client)
            meta = {"dhcp_router": seg.gateway, "dhcp_domain": DNS_DOMAIN,
                    "dhcp_mask": str(ipaddress.ip_network(seg.subnet).netmask)}
            if self.segment_or_none(server) is not seg:
                meta["dhcp_relay"] = seg.gateway
            return meta
        if proto in ("snmp", "snmpv3", "lldp", "cdp"):
            return self._agent_meta(proto, server)
        if proto == "syslog":
            dev = client.device
            if dev is not None and dev.device_type == "switch":
                return {"syslog_format": "3164"}
        if proto in ("dicom", "hl7"):
            # the SCU / sending application states its own identity: its
            # catalog values and env-file meta, under a "client_" prefix
            own = devices.identity_meta(client.device, client.firmware,
                                        client.serial, client.name)
            own.update(self.host_meta.get(client.name, {}).get("server", {}))
            return {f"client_{k}": v for k, v in own.items()
                    if k.startswith(proto + "_")}
        from . import protocols_iiot
        if proto in protocols_iiot.GATEWAY_PROTOCOLS:
            # serial slaves / LoRaWAN sensors behind a gateway, Moxa search
            return protocols_iiot.gateway_meta(self, proto, client, server)
        from .protocols_sec import PLAIN_OF
        if proto in PLAIN_OF:
            # mutual TLS: the client's certificate names the client; a
            # Modbus/TCP Security client's states its role
            return {"tls_client_cn": client.fqdn,
                    "mbsec_role": _MBSEC_ROLE.get(client.role, "Operator")}
        return {}

    def _agent_meta(self, proto: str, agent: Host) -> dict:
        """SNMP agent / LLDP / CDP identity of ``agent`` from its catalog
        banners (sysDescr, sysObjectID, CDP platform) and placement."""
        name = self._alias.get(agent.name, agent.name)
        meta: Dict[str, Any] = {"snmp_sysname": name, "lldp_sysname": name,
                                "cdp_device_id": name,
                                "snmp_syslocation": f"{self.name}, "
                                f"{self.segment_of(agent).name}"}
        if proto == "snmp":
            meta["snmp_community"] = self.snmp_community(agent)
        dev = agent.device
        if dev is None:
            return meta
        for key in ("snmp_sysdescr", "snmp_sysobjectid", "cdp_platform"):
            val = devices.banner(dev, key, name, agent.firmware, agent.serial)
            if val:
                meta[key] = val
        if "snmp_sysdescr" in meta:
            meta["lldp_sysdescr"] = meta["cdp_software"] = meta["snmp_sysdescr"]
        return meta

    def _arp_frames(self) -> List[bytes]:
        """Start-of-cycle address resolution, on each host's own VLAN: every
        host ARPs for its gateway (answered from the HSRP virtual MAC) and
        for each same-segment peer it opens IP flows to; DHCP clients and
        every eighth host also send a gratuitous ARP."""
        if not self.arp_enabled:
            return []
        arp_build = protocols.get("arp").build
        peers: Dict[str, List[str]] = {h.name: [] for h in self.hosts}
        dhcp = set()
        for c, sv, proto in self.conversations:
            if proto == "dhcp":
                dhcp.add(c)
            if (c != sv and c in peers
                    and protocols.get(proto).transport != "l2"
                    and self._seg.get(c) is self._seg.get(sv)
                    and sv not in peers[c]):
                peers[c].append(sv)
        out: List[bytes] = []
        for i, h in enumerate(self.hosts):
            if self.hidden(h):          # behind NAT: not on this capture
                continue
            seg = self.segment_of(h)
            gw = Endpoints(client_mac=h.mac, client_ip=h.ip,
                           server_mac=self.gateway_mac(seg),
                           server_ip=seg.gateway,
                           vlan=seg.vlan)
            out += arp_build(gw, 1)
            if h.name in dhcp or i % 8 == 0:
                out.append(ethernet("ff:ff:ff:ff:ff:ff", h.mac, ETH_P_ARP,
                                    arp(1, h.mac, h.ip, "00:00:00:00:00:00",
                                        h.ip), vlan=seg.vlan))
            for name in peers[h.name]:
                peer = self.host(name)
                ep = Endpoints(client_mac=h.mac, client_ip=h.ip,
                               server_mac=peer.mac, server_ip=peer.ip)
                for f in arp_build(ep, 1):
                    out += self._place(f, h, peer, "access")
        return out

    def segment_or_none(self, host: Host):
        """Like :meth:`segment_of`, but ``None`` for a host not in this env."""
        return self._seg.get(host.name)

    def edr_hosts(self) -> List[Host]:
        """Windows and Linux hosts that run a Falcon sensor. Excludes the EOL
        XP/2000 Windows and embedded OT devices (by catalog model, else
        vendor MAC OUI), which can't — so they stay uncovered."""
        return [h for h in self.hosts if h.os in EDR_OS and not h.embedded
                and h.name not in self._alias]     # one sensor per machine

    def _edr_endpoints(self, win: Host, cloud: Host) -> Endpoints:
        return Endpoints(
            client_mac=win.mac, client_ip=win.ip,
            server_mac=cloud.mac, server_ip=cloud.ip,
            ttl_client=win.fp.ttl, ttl_server=64,
            meta={"sni": cloud.product, "domain": cloud.product,
                  "nbname": win.name, "ua": win.fp.ua,
                  "tls_client": "falcon", "tls_server": "openssl"},
            stack_client=win.stack, stack_server="linux")

    def _edr_streams(self, messages: int,
                     span: str) -> List[List[Tuple[str, List[bytes]]]]:
        """Falcon EDR telemetry: every covered Windows/Linux host keeps a TLS
        channel open to the CrowdStrike sensor cloud, egressing via its own
        gateway (like any internet-bound flow). Beacons spread across the EU-1
        cloud IP pool; a representative host also exercises the upload / download
        / API FQDNs so all of them appear on the wire."""
        def flow(host: Host, ip: str, fqdn: str, n: int):
            cloud = _cs_cloud_host(ip, fqdn)
            ep = self._edr_endpoints(host, cloud)
            frames = protocols.get("edr").build(ep, max(1, n))
            placed = [("edr", self.place(f, host, cloud, span,
                                         self.segment_or_none))
                      for f in frames]
            return [p for p in placed if p[1]]

        return [flow(h, ip, fqdn, messages if bulk else 1)
                for h, ip, fqdn, bulk in self.edr_plan()]

    def edr_plan(self) -> List[Tuple[Host, str, str, bool]]:
        """Who beacons where: (host, cloud IP, FQDN, bulk) per Falcon flow;
        ``bulk`` flows carry ``messages`` exchanges, the rest one beacon."""
        fleet = self.edr_hosts()
        if not fleet:
            return []
        ips, fq = CROWDSTRIKE_CLOUD_IPS, CROWDSTRIKE_FQDNS
        # a low-and-slow beacon per host on the sensor channel, spread over the
        # cloud IP pool so the whole published egress set appears
        plan = [(h, ips[i % len(ips)], fq["ts"], False)
                for i, h in enumerate(fleet)]
        # one host also uploads telemetry, pulls content and hits the API
        anchor = next((h for h in fleet
                       if h.role in ("hist", "file", "dc", "scada")), fleet[0])
        plan += [(anchor, ips[-1], fq["up"], True),
                 (anchor, ips[-2], fq["down"], True),
                 (anchor, ips[-3], fq["api"], False)]
        return plan

    def build(self, messages: int, span: str = "access",
              edr: bool = True) -> List[Tuple[str, bytes]]:
        """One cycle: interleave every modeled conversation once.

        ``span`` is the capture point: ``access`` (each frame once, on its
        sender's VLAN) or ``core`` (routed frames also on the receiver's VLAN).
        ``edr`` adds the CrowdStrike Falcon telemetry every covered Windows host
        emits (on by default; the single-flow routing checks turn it off).
        """
        if span not in SPAN_VIEWS:
            raise ValueError(f"unknown span view {span!r}; use {SPAN_VIEWS}")
        # each stream item is the group of copies one host frame produces;
        # a group stays contiguous so ingress/egress hops sit side by side
        streams: List[List[Tuple[str, List[bytes]]]] = []
        for cname, sname, proto in self.conversations:
            client, server = self.host(cname), self.host(sname)
            ep = self.conv_endpoints(client, server, proto)
            frames = protocols.get(proto).build(ep, max(1, messages))
            placed = [(proto, self._place(f, client, server, span))
                      for f in frames]
            streams.append([p for p in placed if p[1]])   # NAT may hide
        if edr:
            streams += self._edr_streams(messages, span)
        # each cycle opens with address resolution, as after a cache flush
        out: List[Tuple[str, bytes]] = [("arp", f) for f in self._arp_frames()]
        stamp = self._ip_id_stamper()
        i = 0
        while any(i < len(s) for s in streams):
            for s in streams:
                if i < len(s):
                    proto, group = s[i]
                    out.extend((proto, g) for g in stamp(group))
            i += 1
        return out

    def conv_endpoints(self, client: Host, server: Host,
                       proto: str) -> Endpoints:
        """Endpoints (with protocol and per-host meta) of one conversation,
        as :meth:`build` and the timed scheduler build it."""
        ep = self._endpoints(client, server)
        ep.meta.update(self._proto_meta(proto, client, server))
        ep.meta.update(self.host_meta.get(server.name, {}).get("server", {}))
        ep.meta.update(self.host_meta.get(client.name, {}).get("client", {}))
        if proto == "cdp":      # native-VLAN TLV (frame itself is untagged)
            ep.vlan = self.segment_of(server).vlan
        return ep

    def _ip_id_stamper(self) -> Callable[[List[bytes]], List[bytes]]:
        """Windows and embedded stacks number every IP datagram a host sends
        from one counter, so a host's IP IDs rise in wire order across all its
        flows. Returns a function that re-stamps one frame group (a frame and
        its routed copy keep the same ID)."""
        by_ip = {h.ip: h for h in self.hosts
                 if stacks.get(h.stack).ipid == "host"}
        counters: Dict[str, int] = {}

        def stamp(group: List[bytes]) -> List[bytes]:
            ips = frame_ips(group[0])
            host = by_ip.get(ips[0]) if ips else None
            if host is None:
                return group
            n = counters.get(host.ip)
            if n is None:
                n = stacks.hash_int(host.name, "ipid", bits=16)
            counters[host.ip] = (n + 1) & 0xFFFF
            return [set_ip_id(g, n) for g in group]
        return stamp

    def protocols(self) -> List[str]:
        """Protocols this environment's conversations use, in registry order
        (``edr`` is added when any Windows host runs a Falcon sensor)."""
        used = {proto for _, _, proto in self.conversations}
        if self.edr_hosts():
            used.add("edr")
        if self.arp_enabled and self.hosts:
            used.add("arp")
        return [k for k in protocols.PROFILES if k in used]

    def purdue_level(self, host: Host) -> str:
        """Purdue level ("0".."4", "3.5" = IT/OT DMZ): fixed by the catalog
        model for embedded devices, else by where the host sits."""
        dev = host.device
        if (dev is not None and dev.purdue_level
                and dev.device_type != "switch"):   # a switch: where it sits
            return dev.purdue_level
        zone = self.segment_of(host).zone
        if zone == "OT-CELL":
            return "1" if host.role in _FIELD_ROLES else "2"
        return _ZONE_LEVEL.get(zone, "")

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


def _dmz_hosts() -> List[Host]:
    """The IT/OT DMZ (L3.5) that joins the IT org to the OT plant."""
    return [
        Host("HIST-REP", "10.20.50.10", _mac(OUI_WIN, 0x500), "hist", "win2019"),
        Host("JUMP01", "10.20.50.11", _mac(OUI_WIN, 0x501), "jump", "win2019"),
        Host("PATCH01", "10.20.50.12", _mac(OUI_WIN, 0x502), "patch", "win2019"),
        _switch_host("DMZ-SW01", "10.20.50.2", "cisco-c9300-48p", 0x5002),
    ]


def _mixed_hosts() -> List[Host]:
    return _it_hosts() + _ot_hosts() + _dmz_hosts()


def _mixed_segments() -> List[Segment]:
    return _it_segments() + _ot_segments() + [
        Segment("IT-OT-DMZ", 50, "10.20.50.0/24", "DMZ", "10.20.50.1")]


# enterprise-mixed's one deliberate IT -> OT flow that bypasses the DMZ: an
# office PC with the PLC programming suite going online with a cell PLC
MIXED_DMZ_BYPASS: Conversation = ("WS31", "PLC-RW1", "enip")


def _mixed_conversations(hosts: List[Host]) -> List[Conversation]:
    by = {x.name: x for x in hosts}
    conv = _it_conversations(hosts) + _ot_conversations(hosts)
    dmz: List[Conversation] = [
        # IT -> DMZ: users read the historian replica, admins reach the jump
        # host; the DMZ uses the IT domain and patches via the IT proxy
        ("WS21", "HIST-REP", "https"), ("WS22", "HIST-REP", "https"),
        ("WS20", "JUMP01", "https"), ("JUMP01", "DC01", "kerberos"),
        ("JUMP01", "DNS01", "dns"), ("PATCH01", "PROXY01", "http"),
        # OT <-> DMZ: historian replication out, supervised remote access in,
        # patches and AV pulled from the DMZ
        ("HISTORIAN", "HIST-REP", "https"), ("JUMP01", "ENGWS01", "https"),
        ("JUMP01", "ENGWS01", "smb"), ("SCADA01", "PATCH01", "http"),
        ("ENGWS01", "PATCH01", "http"), ("HISTORIAN", "PATCH01", "http"),
        MIXED_DMZ_BYPASS,
    ]
    conv += [c for c in dmz if c[0] in by and c[1] in by]
    conv += _infra_conversations(["DMZ-SW01"], "NMS01", hosts)
    return conv


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

    # Network management (corporate + OT) and a managed switch per segment
    add("NMS01", "10.10.10.18", OUI_WIN, 0x1018, "nms", "linux")
    add("OT-NMS", "10.100.0.17", OUI_WIN, 0x6017, "nms", "linux")
    for name, ip, model in _SITE_SWITCHES:
        h.append(_switch_host(name, ip, model,
                              int(ip.split(".")[2]) << 8 | 0x02))
    return h


# (name, management IP, catalog model): Catalysts on the corporate side and
# DMZ, Cisco IE in operations/packaging, Hirschmann in process/substation,
# Moxa in utilities/BMS
_SITE_SWITCHES = [
    ("CORE-SW01", "10.10.10.2", "cisco-c9300-48p"),
    ("ACC-SW01", "10.10.20.2", "cisco-c9300-48p"),
    ("DMZ-SW01", "10.10.50.2", "cisco-c9300-48p"),
    ("OT-CORE01", "10.100.0.2", "cisco-ie-4000-8gt4g-e"),
    ("SW-PK", "10.100.10.2", "cisco-ie-4000-8gt4g-e"),
    ("SW-PR", "10.100.20.2", "hirschmann-rsp35"),
    ("SW-UT", "10.100.30.2", "moxa-eds-508a"),
    ("SW-BMS", "10.100.40.2", "moxa-eds-508a"),
    ("SW-SUB", "10.100.50.2", "hirschmann-rsp35"),
]


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
    # network management: the corporate NMS watches IT + DMZ switches, the
    # OT NMS the plant's
    conv += _infra_conversations(["CORE-SW01", "ACC-SW01", "DMZ-SW01"],
                                 "NMS01", hosts)
    conv += _infra_conversations([n for n, ip, _ in _SITE_SWITCHES
                                  if ip.startswith("10.100.")], "OT-NMS", hosts)
    conv += _site_identity_conversations(named)
    return [c for c in conv if c[0] in by and c[1] in by]


def _site_identity_conversations(named) -> List[Conversation]:
    """Every embedded device states its identity in its own protocol, and the
    engineering / operations baseline runs from the hosts that own it."""
    conv: List[Conversation] = []
    # Packaging: RSLinx browse from the line HMI, Studio 5000 going online
    # from ENG01, and class-1 I/O between each PLC and its PowerFlexes
    for plc in named("PLC-PK"):
        conv += [("HMI-PK1", plc, "enip-list"), ("ENG01", plc, "enip-eng")]
    for i, drv in enumerate(named("DRV-PK")):
        conv.append((f"PLC-PK{i % 4 + 1}", drv, "enip-io"))
    # Process: TIA Portal block list / upload / planned download from ENG02
    for plc in named("PLC-PR"):
        conv.append(("ENG02", plc, "s7-eng"))
    # Utilities: Modbus device ID from engineering + the power-monitoring
    # historian; the operator HMI writes setpoints
    for plc in named("PLC-UT"):
        conv += [("ENG01", plc, "modbus-id"), ("HMI-UT1", plc, "modbus-write")]
    for m in named("METER-UT"):
        conv.append(("HIST01", m, "modbus-id"))
    # BMS: the JACE discovers its controllers; the supervisor reads the JACE
    for ahu in named("BAC-AHU"):
        conv.append(("BMS-JACE", ahu, "bacnet-id"))
    conv.append(("BMS-SUP", "BMS-JACE", "bacnet-id"))
    # Substation: DNP3 device attributes, SCADA time sync, RTU via SNMP
    for r in named("RELAY"):
        conv.append(("RTAC01", r, "dnp3-id"))
    conv += [("SCADA02", "RTAC01", "dnp3-id"),
             ("SCADA02", "RTAC01", "dnp3-time"),
             ("SCADA02", "RTU-104", "iec104-time"),
             ("SCADA02", "RTU-104", "snmp")]
    return conv


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
         "The full site: the IT organization and the OT plant joined through "
         "an IT/OT DMZ (historian replica, jump host, patch server) — the "
         "realistic converged network an analyser sees at an industrial site, "
         "with one office PC reaching a PLC directly.",
         _mixed_hosts, _mixed_conversations, _mixed_segments)
_reg_env("industrial-site", "Industrial Site", "mixed",
         "A large Purdue-model plant: corporate IT, an IT/OT DMZ, L3 site "
         "operations, Rockwell packaging, Siemens process, Schneider "
         "utilities, a BACnet BMS and an SEL/DNP3 substation, across 9 "
         "VLANs, plus one IT laptop talking straight to the plant floor.",
         _site_hosts, _site_conversations, _site_segments)

# the environments defined in code (env files and packaged sites register
# later, through tgt.envfile.register)
BUILTIN_KEYS = frozenset(ENVIRONMENTS)


def get(key: str) -> Environment:
    return ENVIRONMENTS[key]


def all_environments() -> List[Environment]:
    return list(ENVIRONMENTS.values())
