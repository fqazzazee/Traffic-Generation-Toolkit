"""Modeled organizations — realistic IT and OT networks with fingerprinted hosts.

An :class:`Environment` is a named inventory of :class:`Host` objects (each with
a role, IP, MAC and OS/device fingerprint) plus a generator that emits a
realistic mix of conversations between them: DNS/Kerberos/LDAP to the DC, SMB to
the file server, HTTP/HTTPS browsing, DHCP/NetBIOS fingerprint chatter, and — on
the OT side — Rockwell EtherNet/IP and Siemens S7comm PLC polling with vendor
identity. Legacy hosts (Windows 2000/XP/7) advertise SMBv1 and old User-Agents so
an analyser (Zeek, Suricata, Claroty CTD, …) can inventory assets and flag the risky ones.

Everything is synthetic and self-contained; it reuses the byte-accurate builders
in :mod:`tgt.protocols`, driving them between arbitrary host pairs.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Tuple

from . import protocols
from .packet import Endpoints

# Vendor OUIs — an analyser also fingerprints assets by MAC prefix.
OUI_WIN = "00:50:56"        # VMware-hosted Windows/Linux
OUI_ROCKWELL = "00:1d:9c"   # Rockwell Automation / Allen-Bradley
OUI_SIEMENS = "00:0e:8c"    # Siemens


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
    "rockwell": OSFingerprint("rockwell", "Rockwell PLC (ControlLogix)", 64,
        smb="none", dhcp_vendor="", legacy=False,
        risk="OT asset — patch cadence slow; expose CIP/ENIP"),
    "siemens": OSFingerprint("siemens", "Siemens S7 PLC", 30,
        smb="none", dhcp_vendor="", legacy=False,
        risk="OT asset — S7comm unauthenticated on legacy families"),
}


@dataclass
class Host:
    name: str
    ip: str
    mac: str
    role: str          # dc, dns, file, web, mail, db, proxy, ws, plc, hmi, hist, eng
    os: str            # fingerprint key
    vendor: str = ""
    product: str = ""  # OT: model / order number

    @property
    def fp(self) -> OSFingerprint:
        return FINGERPRINTS[self.os]


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


def _it_conversations(hosts: List[Host]) -> List[Conversation]:
    by = {x.name: x for x in hosts}
    dc = "DC01"
    dns = "DNS01"
    file = "FILE01"
    web = "WEB01"
    proxy = "PROXY01"
    conv: List[Conversation] = []
    users = [x.name for x in hosts if x.role == "ws"]
    for u in users:
        conv += [
            (u, dns, "dhcp"),          # address + fingerprint
            (u, u, "netbios"),         # self-announce (broadcast)
            (u, dns, "dns"),
            (u, dc, "kerberos"),
            (u, dc, "ldap"),
            (u, file, "smb"),          # SMBv1 vs SMB2 depends on the user OS
            (u, proxy, "http"),        # browsing
            (u, "APP01", "https"),     # encrypted app
            (u, dc, "ntp"),
        ]
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

    def host(self, name: str) -> Host:
        return next(h for h in self.hosts if h.name == name)

    def _endpoints(self, client: Host, server: Host, vlan=None) -> Endpoints:
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
            "order": server.product or "6ES7 315-2EH14-0AB0",
            "server": "Microsoft-IIS/10.0" if server.os.startswith("win") else "Apache",
        }
        return Endpoints(
            client_mac=client.mac, client_ip=client.ip,
            server_mac=server.mac, server_ip=server.ip, vlan=vlan,
            ttl_client=client.fp.ttl, ttl_server=server.fp.ttl, meta=meta)

    def build(self, messages: int) -> List[Tuple[str, bytes]]:
        """One cycle: interleave every modeled conversation once."""
        streams: List[List[Tuple[str, bytes]]] = []
        for cname, sname, proto in self.conversations:
            client, server = self.host(cname), self.host(sname)
            ep = self._endpoints(client, server)
            frames = protocols.get(proto).build(ep, max(1, messages))
            streams.append([(proto, f) for f in frames])
        out: List[Tuple[str, bytes]] = []
        i = 0
        while any(i < len(s) for s in streams):
            for s in streams:
                if i < len(s):
                    out.append(s[i])
            i += 1
        return out

    def legacy_hosts(self) -> List[Host]:
        return [h for h in self.hosts if h.fp.legacy]

    def summary(self) -> str:
        cats: Dict[str, int] = {}
        for h in self.hosts:
            cats[h.role] = cats.get(h.role, 0) + 1
        roles = ", ".join(f"{v} {k}" for k, v in sorted(cats.items()))
        leg = len(self.legacy_hosts())
        return (f"{len(self.hosts)} hosts ({roles}); "
                f"{len(self.conversations)} conversations; {leg} legacy/at-risk")


def _mixed_hosts() -> List[Host]:
    return _it_hosts() + _ot_hosts()


def _mixed_conversations(hosts: List[Host]) -> List[Conversation]:
    return _it_conversations(hosts) + _ot_conversations(hosts)


ENVIRONMENTS: Dict[str, Environment] = {}


def _reg_env(key, name, category, desc, hosts_fn, conv_fn):
    hosts = hosts_fn()
    ENVIRONMENTS[key] = Environment(key, name, category, desc, hosts,
                                    conv_fn(hosts))


_reg_env("it-org", "IT Organization", "IT",
         "Enterprise IT: DC/DNS/file/web/mail servers + 12 users with DHCP, "
         "Kerberos, LDAP, SMB, HTTP/HTTPS and OS-fingerprint chatter "
         "(incl. a legacy Windows 2000 file server, Win7 and WinXP users).",
         _it_hosts, _it_conversations)
_reg_env("ot-plant", "OT Plant", "OT",
         "Rockwell + Siemens cells: ControlLogix/CompactLogix over EtherNet/IP, "
         "S7-300/1500 over S7comm, HMIs, historian, engineering WS, and legacy "
         "Windows XP/2000 HMIs with vendor-identity and fingerprint traffic.",
         _ot_hosts, _ot_conversations)
_reg_env("enterprise-mixed", "Mixed IT + OT Site", "mixed",
         "The full site: the IT organization and the OT plant together — the "
         "realistic converged network an analyser sees at an industrial site.",
         _mixed_hosts, _mixed_conversations)


def get(key: str) -> Environment:
    return ENVIRONMENTS[key]


def all_environments() -> List[Environment]:
    return list(ENVIRONMENTS.values())
