"""IT / network-infrastructure protocol builders: SNMP, LLDP/CDP, syslog,
name/service discovery (mDNS, SSDP, LLMNR, NBNS) and MQTT / Sparkplug B.

These are the protocols passive monitors lean on for asset enrichment (SNMP
sysDescr/sysObjectID, LLDP/CDP neighbour + firmware, mDNS/SSDP/NBNS names) and
IIoT visibility (MQTT, Sparkplug B). Builders follow the
:data:`tgt.protocols.FlowBuilder` contract and register into the shared
:data:`tgt.protocols.PROFILES` registry; :mod:`tgt.protocols` imports this
module at its end, so importing either one populates the full registry.

Identity strings come from ``ep.meta`` when present (``snmp_sysdescr``,
``snmp_community``, ``host``, ...) and fall back to sensible defaults.
"""
from __future__ import annotations

import struct
import zlib
from typing import List

from . import packet as P
from .packet import Endpoints
from .protocols import _der, _der_int, _der_seq, _reg, _sport, _tcp_flow

# Fixed wall-clock used across builders (2025-10-06 12:00:00 UTC), matching
# the timestamps the existing builders embed.
_EPOCH_MS = 1759752000000


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
def _mcast_mac(group: str) -> str:
    """IPv4 multicast group -> 01:00:5e + low 23 bits (RFC 1112)."""
    b = P.ip_to_bytes(group)
    return P.bytes_to_mac(b"\x01\x00\x5e" + bytes([b[1] & 0x7F]) + b[2:])


def _udp_to(ep: Endpoints, from_client: bool, sport: int, dport: int,
            dst_ip: str, dst_mac: str, payload: bytes, ttl: int | None = None,
            ident: int = 0) -> bytes:
    """A UDP frame from one endpoint to an arbitrary (multicast/broadcast)
    destination, with the sender's normal TTL unless one is given."""
    s_mac = ep.client_mac if from_client else ep.server_mac
    s_ip = ep.client_ip if from_client else ep.server_ip
    if ttl is None:
        ttl = ep.ttl_client if from_client else ep.ttl_server
    seg = P.udp(s_ip, dst_ip, sport, dport, payload)
    pkt = P.ipv4(s_ip, dst_ip, P.IPPROTO_UDP, seg, ttl=ttl, ident=ident)
    return P.ethernet(dst_mac, s_mac, P.ETH_P_IP, pkt, vlan=ep.vlan)


def _server_name(ep: Endpoints, default: str) -> str:
    return str(ep.meta.get("host", default))


def _dns_name(name: str) -> bytes:
    """Uncompressed DNS wire name."""
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")
                    if p) + b"\x00"


def _rr(name: bytes, rtype: int, rclass: int, ttl: int, rdata: bytes) -> bytes:
    return name + struct.pack("!HHIH", rtype, rclass, ttl, len(rdata)) + rdata


# ===========================================================================
# SNMP (v1 / v2c / v3)
# ===========================================================================
def _oid(dotted: str) -> bytes:
    """BER OBJECT IDENTIFIER (tag 0x06)."""
    arcs = [int(a) for a in dotted.strip(".").split(".")]
    body = b""
    for n in [40 * arcs[0] + arcs[1]] + arcs[2:]:
        chunk = [n & 0x7F]
        n >>= 7
        while n:
            chunk.append(0x80 | (n & 0x7F))
            n >>= 7
        body += bytes(reversed(chunk))
    return _der(0x06, body)


def _vb(oid: str, value: bytes) -> bytes:
    return _der_seq(_oid(oid), value)


_DEV = "sw-access01"                    # default device name


def _sysdescr(ep: Endpoints) -> str:
    """The device's system description (SNMP sysDescr, LLDP): meta, else a
    net-snmp / lldpd style Linux uname string, matching the default
    net-snmp sysObjectID."""
    return str(ep.meta.get("snmp_sysdescr", (
        f"Linux {_server_name(ep, _DEV)} 5.10.0-28-amd64 #1 SMP Debian "
        "5.10.209-2 (2024-01-31) x86_64")))


_NULL = b"\x05\x00"
_SYS = "1.3.6.1.2.1.1"                   # SNMPv2-MIB::system


def _sys_values(ep: Endpoints, uptime: int) -> List[tuple[str, bytes]]:
    """(OID, BER value) for system.1-7 of the agent (the server endpoint)."""
    m = ep.meta
    host = _server_name(ep, _DEV)
    descr = _sysdescr(ep)
    return [
        (f"{_SYS}.1.0", _der(0x04, descr.encode())),
        (f"{_SYS}.2.0", _oid(m.get("snmp_sysobjectid",
                                   "1.3.6.1.4.1.8072.3.2.10"))),
        (f"{_SYS}.3.0", _der_int(uptime, tag=0x43)),          # TimeTicks
        (f"{_SYS}.4.0", _der(0x04, str(m.get("snmp_syscontact",
                                             "noc@corp.local")).encode())),
        (f"{_SYS}.5.0", _der(0x04, str(m.get("snmp_sysname",
                                             host)).encode())),
        (f"{_SYS}.6.0", _der(0x04, str(m.get("snmp_syslocation",
                                             "Plant 1, Control Room")).encode())),
        (f"{_SYS}.7.0", _der_int(int(m.get("snmp_sysservices", 72)))),
    ]


def _snmp_pdu(tag: int, reqid: int, varbinds: List[bytes], err: int = 0,
              idx: int = 0) -> bytes:
    return _der(tag, _der_int(reqid) + _der_int(err) + _der_int(idx) +
                _der_seq(*varbinds))


def snmp_flow(ep: Endpoints, count: int) -> List[bytes]:
    """SNMP (161/UDP): an NMS (client) polling an agent (server) with v2c
    GetRequest for system.1-7 and a GetNext walk of the system group, plus
    the agent's SNMPv1 linkUp trap and v2c linkDown InformRequest (+ ack) to
    162. Community from ``ep.meta['snmp_community']`` (default "public")."""
    community = str(ep.meta.get("snmp_community", "public")).encode()
    uptime0 = int(ep.meta.get("snmp_uptime", 8640000))      # 1 day, in 1/100 s

    def msg(version: int, pdu: bytes) -> bytes:
        return _der_seq(_der_int(version), _der(0x04, community), pdu)

    frames = []
    mgr = _sport()
    for i in range(max(1, count)):
        sysv = _sys_values(ep, uptime0 + 100 * i)
        reqid = 0x2A5C0000 + i
        if i == 0:                                    # GetRequest, all of system
            req = [_vb(o, _NULL) for o, _ in sysv]
            rsp = [_vb(o, v) for o, v in sysv]
            req_tag = 0xA0
        else:                                         # GetNext walk
            k = (i - 1) % len(sysv)
            prev = _SYS if k == 0 else sysv[k - 1][0]
            req = [_vb(prev, _NULL)]
            rsp = [_vb(*sysv[k])]
            req_tag = 0xA1
        frames.append(P.udp_frame(ep, True, mgr, 161,
                                  msg(1, _snmp_pdu(req_tag, reqid, req)),
                                  ident=i))
        frames.append(P.udp_frame(ep, False, 161, mgr,
                                  msg(1, _snmp_pdu(0xA2, reqid, rsp)),
                                  ident=i))

    # Agent-originated notifications to the manager's 162.
    up = uptime0 + 100 * count
    if_index = "1.3.6.1.2.1.2.2.1.1.3"
    objid = _sys_values(ep, up)[1][1]                 # sysObjectID as enterprise
    trap = _der(0xA4, objid + _der(0x40, P.ip_to_bytes(ep.server_ip)) +
                _der_int(3) + _der_int(0) + _der_int(up, tag=0x43) +
                _der_seq(_vb(if_index, _der_int(3))))           # v1 linkUp
    agent = _sport()
    frames.append(P.udp_frame(ep, False, agent, 162, msg(0, trap)))
    inform_vbs = [
        _vb(f"{_SYS}.3.0", _der_int(up + 50, tag=0x43)),
        _vb("1.3.6.1.6.3.1.1.4.1.0", _oid("1.3.6.1.6.3.1.1.5.3")),  # linkDown
        _vb(if_index, _der_int(3)),
        _vb("1.3.6.1.2.1.2.2.1.7.3", _der_int(1)),      # ifAdminStatus up
        _vb("1.3.6.1.2.1.2.2.1.8.3", _der_int(2)),      # ifOperStatus down
    ]
    rid = 0x3B6D0001
    frames.append(P.udp_frame(ep, False, agent, 162,
                              msg(1, _snmp_pdu(0xA6, rid, inform_vbs))))
    frames.append(P.udp_frame(ep, True, 162, agent,
                              msg(1, _snmp_pdu(0xA2, rid, inform_vbs))))
    return frames


def snmpv3_flow(ep: Endpoints, count: int) -> List[bytes]:
    """SNMPv3 (161/UDP): USM engine discovery (empty-user reportable
    GetRequest answered by a Report carrying the agent's engineID, boots and
    time) followed by noAuthNoPriv GetRequests for sysDescr as user
    ``ep.meta['snmp_user']`` (default "monitor")."""
    # RFC 3411 engineID: enterprise 8072 (net-snmp), format 3 = MAC address
    engine = ep.meta.get("snmp_engineid")
    engine = (bytes.fromhex(engine) if isinstance(engine, str) else
              b"\x80\x00\x1f\x88\x03" + P.mac_to_bytes(ep.server_mac))
    user = str(ep.meta.get("snmp_user", "monitor")).encode()
    boots, etime = 3, 86400

    def v3(msgid: int, flags: int, eng: bytes, b: int, t: int, usr: bytes,
           ctx_engine: bytes, pdu: bytes) -> bytes:
        glob = _der_seq(_der_int(msgid), _der_int(65507),
                        _der(0x04, bytes([flags])), _der_int(3))   # USM
        usm = _der_seq(_der(0x04, eng), _der_int(b), _der_int(t),
                       _der(0x04, usr), _der(0x04, b""), _der(0x04, b""))
        scoped = _der_seq(_der(0x04, ctx_engine), _der(0x04, b""), pdu)
        return _der_seq(_der_int(3), glob, _der(0x04, usm), scoped)

    frames = []
    mgr = _sport()
    msgid = 0x1C2D0000 + (zlib.crc32(engine) & 0xFFFF)
    reqid = 0x4E5F0000
    disc = v3(msgid, 0x04, b"", 0, 0, b"", b"", _snmp_pdu(0xA0, reqid, []))
    report = v3(msgid, 0x00, engine, boots, etime, b"", engine, _snmp_pdu(
        0xA8, reqid, [_vb("1.3.6.1.6.3.15.1.1.4.0", _der_int(1, tag=0x41))]))
    frames.append(P.udp_frame(ep, True, mgr, 161, disc))
    frames.append(P.udp_frame(ep, False, 161, mgr, report))
    descr_oid, descr = _sys_values(ep, 0)[0]
    for i in range(max(0, count - 1)):
        mid, rid, t = msgid + 1 + i, reqid + 1 + i, etime + i
        get = v3(mid, 0x04, engine, boots, t, user, engine,
                 _snmp_pdu(0xA0, rid, [_vb(descr_oid, _NULL)]))
        rsp = v3(mid, 0x00, engine, boots, t, user, engine,
                 _snmp_pdu(0xA2, rid, [_vb(descr_oid, descr)]))
        frames.append(P.udp_frame(ep, True, mgr, 161, get, ident=i + 1))
        frames.append(P.udp_frame(ep, False, 161, mgr, rsp, ident=i + 1))
    return frames


# ===========================================================================
# Link-layer discovery: LLDP, CDP
# ===========================================================================
_DEFAULT_CISCO_SW = ("Cisco IOS Software, IE4000 Software "
                     "(IE4000-UNIVERSALK9-M), Version 15.2(7)E4, RELEASE "
                     "SOFTWARE (fc2)")


def lldp_flow(ep: Endpoints, count: int) -> List[bytes]:
    """LLDP (EtherType 0x88cc to 01:80:c2:00:00:0e): the server device's
    periodic LLDPDU — chassis ID (MAC), port ID, TTL, port/system name and
    description, capabilities and IPv4 management address. Link-local, so
    always untagged."""
    m = ep.meta
    name = str(m.get("lldp_sysname", _server_name(ep, _DEV)))
    descr = str(m.get("lldp_sysdescr", _sysdescr(ep)))
    port = str(m.get("lldp_port", "GigabitEthernet1/1"))
    caps, enabled = m.get("lldp_caps", (0x0014, 0x0004))  # bridge+router; bridge

    def tlv(t: int, v: bytes) -> bytes:
        return struct.pack("!H", (t << 9) | len(v)) + v

    mac = P.mac_to_bytes(ep.server_mac)
    mgmt = bytes([5, 1]) + P.ip_to_bytes(ep.server_ip) + \
        b"\x02" + struct.pack("!I", 1) + b"\x00"         # ifIndex 1, no OID
    pdu = (tlv(1, b"\x04" + mac) +                      # chassis: MAC
           tlv(2, b"\x05" + port.encode()) +            # port: interface name
           tlv(3, struct.pack("!H", 120)) +
           tlv(4, str(m.get("lldp_portdesc", "Uplink")).encode()) +
           tlv(5, name.encode()) +
           tlv(6, descr.encode()) +
           tlv(7, struct.pack("!HH", caps, enabled)) +
           tlv(8, mgmt) +
           tlv(0, b""))
    return [P.ethernet("01:80:c2:00:00:0e", ep.server_mac, 0x88CC, pdu)
            for _ in range(max(1, count))]


def _cdp_checksum(data: bytes) -> int:
    """RFC 1071 sum with Cisco's odd-length quirk: the trailing byte is added
    as a *signed* char in the low half of a final word (so 0xC8 counts as -56,
    0xFFC7 in one's complement) instead of being zero-padded at the end —
    what IOS sends and Wireshark validates."""
    if len(data) & 1:
        last = data[-1]
        word = (0xFF00 | last) - 1 if last & 0x80 else last
        data = data[:-1] + struct.pack("!H", word)
    return P.checksum16(data)


def cdp_flow(ep: Endpoints, count: int) -> List[bytes]:
    """CDPv2 (802.3 + LLC/SNAP to 01:00:0c:cc:cc:cc): device ID, IPv4
    addresses, port ID, capabilities, IOS software version, platform, native
    VLAN, duplex and management address from the server device."""
    m = ep.meta

    def tlv(t: int, v: bytes) -> bytes:
        return struct.pack("!HH", t, 4 + len(v)) + v

    addr = struct.pack("!IBBBH", 1, 1, 1, 0xCC, 4) + P.ip_to_bytes(ep.server_ip)
    body = (tlv(0x0001, str(m.get("cdp_device_id",
                                  _server_name(ep, _DEV))).encode()) +
            tlv(0x0002, addr) +
            tlv(0x0003, str(m.get("cdp_port", "GigabitEthernet1/1")).encode()) +
            tlv(0x0004, struct.pack("!I", 0x28)) +        # switch + IGMP
            tlv(0x0005, str(m.get("cdp_software", _DEFAULT_CISCO_SW)).encode()) +
            tlv(0x0006, str(m.get("cdp_platform",
                                  "cisco IE-4000-8GT4G-E")).encode()) +
            tlv(0x000A, struct.pack("!H", ep.vlan or 1)) +   # native VLAN
            tlv(0x000B, b"\x01") +                           # full duplex
            tlv(0x0016, addr))                               # mgmt address
    hdr = struct.pack("!BBH", 2, 180, 0)
    chk = _cdp_checksum(hdr + body)
    cdp = struct.pack("!BBH", 2, 180, chk) + body
    llc = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00" + cdp      # SNAP, Cisco, PID 0x2000
    # 802.3 length field in place of an EtherType; sent untagged
    frame = P.ethernet("01:00:0c:cc:cc:cc", ep.server_mac, len(llc), llc)
    return [frame for _ in range(max(1, count))]


# ===========================================================================
# Syslog
# ===========================================================================
_MON = "Oct"


def syslog_flow(ep: Endpoints, count: int) -> List[bytes]:
    """Syslog (514/UDP): network gear / RTAC (client) logging to a collector
    (server), alternating RFC 3164 (BSD) and RFC 5424 messages — link
    up/down, config changes, logins. ``ep.meta['syslog_format']`` = "3164" |
    "5424" | "mixed" (default)."""
    m = ep.meta
    host = str(m.get("syslog_host", m.get("nbname", "sw-access01")))
    fmt = str(m.get("syslog_format", "mixed"))
    me = ep.client_ip
    bsd = [
        (23, 3, "%LINK-3-UPDOWN: Interface GigabitEthernet1/{p}, changed "
                "state to {st}"),
        (23, 5, "%SYS-5-CONFIG_I: Configured from console by admin on vty0 "
                f"({me})"),
        (4, 6, "sshd[{pid}]: Accepted password for admin from 10.10.10.{p} "
               "port 5{pid} ssh2"),
        (23, 4, "%SW_MATM-4-MACFLAP_NOTIF: Host 0011.2233.44{p:02d} in vlan 1 "
                "is flapping between port Gi1/{p} and port Gi1/8"),
    ]
    ietf = [
        (23, 5, "RTAC", "ACCESS", "User 'operator' logged in via HTTPS"),
        (23, 4, "RTAC", "ALARM", "Communication failure on port {p} "
                                 "(DNP3 outstation 1)"),
        (23, 6, "RTAC", "SETTINGS", "Settings group 1 activated"),
        (16, 3, "linkmgr", "LINKUPDOWN", "Interface port {p} changed state "
                                         "to {st}"),
    ]
    frames = []
    for i in range(max(1, count)):
        p, pid, st = 1 + i % 8, 1200 + i, ("up", "down")[i % 2]
        sec = i % 60
        use_5424 = fmt == "5424" or (fmt == "mixed" and i % 2)
        if use_5424:
            fac, sev, app, msgid, text = ietf[(i // 2) % len(ietf)]
            ts = f"2025-10-06T12:00:{sec:02d}.{(i * 37) % 1000:03d}Z"
            sd = (f'[meta sequenceId="{i + 1}"][origin ip="{me}" '
                  'software="TGT"]')
            line = (f"<{fac * 8 + sev}>1 {ts} {host} {app} {pid} {msgid} {sd} "
                    + text.format(p=p, st=st))
        else:
            fac, sev, text = bsd[(i // 2) % len(bsd)]
            line = (f"<{fac * 8 + sev}>{_MON} {6:2d} 12:00:{sec:02d} {host} "
                    + text.format(p=p, pid=pid, st=st))
        frames.append(P.udp_frame(ep, True, 514, 514, line.encode(), ident=i))
    return frames


# ===========================================================================
# Name / service discovery: mDNS, SSDP, LLMNR, NBNS
# ===========================================================================
def mdns_flow(ep: Endpoints, count: int) -> List[bytes]:
    """mDNS (224.0.0.251:5353): a client's PTR browse for _http._tcp /
    _workstation._tcp and the server's multicast answer (PTR + SRV + TXT +
    A) naming the host."""
    host = _server_name(ep, "hmi01").replace(".", "-")
    inst_name = str(ep.meta.get("mdns_name", host))
    mac = ep.server_mac.lower()
    services = [("_http._tcp", inst_name, 80, [b"path=/"]),
                ("_workstation._tcp", f"{host} [{mac}]", 9, [b""])]
    group, gmac = "224.0.0.251", _mcast_mac("224.0.0.251")
    frames = []
    for i in range(max(1, count)):
        svc, inst, port, txt = services[i % len(services)]
        svc_n = _dns_name(f"{svc}.local")
        inst_n = bytes([len(inst.encode())]) + inst.encode() + svc_n
        host_n = _dns_name(f"{host}.local")
        # Query IDs are nonzero (RFC 6762 only says SHOULD be zero) so a
        # repeated browse is not flagged as a DNS retransmission.
        query = struct.pack("!HHHHHH", i + 1, 0, 1, 0, 0, 0) + svc_n + \
            struct.pack("!HH", 12, 1)                    # PTR IN
        frames.append(_udp_to(ep, True, 5353, 5353, group, gmac, query,
                              ttl=255, ident=i))
        txt_rd = b"".join(bytes([len(t)]) + t for t in txt)
        rsp = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 3) + \
            _rr(svc_n, 12, 1, 4500, inst_n) + \
            _rr(inst_n, 33, 0x8001, 120,
                struct.pack("!HHH", 0, 0, port) + host_n) + \
            _rr(inst_n, 16, 0x8001, 4500, txt_rd) + \
            _rr(host_n, 1, 0x8001, 120, P.ip_to_bytes(ep.server_ip))
        frames.append(_udp_to(ep, False, 5353, 5353, group, gmac, rsp,
                              ttl=255, ident=i))
    return frames


def ssdp_flow(ep: Endpoints, count: int) -> List[bytes]:
    """SSDP (239.255.255.250:1900): a control point's M-SEARCH, the device's
    unicast 200 OK and its multicast NOTIFY ssdp:alive, both carrying the
    SERVER banner (``ep.meta['ssdp_server']``) and a MAC-derived UUID."""
    server = str(ep.meta.get("ssdp_server", "Linux/5.10 UPnP/1.0 Portable "
                             "SDK for UPnP devices/1.14.18"))
    uuid = "uuid:2f402f80-da50-11e1-9b23-" + \
        P.mac_to_bytes(ep.server_mac).hex()
    loc = f"http://{ep.server_ip}:49152/description.xml"
    group, gmac = "239.255.255.250", _mcast_mac("239.255.255.250")
    frames = []
    for i in range(max(1, count)):
        st = ("ssdp:all", "upnp:rootdevice")[i % 2]
        cp = _sport()
        search = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
                  f"MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {st}\r\n\r\n")
        frames.append(_udp_to(ep, True, cp, 1900, group, gmac,
                              search.encode(), ttl=2, ident=i))
        ok = ("HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nEXT:\r\n"
              f"LOCATION: {loc}\r\nSERVER: {server}\r\n"
              f"ST: upnp:rootdevice\r\nUSN: {uuid}::upnp:rootdevice\r\n\r\n")
        frames.append(P.udp_frame(ep, False, 1900, cp, ok.encode(), ident=i))
        notify = ("NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
                  f"CACHE-CONTROL: max-age=1800\r\nLOCATION: {loc}\r\n"
                  f"NT: upnp:rootdevice\r\nNTS: ssdp:alive\r\n"
                  f"SERVER: {server}\r\nUSN: {uuid}::upnp:rootdevice\r\n\r\n")
        frames.append(_udp_to(ep, False, 1900, 1900, group, gmac,
                              notify.encode(), ttl=2, ident=i))
    return frames


def llmnr_flow(ep: Endpoints, count: int) -> List[bytes]:
    """LLMNR (224.0.0.252:5355): a Windows client's multicast A query for a
    single-label name and the owner's unicast answer."""
    name = _server_name(ep, "fileserver").split(".")[0].lower()
    group, gmac = "224.0.0.252", _mcast_mac("224.0.0.252")
    frames = []
    for i in range(max(1, count)):
        tid = (0x7A00 + i) & 0xFFFF
        q = _dns_name(name) + struct.pack("!HH", 1, 1)
        cp = _sport()
        query = struct.pack("!HHHHHH", tid, 0x0000, 1, 0, 0, 0) + q
        frames.append(_udp_to(ep, True, cp, 5355, group, gmac, query,
                              ttl=1, ident=i))
        rsp = struct.pack("!HHHHHH", tid, 0x8000, 1, 1, 0, 0) + q + \
            _rr(_dns_name(name), 1, 1, 30, P.ip_to_bytes(ep.server_ip))
        frames.append(P.udp_frame(ep, False, 5355, cp, rsp, ident=i))
    return frames


def _nb_name(name: str, suffix: int) -> bytes:
    """NetBIOS first-level encoded name (RFC 1001 §14.1)."""
    raw = name.upper()[:15].ljust(15).encode() + bytes([suffix])
    if name == "*":
        raw = b"*" + bytes(15)
    enc = b"".join(bytes([(c >> 4) + 0x41, (c & 0x0F) + 0x41]) for c in raw)
    return b"\x20" + enc + b"\x00"


def nbns_flow(ep: Endpoints, count: int) -> List[bytes]:
    """NBNS (137/UDP): broadcast name query for the server's <20> name with
    the owner's positive response, and NBSTAT node-status queries answered
    with the server's name table and MAC (unit ID)."""
    host = _server_name(ep, "FILESERVER").split(".")[0].upper()[:15]
    workgroup = str(ep.meta.get("realm", "WORKGROUP")).split(".")[0].upper()
    bcast = ".".join(ep.client_ip.split(".")[:3] + ["255"])   # assume /24
    frames = []
    for i in range(max(1, count)):
        tid = (0x8100 + i) & 0xFFFF
        if i % 2 == 0:                                   # name query (B-node)
            q = _nb_name(host, 0x20) + struct.pack("!HH", 0x20, 1)
            query = struct.pack("!HHHHHH", tid, 0x0110, 1, 0, 0, 0) + q
            frames.append(_udp_to(ep, True, 137, 137, bcast,
                                  "ff:ff:ff:ff:ff:ff", query, ident=i))
            rsp = struct.pack("!HHHHHH", tid, 0x8500, 0, 1, 0, 0) + \
                _rr(_nb_name(host, 0x20), 0x20, 1, 300000,
                    b"\x00\x00" + P.ip_to_bytes(ep.server_ip))
            frames.append(P.udp_frame(ep, False, 137, 137, rsp, ident=i))
        else:                                            # NBSTAT (node status)
            star = _nb_name("*", 0)
            query = struct.pack("!HHHHHH", tid, 0x0000, 1, 0, 0, 0) + star + \
                struct.pack("!HH", 0x21, 1)
            frames.append(P.udp_frame(ep, True, 137, 137, query, ident=i))
            names = [(host, 0x00, 0x0400), (workgroup, 0x00, 0x8400),
                     (host, 0x20, 0x0400)]
            table = bytes([len(names)]) + b"".join(
                n[:15].ljust(15).encode() + bytes([sfx]) +
                struct.pack("!H", fl) for n, sfx, fl in names)
            stats = P.mac_to_bytes(ep.server_mac) + bytes(40)
            rsp = struct.pack("!HHHHHH", tid, 0x8400, 0, 1, 0, 0) + \
                _rr(star, 0x21, 1, 0, table + stats)
            frames.append(P.udp_frame(ep, False, 137, 137, rsp, ident=i))
    return frames


# ===========================================================================
# MQTT / Sparkplug B
# ===========================================================================
def _mqtt(first: int, body: bytes) -> bytes:
    """MQTT control packet: fixed header + variable-length remaining length."""
    n, rl = len(body), b""
    while True:
        b, n = n & 0x7F, n >> 7
        rl += bytes([b | (0x80 if n else 0)])
        if not n:
            break
    return bytes([first]) + rl + body


def _ms(b: bytes) -> bytes:
    """MQTT UTF-8 string / binary data: 2-byte length prefix."""
    return struct.pack("!H", len(b)) + b


def _mqtt_connect(cid: bytes, keepalive: int, will: tuple | None = None,
                  user: bytes | None = None, pw: bytes | None = None) -> bytes:
    flags, payload = 0x02, _ms(cid)                      # clean session
    if will:
        topic, msg, qos = will
        flags |= 0x04 | (qos << 3)
        payload += _ms(topic) + _ms(msg)
    if user is not None:
        flags |= 0x80
        payload += _ms(user)
        if pw is not None:
            flags |= 0x40
            payload += _ms(pw)
    return _mqtt(0x10, _ms(b"MQTT") + bytes([4, flags]) +
                 struct.pack("!H", keepalive) + payload)


def _mqtt_publish(topic: bytes, payload: bytes, qos: int = 0,
                  pid: int = 0) -> bytes:
    vh = _ms(topic) + (struct.pack("!H", pid) if qos else b"")
    return _mqtt(0x30 | (qos << 1), vh + payload)


_PINGREQ, _PINGRESP, _DISCONNECT = b"\xc0\x00", b"\xd0\x00", b"\xe0\x00"
_CONNACK = b"\x20\x02\x00\x00"


def _mqtt_creds(ep: Endpoints) -> dict:
    u, p = ep.meta.get("mqtt_user"), ep.meta.get("mqtt_password")
    return {"user": None if u is None else str(u).encode(),
            "pw": None if p is None else str(p).encode()}


def mqtt_flow(ep: Endpoints, count: int) -> List[bytes]:
    """MQTT 3.1.1 (1883): an IIoT client CONNECTs (client id, keepalive),
    SUBSCRIBEs to a command topic, PUBLISHes telemetry at QoS 0 and QoS 1
    (PUBACKed), keeps alive with PINGREQ/PINGRESP and DISCONNECTs."""
    cid = str(ep.meta.get("mqtt_client_id",
                          ep.meta.get("nbname", "edge-gw01"))).encode()
    base = str(ep.meta.get("mqtt_topic", "plant/line1")).encode()
    keepalive = int(ep.meta.get("mqtt_keepalive", 60))
    pid = 1
    sub = _mqtt(0x82, struct.pack("!H", pid) + _ms(base + b"/cmd/#") + b"\x01")
    exchanges = [(_mqtt_connect(cid, keepalive, **_mqtt_creds(ep)), _CONNACK),
                 (sub, _mqtt(0x90, struct.pack("!H", pid) + b"\x01"))]
    tags = (b"temperature", b"pressure", b"flow", b"level")
    for i in range(max(1, count)):
        tag = tags[i % len(tags)]
        body = (b'{"ts":%d,"value":%.2f}' %
                (_EPOCH_MS + 1000 * i, 20.0 + 0.25 * i))
        if i % 2 == 0:                                   # QoS 0, fire and forget
            exchanges.append((_mqtt_publish(base + b"/" + tag, body), b""))
        else:                                            # QoS 1 + PUBACK
            pid += 1
            exchanges.append((_mqtt_publish(base + b"/" + tag, body, 1, pid),
                              _mqtt(0x40, struct.pack("!H", pid))))
        if i % 4 == 3:
            exchanges.append((_PINGREQ, _PINGRESP))
    exchanges.append((_DISCONNECT, b""))
    return _tcp_flow(ep, _sport(), 1883, exchanges)


# --- Sparkplug B: hand-encoded protobuf (sparkplug_b.proto Payload) ----------
def _pb_varint(n: int) -> bytes:
    n &= (1 << 64) - 1
    out = b""
    while True:
        b, n = n & 0x7F, n >> 7
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            return out


def _pb(field: int, wire: int, value: bytes) -> bytes:
    return _pb_varint(field << 3 | wire) + value


def _pb_uint(field: int, v: int) -> bytes:
    return _pb(field, 0, _pb_varint(v))


def _pb_len(field: int, b: bytes) -> bytes:
    return _pb(field, 2, _pb_varint(len(b)) + b)


# Sparkplug DataType -> (Metric value field, encoder)
_SPB_TYPES = {
    "Int32": (3, lambda v: _pb_uint(10, v)),
    "UInt64": (8, lambda v: _pb_uint(11, v)),
    "Float": (9, lambda v: _pb(12, 5, struct.pack("<f", v))),
    "Double": (10, lambda v: _pb(13, 1, struct.pack("<d", v))),
    "Boolean": (11, lambda v: _pb_uint(14, 1 if v else 0)),
    "String": (12, lambda v: _pb_len(15, v.encode())),
}


def _spb_metric(name: str, dtype: str, value, ts: int) -> bytes:
    code, enc = _SPB_TYPES[dtype]
    return _pb_len(1, name.encode()) + _pb_uint(3, ts) + _pb_uint(4, code) + \
        enc(value)


def _spb_payload(ts: int, metrics: List[tuple], seq: int | None) -> bytes:
    out = _pb_uint(1, ts)
    for name, dtype, value in metrics:
        out += _pb_len(2, _spb_metric(name, dtype, value, ts))
    if seq is not None:
        out += _pb_uint(3, seq)
    return out


def sparkplug_flow(ep: Endpoints, count: int) -> List[bytes]:
    """MQTT Sparkplug B (1883): an edge node CONNECTs with an NDEATH will,
    subscribes to its NCMD topic, publishes NBIRTH then NDATA on
    ``spBv1.0/<group>/NDATA/<node>`` with protobuf-encoded metrics, and
    signs off with NDEATH + DISCONNECT. Group/node from
    ``ep.meta['sparkplug_group'|'sparkplug_node']``."""
    group = str(ep.meta.get("sparkplug_group", "Plant1"))
    node = str(ep.meta.get("sparkplug_node",
                           ep.meta.get("nbname", "EdgeNode1")))
    topic = lambda t: f"spBv1.0/{group}/{t}/{node}".encode()   # noqa: E731
    bdseq = 0
    death = _spb_payload(_EPOCH_MS, [("bdSeq", "UInt64", bdseq)], None)
    cid = str(ep.meta.get("mqtt_client_id", f"{group}-{node}")).encode()
    sub = _mqtt(0x82, struct.pack("!H", 1) + _ms(topic("NCMD") + b"/#") +
                b"\x01")
    exchanges = [
        (_mqtt_connect(cid, 30, will=(topic("NDEATH"), death, 1),
                       **_mqtt_creds(ep)), _CONNACK),
        (sub, _mqtt(0x90, struct.pack("!H", 1) + b"\x01")),
    ]
    birth = _spb_payload(_EPOCH_MS, [
        ("bdSeq", "UInt64", bdseq),
        ("Node Control/Rebirth", "Boolean", False),
        ("Properties/Hardware Make", "String", "TGT"),
        ("Line1/Temperature", "Float", 21.5),
        ("Line1/Pressure", "Double", 101.325),
        ("Line1/Running", "Boolean", True),
        ("Line1/Count", "Int32", 0),
    ], 0)
    exchanges.append((_mqtt_publish(topic("NBIRTH"), birth), b""))
    for i in range(max(1, count)):
        ts = _EPOCH_MS + 1000 * (i + 1)
        data = _spb_payload(ts, [
            ("Line1/Temperature", "Float", 21.5 + 0.1 * i),
            ("Line1/Count", "Int32", 10 * (i + 1)),
        ], (i + 1) % 256)
        exchanges.append((_mqtt_publish(topic("NDATA"), data), b""))
        if i % 4 == 3:
            exchanges.append((_PINGREQ, _PINGRESP))
    exchanges.append((_mqtt_publish(topic("NDEATH"), death, 1, 2),
                      _mqtt(0x40, struct.pack("!H", 2))))
    exchanges.append((_DISCONNECT, b""))
    return _tcp_flow(ep, _sport(), 1883, exchanges)


# ===========================================================================
# Registry
# ===========================================================================
_reg("snmp", "SNMP v1/v2c", "IT", "161", "udp", snmp_flow,
     "v2c Get/GetNext of system group (sysDescr, sysName…), v1 trap + inform")
_reg("snmpv3", "SNMPv3", "IT", "161", "udp", snmpv3_flow,
     "USM engine discovery (Report with engineID) + noAuthNoPriv Get")
_reg("lldp", "LLDP", "IT", "-", "l2", lldp_flow,
     "LLDPDU: chassis/port ID, system name + description, mgmt address")
_reg("cdp", "CDP", "IT", "-", "l2", cdp_flow,
     "CDPv2: device ID, IOS version, platform, addresses, port, capabilities")
_reg("syslog", "Syslog", "IT", "514", "udp", syslog_flow,
     "RFC 3164 + RFC 5424 messages from switches / RTACs")
_reg("mdns", "mDNS", "IT", "5353", "udp", mdns_flow,
     "PTR browse + SRV/TXT/A answer for _http._tcp / _workstation._tcp")
_reg("ssdp", "SSDP / UPnP", "IT", "1900", "udp", ssdp_flow,
     "M-SEARCH, 200 OK + NOTIFY ssdp:alive with SERVER banner")
_reg("llmnr", "LLMNR", "IT", "5355", "udp", llmnr_flow,
     "Multicast name query + unicast answer")
_reg("nbns", "NBNS name query", "IT", "137", "udp", nbns_flow,
     "Broadcast name query + NBSTAT node status (name table, MAC)")
_reg("mqtt", "MQTT", "IT", "1883", "tcp", mqtt_flow,
     "CONNECT/SUBSCRIBE, PUBLISH QoS0/QoS1 + PUBACK, PING, DISCONNECT")
_reg("sparkplug", "MQTT Sparkplug B", "OT", "1883", "tcp", sparkplug_flow,
     "spBv1.0 NBIRTH/NDATA/NDEATH with protobuf metrics")
