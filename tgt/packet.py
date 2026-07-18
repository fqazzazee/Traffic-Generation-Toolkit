"""Raw packet construction — pure stdlib, no scapy required.

Everything here returns / consumes raw ``bytes``.  A fully built frame is an
Ethernet frame (layer 2) that can be handed straight to an ``AF_PACKET`` raw
socket or written into a pcap file.

The helpers are deliberately small and explicit so the byte-level patterns that
DPI engines (Zeek, Suricata, Claroty CTD, …) key on stay easy to read and tweak.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# EtherTypes / IP protocol numbers
# ---------------------------------------------------------------------------
ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
ETH_P_VLAN = 0x8100

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17

# TCP flag bits
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20


# ---------------------------------------------------------------------------
# Address helpers
# ---------------------------------------------------------------------------
def mac_to_bytes(mac: str) -> bytes:
    """"aa:bb:cc:dd:ee:ff" -> b'\\xaa\\xbb...'."""
    parts = mac.replace("-", ":").split(":")
    if len(parts) != 6:
        raise ValueError(f"invalid MAC address: {mac!r}")
    return bytes(int(p, 16) for p in parts)


def bytes_to_mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def ip_to_bytes(ip: str) -> bytes:
    parts = ip.split(".")
    if len(parts) != 4:
        raise ValueError(f"invalid IPv4 address: {ip!r}")
    return bytes(int(p) & 0xFF for p in parts)


def checksum16(data: bytes) -> int:
    """Standard Internet 16-bit one's-complement checksum (RFC 1071)."""
    if len(data) & 1:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


# ---------------------------------------------------------------------------
# Layer 2 / 3 / 4 builders
# ---------------------------------------------------------------------------
def ethernet(dst_mac: str, src_mac: str, ethertype: int, payload: bytes,
             vlan: int | None = None) -> bytes:
    hdr = mac_to_bytes(dst_mac) + mac_to_bytes(src_mac)
    if vlan is not None:
        # 802.1Q tag: TPID + PCP/DEI/VID
        hdr += struct.pack("!HH", ETH_P_VLAN, vlan & 0x0FFF)
    hdr += struct.pack("!H", ethertype)
    return hdr + payload


def ipv4(src_ip: str, dst_ip: str, proto: int, payload: bytes,
         ttl: int = 64, ident: int = 0, dscp: int = 0) -> bytes:
    ver_ihl = (4 << 4) | 5
    tos = (dscp & 0x3F) << 2
    total_len = 20 + len(payload)
    flags_frag = 0x4000  # Don't Fragment
    header = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, tos, total_len, ident & 0xFFFF, flags_frag,
        ttl, proto, 0, ip_to_bytes(src_ip), ip_to_bytes(dst_ip),
    )
    chk = checksum16(header)
    header = header[:10] + struct.pack("!H", chk) + header[12:]
    return header + payload


def _l4_checksum(src_ip: str, dst_ip: str, proto: int, segment: bytes) -> int:
    pseudo = ip_to_bytes(src_ip) + ip_to_bytes(dst_ip) + struct.pack(
        "!BBH", 0, proto, len(segment))
    return checksum16(pseudo + segment)


def tcp(src_ip: str, dst_ip: str, sport: int, dport: int, seq: int, ack: int,
        flags: int, payload: bytes = b"", window: int = 8192) -> bytes:
    data_off = (5 << 4)  # 5 * 4 = 20 byte header, no options
    seg = struct.pack(
        "!HHIIBBHHH",
        sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
        data_off, flags, window, 0, 0,
    ) + payload
    chk = _l4_checksum(src_ip, dst_ip, IPPROTO_TCP, seg)
    seg = seg[:16] + struct.pack("!H", chk) + seg[18:]
    return seg


def udp(src_ip: str, dst_ip: str, sport: int, dport: int,
        payload: bytes = b"") -> bytes:
    length = 8 + len(payload)
    seg = struct.pack("!HHHH", sport, dport, length, 0) + payload
    chk = _l4_checksum(src_ip, dst_ip, IPPROTO_UDP, seg)
    if chk == 0:
        chk = 0xFFFF  # UDP: 0 means "no checksum", so use all-ones instead
    seg = seg[:6] + struct.pack("!H", chk) + seg[8:]
    return seg


def icmp_echo(identifier: int, seq: int, payload: bytes = b"") -> bytes:
    hdr = struct.pack("!BBHHH", 8, 0, 0, identifier & 0xFFFF, seq & 0xFFFF)
    body = hdr + payload
    chk = checksum16(body)
    return body[:2] + struct.pack("!H", chk) + body[4:]


def arp(op: int, src_mac: str, src_ip: str, dst_mac: str, dst_ip: str) -> bytes:
    return struct.pack(
        "!HHBBH6s4s6s4s",
        1, ETH_P_IP, 6, 4, op,
        mac_to_bytes(src_mac), ip_to_bytes(src_ip),
        mac_to_bytes(dst_mac), ip_to_bytes(dst_ip),
    )


# ---------------------------------------------------------------------------
# Convenience wrappers that produce complete Ethernet frames
# ---------------------------------------------------------------------------
@dataclass
class Endpoints:
    """The two hosts a flow runs between (client drives, server responds).

    ``ttl_client``/``ttl_server`` and ``meta`` let a flow carry an OS/device
    fingerprint (Windows TTL 128 vs Linux 64, HTTP User-Agent, SMB dialect,
    vendor strings) so an analyser can classify assets and flag legacy ones.
    """
    client_mac: str = "02:00:00:00:00:01"
    client_ip: str = "10.10.10.10"
    server_mac: str = "02:00:00:00:00:02"
    server_ip: str = "10.10.10.20"
    vlan: int | None = None
    ttl_client: int = 64
    ttl_server: int = 64
    meta: dict = field(default_factory=dict)


def ip_frame(ep: Endpoints, from_client: bool, proto: int, l4: bytes,
             ttl: int | None = None, ident: int = 0) -> bytes:
    if ttl is None:
        ttl = ep.ttl_client if from_client else ep.ttl_server
    if from_client:
        s_mac, d_mac, s_ip, d_ip = (ep.client_mac, ep.server_mac,
                                    ep.client_ip, ep.server_ip)
    else:
        s_mac, d_mac, s_ip, d_ip = (ep.server_mac, ep.client_mac,
                                    ep.server_ip, ep.client_ip)
    pkt = ipv4(s_ip, d_ip, proto, l4, ttl=ttl, ident=ident)
    return ethernet(d_mac, s_mac, ETH_P_IP, pkt, vlan=ep.vlan)


def udp_frame(ep: Endpoints, from_client: bool, sport: int, dport: int,
              payload: bytes, ident: int = 0) -> bytes:
    s_ip = ep.client_ip if from_client else ep.server_ip
    d_ip = ep.server_ip if from_client else ep.client_ip
    seg = udp(s_ip, d_ip, sport, dport, payload)
    return ip_frame(ep, from_client, IPPROTO_UDP, seg, ident=ident)
