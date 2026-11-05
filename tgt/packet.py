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
         ttl: int = 64, ident: int = 0, dscp: int = 0,
         df: bool = True) -> bytes:
    ver_ihl = (4 << 4) | 5
    tos = (dscp & 0x3F) << 2
    total_len = 20 + len(payload)
    flags_frag = 0x4000 if df else 0  # Don't Fragment
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
        flags: int, payload: bytes = b"", window: int = 8192,
        options: bytes = b"") -> bytes:
    if len(options) % 4:                 # pad options to a 32-bit boundary
        options += b"\x00" * (4 - len(options) % 4)
    data_off = (5 + len(options) // 4) << 4
    seg = struct.pack(
        "!HHIIBBHHH",
        sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
        data_off, flags, window & 0xFFFF, 0, 0,
    ) + options + payload
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
    ``stack_client``/``stack_server`` name each side's TCP/IP stack
    (:mod:`tgt.stacks`; "" = Windows client / port-typical server).
    """
    client_mac: str = "02:00:00:00:00:01"
    client_ip: str = "10.10.10.10"
    server_mac: str = "02:00:00:00:00:02"
    server_ip: str = "10.10.10.20"
    vlan: int | None = None
    ttl_client: int = 64
    ttl_server: int = 64
    meta: dict = field(default_factory=dict)
    stack_client: str = ""
    stack_server: str = ""


def ip_frame(ep: Endpoints, from_client: bool, proto: int, l4: bytes,
             ttl: int | None = None, ident: int = 0,
             df: bool = True) -> bytes:
    if ttl is None:
        ttl = ep.ttl_client if from_client else ep.ttl_server
    if from_client:
        s_mac, d_mac, s_ip, d_ip = (ep.client_mac, ep.server_mac,
                                    ep.client_ip, ep.server_ip)
    else:
        s_mac, d_mac, s_ip, d_ip = (ep.server_mac, ep.client_mac,
                                    ep.server_ip, ep.client_ip)
    pkt = ipv4(s_ip, d_ip, proto, l4, ttl=ttl, ident=ident, df=df)
    return ethernet(d_mac, s_mac, ETH_P_IP, pkt, vlan=ep.vlan)


def udp_frame(ep: Endpoints, from_client: bool, sport: int, dport: int,
              payload: bytes, ident: int = 0) -> bytes:
    s_ip = ep.client_ip if from_client else ep.server_ip
    d_ip = ep.server_ip if from_client else ep.client_ip
    seg = udp(s_ip, d_ip, sport, dport, payload)
    return ip_frame(ep, from_client, IPPROTO_UDP, seg, ident=ident)


def frame_ips(frame: bytes) -> tuple[str, str] | None:
    """(src_ip, dst_ip) of an IPv4 frame (802.1Q-tagged or not), else None."""
    off = 14
    etype = struct.unpack("!H", frame[12:14])[0]
    if etype == ETH_P_VLAN:
        etype = struct.unpack("!H", frame[16:18])[0]
        off = 18
    if etype != ETH_P_IP or len(frame) < off + 20:
        return None
    return (".".join(map(str, frame[off + 12:off + 16])),
            ".".join(map(str, frame[off + 16:off + 20])))


def rewrite_l2(frame: bytes, src_mac: str, dst_mac: str, vlan: int | None,
               ttl: int | None = None) -> bytes:
    """Re-address a frame as it appears on another hop of a routed path.

    New MACs, the other segment's 802.1Q tag and (for IPv4) a new TTL with the
    header checksum recomputed. TCP/UDP checksums do not cover the TTL, so the
    L4 segment is carried over untouched. An incoming tag's priority (PCP) and
    DEI bits are kept on the new tag — GOOSE / SV / PROFINET RT rely on them —
    and a priority-tagged frame re-addressed with ``vlan=None`` stays
    priority-tagged (VID 0).
    """
    etype = struct.unpack("!H", frame[12:14])[0]
    body = frame[14:]
    prio = 0                                    # PCP + DEI (top 4 TCI bits)
    if etype == ETH_P_VLAN:
        prio = struct.unpack("!H", frame[14:16])[0] & 0xF000
        etype = struct.unpack("!H", frame[16:18])[0]
        body = frame[18:]
    if etype == ETH_P_IP and ttl is not None and len(body) >= 20:
        ihl = (body[0] & 0x0F) * 4
        hdr = bytearray(body[:ihl])
        hdr[8] = max(1, min(255, ttl))
        hdr[10:12] = b"\x00\x00"
        hdr[10:12] = struct.pack("!H", checksum16(bytes(hdr)))
        body = bytes(hdr) + body[ihl:]
    if prio:
        return (mac_to_bytes(dst_mac) + mac_to_bytes(src_mac) +
                struct.pack("!HHH", ETH_P_VLAN, prio | ((vlan or 0) & 0x0FFF),
                            etype) + body)
    return ethernet(dst_mac, src_mac, etype, body, vlan=vlan)


def set_ip_id(frame: bytes, ident: int) -> bytes:
    """``frame`` with its IPv4 Identification set to ``ident`` (header
    checksum recomputed; L4 checksums do not cover it). Non-IPv4 frames are
    returned unchanged."""
    off = 18 if frame[12:14] == b"\x81\x00" else 14
    if frame[off - 2:off] != b"\x08\x00" or len(frame) < off + 20:
        return frame
    ihl = (frame[off] & 0x0F) * 4
    hdr = bytearray(frame[off:off + ihl])
    hdr[4:6] = struct.pack("!H", ident & 0xFFFF)
    hdr[10:12] = b"\x00\x00"
    hdr[10:12] = struct.pack("!H", checksum16(bytes(hdr)))
    return frame[:off] + bytes(hdr) + frame[off + ihl:]


def rewrite_ips(frame: bytes, src_ip: str | None = None,
                dst_ip: str | None = None, ttl_delta: int = 0) -> bytes:
    """``frame`` with its IPv4 source and/or destination replaced, as a NAT
    router forwards it: the IP header checksum and the TCP/UDP checksum (whose
    pseudo-header covers the addresses) are recomputed, and ``ttl_delta``
    (e.g. -1 for the router hop) is applied to the TTL. Ethernet padding is
    kept; non-IPv4 frames are returned unchanged."""
    off = 18 if frame[12:14] == b"\x81\x00" else 14
    if frame[off - 2:off] != b"\x08\x00" or len(frame) < off + 20:
        return frame
    ihl = (frame[off] & 0x0F) * 4
    total = struct.unpack("!H", frame[off + 2:off + 4])[0]
    hdr = bytearray(frame[off:off + ihl])
    if src_ip:
        hdr[12:16] = ip_to_bytes(src_ip)
    if dst_ip:
        hdr[16:20] = ip_to_bytes(dst_ip)
    if ttl_delta:
        hdr[8] = max(1, min(255, hdr[8] + ttl_delta))
    hdr[10:12] = b"\x00\x00"
    hdr[10:12] = struct.pack("!H", checksum16(bytes(hdr)))
    l4 = bytearray(frame[off + ihl:off + total])
    frag = struct.unpack("!H", bytes(hdr[6:8]))[0] & 0x1FFF
    proto, s, d = hdr[9], hdr[12:16], hdr[16:20]
    at = {IPPROTO_TCP: 16, IPPROTO_UDP: 6}.get(proto)
    if at is not None and not frag and len(l4) >= at + 2 and \
            (proto != IPPROTO_UDP or l4[6:8] != b"\x00\x00"):
        l4[at:at + 2] = b"\x00\x00"
        pseudo = bytes(s) + bytes(d) + struct.pack("!BBH", 0, proto, len(l4))
        chk = checksum16(pseudo + bytes(l4))
        if proto == IPPROTO_UDP and chk == 0:
            chk = 0xFFFF
        l4[at:at + 2] = struct.pack("!H", chk)
    return frame[:off] + bytes(hdr) + bytes(l4) + frame[off + total:]
