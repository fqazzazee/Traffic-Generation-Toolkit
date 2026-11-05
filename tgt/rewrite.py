"""Re-address captured frames for replay: IPv4 / MAC remap and VLAN retag.

``tgt run --replay FILE`` can put a customer capture onto a lab segment that
uses different addressing::

    --remap-ip 192.168.1.10=10.100.10.21,192.168.1.11=10.100.10.22
    --remap-subnet 192.168.1.0/24=10.100.10.0/24     (host bits kept)
    --remap-mac 00:1d:9c:aa:bb:cc=00:1d:9c:11:22:33
    --vlan 30            (retag: replace/add the outer 802.1Q id; 0 = untag)

Explicit ``--remap-ip`` entries win over subnet rules; of several subnet rules
the longest prefix wins. IPv4 source/destination addresses are rewritten in
the IP header and in ARP; the IP header checksum and the TCP/UDP checksum are
recomputed for complete datagrams (a capture with offloaded, invalid
checksums comes out valid) and updated incrementally (RFC 1624) for
fragments or snaplen-truncated packets, whose payload is not all there.
UDP datagrams sent without a checksum (0) keep none. IPv6 and the inner
headers quoted in ICMP errors are left as they are.
"""
from __future__ import annotations

import ipaddress
import struct
from typing import Dict, Iterable, List, Optional, Tuple

from . import packet as P

_VLAN_TPIDS = (0x8100, 0x88A8, 0x9100)


class RewriteError(ValueError):
    pass


def _pairs(specs: Iterable[str], what: str) -> List[Tuple[str, str]]:
    out = []
    for spec in specs or ():
        for item in str(spec).split(","):
            item = item.strip()
            if not item:
                continue
            if "=" not in item:
                raise RewriteError(f"bad {what} {item!r}: use OLD=NEW")
            old, new = (x.strip() for x in item.split("=", 1))
            out.append((old, new))
    return out


def _mac(text: str) -> bytes:
    try:
        b = P.mac_to_bytes(text)
    except Exception:
        b = b""
    if len(b) != 6:
        raise RewriteError(f"bad MAC address {text!r}")
    return b


class Rewriter:
    """Applies IPv4 / MAC maps and a VLAN retag to Ethernet frames."""

    def __init__(self, ip_map: Optional[Dict[str, str]] = None,
                 subnets: Iterable[Tuple[str, str]] = (),
                 mac_map: Optional[Dict[str, str]] = None,
                 vlan: Optional[int] = None):
        self.ip_map: Dict[bytes, bytes] = {}
        for old, new in (ip_map or {}).items():
            try:
                self.ip_map[ipaddress.IPv4Address(old).packed] = \
                    ipaddress.IPv4Address(new).packed
            except ValueError as e:
                raise RewriteError(f"bad --remap-ip {old}={new}: {e}")
        self.subnets: List[Tuple[int, int, int]] = []   # (mask, old, new)
        for old, new in subnets:
            try:
                a = ipaddress.IPv4Network(old, strict=False)
                b = ipaddress.IPv4Network(new, strict=False)
            except ValueError as e:
                raise RewriteError(f"bad --remap-subnet {old}={new}: {e}")
            if a.prefixlen != b.prefixlen:
                raise RewriteError(f"--remap-subnet {old}={new}: prefix "
                                   "lengths differ")
            self.subnets.append((int(a.netmask), int(a.network_address),
                                 int(b.network_address)))
        self.subnets.sort(key=lambda t: -t[0])          # longest prefix first
        self.mac_map: Dict[bytes, bytes] = {
            _mac(o): _mac(n) for o, n in (mac_map or {}).items()}
        if vlan is not None and not 0 <= vlan <= 4094:
            raise RewriteError(f"bad VLAN id {vlan} (0 = untag, 1-4094)")
        self.vlan = vlan
        self._cache: Dict[bytes, bytes] = {}

    @classmethod
    def from_specs(cls, remap_ip: Iterable[str] = (),
                   remap_subnet: Iterable[str] = (),
                   remap_mac: Iterable[str] = (),
                   vlan: Optional[int] = None) -> Optional["Rewriter"]:
        """Build from CLI-style ``OLD=NEW[,OLD=NEW]`` strings; None when
        there is nothing to rewrite. Raises RewriteError on bad input."""
        ips = dict(_pairs(remap_ip, "--remap-ip"))
        nets = _pairs(remap_subnet, "--remap-subnet")
        macs = dict(_pairs(remap_mac, "--remap-mac"))
        if not (ips or nets or macs or vlan is not None):
            return None
        return cls(ips, nets, macs, vlan)

    def describe(self) -> str:
        parts = []
        if self.ip_map:
            parts.append(f"{len(self.ip_map)} IP")
        if self.subnets:
            parts.append(f"{len(self.subnets)} subnet")
        if self.mac_map:
            parts.append(f"{len(self.mac_map)} MAC")
        if self.vlan is not None:
            parts.append(f"VLAN {self.vlan}" if self.vlan else "untag")
        return "rewrite: " + ", ".join(parts)

    # -- addresses -----------------------------------------------------------
    def ip(self, addr: bytes) -> bytes:
        hit = self._cache.get(addr)
        if hit is not None:
            return hit
        new = self.ip_map.get(addr)
        if new is None:
            n = int.from_bytes(addr, "big")
            for mask, old, base in self.subnets:
                if n & mask == old:
                    new = (base | (n & ~mask & 0xFFFFFFFF)).to_bytes(4, "big")
                    break
            else:
                new = addr
        if len(self._cache) < 65536:
            self._cache[addr] = new
        return new

    def mac(self, addr: bytes) -> bytes:
        return self.mac_map.get(addr, addr)

    # -- frames ----------------------------------------------------------------
    def apply(self, frame: bytes) -> bytes:
        if len(frame) < 14:
            return frame
        buf = bytearray(frame)
        if self.mac_map:
            buf[0:6] = self.mac(bytes(buf[0:6]))
            buf[6:12] = self.mac(bytes(buf[6:12]))
        if self.vlan is not None:
            buf = self._retag(buf)
        # walk VLAN tags to the payload ethertype
        off = 12
        etype = struct.unpack_from("!H", buf, off)[0]
        while etype in _VLAN_TPIDS and len(buf) >= off + 6:
            off += 4
            etype = struct.unpack_from("!H", buf, off)[0]
        off += 2
        if etype == P.ETH_P_IP and (self.ip_map or self.subnets):
            self._ipv4(buf, off)
        elif etype == 0x0806:
            self._arp(buf, off)
        return bytes(buf)

    def _retag(self, buf: bytearray) -> bytearray:
        tpid = struct.unpack_from("!H", buf, 12)[0]
        if tpid in _VLAN_TPIDS and len(buf) >= 18:
            if self.vlan == 0:              # untag: drop the outer tag
                return buf[:12] + buf[16:]
            tci = struct.unpack_from("!H", buf, 14)[0]
            struct.pack_into("!H", buf, 14, (tci & 0xF000) | self.vlan)
            return buf
        if self.vlan == 0:
            return buf
        return buf[:12] + struct.pack("!HH", 0x8100, self.vlan) + buf[12:]

    def _arp(self, buf: bytearray, off: int) -> None:
        if len(buf) < off + 28:
            return
        htype, ptype, hlen, plen = struct.unpack_from("!HHBB", buf, off)
        if hlen != 6 or plen != 4 or ptype != P.ETH_P_IP:
            return
        for o in (off + 8, off + 18):           # sender / target MAC
            buf[o:o + 6] = self.mac(bytes(buf[o:o + 6]))
        for o in (off + 14, off + 24):          # sender / target IP
            buf[o:o + 4] = self.ip(bytes(buf[o:o + 4]))

    def _ipv4(self, buf: bytearray, off: int) -> None:
        if len(buf) < off + 20 or buf[off] >> 4 != 4:
            return
        ihl = (buf[off] & 0x0F) * 4
        if ihl < 20 or len(buf) < off + ihl:
            return
        src, dst = bytes(buf[off + 12:off + 16]), bytes(buf[off + 16:off + 20])
        nsrc, ndst = self.ip(src), self.ip(dst)
        if nsrc == src and ndst == dst:
            return
        buf[off + 12:off + 16] = nsrc
        buf[off + 16:off + 20] = ndst
        buf[off + 10:off + 12] = b"\0\0"
        struct.pack_into("!H", buf, off + 10,
                         P.checksum16(bytes(buf[off:off + ihl])))
        total = struct.unpack_from("!H", buf, off + 2)[0]
        frag = struct.unpack_from("!H", buf, off + 6)[0]
        proto = buf[off + 9]
        if frag & 0x1FFF or proto not in (P.IPPROTO_TCP, P.IPPROTO_UDP):
            return                  # non-first fragment / no pseudo-header
        l4 = off + ihl
        ck = l4 + (16 if proto == P.IPPROTO_TCP else 6)
        if len(buf) < ck + 2:
            return
        old_ck = struct.unpack_from("!H", buf, ck)[0]
        if proto == P.IPPROTO_UDP and old_ck == 0:
            return                  # sent without a checksum
        complete = (not frag & 0x2000) and total >= ihl and \
            len(buf) >= off + total
        if complete:
            seg = bytearray(buf[l4:off + total])
            seg[ck - l4:ck - l4 + 2] = b"\0\0"
            pseudo = nsrc + ndst + struct.pack("!BBH", 0, proto, len(seg))
            new_ck = P.checksum16(pseudo + bytes(seg))
            if proto == P.IPPROTO_UDP and new_ck == 0:
                new_ck = 0xFFFF
        else:
            new_ck = _adjust(old_ck, src + dst, nsrc + ndst)
        struct.pack_into("!H", buf, ck, new_ck)


def _adjust(ck: int, old: bytes, new: bytes) -> int:
    """RFC 1624 incremental update: HC' = ~(~HC + ~m + m')."""
    s = ~ck & 0xFFFF
    for i in range(0, len(old), 2):
        s += (~((old[i] << 8) | old[i + 1])) & 0xFFFF
        s += (new[i] << 8) | new[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF
