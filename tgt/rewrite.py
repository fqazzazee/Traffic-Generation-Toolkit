"""Re-address captured frames for replay: IPv4/IPv6 / MAC remap, VLAN retag.

``tgt run --replay FILE`` can put a customer capture onto a lab segment that
uses different addressing::

    --remap-ip 192.168.1.10=10.100.10.21,fd00::10=fd10::21
    --remap-subnet 192.168.1.0/24=10.100.10.0/24,fd00:1::/64=fd10:1::/64
    --remap-mac 00:1d:9c:aa:bb:cc=00:1d:9c:11:22:33
    --vlan 30            (retag: replace/add the outer 802.1Q id; 0 = untag)

IPv4 and IPv6 rules mix freely in one run (each pair must be one family).
Explicit ``--remap-ip`` entries win over subnet rules; of several subnet rules
the longest prefix wins. IPv4 source/destination addresses are rewritten in
the IP header and in ARP; the IP header checksum and the TCP/UDP checksum are
recomputed for complete datagrams (a capture with offloaded, invalid
checksums comes out valid) and updated incrementally (RFC 1624) for
fragments or snaplen-truncated packets, whose payload is not all there.
UDP datagrams sent without a checksum (0) keep none.

IPv6: source/destination, the addresses of a type 0/2/4 routing header and
the NDP target (NS/NA/redirect) are rewritten; the hop-by-hop, routing,
destination-options, fragment and AH extension headers are walked to the
upper layer, whose pseudo-header checksum (TCP, UDP, ICMPv6, OSPFv3, PIM,
VRRPv3) is fixed against the final destination. Non-first fragments get
their addresses rewritten but no L4 checksum (it is not in them). NDP
source/target link-layer options follow ``--remap-mac``, and so does an
EUI-64 interface id (link-local / SLAAC address) built from a remapped MAC.

Frames that are IP by EtherType but cannot be parsed (truncated header,
truncated extension chain, an unknown routing header still in flight) are
left as captured above L2 (the MAC map and VLAN retag still apply) and
counted in :attr:`Rewriter.unparsed`. The inner headers
quoted in ICMP errors are left as they are.
"""
from __future__ import annotations

import ipaddress
import struct
from typing import Dict, Iterable, List, Optional, Tuple

from . import packet as P

_VLAN_TPIDS = (0x8100, 0x88A8, 0x9100)
ETH_P_IPV6 = 0x86DD
# IPv6 extension headers walked to the upper layer (hop-by-hop, routing,
# fragment, AH, destination options)
_V6_EXT = (0, 43, 44, 51, 60)
# Offset of the checksum in the upper layers whose checksum covers the IPv6
# pseudo-header: TCP, UDP, ICMPv6, OSPFv3, PIM, VRRPv3
_V6_CSUM = {6: 16, 17: 6, 58: 2, 89: 12, 103: 2, 112: 6}


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


def eui64(mac: bytes) -> bytes:
    """Modified EUI-64 interface id of a MAC (RFC 4291 appendix A)."""
    return bytes([mac[0] ^ 0x02]) + mac[1:3] + b"\xff\xfe" + mac[3:6]


class Rewriter:
    """Applies IPv4/IPv6 / MAC maps and a VLAN retag to Ethernet frames."""

    def __init__(self, ip_map: Optional[Dict[str, str]] = None,
                 subnets: Iterable[Tuple[str, str]] = (),
                 mac_map: Optional[Dict[str, str]] = None,
                 vlan: Optional[int] = None):
        self.ip_map: Dict[bytes, bytes] = {}    # 4- or 16-byte keys
        for old, new in (ip_map or {}).items():
            try:
                a, b = ipaddress.ip_address(old), ipaddress.ip_address(new)
            except ValueError as e:
                raise RewriteError(f"bad --remap-ip {old}={new}: {e}")
            if a.version != b.version:
                raise RewriteError(f"--remap-ip {old}={new}: IPv{a.version} "
                                   f"to IPv{b.version}")
            self.ip_map[a.packed] = b.packed
        # (mask, old, new) per family, longest prefix first
        self.subnets: List[Tuple[int, int, int]] = []    # IPv4
        self.subnets6: List[Tuple[int, int, int]] = []   # IPv6
        for old, new in subnets:
            try:
                a = ipaddress.ip_network(old, strict=False)
                b = ipaddress.ip_network(new, strict=False)
            except ValueError as e:
                raise RewriteError(f"bad --remap-subnet {old}={new}: {e}")
            if a.version != b.version:
                raise RewriteError(f"--remap-subnet {old}={new}: IPv"
                                   f"{a.version} to IPv{b.version}")
            if a.prefixlen != b.prefixlen:
                raise RewriteError(f"--remap-subnet {old}={new}: prefix "
                                   "lengths differ")
            (self.subnets if a.version == 4 else self.subnets6).append(
                (int(a.netmask), int(a.network_address),
                 int(b.network_address)))
        self.subnets.sort(key=lambda t: -t[0])
        self.subnets6.sort(key=lambda t: -t[0])
        self.mac_map: Dict[bytes, bytes] = {
            _mac(o): _mac(n) for o, n in (mac_map or {}).items()}
        if vlan is not None and not 0 <= vlan <= 4094:
            raise RewriteError(f"bad VLAN id {vlan} (0 = untag, 1-4094)")
        self.vlan = vlan
        self._cache: Dict[bytes, bytes] = {}
        self.unparsed = 0       # IP frames left untouched (unparseable)

    @property
    def _v4(self) -> bool:
        return bool(self.subnets or any(len(k) == 4 for k in self.ip_map))

    @property
    def _v6(self) -> bool:
        return bool(self.subnets6 or self.mac_map
                    or any(len(k) == 16 for k in self.ip_map))

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
        v6 = sum(len(k) == 16 for k in self.ip_map)
        if len(self.ip_map) - v6:
            parts.append(f"{len(self.ip_map) - v6} IP")
        if v6:
            parts.append(f"{v6} IPv6")
        if self.subnets:
            parts.append(f"{len(self.subnets)} subnet")
        if self.subnets6:
            parts.append(f"{len(self.subnets6)} IPv6 subnet")
        if self.mac_map:
            parts.append(f"{len(self.mac_map)} MAC")
        if self.vlan is not None:
            parts.append(f"VLAN {self.vlan}" if self.vlan else "untag")
        return "rewrite: " + ", ".join(parts)

    # -- addresses -----------------------------------------------------------
    def ip(self, addr: bytes) -> bytes:
        """New address of a 4-byte (IPv4) or 16-byte (IPv6) address."""
        hit = self._cache.get(addr)
        if hit is not None:
            return hit
        new = self.ip_map.get(addr)
        if new is None:
            n = int.from_bytes(addr, "big")
            size = len(addr)
            full = (1 << (8 * size)) - 1
            for mask, old, base in (self.subnets if size == 4
                                    else self.subnets6):
                if n & mask == old:
                    new = (base | (n & ~mask & full)).to_bytes(size, "big")
                    break
            else:
                new = addr
            if size == 16 and self.mac_map:
                new = self._eui64(new)
        if len(self._cache) < 65536:
            self._cache[addr] = new
        return new

    def mac(self, addr: bytes) -> bytes:
        return self.mac_map.get(addr, addr)

    def _eui64(self, addr: bytes) -> bytes:
        """An IPv6 address whose interface id is the modified EUI-64 of a
        remapped MAC takes the new MAC's interface id."""
        if addr[11] != 0xFF or addr[12] != 0xFE:
            return addr
        new = self.mac_map.get(bytes([addr[8] ^ 0x02]) + addr[9:11]
                               + addr[13:16])
        return addr if new is None else addr[:8] + eui64(new)

    # -- frames ----------------------------------------------------------------
    def apply_all(self, frame: bytes) -> List[bytes]:
        """The frame(s) to send for one captured frame (a subclass may place
        one frame as zero or several copies)."""
        return [self.apply(frame)]

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
        if etype == P.ETH_P_IP and self._v4:
            self._ipv4(buf, off)
        elif etype == ETH_P_IPV6 and self._v6:
            if not self._ipv6(buf, off):    # nothing above L2 was changed
                self.unparsed += 1
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
            self.unparsed += 1
            return
        ihl = (buf[off] & 0x0F) * 4
        if ihl < 20 or len(buf) < off + ihl:
            self.unparsed += 1
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

    def _ipv6(self, buf: bytearray, off: int) -> bool:
        """Rewrite one IPv6 packet in place; False = unparseable (the caller
        restores the frame)."""
        if len(buf) < off + 40 or buf[off] >> 4 != 6:
            return False
        plen = struct.unpack_from("!H", buf, off + 4)[0]
        end = off + 40 + plen
        nh, p = buf[off + 6], off + 40
        frag = None                     # (offset, more) of a fragment header
        routing: List[int] = []         # offsets of routing-header addresses
        final = None                    # offset of the final destination
        while nh in _V6_EXT:
            if len(buf) < p + 8:
                return False            # truncated extension chain
            if nh == 44:
                fo = struct.unpack_from("!H", buf, p + 2)[0]
                frag = (fo >> 3, fo & 1)
                hl = 8
            elif nh == 51:
                hl = (buf[p + 1] + 2) * 4
            else:
                hl = (buf[p + 1] + 1) * 8
            if len(buf) < p + hl:
                return False
            if nh == 43:
                rtype, left = buf[p + 2], buf[p + 3]
                if rtype in (0, 2, 4):
                    addrs = [p + 8 + 16 * i for i in range((hl - 8) // 16)]
                    routing += addrs
                    if left and addrs:
                        # an SRH (type 4) lists the segments last first
                        final = addrs[0] if rtype == 4 else addrs[-1]
                elif left:
                    return False        # cannot tell the final destination
            nh = buf[p]
            p += hl
            if frag is not None and frag[0]:
                break                   # non-first fragment: no upper header
        dst_o = final if final is not None else off + 24
        old_pseudo = bytes(buf[off + 8:off + 24] + buf[dst_o:dst_o + 16])
        changed = False
        for o in [off + 8, off + 24] + routing:
            a = bytes(buf[o:o + 16])
            b = self.ip(a)
            if b != a:
                buf[o:o + 16] = b
                changed = True
        if frag is not None and frag[0]:
            return True                 # non-first fragment: addresses only
        ck_off = _V6_CSUM.get(nh)
        if ck_off is None or len(buf) < p + ck_off + 2:
            return True
        if nh == 112 and buf[p] >> 4 != 3:
            return True                 # only VRRPv3 uses the pseudo-header
        # NDP: target (+ redirect destination) and link-layer address options
        inner: List[Tuple[int, bytes]] = []     # (offset, old bytes) in L4
        if nh == 58 and buf[p] in (135, 136, 137):
            for o in [p + 8] + ([p + 24] if buf[p] == 137 else []):
                if len(buf) >= o + 16:
                    a = bytes(buf[o:o + 16])
                    b = self.ip(a)
                    if b != a:
                        inner.append((o, a))
                        buf[o:o + 16] = b
            o = p + (40 if buf[p] == 137 else 24)
            while len(buf) >= o + 8 and buf[o + 1]:
                if buf[o] in (1, 2) and buf[o + 1] == 1:
                    a = bytes(buf[o + 2:o + 8])
                    b = self.mac(a)
                    if b != a:
                        inner.append((o + 2, a))
                        buf[o + 2:o + 8] = b
                o += buf[o + 1] * 8
        if not changed and not inner:
            return True
        ck = p + ck_off
        old_ck = struct.unpack_from("!H", buf, ck)[0]
        if nh == P.IPPROTO_UDP and old_ck == 0:
            return True                 # sent without a checksum
        new_pseudo = bytes(buf[off + 8:off + 24] + buf[dst_o:dst_o + 16])
        if frag is None and plen and p < end <= len(buf):
            seg = bytearray(buf[p:end])
            seg[ck_off:ck_off + 2] = b"\0\0"
            pseudo = new_pseudo + struct.pack("!IxxxB", len(seg), nh)
            new_ck = P.checksum16(pseudo + bytes(seg))
            if nh == P.IPPROTO_UDP and new_ck == 0:
                new_ck = 0xFFFF
        else:                           # first fragment / truncated
            old_b, new_b = old_pseudo, new_pseudo
            for o, a in inner:
                old_b += a
                new_b += bytes(buf[o:o + len(a)])
            new_ck = _adjust(old_ck, old_b, new_b)
        struct.pack_into("!H", buf, ck, new_ck)
        return True


def _adjust(ck: int, old: bytes, new: bytes) -> int:
    """RFC 1624 incremental update: HC' = ~(~HC + ~m + m')."""
    s = ~ck & 0xFFFF
    for i in range(0, len(old), 2):
        s += (~((old[i] << 8) | old[i + 1])) & 0xFFFF
        s += (new[i] << 8) | new[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF
