"""Read frames from a libpcap (.pcap) or pcapng file — pure stdlib, streamed.

Used by the replay input so TGT can put a captured capture (e.g. a real
threat-traffic sample) back on the wire for an analyser to ingest.

* classic pcap: both byte orders, microsecond and nanosecond timestamps;
* pcapng: Section Header (either byte order, several sections per file),
  Interface Description (several interfaces, each with its own link type and
  ``if_tsresol`` / ``if_tsoffset``), Enhanced, Simple and the obsolete Packet
  blocks; every other block type is skipped;
* link types Ethernet (1), raw IP (101, and 228/229 raw IPv4/IPv6) and Linux
  SLL (113); raw-IP / SLL frames are wrapped in a synthetic Ethernet header so
  they can leave an AF_PACKET socket.

:func:`iter_frames` reads one record at a time, so a multi-gigabyte capture
replays in constant memory; :func:`read_frames` is the old load-everything
list form.
"""
from __future__ import annotations

import struct
from typing import BinaryIO, Iterator, List, NamedTuple, Optional, Tuple

from . import packet as P

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW_IP = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229

_RAW_IP = (LINKTYPE_RAW_IP, LINKTYPE_IPV4, LINKTYPE_IPV6)
SUPPORTED = (LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL) + _RAW_IP

PCAPNG_SHB = 0x0A0D0D0A
_BOM = 0x1A2B3C4D
_PCAP_MAGICS = {b"\xa1\xb2\xc3\xd4": (">", False), b"\xa1\xb2\x3c\x4d": (">", True),
                b"\xd4\xc3\xb2\xa1": ("<", False), b"\x4d\x3c\xb2\xa1": ("<", True)}
_MAX_BLOCK = 256 * 1024 * 1024       # sanity bound on one pcapng block


class PcapError(Exception):
    pass


class Packet(NamedTuple):
    ts: float           # seconds since the epoch (float)
    frame: bytes        # as captured (or Ethernet-wrapped, see iter_packets)
    linktype: int
    interface: int      # pcapng interface id (0 for classic pcap)
    orig_len: int       # length on the wire (>= len(frame) when truncated)


def _wrap_ethernet(frame: bytes, linktype: int) -> bytes:
    """Return an Ethernet frame regardless of the capture's link type."""
    if linktype == LINKTYPE_ETHERNET:
        return frame
    if linktype in _RAW_IP:
        ver = (frame[0] >> 4) if frame else 4
        etype = P.ETH_P_IP if ver == 4 else 0x86DD
        return P.ethernet("02:00:00:00:00:02", "02:00:00:00:00:01", etype, frame)
    if linktype == LINKTYPE_LINUX_SLL:
        # 16-byte SLL header; bytes 14-15 are the ethertype, rest is the L3 pkt
        if len(frame) < 16:
            return frame
        etype = struct.unpack("!H", frame[14:16])[0]
        return P.ethernet("02:00:00:00:00:02", "02:00:00:00:00:01",
                          etype, frame[16:])
    raise PcapError(f"unsupported link type {linktype} "
                    "(need Ethernet/1, raw-IP/101 or SLL/113)")


def file_format(path: str) -> str:
    """``"pcap"`` or ``"pcapng"`` from the magic; PcapError otherwise."""
    with open(path, "rb") as fh:
        head = fh.read(4)
    if len(head) < 4:
        raise PcapError("file too short to be a pcap")
    if head in _PCAP_MAGICS:
        return "pcap"
    if struct.unpack("<I", head)[0] == PCAPNG_SHB:
        return "pcapng"
    raise PcapError("not a pcap or pcapng file (bad magic)")


# ---------------------------------------------------------------------------
# classic pcap
# ---------------------------------------------------------------------------
def _iter_pcap(fh: BinaryIO) -> Iterator[Packet]:
    hdr = fh.read(24)
    if len(hdr) < 24:
        raise PcapError("file too short to be a pcap")
    endian, nanos = _PCAP_MAGICS[hdr[:4]]
    linktype = struct.unpack(endian + "I", hdr[20:24])[0] & 0x0FFFFFFF
    div = 1e9 if nanos else 1e6
    rec = struct.Struct(endian + "IIII")
    while True:
        h = fh.read(16)
        if len(h) < 16:
            return                          # EOF (or truncated record header)
        ts_s, ts_frac, incl, orig = rec.unpack(h)
        if incl > _MAX_BLOCK:
            raise PcapError(f"corrupt record (caplen {incl})")
        data = fh.read(incl)
        if len(data) < incl:
            return                          # truncated final record
        yield Packet(ts_s + ts_frac / div, data, linktype, 0, orig)


# ---------------------------------------------------------------------------
# pcapng
# ---------------------------------------------------------------------------
class _Iface:
    __slots__ = ("linktype", "snaplen", "units", "offset")

    def __init__(self, linktype: int, snaplen: int, units: float, offset: int):
        self.linktype, self.snaplen = linktype, snaplen
        self.units, self.offset = units, offset   # ticks per second, seconds


def _options(body: bytes, endian: str) -> Iterator[Tuple[int, bytes]]:
    off = 0
    while off + 4 <= len(body):
        code, length = struct.unpack(endian + "HH", body[off:off + 4])
        if code == 0:                       # opt_endofopt
            return
        val = body[off + 4:off + 4 + length]
        yield code, val
        off += 4 + ((length + 3) & ~3)


def _idb(body: bytes, endian: str, resolution: Optional[float]) -> _Iface:
    if len(body) < 8:
        raise PcapError("corrupt pcapng Interface Description Block")
    linktype, _, snaplen = struct.unpack(endian + "HHI", body[:8])
    units, offset = 1e6, 0                 # default: microseconds
    for code, val in _options(body[8:], endian):
        if code == 9 and val:               # if_tsresol
            r = val[0]
            units = float(2 ** (r & 0x7F)) if r & 0x80 else float(10 ** r)
        elif code == 14 and len(val) >= 8:  # if_tsoffset (seconds)
            offset = struct.unpack(endian + "q", val[:8])[0]
    if resolution:                          # caller override (ticks/second)
        units = resolution
    return _Iface(linktype, snaplen, units, offset)


def _iter_pcapng(fh: BinaryIO, resolution: Optional[float] = None,
                 skip_data: bool = False) -> Iterator[Packet]:
    """``skip_data`` seeks over packet data (yielding empty frames) — for a
    quick count of a large file."""
    endian = "<"
    ifaces: List[_Iface] = []
    last_ts = 0.0
    while True:
        head = fh.read(8)
        if len(head) < 8:
            return
        btype_le = struct.unpack("<I", head[:4])[0]
        if btype_le == PCAPNG_SHB:          # new section: byte order may change
            bom = fh.read(4)
            if len(bom) < 4:
                return
            if struct.unpack("<I", bom)[0] == _BOM:
                endian = "<"
            elif struct.unpack(">I", bom)[0] == _BOM:
                endian = ">"
            else:
                raise PcapError("corrupt pcapng Section Header (byte-order "
                                "magic)")
            blen = struct.unpack(endian + "I", head[4:8])[0]
            if blen < 28 or blen % 4 or blen > _MAX_BLOCK:
                raise PcapError(f"corrupt pcapng Section Header (length {blen})")
            rest = fh.read(blen - 12)
            if len(rest) < blen - 12:
                return
            ifaces = []
            continue
        btype, blen = struct.unpack(endian + "II", head)
        if blen < 12 or blen % 4 or blen > _MAX_BLOCK:
            raise PcapError(f"corrupt pcapng block (type {btype:#x}, "
                            f"length {blen})")
        if skip_data and btype in (2, 3, 6) and blen >= 32:
            body = fh.read(20)
            fh.seek(blen - 28, 1)
            if len(body) < 20 or fh.tell() > _size(fh):
                return
            body += b"\0" * (blen - 28)      # length stand-in, not read
        elif skip_data and btype not in (1, 2, 3, 6):
            fh.seek(blen - 8, 1)
            if fh.tell() > _size(fh):
                return
            continue
        else:
            body = fh.read(blen - 8)
        if len(body) < blen - 8:
            return                          # truncated final block
        body = body[:-4]                    # trailing block-total-length
        if btype == 1:                      # Interface Description
            ifaces.append(_idb(body, endian, resolution))
        elif btype == 6:                    # Enhanced Packet
            if len(body) < 20:
                raise PcapError("corrupt pcapng Enhanced Packet Block")
            ifid, hi, lo, cap, orig = struct.unpack(endian + "IIIII",
                                                    body[:20])
            if ifid >= len(ifaces):
                raise PcapError(f"pcapng packet on undeclared interface {ifid}")
            ifc = ifaces[ifid]
            last_ts = ifc.offset + ((hi << 32) | lo) / ifc.units
            yield Packet(last_ts, body[20:20 + cap], ifc.linktype, ifid, orig)
        elif btype == 3:                    # Simple Packet (interface 0, no ts)
            if not ifaces or len(body) < 4:
                raise PcapError("pcapng Simple Packet Block before any "
                                "interface")
            orig = struct.unpack(endian + "I", body[:4])[0]
            cap = min(orig, len(body) - 4)
            if ifaces[0].snaplen:
                cap = min(cap, ifaces[0].snaplen)
            yield Packet(last_ts, body[4:4 + cap], ifaces[0].linktype, 0, orig)
        elif btype == 2:                    # Packet Block (obsolete)
            if len(body) < 20:
                raise PcapError("corrupt pcapng Packet Block")
            ifid, _, hi, lo, cap, orig = struct.unpack(endian + "HHIIII",
                                                       body[:20])
            if ifid >= len(ifaces):
                raise PcapError(f"pcapng packet on undeclared interface {ifid}")
            ifc = ifaces[ifid]
            last_ts = ifc.offset + ((hi << 32) | lo) / ifc.units
            yield Packet(last_ts, body[20:20 + cap], ifc.linktype, ifid, orig)
        # NRB (4), ISB (5), DSB (10), custom blocks, ...: skipped


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------
def iter_packets(path: str, wrap: bool = True,
                 resolution: Optional[float] = None) -> Iterator[Packet]:
    """Stream :class:`Packet` records from a pcap or pcapng file.

    ``wrap`` turns raw-IP / SLL frames into Ethernet frames (``linktype`` is
    then still the capture's). ``resolution`` overrides the pcapng timestamp
    resolution in ticks per second (e.g. ``1e9``) for files written with a
    wrong ``if_tsresol``. Packets on unsupported link types raise PcapError.
    """
    fmt = file_format(path)
    with open(path, "rb") as fh:
        it = _iter_pcap(fh) if fmt == "pcap" else _iter_pcapng(fh, resolution)
        for pkt in it:
            if wrap:
                pkt = pkt._replace(frame=_wrap_ethernet(pkt.frame,
                                                        pkt.linktype))
            yield pkt


def iter_frames(path: str, wrap: bool = True,
                resolution: Optional[float] = None
                ) -> Iterator[Tuple[float, bytes]]:
    """Stream ``(timestamp, frame)`` tuples (see :func:`iter_packets`)."""
    for pkt in iter_packets(path, wrap, resolution):
        yield pkt.ts, pkt.frame


def read_frames(path: str, wrap: bool = True) -> List[Tuple[float, bytes]]:
    """Load ``(timestamp, ethernet_frame)`` tuples from a pcap/pcapng file."""
    out = list(iter_frames(path, wrap))
    if not out:
        raise PcapError("no packets found in file")
    return out


def probe(path: str) -> Tuple[str, int]:
    """Validate a capture before replaying it: its format and the number of
    packets, scanning record headers only (data is skipped, not read).
    Raises PcapError (bad file, no packets, unsupported link type)."""
    fmt = file_format(path)
    n = 0
    if fmt == "pcap":
        with open(path, "rb") as fh:
            hdr = fh.read(24)
            if len(hdr) < 24:
                raise PcapError("file too short to be a pcap")
            endian, _ = _PCAP_MAGICS[hdr[:4]]
            lt = struct.unpack(endian + "I", hdr[20:24])[0] & 0x0FFFFFFF
            if lt not in SUPPORTED:
                _wrap_ethernet(b"", lt)     # raises with the message
            while True:
                h = fh.read(16)
                if len(h) < 16:
                    break
                incl = struct.unpack(endian + "I", h[8:12])[0]
                if incl > _MAX_BLOCK:
                    raise PcapError(f"corrupt record (caplen {incl})")
                fh.seek(incl, 1)
                n += 1
            # a record cut short at EOF does not count
            if n and fh.tell() > _size(fh):
                n -= 1
    else:
        with open(path, "rb") as fh:
            for pkt in _iter_pcapng(fh, skip_data=True):
                if pkt.linktype not in SUPPORTED:
                    _wrap_ethernet(b"", pkt.linktype)
                n += 1
    if not n:
        raise PcapError("no packets found in file")
    return fmt, n


def _size(fh: BinaryIO) -> int:
    pos = fh.tell()
    end = fh.seek(0, 2)
    fh.seek(pos)
    return end


def summarize(path: str) -> str:
    n = total = 0
    first = last = None
    for ts, f in iter_frames(path):
        n += 1
        total += len(f)
        first = ts if first is None else first
        last = ts
    if not n:
        raise PcapError("no packets found in file")
    span = (last - first) if n > 1 else 0.0
    return f"{n} packets, {total} bytes, {span:.1f}s capture span"
