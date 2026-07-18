"""Read frames from a classic libpcap (.pcap) file — pure stdlib.

Used by the replay input so TGT can put a captured capture (e.g. a real
threat-traffic sample) back on the wire for an analyser to ingest. Handles both
byte orders, microsecond and nanosecond timestamps, and the Ethernet (1),
raw-IPv4 (101) and Linux SLL (113) link types; raw-IP frames are wrapped in a
synthetic Ethernet header so they can leave an AF_PACKET socket.
"""
from __future__ import annotations

import struct
from typing import Iterator, List, Tuple

from . import packet as P

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW_IP = 101
LINKTYPE_LINUX_SLL = 113


class PcapError(Exception):
    pass


def _wrap_ethernet(frame: bytes, linktype: int) -> bytes:
    """Return an Ethernet frame regardless of the capture's link type."""
    if linktype == LINKTYPE_ETHERNET:
        return frame
    if linktype == LINKTYPE_RAW_IP:
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
    raise PcapError(f"unsupported pcap link type {linktype} "
                    "(need Ethernet/1, raw-IP/101 or SLL/113)")


def read_frames(path: str, wrap: bool = True) -> List[Tuple[float, bytes]]:
    """Load ``(timestamp, ethernet_frame)`` tuples from a pcap file."""
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) < 24:
        raise PcapError("file too short to be a pcap")

    magic = data[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic[:4] == b"\x0a\x0d\x0d\x0a":
        raise PcapError("this is a pcapng file — convert with "
                        "`editcap -F pcap in.pcapng out.pcap` first")
    else:
        raise PcapError("not a libpcap file (bad magic)")
    nanos = magic in (b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1")

    linktype = struct.unpack(endian + "I", data[20:24])[0]
    out: List[Tuple[float, bytes]] = []
    off = 24
    while off + 16 <= len(data):
        ts_s, ts_frac, incl, orig = struct.unpack(endian + "IIII",
                                                  data[off:off + 16])
        off += 16
        if off + incl > len(data):
            break                       # truncated final record
        frame = data[off:off + incl]
        off += incl
        ts = ts_s + ts_frac / (1e9 if nanos else 1e6)
        out.append((ts, _wrap_ethernet(frame, linktype) if wrap else frame))
    if not out:
        raise PcapError("no packets found in file")
    return out


def summarize(path: str) -> str:
    frames = read_frames(path)
    total = sum(len(f) for _, f in frames)
    span = frames[-1][0] - frames[0][0] if len(frames) > 1 else 0.0
    return f"{len(frames)} packets, {total} bytes, {span:.1f}s capture span"
