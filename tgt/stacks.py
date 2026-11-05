"""Per-OS TCP/IP stack fingerprints — SYN options, windows, IP ID, DF.

Passive fingerprinting (p0f, Zeek/JA4T-style, OT and IT monitors) classifies a
host by how its stack opens a connection: the TCP option *layout* in the SYN
(``mss,nop,ws,nop,nop,sok`` is Windows; ``mss,sok,ts,nop,ws`` is Linux; a bare
``mss`` is an embedded RTOS), the initial window and scale, whether timestamps
are used, the IP ID pattern and the DF bit. Each :class:`Stack` here describes
one family; :class:`tgt.protocols.TcpSession` builds every segment from the
client's and the server's stack separately.

Values follow observed stacks (p0f v3 signatures and captures): Windows 10 /
Server 2016-2019 open with window 64240 and scale 8, Windows 7 / 2008 R2 with
8192 and scale 2, Server 2012 R2 with 8192 and scale 8; XP / 2000 never scale
the window; Linux sends timestamps and scale 7. Embedded controllers advertise
only an MSS and a small window, and number IP datagrams from one counter.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class Stack:
    key: str
    label: str
    style: str             # SYN option layout: "win", "winxp", "linux", "mss"
    mss: int = 1460
    wscale: int = -1       # window-scale shift offered; -1 = no scaling
    sack: bool = True      # offers SACK_PERM
    ts: str = "none"       # timestamps: "initiate" | "respond" | "none"
    syn_win: int = 8192    # window in the SYN
    synack_win: int = 0    # window in the SYN+ACK (0 = syn_win)
    win: int = 8192        # receive window (bytes) once established
    ipid: str = "host"     # "host": one counter per host (Windows, RTOS)
                           # "conn": per-connection counter, SYN+ACK id 0 (Linux)
                           # "zero": always 0
    df: bool = True        # IP Don't Fragment
    delack_ms: int = 200   # delayed-ACK timer (TSval clock advance)


STACKS: Dict[str, Stack] = {s.key: s for s in (
    Stack("win10", "Windows 10 / Server 2016-2019", "win", wscale=8,
          ts="respond", syn_win=64240, synack_win=65535, win=262656),
    Stack("win2012", "Windows 8 / Server 2012 R2", "win", wscale=8,
          ts="respond", syn_win=8192, win=262144),
    Stack("win7", "Windows 7 / Server 2008 R2", "win", wscale=2,
          ts="respond", syn_win=8192, win=65700),
    Stack("winxp", "Windows XP / Server 2003", "winxp", syn_win=64240,
          win=64240),
    Stack("win2000", "Windows 2000", "winxp", syn_win=65535, win=65535),
    Stack("linux", "Linux 3.x-6.x", "linux", wscale=7, ts="initiate",
          syn_win=64240, synack_win=65160, win=64256, ipid="conn",
          delack_ms=40),
    # Embedded controllers: MSS only, small fixed windows, one IP-ID counter
    Stack("rockwell", "Rockwell Logix EtherNet/IP module", "mss", sack=False,
          syn_win=8192, win=8192),
    Stack("rockwell-drive", "Rockwell PowerFlex drive", "mss", sack=False,
          syn_win=4096, win=4096),
    Stack("siemens", "Siemens SIMATIC CPU / CP", "mss", sack=False,
          syn_win=8192, win=8192, df=False),
    Stack("schneider", "Schneider Modicon CPU / NOE", "mss", sack=False,
          syn_win=4380, win=4380),
    Stack("sel", "SEL relay / RTAC", "mss", mss=536, sack=False,
          syn_win=2144, win=2144),
    Stack("embedded", "Embedded RTOS (generic)", "mss", sack=False,
          syn_win=4096, win=4096),
)}

# Stack of a general-purpose host / OT fingerprint without a catalog hint
OS_STACK: Dict[str, str] = {
    "win2019": "win10", "win10": "win10", "win2012": "win2012",
    "win7": "win7", "winxp": "winxp", "win2000": "win2000", "linux": "linux",
    "rockwell": "rockwell", "siemens": "siemens", "schneider": "schneider",
    "bacnet": "embedded", "sel": "sel",
    "rtos": "embedded", "linux-embedded": "linux",
}

# Profile-only runs (no environment): a Windows client, and for OT protocols
# the vendor stack that typically serves that port.
DEFAULT_CLIENT = "win10"
DEFAULT_SERVER = "win10"
PORT_SERVER_STACK: Dict[int, str] = {
    502: "schneider", 102: "siemens", 44818: "rockwell", 20000: "sel",
    2404: "embedded", 47808: "embedded",
}


def get(key: str) -> Stack:
    return STACKS.get(key) or STACKS[DEFAULT_CLIENT]


def for_os(os_key: str) -> str:
    """Stack key for an OS-fingerprint key (unknown -> Windows 10)."""
    return OS_STACK.get(os_key, DEFAULT_CLIENT)


def server_default(dport: int) -> str:
    return PORT_SERVER_STACK.get(dport, DEFAULT_SERVER)


def hash_int(*parts, bits: int = 32) -> int:
    """Deterministic pseudo-random integer from ``parts`` (stable across runs,
    unlike ``hash()``)."""
    h = hashlib.sha256("|".join(map(str, parts)).encode()).digest()
    return int.from_bytes(h[:8], "big") & ((1 << bits) - 1)


# ---------------------------------------------------------------------------
# TCP option encoding
# ---------------------------------------------------------------------------
NOP = b"\x01"


def _mss(v: int) -> bytes:
    return struct.pack("!BBH", 2, 4, v)


def _ws(shift: int) -> bytes:
    return struct.pack("!BBB", 3, 3, shift)


_SOK = b"\x04\x02"


def ts_option(tsval: int, tsecr: int, pad: bool = True) -> bytes:
    """Timestamps option; ``pad`` prefixes the NOP,NOP every stack uses on
    established segments."""
    opt = struct.pack("!BBII", 8, 10, tsval & 0xFFFFFFFF, tsecr & 0xFFFFFFFF)
    return NOP + NOP + opt if pad else opt


def syn_options(st: Stack, ws: bool, sack: bool, ts: bool,
                tsval: int = 0, tsecr: int = 0) -> bytes:
    """SYN / SYN+ACK options in ``st``'s own order. ``ws``/``sack``/``ts`` say
    which options this segment carries (a SYN offers what its stack supports;
    a SYN+ACK only what both sides do)."""
    if st.style == "mss":
        return _mss(st.mss)
    tso = ts_option(tsval, tsecr, pad=False)
    if st.style == "linux":
        out = _mss(st.mss)
        if sack and ts:
            out += _SOK + tso
        elif ts:
            out += NOP + NOP + tso
        elif sack:
            out += NOP + NOP + _SOK
        if ws:
            out += NOP + _ws(st.wscale)
        return out
    # Windows: mss,nop,ws,nop,nop,sok (Vista+); XP/2000: mss,nop,nop,sok
    out = _mss(st.mss)
    if ws:
        out += NOP + _ws(st.wscale)
    if ts:
        if sack:
            out += _SOK + tso if ws else NOP + NOP + _SOK + NOP + NOP + tso
        else:
            out += NOP + NOP + tso
    elif sack:
        out += NOP + NOP + _SOK
    return out
