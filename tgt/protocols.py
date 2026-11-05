"""Protocol payload + flow builders.

Each *flow builder* takes :class:`~tgt.packet.Endpoints` and a message ``count``
and returns a list of complete Ethernet frames (``bytes``).  OT/ICS protocols
are crafted at the byte level so the well-known signatures that DPI engines such
a DPI monitor (Zeek, Suricata, Claroty CTD, …) classifies on are explicit.

TCP protocols emit a coherent session (SYN / SYN-ACK / ACK, PSH data both ways,
FIN teardown) via :class:`TcpSession` so stream-reassembling sensors see a real
conversation rather than orphaned segments.
"""
from __future__ import annotations

import contextlib
import math
import random
import struct
import threading
import zlib
from dataclasses import replace
from typing import Callable, List

from . import packet as P
from . import stacks
from .packet import Endpoints

# A flow builder: (endpoints, message_count) -> list of frames
FlowBuilder = Callable[[Endpoints, int], List[bytes]]


# ---------------------------------------------------------------------------
# TCP session helper
# ---------------------------------------------------------------------------
class TcpSession:
    """Tracks sequence/ack numbers for a single TCP conversation.

    Each side's segments follow its own TCP/IP stack (:mod:`tgt.stacks`, from
    ``ep.stack_client`` / ``ep.stack_server``): SYN option layout, windows and
    scaling, timestamps when both sides agree, IP ID pattern and DF. Payloads
    larger than the negotiated MSS are segmented, and the receiver ACKs every
    second full segment.
    """

    def __init__(self, ep: Endpoints, sport: int, dport: int,
                 iss: int | None = None, irs: int | None = None):
        self.ep = ep
        self.sport = sport
        self.dport = dport
        # random ISN per direction (RFC 6528), drawn from the build context
        # so a seeded run reproduces them
        self.c_seq = _rand32() if iss is None else iss   # client next seq
        self.s_seq = _rand32() if irs is None else irs   # server next seq
        self.frames: List[bytes] = []
        self._init_stacks()

    def _init_stacks(self) -> None:
        ep = self.ep
        c = stacks.get(ep.stack_client or stacks.DEFAULT_CLIENT)
        s = stacks.get(ep.stack_server or stacks.server_default(self.dport))
        self.stk = {True: c, False: s}
        self.ws = c.wscale >= 0 and s.wscale >= 0
        self.sack = c.sack and s.sack
        self.ts = c.ts == "initiate" and s.ts in ("initiate", "respond")
        self.mss = min(c.mss, s.mss) - (12 if self.ts else 0)
        key = (ep.client_ip, ep.server_ip, self.sport, self.dport)
        # IP ID and timestamp-clock starting points, per side and connection
        self._ipid = {True: stacks.hash_int(*key, "ipid-c", bits=16),
                      False: stacks.hash_int(*key, "ipid-s", bits=16)}
        self._tsbase = {True: stacks.hash_int(*key, "ts-c"),
                        False: stacks.hash_int(*key, "ts-s")}
        self._tsecr = {True: 0, False: 0}
        self._clock = 0           # ms since the SYN (1 kHz timestamp clock)

    def _emit(self, from_client: bool, flags: int, payload: bytes = b"") -> None:
        # never exceed the negotiated MSS (per-OS stacks, see _init_stacks)
        while len(payload) > self.mss:
            self._emit(from_client, flags & ~P.PSH, payload[:self.mss])
            payload = payload[self.mss:]
        if from_client:
            seq, ack = self.c_seq, self.s_seq
            sport, dport = self.sport, self.dport
        else:
            seq, ack = self.s_seq, self.c_seq
            sport, dport = self.dport, self.sport
        if flags == P.SYN:              # bare SYN: nothing to acknowledge yet
            ack = 0
        st = self.stk[from_client]
        tsval = (self._tsbase[from_client] + self._clock) & 0xFFFFFFFF
        self._clock += 1
        if flags & P.SYN:
            first = from_client          # SYN offers; SYN+ACK answers
            opts = stacks.syn_options(
                st, ws=st.wscale >= 0 if first else self.ws,
                sack=st.sack if first else self.sack,
                ts=st.ts == "initiate" if first else self.ts,
                tsval=tsval, tsecr=self._tsecr[from_client])
            window = st.syn_win if first else (st.synack_win or st.syn_win)
        else:
            opts = (stacks.ts_option(tsval, self._tsecr[from_client])
                    if self.ts else b"")
            window = st.win >> st.wscale if self.ws else min(st.win, 0xFFFF)
            if flags & P.RST:
                window = 0
        self._tsecr[not from_client] = tsval
        if st.ipid == "zero" or (st.ipid == "conn" and flags & P.SYN
                                 and not from_client):
            ident = 0                    # Linux SYN+ACK: no socket yet, id 0
        else:
            ident = self._ipid[from_client]
            self._ipid[from_client] = (ident + 1) & 0xFFFF
        seg = P.tcp(
            self.ep.client_ip if from_client else self.ep.server_ip,
            self.ep.server_ip if from_client else self.ep.client_ip,
            sport, dport, seq, ack, flags, payload, window=window,
            options=opts,
        )
        self.frames.append(P.ip_frame(self.ep, from_client, P.IPPROTO_TCP, seg,
                                      ident=ident, df=st.df))
        # advance sequence numbers
        adv = len(payload) + (1 if flags & (P.SYN | P.FIN) else 0)
        if from_client:
            self.c_seq = (self.c_seq + adv) & 0xFFFFFFFF
        else:
            self.s_seq = (self.s_seq + adv) & 0xFFFFFFFF

    def handshake(self) -> None:
        self._emit(True, P.SYN)
        self._emit(False, P.SYN | P.ACK)
        self._emit(True, P.ACK)

    def _send(self, from_client: bool, payload: bytes) -> None:
        """``payload`` in MSS-sized segments (PSH on the last); the peer ACKs
        every second full segment, as delayed-ACK stacks do."""
        mss = max(1, self.mss)
        chunks = [payload[i:i + mss] for i in range(0, len(payload), mss)]
        for n, chunk in enumerate(chunks):
            last = n == len(chunks) - 1
            self._emit(from_client, P.PSH | P.ACK if last else P.ACK, chunk)
            if not last and n % 2 == 1:
                self._emit(not from_client, P.ACK)

    def request(self, payload: bytes) -> None:
        self._send(True, payload)

    def response(self, payload: bytes) -> None:
        self._send(False, payload)

    def delayed_ack(self, from_client: bool = True) -> None:
        """A pure ACK sent when the delayed-ACK timer fires (nothing to
        piggyback it on, e.g. a poller idle until its next cycle)."""
        self._clock += self.stk[from_client].delack_ms
        self._emit(from_client, P.ACK)

    def teardown(self, rst: bool = False) -> None:
        """FIN handshake, or with ``rst`` an abortive close (RST+ACK from the
        client, as a browser dropping a connection does)."""
        if rst:
            self._emit(True, P.RST | P.ACK)
            return
        self._emit(True, P.FIN | P.ACK)
        self._emit(False, P.FIN | P.ACK)
        self._emit(True, P.ACK)


def _tcp_flow(ep: Endpoints, sport: int, dport: int,
              exchanges: List[tuple[bytes, bytes]], abort: bool = False,
              idle_from: int = 0) -> List[bytes]:
    """Build one TCP session: handshake, each (request, response), teardown.

    The client idles between exchanges (a poll interval), so from exchange
    ``idle_from`` on, a response that is not the last is followed by the
    client's delayed pure ACK. ``abort`` closes with RST instead of FIN.
    """
    s = TcpSession(ep, sport, dport)
    s.handshake()
    for n, (req, resp) in enumerate(exchanges):
        if req:
            s.request(req)
        if resp:
            s.response(resp)
            if idle_from <= n < len(exchanges) - 1:
                s.delayed_ack()
    s.teardown(rst=abort)
    return s.frames


def _aborts(ep: Endpoints, sport: int, dport: int, one_in: int = 6) -> bool:
    """Deterministically pick about one session in ``one_in`` to be aborted
    with RST (browsers and HTTP libraries drop idle keep-alive connections)."""
    return stacks.hash_int(ep.client_ip, ep.server_ip, sport, dport,
                           "rst") % one_in == 0


# A client ephemeral source port that increments per session for realism.
_next_sport = 40000
SPORT_LO, SPORT_HI = 40000, 60000


def _sport() -> int:
    global _next_sport
    _next_sport += 1
    if _next_sport > SPORT_HI:
        _next_sport = SPORT_LO
    _bctx.sports_used += 1
    return _next_sport


# ---------------------------------------------------------------------------
# Build context: per-cycle variation, reproducible under a run seed
# ---------------------------------------------------------------------------
class BuildContext:
    """What one build (one engine cycle) varies: a seeded RNG for TCP ISNs,
    session handles and the like, the cycle index that app-level counters
    continue from, and a salt for process-value drift. Builders consult the
    module-level context (see :func:`begin_build`) so their signatures stay
    ``(endpoints, count)``. Without a seed every build differs."""

    def __init__(self, seed: int | None = None, cycle: int = 0):
        self.seed = seed
        self.cycle = cycle
        self.rng = (random.Random(f"tgt:{seed}:{cycle}") if seed is not None
                    else random.Random())
        self.salt = seed if seed is not None else random.getrandbits(48)
        self.sports_used = 0


_bctx = BuildContext()


def begin_build(seed: int | None, cycle: int = 0,
                sport_stride: int = 0) -> BuildContext:
    """Start a build: fresh context for ``(seed, cycle)`` and the ephemeral
    source-port allocator reset to where that cycle's ports begin — a
    seed-derived offset plus ``cycle * sport_stride`` — so ports keep
    advancing across cycles (no 4-tuple reuse while the range lasts) and two
    builds of the same seed + cycle are identical."""
    global _bctx, _next_sport
    _bctx = BuildContext(seed, cycle)
    span = SPORT_HI - SPORT_LO + 1
    off = (zlib.crc32(f"tgt:{_bctx.salt}".encode()) + cycle * sport_stride)
    _next_sport = SPORT_LO + (off - 1) % span     # _sport() pre-increments
    return _bctx


def build_context() -> BuildContext:
    return _bctx


# Builds run on more than one thread (the engine prebuilds the next cycle in
# the background while the control API's injections build on the engine
# thread); a build holds this lock from begin_build to its last frame.
BUILD_LOCK = threading.RLock()


@contextlib.contextmanager
def isolated_build(seed: int | None, cycle: int = 0, sport_stride: int = 0):
    """A build of its own: under :data:`BUILD_LOCK`, with a fresh context
    for ``(seed, cycle)``, the caller's context and port allocator restored
    afterwards — so an out-of-band build (an injection) neither waits on nor
    perturbs the run's own seeded builds."""
    global _bctx, _next_sport
    with BUILD_LOCK:
        saved = (_bctx, _next_sport)
        try:
            yield begin_build(seed, cycle, sport_stride)
        finally:
            _bctx, _next_sport = saved


def _rand32() -> int:
    return _bctx.rng.getrandbits(32)


def _cycle_base(count: int) -> int:
    """Offset for per-flow counters (transaction ids, sequence numbers,
    sample indexes) so they continue across cycles instead of restarting."""
    return _bctx.cycle * max(1, count)


def _knot(key: str, k: int) -> float:
    return zlib.crc32(f"{_bctx.salt}:{key}:{k}".encode()) / 0x7FFFFFFF - 1.0


def _drift(key: str, t: int, period: int = 24) -> float:
    """Smooth pseudo-random drift in [-1, 1] of process value ``key`` at
    sample ``t`` (value noise: cosine-interpolated seeded knots), so a polled
    value wanders plausibly over a run yet is a pure function of the seed."""
    k, f = divmod(t, period)
    a, b = _knot(key, k), _knot(key, k + 1)
    return a + (b - a) * (1 - math.cos(math.pi * f / period)) / 2


# ---------------------------------------------------------------------------
# Shared encoders
# ---------------------------------------------------------------------------
def _der(tag: int, content: bytes) -> bytes:
    """One ASN.1 DER TLV (Kerberos, LDAP), long-form length when needed."""
    n = len(content)
    if n < 0x80:
        return bytes([tag, n]) + content
    ln = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(ln)]) + ln + content


def _der_int(v: int, tag: int = 0x02) -> bytes:
    return _der(tag, v.to_bytes((v.bit_length() + 8) // 8 or 1, "big",
                                signed=True))


def _der_seq(*items: bytes) -> bytes:
    return _der(0x30, b"".join(items))


def _ctx(n: int, content: bytes) -> bytes:
    """Explicit context tag [n] (constructed)."""
    return _der(0xA0 | n, content)


def _tpkt(payload: bytes) -> bytes:
    """ISO-on-TCP (RFC 1006) TPKT header, used by S7comm."""
    return struct.pack("!BBH", 0x03, 0x00, 4 + len(payload)) + payload


_COTP_DT = b"\x02\xf0\x80"          # COTP DT, TPDU-NR 0, last data unit


def _s7(rosctr: int, ref: int, param: bytes, data: bytes = b"") -> bytes:
    """S7comm PDU in COTP DT: Job(1)/Userdata(7) 10-byte header, Ack_Data(3)
    adds the 2-byte error class/code."""
    hdr = struct.pack("!BBHHHH", 0x32, rosctr, 0, ref & 0xFFFF, len(param),
                      len(data))
    if rosctr in (2, 3):
        hdr += b"\x00\x00"
    return _tpkt(_COTP_DT + hdr + param + data)


def _s7_connect() -> List[tuple[bytes, bytes]]:
    """COTP connect (TSAP rack 0 / slot 2) + S7 Setup Communication — how
    every S7 session opens before any read or SZL request."""
    params = b"\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x02"
    cr = _tpkt(struct.pack("!BBHHB", 6 + len(params), 0xE0, 0x0000, 0x0001,
                           0x00) + params)
    cc = _tpkt(struct.pack("!BBHHB", 6 + len(params), 0xD0, 0x0001, 0x0044,
                           0x00) + params)
    # Setup Communication: max AmQ calling/called 1, PDU length 480 -> 240
    setup = _s7(1, 0, struct.pack("!BBHHH", 0xF0, 0x00, 1, 1, 480))
    setup_ack = _s7(3, 0, struct.pack("!BBHHH", 0xF0, 0x00, 1, 1, 240))
    return [(cr, cc), (setup, setup_ack)]


def _enip(cmd: int, session: int, data: bytes, context: int = 0) -> bytes:
    """EtherNet/IP encapsulation header (24 bytes, little-endian)."""
    return struct.pack("<HHIIQI", cmd, len(data), session, 0, context, 0) + data


def _cpf(*items: tuple[int, bytes]) -> bytes:
    """EtherNet/IP Common Packet Format: item count + (type, length, data)."""
    return struct.pack("<H", len(items)) + b"".join(
        struct.pack("<HH", t, len(d)) + d for t, d in items)


# ===========================================================================
# OT / ICS protocols
# ===========================================================================
def modbus_flow(ep: Endpoints, count: int) -> List[bytes]:
    """Modbus/TCP (502): Read Holding Registers polling mixed with Read Input
    Registers (FC 4), Read Coils (FC 1) and Read Discrete Inputs (FC 2), an
    occasional Write Single Register (FC 6, echoed back) setpoint update — one
    request in eight, the fourth of each eight — and, once in sixteen, a read
    past the end of the register map answered by exception 0x83/0x02
    (Illegal Data Address). Behind a Modbus TCP -> RTU gateway the unit id
    addresses each serial slave in ``ep.meta['modbus_units']`` in turn."""
    exchanges = []
    cb, dev = _cycle_base(count), f"mb:{ep.server_ip}"
    units = [int(u) for u in ep.meta.get("modbus_units") or (1,)]
    for i in range(count):
        tid = (cb + i + 1) & 0xFFFF
        unit = units[(cb + i) % len(units)]
        if len(units) > 1:
            dev = f"mb:{ep.server_ip}:{unit}"
        if i % 8 == 3:
            # Write Single Register (FC 0x06): setpoint register 40101; the
            # normal response echoes the request exactly
            req = struct.pack("!HHHBBHH", tid, 0, 6, unit, 0x06, 100,
                              int(0x0200 + 32 * _drift(dev + ":sp", cb + i)))
            exchanges.append((req, req))
            continue
        if i % 16 == 9:
            # FC 3 beyond the mapped registers -> exception 0x83, code 0x02
            req = struct.pack("!HHHBBHH", tid, 0, 6, unit, 0x03, 9000, 10)
            exchanges.append((req, struct.pack("!HHHBBB", tid, 0, 3, unit,
                                               0x83, 0x02)))
            continue
        if i % 8 in (5, 7):
            # Read Coils (FC 1) / Read Discrete Inputs (FC 2): 16 bits
            fc = 0x01 if i % 8 == 5 else 0x02
            req = struct.pack("!HHHBBHH", tid, 0, 6, unit, fc, 0, 16)
            bits = struct.pack("<H", (0x00A5 + cb + i) & 0xFFFF)
            exchanges.append((req, struct.pack("!HHHBBB", tid, 0, 3 + 2, unit,
                                               fc, 2) + bits))
            continue
        # Read Holding Registers (FC 0x03) / Read Input Registers (FC 0x04):
        # start=0, qty=10
        fc = 0x04 if i % 8 == 2 else 0x03
        req = struct.pack("!HHHBB HH", tid, 0, 6, unit, fc, 0, 10)
        # Response: 10 registers (20 bytes) of drifting process values
        regvals = b"".join(
            struct.pack("!H", int(0x1000 + 0x80 * r +
                                  0x40 * _drift(f"{dev}:{fc}:{r}", cb + i)))
            for r in range(10))
        resp = struct.pack("!HHHBBB", tid, 0, 3 + len(regvals), unit,
                           fc, len(regvals)) + regvals
        exchanges.append((req, resp))
    return _tcp_flow(ep, _sport(), 502, exchanges)


def _dnp3_crc(data: bytes) -> bytes:
    """DNP3 link-layer CRC-16 (poly 0x3D65, reflected), little-endian."""
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return struct.pack("<H", ~crc & 0xFFFF)


def _dnp3_link(ctrl: int, dst: int, src: int, user: bytes) -> bytes:
    """DNP3 link frame: 0x0564 header + CRC, user data with a CRC after every
    16 bytes."""
    hdr = struct.pack("<BBBBHH", 0x05, 0x64, 5 + len(user), ctrl, dst, src)
    out = hdr + _dnp3_crc(hdr)
    for k in range(0, len(user), 16):              # CRC after every 16 bytes
        out += user[k:k + 16] + _dnp3_crc(user[k:k + 16])
    return out


def _dnp3_addrs(ep: Endpoints) -> tuple[int, int]:
    """(master, outstation) link addresses: ``ep.meta['dnp3_master']`` /
    ``['dnp3_outstation']``, default 10 / 1."""
    return (int(ep.meta.get("dnp3_master", 10)),
            int(ep.meta.get("dnp3_outstation", 1)))


def _dnp3_req(ep: Endpoints, seq: int, fc: int, objs: bytes) -> bytes:
    """A master -> outstation application request in one link frame."""
    master, out = _dnp3_addrs(ep)
    return _dnp3_link(0xC4, out, master, bytes([0xC0 | (seq & 0x3F),
                                                0xC0 | (seq & 0x0F), fc]) + objs)


def _dnp3_rsp(ep: Endpoints, seq: int, objs: bytes, fc: int = 0x81,
              ac_flags: int = 0xC0, iin: bytes = b"\x00\x00") -> bytes:
    """An outstation -> master response (``fc`` 0x81, or 0x82 unsolicited)."""
    master, out = _dnp3_addrs(ep)
    return _dnp3_link(0x44, master, out, bytes([0xC0 | (seq & 0x3F),
                                                ac_flags | (seq & 0x0F), fc]) +
                      iin + objs)


_DNP3_EPOCH_MS = 1791288000000      # 2026-10-06 12:00:00 UTC, DNP3 time base


def _dnp3_time(ms: int) -> bytes:
    """DNP3 48-bit absolute time (ms since 1970, little-endian)."""
    return struct.pack("<Q", ms)[:6]


def dnp3_flow(ep: Endpoints, count: int) -> List[bytes]:
    """DNP3 (20000): link frames (0x0564 + per-block CRCs) between a master and
    one outstation (link addresses from ``ep.meta['dnp3_master']`` /
    ``['dnp3_outstation']``, default 10 / 1). Each cycle of four: a class-0
    integrity READ answered by analog inputs (g30v2), a class-1 event poll
    answered by a time-stamped binary-input event (g2v2), a class-2/3 poll
    answered by an analog event (g32v2), and an unsolicited response carrying
    an event that the master confirms."""
    exchanges = []
    cb = _cycle_base(count)
    for i in range(count):
        k = i % 4
        if k == 0:
            read = b"\x3c\x01\x06"                  # READ g60v1 (class 0), all
            points = b"".join(struct.pack("<Bh", 0x01, int(
                1000 * (p + 1) + 200 * _drift(f"dnp3:{ep.server_ip}:{p}",
                                              cb + i)))
                for p in range(4))                  # flags ONLINE + int16
            resp = b"\x1e\x02\x00\x00\x03" + points   # g30v2, start-stop 0..3
        elif k == 1:
            read = b"\x3c\x02\x06"                  # class 1 events
            # g2v2 binary input event with absolute time, 1 event, 2-byte index
            resp = b"\x02\x02\x28\x01\x00" + struct.pack("<HB", i % 8, 0x81) + \
                _dnp3_time(_DNP3_EPOCH_MS + 1000 * (cb + i))
        elif k == 2:
            read = b"\x3c\x03\x06\x3c\x04\x06"      # class 2 + class 3 events
            # g32v2 16-bit analog input event without time
            resp = b"\x20\x02\x28\x01\x00" + struct.pack(
                "<HBh", i % 4, 0x01,
                int(1000 + 200 * _drift(f"dnp3ev:{ep.server_ip}", cb + i)))
        if k < 3:
            exchanges.append((_dnp3_req(ep, cb + i, 0x01, read),
                              _dnp3_rsp(ep, cb + i, resp)))
            continue
        # unsolicited response (UNS + CON) with one binary event; the master
        # answers with an Application Confirm echoing the sequence + UNS bit
        ev = b"\x02\x02\x28\x01\x00" + struct.pack("<HB", i % 8, 0x01) + \
            _dnp3_time(_DNP3_EPOCH_MS + 1000 * (cb + i) + 250)
        exchanges.append((b"", _dnp3_rsp(ep, cb + i, ev, fc=0x82, ac_flags=0xF0)))
        master, out = _dnp3_addrs(ep)
        confirm = _dnp3_link(0xC4, out, master, bytes([
            0xC0 | ((cb + i) & 0x3F), 0xD0 | ((cb + i) & 0x0F), 0x00]))
        exchanges.append((confirm, b""))
    return _tcp_flow(ep, _sport(), 20000, exchanges)


def enip_flow(ep: Endpoints, count: int) -> List[bytes]:
    """EtherNet/IP (44818): RegisterSession, unconnected CIP Get_Attribute_Single
    polls (Identity status) in SendRRData, then UnRegisterSession."""
    session = _rand32() | 1                        # target-assigned per session
    cb = _cycle_base(count)
    exchanges = [(_enip(0x0065, 0, struct.pack("<HH", 1, 0)),
                  _enip(0x0065, session, struct.pack("<HH", 1, 0)))]

    def rr(cip: bytes, ctx: int) -> bytes:      # SendRRData: handle, timeout
        return _enip(0x006F, session, struct.pack("<IH", 0, 10) +
                     _cpf((0x0000, b""), (0x00B2, cip)), context=ctx)

    for i in range(count):
        # Get_Attribute_Single, path class 0x01 / instance 1 / attribute 5
        req = bytes([0x0E, 0x03, 0x20, 0x01, 0x24, 0x01, 0x30, 0x05])
        rsp = bytes([0x8E, 0x00, 0x00, 0x00]) + struct.pack("<H", 0x0060)
        exchanges.append((rr(req, cb + i + 1), rr(rsp, cb + i + 1)))
    exchanges.append((_enip(0x0066, session, b""), b""))   # UnRegisterSession
    return _tcp_flow(ep, _sport(), 44818, exchanges)


def s7comm_flow(ep: Endpoints, count: int) -> List[bytes]:
    """S7comm (102): COTP connect, Setup Communication, then Read Var jobs on
    DB1 answered by Ack_Data with the bytes read."""
    exchanges = _s7_connect()
    cb = _cycle_base(count)
    for i in range(count):
        ref = cb + i + 1
        addr = (i * 10) << 3                       # byte offset, in bits
        item = b"\x12\x0a\x10\x02" + struct.pack("!HHB", 10, 1, 0x84) + \
            addr.to_bytes(3, "big")                # S7ANY: 10 BYTE of DB1
        job = _s7(1, ref, b"\x04\x01" + item)
        values = bytes(int(128 + 100 * _drift(f"s7:{ep.server_ip}:{i}:{v}",
                                              cb + i)) for v in range(10))
        ack = _s7(3, ref, b"\x04\x01",
                  b"\xff\x04" + struct.pack("!H", len(values) * 8) + values)
        exchanges.append((job, ack))
    return _tcp_flow(ep, _sport(), 102, exchanges)


def _iec104_u(ctrl: int) -> bytes:
    """IEC 104 U-format APDU: STARTDT 0x07/0x0B, STOPDT 0x13/0x23, TESTFR
    0x43/0x83 (act/con)."""
    return bytes([0x68, 4, ctrl, 0, 0, 0])


def _iec104_s(nr: int) -> bytes:
    """IEC 104 S-format acknowledgement of everything below ``nr``."""
    return struct.pack("<BBHH", 0x68, 4, 0x0001, nr << 1)


def _iec104_i(ns: int, nr: int, asdu: bytes) -> bytes:
    """IEC 104 I-format APDU carrying one ASDU."""
    return struct.pack("<BBHH", 0x68, 4 + len(asdu), ns << 1, nr << 1) + asdu


def _iec104_asdu(type_id: int, cot: int, ioa: int, element: bytes,
                 ca: int = 1) -> bytes:
    """One information object, COT + originator 0, common address ``ca``,
    3-byte IOA."""
    return struct.pack("<BBBBH", type_id, 1, cot, 0, ca) + \
        ioa.to_bytes(3, "little") + element


def _cp56(ms: int) -> bytes:
    """CP56Time2a for ``ms`` milliseconds after 2026-10-06 12:00:00 (a
    Tuesday), staying within that hour."""
    ms %= 3600000
    minute, msec = divmod(ms, 60000)
    return struct.pack("<HBBBBB", msec, minute, 12, (2 << 5) | 6, 10, 26)


def iec104_flow(ep: Endpoints, count: int) -> List[bytes]:
    """IEC 60870-5-104 (2404): STARTDT, a station interrogation answered with
    measured floats (M_ME_NC_1), then spontaneous values acked by S-frames —
    alternating plain floats with time-tagged single points (M_SP_TB_1) and
    floats (M_ME_TF_1) — and TESTFR act/con keep-alives on idle. The common
    address comes from ``ep.meta['common_address']`` (default 1)."""
    ca = int(ep.meta.get("common_address", 1))

    def asdu(type_id: int, cot: int, ioa: int, element: bytes) -> bytes:
        return _iec104_asdu(type_id, cot, ioa, element, ca)

    cb = _cycle_base(count)

    def value(i: int) -> bytes:                    # short float + QDS
        hz = 50.0 + 0.05 * _drift(f"104:{ep.server_ip}:{i % 4}", cb + i)
        return struct.pack("<fB", hz, 0x00)

    u, s, i_fr = _iec104_u, _iec104_s, _iec104_i
    gi = b"\x14"                                   # QOI 20: station
    exchanges = [(u(0x07), u(0x0B))]               # STARTDT act / con
    exchanges.append((
        i_fr(0, 0, asdu(100, 6, 0, gi)),           # C_IC_NA_1 activation
        i_fr(0, 1, asdu(100, 7, 0, gi)) +          # ... confirmation
        i_fr(1, 1, asdu(13, 20, 1001, value(0))) +   # interrogated value
        i_fr(2, 1, asdu(100, 10, 0, gi))))         # ... termination
    ns = 3
    for i in range(1, max(1, count)):
        k = i % 3
        if k == 1:                                 # M_ME_NC_1 spontaneous
            obj = asdu(13, 3, 1001 + i % 4, value(i))
        elif k == 2:                               # M_SP_TB_1: SIQ + time
            obj = asdu(30, 3, 2001 + i % 4, bytes([i & 1]) +
                       _cp56(1000 * i))
        else:                                      # M_ME_TF_1: float + time
            obj = asdu(36, 3, 1001 + i % 4, value(i) + _cp56(1000 * i + 20))
        exchanges.append((s(ns), i_fr(ns, 1, obj)))
        ns += 1
        if i % 4 == 0:                             # t3 idle: link test
            exchanges.append((u(0x43), u(0x83)))
    tested = exchanges[-1][0] == u(0x43)
    exchanges.append((s(ns), b""))
    if not tested:
        exchanges.append((u(0x43), u(0x83)))       # TESTFR act / con
    return _tcp_flow(ep, _sport(), 2404, exchanges)


def bacnet_flow(ep: Endpoints, count: int) -> List[bytes]:
    """BACnet/IP (47808/UDP): BVLC + NPDU + APDU ReadProperty of an
    analog-input's present-value, answered by a ComplexACK carrying the REAL."""
    def bvll(npdu: bytes, apdu: bytes) -> bytes:   # Original-Unicast-NPDU
        return struct.pack("!BBH", 0x81, 0x0A, 4 + len(npdu) + len(apdu)) + \
            npdu + apdu

    base = zlib.crc32(P.ip_to_bytes(ep.client_ip))
    cb = _cycle_base(count)
    frames = []
    for i in range(count):
        invoke = (base + cb + i) & 0xFF
        # context [0] object id analog-input:N, context [1] present-value (85)
        obj = b"\x0c" + struct.pack("!I", (0 << 22) | (1 + i % 4)) + b"\x19\x55"
        # Confirmed-Request, max-segs 0 / max-APDU 1476, invoke id, svc 12
        req = struct.pack("!BBBB", 0x00, 0x05, invoke, 0x0C) + obj
        # ComplexACK, same invoke id: [3] { REAL } property value
        ack = struct.pack("!BBB", 0x30, invoke, 0x0C) + obj + b"\x3e\x44" + \
            struct.pack("!f", 21.5 + 1.5 * _drift(
                f"bac:{ep.server_ip}:{1 + i % 4}", cb + i)) + b"\x3f"
        frames.append(P.udp_frame(ep, True, 47808, 47808,
                                  bvll(b"\x01\x04", req), ident=i))  # expect reply
        frames.append(P.udp_frame(ep, False, 47808, 47808,
                                  bvll(b"\x01\x00", ack), ident=i))
    return frames


_OID_SHA256_RSA = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b"
_OID_RSA = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"


def _cert_placeholder(cn: str, org: str) -> bytes:
    """A structurally valid, self-signed X.509 v3 certificate (DER) for
    ``CN=cn, O=org`` with a placeholder RSA-1024 key and signature — what an
    OPC UA server hands out as its application instance certificate."""
    seed = zlib.crc32(cn.encode())
    name = _der_seq(
        _der(0x31, _der_seq(b"\x06\x03\x55\x04\x0a", _der(0x0C, org.encode()))),
        _der(0x31, _der_seq(b"\x06\x03\x55\x04\x03", _der(0x0C, cn.encode()))))
    alg = _der_seq(_OID_SHA256_RSA, b"\x05\x00")
    modulus = b"\x00\xc5" + struct.pack(">I", seed) * 31 + b"\x01\x01"
    rsa = _der_seq(_der(0x02, modulus), _der_int(65537))
    spki = _der_seq(_der_seq(_OID_RSA, b"\x05\x00"), _der(0x03, b"\x00" + rsa))
    tbs = _der_seq(_der(0xA0, _der_int(2)), _der_int(seed | 1), alg, name,
                   _der_seq(_der(0x17, b"250101000000Z"),
                            _der(0x17, b"350101000000Z")), name, spki)
    sig = _der(0x03, b"\x00" + struct.pack(">I", seed ^ 0x5A5A5A5A) * 32)
    return _der_seq(tbs, alg, sig)


def opcua_flow(ep: Endpoints, count: int) -> List[bytes]:
    """OPC UA binary (4840): Hello/Acknowledge, OpenSecureChannel (policy None),
    GetEndpoints (the server lists a None and a Basic256Sha256 SignAndEncrypt
    endpoint with its certificate), CreateSession/ActivateSession (anonymous)
    exchanging client and server ApplicationDescriptions, Read requests for a
    process value, then CloseSession and CloseSecureChannel.

    The server's identity comes from ``ep.meta``: ``opcua_app_uri``,
    ``opcua_product_uri`` and ``opcua_app_name`` (defaults derived from
    ``host``); the client's from ``nbname``."""
    host = str(ep.meta.get("host", ep.server_ip))
    client = str(ep.meta.get("nbname", ep.client_ip))
    url = f"opc.tcp://{host}:4840".encode()
    policy = b"http://opcfoundation.org/UA/SecurityPolicy#None"
    b256 = b"http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
    null = struct.pack("<i", -1)                   # null String / ByteString
    ts = 134041248000000000                        # DateTime: 2025-10-06
    chan, token = 0x2000 + (zlib.crc32(url) & 0xFFF), 1

    def s(b: bytes) -> bytes:
        return struct.pack("<i", len(b)) + b

    def arr(items: List[bytes]) -> bytes:
        return struct.pack("<i", len(items)) + b"".join(items)

    def chunk(kind: bytes, body: bytes) -> bytes:
        return kind + b"F" + struct.pack("<I", 8 + len(body)) + body

    def nid(n: int, ns: int = 0) -> bytes:         # four-byte NodeId
        return struct.pack("<BBH", 0x01, ns, n)

    auth = nid(0x7A00 | (zlib.crc32(client.encode()) & 0xFF), ns=1)

    def req_hdr(handle: int, tok: bytes = b"\x00\x00") -> bytes:
        # token, time, handle, diag, audit, timeout, additional header
        return tok + struct.pack("<qII", ts, handle, 0) + null + \
            struct.pack("<I", 10000) + b"\x00\x00\x00"

    def rsp_hdr(handle: int) -> bytes:   # time, handle, result, diag, strings, ext
        return struct.pack("<qII", ts, handle, 0) + b"\x00" + null + \
            b"\x00\x00\x00"

    def asym(seq: int, body: bytes) -> bytes:
        return chunk(b"OPN", struct.pack("<I", chan if seq > 1 else 0) +
                     s(policy) + null + null + struct.pack("<II", 1, 1) + body)

    def sym(kind: bytes, seq: int, req_id: int, body: bytes) -> bytes:
        return chunk(kind, struct.pack("<IIII", chan, token, seq, req_id) + body)

    def app_desc(uri: str, product: str, name: str, app_type: int,
                 disc: List[bytes]) -> bytes:
        return s(uri.encode()) + s(product.encode()) + b"\x02" + \
            s(name.encode()) + struct.pack("<i", app_type) + null + null + \
            arr(disc)

    server = app_desc(
        str(ep.meta.get("opcua_app_uri", f"urn:{host}:UA:Server")),
        str(ep.meta.get("opcua_product_uri", "urn:tgt:opcua:server")),
        str(ep.meta.get("opcua_app_name", f"{host} OPC UA Server")), 0,
        [s(url)])
    cert = _cert_placeholder(host, str(ep.meta.get("opcua_org", "TGT")))
    transport = b"http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary"

    def token_policy(pid: bytes, kind: int, pol: bytes) -> bytes:
        return s(pid) + struct.pack("<i", kind) + null + null + \
            (s(pol) if pol else null)

    def endpoint(mode: int, pol: bytes, level: int) -> bytes:
        return s(url) + server + s(cert) + struct.pack("<i", mode) + \
            s(pol) + arr([token_policy(b"Anonymous", 0, b""),
                          token_policy(b"UserName", 1, b256)]) + \
            s(transport) + bytes([level])

    endpoints = arr([endpoint(1, policy, 0), endpoint(3, b256, 3)])

    hel = chunk(b"HEL", struct.pack("<IIIII", 0, 65535, 65535, 0, 0) + s(url))
    ack = chunk(b"ACK", struct.pack("<IIIII", 0, 65535, 65535, 2097152, 0))
    opn = asym(1, nid(446) + req_hdr(1) + struct.pack("<III", 0, 0, 1) +
               s(b"") + struct.pack("<I", 3600000))
    opn_rsp = asym(2, nid(449) + rsp_hdr(1) + struct.pack("<I", 0) +
                   struct.pack("<IIqI", chan, token, ts, 3600000) + s(b""))
    exchanges = [(hel, ack), (opn, opn_rsp)]
    # GetEndpoints
    exchanges.append((
        sym(b"MSG", 2, 2, nid(428) + req_hdr(2) + s(url) + arr([]) + arr([])),
        sym(b"MSG", 2, 2, nid(431) + rsp_hdr(2) + endpoints)))
    # CreateSession: client ApplicationDescription in, server endpoints out
    nonce = struct.pack("<I", zlib.crc32(client.encode())) * 8
    cdesc = app_desc(f"urn:{client}:UA:Client", "urn:tgt:opcua:client",
                     f"{client} OPC UA Client", 1, [])
    exchanges.append((
        sym(b"MSG", 3, 3, nid(461) + req_hdr(3) + cdesc + null + s(url) +
            s(f"{client} Session1".encode()) + s(nonce) + null +
            struct.pack("<dI", 1200000.0, 0)),
        sym(b"MSG", 3, 3, nid(464) + rsp_hdr(3) + nid(0x5E00 | (chan & 0xFF),
                                                        ns=1) + auth +
            struct.pack("<d", 1200000.0) + s(nonce[::-1]) + s(cert) +
            endpoints + arr([]) + null + null + struct.pack("<I", 0))))
    # ActivateSession: anonymous identity token
    anon = s(b"Anonymous")
    ident = nid(321) + b"\x01" + struct.pack("<i", len(anon)) + anon
    exchanges.append((
        sym(b"MSG", 4, 4, nid(467) + req_hdr(4, auth) + null + null +
            arr([]) + arr([s(b"en-US")]) + ident + null + null),
        sym(b"MSG", 4, 4, nid(470) + rsp_hdr(4) + s(nonce) + arr([]) +
            arr([]))))
    base = 5
    for i in range(count):
        seq = h = base + i
        node = nid(1001 + i % 8, ns=2) + struct.pack("<I", 13) + null + \
            struct.pack("<H", 0) + null            # Value attr, no range/encoding
        read = sym(b"MSG", seq, h, nid(631) + req_hdr(h, auth) +
                   struct.pack("<dIi", 0.0, 2, 1) + node)
        dv = b"\x01\x0b" + struct.pack("<d", 72.5 + i)   # DataValue: Double
        rsp = sym(b"MSG", seq, h, nid(634) + rsp_hdr(h) +
                  struct.pack("<i", 1) + dv + struct.pack("<i", 0))
        exchanges.append((read, rsp))
    n = base + count
    exchanges.append((sym(b"MSG", n, n, nid(473) + req_hdr(n, auth) + b"\x01"),
                      sym(b"MSG", n, n, nid(476) + rsp_hdr(n))))
    n += 1
    exchanges.append((sym(b"CLO", n, n, nid(452) + req_hdr(n, auth)), b""))
    return _tcp_flow(ep, _sport(), 4840, exchanges)


# ===========================================================================
# IT / infrastructure protocols (background noise, discovery, baselining)
# ===========================================================================
def arp_flow(ep: Endpoints, count: int) -> List[bytes]:
    """Gratuitous ARP announcements + who-has requests."""
    frames = []
    for i in range(count):
        # who-has server_ip? tell client_ip  (broadcast)
        who = P.arp(1, ep.client_mac, ep.client_ip,
                    "00:00:00:00:00:00", ep.server_ip)
        frames.append(P.ethernet("ff:ff:ff:ff:ff:ff", ep.client_mac,
                                  P.ETH_P_ARP, who, vlan=ep.vlan))
        # is-at reply
        isat = P.arp(2, ep.server_mac, ep.server_ip,
                     ep.client_mac, ep.client_ip)
        frames.append(P.ethernet(ep.client_mac, ep.server_mac,
                                  P.ETH_P_ARP, isat, vlan=ep.vlan))
    return frames


_PING_DATA = b"abcdefghijklmnopqrstuvwabcdefghi"   # Windows ping.exe


def icmp_flow(ep: Endpoints, count: int) -> List[bytes]:
    """ICMP echo request/reply (ping sweep style)."""
    frames, cb = [], _cycle_base(count)
    for i in range(count):
        req = P.icmp_echo(0x1234, cb + i, _PING_DATA)
        frames.append(P.ip_frame(ep, True, P.IPPROTO_ICMP, req, ident=i))
        rep = struct.pack("!BBHHH", 0, 0, 0, 0x1234, (cb + i) & 0xFFFF) + \
            _PING_DATA
        chk = P.checksum16(rep)
        rep = rep[:2] + struct.pack("!H", chk) + rep[4:]
        frames.append(P.ip_frame(ep, False, P.IPPROTO_ICMP, rep, ident=i))
    return frames


def dns_flow(ep: Endpoints, count: int,
             names: List[tuple[str, str]] | None = None) -> List[bytes]:
    """DNS (53/UDP): A-record query + response, each from one client port.

    ``names`` (or ``ep.meta['dns_names']``) is a list of ``(fqdn, ipv4)`` pairs
    the client resolves in turn, so a monitor can learn hostname -> IP from the
    answers (an environment passes its real inventory names). Without it the
    client looks up ``plcN.ot.local`` names that resolve into its own /24.
    """
    def qname(name: str) -> bytes:
        out = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
        return out + b"\x00"

    names = names or ep.meta.get("dns_names")
    if not names:
        net = ep.client_ip.rsplit(".", 1)[0]
        names = [(f"plc{n}.ot.local", f"{net}.{100 + n}") for n in range(5)]
    base = zlib.crc32(P.ip_to_bytes(ep.client_ip))
    cb = _cycle_base(count)
    frames = []
    for i in range(count):
        name, addr = names[i % len(names)]
        tid = (base + (cb + i) * 0x9E5) & 0xFFFF
        sport = _sport()                           # one port per transaction
        q = qname(name) + struct.pack("!HH", 1, 1)
        query = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + q
        frames.append(P.udp_frame(ep, True, sport, 53, query, ident=i))
        ans = struct.pack("!HHHHHH", tid, 0x8180, 1, 1, 0, 0) + q + \
            struct.pack("!HHHIH4s", 0xC00C, 1, 1, 60, 4, P.ip_to_bytes(addr))
        frames.append(P.udp_frame(ep, False, 53, sport, ans, ident=i))
    return frames


def http_flow(ep: Endpoints, count: int) -> List[bytes]:
    """HTTP (80): GET request + 200 OK.

    The User-Agent comes from ``ep.meta['ua']`` when set, so a client's browser
    and OS (e.g. MSIE 6.0 on Windows XP) is fingerprintable on the wire.
    """
    ua = ep.meta.get("ua", "TGT-Traffic-Gen")
    host = ep.meta.get("host", ep.server_ip)
    server_banner = ep.meta.get("server", "Apache")
    exchanges = []
    for i in range(count):
        path = ep.meta.get("path", f"/status?poll={i}")
        req = (f"GET {path} HTTP/1.1\r\n"
               f"Host: {host}\r\n"
               f"User-Agent: {ua}\r\n"
               "Accept: */*\r\n\r\n").encode()
        body = f'{{"tag":"AI-{i}","value":{i * 3}}}'.encode()
        resp = (f"HTTP/1.1 200 OK\r\nServer: {server_banner}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n\r\n").encode() + body
        exchanges.append((req, resp))
    sport = _sport()
    return _tcp_flow(ep, sport, 80, exchanges,
                     abort=_aborts(ep, sport, 80))


# ---------------------------------------------------------------------------
# Enterprise IT protocols (identity / fingerprint bearing)
# ---------------------------------------------------------------------------
def smb_flow(ep: Endpoints, count: int) -> List[bytes]:
    """SMB (445): NEGOTIATE, then ECHO keep-alives.

    Legacy hosts advertise only SMBv1 ("NT LM 0.12"), which flags them as
    exposed to MS17-010 / EternalBlue; modern hosts negotiate SMB 3.0.2. Driven
    by ``ep.meta['smb']`` = "smb1" | "smb2" (default smb2).
    """
    def nbss(payload: bytes) -> bytes:           # session message + 24-bit len
        return struct.pack("!I", len(payload)) + payload

    systime = 134041248000000000                   # FILETIME 2025-10-06
    dialect = ep.meta.get("smb", "smb2")
    exchanges = []
    if dialect == "smb1":
        def hdr(cmd: int, flags: int, mid: int) -> bytes:
            # cmd, status, flags, flags2 (unicode|NT status|long names) ...
            return b"\xffSMB" + struct.pack("<BIBH", cmd, 0, flags, 0xC853) + \
                struct.pack("<H8sHHHHH", 0, bytes(8), 0, 0, 0xFEFF, 0, mid)

        dialects = b"\x02NT LM 0.12\x00\x02LANMAN2.1\x00"
        domain = ep.meta.get("realm", "CORP.LOCAL").split(".")[0]
        names = (domain + "\x00" + ep.meta.get("host", "SERVER").upper() +
                 "\x00").encode("utf-16-le")
        neg = hdr(0x72, 0x18, 1) + struct.pack("<BH", 0, len(dialects)) + \
            dialects
        # WordCount 17: dialect 0, user-level + challenge auth, no ext. sec.
        neg_rsp = hdr(0x72, 0x98, 1) + struct.pack(
            "<BHBHHIIIIQhB", 17, 0, 0x03, 50, 1, 16644, 65536, 0,
            0x0000E3FD, systime, 0, 8) + \
            struct.pack("<H", 8 + len(names)) + b"\x11\x22\x33\x44\x55\x66\x77\x88" + names
        exchanges.append((nbss(neg), nbss(neg_rsp)))
        for i in range(max(0, count - 1)):
            data = b"tgt-echo"
            echo = hdr(0x2B, 0x18, i + 2) + struct.pack("<BHH", 1, 1, len(data)) + data
            echo_rsp = hdr(0x2B, 0x98, i + 2) + struct.pack("<BHH", 1, 1, len(data)) + data
            exchanges.append((nbss(echo), nbss(echo_rsp)))
    else:
        def hdr(cmd: int, mid: int, resp: bool) -> bytes:
            return b"\xfeSMB" + struct.pack(
                "<HHIHHIIQIIQ", 64, 0, 0, cmd, 1, 1 if resp else 0, 0, mid,
                0xFEFF, 0, 0) + bytes(16)

        dialects = (0x0202, 0x0210, 0x0300, 0x0302)
        guid = bytes(10) + P.mac_to_bytes(ep.client_mac)
        neg = hdr(0, 0, False) + struct.pack(
            "<HHHHI16sQ", 36, len(dialects), 0x01, 0, 0x7F, guid, 0) + \
            struct.pack(f"<{len(dialects)}H", *dialects)
        sguid = bytes(10) + P.mac_to_bytes(ep.server_mac)
        neg_rsp = hdr(0, 0, True) + struct.pack(
            "<HHHH16sIIIIQQHHI", 65, 0x01, 0x0302, 0, sguid, 0x2F,
            8388608, 8388608, 8388608, systime, 0, 0x80, 0, 0)
        exchanges.append((nbss(neg), nbss(neg_rsp)))
        for i in range(max(0, count - 1)):
            echo = struct.pack("<HH", 4, 0)
            exchanges.append((nbss(hdr(0x0D, i + 1, False) + echo),
                              nbss(hdr(0x0D, i + 1, True) + echo)))
    return _tcp_flow(ep, _sport(), 445, exchanges)


def _krb_principal(name_type: int, *parts: str) -> bytes:
    return _der_seq(_ctx(0, _der_int(name_type)),
                    _ctx(1, _der_seq(*(_der(0x1B, p.encode()) for p in parts))))


def kerberos_flow(ep: Endpoints, count: int) -> List[bytes]:
    """Kerberos (88/TCP): AS-REQ and the DC's KRB-ERROR PREAUTH_REQUIRED.

    A Windows client's first AS-REQ carries no pre-authentication and the DC
    answers KDC_ERR_PREAUTH_REQUIRED (25) — the opening move of every domain
    logon. Classifiers key on port 88, the realm and the client principal.
    """
    realm = ep.meta.get("realm", "CORP.LOCAL")
    host = ep.meta.get("nbname")
    cname = f"{host}$" if host else "user"         # computer account logon
    exchanges = []
    for i in range(count):
        body = _der_seq(
            _ctx(0, _der(0x03, b"\x00\x40\x81\x00\x10")),   # kdc-options
            _ctx(1, _krb_principal(1, cname)),              # NT-PRINCIPAL
            _ctx(2, _der(0x1B, realm.encode())),
            _ctx(3, _krb_principal(2, "krbtgt", realm)),    # NT-SRV-INST
            _ctx(5, _der(0x18, b"20370913024805Z")),        # till
            _ctx(7, _der_int(0x1A2B3C00 + i)),              # nonce
            _ctx(8, _der_seq(_der_int(18), _der_int(17), _der_int(23))))
        req = _der(0x6A, _der_seq(_ctx(1, _der_int(5)), _ctx(2, _der_int(10)),
                                  _ctx(4, body)))
        err = _der(0x7E, _der_seq(
            _ctx(0, _der_int(5)), _ctx(1, _der_int(30)),
            _ctx(4, _der(0x18, b"20261006120000Z")), _ctx(5, _der_int(i * 1000)),
            _ctx(6, _der_int(25)),                          # PREAUTH_REQUIRED
            _ctx(9, _der(0x1B, realm.encode())),
            _ctx(10, _krb_principal(2, "krbtgt", realm))))
        exchanges.append((struct.pack("!I", len(req)) + req,
                          struct.pack("!I", len(err)) + err))
    return _tcp_flow(ep, _sport(), 88, exchanges)


def ldap_flow(ep: Endpoints, count: int) -> List[bytes]:
    """LDAP (389): simple bind, rootDSE searches, unbind.

    The rootDSE query (defaultNamingContext, dnsHostName) is how domain members
    locate AD; the bind DN carries the client's identity.
    """
    dn = ep.meta.get("dn", "CN=svc,DC=corp,DC=local").encode()
    at = dn.upper().find(b"DC=")
    naming = dn[at:] if at >= 0 else b""
    fqdn = ep.meta.get("sni", ep.meta.get("host", "dc01.corp.local")).encode()

    def msg(mid: int, op: bytes) -> bytes:
        return _der_seq(_der_int(mid), op)

    def result(tag: int) -> bytes:                 # success, no DN, no message
        return _der(tag, _der(0x0A, b"\x00") + _der(0x04, b"") + _der(0x04, b""))

    def attr(name: bytes, val: bytes) -> bytes:    # PartialAttribute
        return _der_seq(_der(0x04, name), _der(0x31, _der(0x04, val)))

    bind = msg(1, _der(0x60, _der_int(3) + _der(0x04, dn) + _der(0x80, b"")))
    exchanges = [(bind, msg(1, result(0x61)))]
    for i in range(count):
        mid = i + 2
        search = msg(mid, _der(0x63,
            _der(0x04, b"") + _der(0x0A, b"\x00") + _der(0x0A, b"\x00") +
            _der_int(0) + _der_int(0) + _der(0x01, b"\x00") +
            _der(0x87, b"objectClass") +           # filter: (objectClass=*)
            _der_seq(_der(0x04, b"defaultNamingContext"),
                     _der(0x04, b"dnsHostName"))))
        entry = msg(mid, _der(0x64, _der(0x04, b"") + _der_seq(
            attr(b"defaultNamingContext", naming), attr(b"dnsHostName", fqdn))))
        exchanges.append((search, entry + msg(mid, result(0x65))))
    exchanges.append((msg(count + 2, _der(0x42, b"")), b""))   # unbind
    return _tcp_flow(ep, _sport(), 389, exchanges)


def https_flow(ep: Endpoints, count: int) -> List[bytes]:
    """HTTPS (443): one TLS handshake, then ``count`` encrypted requests.

    The ClientHello follows the client's TLS stack (``ep.meta['tls_client']``,
    a :data:`tgt.tls.TEMPLATES` key: Chrome, Firefox, SChannel 10/7/XP/2000,
    OpenSSL, Falcon; default Chrome), so JA3/JA4 identify the client OS and
    software; the SNI is ``ep.meta['sni']``. The server
    (``ep.meta['tls_server']``: openssl | schannel | schannel-legacy |
    embedded) answers consistently — TLS 1.3 when both sides support it, else
    TLS 1.2/1.0 with a certificate whose CN is the SNI — or refuses an
    unsupported client with a fatal alert.
    """
    from . import tls
    sni = ep.meta.get("sni", ep.meta.get("host", "server.corp.local"))
    tpl = tls.TEMPLATES.get(ep.meta.get("tls_client", ""),
                            tls.TEMPLATES["chrome"])
    srv = tls.SERVERS.get(ep.meta.get("tls_server", ""),
                          tls.SERVERS["openssl"])
    sport = _sport()
    exchanges, handshake = tls.session(
        tpl, srv, sni, count,
        (ep.client_ip, ep.server_ip, sport, ep.meta.get("cycle", "")))
    return _tcp_flow(ep, sport, 443, exchanges, idle_from=handshake,
                     abort=(tpl.key in ("chrome", "firefox")
                            and _aborts(ep, sport, 443)))


def edr_flow(ep: Endpoints, count: int) -> List[bytes]:
    """CrowdStrike Falcon EDR telemetry: the sensor's outbound TLS channel to
    the CrowdStrike Security Cloud.

    It is an ordinary HTTPS/TLS session; the EDR tell is the SNI — a CrowdStrike
    cloud host (``*.cloudsink.net`` for the sensor channel, ``*.crowdstrike.com``
    for API/console). CrowdStrike publishes connectivity by FQDN (its cloud is
    AWS-hosted with dynamic IPs), so the SNI is what a sensor fingerprints EDR
    traffic on. Set the host via ``ep.meta['sni']``; defaults to the US-1 sensor
    proxy."""
    meta = dict(ep.meta)
    if not meta.get("sni") and not meta.get("domain"):
        meta["sni"] = "ts01-b.cloudsink.net"
    meta.setdefault("tls_client", "falcon")
    return https_flow(replace(ep, meta=meta), count)


def dhcp_flow(ep: Endpoints, count: int) -> List[bytes]:
    """DHCP (67/68): a full DORA lease, then unicast renewals.

    Discover/Request leave the client as 0.0.0.0:68 -> 255.255.255.255:67 (MAC
    ff:ff:ff:ff:ff:ff) carrying option 12 (host name — a primary naming source
    for passive monitors), 61 (client id), 50 (requested IP), 55 (parameter
    request list) and 60 (vendor class, e.g. "MSFT 5.0", omitted when
    ``ep.meta['dhcp_vendor']`` is empty) — the OS fingerprint. Offer/ACK assign
    the client its address (yiaddr) with options 54/51/58/59/1/3/6. Optional
    meta: ``nbname`` (host name), ``dhcp_router``, ``dhcp_mask``,
    ``dhcp_dns``, ``dhcp_domain`` and ``dhcp_relay`` (giaddr of a relay agent).
    """
    vendor = ep.meta.get("dhcp_vendor", "MSFT 5.0").encode()
    hostname = ep.meta.get("nbname", "WORKSTATION").encode()
    router = ep.meta.get("dhcp_router",
                         ep.client_ip.rsplit(".", 1)[0] + ".1")
    mask = ep.meta.get("dhcp_mask", "255.255.255.0")
    dns = ep.meta.get("dhcp_dns", ep.server_ip)
    domain = ep.meta.get("dhcp_domain", "").encode()
    giaddr = ep.meta.get("dhcp_relay", "0.0.0.0")
    mac = P.mac_to_bytes(ep.client_mac)
    you, sid = P.ip_to_bytes(ep.client_ip), P.ip_to_bytes(ep.server_ip)

    def opt(code: int, data: bytes) -> bytes:
        return bytes([code, len(data)]) + data

    def msg(op: int, xid: int, opts: bytes, ciaddr: bytes = bytes(4),
            yiaddr: bytes = bytes(4), relay: str = "0.0.0.0") -> bytes:
        body = struct.pack("!BBBBIHH", op, 1, 6, 0, xid, 0, 0) + ciaddr + yiaddr + bytes(4) + \
            P.ip_to_bytes(relay) + mac + bytes(10) + bytes(192) + \
            struct.pack("!I", 0x63825363) + opts + b"\xff"   # magic cookie
        return body.ljust(300, b"\x00")            # BOOTP minimum size

    def broadcast(payload: bytes, ident: int) -> bytes:
        seg = P.udp("0.0.0.0", "255.255.255.255", 68, 67, payload)
        pkt = P.ipv4("0.0.0.0", "255.255.255.255", P.IPPROTO_UDP, seg,
                     ttl=ep.ttl_client, ident=ident)
        return P.ethernet("ff:ff:ff:ff:ff:ff", ep.client_mac, P.ETH_P_IP, pkt,
                          vlan=ep.vlan)

    cid, host = opt(61, b"\x01" + mac), opt(12, hostname)
    fingerprint = (opt(60, vendor) if vendor else b"") + \
        opt(55, b"\x01\x03\x06\x0f\x1f\x21\x2b\x2c")
    lease = opt(54, sid) + opt(51, struct.pack("!I", 691200)) + \
        opt(58, struct.pack("!I", 345600)) + opt(59, struct.pack("!I", 604800)) + \
        opt(1, P.ip_to_bytes(mask)) + opt(3, P.ip_to_bytes(router)) + \
        opt(6, P.ip_to_bytes(dns)) + (opt(15, domain) if domain else b"")
    seed = zlib.crc32(mac)
    frames = []
    for i in range(count):
        xid = (seed + i * 0x9E3779B1) & 0xFFFFFFFF
        if i == 0:                                 # DORA: Discover/Offer/Request/ACK
            disc = msg(1, xid, opt(53, b"\x01") + cid + opt(50, you) + host +
                       fingerprint)
            frames.append(broadcast(disc, 0))
            frames.append(P.udp_frame(ep, False, 67, 68, msg(
                2, xid, opt(53, b"\x02") + lease, yiaddr=you, relay=giaddr)))
            req = msg(1, xid, opt(53, b"\x03") + cid + opt(50, you) +
                      opt(54, sid) + host + fingerprint)
            frames.append(broadcast(req, 1))
        else:                                      # T1 renewal, unicast to server
            req = msg(1, xid, opt(53, b"\x03") + cid + host + fingerprint,
                      ciaddr=you)
            frames.append(P.udp_frame(ep, True, 68, 67, req, ident=i + 1))
        frames.append(P.udp_frame(ep, False, 67, 68, msg(
            2, xid, opt(53, b"\x05") + lease, ciaddr=you if i else bytes(4),
            yiaddr=you, relay=giaddr if i == 0 else "0.0.0.0"), ident=i))
    return frames


# NetBIOS OS version (major, minor) a Browser host announcement states, by
# OS fingerprint key (Samba announces 6.1); servers set SV_TYPE_SERVER_NT
_NB_OS_VERSION = {"win10": (10, 0), "win2019": (10, 0), "win2012": (6, 3),
                  "win7": (6, 1), "winxp": (5, 1), "win2000": (5, 0)}
_NB_SERVER_OS = {"win2019", "win2012", "win2000"}


def _nb_encode(name: str, suffix: int) -> bytes:
    """NetBIOS first-level encoded name (RFC 1001 §14.1) with its suffix."""
    raw = name.upper()[:15].ljust(15).encode("ascii", "replace") + \
        bytes([suffix & 0xFF])
    return b"\x20" + b"".join(bytes([(c >> 4) + 0x41, (c & 0x0F) + 0x41])
                              for c in raw) + b"\x00"


def _host_announcement(name: str, workgroup: str, os_key: str, src_ip: str,
                       dgm_id: int, update: int) -> bytes:
    """NetBIOS datagram (138/UDP, DIRECT_GROUP to WORKGROUP<1D>) carrying a
    [MS-BRWS] HostAnnouncement on \\MAILSLOT\\BROWSE: server name, OS
    version, server-type flags, 12-minute periodicity."""
    major, minor = _NB_OS_VERSION.get(os_key, (6, 1))
    stype = 0x00011003                  # workstation, server, NT wks, pot. browser
    if os_key in _NB_SERVER_OS:
        stype |= 0x00008000             # NT server
    comment = b"Samba" if os_key == "linux" else b""
    ann = struct.pack("<BBI", 0x01, update & 0xFF, 720000) + \
        name.upper()[:15].encode("ascii", "replace").ljust(16, b"\x00") + \
        struct.pack("<BBIBBH", major, minor, stype, 15, 1, 0xAA55) + \
        comment + b"\x00"
    mailslot = b"\\MAILSLOT\\BROWSE\x00"
    off = 32 + 1 + 17 * 2 + 2 + len(mailslot)       # data offset from SMB hdr
    smb = b"\xffSMB" + bytes([0x25]) + bytes(27) + bytes([17]) + \
        struct.pack("<HHHHBBHIHHHHHBB", 0, len(ann), 0, 0, 0, 0, 0, 0, 0,
                    0, off, len(ann), off, 3, 0) + \
        struct.pack("<HHH", 1, 1, 2) + \
        struct.pack("<H", len(mailslot) + len(ann)) + mailslot + ann
    names = _nb_encode(name, 0x00) + _nb_encode(workgroup, 0x1D)
    return struct.pack("!BBH4sHHH", 0x11, 0x02, dgm_id & 0xFFFF,
                       P.ip_to_bytes(src_ip), 138, len(names) + len(smb), 0) + \
        names + smb


def netbios_flow(ep: Endpoints, count: int) -> List[bytes]:
    """NetBIOS name registration (137/UDP) and Browser host announcement
    (138/UDP) carrying the host name and OS version.

    Both are B-node broadcasts from the announcing host (``client``) to its
    subnet broadcast (``ep.meta['bcast']``, else the /24) and
    ff:ff:ff:ff:ff:ff — they stay in the sender's VLAN and nobody answers.
    The first message registers the name; every message carries a host
    announcement — a classic passive fingerprint source.
    """
    name = str(ep.meta.get("nbname", "WORKSTATION")).upper()[:15]
    workgroup = str(ep.meta.get("realm", "WORKGROUP")).split(".")[0].upper()
    os_key = str(ep.meta.get("nb_os", ""))
    bcast = ep.meta.get("bcast") or \
        ".".join(ep.client_ip.split(".")[:3] + ["255"])

    def send(sport: int, payload: bytes, ident: int) -> bytes:
        seg = P.udp(ep.client_ip, bcast, sport, sport, payload)
        pkt = P.ipv4(ep.client_ip, bcast, P.IPPROTO_UDP, seg,
                     ttl=ep.ttl_client, ident=ident, df=False)
        return P.ethernet("ff:ff:ff:ff:ff:ff", ep.client_mac, P.ETH_P_IP,
                          pkt, vlan=ep.vlan)

    frames, cb = [], _cycle_base(count)
    for i in range(count):
        n = cb + i
        if i == 0:                      # name registration (B-node, unique)
            pkt = struct.pack("!HHHHHH", (0x8000 + n) & 0xFFFF, 0x2910, 1,
                              0, 0, 1) + _nb_encode(name, 0x00) + \
                struct.pack("!HH", 0x0020, 0x0001) + \
                struct.pack("!HHHIHH4s", 0xC00C, 0x0020, 0x0001, 300000, 6,
                            0x0000, P.ip_to_bytes(ep.client_ip))
            frames.append(send(137, pkt, 2 * i))
        frames.append(send(138, _host_announcement(
            name, workgroup, os_key, ep.client_ip, 0x4000 + n, n),
            2 * i + 1))
    return frames


def ntp_flow(ep: Endpoints, count: int) -> List[bytes]:
    """NTP (123/UDP): client polls (64 s apart) + a synchronised server's
    replies with consistent timestamps (origin = the client's transmit time).

    Times derive from a fixed epoch (2026-10-06 12:00 UTC) plus a per-client
    offset so builds stay deterministic. The server is stratum 2 referencing a
    public stratum-1 clock (``ep.meta['ntp_stratum']`` / ``['ntp_refid']``).
    """
    stratum = int(ep.meta.get("ntp_stratum", 2))
    refid = P.ip_to_bytes(ep.meta.get("ntp_refid", "129.6.15.28"))  # NIST
    t0 = _NTP_EPOCH + zlib.crc32(P.ip_to_bytes(ep.client_ip)) % 3600

    def ts(sec: float) -> bytes:                   # 32.32 fixed-point
        whole = int(sec)
        return struct.pack("!II", whole & 0xFFFFFFFF,
                           int((sec - whole) * 2 ** 32) & 0xFFFFFFFF)

    frames, cb = [], _cycle_base(count)
    for i in range(count):
        t1 = t0 + 64 * (cb + i) + 0.137 * (i % 7)  # client transmit
        t2 = t1 + 0.000412                         # server receive
        t3 = t2 + 0.000031                         # server transmit
        sport = _sport()                           # one port per transaction
        # LI 0, VN 3, mode 3 (client); poll 2^6, precision 2^-20
        req = struct.pack("!BBbb", 0x1B, 0, 6, -20) + bytes(12) + \
            bytes(24) + ts(t1)
        frames.append(P.udp_frame(ep, True, sport, 123, req, ident=i))
        # LI 0, VN 3, mode 4 (server); root delay/dispersion in 16.16 seconds
        resp = struct.pack("!BBbb", 0x1C, stratum, 6, -23) + \
            struct.pack("!II", 0x0000034F, 0x00000A3D) + refid + \
            ts(t1 - 312.5) + ts(t1) + ts(t2) + ts(t3)
        frames.append(P.udp_frame(ep, False, 123, sport, resp, ident=i))
    return frames


_NTP_EPOCH = 4000276800        # 2026-10-06 12:00:00 UTC in NTP-era seconds


# ---------------------------------------------------------------------------
# OT asset-identity / fingerprint flows (vendor + model strings)
# ---------------------------------------------------------------------------
def enip_identity_flow(ep: Endpoints, count: int) -> List[bytes]:
    """EtherNet/IP (44818): List Identity carrying a Rockwell/Allen-Bradley
    product name — what a monitor reads to inventory the PLC vendor and model.

    Per-device identity comes from ``ep.meta`` (see ``tgt.devices``):
    ``cip_product_code``, ``cip_revision`` (major, minor) and ``cip_serial``;
    without them it reports product code 55, revision 20.11 and a serial
    derived from the server MAC."""
    ident, attrs = _enip_identity_item(ep)
    exchanges = []
    for i in range(count):
        exchanges.append((_enip(0x0063, 0, b"", context=i + 1),
                          _enip(0x0063, 0, _cpf((0x000C, ident)),
                                context=i + 1)))
    # explicit messaging: Get_Attribute_All on the Identity object (class 1,
    # instance 1) inside a registered session
    session = 0x23450000 | (zlib.crc32(P.ip_to_bytes(ep.client_ip)) & 0xFFFF)
    exchanges.append((_enip(0x0065, 0, struct.pack("<HH", 1, 0)),
                      _enip(0x0065, session, struct.pack("<HH", 1, 0))))
    ctx = count + 1
    exchanges.append((
        _enip_rr(session, bytes([0x01, 0x02, 0x20, 0x01, 0x24, 0x01]), ctx),
        _enip_rr(session, bytes([0x81, 0x00, 0x00, 0x00]) + attrs, ctx)))
    exchanges.append((_enip(0x0066, session, b""), b""))   # UnRegisterSession
    return _tcp_flow(ep, _sport(), 44818, exchanges)


def _enip_rr(session: int, cip: bytes, ctx: int) -> bytes:
    """SendRRData (unconnected explicit message): interface handle 0,
    timeout 10, CPF null address + unconnected data item."""
    return _enip(0x006F, session, struct.pack("<IH", 0, 10) +
                 _cpf((0x0000, b""), (0x00B2, cip)), context=ctx)


def _enip_identity_item(ep: Endpoints) -> tuple[bytes, bytes]:
    """(List Identity CPF item 0x0C body, Identity attributes 1-7) of the
    target device. Vendor id 0x0001 = Rockwell Automation; device type 0x0E
    PLC, 0x02 AC drive; product code / revision / serial from ``ep.meta``
    (``cip_product_code``, ``cip_revision``, ``cip_serial``)."""
    product = ep.meta.get("product", "1756-L71/B LOGIX5571").encode()[:32]
    vendor_id = ep.meta.get("vendor_id", 0x0001)
    dev_type = ep.meta.get("device_type", 0x000E)
    code = ep.meta.get("cip_product_code", 55)
    major, minor = ep.meta.get("cip_revision", (20, 11))
    serial = ep.meta.get("cip_serial")
    if serial is None:
        serial = zlib.crc32(P.mac_to_bytes(ep.server_mac))
    sock = struct.pack(">hHI8s", 2, 44818,
                       int.from_bytes(P.ip_to_bytes(ep.server_ip), "big"),
                       bytes(8))
    # vendor, device type, product code, revision, status, serial,
    # product name (SHORT_STRING)
    attrs = struct.pack("<HHHBBHI", vendor_id, dev_type, code, major, minor,
                        0x0060, serial) + bytes([len(product)]) + product
    # encapsulation version, socket, attributes, state 3 = operational
    return struct.pack("<H", 1) + sock + attrs + b"\x03", attrs


def s7_identity_flow(ep: Endpoints, count: int) -> List[bytes]:
    """S7comm (102): SZL 0x0011 read returning the Siemens order number
    (e.g. 6ES7 ...) and firmware version, then SZL 0x001C returning the
    station/module name and serial number — how monitors fingerprint S7 PLCs.

    Per-device identity comes from ``ep.meta`` (see ``tgt.devices``):
    ``s7_firmware`` (major, minor, patch), ``s7_serial`` and ``s7_module``;
    without them it reports V3.2.0 and a serial derived from the server MAC."""
    order = ep.meta.get("order", "6ES7 315-2EH14-0AB0").encode().ljust(20)[:20]
    fw = bytes([0x56]) + bytes(ep.meta.get("s7_firmware", (3, 2, 0)))  # 'V'3.2.0
    # SZL 0x0011 records (28 bytes): index, MlfB, BGTyp, Ausbg, Ausbe
    recs = struct.pack("!H20sHHH", 0x0001, order, 0, 0x0001, 0x0001) + \
        struct.pack("!H20sHHH", 0x0006, order, 0, 0x0001, 0x0001) + \
        struct.pack("!H20sH4s", 0x0007, b" " * 20, 0, fw)
    szl = struct.pack("!HHHH", 0x0011, 0x0000, 28, 3) + recs
    # SZL 0x001C component identification (34-byte records): index + text
    serial = ep.meta.get("s7_serial") or "S C-%012d" % (
        zlib.crc32(P.mac_to_bytes(ep.server_mac)) % 10 ** 12)
    module = ep.meta.get("s7_module", "CPU 315-2 PN/DP")
    station = ep.meta.get("host", "SIMATIC 300(1)")

    def comp(index: int, text: str, width: int = 24) -> bytes:
        return struct.pack("!H", index) + \
            text.encode()[:width].ljust(width, b"\x00").ljust(32, b"\x00")

    comps = [comp(0x0001, station), comp(0x0002, module), comp(0x0003, ""),
             comp(0x0004, "Original Siemens Equipment", 26),
             comp(0x0005, serial), comp(0x0007, module)]
    szl1c = struct.pack("!HHHH", 0x001C, 0x0000, 34, len(comps)) + \
        b"".join(comps)
    # SZL 0x0424 index 0: current mode (RUN, entered from STARTUP)
    szl424 = struct.pack("!HHHH", 0x0424, 0x0000, 20, 1) + struct.pack(
        "!HBB4s4s", 0x4302, 0xFF, 0x58, b"\x00" * 4, b"\x00" * 4) + \
        _S7_BOOT_TIME
    # SZL 0x0131 index 1: communication capabilities (max PDU, connections)
    szl131 = struct.pack("!HHHH", 0x0131, 0x0001, 40, 1) + struct.pack(
        "!HHHII", 0x0001, 240, 16, 187500, 12000000) + bytes(26)

    def szl_read(ref: int, szl_id: int, index: int, body: bytes):
        # userdata: CPU functions (0x4) request, subfunction read SZL
        req = _s7(7, ref, b"\x00\x01\x12\x04\x11\x44\x01\x00",
                  b"\xff\x09\x00\x04" + struct.pack("!HH", szl_id, index))
        rsp = _s7(7, ref, b"\x00\x01\x12\x08\x12\x84\x01" +
                  bytes([ref & 0xFF]) + b"\x00\x00\x00\x00",
                  b"\xff\x09" + struct.pack("!H", len(body)) + body)
        return req, rsp

    exchanges = _s7_connect()
    for i in range(count):
        for k, (szl_id, body) in enumerate(((0x0011, szl), (0x001C, szl1c))):
            exchanges.append(szl_read(2 * i + k + 1, szl_id, 0, body))
    exchanges.append(szl_read(2 * count + 1, 0x0424, 0x0000, szl424))
    exchanges.append(szl_read(2 * count + 2, 0x0131, 0x0001, szl131))
    return _tcp_flow(ep, _sport(), 102, exchanges)


# S7 BCD timestamp 2026-10-06 12:00:00.000, weekday 3 (Tuesday)
_S7_BOOT_TIME = b"\x26\x10\x06\x12\x00\x00\x00\x03"




# ===========================================================================
# Registry
# ===========================================================================
class Profile:
    def __init__(self, key: str, name: str, category: str, port: str,
                 transport: str, build: FlowBuilder, desc: str):
        self.key = key
        self.name = name
        self.category = category
        self.port = port
        self.transport = transport
        self.build = build
        self.desc = desc

    @property
    def link_local(self) -> bool:
        """Frames never leave the sender's L2 segment: every ``l2`` profile,
        plus IP profiles in :data:`LINK_LOCAL` (TTL-1 / link-scope multicast
        or subnet broadcast), which an environment must not route."""
        return self.transport == "l2" or self.key in LINK_LOCAL


PROFILES: dict[str, Profile] = {}

# IP-transported profiles that are link-local: PTP over UDP (224.0.1.129,
# TTL 1), mDNS (224.0.0.251) and LLMNR (224.0.0.252, link-scope multicast),
# SSDP (239.255.255.250, TTL 2, not multicast-routed) and NBNS name queries
# (subnet broadcast). Modules registering more such profiles add them here.
LINK_LOCAL: set = {"ptp", "mdns", "llmnr", "ssdp", "nbns"}


def _reg(key, name, category, port, transport, build, desc):
    PROFILES[key] = Profile(key, name, category, port, transport, build, desc)


# OT / ICS
_reg("modbus", "Modbus/TCP", "OT", "502", "tcp", modbus_flow,
     "FC 3/4/1/2 polling, FC 6 setpoint writes, exception 0x83")
_reg("dnp3", "DNP3", "OT", "20000", "tcp", dnp3_flow,
     "Class 0/1/2/3 polls + unsolicited events, per-device addresses")
_reg("enip", "EtherNet/IP + CIP", "OT", "44818", "tcp", enip_flow,
     "RegisterSession + SendRRData CIP Get_Attribute_Single polls")
_reg("s7comm", "S7comm (Siemens)", "OT", "102", "tcp", s7comm_flow,
     "COTP connect, Setup Communication, Read Var job/ack_data")
_reg("iec104", "IEC 60870-5-104", "OT", "2404", "tcp", iec104_flow,
     "STARTDT, interrogation, time-tagged spontaneous points, TESTFR")
_reg("bacnet", "BACnet/IP", "OT", "47808", "udp", bacnet_flow,
     "ReadProperty on analog-input objects + ComplexACK replies")
_reg("opcua", "OPC UA", "OT", "4840", "tcp", opcua_flow,
     "GetEndpoints, Create/ActivateSession, Read, CloseSession")
# OT asset identity / fingerprint
_reg("enip-id", "EtherNet/IP List Identity", "OT", "44818", "tcp",
     enip_identity_flow, "List Identity + Identity Get_Attribute_All")
_reg("s7-id", "S7 SZL Identity", "OT", "102", "tcp", s7_identity_flow,
     "SZL 0x0011/0x001C order no., firmware, serial; 0x0424 mode")
# IT / infra
_reg("arp", "ARP", "IT", "-", "l2", arp_flow,
     "who-has/is-at + gratuitous announcements")
_reg("icmp", "ICMP echo", "IT", "-", "ip", icmp_flow,
     "Ping request/reply sweep")
_reg("dns", "DNS", "IT", "53", "udp", dns_flow,
     "A-record query/response")
_reg("http", "HTTP", "IT", "80", "tcp", http_flow,
     "Web browsing GET / 200 OK with per-host User-Agent")
_reg("https", "HTTPS / TLS", "IT", "443", "tcp", https_flow,
     "Per-OS TLS handshake (JA3/JA4, SNI, certificate) + app data")
_reg("edr", "CrowdStrike EDR", "IT", "443", "tcp", edr_flow,
     "Falcon sensor TLS telemetry to the CrowdStrike cloud (cloudsink SNI)")
_reg("smb", "SMB / CIFS", "IT", "445", "tcp", smb_flow,
     "Negotiate (SMBv1 legacy or SMB 3.0.2) + echo keep-alives")
_reg("kerberos", "Kerberos", "IT", "88", "tcp", kerberos_flow,
     "AS-REQ + PREAUTH_REQUIRED from the Domain Controller")
_reg("ldap", "LDAP / AD", "IT", "389", "tcp", ldap_flow,
     "bind + rootDSE search against Active Directory")
_reg("dhcp", "DHCP", "IT", "67", "udp", dhcp_flow,
     "DORA lease + renewals: host name, option 55 + vendor-class fingerprint")
_reg("netbios", "NetBIOS-NS", "IT", "137", "udp", netbios_flow,
     "Broadcast name registration + browser host announcement "
     "(138/UDP: host name + OS version)")
_reg("ntp", "NTP", "IT", "123", "udp", ntp_flow,
     "Client polls + stratum-2 server replies with real timestamps")


def get(key: str) -> Profile:
    if key not in PROFILES:
        raise KeyError(key)
    return PROFILES[key]


def all_profiles() -> List[Profile]:
    return list(PROFILES.values())


# OT identity + engineering-operation profiles (Modbus FC43, BACnet I-Am, …)
from . import protocols_ot  # noqa: E402,F401
# Industrial L2 / substation profiles (PROFINET, IEC 61850, PTP) register here.
from . import protocols_ind  # noqa: E402,F401
from . import protocols_infra  # noqa: E402,F401  (registers SNMP, LLDP, MQTT…)
from . import protocols_eng  # noqa: E402,F401  (registers FTP, SSH, RDP, FINS…)
from . import protocols_util  # noqa: E402,F401  (registers SEL ASCII engineering)
from . import protocols_site  # noqa: E402,F401  (registers MRP, DLR, DICOM, HL7…)
from . import protocols_codesys  # noqa: E402,F401  (registers CODESYS V3)
from . import protocols_iiot  # noqa: E402,F401  (registers RTU-over-TCP, LoRaWAN…)
from . import protocols_sec  # noqa: E402,F401  (CIP Security, TLS/DTLS, UA)
