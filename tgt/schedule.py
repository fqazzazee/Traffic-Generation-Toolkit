"""Timed scheduler — every conversation on its own clock.

``tgt run --schedule timed`` (and every ``tgt campaign``) replaces the cycle
model (all conversations once per batch at one global pps) with a heap of
streams: each conversation recurs on its own period with jitter
(:mod:`tgt.timing`), answers come back after a path- and device-dependent
round trip, HMI/SCADA/historian pollers keep one long-lived TCP connection
(handshake once, every poll reuses it), and an optional day profile shapes
user activity. :meth:`Scheduler.run` yields frames in time order, stamped in
*simulated* seconds since the start; the engine maps that onto the wall clock
(real time, ``--speed`` compression) or the synthetic clock (as fast as
possible).

Frames still come from the ordinary flow builders: a short-lived session is
one builder call per occurrence; a persistent one is cut into its exchanges
(:func:`exchanges`) — setup once, one poll per occurrence, the next chunk of
polls rebased onto the same connection (ports, sequence numbers, IP IDs, TCP
timestamps on a 1 kHz clock that follows the simulated time).
"""
from __future__ import annotations

import heapq
import math
import random
import struct
import zlib
from typing import Callable, Dict, Iterator, List, Optional, Tuple

from . import protocols, stacks, timing
from .packet import Endpoints, checksum16, mac_to_bytes

SYN, FIN, RST, ACK = 0x02, 0x01, 0x04, 0x10
INF = float("inf")

# one scheduled frame: (t, tiebreak, key, copies on the wire, source, first
# frame of an occurrence?)
Item = Tuple[float, int, str, List[bytes], str, bool]


# ---------------------------------------------------------------------------
# Frame anatomy
# ---------------------------------------------------------------------------
def view(frame: bytes, cmac: bytes) -> tuple:
    """(from client?, TCP flags, payload length, IP offset, L4 offset,
    is TCP) of a host-built frame; ``cmac`` is the client's MAC."""
    frm = frame[6:12] == cmac
    off = 18 if frame[12:14] == b"\x81\x00" else 14
    if frame[off - 2:off] != b"\x08\x00" or len(frame) < off + 20:
        return frm, 0, len(frame) - off, off, 0, False
    ihl = (frame[off] & 15) * 4
    total = (frame[off + 2] << 8) | frame[off + 3]
    l4 = off + ihl
    proto = frame[off + 9]
    if proto == 6 and len(frame) >= l4 + 20:
        doff = (frame[l4 + 12] >> 4) * 4
        return frm, frame[l4 + 13], total - ihl - doff, off, l4, True
    if proto == 17:
        return frm, 0, total - ihl - 8, off, l4, False
    return frm, 0, total - ihl, off, l4, False


def exchanges(frames: List[bytes], cmac: bytes) -> List[List[bytes]]:
    """Cut one flow into exchanges: the TCP handshake, then a new exchange at
    each client segment with data that follows the server's data (or the
    handshake), and the teardown from the first FIN/RST on."""
    groups: List[List[bytes]] = []
    last = None            # side that sent the previous data
    after_syn = closing = False
    for f in frames:
        frm, flags, plen, _, _, tcp = view(f, cmac)
        new = not groups
        if tcp and flags & (FIN | RST) and not closing:
            new = closing = True
        elif not closing and plen > 0 and frm and (last is False or after_syn):
            new = True
        if tcp and flags & SYN:
            after_syn = True
        elif plen > 0:
            after_syn = False
        if plen > 0:
            last = frm
        if new:
            groups.append([])
        groups[-1].append(f)
    return groups


def _ts_offset(frame: bytes, l4: int) -> int:
    """Offset of the TSval in a TCP segment's timestamp option, or 0."""
    end = l4 + (frame[l4 + 12] >> 4) * 4
    i = l4 + 20
    while i < end:
        kind = frame[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        if i + 1 >= end:
            break
        if kind == 8:
            return i + 2
        i += max(2, frame[i + 1])
    return 0


class Connection:
    """Live state of one persistent TCP connection (client side ``sport``):
    next sequence numbers, per-side IP ID counters and timestamp clocks."""

    def __init__(self) -> None:
        self.sport: Optional[int] = None
        self.c_next: Optional[int] = None
        self.s_next: Optional[int] = None
        self.ipid: Dict[bool, Optional[int]] = {True: None, False: None}
        self.tsbase: Dict[bool, Optional[int]] = {True: None, False: None}
        self.tslast: Dict[bool, int] = {True: 0, False: 0}
        self.t0 = 0.0
        # application sequence counters (IEC 104 APCI): side -> [next N(S),
        # I-frames received]; see renumber_iec104
        self.apci: Dict[bool, List[int]] = {True: [0, 0], False: [0, 0]}

    def rewrite(self, frame: bytes, t: float, cmac: bytes,
                delta: Optional[Tuple[int, int]]) -> bytes:
        """``frame`` moved onto this connection at simulated time ``t``:
        sequence numbers shifted by ``delta`` (client, server), the client
        port, continuing IP IDs and timestamps on a 1 kHz clock."""
        frm, flags, plen, off, l4, tcp = view(frame, cmac)
        if not tcp:
            return frame
        b = bytearray(frame)
        sp, dp, seq, ack = struct.unpack_from("!HHII", b, l4)
        if self.sport is None:
            self.sport = sp if frm else dp
            self.t0 = t
        if frm:
            sp = self.sport
        else:
            dp = self.sport
        if delta is not None:
            dc, ds = delta
            if frm:
                seq, ack = (seq + dc) & 0xFFFFFFFF, (ack + ds) & 0xFFFFFFFF
            else:
                seq, ack = (seq + ds) & 0xFFFFFFFF, (ack + dc) & 0xFFFFFFFF
            if flags == SYN:
                ack = 0
        struct.pack_into("!HHII", b, l4, sp, dp, seq, ack)
        adv = plen + (1 if flags & (SYN | FIN) else 0)
        if frm:
            self.c_next = (seq + adv) & 0xFFFFFFFF
        else:
            self.s_next = (seq + adv) & 0xFFFFFFFF
        ts = _ts_offset(b, l4)
        if ts:
            val = struct.unpack_from("!I", b, ts)[0]
            if self.tsbase[frm] is None:
                self.tsbase[frm] = val
            val = (self.tsbase[frm] + int((t - self.t0) * 1000)) & 0xFFFFFFFF
            ecr = self.tslast[not frm] if not flags == SYN else 0
            struct.pack_into("!II", b, ts, val, ecr)
            self.tslast[frm] = val
        ident = struct.unpack_from("!H", b, off + 4)[0]
        if ident:
            nxt = self.ipid[frm]
            if nxt is None:
                nxt = ident
            struct.pack_into("!H", b, off + 4, nxt)
            self.ipid[frm] = (nxt + 1) & 0xFFFF or 1
        ihl = l4 - off
        b[off + 10:off + 12] = b"\x00\x00"
        struct.pack_into("!H", b, off + 10, checksum16(bytes(b[off:l4])))
        total = (b[off + 2] << 8) | b[off + 3]
        b[l4 + 16:l4 + 18] = b"\x00\x00"
        seg = bytes(b[l4:off + total])
        pseudo = bytes(b[off + 12:off + 20]) + struct.pack("!BBH", 0, 6,
                                                           total - ihl)
        struct.pack_into("!H", b, l4 + 16, checksum16(pseudo + seg))
        return bytes(b)

    def delta(self, frame: bytes, cmac: bytes) -> Optional[Tuple[int, int]]:
        """Sequence shift that continues this connection with ``frame`` (the
        first TCP segment of a group from another build)."""
        frm, flags, _, _, l4, tcp = view(frame, cmac)
        if not tcp or self.c_next is None or self.s_next is None:
            return None
        seq, ack = struct.unpack_from("!II", frame, l4 + 4)
        if frm:
            return ((self.c_next - seq) & 0xFFFFFFFF,
                    (self.s_next - ack) & 0xFFFFFFFF)
        return ((self.c_next - ack) & 0xFFFFFFFF,
                (self.s_next - seq) & 0xFFFFFFFF)


def renumber_iec104(conn: Connection, frame: bytes, cmac: bytes) -> bytes:
    """IEC 104 send/receive sequence numbers continued on ``conn``: each
    I-format APDU gets its side's next N(S) and N(R) = the I-frames that side
    has received; an S-format APDU acknowledges them all (both counters wrap
    at 2^15). A persistent connection is built in chunks, each of which
    numbers from 0; this keeps the numbering continuous across them. The
    TCP checksum is left for :meth:`Connection.rewrite`."""
    frm, _, plen, _, l4, tcp = view(frame, cmac)
    if not tcp or plen <= 0:
        return frame
    b = bytearray(frame)
    p = l4 + (b[l4 + 12] >> 4) * 4
    end = p + plen
    me, peer = conn.apci[frm], conn.apci[not frm]
    while p + 6 <= end and b[p] == 0x68:
        if b[p + 2] & 1 == 0:                      # I-format
            struct.pack_into("<HH", b, p + 2, me[0] << 1, me[1] << 1)
            me[0] = (me[0] + 1) & 0x7FFF
            peer[1] = (peer[1] + 1) & 0x7FFF
        elif b[p + 2] & 3 == 1:                    # S-format
            struct.pack_into("<H", b, p + 4, me[1] << 1)
        p += 2 + b[p + 1]
    return bytes(b)


# per-protocol application-layer renumbering on persistent connections
RENUMBER: Dict[str, Callable[[Connection, bytes, bytes], bytes]] = {
    "iec104": renumber_iec104,
}


# ---------------------------------------------------------------------------
# Streams
# ---------------------------------------------------------------------------
class Stream:
    """One recurring conversation.

    ``build(count)`` returns host-built frames (the build context is set
    first); ``place(frame)`` returns the copies that frame becomes on the
    wire. ``fp`` fingerprints everything the frames depend on: a phase
    change keeps a stream whose ``sid`` and ``fp`` are unchanged (its
    connection survives) and restarts any other.
    """

    def __init__(self, sid: tuple, key: str, source: str,
                 builder: Callable[[Endpoints, int], List[bytes]],
                 ep: Endpoints, place: Callable[[bytes], List[bytes]],
                 period: float, jitter: float, count: int = 1,
                 cls: str = "infra", path: str = "segment",
                 embedded: bool = False, persistent=None,
                 fp: str = "", dead: bool = False) -> None:
        self.sid, self.key, self.source = sid, key, source
        self.builder, self.ep, self.place = builder, ep, place
        self.period = max(1e-4, float(period))
        self.jitter = min(max(float(jitter), 0.0), 0.95)
        self.count, self.cls = max(1, int(count)), cls
        self.persistent = persistent
        self.fp, self.dead = fp, dead
        self.cmac = mac_to_bytes(ep.client_mac)
        self.rtt = timing.pick(*timing.RTT[path], ep.client_ip, ep.server_ip,
                               "rtt")
        self.proc = timing.pick(
            *(timing.PROCESSING.get(key) or
              timing.PROCESSING["embedded" if embedded else "host"]),
            ep.server_ip, "proc")
        self.delack = {
            True: stacks.get(ep.stack_client or stacks.DEFAULT_CLIENT)
            .delack_ms / 1000.0,
            False: stacks.get(ep.stack_server or "linux").delack_ms / 1000.0}
        self.alive = True
        self.next_t = INF
        self.occ = 0                 # occurrences so far
        self.wire = 0                # wire frames so far (sprinkle ratio)
        self.builds = 0              # builder calls so far
        self.seed = 0
        self.rng = random.Random(0)
        # persistent state
        self.conn: Optional[Connection] = None
        self.polls: List[List[bytes]] = []
        self.close: List[List[bytes]] = []
        self.lifetime = 0.0
        self.tuple: Optional[tuple] = None
        self.refreshed = 0.0         # last setup-exchange refresh (REFRESH)

    # -- building ----------------------------------------------------------
    def bind(self, seed: int, gen: int = 0) -> None:
        """Seed this stream's randomness from the run seed, its id and how
        many times the id was (re)started, so a restarted conversation
        opens a new connection (ports, ISNs) rather than replaying one."""
        tag = f"{seed}:{self.sid!r}" + (f":{gen}" if gen else "")
        self.seed = zlib.crc32(tag.encode()) ^ (seed & 0xFFFFFFFF)
        self.rng = random.Random(tag)
        if self.persistent:
            lo, hi = self.persistent[2]
            self.lifetime = self.rng.uniform(lo, hi) if hi > 0 else 0.0

    def _build(self, count: int, sched=None) -> List[bytes]:
        """One builder call; a TCP session whose 4-tuple an open persistent
        connection holds is rebuilt (next ephemeral port)."""
        for _ in range(8):
            # under the build lock: an injection pass may be building on
            # its worker thread (tgt.control), and the build context is
            # module state
            with protocols.BUILD_LOCK:
                protocols.begin_build(self.seed, self.builds, sport_stride=8)
                self.builds += 1
                frames = self.builder(self.ep, count)
            if sched is None or not sched.ports:
                return frames
            tup = _tuple(frames, self.cmac)
            if tup is None or sched.ports.get(tup, self) is self:
                return frames
        return frames

    # -- timing ------------------------------------------------------------
    def interval(self) -> float:
        j = self.jitter
        return self.period * (1.0 + self.rng.uniform(-j, j))

    def offsets(self, frames: List[bytes]) -> List[float]:
        """Send time of each frame relative to the first: the answering side
        replies after the path RTT (+ its processing time for data), a pure
        ACK closing an exchange waits for the delayed-ACK timer, the client
        turns around quickly, back-to-back segments go out serialised."""
        out, t, prev = [], 0.0, None
        n = len(frames)
        r = self.rng.uniform
        for i, f in enumerate(frames):
            frm, flags, plen = view(f, self.cmac)[:3]
            if prev is None:
                dt = 0.0
            elif frm != prev[0]:
                pure_ack = plen == 0 and flags == ACK
                if pure_ack and prev[2] > 0 and i == n - 1:
                    dt = self.delack[frm] * r(0.9, 1.0)
                elif not frm:                  # server answering
                    dt = self.rtt * r(0.85, 1.25)
                    if plen > 0:
                        dt += self.proc * r(0.7, 1.4)
                else:                          # client turn-around
                    dt = r(*timing.THINK)
            else:
                dt = timing.GAP + len(f) * 8e-9
            t += dt
            out.append(t)
            prev = (frm, flags, plen)
        return out

    # -- occurrences ---------------------------------------------------------
    def occur(self, t: float, sched=None
              ) -> List[Tuple[float, List[bytes], bool]]:
        """Frames of the occurrence at ``t``: (time, wire copies, first?)."""
        self.occ += 1
        conn = self.conn
        if self.dead:
            frames = self._retry()
        elif self.persistent:
            frames = self._poll(t, sched)
            if frames is None:                  # cannot be cut: fall back
                self.persistent = None
                frames = self._build(self.count, sched)
        else:
            frames = self._build(self.count, sched)
        if not frames:
            return []
        if isinstance(frames, tuple):           # pre-timed (retries)
            frames, offs = frames
        else:
            offs = self.offsets(frames)
        out = []
        # the connection the frames ride on (a closing one is already
        # detached from the stream)
        conn = (self.conn or conn) if self.persistent and not self.dead \
            else None
        delta = None
        first = True
        renumber = RENUMBER.get(self.key) if conn is not None else None
        for f, dt in zip(frames, offs):
            if conn is not None:
                if conn.c_next is not None and delta is None and \
                        view(f, self.cmac)[5]:
                    delta = conn.delta(f, self.cmac)
                if renumber is not None:
                    f = renumber(conn, f, self.cmac)
                f = conn.rewrite(f, t + dt, self.cmac, delta)
            out.append((t + dt, self.place(f), first))
            first = False
        return out

    def _retry(self):
        """A client whose server is gone: a SYN and its retransmissions
        (1 s, 3 s later), or the bare request for a datagram protocol."""
        frames = self._build(1)
        if not frames or view(frames[0], self.cmac)[0] is False:
            return []
        f0 = frames[0]
        frm, flags, _, _, _, tcp = view(f0, self.cmac)
        if tcp and flags & SYN:
            return [f0, f0, f0], [0.0, 1.0, 3.0]
        return [f0], [0.0]

    def _poll(self, t: float, sched=None) -> Optional[List[bytes]]:
        """Next poll of the persistent session (opening it first if needed;
        reconnecting once its lifetime is up)."""
        setup, teardown, _ = self.persistent
        out: List[bytes] = []
        if self.conn is not None and not self.polls and self.lifetime and \
                t - self.conn.t0 >= self.lifetime:
            # the connection has lived its life: close it, open a fresh one
            for g in self.close:
                out += g
            self.release(sched)
            self.conn = None
            self.close = []
            return out
        ref = timing.REFRESH.get(self.key)
        if ref and self.conn is not None and t - self.refreshed >= ref[0]:
            # a setup exchange that recurs on the open connection (IEC 104
            # general interrogation): from a fresh build, in place of a poll
            self.refreshed = t
            groups = exchanges(self._build(1), self.cmac)
            if len(groups) > ref[1]:
                return list(groups[ref[1]])
        if not self.polls:
            frames = self._build(timing.CHUNK,
                                 sched if self.conn is None else None)
            groups = exchanges(frames, self.cmac)
            if len(groups) <= setup + teardown:
                return None
            self.polls = groups[setup:len(groups) - teardown][::-1]
            self.close = groups[len(groups) - teardown:]
            if self.conn is None:
                self.conn = Connection()
                self.refreshed = t
                self.tuple = _tuple(frames, self.cmac)
                if sched is not None and self.tuple is not None:
                    sched.ports[self.tuple] = self
                for g in groups[:setup]:
                    out += g
                if self.key == "dhcp":      # DORA now, the renewals later
                    return out
        for _ in range(self.count):
            if self.polls:
                out += self.polls.pop()
        return out

    def release(self, sched) -> None:
        """Forget this stream's persistent 4-tuple (connection gone)."""
        tup = getattr(self, "tuple", None)
        if sched is not None and tup is not None and \
                sched.ports.get(tup) is self:
            del sched.ports[tup]
        self.tuple = None


class ArpStream(Stream):
    """A host refreshing its ARP cache: who-has its gateway (answered from
    the HSRP virtual MAC) and each same-segment peer it talks to."""

    def __init__(self, sid, env, host, peers, period, fp, gratuitous=False):
        seg = env.segment_of(host)
        ep = Endpoints(client_mac=host.mac, client_ip=host.ip,
                       server_mac=seg.gateway_mac, server_ip=seg.gateway,
                       vlan=seg.vlan)
        super().__init__(sid, "arp", "baseline", protocols.get("arp").build,
                         ep, lambda f: [f], period, timing.spec("arp")[2],
                         path="segment", fp=fp)
        self.env, self.host, self.peers = env, host, peers
        self.gratuitous = gratuitous

    def occur(self, t: float, sched=None):
        with protocols.BUILD_LOCK:          # see Stream._build
            return self._occur(t, sched)

    def _occur(self, t: float, sched=None):
        self.occ += 1
        protocols.begin_build(self.seed, self.builds, sport_stride=8)
        self.builds += 1
        out: List[Tuple[float, List[bytes], bool]] = []
        arp = protocols.get("arp").build
        first = True
        if self.gratuitous and self.occ == 1:
            out.append((t, [gratuitous_arp(self.env, self.host)], True))
            t += 0.001
            first = False
        for f, dt in zip(*self._timed(arp(self.ep, 1))):
            out.append((t + dt, [f], first))
            first = False
        t += 0.002
        for peer in self.peers:
            ep = Endpoints(client_mac=self.host.mac, client_ip=self.host.ip,
                           server_mac=peer.mac, server_ip=peer.ip)
            frames, offs = self._timed(arp(ep, 1))
            for f, dt in zip(frames, offs):
                out.append((t + dt, self.env._place(f, self.host, peer,
                                                    "access"), False))
            t += 0.001
        return out

    def _timed(self, frames):
        return frames, [i * self.rtt for i in range(len(frames))]


def _tuple(frames: List[bytes], cmac: bytes) -> Optional[tuple]:
    """(client IP, server IP, client port, server port) of the first TCP
    segment the client sends in ``frames``, else ``None``."""
    for f in frames[:4]:
        frm, _, _, off, l4, tcp = view(f, cmac)
        if tcp:
            sp, dp = struct.unpack_from("!HH", f, l4)
            ips = (f[off + 12:off + 16], f[off + 16:off + 20])
            return (ips + (sp, dp)) if frm else (ips[::-1] + (dp, sp))
    return None


def gratuitous_arp(env, host) -> bytes:
    from .packet import ETH_P_ARP, arp, ethernet
    seg = env.segment_of(host)
    return ethernet("ff:ff:ff:ff:ff:ff", host.mac, ETH_P_ARP,
                    arp(1, host.mac, host.ip, "00:00:00:00:00:00", host.ip),
                    vlan=seg.vlan)


# ---------------------------------------------------------------------------
# Stream sets
# ---------------------------------------------------------------------------
def _fp(*parts) -> str:
    return repr(parts)


def env_streams(env, span: str = "access", offline=(),
                sprinkle=(), sprinkle_messages: int = 2,
                timing_over: Optional[Dict] = None) -> List[Stream]:
    """Every recurring stream of an environment: its conversations, Falcon
    EDR channels, per-host ARP refresh and any sprinkled incident flows.
    Hosts in ``offline`` send nothing; their clients retry."""
    offline = set(offline)
    out: List[Stream] = []
    seg = env.segment_or_none
    for conv in env.conversations:
        cname, sname, proto = conv
        if cname in offline:
            continue
        client, server = env.host(cname), env.host(sname)
        dead = sname in offline and sname != cname
        ep = env.conv_endpoints(client, server, proto)
        tm = timing.conversation_timing(env, conv)
        lo, hi, jit, n, _ = timing.spec(proto)
        if proto == "enip-io":
            ep.meta["enip_rpi_us"] = int(round(tm["period"] * 1e6))
        cls = timing.activity_class(proto, client.role, server.role)
        out.append(Stream(
            ("conv",) + tuple(conv), proto, "baseline",
            protocols.get(proto).build, ep,
            (lambda f, c=client, s=server: env._place(f, c, s, span)),
            tm["period"], tm["jitter"], n, cls,
            timing.path_kind(seg(client), seg(server)), server.embedded,
            timing.PERSISTENT.get(proto),
            _fp(client, server, env.host_meta.get(cname),
                env.host_meta.get(sname), dead, span, tm), dead))
    from .enterprise import _cs_cloud_host
    for h, ip, fqdn, bulk in env.edr_plan():
        if h.name in offline:
            continue
        cloud = _cs_cloud_host(ip, fqdn)
        ep = env._edr_endpoints(h, cloud)
        row = "edr-bulk" if bulk else "edr"
        lo, hi, jit, n, cls = timing.spec(row)
        out.append(Stream(
            ("edr", h.name, ip, fqdn), "edr", "baseline",
            protocols.get("edr").build, ep,
            (lambda f, c=h, s=cloud: env.place(f, c, s, span, seg)),
            timing.pick(lo, hi, h.name, ip, fqdn), jit, 3 if bulk else 1,
            cls, "wan", False,
            None if bulk else timing.PERSISTENT.get("edr"), _fp(h, span)))
    if env.arp_enabled:
        peers: Dict[str, list] = {h.name: [] for h in env.hosts}
        dhcp = set()
        for c, sv, proto in env.conversations:
            if proto == "dhcp":
                dhcp.add(c)
            if (c != sv and protocols.get(proto).transport != "l2"
                    and seg(env.host(c)) is seg(env.host(sv))
                    and sv not in offline
                    and env.host(sv) not in peers[c]):
                peers[c].append(env.host(sv))
        for i, h in enumerate(env.hosts):
            if h.name in offline:
                continue
            out.append(ArpStream(
                ("arp", h.name), env, h, peers[h.name], timing.arp_period(h),
                _fp(h, [p.ip for p in peers[h.name]]),
                gratuitous=h.name in dhcp or i % 8 == 0))
    out += sprinkle_streams(env, sprinkle, sprinkle_messages, span)
    return out


def _attack_stream(sid, inc, a, v, atk, meta, count, source, place, path):
    from .incidents import ATTACKS
    ep = inc._endpoints(a, v, meta)
    lo, hi, jit = timing.ATTACK_PERIODS.get(atk, timing.DEFAULT_ATTACK_PERIOD)
    return Stream(sid, atk, source, ATTACKS[atk][0], ep, place,
                  timing.pick(lo, hi, a.ip, v.ip, atk), jit, count, "infra",
                  path, False, None, _fp(a, v, meta, count))


def sprinkle_streams(env, sprinkle, count: int, span: str = "access",
                     tagged: bool = True) -> List[Stream]:
    """Sprinkled incidents' attack flows riding on ``env``'s hosts."""
    from . import incidents
    out = []
    seg = env.segment_or_none
    for key in sprinkle:
        inc = incidents.get(key)
        mapping = inc.map_onto(env)
        for i, (an, vn, atk, meta) in enumerate(inc.flows):
            a = mapping.get(an) or inc.host(an)
            v = mapping.get(vn) or inc.host(vn)
            place = ((lambda f, a=a, v=v: env.place(f, a, v, span, seg))
                     if tagged else (lambda f: [f]))
            out.append(_attack_stream(
                ("sprinkle", key, i), inc, a, v, atk, meta, count,
                f"sprinkle:{key}", place,
                timing.path_kind(seg(a), seg(v))))
    return out


def incident_streams(key: str, count: int) -> List[Stream]:
    from . import incidents
    inc = incidents.get(key)
    return [_attack_stream(("incident", key, i), inc, inc.host(a),
                           inc.host(v), atk, meta, count, f"incident:{key}",
                           (lambda f: [f]), "routed")
            for i, (a, v, atk, meta) in enumerate(inc.flows)]


def profile_streams(profiles, ep: Endpoints) -> List[Stream]:
    out = []
    for key in profiles:
        lo, hi, jit, n, cls = timing.spec(key)
        e = Endpoints(**{**ep.__dict__, "meta": dict(ep.meta)})
        period = timing.pick(lo, hi, ep.client_ip, ep.server_ip, key)
        if key == "enip-io":
            e.meta["enip_rpi_us"] = int(round(period * 1e6))
        out.append(Stream(("profile", key), key, "baseline",
                          protocols.get(key).build, e, (lambda f: [f]),
                          period, jit, n, cls, "segment", False,
                          timing.PERSISTENT.get(key), _fp(key, ep)))
    return out


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------
class HostStamper:
    """Hosts whose stack numbers every datagram from one counter get their
    IP IDs re-stamped in wire order, across all their streams and phases."""

    def __init__(self) -> None:
        self.by_ip: Dict[bytes, str] = {}
        self.counters: Dict[str, int] = {}

    def load(self, hosts) -> None:
        self.by_ip = {bytes(int(x) for x in h.ip.split(".")): h.name
                      for h in hosts
                      if stacks.get(h.stack).ipid == "host"}

    def __call__(self, copies: List[bytes]) -> List[bytes]:
        f = copies[0]
        off = 18 if f[12:14] == b"\x81\x00" else 14
        if f[off - 2:off] != b"\x08\x00" or len(f) < off + 20:
            return copies
        name = self.by_ip.get(f[off + 12:off + 16])
        if name is None:
            return copies
        n = self.counters.get(name)
        if n is None:
            n = stacks.hash_int(name, "ipid", bits=16)
        self.counters[name] = (n + 1) & 0xFFFF
        return [_set_ident(g, n) for g in copies]


def _set_ident(frame: bytes, ident: int) -> bytes:
    """``frame`` with IPv4 Identification ``ident``, the header checksum
    updated incrementally (RFC 1624) rather than recomputed."""
    off = 18 if frame[12:14] == b"\x81\x00" else 14
    old = (frame[off + 4] << 8) | frame[off + 5]
    if old == ident:
        return frame
    ck = (frame[off + 10] << 8) | frame[off + 11]
    x = (~ck & 0xFFFF) + (~old & 0xFFFF) + ident
    x = (x & 0xFFFF) + (x >> 16)
    x = (x & 0xFFFF) + (x >> 16)
    ck = ~x & 0xFFFF
    b = bytearray(frame)
    b[off + 4], b[off + 5] = ident >> 8, ident & 0xFF
    b[off + 10], b[off + 11] = ck >> 8, ck & 0xFF
    return bytes(b)


class Scheduler:
    """Merges every stream's occurrences into one time-ordered frame stream.

    ``load`` (re)declares the streams of the current phase; streams whose id
    and fingerprint are unchanged keep running (and keep their connection),
    others stop and new ones start shortly after ``t``.
    """

    def __init__(self, seed: int, epoch0: float = 0.0,
                 day_profile: Optional[str] = None,
                 utc_offset: float = 0.0, min_period: float = 0.0) -> None:
        self.seed = seed
        self.min_period = min_period
        self.epoch0 = epoch0
        self.day_profile = day_profile
        self.utc_offset = utc_offset
        self.streams: Dict[tuple, Stream] = {}
        self._sheap: List[tuple] = []
        self._fheap: List[Item] = []
        self._n = 0
        self.stamp = HostStamper()
        self.injected = 0
        self.ports: Dict[tuple, Stream] = {}    # open persistent 4-tuples
        self.gen: Dict[tuple, int] = {}         # restarts per stream id
        # --sprinkle-ratio: target fraction of wire frames from sprinkle
        # streams (0 = their natural periods); frames so far by sprinkle?
        self.ratio = 0.0
        self.wire: Dict[bool, int] = {False: 0, True: 0}
        self._n_sprinkle = 0

    # -- stream management --------------------------------------------------
    def load(self, streams: List[Stream], t: float, hosts=(),
             initial: bool = False, soon: Optional[Dict] = None
             ) -> Tuple[List[Stream], List[Stream]]:
        """Make ``streams`` the active set at simulated time ``t``: at the
        start each new stream's first occurrence falls at random within its
        period, later within min(period, 30 s), or ``soon[sid]`` seconds
        after ``t``. Returns (started, stopped)."""
        soon = soon or {}
        if hosts:
            self.stamp.load(hosts)
        new = {s.sid: s for s in streams}
        stopped = []
        for sid, old in list(self.streams.items()):
            s = new.get(sid)
            if s is None or s.fp != old.fp:
                old.alive = False
                old.release(self)
                stopped.append(old)
                del self.streams[sid]
        started = []
        for sid, s in new.items():
            if sid in self.streams:
                continue
            gen = self.gen.get(sid, -1) + 1
            self.gen[sid] = gen
            s.bind(self.seed, gen)
            if s.period < self.min_period:
                s.period = self.min_period
                if s.key == "enip-io":
                    s.ep.meta["enip_rpi_us"] = int(s.period * 1e6)
            first = soon.get(sid)
            if first is None:
                first = s.rng.uniform(0, s.period if initial and not (
                    self.ratio and s.source.startswith("sprinkle:"))
                    else min(s.period, 30.0))
            self._schedule(s, t + first, step=False)
            self.streams[sid] = s
            started.append(s)
        self._n_sprinkle = sum(1 for x in self.streams.values()
                               if x.source.startswith("sprinkle:"))
        return started, stopped

    def inject(self, t: float, key: str, frames: List[List[bytes]],
               source: str = "baseline", gap: float = 0.0005) -> None:
        """One-off frames (e.g. a gratuitous ARP on arrival) at ``t``."""
        for i, copies in enumerate(frames):
            self._push(t + i * gap, key, copies, source, i == 0)
        self.injected += len(frames)

    def _push(self, t, key, copies, source, occ) -> None:
        self._n += 1
        heapq.heappush(self._fheap, (t, self._n, key, copies, source, occ))

    def _factor(self, s: Stream, t: float) -> float:
        return timing.factor(self.day_profile, s.cls, self.epoch0 + t,
                             self.utc_offset)

    def _schedule(self, s: Stream, t: float, step: bool = True) -> None:
        """Queue ``s``'s next occurrence: one interval after ``t`` (or at
        ``t`` itself with ``step=False``). Under a day profile, candidate
        times come ``peak`` times as often and each is kept with probability
        factor/peak (thinning), so the class's rate follows the hour. With a
        sprinkle ratio, sprinkle streams follow :meth:`_ratio_interval`."""
        if step and self.ratio > 0 and s.source.startswith("sprinkle:"):
            t += self._ratio_interval(s, t)
        elif timing.DAY_PROFILES.get(self.day_profile or "flat", {}).get(s.cls):
            peak = timing.peak(self.day_profile, s.cls)
            if step:
                t += s.interval() / peak
            for _ in range(100000):
                if s.rng.random() * peak < self._factor(s, t):
                    break
                t += s.interval() / peak
        elif step:
            t += s.interval()
        s.next_t = t
        self._n += 1
        heapq.heappush(self._sheap, (t, self._n, s))

    def _ratio_interval(self, s: Stream, t: float) -> float:
        """Next interval of sprinkle stream ``s`` so that sprinkle frames
        make up ``ratio`` of the wire: the sprinkle streams share the frame
        rate ``baseline rate * r / (1 - r)`` equally, each recurring as often
        as its mean frames per occurrence allow, sped up (or slowed down, at
        most 4x) while the sprinkle total so far is short of (or over) its
        target. The baseline rate is measured, so it follows day profiles
        and campaign phases."""
        r = min(self.ratio, 0.9)
        base, spr = self.wire[False], self.wire[True]
        want = base / max(t, 1.0) * r / (1.0 - r)      # sprinkle frames/s
        if want <= 0 or s.occ == 0:
            return s.interval()
        iv = (s.wire / s.occ) * max(1, self._n_sprinkle) / want
        target = base * r / (1.0 - r)
        iv *= min(max((spr + 1.0) / (target + 1.0), 0.25), 4.0)
        return max(1e-3, iv * (1.0 + s.rng.uniform(-s.jitter, s.jitter)))

    # -- the merged stream -----------------------------------------------------
    def run(self, t_end: float = INF) -> Iterator[Item]:
        """Yield frames with ``t < t_end`` in time order (IP IDs of
        host-counter stacks stamped in wire order). Frames past ``t_end``
        stay queued for the next call."""
        sheap, fheap = self._sheap, self._fheap
        pop, push = heapq.heappop, heapq.heappush
        while True:
            while sheap and sheap[0][0] < t_end and (
                    not fheap or sheap[0][0] <= fheap[0][0]):
                t, _, s = pop(sheap)
                if not s.alive or t != s.next_t:
                    continue
                spr = s.source.startswith("sprinkle:")
                for ft, copies, occ in s.occur(t, self):
                    self._n += 1
                    push(fheap, (ft, self._n, s.key, copies, s.source, occ))
                    self.wire[spr] += len(copies)
                    if spr:
                        s.wire += len(copies)
                self._schedule(s, t)
            if not fheap or fheap[0][0] >= t_end:
                return
            t, n, key, copies, source, occ = pop(fheap)
            yield t, n, key, self.stamp(copies), source, occ

    def pending(self) -> int:
        return len(self._fheap)
