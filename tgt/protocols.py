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

import struct
import zlib
from dataclasses import replace
from typing import Callable, List

from . import packet as P
from .packet import Endpoints

# A flow builder: (endpoints, message_count) -> list of frames
FlowBuilder = Callable[[Endpoints, int], List[bytes]]


# ---------------------------------------------------------------------------
# TCP session helper
# ---------------------------------------------------------------------------
class TcpSession:
    """Tracks sequence/ack numbers for a single TCP conversation."""

    def __init__(self, ep: Endpoints, sport: int, dport: int,
                 iss: int = 1000, irs: int = 5000):
        self.ep = ep
        self.sport = sport
        self.dport = dport
        self.c_seq = iss          # client next seq
        self.s_seq = irs          # server next seq
        self.frames: List[bytes] = []

    def _emit(self, from_client: bool, flags: int, payload: bytes = b"") -> None:
        if from_client:
            seq, ack = self.c_seq, self.s_seq
            sport, dport = self.sport, self.dport
        else:
            seq, ack = self.s_seq, self.c_seq
            sport, dport = self.dport, self.sport
        seg = P.tcp(
            self.ep.client_ip if from_client else self.ep.server_ip,
            self.ep.server_ip if from_client else self.ep.client_ip,
            sport, dport, seq, ack, flags, payload,
        )
        self.frames.append(P.ip_frame(self.ep, from_client, P.IPPROTO_TCP, seg))
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

    def request(self, payload: bytes) -> None:
        self._emit(True, P.PSH | P.ACK, payload)

    def response(self, payload: bytes) -> None:
        self._emit(False, P.PSH | P.ACK, payload)

    def teardown(self) -> None:
        self._emit(True, P.FIN | P.ACK)
        self._emit(False, P.FIN | P.ACK)
        self._emit(True, P.ACK)


def _tcp_flow(ep: Endpoints, sport: int, dport: int,
              exchanges: List[tuple[bytes, bytes]]) -> List[bytes]:
    """Build one TCP session: handshake, each (request, response), teardown."""
    s = TcpSession(ep, sport, dport)
    s.handshake()
    for req, resp in exchanges:
        if req:
            s.request(req)
        if resp:
            s.response(resp)
    s.teardown()
    return s.frames


# A client ephemeral source port that increments per session for realism.
_next_sport = 40000


def _sport() -> int:
    global _next_sport
    _next_sport += 1
    if _next_sport > 60000:
        _next_sport = 40000
    return _next_sport


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
    """Modbus/TCP (502): Read Holding Registers + Write Single Register."""
    exchanges = []
    for i in range(count):
        tid = (i + 1) & 0xFFFF
        unit = 1
        # Read Holding Registers (FC 0x03): start=0, qty=10
        req = struct.pack("!HHHBB HH", tid, 0, 6, unit, 0x03, 0, 10)
        # Response: 10 registers (20 bytes) of sample values
        regvals = b"".join(struct.pack("!H", (0x1000 + i + r) & 0xFFFF)
                           for r in range(10))
        resp = struct.pack("!HHHBBB", tid, 0, 3 + len(regvals), unit,
                           0x03, len(regvals)) + regvals
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


def dnp3_flow(ep: Endpoints, count: int) -> List[bytes]:
    """DNP3 (20000): link frames (0x0564 + per-block CRCs) carrying a master's
    class-0 READ and the outstation's analog-input RESPONSE (g30v2)."""
    def link(ctrl: int, dst: int, src: int, user: bytes) -> bytes:
        hdr = struct.pack("<BBBBHH", 0x05, 0x64, 5 + len(user), ctrl, dst, src)
        out = hdr + _dnp3_crc(hdr)
        for k in range(0, len(user), 16):          # CRC after every 16 bytes
            out += user[k:k + 16] + _dnp3_crc(user[k:k + 16])
        return out

    exchanges = []
    for i in range(count):
        tp = 0xC0 | (i & 0x3F)                     # transport: FIN | FIR | seq
        ac = 0xC0 | (i & 0x0F)                     # application: FIR | FIN | seq
        read = bytes([tp, ac, 0x01]) + b"\x3c\x01\x06"   # READ g60v1, all
        points = b"".join(struct.pack("<Bh", 0x01, 100 * i + p)
                          for p in range(4))      # flags ONLINE + int16
        resp = bytes([tp, ac, 0x81, 0x00, 0x00]) + \
            b"\x1e\x02\x00\x00\x03" + points       # g30v2, start-stop 0..3
        exchanges.append((link(0xC4, 1, 10, read), link(0x44, 10, 1, resp)))
    return _tcp_flow(ep, _sport(), 20000, exchanges)


def enip_flow(ep: Endpoints, count: int) -> List[bytes]:
    """EtherNet/IP (44818): RegisterSession, unconnected CIP Get_Attribute_Single
    polls (Identity status) in SendRRData, then UnRegisterSession."""
    session = 0x12340000 | (zlib.crc32(P.ip_to_bytes(ep.client_ip)) & 0xFFFF)
    exchanges = [(_enip(0x0065, 0, struct.pack("<HH", 1, 0)),
                  _enip(0x0065, session, struct.pack("<HH", 1, 0)))]

    def rr(cip: bytes, ctx: int) -> bytes:      # SendRRData: handle, timeout
        return _enip(0x006F, session, struct.pack("<IH", 0, 10) +
                     _cpf((0x0000, b""), (0x00B2, cip)), context=ctx)

    for i in range(count):
        # Get_Attribute_Single, path class 0x01 / instance 1 / attribute 5
        req = bytes([0x0E, 0x03, 0x20, 0x01, 0x24, 0x01, 0x30, 0x05])
        rsp = bytes([0x8E, 0x00, 0x00, 0x00]) + struct.pack("<H", 0x0060)
        exchanges.append((rr(req, i + 1), rr(rsp, i + 1)))
    exchanges.append((_enip(0x0066, session, b""), b""))   # UnRegisterSession
    return _tcp_flow(ep, _sport(), 44818, exchanges)


def s7comm_flow(ep: Endpoints, count: int) -> List[bytes]:
    """S7comm (102): COTP connect, Setup Communication, then Read Var jobs on
    DB1 answered by Ack_Data with the bytes read."""
    exchanges = _s7_connect()
    for i in range(count):
        ref = i + 1
        addr = (i * 10) << 3                       # byte offset, in bits
        item = b"\x12\x0a\x10\x02" + struct.pack("!HHB", 10, 1, 0x84) + \
            addr.to_bytes(3, "big")                # S7ANY: 10 BYTE of DB1
        job = _s7(1, ref, b"\x04\x01" + item)
        values = bytes((i + v) & 0xFF for v in range(10))
        ack = _s7(3, ref, b"\x04\x01",
                  b"\xff\x04" + struct.pack("!H", len(values) * 8) + values)
        exchanges.append((job, ack))
    return _tcp_flow(ep, _sport(), 102, exchanges)


def iec104_flow(ep: Endpoints, count: int) -> List[bytes]:
    """IEC 60870-5-104 (2404): STARTDT, a station interrogation answered with
    measured floats (M_ME_NC_1), then spontaneous values acked by S-frames."""
    def u(ctrl: int) -> bytes:                     # U-format: 4 control octets
        return bytes([0x68, 4, ctrl, 0, 0, 0])

    def s(nr: int) -> bytes:                       # S-format acknowledgement
        return struct.pack("<BBHH", 0x68, 4, 0x0001, nr << 1)

    def i_fr(ns: int, nr: int, asdu: bytes) -> bytes:
        return struct.pack("<BBHH", 0x68, 4 + len(asdu), ns << 1, nr << 1) + asdu

    def asdu(type_id: int, cot: int, ioa: int, element: bytes) -> bytes:
        # 1 object, COT + originator 0, common address 1, 3-byte IOA
        return struct.pack("<BBBBH", type_id, 1, cot, 0, 1) + \
            ioa.to_bytes(3, "little") + element

    def value(i: int) -> bytes:                    # short float + QDS
        return struct.pack("<fB", 49.95 + 0.01 * i, 0x00)

    gi = b"\x14"                                   # QOI 20: station
    exchanges = [(u(0x07), u(0x0B))]               # STARTDT act / con
    exchanges.append((
        i_fr(0, 0, asdu(100, 6, 0, gi)),           # C_IC_NA_1 activation
        i_fr(0, 1, asdu(100, 7, 0, gi)) +          # ... confirmation
        i_fr(1, 1, asdu(13, 20, 1001, value(0))) +   # interrogated value
        i_fr(2, 1, asdu(100, 10, 0, gi))))         # ... termination
    ns = 3
    for i in range(1, max(1, count)):
        exchanges.append((s(ns), i_fr(ns, 1, asdu(13, 3, 1001 + i % 4,
                                                  value(i)))))
        ns += 1
    exchanges.append((s(ns), b""))
    return _tcp_flow(ep, _sport(), 2404, exchanges)


def bacnet_flow(ep: Endpoints, count: int) -> List[bytes]:
    """BACnet/IP (47808/UDP): BVLC + NPDU + APDU ReadProperty."""
    frames = []
    for i in range(count):
        # APDU: confirmed-request, ReadProperty (svc 12), object analog-input 1
        apdu = struct.pack("!BBB", 0x00, 0x05, 0x0C) + \
            b"\x0c\x00\x00\x00\x01\x19\x55"
        npdu = struct.pack("!BB", 0x01, 0x00)
        bvlc = struct.pack("!BBH", 0x81, 0x0A, 4 + len(npdu) + len(apdu))
        payload = bvlc + npdu + apdu
        frames.append(P.udp_frame(ep, True, 47808, 47808, payload, ident=i))
    return frames


def opcua_flow(ep: Endpoints, count: int) -> List[bytes]:
    """OPC UA binary (4840): Hello/Acknowledge, OpenSecureChannel (policy None),
    Read requests for a process value, then CloseSecureChannel."""
    url = f"opc.tcp://{ep.meta.get('host', ep.server_ip)}:4840".encode()
    policy = b"http://opcfoundation.org/UA/SecurityPolicy#None"
    null = struct.pack("<i", -1)                   # null String / ByteString
    ts = 134041248000000000                        # DateTime: 2025-10-06
    chan, token = 0x2000 + (zlib.crc32(url) & 0xFFF), 1

    def s(b: bytes) -> bytes:
        return struct.pack("<i", len(b)) + b

    def chunk(kind: bytes, body: bytes) -> bytes:
        return kind + b"F" + struct.pack("<I", 8 + len(body)) + body

    def nid(n: int, ns: int = 0) -> bytes:         # four-byte NodeId
        return struct.pack("<BBH", 0x01, ns, n)

    def req_hdr(handle: int) -> bytes:   # token, time, handle, diag, audit, timeout, ext
        return b"\x00\x00" + struct.pack("<qII", ts, handle, 0) + null + \
            struct.pack("<I", 10000) + b"\x00\x00\x00"

    def rsp_hdr(handle: int) -> bytes:   # time, handle, result, diag, strings, ext
        return struct.pack("<qII", ts, handle, 0) + b"\x00" + null + \
            b"\x00\x00\x00"

    def asym(seq: int, body: bytes) -> bytes:
        return chunk(b"OPN", struct.pack("<I", chan if seq > 1 else 0) +
                     s(policy) + null + null + struct.pack("<II", 1, 1) + body)

    def sym(kind: bytes, seq: int, req_id: int, body: bytes) -> bytes:
        return chunk(kind, struct.pack("<IIII", chan, token, seq, req_id) + body)

    hel = chunk(b"HEL", struct.pack("<IIIII", 0, 65535, 65535, 0, 0) + s(url))
    ack = chunk(b"ACK", struct.pack("<IIIII", 0, 65535, 65535, 2097152, 0))
    opn = asym(1, nid(446) + req_hdr(1) + struct.pack("<III", 0, 0, 1) +
               s(b"") + struct.pack("<I", 3600000))
    opn_rsp = asym(2, nid(449) + rsp_hdr(1) + struct.pack("<I", 0) +
                   struct.pack("<IIqI", chan, token, ts, 3600000) + s(b""))
    exchanges = [(hel, ack), (opn, opn_rsp)]
    for i in range(count):
        seq, h = i + 2, i + 2
        node = nid(1001 + i % 8, ns=2) + struct.pack("<I", 13) + null + \
            struct.pack("<H", 0) + null            # Value attr, no range/encoding
        read = sym(b"MSG", seq, h, nid(631) + req_hdr(h) +
                   struct.pack("<dIi", 0.0, 2, 1) + node)
        dv = b"\x01\x0b" + struct.pack("<d", 72.5 + i)   # DataValue: Double
        rsp = sym(b"MSG", seq, h, nid(634) + rsp_hdr(h) +
                  struct.pack("<i", 1) + dv + struct.pack("<i", 0))
        exchanges.append((read, rsp))
    n = count + 2
    exchanges.append((sym(b"CLO", n, n, nid(452) + req_hdr(n)), b""))
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
    frames = []
    for i in range(count):
        req = P.icmp_echo(0x1234, i, _PING_DATA)
        frames.append(P.ip_frame(ep, True, P.IPPROTO_ICMP, req, ident=i))
        rep = struct.pack("!BBHHH", 0, 0, 0, 0x1234, i) + _PING_DATA
        chk = P.checksum16(rep)
        rep = rep[:2] + struct.pack("!H", chk) + rep[4:]
        frames.append(P.ip_frame(ep, False, P.IPPROTO_ICMP, rep, ident=i))
    return frames


def dns_flow(ep: Endpoints, count: int) -> List[bytes]:
    """DNS (53/UDP): A-record query + response."""
    def qname(name: str) -> bytes:
        out = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
        return out + b"\x00"

    frames = []
    for i in range(count):
        tid = (i + 1) & 0xFFFF
        q = qname(f"plc{i % 5}.ot.local") + struct.pack("!HH", 1, 1)
        query = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + q
        frames.append(P.udp_frame(ep, True, _sport(), 53, query, ident=i))
        ans = struct.pack("!HHHHHH", tid, 0x8180, 1, 1, 0, 0) + q + \
            struct.pack("!HHHIH4s", 0xC00C, 1, 1, 60, 4, P.ip_to_bytes(ep.server_ip))
        frames.append(P.udp_frame(ep, False, 53, _sport(), ans, ident=i))
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
    return _tcp_flow(ep, _sport(), 80, exchanges)


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
    """HTTPS (443): TLS ClientHello + ServerHello (SNI + cipher list).

    The SNI host and offered ciphers make the session fingerprintable
    (JA3-style) so an analyser sees encrypted web traffic and its endpoints.
    """
    sni = ep.meta.get("sni", ep.meta.get("host", "server.corp.local")).encode()
    exchanges = []
    for i in range(count):
        # SNI extension
        server_name = struct.pack("!BH", 0, len(sni)) + sni
        sni_list = struct.pack("!H", len(server_name)) + server_name
        sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
        exts = sni_ext
        ciphers = struct.pack("!HHHH", 0x1301, 0x1302, 0xc02f, 0xc030)
        body = (struct.pack("!H", 0x0303) + bytes(32) + b"\x00" +
                struct.pack("!H", len(ciphers)) + ciphers +
                b"\x01\x00" + struct.pack("!H", len(exts)) + exts)
        hello = struct.pack("!B", 0x01) + struct.pack("!I", len(body))[1:] + body
        rec = struct.pack("!BHH", 0x16, 0x0301, len(hello)) + hello  # handshake
        # ServerHello record (minimal)
        sh_body = struct.pack("!H", 0x0303) + bytes(32) + b"\x00" + \
            struct.pack("!H", 0x1301) + b"\x00\x00\x00"
        sh = struct.pack("!B", 0x02) + struct.pack("!I", len(sh_body))[1:] + sh_body
        srec = struct.pack("!BHH", 0x16, 0x0303, len(sh)) + sh
        exchanges.append((rec, srec))
    return _tcp_flow(ep, _sport(), 443, exchanges)


def edr_flow(ep: Endpoints, count: int) -> List[bytes]:
    """CrowdStrike Falcon EDR telemetry: the sensor's outbound TLS channel to
    the CrowdStrike Security Cloud.

    It is an ordinary HTTPS/TLS session; the EDR tell is the SNI — a CrowdStrike
    cloud host (``*.cloudsink.net`` for the sensor channel, ``*.crowdstrike.com``
    for API/console). CrowdStrike publishes connectivity by FQDN (its cloud is
    AWS-hosted with dynamic IPs), so the SNI is what a sensor fingerprints EDR
    traffic on. Set the host via ``ep.meta['sni']``; defaults to the US-1 sensor
    proxy."""
    if not ep.meta.get("sni") and not ep.meta.get("domain"):
        ep = replace(ep, meta={**ep.meta, "sni": "ts01-b.cloudsink.net"})
    return https_flow(ep, count)


def dhcp_flow(ep: Endpoints, count: int) -> List[bytes]:
    """DHCP (67/68): Discover + Offer with a fingerprint (option 55 + vendor 60).

    Option 55 (parameter request list) and option 60 (vendor class, e.g.
    "MSFT 5.0") are exactly what device-fingerprinting engines use to identify
    the OS — set via ``ep.meta['dhcp_vendor']``.
    """
    vendor = ep.meta.get("dhcp_vendor", "MSFT 5.0").encode()
    chaddr = P.mac_to_bytes(ep.client_mac) + bytes(10)
    frames = []
    for i in range(count):
        base = struct.pack("!BBBBIHH", 1, 1, 6, 0, 0x3903F326, 0, 0x8000) + \
            bytes(4) * 4 + chaddr + bytes(64) + bytes(128) + \
            struct.pack("!I", 0x63825363)          # magic cookie
        # options: 53 (DHCPDISCOVER), 55 (param request list), 60 (vendor class)
        opts = b"\x35\x01\x01" + \
            b"\x37\x08\x01\x03\x06\x0f\x1f\x21\x2b\x2c" + \
            b"\x3c" + bytes([len(vendor)]) + vendor + b"\xff"
        disc = base + opts
        frames.append(P.udp_frame(ep, True, 68, 67, disc, ident=i))
        offer_opts = b"\x35\x01\x02\xff"           # DHCPOFFER
        offer = base + offer_opts
        frames.append(P.udp_frame(ep, False, 67, 68, offer, ident=i))
    return frames


def netbios_flow(ep: Endpoints, count: int) -> List[bytes]:
    """NetBIOS (137/UDP): name registration/announcement carrying the host name.

    NetBIOS name-service broadcasts advertise the workstation name and, with
    the browser service, its OS — a classic passive fingerprint source.
    """
    name = ep.meta.get("nbname", "WORKSTATION").upper()[:15].ljust(15)
    def encode_nb(n: str) -> bytes:
        enc = b""
        for ch in (n + "\x00")[:16]:
            b = ord(ch)
            enc += bytes([(b >> 4) + 0x41, (b & 0x0F) + 0x41])
        return b"\x20" + enc + b"\x00"
    frames = []
    for i in range(count):
        # name registration request (broadcast)
        pkt = struct.pack("!HHHHHH", (i + 1) & 0xFFFF, 0x2910, 1, 0, 0, 1) + \
            encode_nb(name) + struct.pack("!HH", 0x0020, 0x0001) + \
            struct.pack("!HHHIHH4s", 0xC00C, 0x0020, 0x0001, 300000, 6,
                        0x0000, P.ip_to_bytes(ep.client_ip))   # B-node, unique
        frames.append(P.udp_frame(ep, True, 137, 137, pkt, ident=i))
    return frames


def ntp_flow(ep: Endpoints, count: int) -> List[bytes]:
    """NTP (123/UDP): client request + server response."""
    frames = []
    for i in range(count):
        req = struct.pack("!B", 0x1B) + bytes(47)  # LI=0 VN=3 mode=3 (client)
        frames.append(P.udp_frame(ep, True, _sport(), 123, req, ident=i))
        resp = struct.pack("!B", 0x1C) + bytes(47)  # mode=4 (server)
        frames.append(P.udp_frame(ep, False, 123, _sport(), resp, ident=i))
    return frames


# ---------------------------------------------------------------------------
# OT asset-identity / fingerprint flows (vendor + model strings)
# ---------------------------------------------------------------------------
def enip_identity_flow(ep: Endpoints, count: int) -> List[bytes]:
    """EtherNet/IP (44818): List Identity carrying a Rockwell/Allen-Bradley
    product name — what a monitor reads to inventory the PLC vendor and model."""
    product = ep.meta.get("product", "1756-L71/B LOGIX5571").encode()[:32]
    vendor_id = ep.meta.get("vendor_id", 0x0001)   # 0x0001 = Rockwell Automation
    dev_type = ep.meta.get("device_type", 0x000E)  # 0x0E PLC, 0x02 AC drive
    serial = zlib.crc32(P.mac_to_bytes(ep.server_mac))
    sock = struct.pack(">hHI8s", 2, 44818,
                       int.from_bytes(P.ip_to_bytes(ep.server_ip), "big"),
                       bytes(8))
    # version, socket, vendor, device type, product code, revision 20.11,
    # status, serial, product name (SHORT_STRING), state 3 = operational
    ident = struct.pack("<H", 1) + sock + struct.pack(
        "<HHHBBHI", vendor_id, dev_type, 55, 20, 11, 0x0060, serial) + \
        bytes([len(product)]) + product + b"\x03"
    exchanges = []
    for i in range(count):
        exchanges.append((_enip(0x0063, 0, b"", context=i + 1),
                          _enip(0x0063, 0, _cpf((0x000C, ident)),
                                context=i + 1)))
    return _tcp_flow(ep, _sport(), 44818, exchanges)


def s7_identity_flow(ep: Endpoints, count: int) -> List[bytes]:
    """S7comm (102): SZL 0x0011 read returning the Siemens order number
    (e.g. 6ES7 ...) and firmware version — how monitors fingerprint S7 PLCs."""
    order = ep.meta.get("order", "6ES7 315-2EH14-0AB0").encode().ljust(20)[:20]
    # SZL 0x0011 records (28 bytes): index, MlfB, BGTyp, Ausbg, Ausbe
    recs = struct.pack("!H20sHHH", 0x0001, order, 0, 0x0001, 0x0001) + \
        struct.pack("!H20sHHH", 0x0006, order, 0, 0x0001, 0x0001) + \
        struct.pack("!H20sHHH", 0x0007, b" " * 20, 0, 0x5603, 0x0200)  # V3.2
    szl = struct.pack("!HHHH", 0x0011, 0x0000, 28, 3) + recs
    exchanges = _s7_connect()
    for i in range(count):
        ref = i + 1
        # userdata: CPU functions (0x4) request, subfunction read SZL
        req = _s7(7, ref, b"\x00\x01\x12\x04\x11\x44\x01\x00",
                  b"\xff\x09\x00\x04\x00\x11\x00\x00")    # SZL 0x0011 idx 0
        rsp = _s7(7, ref, b"\x00\x01\x12\x08\x12\x84\x01" + bytes([ref & 0xFF]) +
                  b"\x00\x00\x00\x00",
                  b"\xff\x09" + struct.pack("!H", len(szl)) + szl)
        exchanges.append((req, rsp))
    return _tcp_flow(ep, _sport(), 102, exchanges)


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


PROFILES: dict[str, Profile] = {}


def _reg(key, name, category, port, transport, build, desc):
    PROFILES[key] = Profile(key, name, category, port, transport, build, desc)


# OT / ICS
_reg("modbus", "Modbus/TCP", "OT", "502", "tcp", modbus_flow,
     "Read Holding Registers + Write Single Register polling")
_reg("dnp3", "DNP3", "OT", "20000", "tcp", dnp3_flow,
     "CRC-valid link frames: class-0 READ + analog-input RESPONSE")
_reg("enip", "EtherNet/IP + CIP", "OT", "44818", "tcp", enip_flow,
     "RegisterSession + SendRRData CIP Get_Attribute_Single polls")
_reg("s7comm", "S7comm (Siemens)", "OT", "102", "tcp", s7comm_flow,
     "COTP connect, Setup Communication, Read Var job/ack_data")
_reg("iec104", "IEC 60870-5-104", "OT", "2404", "tcp", iec104_flow,
     "STARTDT, interrogation + M_ME_NC_1 floats, S-frame acks")
_reg("bacnet", "BACnet/IP", "OT", "47808", "udp", bacnet_flow,
     "BVLC/NPDU ReadProperty on analog-input objects")
_reg("opcua", "OPC UA", "OT", "4840", "tcp", opcua_flow,
     "Hello/Ack, OpenSecureChannel, ReadRequest/Response, Close")
# OT asset identity / fingerprint
_reg("enip-id", "EtherNet/IP List Identity", "OT", "44818", "tcp",
     enip_identity_flow, "Rockwell/Allen-Bradley vendor + product identity")
_reg("s7-id", "S7 SZL Identity", "OT", "102", "tcp", s7_identity_flow,
     "Siemens module/order number (6ES7…) identification")
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
     "TLS ClientHello/ServerHello with SNI + cipher list")
_reg("edr", "CrowdStrike EDR", "IT", "443", "tcp", edr_flow,
     "Falcon sensor TLS telemetry to the CrowdStrike cloud (cloudsink SNI)")
_reg("smb", "SMB / CIFS", "IT", "445", "tcp", smb_flow,
     "Negotiate (SMBv1 legacy or SMB 3.0.2) + echo keep-alives")
_reg("kerberos", "Kerberos", "IT", "88", "tcp", kerberos_flow,
     "AS-REQ + PREAUTH_REQUIRED from the Domain Controller")
_reg("ldap", "LDAP / AD", "IT", "389", "tcp", ldap_flow,
     "bind + rootDSE search against Active Directory")
_reg("dhcp", "DHCP", "IT", "67", "udp", dhcp_flow,
     "Discover/Offer with option 55 + vendor-class fingerprint")
_reg("netbios", "NetBIOS-NS", "IT", "137", "udp", netbios_flow,
     "Name registration/announcement carrying host name + OS")
_reg("ntp", "NTP", "IT", "123", "udp", ntp_flow,
     "Time sync client/server exchange")


def get(key: str) -> Profile:
    if key not in PROFILES:
        raise KeyError(key)
    return PROFILES[key]


def all_profiles() -> List[Profile]:
    return list(PROFILES.values())
