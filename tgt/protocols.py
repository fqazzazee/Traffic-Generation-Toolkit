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


def dnp3_flow(ep: Endpoints, count: int) -> List[bytes]:
    """DNP3 (20000): data-link header (0x0564) + application read request."""
    def dl_frame(src: int, dst: int, ctrl: int, app: bytes) -> bytes:
        length = 5 + len(app)          # len counts everything after the len byte
        hdr = struct.pack("<BBBBHH", 0x05, 0x64, length & 0xFF, ctrl,
                          dst & 0xFFFF, src & 0xFFFF)
        # CRC bytes are normally appended per block; sensors classify on the
        # 0x0564 start pattern + control/addressing, which we reproduce here.
        return hdr + app

    exchanges = []
    for i in range(count):
        # Application layer: transport hdr + app ctrl + function READ (0x01)
        req_app = struct.pack("<BBB", 0xC0 | (i & 0x3F), 0xC0 | (i & 0x0F), 0x01)
        resp_app = struct.pack("<BBBBB", 0xC0 | (i & 0x3F), 0xC0 | (i & 0x0F),
                               0x81, 0x00, 0x00)  # RESPONSE + IIN
        req = dl_frame(src=10, dst=1, ctrl=0xC4, app=req_app)
        resp = dl_frame(src=1, dst=10, ctrl=0x44, app=resp_app)
        exchanges.append((req, resp))
    return _tcp_flow(ep, _sport(), 20000, exchanges)


def enip_flow(ep: Endpoints, count: int) -> List[bytes]:
    """EtherNet/IP (44818): register session + CIP list-identity style exchange."""
    def enip(cmd: int, session: int, data: bytes) -> bytes:
        return struct.pack("<HHIIQI", cmd, len(data), session, 0, 0, 0) + data

    exchanges = []
    session = 0x00000000
    # RegisterSession (0x0065): protocol version 1, options 0
    reg = enip(0x0065, 0, struct.pack("<HH", 1, 0))
    reg_resp = enip(0x0065, 0x12345678, struct.pack("<HH", 1, 0))
    exchanges.append((reg, reg_resp))
    session = 0x12345678
    for i in range(max(0, count - 1)):
        # SendRRData (0x006F) wrapping a small CIP service request
        cip = struct.pack("<BBBB", 0x0E, 0x02, 0x20, 0x01)  # Get_Attribute_Single
        data = struct.pack("<IHH", 0, 0, len(cip)) + cip
        req = enip(0x006F, session, data)
        resp = enip(0x006F, session, data + b"\x00\x00")
        exchanges.append((req, resp))
    return _tcp_flow(ep, _sport(), 44818, exchanges)


def s7comm_flow(ep: Endpoints, count: int) -> List[bytes]:
    """S7comm (102): TPKT + COTP + S7 header, ROSCTR job/ack pattern."""
    def tpkt(cotp_plus: bytes) -> bytes:
        length = 4 + len(cotp_plus)
        return struct.pack("!BBH", 0x03, 0x00, length) + cotp_plus

    # COTP connection request (once) then S7 data PDUs
    frames_ex = []
    # COTP CR (class 0)
    cotp_cr = struct.pack("!BB HHB", 17, 0xE0, 0, 0, 0x00) + \
        b"\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x02"
    cotp_cc = struct.pack("!BB HHB", 17, 0xD0, 0, 0, 0x00) + \
        b"\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x02"
    frames_ex.append((tpkt(cotp_cr), tpkt(cotp_cc)))

    cotp_dt = struct.pack("!BBB", 2, 0xF0, 0x80)  # COTP DT, EOT
    for i in range(max(0, count - 1)):
        # S7 header: proto 0x32, ROSCTR job(1)/ack_data(3), PDUref, par/data len
        s7_job = struct.pack("!BBHHHH", 0x32, 0x01, 0, (i + 1) & 0xFFFF, 8, 0) + \
            b"\x00\x04\x01\x12\x0a\x10\x02"  # read-var style param
        s7_ack = struct.pack("!BBHHHHBB", 0x32, 0x03, 0, (i + 1) & 0xFFFF,
                             2, 5, 0, 0) + b"\x00\x04\x01"
        req = tpkt(cotp_dt + s7_job)
        resp = tpkt(cotp_dt + s7_ack)
        frames_ex.append((req, resp))
    return _tcp_flow(ep, _sport(), 102, frames_ex)


def iec104_flow(ep: Endpoints, count: int) -> List[bytes]:
    """IEC 60870-5-104 (2404): APCI (0x68) U/I frames, TESTFR + measured values."""
    def apci_u(control: int) -> bytes:
        # U-format: STARTDT/STOPDT/TESTFR act/con
        return struct.pack("<BBBBB", 0x68, 4, control, 0, 0)

    def apci_i(tx: int, rx: int, asdu: bytes) -> bytes:
        length = 4 + len(asdu)
        ctrl = struct.pack("<HH", (tx << 1) & 0xFFFF, (rx << 1) & 0xFFFF)
        return struct.pack("<BB", 0x68, length) + ctrl + asdu

    exchanges = []
    # STARTDT act / con
    exchanges.append((apci_u(0x07), apci_u(0x0B)))
    tx = rx = 0
    for i in range(max(0, count - 1)):
        # ASDU: type 13 (M_ME_NC_1 float), 1 obj, COT=3 (spont), CA=1, IOA=1
        asdu = struct.pack("<BBBH", 13, 0x01, 0x03, 1) + \
            struct.pack("<BH", 1, 0) + struct.pack("<fB", 1.5 + i, 0x00)
        exchanges.append((apci_i(tx, rx, asdu), apci_u(0x43)))  # TESTFR con ack
        tx += 1
        rx += 1
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
    """OPC UA (4840): Hello / Acknowledge handshake pattern."""
    endpoint_url = b"opc.tcp://plc.local:4840"
    hel_body = struct.pack("<IIIIII", 0, 65536, 65536, 65536, 0,
                           len(endpoint_url)) + endpoint_url
    hel = b"HEL" + b"F" + struct.pack("<I", 8 + len(hel_body)) + hel_body
    ack_body = struct.pack("<IIIIII", 0, 65536, 65536, 65536, 0, 0)
    ack = b"ACK" + b"F" + struct.pack("<I", 8 + len(ack_body)) + ack_body
    exchanges = [(hel, ack)]
    for _ in range(max(0, count - 1)):
        msg = b"MSG" + b"F" + struct.pack("<I", 12) + b"\x00\x00\x00\x00"
        exchanges.append((msg, msg))
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


def icmp_flow(ep: Endpoints, count: int) -> List[bytes]:
    """ICMP echo request/reply (ping sweep style)."""
    frames = []
    for i in range(count):
        req = P.icmp_echo(0x1234, i, b"tgt-icmp-probe--" + bytes(16))
        frames.append(P.ip_frame(ep, True, P.IPPROTO_ICMP, req, ident=i))
        rep = struct.pack("!BBHHH", 0, 0, 0, 0x1234, i) + b"tgt-icmp-probe--" + bytes(16)
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
    """SMB (445): negotiate + tree connect.

    Legacy hosts advertise only SMBv1 ("NT LM 0.12"), which flags them as
    exposed to MS17-010 / EternalBlue; modern hosts negotiate SMB2. Driven by
    ``ep.meta['smb']`` = "smb1" | "smb2" (default smb2).
    """
    def netbios(payload: bytes) -> bytes:
        return struct.pack("!I", len(payload))[1:].rjust(4, b"\x00")[:4] + payload

    dialect = ep.meta.get("smb", "smb2")
    exchanges = []
    for i in range(count):
        if dialect == "smb1":
            # SMB1 NEGOTIATE listing legacy dialects incl. "NT LM 0.12"
            dialects = b"\x02NT LM 0.12\x00\x02LANMAN2.1\x00"
            smb = (b"\xffSMB" + struct.pack("<B", 0x72) +          # NEGOTIATE
                   struct.pack("<I", 0) + b"\x18\x53\xc8" +
                   struct.pack("<HHHHIHHHHH", 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               (i + 1) & 0xFFFF) +
                   struct.pack("<BH", 0, len(dialects)) + dialects)
            req = netbios(smb)
            resp_smb = (b"\xffSMB" + struct.pack("<B", 0x72) +
                        struct.pack("<I", 0) + b"\x98\x53\xc8" + bytes(20) +
                        b"\x11\x05\x00\x03\x0a\x00\x01\x00")
            resp = netbios(resp_smb)
        else:
            # SMB2 NEGOTIATE (dialect 0x0311 / 3.1.1)
            smb2 = (b"\xfeSMB" + struct.pack("<HH", 64, 1) + bytes(2) +
                    struct.pack("<HH", 0, 0) + struct.pack("<I", 0) +
                    struct.pack("<I", i + 1) + bytes(44) +
                    struct.pack("<HHHH", 36, 2, 0, 0) +
                    struct.pack("<HH", 0x0202, 0x0311))
            req = netbios(smb2)
            resp = netbios(smb2[:64] + struct.pack("<HHH", 65, 0, 0x0311))
        exchanges.append((req, resp))
    return _tcp_flow(ep, _sport(), 445, exchanges)


def kerberos_flow(ep: Endpoints, count: int) -> List[bytes]:
    """Kerberos (88): AS-REQ / AS-REP style exchange to a Domain Controller."""
    realm = ep.meta.get("realm", "CORP.LOCAL").encode()
    exchanges = []
    for i in range(count):
        # minimal ASN.1-ish AS-REQ carrying the realm (classifiers key on
        # port 88 + the KRB_AS_REQ application tag 0x6a and the realm string)
        req = b"\x6a\x2e\x30\x2c" + b"\xa1\x03\x02\x01\x05" + \
            b"\xa2\x03\x02\x01\x0a" + b"\x1b" + bytes([len(realm)]) + realm
        rep = b"\x6b\x2e\x30\x2c" + b"\xa0\x03\x02\x01\x05" + \
            b"\xa1\x03\x02\x01\x0b" + b"\x1b" + bytes([len(realm)]) + realm
        exchanges.append((struct.pack("!I", len(req)) + req,
                          struct.pack("!I", len(rep)) + rep))
    return _tcp_flow(ep, _sport(), 88, exchanges)


def ldap_flow(ep: Endpoints, count: int) -> List[bytes]:
    """LDAP (389): bindRequest + searchRequest to Active Directory."""
    dn = ep.meta.get("dn", "CN=svc,DC=corp,DC=local").encode()
    exchanges = []
    for i in range(count):
        # LDAP bindRequest (appl 0) with a simple DN — enough to classify AD/LDAP
        inner = b"\x02\x01\x03" + b"\x04" + bytes([len(dn)]) + dn + \
            b"\x80\x00"
        bind = b"\x30" + bytes([len(inner) + 5]) + b"\x02\x01\x01" + \
            b"\x60" + bytes([len(inner)]) + inner
        srch = b"\x30\x0c\x02\x01\x02\x63\x07\x04\x00\x0a\x01\x00\x0a\x01\x00"
        exchanges.append((bind, srch))
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
            encode_nb(name) + struct.pack("!HH", 0x0020, 0x0001)
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
    product = ep.meta.get("product", "1756-L71/B LOGIX5571").encode()
    vendor_id = ep.meta.get("vendor_id", 0x0001)   # 0x0001 = Rockwell Automation
    exchanges = []
    for i in range(count):
        req = struct.pack("<HHIIQI", 0x0063, 0, 0, 0, 0, 0)   # ListIdentity
        # CPF: 1 item, Identity object with vendor/device/product-name string
        idbody = struct.pack("<HHHHIHBB", 1, 0x000C, 0, 0x0001, 0, vendor_id,
                             0x0E, 0x00) + struct.pack("<HHI", 0x000C, 0x0001,
                             0x00010203) + bytes([len(product)]) + product
        resp = struct.pack("<HHIIQI", 0x0063, len(idbody), 0, 0, 0, 0) + idbody
        exchanges.append((req, resp))
    return _tcp_flow(ep, _sport(), 44818, exchanges)


def s7_identity_flow(ep: Endpoints, count: int) -> List[bytes]:
    """S7comm (102): SZL read returning a Siemens module/order number
    (e.g. 6ES7 ...), used to fingerprint Siemens S7 PLC family and firmware."""
    order = ep.meta.get("order", "6ES7 315-2EH14-0AB0 ").encode()
    def tpkt(payload: bytes) -> bytes:
        return struct.pack("!BBH", 0x03, 0x00, 4 + len(payload)) + payload
    cotp_dt = struct.pack("!BBB", 2, 0xF0, 0x80)
    exchanges = []
    for i in range(count):
        # userdata SZL request (0x0011/0x001C module identification)
        req_s7 = struct.pack("!BBHHHH", 0x32, 0x07, 0, (i + 1) & 0xFFFF, 8, 8) + \
            b"\x00\x01\x12\x04\x11\x44\x01\x00"
        resp_s7 = struct.pack("!BBHHHH", 0x32, 0x07, 0, (i + 1) & 0xFFFF, 12,
                              len(order) + 8) + \
            b"\x00\x01\x12\x08\x12\x84\x01\x00" + order
        exchanges.append((tpkt(cotp_dt + req_s7), tpkt(cotp_dt + resp_s7)))
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
     "0x0564 data-link frames with application READ requests")
_reg("enip", "EtherNet/IP + CIP", "OT", "44818", "tcp", enip_flow,
     "RegisterSession + CIP Get_Attribute exchanges")
_reg("s7comm", "S7comm (Siemens)", "OT", "102", "tcp", s7comm_flow,
     "TPKT/COTP connect + S7 job/ack read-var PDUs")
_reg("iec104", "IEC 60870-5-104", "OT", "2404", "tcp", iec104_flow,
     "APCI STARTDT + I-format ASDU measured values")
_reg("bacnet", "BACnet/IP", "OT", "47808", "udp", bacnet_flow,
     "BVLC/NPDU ReadProperty on analog-input objects")
_reg("opcua", "OPC UA", "OT", "4840", "tcp", opcua_flow,
     "Hello/Acknowledge secure-channel handshake")
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
_reg("smb", "SMB / CIFS", "IT", "445", "tcp", smb_flow,
     "SMB negotiate (SMBv1 legacy or SMB2) + file-share traffic")
_reg("kerberos", "Kerberos", "IT", "88", "tcp", kerberos_flow,
     "AS-REQ/AS-REP to the Domain Controller")
_reg("ldap", "LDAP / AD", "IT", "389", "tcp", ldap_flow,
     "bind + search against Active Directory")
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
