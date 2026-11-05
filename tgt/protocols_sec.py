"""Secure OT protocol variants — what a passive monitor sees when it cannot
read the payload (issue #66).

Each secure variant is the plaintext conversation of its base protocol
carried through the protection the standard prescribes. The base builder
runs first and every application message it would send becomes one
encrypted record of the same plaintext size (plus the record overhead of the
negotiated cipher suite), in the same order and direction — so polls, their
sizes and their rhythm look like the cleartext session, which is what a
monitor can still baseline:

* ``enip-tls``   CIP Security, EtherNet/IP over TLS 1.2 on 2221/tcp: mutual
  authentication (the device and the originator present certificates),
  RegisterSession and the CIP polls as application data.
* ``enip-dtls``  CIP Security class-1 I/O: the Forward_Open over TLS on
  2221/tcp, then a DTLS 1.2 association (cookie exchange, mutual
  certificates) and the cyclic I/O as DTLS application data. UDP **2221**,
  not 2222: CIP Security carries secured I/O on the secure port, and that is
  where Wireshark's EtherNet/IP dissector registers DTLS (2222/udp is decoded
  as plaintext CIP I/O and would show the records as malformed).
* ``s7plus-tls`` S7-1500 (firmware V2.9+ / TIA Portal V17+) secure PG/HMI
  communication: COTP connection request/confirm and the S7CommPlus InitSsl
  exchange (function 0x05B3) in clear on 102, then TLS 1.3 records carried
  in COTP data TPDUs; server certificate only (the client proves itself with
  the PLC's access level password inside the session).
* ``opcua-sign-encrypt``  OPC UA Basic256Sha256 / SignAndEncrypt: Hello /
  Acknowledge in clear, OpenSecureChannel with the asymmetric security
  header (policy URI, sender application instance certificate, SHA-1
  thumbprint of the receiver's) and an RSA-OAEP-encrypted, signed body, then
  MSG / CLO chunks with the symmetric header (channel id, token id) and an
  AES-CBC body with HMAC-SHA256 signature.
* ``iec104-tls`` IEC 60870-5-104 under IEC 62351-3 on 19998/tcp (IANA
  ``iec-104-sec``), TLS 1.2 with mutual authentication.
* ``dnp3-tls``   DNP3 over TLS 1.2 (IEC 62351-3 / IEEE 1815-2012 Annex) on
  **19999/tcp**, the IANA ``dnp-sec`` port: it keeps secured and plaintext
  DNP3 apart (a 20000/tcp listener cannot tell a TLS ClientHello from a link
  frame) and it is what Wireshark maps to TLS + DNP3.
* ``modbus-sec`` Modbus/TCP Security on 802/tcp (IANA ``mbap-s``): TLS 1.2,
  mutual authentication, the client certificate carrying the Modbus role
  extension (OID 1.3.6.1.4.1.50316.802.1, a UTF8String role such as
  ``Operator``) the server authorizes function codes against.

Clients connect by IP address, so no ClientHello carries an SNI, and no ALPN
is offered. With TLS 1.2 (and DTLS 1.2, and OPC UA's OpenSecureChannel) the
certificates cross the wire in clear — their subject names the host — while
TLS 1.3 encrypts them. :data:`ENCRYPTION` and :data:`CERTS_IN_CLEAR` tell
:mod:`tgt.inventory` what stays observable.

Endpoint meta: ``sni`` (the server's name, its certificate CN — the
environment sets the host's FQDN), ``tls_client_cn`` (the client
certificate CN), ``tls_client`` (the client's OS TLS stack, see
:mod:`tgt.tls`), ``mbsec_role`` (Modbus role, default ``Operator``) and the
base protocol's own keys.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import replace
from typing import Dict, List, Tuple

from . import packet as P
from . import tls
from .packet import Endpoints
from .protocols import (TcpSession, _cycle_base, _rand32, _reg, _sport,
                        _tcp_flow, _tpkt)
from .protocols import get as _profile

# plaintext protocol -> its secure variant (env files: "secure": true)
SECURE_OF: Dict[str, str] = {
    "enip": "enip-tls", "enip-io": "enip-dtls", "s7plus": "s7plus-tls",
    "opcua": "opcua-sign-encrypt", "iec104": "iec104-tls",
    "dnp3": "dnp3-tls", "modbus": "modbus-sec",
}
PLAIN_OF: Dict[str, str] = {v: k for k, v in SECURE_OF.items()}
# the protection a monitor sees on the wire
ENCRYPTION: Dict[str, str] = {
    "enip-tls": "tls1.2", "enip-dtls": "dtls1.2", "s7plus-tls": "tls1.3",
    "opcua-sign-encrypt": "opcua-basic256sha256", "iec104-tls": "tls1.2",
    "dnp3-tls": "tls1.2", "modbus-sec": "tls1.2",
}
# whose certificate crosses in clear: (server's, client's)
CERTS_IN_CLEAR: Dict[str, Tuple[bool, bool]] = {
    "enip-tls": (True, True), "enip-dtls": (True, True),
    "s7plus-tls": (False, False), "opcua-sign-encrypt": (True, True),
    "iec104-tls": (True, True), "dnp3-tls": (True, True),
    "modbus-sec": (True, True),
}

# Server side of each variant: TLS versions and suite preference (RSA
# certificates, so RSA / ECDHE_RSA suites), whether it hands out tickets,
# whether it requires a client certificate.
_SERVERS: Dict[str, Tuple[tls.ServerProfile, bool]] = {
    # CIP Security EtherNet/IP confidentiality profile: TLS 1.2,
    # TLS_RSA_WITH_AES_128_CBC_SHA256 first
    "enip-tls": (tls.ServerProfile("cip-security", 0x0303, 0x0303,
                                   (0x003C, 0x002F, 0xC027, 0xC02F),
                                   tickets=False), True),
    # S7-1500 V2.9+: TLS 1.3 only, server-authenticated
    "s7plus-tls": (tls.ServerProfile("s7-1500", 0x0304, 0x0304, (),
                                     (0x1302, 0x1301, 0x1303)), False),
    # IEC 62351-3 Ed.2 profile for 104 and DNP3: TLS 1.2, ECDHE first
    "iec104-tls": (tls.ServerProfile("iec62351-3", 0x0303, 0x0303,
                                     (0xC02F, 0xC030, 0xC027, 0x003C),
                                     tickets=False), True),
    "dnp3-tls": (tls.ServerProfile("iec62351-3", 0x0303, 0x0303,
                                   (0xC02F, 0xC030, 0xC027, 0x003C),
                                   tickets=False), True),
    # Modbus/TCP Security: TLS 1.2 minimum, AES-128-CBC-SHA256 mandatory
    "modbus-sec": (tls.ServerProfile("mbap-s", 0x0303, 0x0303,
                                     (0xC02F, 0x003C, 0xC027),
                                     tickets=False), True),
}
_SERVERS["enip-dtls"] = _SERVERS["enip-tls"]

_DPORT = {"enip-tls": 2221, "enip-dtls": 2221, "s7plus-tls": 102,
          "opcua-sign-encrypt": 4840, "iec104-tls": 19998, "dnp3-tls": 19999,
          "modbus-sec": 802}

# An OT application uses its OS TLS library (or a bundled OpenSSL), not a
# browser: map the browser / pre-TLS-1.2 client stacks onto one that can
# meet a TLS 1.2 device.
_OT_CLIENT = {"chrome": "schannel10", "firefox": "openssl",
              "schannel-xp": "openssl", "schannel-2000": "openssl",
              "falcon": "openssl"}

MODBUS_ROLE_OID = "1.3.6.1.4.1.50316.802.1"


def _client_template(ep: Endpoints, proto: str) -> tls.ClientTemplate:
    """The client's TLS stack for an OT connection by IP address: no SNI,
    no ALPN. TIA Portal / WinCC bring their own OpenSSL (TLS 1.3)."""
    if proto == "s7plus-tls":
        key = "openssl"
    else:
        key = str(ep.meta.get("tls_client", "") or "openssl")
        key = _OT_CLIENT.get(key, key)
    t = tls.TEMPLATES.get(key, tls.TEMPLATES["openssl"])
    return replace(t, exts=tuple(e for e in t.exts
                                 if e not in ("server_name", "alpn")),
                   alpn=())


def _server_cn(ep: Endpoints) -> str:
    return str(ep.meta.get("sni") or ep.meta.get("host") or ep.server_ip)


def _client_cn(ep: Endpoints) -> str:
    return str(ep.meta.get("tls_client_cn") or ep.meta.get("nbname")
               or ep.client_ip)


def _role_extension(role: str) -> bytes:
    """Modbus/TCP Security role extension (non-critical): OID
    1.3.6.1.4.1.50316.802.1, value a DER UTF8String."""
    return tls._seq(tls._oid(MODBUS_ROLE_OID),
                    tls._der(0x04, tls._der(0x0C, role.encode())))


def certificates(ep: Endpoints, proto: str) -> Tuple[bytes, bytes]:
    """(server certificate, client certificate or b"") of a secure
    conversation: device / host certificates from the plant CA, CN = the
    host's name; the Modbus client's carries its role."""
    scn = _server_cn(ep)
    server = tls.certificate(scn)
    if not _SERVERS.get(proto, (None, True))[1]:
        return server, b""
    ccn = _client_cn(ep)
    extra = ()
    if proto == "modbus-sec":
        extra = (_role_extension(str(ep.meta.get("mbsec_role")
                                     or "Operator")),)
    client = tls.certificate(ccn, tls._Rand("cert", ccn, "client"),
                             eku=(tls.CLIENT_AUTH,), extra=extra)
    return server, client


# ---------------------------------------------------------------------------
# The base protocol's messages
# ---------------------------------------------------------------------------
def _messages(frames: List[bytes], ep: Endpoints) -> List[Tuple[str, bool,
                                                                 bytes]]:
    """(transport, from client, payload) of each application message in a
    host-built flow: TCP segments re-joined up to the PSH that ends each
    write, UDP datagrams as they are."""
    cmac = P.mac_to_bytes(ep.client_mac)
    out: List[Tuple[str, bool, bytes]] = []
    buf = {True: b"", False: b""}
    for f in frames:
        off = 18 if f[12:14] == b"\x81\x00" else 14
        if f[off - 2:off] != b"\x08\x00":
            continue
        frm = f[6:12] == cmac
        l4 = off + (f[off] & 15) * 4
        end = off + struct.unpack_from("!H", f, off + 2)[0]
        if f[off + 9] == P.IPPROTO_TCP:
            data = f[l4 + (f[l4 + 12] >> 4) * 4:end]
            if data:
                buf[frm] += data
                if f[l4 + 13] & P.PSH:
                    out.append(("tcp", frm, buf[frm]))
                    buf[frm] = b""
        elif f[off + 9] == P.IPPROTO_UDP:
            out.append(("udp", frm, f[l4 + 8:end]))
    return out


def _pairs(msgs) -> List[List[bytes]]:
    """Request / response exchanges: a client message opens one, the
    server's next message answers it; a server message nobody asked for
    (DNP3 unsolicited) stands alone."""
    ex: List[List[bytes]] = []
    for frm, data in msgs:
        if frm or not ex or ex[-1][1]:
            ex.append([data, b""] if frm else [b"", data])
        else:
            ex[-1][1] = data
    return ex


def _seed(ep: Endpoints, sport: int, proto: str) -> tuple:
    return (ep.client_ip, ep.server_ip, sport, proto, _rand32())


def _records(ch: tls.Channel, n: int) -> bytes:
    """Application data for an ``n``-byte message (16 KiB per record)."""
    out = b""
    while True:
        k = min(n, 16384)
        out += ch.record(k)
        n -= k
        if n <= 0:
            return out


def _session(ep: Endpoints, proto: str, sport: int):
    srv, _ = _SERVERS[proto]
    server, client = certificates(ep, proto)
    return tls.handshake(_client_template(ep, proto), srv, "",
                         _seed(ep, sport, proto), server_cert=server,
                         client_cert=client)


def _tls_flow(ep: Endpoints, count: int, proto: str) -> List[bytes]:
    """The base protocol's TCP conversation as TLS application data: TLS
    handshake, one record per message, close_notify both ways, FIN."""
    msgs = [(frm, d) for kind, frm, d in
            _messages(_profile(PLAIN_OF[proto]).build(ep, count), ep)
            if kind == "tcp"]
    sport = _sport()
    hs, ch = _session(ep, proto, sport)
    app = [(_records(ch, len(c)) if c else b"",
            _records(ch, len(r)) if r else b"") for c, r in _pairs(msgs)]
    close = (ch.close_notify(), ch.close_notify())
    return _tcp_flow(ep, sport, _DPORT[proto], hs + app + [close],
                     idle_from=len(hs))


def enip_tls_flow(ep: Endpoints, count: int) -> List[bytes]:
    """CIP Security (2221/tcp): EtherNet/IP explicit messaging — Register
    Session, CIP Get_Attribute_Single polls, UnRegisterSession — inside a
    mutually authenticated TLS 1.2 session."""
    return _tls_flow(ep, count, "enip-tls")


def iec104_tls_flow(ep: Endpoints, count: int) -> List[bytes]:
    """IEC 60870-5-104 secured per IEC 62351-3 (19998/tcp): STARTDT,
    interrogation, spontaneous points and TESTFR as TLS 1.2 records."""
    return _tls_flow(ep, count, "iec104-tls")


def dnp3_tls_flow(ep: Endpoints, count: int) -> List[bytes]:
    """DNP3 over TLS 1.2 (19999/tcp): class polls, unsolicited responses and
    confirms as TLS records."""
    return _tls_flow(ep, count, "dnp3-tls")


def modbus_sec_flow(ep: Endpoints, count: int) -> List[bytes]:
    """Modbus/TCP Security (802/tcp): the Modbus poll inside TLS 1.2 with a
    role-bearing client certificate (``ep.meta['mbsec_role']``)."""
    return _tls_flow(ep, count, "modbus-sec")


# ---------------------------------------------------------------------------
# CIP Security class-1 I/O (TLS + DTLS)
# ---------------------------------------------------------------------------
def enip_dtls_flow(ep: Endpoints, count: int) -> List[bytes]:
    """CIP Security implicit I/O: RegisterSession + Forward_Open as TLS
    records on 2221/tcp, a DTLS 1.2 handshake on 2221/udp, the cyclic
    O->T / T->O class-1 packets as DTLS application data (record sequence
    numbers continuing across builds), then Forward_Close and
    UnRegisterSession over TLS."""
    proto = "enip-dtls"
    msgs = _messages(_profile("enip-io").build(ep, count), ep)
    first_udp = next((i for i, m in enumerate(msgs) if m[0] == "udp"),
                     len(msgs))
    last_udp = max((i for i, m in enumerate(msgs) if m[0] == "udp"),
                   default=first_udp - 1)
    pre = [(frm, d) for _, frm, d in msgs[:first_udp]]
    post = [(frm, d) for _, frm, d in msgs[last_udp + 1:]]
    io = msgs[first_udp:last_udp + 1]
    sport = _sport()
    hs, ch = _session(ep, proto, sport)
    srv, _ = _SERVERS[proto]
    server, client = certificates(ep, proto)
    cb = _cycle_base(count)
    dhs, dch = tls.dtls_handshake(tls.DTLS_CLIENT, srv,
                                  _seed(ep, sport, "dtls"), server, client,
                                  app_seq=1 + cb)
    s = TcpSession(ep, sport, 2221)
    s.handshake()

    def tcp(pairs, idle: bool) -> None:
        for c, r in pairs:
            if c:
                s.request(c)
            if r:
                s.response(r)
                if idle:
                    s.delayed_ack()

    tcp(hs, False)
    tcp([(_records(ch, len(c)) if c else b"",
          _records(ch, len(r)) if r else b"") for c, r in _pairs(pre)], False)
    ident = cb & 0xFFFF
    for cgrams, sgrams in dhs:
        for frm, grams in ((True, cgrams), (False, sgrams)):
            for g in grams:
                s.frames.append(P.udp_frame(ep, frm, 2221, 2221, g,
                                            ident=ident))
                ident = (ident + 1) & 0xFFFF
    for _, frm, d in io:
        s.frames.append(P.udp_frame(ep, frm, 2221, 2221,
                                    dch.record(len(d), frm), ident=ident))
        ident = (ident + 1) & 0xFFFF
    tcp([(_records(ch, len(c)) if c else b"",
          _records(ch, len(r)) if r else b"") for c, r in _pairs(post)]
        + [(ch.close_notify(), ch.close_notify())], False)
    s.teardown()
    return s.frames


# ---------------------------------------------------------------------------
# S7CommPlus over TLS (S7-1500 V2.9+)
# ---------------------------------------------------------------------------
_TPDU = 1024                 # COTP TPDU size the connection request offers


def _cotp(data: bytes) -> bytes:
    """TLS bytes in COTP DT TPDUs (EOT on the last) inside TPKT."""
    room = _TPDU - 3
    chunks = [data[k:k + room] for k in range(0, len(data), room)]
    return b"".join(_tpkt(b"\x02\xf0" + bytes([0x80 if n == len(chunks) - 1
                                               else 0x00]) + c)
                    for n, c in enumerate(chunks))


def s7plus_tls_flow(ep: Endpoints, count: int) -> List[bytes]:
    """S7-1500 secure PG/HMI communication (102/tcp): COTP CR/CC to the
    SIMATIC-ROOT-HMI TSAP and the S7CommPlus InitSsl request/response in
    clear, then TLS 1.3 in COTP data TPDUs — CreateObject, SetMultiVariables,
    the GetMultiVariables polls and DeleteObject as application data, each
    record sized like the S7CommPlus PDU it carries."""
    from .protocols_eng import _s7p, _s7p_req, _s7p_rsp, _vlq
    proto = "s7plus-tls"
    msgs = [(frm, d) for kind, frm, d in
            _messages(_profile("s7plus").build(ep, count), ep)
            if kind == "tcp"]
    pairs = _pairs(msgs)
    init = (_s7p(1, _s7p_req(0x05B3, 1, 0x00000120, struct.pack("!I", 0),
                             flags=0x36)),
            _s7p(1, _s7p_rsp(0x05B3, 1, _vlq(0) + struct.pack("!I", 0))))
    sport = _sport()
    hs, ch = _session(ep, proto, sport)

    def wrap(m: bytes) -> bytes:        # PDU without TPKT + COTP DT header
        return _cotp(_records(ch, max(1, len(m) - 7))) if m else b""

    exchanges = [tuple(pairs[0]), init]
    exchanges += [(_cotp(c), _cotp(r)) for c, r in hs]
    exchanges += [(wrap(c), wrap(r)) for c, r in pairs[1:]]
    exchanges.append((_cotp(ch.close_notify()), _cotp(ch.close_notify())))
    return _tcp_flow(ep, sport, 102, exchanges, idle_from=2 + len(hs))


# ---------------------------------------------------------------------------
# OPC UA SignAndEncrypt (Basic256Sha256)
# ---------------------------------------------------------------------------
B256SHA256 = b"http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
_RSA_SHA256 = b"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"


def _ua_string(b: bytes) -> bytes:
    return struct.pack("<i", len(b)) + b


def opcua_certificates(ep: Endpoints) -> Tuple[bytes, bytes]:
    """(server, client) self-signed application instance certificates:
    subject CN = application name, O = organisation, DC = host; SAN = the
    application URI + DNS name; serverAuth + clientAuth; digitalSignature,
    nonRepudiation, keyEncipherment, dataEncipherment."""
    host = str(ep.meta.get("host", ep.server_ip))
    client = str(ep.meta.get("nbname", ep.client_ip))
    org = str(ep.meta.get("opcua_org", "TGT"))
    out = []
    for fqdn, uri, name in (
            (_server_cn(ep),
             str(ep.meta.get("opcua_app_uri", f"urn:{host}:UA:Server")),
             str(ep.meta.get("opcua_app_name", f"{host} OPC UA Server"))),
            (_client_cn(ep), f"urn:{client}:UA:Client",
             f"{client} OPC UA Client")):
        subj = (("DC", fqdn), ("O", org), ("CN", name))
        out.append(tls.certificate(
            name, tls._Rand("cert", uri), issuer=subj, subject=subj,
            san=((0x86, uri), (0x82, fqdn)),
            eku=(tls.SERVER_AUTH, tls.CLIENT_AUTH), key_usage=b"\x04\xf0"))
    return out[0], out[1]


def opcua_sign_encrypt_flow(ep: Endpoints, count: int) -> List[bytes]:
    """OPC UA (4840) secured with Basic256Sha256 / SignAndEncrypt: the same
    session as ``opcua`` (GetEndpoints, Create/ActivateSession, Reads,
    CloseSession, CloseSecureChannel) with Hello / Acknowledge in clear,
    OpenSecureChannel under the asymmetric security header — sender
    certificate and receiver thumbprint visible, body RSA-OAEP encrypted
    (214-byte blocks to 256) and signed — and every later chunk under the
    symmetric header with an AES-CBC body (16-byte blocks) carrying the
    32-byte HMAC-SHA256 signature."""
    msgs = [(frm, d) for kind, frm, d in
            _messages(_profile("opcua").build(ep, count), ep)
            if kind == "tcp"]
    sport = _sport()
    rnd = tls._Rand("opcua", *_seed(ep, sport, "opcua-sign-encrypt"))
    scert, ccert = opcua_certificates(ep)
    thumb = {True: hashlib.sha1(scert).digest(),
             False: hashlib.sha1(ccert).digest()}
    sent = {True: 0, False: 0}
    out: List[Tuple[bool, bytes]] = []
    for frm, d in msgs:
        kind = d[:3]
        n = sent[frm]
        sent[frm] += 1
        if kind in (b"HEL", b"ACK"):
            out.append((frm, d))
            continue
        if kind == b"OPN":
            chan = struct.unpack_from("<I", d, 8)[0]
            pol = struct.unpack_from("<i", d, 12)[0]
            # sequence header + body, plus the 32-byte nonce SignAndEncrypt
            # adds to the request / response
            inner = len(d) - (16 + pol + 8) + 32
            size = -(-(inner + 1 + 256) // 214) * 256
            body = struct.pack("<I", chan) + _ua_string(B256SHA256) + \
                _ua_string(ccert if frm else scert) + \
                _ua_string(thumb[frm]) + rnd.bytes(size)
            out.append((frm, b"OPNF" + struct.pack("<I", 8 + len(body)) +
                        body))
            continue
        chan, token = struct.unpack_from("<II", d, 8)
        inner = len(d) - 16
        if frm and n == 3:            # CreateSession: client certificate
            inner += len(ccert)
        elif (frm and n == 4) or (not frm and n == 3):
            # ActivateSession client signature / CreateSession server one
            inner += len(_RSA_SHA256) + 256
        size = -(-(inner + 1 + 32) // 16) * 16
        out.append((frm, kind + b"F" + struct.pack("<I", 16 + size) +
                    struct.pack("<II", chan, token) + rnd.bytes(size)))
    return _tcp_flow(ep, sport, 4840, [tuple(p) for p in _pairs(out)])


# ===========================================================================
# Registry
# ===========================================================================
_reg("enip-tls", "CIP Security EtherNet/IP (TLS)", "OT", "2221", "tcp",
     enip_tls_flow, "TLS 1.2 mutual auth; RegisterSession + CIP polls "
     "as records")
_reg("enip-dtls", "CIP Security class-1 I/O (DTLS)", "OT", "2221", "udp",
     enip_dtls_flow, "Forward_Open over TLS, DTLS 1.2 cookie handshake, "
     "cyclic I/O records")
_reg("s7plus-tls", "S7CommPlus over TLS (S7-1500)", "OT", "102", "tcp",
     s7plus_tls_flow, "COTP + InitSsl in clear, then TLS 1.3 in COTP DT")
_reg("opcua-sign-encrypt", "OPC UA SignAndEncrypt", "OT", "4840", "tcp",
     opcua_sign_encrypt_flow, "Basic256Sha256 OPN with certificates, "
     "encrypted MSG chunks")
_reg("iec104-tls", "IEC 104 over TLS (62351-3)", "OT", "19998", "tcp",
     iec104_tls_flow, "TLS 1.2 mutual auth; STARTDT/GI/spontaneous "
     "as records")
_reg("dnp3-tls", "DNP3 over TLS (62351-3)", "OT", "19999", "tcp",
     dnp3_tls_flow, "TLS 1.2 mutual auth; class polls + unsolicited "
     "as records")
_reg("modbus-sec", "Modbus/TCP Security", "OT", "802", "tcp",
     modbus_sec_flow, "TLS 1.2, client certificate with Modbus role "
     "extension")
