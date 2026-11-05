"""CODESYS V3 runtime protocol (issue #49): an engineering station's gateway
talking to CODESYS-based controllers (WAGO PFC, Schneider Modicon M2xx,
Eaton XC300 ...).

Two registry profiles:

* ``codesys-disc`` (UDP 1740) — the gateway's network scan: a name-service
  NameResolve broadcast from the engineering station's UDP block driver and
  each runtime's DeviceInfo reply (node name, device name, vendor name,
  firmware, serial);
* ``codesys`` (TCP 11740) — an online session: the same DeviceInfo
  identification over the TCP block driver, open channel, device login,
  application login, a project-information read, periodic monitoring reads
  (with channel keep-alives), application / device logout, close channel.

Layering (every multi-byte field little-endian unless noted), as described
by Kaspersky ICS-CERT ("Security research: CODESYS Runtime, a PLC control
framework", part 2, 2019) and implemented by Microsoft's open-source
ics-forensics-tools CodeSysV3 plugin; service / tag numbers of the device,
application and monitoring services are those of the CODESYS
``DatasourceApplicationV3`` library's ``Services`` constants:

* block driver — TCP only: magic ``00 01 17 e8`` (u32 0xE8170100) and the
  total PDU length including these 8 bytes (<= 520). UDP carries the
  datagram directly; the port (1740 + index 0..3) is part of the address.
* datagram (router) layer — 0xC5, hop info (hop count 13 << 3 | header
  length 3 words), packet info (priority normal << 6), service id (0x03
  name-service server, 0x04 name-service client, 0x40 channel manager),
  message id, address lengths in 16-bit words (receiver in the low nibble,
  as Microsoft's structure declares it; Kaspersky describes the opposite
  order — every PDU here except the scan request has equal lengths, so only
  that one depends on it), receiver address, sender address, zero padding to
  a 4-byte boundary (counted from the start of the block driver header).
  TCP addresses are the big-endian port + IPv4 address; UDP addresses are
  relative: port index + last octet of the address.
* name service — header subcmd / version (0x0400) / message id; the
  DeviceInfo reply (subcmd 0xC280) is Microsoft's ``NsClientDeviceInfo``
  layout, then UTF-16LE node / device / vendor names (each NUL-terminated)
  and the ASCII serial number. The four firmware bytes are stored least
  significant first. ``max_channels``, ``byte_order``, the target type / id
  values and the 11 bytes between the fixed fields and the names are
  representative (opaque).
* channel layer — open channel (0xC3 / reply 0x83, CRC-32 over the header),
  application blocks (0x01: flags bit 7 = request, bit 0 = first block,
  channel id, block id, ack id, then on a first block the remaining data
  size + CRC-32 of the service message), block acks (0x02), keep-alive
  (0x03) and close channel (0xC4, no reply). Ack / keep-alive flags (0) are
  representative.
* services layer — protocol id 0xCD55 (plain tags), header size 12,
  service group (bit 7 set on replies), service id, session id, content
  size; then tags: base-128 id and size, header padded to 4 bytes with
  continuation bytes, ids >= 0x80 hold child tags. Used here: device login
  (group 1 / service 2: crypt type 0x22, challenge 0x23, credentials 0x81
  {user 0x10, password 0x11}; reply 0x82 {result 0x20, setting flags 0x24,
  session id 0x21}), device logout (1/3), application login / logout (2/1,
  2/2: 0x81 {application name 0x01}; reply 0x81 {result 0x10, application
  id 0x11}) and Monitoring2 read (0x1B/1: application header 0x01, read
  expression list 0x02; reply value list 0x40). The project-information read
  (application group, service 0x26) and the content of the expression list,
  value list, password hash and project-info tags are representative
  (opaque); no encryption (the secure protocol id 0x7557) is modelled.

Stock Wireshark has no CODESYS V3 dissector, so frames decode as plain
TCP / UDP; :func:`decode` parses the headers back for the self-tests.
Identity comes from ``ep.meta``: ``codesys_node``, ``codesys_device``,
``codesys_vendor``, ``codesys_firmware``, ``codesys_serial``,
``codesys_target_type``, ``codesys_target_id`` (filled by
:func:`tgt.devices.identity_meta` for catalog models with a ``codesys``
identity), then ``host`` / ``model`` / ``vendor`` / ``firmware``; plus
``codesys_user``, ``codesys_app`` and ``codesys_project``.
"""
from __future__ import annotations

import re
import struct
import zlib
from typing import Dict, List, Optional, Tuple

from . import packet as P
from .packet import Endpoints
from .protocols import TcpSession, _cycle_base, _drift, _rand32, _reg, _sport
from .protocols_ot import _bcast_or_unicast

TCP_PORT = 11740                 # CmpBlkDrvTcp (11740-11743)
UDP_PORT = 1740                  # CmpBlkDrvUdp (1740-1743, port index 0-3)
TCP_MAGIC = struct.pack("<I", 0xE8170100)     # on the wire: 00 01 17 e8
MAX_PDU = 512                    # datagram layer bytes per block-driver PDU
DG_MAGIC = 0xC5

# datagram-layer services
DG_NS_SERVER, DG_NS_CLIENT, DG_CHANNEL = 0x03, 0x04, 0x40
# name-service sub-commands
NS_NAME_RESOLVE, NS_DEVICE_INFO = 0xC202, 0xC280
NS_VERSION = 0x0400
# channel-layer packet types
CH_BLK, CH_ACK, CH_KEEPALIVE = 0x01, 0x02, 0x03
CH_OPEN, CH_CLOSE, CH_OPEN_RSP = 0xC3, 0xC4, 0x83
# services layer
SVC_PROTOCOL = 0xCD55
SG_DEVICE, SG_APP, SG_MON2 = 0x01, 0x02, 0x1B
SRV_DEV_LOGIN, SRV_DEV_LOGOUT = 0x02, 0x03
SRV_APP_LOGIN, SRV_APP_LOGOUT = 0x01, 0x02
SRV_APP_PROJECT_INFO = 0x26      # representative
SRV_MON2_READ = 0x01

_NS_FIXED = struct.Struct("<HHIHBBHHHHHHI4sIB")   # NsClientDeviceInfo, 37 B
_NS_NAMES_AT = 48                 # names start 48 B after the NS header


# ---------------------------------------------------------------------------
# Encoders
# ---------------------------------------------------------------------------
def _varint(n: int) -> bytes:
    """Little-endian base-128 (tag ids and sizes)."""
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def tag(tid: int, data: bytes = b"", align: int = 0x40) -> bytes:
    """One services-layer tag: id, size (header padded with continuation
    bytes until its length modulo ``align >> 4`` is ``align & 0xF``), data."""
    hdr = bytearray(_varint(tid) + _varint(len(data)))
    mod, rem = align >> 4, align & 0x0F
    while len(hdr) % mod != rem:
        hdr[-1] |= 0x80
        hdr.append(0x00)
    return bytes(hdr) + data


def _cstr(s: str) -> bytes:
    return s.encode("latin-1", "replace") + b"\x00"


def service(group: int, sid: int, session: int, body: bytes,
            reply: bool = False) -> bytes:
    """Services-layer message: 16-byte header (protocol id 0xCD55, header
    size 12, group | 0x80 on replies, service, session id, content size)."""
    return struct.pack("<HHHHII", SVC_PROTOCOL, 12,
                       group | (0x80 if reply else 0), sid,
                       session & 0xFFFFFFFF, len(body)) + body


def datagram(svc: int, receiver: bytes, sender: bytes, payload: bytes,
             pre: int = 0, msg_id: int = 0) -> bytes:
    """Datagram (router) layer; ``pre`` = bytes in front of it (the 8-byte
    TCP block driver header) for the 4-byte alignment of the payload."""
    hdr = bytes([DG_MAGIC, (13 << 3) | 3, 1 << 6, svc, msg_id & 0xFF,
                 (len(sender) // 2) << 4 | (len(receiver) // 2)])
    head = hdr + receiver + sender
    return head + bytes(-(pre + len(head)) % 4) + payload


def block_tcp(dg: bytes) -> bytes:
    """TCP block driver: magic + total length (incl. these 8 bytes)."""
    return TCP_MAGIC + struct.pack("<I", 8 + len(dg)) + dg


def tcp_addr(ip: str, port: int) -> bytes:
    return struct.pack(">H", port) + P.ip_to_bytes(ip)


def udp_addr(ip: str, port: int = UDP_PORT) -> bytes:
    return bytes([(port - UDP_PORT) & 0x03, P.ip_to_bytes(ip)[3]])


def ns_request(msg_id: int) -> bytes:
    return struct.pack("<HHI", NS_NAME_RESOLVE, NS_VERSION,
                       msg_id & 0xFFFFFFFF)


def _fw_bytes(firmware: str) -> bytes:
    """'04.02.13(24)' / 'V3.5.19.30' -> 4 bytes, least significant first."""
    parts = [int(x) & 0xFF for x in re.findall(r"\d+", firmware)][:4]
    parts += [0] * (4 - len(parts))
    return bytes(reversed(parts))


def ns_device_info(msg_id: int, node: str, device: str, vendor: str,
                   firmware: str, serial: str, target_type: int = 0x1006,
                   target_id: int = 0x0001, max_channels: int = 4) -> bytes:
    fixed = _NS_FIXED.pack(
        NS_DEVICE_INFO, NS_VERSION, msg_id & 0xFFFFFFFF, max_channels, 1, 0,
        0, len(node), len(device), len(vendor), target_type & 0xFFFF,
        target_id & 0xFFFF, 0, _fw_bytes(firmware), 0,
        len(serial.encode("ascii", "replace")) & 0xFF)
    names = b"".join(s.encode("utf-16-le") + b"\x00\x00"
                     for s in (node, device, vendor))
    return fixed + bytes(_NS_NAMES_AT - len(fixed)) + names + \
        serial.encode("ascii", "replace")[:255]


def _crc_hdr(fmt: str, *fields) -> bytes:
    """Channel-manager header whose CRC-32 (4th field) covers the header
    with the CRC field zeroed."""
    raw = struct.pack(fmt, *fields)
    crc = zlib.crc32(raw) & 0xFFFFFFFF
    return raw[:4] + struct.pack("<I", crc) + raw[8:]


def open_channel(msg_id: int, buf: int = 0x001F4000) -> bytes:
    return _crc_hdr("<BBHIIII", CH_OPEN, 0, 0x0101, 0, msg_id & 0xFFFFFFFF,
                    buf, 5)


def open_channel_reply(msg_id: int, channel: int,
                       buf: int = 0x001F4000) -> bytes:
    return _crc_hdr("<BBHIIHHII", CH_OPEN_RSP, 0, 0x0101, 0,
                    msg_id & 0xFFFFFFFF, 0, channel, buf, 5)


def close_channel(channel: int) -> bytes:
    return _crc_hdr("<BBHIHH", CH_CLOSE, 0, 0x0101, 0, channel, 0)


def blocks(channel: int, blk_id: int, ack_id: int, msg: bytes,
           request: bool, room: int) -> List[bytes]:
    """Application blocks carrying one services-layer message: the first
    with the total size + CRC-32, the rest with the 12-byte header."""
    req = 0x80 if request else 0x00
    first = room - 20
    out = [struct.pack("<BBHIIII", CH_BLK, req | 0x01, channel, blk_id,
                       ack_id, len(msg), zlib.crc32(msg) & 0xFFFFFFFF) +
           msg[:first]]
    off = first
    while off < len(msg):
        blk_id += 1
        out.append(struct.pack("<BBHII", CH_BLK, req, channel, blk_id,
                               ack_id) + msg[off:off + room - 12])
        off += room - 12
    return out


def ack(channel: int, blk_id: int) -> bytes:
    return struct.pack("<BBHI", CH_ACK, 0, channel, blk_id)


def keepalive(channel: int) -> bytes:
    return struct.pack("<BBH", CH_KEEPALIVE, 0, channel)


# ---------------------------------------------------------------------------
# Decoder (self-tests / round trip)
# ---------------------------------------------------------------------------
def _read_varint(b: bytes, i: int) -> Tuple[int, int]:
    v = shift = 0
    while True:
        c = b[i]
        i += 1
        v |= (c & 0x7F) << shift
        shift += 7
        if not c & 0x80:
            return v, i


def parse_tags(b: bytes) -> List[Tuple[int, object]]:
    """[(id, data or child list)] of a services-layer tag body."""
    out: List[Tuple[int, object]] = []
    i = 0
    while i < len(b):
        tid, i = _read_varint(b, i)
        size, i = _read_varint(b, i)
        data = b[i:i + size]
        if len(data) != size:
            raise ValueError("tag overruns its message")
        i += size
        out.append((tid, parse_tags(data) if tid >= 0x80 else data))
    return out


def decode(pl: bytes, tcp: bool = True) -> Dict:
    """Parse a UDP datagram / TCP block-driver PDU back into its fields.
    Raises ValueError on a malformed header."""
    d: Dict = {}
    i = 0
    if tcp:
        if pl[:4] != TCP_MAGIC:
            raise ValueError("bad block driver magic")
        d["length"] = struct.unpack("<I", pl[4:8])[0]
        if d["length"] != len(pl) or d["length"] > MAX_PDU + 8:
            raise ValueError("block driver length mismatch")
        i = 8
    if pl[i] != DG_MAGIC:
        raise ValueError("bad datagram magic")
    d["hop_count"], d["hdr_words"] = pl[i + 1] >> 3, pl[i + 1] & 7
    d["priority"] = pl[i + 2] >> 6
    d["service"], d["msg_id"] = pl[i + 3], pl[i + 4]
    rl, sl = (pl[i + 5] & 0x0F) * 2, (pl[i + 5] >> 4) * 2
    j = i + 2 * d["hdr_words"]
    d["receiver"], d["sender"] = pl[j:j + rl], pl[j + rl:j + rl + sl]
    j += rl + sl
    j += -j % 4
    body = pl[j:]
    if d["service"] in (DG_NS_SERVER, DG_NS_CLIENT):
        d["ns_subcmd"], d["ns_version"], d["ns_msg_id"] = \
            struct.unpack("<HHI", body[:8])
        if d["ns_subcmd"] == NS_DEVICE_INFO:
            f = _NS_FIXED.unpack(body[:_NS_FIXED.size])
            k = _NS_NAMES_AT + f[6]
            for name, n in (("node", f[7]), ("device", f[8]),
                            ("vendor", f[9])):
                d[name] = body[k:k + 2 * n].decode("utf-16-le")
                k += 2 * (n + 1)
            fw = f[13]
            d["firmware"] = ".".join(str(x) for x in reversed(fw))
            d["serial"] = body[k:k + f[15]].decode("ascii")
            d["target_type"], d["target_id"] = f[10], f[11]
            if k + f[15] != len(body):
                raise ValueError("device info length mismatch")
        return d
    if d["service"] != DG_CHANNEL:
        raise ValueError("unknown datagram service")
    t = body[0]
    d["ch_type"] = t
    if t in (CH_OPEN, CH_OPEN_RSP, CH_CLOSE):
        crc = struct.unpack("<I", body[4:8])[0]
        if zlib.crc32(body[:4] + bytes(4) + body[8:]) & 0xFFFFFFFF != crc:
            raise ValueError("channel header CRC mismatch")
        if t == CH_OPEN_RSP:
            d["msg_id_ch"], _, d["channel"] = struct.unpack(
                "<IHH", body[8:16])
        elif t == CH_CLOSE:
            d["channel"] = struct.unpack("<H", body[8:10])[0]
        else:
            d["msg_id_ch"] = struct.unpack("<I", body[8:12])[0]
    elif t == CH_BLK:
        d["flags"] = body[1]
        d["channel"], d["blk_id"], d["ack_id"] = struct.unpack(
            "<HII", body[2:12])
        if body[1] & 0x01:
            d["size"], d["crc"] = struct.unpack("<II", body[12:20])
            d["data"] = body[20:]
        else:
            d["data"] = body[12:]
    elif t == CH_ACK:
        d["channel"], d["blk_id"] = struct.unpack("<HI", body[2:8])
    elif t == CH_KEEPALIVE:
        d["channel"] = struct.unpack("<H", body[2:4])[0]
    else:
        raise ValueError("unknown channel packet type")
    return d


def decode_service(msg: bytes) -> Dict:
    """Services-layer header + tags of a reassembled message."""
    proto, hsize, group, sid, session, size = struct.unpack(
        "<HHHHII", msg[:16])
    if proto != SVC_PROTOCOL or hsize != 12 or size != len(msg) - 16:
        raise ValueError("bad services header")
    return {"group": group & 0x7F, "reply": bool(group & 0x80), "sid": sid,
            "session": session, "tags": parse_tags(msg[16:])}


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------
def _meta(ep: Endpoints, *keys: str, default=None):
    for k in keys:
        v = ep.meta.get(k)
        if v not in (None, ""):
            return v
    return default


def identity(ep: Endpoints) -> Dict:
    """Identity strings the runtime reports in its DeviceInfo reply."""
    return {
        "node": str(_meta(ep, "codesys_node", "host", default="PLC01"))[:64],
        "device": str(_meta(ep, "codesys_device", "model",
                            default="CODESYS Control for Linux SL"))[:64],
        "vendor": str(_meta(ep, "codesys_vendor", "vendor",
                            default="CODESYS GmbH"))[:64],
        "firmware": str(_meta(ep, "codesys_firmware", "firmware",
                              default="3.5.19.30")),
        "serial": str(_meta(ep, "codesys_serial", "serial",
                            default=""))[:64],
        "target_type": int(_meta(ep, "codesys_target_type",
                                 default=0x1006)),
        "target_id": int(_meta(ep, "codesys_target_id", default=0x0001)),
    }


def _device_info(ep: Endpoints, msg_id: int) -> bytes:
    i = identity(ep)
    return ns_device_info(msg_id, i["node"], i["device"], i["vendor"],
                          i["firmware"], i["serial"], i["target_type"],
                          i["target_id"])


def codesys_disc_flow(ep: Endpoints, count: int) -> List[bytes]:
    """Gateway network scan (UDP 1740): the engineering station's
    NameResolve broadcast to ``ep.meta['bcast']`` (default
    255.255.255.255; unicast when empty) and the runtime's DeviceInfo reply
    to the station's port — one scan, repeated up to three times."""
    frames = []
    me, peer = udp_addr(ep.client_ip), udp_addr(ep.server_ip)
    for n in range(max(1, min(3, count))):
        msg = _rand32()
        req = datagram(DG_NS_SERVER, b"", me, ns_request(msg))
        rsp = datagram(DG_NS_CLIENT, me, peer, _device_info(ep, msg))
        frames.append(_bcast_or_unicast(ep, UDP_PORT, UDP_PORT, req, ident=n))
        frames.append(P.udp_frame(ep, False, UDP_PORT, UDP_PORT, rsp,
                                  ident=n))
    return frames


class _Channel:
    """One CODESYS channel over a TCP session: block / ack numbering per
    side, datagram addressing and block-driver framing."""

    def __init__(self, s: TcpSession, ep: Endpoints):
        self.s = s
        self.addr = {True: tcp_addr(ep.client_ip, s.sport),
                     False: tcp_addr(ep.server_ip, s.dport)}
        self.channel = 0
        self.blk = {True: 0, False: 0}      # last block id sent per side

    def pdu(self, from_client: bool, svc: int, payload: bytes) -> None:
        dg = datagram(svc, self.addr[not from_client], self.addr[from_client],
                      payload, pre=8)
        data = block_tcp(dg)
        if from_client:
            self.s.request(data)
        else:
            self.s.response(data)

    def room(self) -> int:
        """Channel-layer bytes per PDU (after datagram header + padding)."""
        head = 8 + 6 + 2 * len(self.addr[True])
        return MAX_PDU - (head + -head % 4 - 8)

    def send(self, from_client: bool, msg: bytes) -> None:
        """A services message as application blocks, each acknowledged."""
        first = self.blk[from_client] + 1
        for blk in blocks(self.channel, first, self.blk[not from_client],
                          msg, from_client, self.room()):
            self.blk[from_client] = struct.unpack("<I", blk[4:8])[0]
            self.pdu(from_client, DG_CHANNEL, blk)
            self.pdu(not from_client, DG_CHANNEL,
                     ack(self.channel, self.blk[from_client]))

    def call(self, req: bytes, rsp: bytes) -> None:
        self.send(True, req)
        self.send(False, rsp)


def _mon_values(ep: Endpoints, t: int, n: int) -> bytes:
    key = f"cds|{ep.server_ip}"
    return b"".join(struct.pack("<f", round(50.0 + 20.0 * _drift(
        f"{key}|{v}", t), 2)) for v in range(n))


def codesys_flow(ep: Endpoints, count: int) -> List[bytes]:
    """Online session (TCP 11740): DeviceInfo identification, open
    channel, device login, application login, project-information read,
    ``count`` Monitoring2 reads (a keep-alive before every fourth),
    application + device logout, close channel. Meta: see the module
    docstring."""
    s = TcpSession(ep, _sport(), TCP_PORT)
    s.handshake()
    ch = _Channel(s, ep)
    # identification: name service over the TCP block driver
    msg = _rand32()
    ch.pdu(True, DG_NS_SERVER, ns_request(msg))
    ch.pdu(False, DG_NS_CLIENT, _device_info(ep, msg))
    # open channel
    msg = _rand32()
    ch.channel = 1 + _rand32() % 0xFFFE
    ch.pdu(True, DG_CHANNEL, open_channel(msg))
    ch.pdu(False, DG_CHANNEL, open_channel_reply(msg, ch.channel))
    # device login (session 0) -> session id
    user = str(_meta(ep, "codesys_user", default="admin"))
    if len(user) % 2:
        user += "\x00"
    session = _rand32() or 1
    pw_hash = struct.pack("<8I", *(_rand32() for _ in range(8)))  # opaque
    login = (tag(0x22, struct.pack("<I", 1)) +
             tag(0x23, struct.pack("<I", _rand32())) +
             tag(0x81, tag(0x10, user.encode("latin-1"), align=0x42) +
                 tag(0x11, pw_hash)))
    reply = tag(0x82, tag(0x20, struct.pack("<H", 0)) +
                tag(0x24, struct.pack("<I", 0)) +
                tag(0x21, struct.pack("<I", session)))
    ch.call(service(SG_DEVICE, SRV_DEV_LOGIN, 0, login),
            service(SG_DEVICE, SRV_DEV_LOGIN, 0, reply, reply=True))
    # application login -> application id
    app = str(_meta(ep, "codesys_app", default="Application"))
    app_id = 1 + _rand32() % 0xFFFF
    ch.call(service(SG_APP, SRV_APP_LOGIN, session,
                    tag(0x81, tag(0x01, _cstr(app)))),
            service(SG_APP, SRV_APP_LOGIN, session,
                    tag(0x81, tag(0x10, struct.pack("<H", 0)) +
                        tag(0x11, struct.pack("<I", app_id))), reply=True))
    # project information (strings as the IDE's online view shows them)
    project = str(_meta(ep, "codesys_project", default=f"{app}_Project"))
    info = (tag(0x01, _cstr(project)) +
            tag(0x02, _cstr(str(_meta(ep, "codesys_author",
                                      default="Engineering")))) +
            tag(0x03, _cstr(str(_meta(ep, "codesys_project_version",
                                      default="1.0.0.0")))) +
            tag(0x04, _cstr(f"{app} on {identity(ep)['device']}")))
    ch.call(service(SG_APP, SRV_APP_PROJECT_INFO, session,
                    tag(0x01, struct.pack("<I", app_id))),
            service(SG_APP, SRV_APP_PROJECT_INFO, session,
                    tag(0x81, info), reply=True))
    # periodic monitoring reads of a watch list of 8 variables
    nvars = 8
    explist = b"".join(struct.pack("<HHI", 0x0004, 0x0010 + v,
                                   0x2000 + 4 * v) for v in range(nvars))
    base = _cycle_base(count)
    for n in range(max(1, count)):
        if n % 4 == 3:
            ch.pdu(True, DG_CHANNEL, keepalive(ch.channel))
        ch.call(service(SG_MON2, SRV_MON2_READ, session,
                        tag(0x01, struct.pack("<II", app_id, 0)) +
                        tag(0x02, explist)),
                service(SG_MON2, SRV_MON2_READ, session,
                        tag(0x40, _mon_values(ep, base + n, nvars)),
                        reply=True))
    # logout, close
    ch.call(service(SG_APP, SRV_APP_LOGOUT, session,
                    tag(0x00, struct.pack("<I", app_id))),
            service(SG_APP, SRV_APP_LOGOUT, session,
                    tag(0x81, tag(0x10, struct.pack("<H", 0))), reply=True))
    ch.call(service(SG_DEVICE, SRV_DEV_LOGOUT, session,
                    tag(0x00, struct.pack("<I", session))),
            service(SG_DEVICE, SRV_DEV_LOGOUT, session, b"", reply=True))
    ch.pdu(True, DG_CHANNEL, close_channel(ch.channel))
    s.teardown()
    return s.frames


def session_messages(frames: List[bytes]) -> List[Tuple[bool, Dict]]:
    """Reassembled (from_client, decode_service()) messages of a
    ``codesys`` session (self-tests)."""
    out: List[Tuple[bool, Dict]] = []
    buf: Dict[bool, bytearray] = {True: bytearray(), False: bytearray()}
    want: Dict[bool, Optional[int]] = {True: None, False: None}
    for f in frames:
        ihl = (f[14] & 0x0F) * 4
        l4 = f[14 + ihl:]
        pl = l4[(l4[12] >> 4) * 4:]
        if not pl:
            continue
        fc = struct.unpack("!H", l4[2:4])[0] == TCP_PORT
        d = decode(pl)
        if d.get("ch_type") != CH_BLK:
            continue
        if d["flags"] & 0x01:
            buf[fc] = bytearray(d["data"])
            want[fc] = d["size"]
        else:
            buf[fc] += d["data"]
        if want[fc] is not None and len(buf[fc]) >= want[fc]:
            out.append((fc, decode_service(bytes(buf[fc]))))
            want[fc] = None
    return out


_reg("codesys", "CODESYS V3", "OT", "11740", "tcp", codesys_flow,
     "DeviceInfo, open channel, device/app login, project info, "
     "Monitoring2 reads (block driver 0x000117e8)")
_reg("codesys-disc", "CODESYS V3 discovery", "OT", "1740", "udp",
     codesys_disc_flow,
     "Gateway scan: NameResolve broadcast + DeviceInfo (vendor, device, "
     "firmware, serial)")
