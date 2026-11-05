"""Serial-to-Ethernet gateways and IIoT: field devices a monitor only sees
through a gateway.

Imported from the bottom of :mod:`tgt.protocols`, which owns the registry.

* ``modbus-rtu-tcp`` Modbus RTU frames (slave id, PDU, CRC-16/Modbus
  little-endian — no MBAP header) carried raw over TCP to a device server in
  TCP-server mode: Moxa NPort numbering, serial port *N* listens on
  4000 + *N* (4001 for port 1). The SCADA master polls each slave on the
  RS-485 drop in turn (FC 3/4/1/2, an FC 6 setpoint write one poll in eight,
  an exception 0x83/0x02 one in sixteen). Wireshark: decode-as ``mbrtu``.
* ``dnp3-serial``    DNP3 serial link frames (0x0564 header, CRC per block —
  byte-identical to the serial line) through the same raw TCP port: class
  0/1/2/3 polls of each outstation on the multidrop line in turn, no
  unsolicited (a multidrop line runs polled). Wireshark: decode-as ``dnp3``.
* ``realcom``        Moxa RealCOM data channel (TCP 950 + *N* - 1): the host
  driver's virtual COM port; carries the raw serial bytes (Modbus RTU, or
  DNP3 frames when the devices behind the port speak DNP3).
* ``realcom-cmd``    RealCOM command channel (TCP 966 + *N* - 1): the driver
  opens the port (ASPP PORT_INIT: baud index, 8N1 mode, DTR/RTS, flow
  control) and then answers the device server's keep-alive POLLING with
  ALIVE. Signature-level: the ``[command, length, data]`` framing and the
  command codes (PORT_INIT 0x2C, POLLING 0x27, ALIVE 0x28) follow Moxa's
  published Linux driver; the PORT_INIT reply contents are representative.
  No Wireshark dissector (TCP data).
* ``moxa-discovery`` Moxa device search on UDP 4800 (NPort Administrator /
  DSU): the 8-byte search request ``01 00 00 08 00 00 00 00`` to
  255.255.255.255 (unicast to a routed device) and each device's 24-byte
  reply ``81 00 00 18 ...``. Only the request and the reply header (response
  bit, length) are claimed exact; the reply body (product id, MAC, IP) is a
  representative layout. No Wireshark dissector (UDP data).
* ``bacnet-sc``      BACnet Secure Connect (ASHRAE 135 Annex AB): a node's
  WebSocket connection to its hub over TLS 1.3 on 443 — mutual TLS, then the
  HTTP Upgrade to subprotocol ``hub.bsc.bacnet.org``, BVLC-SC
  Connect-Request/Accept, a heartbeat-sized record cadence (Heartbeat-Request
  4 bytes in a masked WebSocket frame) with an occasional Encapsulated-NPDU,
  and Disconnect + close_notify at the end. Everything after the
  ClientHello/ServerHello is encrypted, so on the wire it is TLS with record
  sizes only — opaque by design; the SNI names the hub.
* ``lorawan-udp``    LoRaWAN gateway → network server, Semtech UDP packet
  forwarder protocol v2 on 1700/udp: PUSH_DATA (``rxpk`` uplinks, periodic
  ``stat``) + PUSH_ACK on the upstream socket, PULL_DATA keep-alives +
  PULL_ACK and PULL_RESP (``txpk``) + TX_ACK on the downstream socket. The
  gateway EUI is the gateway's MAC with FFFE inserted (EUI-64); each rxpk
  ``data`` is a base64 PHYPayload (MHDR, DevAddr, FCtrl, FCnt advancing per
  device, FPort, encrypted FRMPayload, MIC). Wireshark has no Semtech UDP
  dissector in 4.6 (UDP data).

Field devices behind a gateway come from the environment's
``field_devices`` (see :func:`gateway_meta`): ``ep.meta['serial_addresses']``
(Modbus slave ids / DNP3 outstation addresses / LoRaWAN DevAddrs),
``serial_port`` and the TCP port it maps to. Every builder has defaults, so
each also runs stand-alone.
"""
from __future__ import annotations

import base64
import json
import struct
import time
import zlib
from dataclasses import replace
from typing import Any, Dict, List, Tuple

from . import packet as P
from . import tls
from .packet import Endpoints
from .protocols import (TcpSession, _cycle_base, _dnp3_req, _dnp3_rsp,
                        _dnp3_time, _DNP3_EPOCH_MS, _drift, _rand32, _reg,
                        _sport, _tcp_flow)

# 2026-10-06 12:00:00 UTC, the time base used across TGT
_EPOCH_S = 1791288000

# access protocol -> serial / radio protocol of the devices behind it
# (realcom carries whatever the port's devices speak: modbus-rtu or dnp3)
VIA: Dict[str, str] = {
    "modbus-rtu-tcp": "modbus-rtu",
    "dnp3-serial": "dnp3",
    "realcom": "modbus-rtu",
    "modbus": "modbus-rtu",          # a Modbus TCP -> RTU gateway (MGate)
    "lorawan-udp": "lorawan",
}
FIELD_PROTOCOLS = ("modbus-rtu", "dnp3", "lorawan")
# conversations whose endpoint meta comes from :func:`gateway_meta`
GATEWAY_PROTOCOLS = frozenset(VIA) | {"realcom-cmd", "moxa-discovery"}
# address range per field protocol (Modbus slave id, DNP3 link address,
# LoRaWAN DevAddr)
ADDRESS_RANGE = {"modbus-rtu": (1, 247), "dnp3": (0, 65519),
                 "lorawan": (0, 0xFFFFFFFF)}


# ===========================================================================
# Environment glue: who sits behind which gateway
# ===========================================================================
def behind(env, gateway: str, via: str) -> List[Dict[str, Any]]:
    """Field devices reached through host ``gateway`` with protocol ``via``,
    by address."""
    return sorted((d for d in getattr(env, "field_devices", ()) or ()
                   if d["behind"] == gateway and d["via"] == via),
                  key=lambda d: d["address"])


def gateway_meta(env, proto: str, client, server) -> Dict[str, Any]:
    """Endpoint meta for a conversation ``client -> server`` over ``proto``
    from the environment's field devices: the addresses polled behind the
    gateway, its serial port and the TCP port that port maps to; the Moxa
    search broadcast when both ends share a segment."""
    if proto == "moxa-discovery":
        same = env.segment_or_none(client) is env.segment_or_none(server)
        meta = {"bcast": "255.255.255.255" if same else ""}
        dev = server.device
        if dev is not None and "moxa" in dev.identity:
            meta["moxa_product_id"] = dev.identity["moxa"]["product_id"]
        return meta
    if proto == "lorawan-udp":          # the gateway is the forwarder (client)
        devs = behind(env, client.name, proto)
        return {"lora_devices": [d["address"] for d in devs]} if devs else {}
    devs = behind(env, server.name,
                  "realcom" if proto == "realcom-cmd" else proto)
    if not devs:
        return {}
    if proto == "modbus":
        return {"modbus_units": [d["address"] for d in devs]}
    port = devs[0]["port"]
    meta: Dict[str, Any] = {"serial_addresses": [d["address"] for d in devs],
                            "serial_port": port,
                            "serial_protocol": devs[0]["protocol"]}
    meta.update(ports(proto, port))
    return meta


def ports(proto: str, port: int) -> Dict[str, int]:
    """TCP port meta of serial port ``port`` on a device server (Moxa
    numbering: raw TCP server 4000 + N, RealCOM data 950 + N - 1 and
    command 966 + N - 1)."""
    if proto in ("modbus-rtu-tcp", "dnp3-serial"):
        return {"serial_tcp_port": 4000 + port}
    if proto in ("realcom", "realcom-cmd"):
        return {"realcom_data_port": 950 + port - 1,
                "realcom_cmd_port": 966 + port - 1}
    return {}


def flow_dport(env, conv) -> int:
    """The TCP port a gateway conversation really uses (0 = the protocol's
    registered port)."""
    c, s, proto = conv
    if proto not in ("modbus-rtu-tcp", "dnp3-serial", "realcom",
                     "realcom-cmd"):
        return 0
    meta = gateway_meta(env, proto, env.host(c), env.host(s))
    return int(meta.get("realcom_cmd_port" if proto == "realcom-cmd" else
                        "realcom_data_port" if proto == "realcom" else
                        "serial_tcp_port", 0))


def _addresses(ep: Endpoints, default: List[int]) -> List[int]:
    return [int(a) for a in ep.meta.get("serial_addresses") or default]


# ===========================================================================
# Modbus RTU
# ===========================================================================
def crc16_modbus(data: bytes) -> int:
    """CRC-16/MODBUS (poly 0xA001 reflected, init 0xFFFF); sent low byte
    first."""
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def rtu_frame(slave: int, pdu: bytes) -> bytes:
    """A Modbus RTU ADU: slave id + PDU + CRC (little-endian)."""
    body = bytes([slave & 0xFF]) + pdu
    return body + struct.pack("<H", crc16_modbus(body))


def _mb_poll(key: str, t: int) -> Tuple[bytes, bytes]:
    """(request PDU, response PDU) of poll ``t`` of one slave: FC 3/4
    register reads of drifting process values, FC 1/2 bit reads, an FC 6
    setpoint write (echoed) one poll in eight and an exception 0x83/0x02
    (read past the register map) one in sixteen."""
    if t % 8 == 3:
        pdu = struct.pack("!BHH", 0x06, 100,
                          int(0x0200 + 32 * _drift(key + ":sp", t)))
        return pdu, pdu
    if t % 16 == 9:
        return struct.pack("!BHH", 0x03, 9000, 10), b"\x83\x02"
    if t % 8 in (5, 7):
        fc = 0x01 if t % 8 == 5 else 0x02
        return (struct.pack("!BHH", fc, 0, 16),
                struct.pack("!BB", fc, 2) +
                struct.pack("<H", (0x00A5 + t) & 0xFFFF))
    fc = 0x04 if t % 8 == 2 else 0x03
    regs = b"".join(struct.pack("!H", int(
        0x1000 + 0x80 * r + 0x40 * _drift(f"{key}:{fc}:{r}", t)))
        for r in range(10))
    return (struct.pack("!BHH", fc, 0, 10),
            struct.pack("!BB", fc, len(regs)) + regs)


def _rtu_exchanges(ep: Endpoints, count: int) -> List[Tuple[bytes, bytes]]:
    """Round-robin polls of each slave behind the port, as RTU frames."""
    units = _addresses(ep, [1])
    cb = _cycle_base(count)
    out = []
    for i in range(count):
        t = cb + i
        unit = units[t % len(units)]
        req, rsp = _mb_poll(f"rtu:{ep.server_ip}:{unit}", t // len(units))
        out.append((rtu_frame(unit, req), rtu_frame(unit, rsp)))
    return out


def modbus_rtu_tcp_flow(ep: Endpoints, count: int) -> List[bytes]:
    """Modbus RTU over raw TCP to a serial device server (port
    ``ep.meta['serial_tcp_port']``, default 4001): the master polls each
    slave in ``ep.meta['serial_addresses']`` (default [1]) in turn."""
    port = int(ep.meta.get("serial_tcp_port", 4001))
    return _tcp_flow(ep, _sport(), port, _rtu_exchanges(ep, count))


# ===========================================================================
# DNP3 serial (multidrop) through a terminal server
# ===========================================================================
def _dnp3_exchanges(ep: Endpoints, count: int) -> List[Tuple[bytes, bytes]]:
    """Class 0 integrity / class 1 / class 2+3 event polls, each outstation
    on the line in turn (no unsolicited responses on a polled multidrop
    line)."""
    outs = _addresses(ep, [int(ep.meta.get("dnp3_outstation", 1))])
    cb = _cycle_base(count)
    out = []
    for i in range(count):
        t = cb + i
        addr = outs[t % len(outs)]
        k = (t // len(outs)) % 3
        o = replace(ep, meta=dict(ep.meta, dnp3_outstation=addr))
        if k == 0:
            read = b"\x3c\x01\x06"                  # class 0, all points
            pts = b"".join(struct.pack("<Bh", 0x01, int(
                1000 * (p + 1) + 200 * _drift(f"dnp3s:{ep.server_ip}:{addr}"
                                              f":{p}", t)))
                for p in range(4))
            resp = b"\x1e\x02\x00\x00\x03" + pts   # g30v2 0..3
        elif k == 1:
            read = b"\x3c\x02\x06"                  # class 1 events
            resp = b"\x02\x02\x28\x01\x00" + struct.pack(
                "<HB", t % 8, 0x81) + _dnp3_time(_DNP3_EPOCH_MS + 1000 * t)
        else:
            read = b"\x3c\x03\x06\x3c\x04\x06"      # class 2 + 3 events
            resp = b"\x20\x02\x28\x01\x00" + struct.pack(
                "<HBh", t % 4, 0x01,
                int(1000 + 200 * _drift(f"dnp3sev:{ep.server_ip}:{addr}", t)))
        out.append((_dnp3_req(o, t, 0x01, read), _dnp3_rsp(o, t, resp)))
    return out


def dnp3_serial_flow(ep: Endpoints, count: int) -> List[bytes]:
    """DNP3 serial frames over raw TCP to a terminal server (port
    ``ep.meta['serial_tcp_port']``, default 4001): each outstation in
    ``ep.meta['serial_addresses']`` polled in turn by the master
    (``ep.meta['dnp3_master']``, default 10)."""
    port = int(ep.meta.get("serial_tcp_port", 4001))
    return _tcp_flow(ep, _sport(), port, _dnp3_exchanges(ep, count))


# ===========================================================================
# Moxa RealCOM (virtual COM port driver <-> NPort)
# ===========================================================================
ASPP_PORT_INIT = 0x2C
ASPP_POLLING = 0x27
ASPP_ALIVE = 0x28
# ASPP baud-rate index (driver table: 300 … 921600 baud); 9600 -> 6
_ASPP_BAUD = {300: 0, 600: 1, 1200: 2, 2400: 3, 4800: 4, 7200: 5, 9600: 6,
              19200: 7, 38400: 8, 57600: 9, 115200: 10, 230400: 11,
              460800: 12, 921600: 13}


def _aspp(cmd: int, data: bytes) -> bytes:
    return bytes([cmd, len(data)]) + data


def realcom_flow(ep: Endpoints, count: int) -> List[bytes]:
    """RealCOM data channel (``ep.meta['realcom_data_port']``, default 950):
    the serial bytes an application writes to its virtual COM port —
    Modbus RTU polls, or DNP3 frames when ``ep.meta['serial_protocol']`` is
    ``dnp3``."""
    port = int(ep.meta.get("realcom_data_port", 950))
    if ep.meta.get("serial_protocol") == "dnp3":
        ex = _dnp3_exchanges(ep, count)
    else:
        ex = _rtu_exchanges(ep, count)
    return _tcp_flow(ep, _sport(), port, ex)


def realcom_cmd_flow(ep: Endpoints, count: int) -> List[bytes]:
    """RealCOM command channel (``ep.meta['realcom_cmd_port']``, default
    966): PORT_INIT (``ep.meta['serial_baud']``, default 9600, 8N1, DTR+RTS
    on, no flow control) answered by the device server, then per message
    its POLLING keep-alive (sequence id) and the driver's ALIVE echo."""
    port = int(ep.meta.get("realcom_cmd_port", 966))
    baud = _ASPP_BAUD.get(int(ep.meta.get("serial_baud", 9600)), 6)
    s = TcpSession(ep, _sport(), port)
    s.handshake()
    # baud index, mode (8 data bits, 1 stop, no parity), DTR, RTS,
    # RTS/CTS, CTS/RTS, XON, XOFF
    s.request(_aspp(ASPP_PORT_INIT, bytes([baud, 0x03, 1, 1, 0, 0, 0, 0])))
    s.response(_aspp(ASPP_PORT_INIT, b"\x00\xb0\x00"))   # line/modem status
    s.delayed_ack()
    cb = _cycle_base(count)
    for i in range(count):
        poll_id = (cb + i) & 0xFF
        s.response(_aspp(ASPP_POLLING, bytes([poll_id])))
        s.request(_aspp(ASPP_ALIVE, bytes([poll_id])))
        s.delayed_ack(from_client=False)
    s.teardown()
    return s.frames


# ===========================================================================
# Moxa device search (UDP 4800)
# ===========================================================================
MOXA_SEARCH = b"\x01\x00\x00\x08\x00\x00\x00\x00"


def moxa_discovery_flow(ep: Endpoints, count: int) -> List[bytes]:
    """Moxa device search: the search request to ``ep.meta['bcast']``
    (default 255.255.255.255; unicast when empty) from the utility's port
    and the device's unicast 24-byte reply (header ``81 00 00 18``, then a
    representative body: product id ``ep.meta['moxa_product_id']``, MAC,
    IP). One search per message."""
    from .protocols_ot import _bcast_or_unicast
    pid = int(ep.meta.get("moxa_product_id", 0x5150))
    reply = (b"\x81\x00\x00\x18" + b"\x00" * 4 + struct.pack("!I", pid) +
             P.mac_to_bytes(ep.server_mac) + P.ip_to_bytes(ep.server_ip) +
             b"\x00\x00")
    sport = _sport()
    frames = []
    for i in range(max(1, count)):
        frames.append(_bcast_or_unicast(ep, sport, 4800, MOXA_SEARCH,
                                        ident=i))
        frames.append(P.udp_frame(ep, False, 4800, sport, reply, ident=i))
    return frames


# ===========================================================================
# BACnet Secure Connect (TLS 1.3 + WebSocket to the hub)
# ===========================================================================
BSC_SUBPROTOCOL = "hub.bsc.bacnet.org"
# BVLC-SC function codes (ASHRAE 135 Annex AB)
BSC_ENCAPSULATED_NPDU = 0x01
BSC_CONNECT_REQUEST = 0x06
BSC_CONNECT_ACCEPT = 0x07
BSC_DISCONNECT_REQUEST = 0x08
BSC_DISCONNECT_ACK = 0x09
BSC_HEARTBEAT_REQUEST = 0x0A
BSC_HEARTBEAT_ACK = 0x0B

# A BACnet/SC node's TLS stack (embedded, TLS 1.3 only, ECDSA certificates,
# ALPN http/1.1 for the WebSocket upgrade) and the hub's (TLS 1.3 only, no
# session tickets). Opaque after the hellos; the record sizes are the tell.
BSC_CLIENT = tls.ClientTemplate(
    "bacnet-sc", "BACnet/SC node (embedded TLS 1.3)", 0x0303,
    (0x1301, 0x1302, 0x1303),
    ("server_name", "supported_groups", "signature_algorithms", "alpn",
     "supported_versions", "psk_key_exchange_modes", "key_share"),
    record=0x0303, groups=(0x001D, 0x0017, 0x0018),
    sigalgs=(0x0403, 0x0503, 0x0804, 0x0805, 0x0401, 0x0501),
    alpn=("http/1.1",), versions=(0x0304,), key_shares=(0x001D,), sid_len=0)
BSC_HUB = tls.ServerProfile("bacnet-sc-hub", 0x0304, 0x0304, (),
                            (0x1301, 0x1302, 0x1303), tickets=False)


def _ws_len(n: int, masked: bool) -> int:
    """Size of a binary WebSocket frame carrying ``n`` payload bytes."""
    ext = 0 if n < 126 else 2 if n < 65536 else 8
    return 2 + ext + (4 if masked else 0) + n


def bacnet_sc_flow(ep: Endpoints, count: int) -> List[bytes]:
    """A BACnet/SC node's hub connection (443, SNI ``ep.meta['sni']``):
    TLS 1.3 with a client certificate, the WebSocket upgrade, BVLC-SC
    Connect-Request/Accept, then per message a Heartbeat-Request/ACK or —
    one in three — an Encapsulated-NPDU exchange (a confirmed request to a
    peer node and its answer, relayed by the hub), and Disconnect-Request/
    ACK + close_notify to finish."""
    sni = ep.meta.get("sni") or ep.meta.get("host", "bsc-hub.corp.local")
    sport = _sport()
    seed = (ep.client_ip, ep.server_ip, sport, "bsc")
    key = base64.b64encode(tls._Rand("ws-key", *seed).bytes(16)).decode()
    upgrade = (f"GET / HTTP/1.1\r\nHost: {sni}\r\nUpgrade: websocket\r\n"
               f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
               f"Sec-WebSocket-Version: 13\r\n"
               f"Sec-WebSocket-Protocol: {BSC_SUBPROTOCOL}\r\n\r\n")
    accept = base64.b64encode(tls._Rand("ws-acc", *seed).bytes(20)).decode()
    switched = ("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                f"Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n"
                f"Sec-WebSocket-Protocol: {BSC_SUBPROTOCOL}\r\n\r\n")
    tpl = replace(BSC_CLIENT, upload=(len(upgrade), len(upgrade)),
                  download=(len(switched), len(switched)))
    exchanges, hs = tls.session(tpl, BSC_HUB, sni, 1, seed)
    rnd = tls._Rand("bsc-app", *seed)
    cs = 0x1301

    def rec(n: int) -> bytes:          # one TLS 1.3 application_data record
        return tls._record(23, 0x0303, tls._sealed(cs, 0x0304, n, rnd))

    if len(exchanges) > hs:
        # mutual TLS: the node's Certificate + CertificateVerify precede its
        # Finished (in front of the upgrade request)
        fin, rsp = exchanges[hs]
        k = 6 if fin[:1] == b"\x14" else 0          # after a compat CCS
        exchanges[hs] = (fin[:k] + rec(4 + 3 + 3 + 470 + 2 + 4 + 4 + 72) +
                         fin[k:], rsp)
    # Connect-Request / Connect-Accept: 4-byte header + VMAC(6) + device
    # UUID(16) + max BVLC length(2) + max NPDU length(2)
    exchanges.append((rec(_ws_len(30, True)), rec(_ws_len(30, False))))
    cb = _cycle_base(count)
    for i in range(count):
        t = cb + i
        if t % 3 == 2:
            # Encapsulated-NPDU to a peer (dest VMAC) and its answer (orig
            # VMAC): a ReadProperty / ComplexACK-sized APDU
            n = 4 + 6 + 2 + 13 + (t % 4)
            exchanges.append((rec(_ws_len(n, True)),
                              rec(_ws_len(n + 7, False))))
        else:
            exchanges.append((rec(_ws_len(4, True)), rec(_ws_len(4, False))))
    close = tls._record(23, 0x0303, tls._sealed(cs, 0x0304, 2, rnd))
    exchanges.append((rec(_ws_len(4, True)) + close,
                      rec(_ws_len(4, False)) + close))
    return _tcp_flow(ep, sport, 443, exchanges, idle_from=hs + 1)


# ===========================================================================
# LoRaWAN — Semtech UDP packet forwarder (1700/udp)
# ===========================================================================
LORA_VERSION = 2
PUSH_DATA, PUSH_ACK, PULL_DATA, PULL_RESP, PULL_ACK, TX_ACK = range(6)
# EU868 uplink channels (MHz) and the data rates a fleet settles on
_EU868 = (868.1, 868.3, 868.5, 867.1, 867.3, 867.5, 867.7, 867.9)
_DATR = ("SF7BW125", "SF8BW125", "SF9BW125", "SF10BW125")
_DEFAULT_DEVADDRS = (0x26011BDA, 0x26011C3F, 0x260B4F21)


def gateway_eui(mac: str) -> bytes:
    """EUI-64 of a packet forwarder from its MAC (FFFE inserted)."""
    b = P.mac_to_bytes(mac)
    return b[:3] + b"\xff\xfe" + b[3:]


def _token() -> int:
    """A random 16-bit token, its low byte kept above 0x10. Wireshark maps
    1700/udp to RADIUS (CoA), whose length field overlaps token-low +
    identifier: a value over 4096 (the RADIUS maximum) makes it decline the
    datagram, anything in 20..4096 decodes as a malformed RADIUS packet.
    Tokens are random, so this only skips a sliver of them."""
    tok = _rand32() & 0xFFFF
    return tok if tok & 0xFF > 0x10 else tok | 0x80


def _phy(mhdr: int, devaddr: int, fctrl: int, fcnt: int, fport, payload_len,
         rnd_key: str) -> bytes:
    """LoRaWAN 1.0.x PHYPayload: MHDR | DevAddr | FCtrl | FCnt | [FPort |
    FRMPayload] | MIC (FRMPayload and MIC pseudo-random: encrypted /
    keyed)."""
    body = struct.pack("<BIBH", mhdr, devaddr, fctrl, fcnt & 0xFFFF)
    if fport is not None:
        body += bytes([fport]) + tls._Rand("frm", rnd_key).bytes(payload_len)
    return body + tls._Rand("mic", rnd_key).bytes(4)


def _acks_before(t: int, k: int, n: int) -> int:
    """FCntDown of device ``k`` (of ``n``) at message ``t``: how many of its
    earlier uplinks were confirmed (and so answered by an ACK downlink)."""
    period = 8 * n
    hits = [x for x in range(period) if x % 8 == 5 and x % n == k]
    return (t // period) * len(hits) + sum(1 for x in hits if x < t % period)


def _iso(t: float) -> str:
    us = int(round((t % 1) * 1e6))
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(int(t))) + \
        f".{us:06d}Z"


def _js(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode()


def lorawan_udp_flow(ep: Endpoints, count: int) -> List[bytes]:
    """A LoRaWAN gateway's packet forwarder (client) and its network server
    (1700/udp). Per message: an uplink from the next end device in
    ``ep.meta['lora_devices']`` (DevAddrs; FCnt advances per device) as a
    PUSH_DATA ``rxpk`` + PUSH_ACK; every third a PULL_DATA keep-alive +
    PULL_ACK on the downstream socket; every fourth a ``stat`` report; one
    uplink in eight is confirmed and answered by a PULL_RESP ``txpk`` (RX1,
    1 s later, ACK bit set) that the gateway acknowledges with TX_ACK.
    ``ep.meta['lora_gw_eui']`` (16 hex digits) overrides the EUI derived
    from the gateway's MAC."""
    eui = bytes.fromhex(str(ep.meta["lora_gw_eui"])) \
        if ep.meta.get("lora_gw_eui") else gateway_eui(ep.client_mac)
    devs = [int(d) for d in ep.meta.get("lora_devices") or _DEFAULT_DEVADDRS]
    up, down = _sport(), _sport()
    cb = _cycle_base(count)
    frames: List[bytes] = []
    gw = zlib.crc32(eui)

    def tx(from_gw: bool, sock: int, payload: bytes) -> None:
        frames.append(P.udp_frame(ep, True, sock, 1700, payload) if from_gw
                      else P.udp_frame(ep, False, 1700, sock, payload))

    for i in range(max(1, count)):
        t = cb + i
        now = _EPOCH_S + 37.0 * t + (gw % 1000) / 1000.0
        tmst = (gw + int(37e6 * t)) & 0xFFFFFFFF          # µs counter
        if t % 3 == 0:
            tok = _token()
            tx(True, down, struct.pack("!BHB", LORA_VERSION, tok, PULL_DATA)
               + eui)
            tx(False, down, struct.pack("!BHB", LORA_VERSION, tok, PULL_ACK))
        k = t % len(devs)
        devaddr, fcnt = devs[k], t // len(devs)
        confirmed = t % 8 == 5
        size = 10 + (devaddr % 5)
        phy = _phy(0x80 if confirmed else 0x40, devaddr, 0x80, fcnt,
                   1 + devaddr % 100, size, f"{devaddr}:{fcnt}")
        chan = (devaddr + fcnt) % len(_EU868)
        datr = _DATR[devaddr % len(_DATR)]
        rssi = -60 - (devaddr % 50) + int(4 * _drift(f"rssi:{devaddr}", t))
        lsnr = round(9.5 - (devaddr % 50) / 5 + _drift(f"snr:{devaddr}", t),
                     1)
        rxpk = {"tmst": tmst, "time": _iso(now), "chan": chan, "rfch":
                0 if chan < 3 else 1, "freq": _EU868[chan], "stat": 1,
                "modu": "LORA", "datr": datr, "codr": "4/5", "rssi": rssi,
                "lsnr": lsnr, "size": len(phy),
                "data": base64.b64encode(phy).decode()}
        tok = _token()
        tx(True, up, struct.pack("!BHB", LORA_VERSION, tok, PUSH_DATA) + eui
           + _js({"rxpk": [rxpk]}))
        tx(False, up, struct.pack("!BHB", LORA_VERSION, tok, PUSH_ACK))
        if t % 4 == 1:
            n = 4 + t // 4
            stat = {"time": time.strftime("%Y-%m-%d %H:%M:%S GMT",
                                          time.gmtime(int(now) + 2)),
                    "rxnb": n, "rxok": n, "rxfw": n, "ackr": 100.0,
                    "dwnb": t // 8, "txnb": t // 8}
            tok = _token()
            tx(True, up, struct.pack("!BHB", LORA_VERSION, tok, PUSH_DATA)
               + eui + _js({"stat": stat}))
            tx(False, up, struct.pack("!BHB", LORA_VERSION, tok, PUSH_ACK))
        if confirmed:
            down_phy = _phy(0x60, devaddr, 0x20,
                            _acks_before(t, k, len(devs)), None, 0,
                            f"dn:{devaddr}:{t}")
            txpk = {"imme": False, "tmst": (tmst + 1000000) & 0xFFFFFFFF,
                    "freq": _EU868[chan], "rfch": 0, "powe": 14,
                    "modu": "LORA", "datr": datr, "codr": "4/5",
                    "ipol": True, "size": len(down_phy),
                    "data": base64.b64encode(down_phy).decode()}
            tok = _token()
            tx(False, down, struct.pack("!BHB", LORA_VERSION, tok, PULL_RESP)
               + _js({"txpk": txpk}))
            tx(True, down, struct.pack("!BHB", LORA_VERSION, tok, TX_ACK) +
               eui + _js({"txpk_ack": {"error": "NONE"}}))
    return frames


# ===========================================================================
# Registry
# ===========================================================================
_reg("modbus-rtu-tcp", "Modbus RTU over TCP (serial gateway)", "OT", "4001",
     "tcp", modbus_rtu_tcp_flow,
     "RTU frames (slave id + CRC-16) raw over TCP to a device server, "
     "slaves polled in turn")
_reg("dnp3-serial", "DNP3 serial via terminal server", "OT", "4001", "tcp",
     dnp3_serial_flow,
     "DNP3 serial link frames over raw TCP 4000+N, multidrop outstations "
     "polled in turn")
_reg("realcom", "Moxa RealCOM data channel", "OT", "950", "tcp", realcom_flow,
     "Virtual COM port data (Modbus RTU / DNP3 serial bytes) to an NPort")
_reg("realcom-cmd", "Moxa RealCOM command channel", "OT", "966", "tcp",
     realcom_cmd_flow,
     "ASPP PORT_INIT (baud, mode, DTR/RTS) + POLLING / ALIVE keep-alives")
_reg("moxa-discovery", "Moxa device search", "OT", "4800", "udp",
     moxa_discovery_flow,
     "NPort Administrator search broadcast (01 00 00 08) + 24-byte replies")
_reg("bacnet-sc", "BACnet Secure Connect", "OT", "443", "tcp", bacnet_sc_flow,
     "TLS 1.3 + WebSocket to the hub: connect, heartbeats, encapsulated "
     "NPDUs (opaque)")
_reg("lorawan-udp", "LoRaWAN Semtech UDP forwarder", "OT", "1700", "udp",
     lorawan_udp_flow,
     "PUSH_DATA rxpk/stat, PULL_DATA keep-alives, PULL_RESP txpk + TX_ACK")
