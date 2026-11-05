"""OT device identity on the wire, and normal engineering operations.

Identity flows make an embedded device state its vendor, model, firmware and
serial in the protocol it actually speaks, so a passive monitor can inventory
it without an active scan:

* ``modbus-id``  Modbus FC 43/14 Read Device Identification (basic + regular)
* ``bacnet-id``  BACnet Who-Is / I-Am + ReadPropertyMultiple of the Device
  object (vendor-name, model-name, firmware-revision, …)
* ``enip-list``  EtherNet/IP List Identity broadcast on UDP 44818 (RSLinx-style
  browse) with unicast replies, plus List Services
* ``dnp3-id``    DNP3 device-attribute reads (group 0: manufacturer, model,
  software version, serial)

``enip-io`` adds the CIP class-1 implicit I/O a controller keeps with its
adapters and drives (Forward_Open on TCP 44818, cyclic UDP 2222).

The operations flows are the benign engineering baseline a monitor's "program
download" / "mode change" / "write" / "time set" alerts should be judged
against; environments emit them only from engineering workstations, operator
HMIs and the SCADA master, once per cycle:

* ``s7-eng``       S7 block list, block upload and a planned download of one DB
* ``enip-eng``     CIP reads of the controller's mode/status and program list
* ``modbus-write`` operator setpoint / command writes (FC 16, 5, 15)
* ``dnp3-time``    DNP3 Delay Measure + time write (g50v1)
* ``iec104-time``  IEC 104 clock synchronisation (C_CS_NA_1)

Identity values come from ``ep.meta`` (filled from the device catalog by
:func:`tgt.devices.identity_meta`); every builder has defaults so it also runs
stand-alone.
"""
from __future__ import annotations

import struct
import zlib
from typing import Dict, List

from . import packet as P
from .packet import Endpoints
from .protocols import (TcpSession, _cp56, _cpf, _dnp3_req, _dnp3_rsp,
                        _dnp3_time, _DNP3_EPOCH_MS, _enip, _enip_identity_item,
                        _enip_rr, _iec104_asdu, _iec104_i, _iec104_s,
                        _iec104_u, _reg, _s7, _s7_connect, _sport, _tcp_flow)

# Ground-truth notes for the operations profiles (``tgt inventory`` flows).
OPERATIONS: Dict[str, str] = {
    "s7-eng": "planned engineering change: S7 block list, OB1 upload and "
              "download of DB10 from the engineering workstation",
    "enip-eng": "engineering read of controller mode/status, program list "
                "and clock from the engineering workstation",
    "modbus-write": "operator setpoint and command writes from the HMI",
    "dnp3-time": "SCADA master time synchronisation (Delay Measure + "
                 "g50v1 write)",
    "iec104-time": "SCADA master clock synchronisation (C_CS_NA_1)",
}
# ... of which the engineering-workstation ones (the rest are operator / SCADA)
ENGINEERING = frozenset({"s7-eng", "enip-eng"})


def _bcast_or_unicast(ep: Endpoints, sport: int, dport: int, payload: bytes,
                      ident: int = 0) -> bytes:
    """A client UDP datagram to ``ep.meta['bcast']`` (a broadcast address,
    default 255.255.255.255, sent to MAC ff:ff:ff:ff:ff:ff) or, when that
    is empty, unicast to the server."""
    bcast = ep.meta.get("bcast", "255.255.255.255")
    if not bcast:
        return P.udp_frame(ep, True, sport, dport, payload, ident=ident)
    seg = P.udp(ep.client_ip, bcast, sport, dport, payload)
    pkt = P.ipv4(ep.client_ip, bcast, P.IPPROTO_UDP, seg,
                 ttl=ep.ttl_client, ident=ident)
    return P.ethernet("ff:ff:ff:ff:ff:ff", ep.client_mac, P.ETH_P_IP, pkt,
                      vlan=ep.vlan)


def _server_bcast(ep: Endpoints, sport: int, dport: int, payload: bytes,
                  ident: int = 0) -> bytes:
    """A server UDP datagram to the same broadcast address (or unicast back
    to the client when ``ep.meta['bcast']`` is empty)."""
    bcast = ep.meta.get("bcast", "255.255.255.255")
    if not bcast:
        return P.udp_frame(ep, False, sport, dport, payload, ident=ident)
    seg = P.udp(ep.server_ip, bcast, sport, dport, payload)
    pkt = P.ipv4(ep.server_ip, bcast, P.IPPROTO_UDP, seg,
                 ttl=ep.ttl_server, ident=ident)
    return P.ethernet("ff:ff:ff:ff:ff:ff", ep.server_mac, P.ETH_P_IP, pkt,
                      vlan=ep.vlan)


# ===========================================================================
# Modbus/TCP
# ===========================================================================
def _mbap(tid: int, unit: int, pdu: bytes) -> bytes:
    return struct.pack("!HHHB", tid & 0xFFFF, 0, 1 + len(pdu), unit) + pdu


def modbus_id_flow(ep: Endpoints, count: int) -> List[bytes]:
    """Modbus/TCP (502): FC 43 / MEI 14 Read Device Identification — basic
    objects (VendorName, ProductCode, MajorMinorRevision) then regular ones
    (VendorUrl, ProductName, ModelName, UserApplicationName), conformity
    level 0x82. Values from ``ep.meta``: ``modbus_vendor``,
    ``modbus_product_code``, ``modbus_revision``, ``modbus_vendor_url``,
    ``modbus_product_name``, ``modbus_model_name``, ``host``."""
    m = ep.meta
    objs = [
        str(m.get("modbus_vendor", "Schneider Electric")),
        str(m.get("modbus_product_code", "BMX P34 2020")),
        str(m.get("modbus_revision", "V3.10")),
        str(m.get("modbus_vendor_url", "www.se.com")),
        str(m.get("modbus_product_name", "BMX P34 2020")),
        str(m.get("modbus_model_name", "Modicon M340")),
        str(m.get("host", "PLC")),
    ]
    unit = int(m.get("modbus_unit", 0xFF))

    def rsp(code: int, first: int, last: int) -> bytes:
        body = b"".join(bytes([k, len(objs[k].encode()[:64])]) +
                        objs[k].encode()[:64] for k in range(first, last))
        return bytes([0x2B, 0x0E, code, 0x82, 0x00, 0x00, last - first]) + body

    exchanges = []
    tid = 0
    for _ in range(max(1, count)):
        for code, first, last in ((1, 0, 3), (2, 3, 7)):
            tid += 1
            exchanges.append((_mbap(tid, unit, bytes([0x2B, 0x0E, code,
                                                      first])),
                              _mbap(tid, unit, rsp(code, first, last))))
    return _tcp_flow(ep, _sport(), 502, exchanges)


def modbus_write_flow(ep: Endpoints, count: int) -> List[bytes]:
    """Modbus/TCP (502): an operator's setpoint change from the HMI — read
    the setpoint block (FC 3), write two setpoints (FC 16), send a start
    command (FC 5, coil ON), set eight mode coils (FC 15) and read back.
    One operation per build, whatever ``count``."""
    unit = int(ep.meta.get("modbus_unit", 1))
    sp = [(0x0200 + n) & 0xFFFF for n in range(4)]

    def read_back(tid: int, vals: List[int]):
        req = _mbap(tid, unit, struct.pack("!BHH", 0x03, 100, len(vals)))
        regs = b"".join(struct.pack("!H", v) for v in vals)
        return req, _mbap(tid, unit, bytes([0x03, len(regs)]) + regs)

    new = [sp[0] + 25, sp[1] + 10]
    regs = b"".join(struct.pack("!H", v) for v in new)
    exchanges = [read_back(1, sp)]
    exchanges.append((
        _mbap(2, unit, struct.pack("!BHHB", 0x10, 100, 2, 4) + regs),
        _mbap(2, unit, struct.pack("!BHH", 0x10, 100, 2))))
    start = _mbap(3, unit, struct.pack("!BHH", 0x05, 16, 0xFF00))
    exchanges.append((start, start))                # FC 5 echoes the request
    exchanges.append((
        _mbap(4, unit, struct.pack("!BHHBB", 0x0F, 32, 8, 1, 0x05)),
        _mbap(4, unit, struct.pack("!BHH", 0x0F, 32, 8))))
    exchanges.append(read_back(5, new + sp[2:]))
    return _tcp_flow(ep, _sport(), 502, exchanges)


# ===========================================================================
# BACnet/IP
# ===========================================================================
def _bvlc(func: int, npdu: bytes, apdu: bytes) -> bytes:
    return struct.pack("!BBH", 0x81, func, 4 + len(npdu) + len(apdu)) + \
        npdu + apdu


def _bac_uint(v: int) -> bytes:
    n = max(1, (v.bit_length() + 7) // 8)
    return v.to_bytes(n, "big")


def _bac_ctx(tag: int, v: int) -> bytes:
    """Context-tagged unsigned (tag numbers < 15)."""
    b = _bac_uint(v)
    return bytes([(tag << 4) | 0x08 | len(b)]) + b


def _bac_app_uint(v: int, tag: int = 2) -> bytes:
    b = _bac_uint(v)
    return bytes([(tag << 4) | len(b)]) + b


def _bac_str(s: str) -> bytes:
    """Application-tagged CharacterString, UTF-8 (charset 0)."""
    b = b"\x00" + s.encode()[:200]
    if len(b) <= 4:
        return bytes([0x70 | len(b)]) + b
    return bytes([0x75, len(b)]) + b


def _bac_objid(obj_type: int, inst: int) -> int:
    return (obj_type << 22) | (inst & 0x3FFFFF)


# Device-object properties a BACnet discovery tool reads, in order
_BAC_PROPS = [(77, "name"), (121, "vendor"), (120, "vendor_id"),
              (70, "model"), (44, "firmware"), (12, "app"), (372, "serial")]


def bacnet_id_flow(ep: Endpoints, count: int) -> List[bytes]:
    """BACnet/IP (47808/UDP): a Who-Is for the device's instance (broadcast to
    ``ep.meta['bcast']``, default 255.255.255.255; unicast when empty) and its
    I-Am (vendor id, max APDU 1476, segmentation), then ReadPropertyMultiple
    on the Device object returning object-name, vendor-name,
    vendor-identifier, model-name, firmware-revision,
    application-software-version and serial-number; further cycles
    ReadProperty one of them. Values from ``ep.meta``: ``bacnet_instance``,
    ``bacnet_vendor_id``, ``bacnet_vendor``, ``bacnet_model``,
    ``bacnet_firmware``, ``bacnet_app_version``, ``bacnet_serial``,
    ``host``."""
    m = ep.meta
    inst = int(m.get("bacnet_instance", 1001))
    firmware = str(m.get("bacnet_firmware", "12.0.0"))
    vals = {
        "name": str(m.get("host", f"DEV{inst}")),
        "vendor": str(m.get("bacnet_vendor", "Johnson Controls")),
        "vendor_id": int(m.get("bacnet_vendor_id", 5)),
        "model": str(m.get("bacnet_model", "FEC2611-0")),
        "firmware": firmware,
        "app": str(m.get("bacnet_app_version", firmware)),
        "serial": str(m.get("bacnet_serial", "")),
    }
    props = [(p, k) for p, k in _BAC_PROPS if k != "serial" or vals["serial"]]
    dev = struct.pack("!I", _bac_objid(8, inst))

    def value(key: str) -> bytes:
        v = vals[key]
        return _bac_app_uint(v) if isinstance(v, int) else _bac_str(v)

    def prop_ref(tag: int, pid: int) -> bytes:
        return _bac_ctx(tag, pid)

    bcast = m.get("bcast", "255.255.255.255")
    frames = []
    # Who-Is with device-instance range limits, and the device's I-Am
    whois = b"\x10\x08" + _bac_ctx(0, inst) + _bac_ctx(1, inst)
    frames.append(_bcast_or_unicast(ep, 47808, 47808, _bvlc(
        0x0B if bcast else 0x0A, b"\x01\x00", whois)))
    seg = int(m.get("bacnet_segmentation", 3))     # 3 = no-segmentation
    iam = b"\x10\x00\xc4" + dev + _bac_app_uint(1476) + \
        bytes([0x91, seg]) + _bac_app_uint(vals["vendor_id"])
    frames.append(_server_bcast(ep, 47808, 47808, _bvlc(
        0x0B if bcast else 0x0A, b"\x01\x00", iam)))
    base = zlib.crc32(P.ip_to_bytes(ep.client_ip) + dev)
    for i in range(max(1, count)):
        invoke = (base + i) & 0xFF
        if i == 0:                                 # ReadPropertyMultiple
            refs = b"".join(prop_ref(0, p) for p, _ in props)
            req = struct.pack("!BBBB", 0x00, 0x05, invoke, 0x0E) + b"\x0c" + \
                dev + b"\x1e" + refs + b"\x1f"
            results = b"".join(prop_ref(2, p) + b"\x4e" + value(k) + b"\x4f"
                               for p, k in props)
            ack = struct.pack("!BBB", 0x30, invoke, 0x0E) + b"\x0c" + dev + \
                b"\x1e" + results + b"\x1f"
        else:                                      # ReadProperty
            pid, key = props[i % len(props)]
            obj = b"\x0c" + dev + prop_ref(1, pid)
            req = struct.pack("!BBBB", 0x00, 0x05, invoke, 0x0C) + obj
            ack = struct.pack("!BBB", 0x30, invoke, 0x0C) + obj + b"\x3e" + \
                value(key) + b"\x3f"
        frames.append(P.udp_frame(ep, True, 47808, 47808,
                                  _bvlc(0x0A, b"\x01\x04", req), ident=i))
        frames.append(P.udp_frame(ep, False, 47808, 47808,
                                  _bvlc(0x0A, b"\x01\x00", ack), ident=i))
    return frames


# ===========================================================================
# EtherNet/IP + CIP
# ===========================================================================
def enip_list_flow(ep: Endpoints, count: int) -> List[bytes]:
    """EtherNet/IP (44818/UDP): an RSLinx-style browse — List Identity sent
    to ``ep.meta['bcast']`` (default 255.255.255.255; unicast when empty)
    answered unicast by the device with its identity (vendor, device type,
    product code, revision, serial, product name), then a unicast List
    Services."""
    ident, _ = _enip_identity_item(ep)
    sport = _sport()
    ctx0 = zlib.crc32(P.ip_to_bytes(ep.client_ip)) & 0xFFFF0000
    frames = []
    for i in range(max(1, count)):
        ctx = ctx0 | (i + 1)
        frames.append(_bcast_or_unicast(ep, sport, 44818,
                                        _enip(0x0063, 0, b"", context=ctx),
                                        ident=i))
        frames.append(P.udp_frame(ep, False, 44818, sport, _enip(
            0x0063, 0, _cpf((0x000C, ident)), context=ctx), ident=i))
    # List Services: "Communications", CIP over TCP + class 0/1 over UDP
    svc = struct.pack("<HH", 1, 0x0120) + b"Communications\x00\x00"
    ctx = ctx0 | 0xFFFF
    frames.append(P.udp_frame(ep, True, sport, 44818,
                              _enip(0x0004, 0, b"", context=ctx)))
    frames.append(P.udp_frame(ep, False, 44818, sport, _enip(
        0x0004, 0, _cpf((0x0100, svc)), context=ctx)))
    return frames


def enip_io_flow(ep: Endpoints, count: int) -> List[bytes]:
    """CIP class-1 implicit I/O between a controller (client, originator) and
    an I/O adapter or drive (server, target): a Forward_Open over TCP 44818
    (point-to-point both ways, 20 ms RPI, electronic key from the target's
    identity meta), ``count`` cyclic exchanges on UDP 2222 (sequenced
    address item + connected data; O->T with the 32-bit run/idle header),
    then Forward_Close."""
    vendor, dtype = ep.meta.get("vendor_id", 1), ep.meta.get("device_type", 0x02)
    code = ep.meta.get("cip_product_code", 2192)
    major, minor = ep.meta.get("cip_revision", (13, 2))
    seed = zlib.crc32(P.ip_to_bytes(ep.client_ip) + P.ip_to_bytes(ep.server_ip))
    session = 0x34560000 | (seed & 0xFFFF)
    t2o_id = 0x00FF0000 | (seed & 0xFFFF)          # chosen by the originator
    o2t_id = 0x7E000000 | ((seed >> 8) & 0xFFFF)    # chosen by the target
    serial, orig_serial = (seed >> 16) & 0xFFFF, 0x00C0FFEE
    o2t_data, t2o_data = 8, 8                       # command/ref, status/fbk
    rpi = 20000                                     # µs
    key = struct.pack("<BBHHHBB", 0x34, 0x04, vendor, dtype, code,
                      major & 0x7F, minor)
    path = key + bytes([0x20, 0x04, 0x24, 0x06, 0x2C, 0x02, 0x2C, 0x01])
    fwd_open = bytes([0x54, 0x02, 0x20, 0x06, 0x24, 0x01]) + struct.pack(
        "<BBIIHHIB3sIHIHBB", 0x0A, 0x0E, 0, t2o_id, serial, 0x0001,
        orig_serial, 0x02, b"\x00" * 3,
        rpi, 0x4800 | (o2t_data + 6), rpi, 0x4800 | (t2o_data + 2),
        0x01, len(path) // 2) + path
    fwd_open_rsp = bytes([0xD4, 0x00, 0x00, 0x00]) + struct.pack(
        "<IIHHIIIBB", o2t_id, t2o_id, serial, 0x0001, orig_serial, rpi, rpi,
        0, 0)
    close_path = bytes([0x20, 0x04, 0x24, 0x06, 0x2C, 0x02, 0x2C, 0x01])
    fwd_close = bytes([0x4E, 0x02, 0x20, 0x06, 0x24, 0x01]) + struct.pack(
        "<BBHHIBB", 0x0A, 0x0E, serial, 0x0001, orig_serial,
        len(close_path) // 2, 0) + close_path
    fwd_close_rsp = bytes([0xCE, 0x00, 0x00, 0x00]) + struct.pack(
        "<HHIBB", serial, 0x0001, orig_serial, 0, 0)

    s = TcpSession(ep, _sport(), 44818)
    s.handshake()
    s.request(_enip(0x0065, 0, struct.pack("<HH", 1, 0)))
    s.response(_enip(0x0065, session, struct.pack("<HH", 1, 0)))
    s.request(_enip_rr(session, fwd_open, 1))
    s.response(_enip_rr(session, fwd_open_rsp, 1))
    for i in range(max(1, count)):
        seq = i + 1
        o2t = _cpf((0x8002, struct.pack("<II", o2t_id, seq)),
                   (0x00B1, struct.pack("<HI", seq & 0xFFFF, 1) +
                    struct.pack("<HHI", 0x047F, 0, 1750 + i)))   # RUN
        t2o = _cpf((0x8002, struct.pack("<II", t2o_id, seq)),
                   (0x00B1, struct.pack("<H", seq & 0xFFFF) +
                    struct.pack("<HHI", 0x0F07, 0, 1748 + i)))
        s.frames.append(P.udp_frame(ep, True, 2222, 2222, o2t, ident=seq))
        s.frames.append(P.udp_frame(ep, False, 2222, 2222, t2o, ident=seq))
    s.request(_enip_rr(session, fwd_close, 2))
    s.response(_enip_rr(session, fwd_close_rsp, 2))
    s.request(_enip(0x0066, session, b""))
    s.teardown()
    return s.frames


def enip_eng_flow(ep: Endpoints, count: int) -> List[bytes]:
    """EtherNet/IP (44818): what Studio 5000 reads going online — the
    Identity status word (controller mode / keyswitch bits), the program and
    task names from the Symbol object (Get_Instance_Attribute_List, class
    0x6B) and the controller's wall-clock time (class 0x8B). One operation
    per build, whatever ``count``."""
    session = 0x45670000 | (zlib.crc32(P.ip_to_bytes(ep.client_ip)) & 0xFFFF)
    exchanges = [(_enip(0x0065, 0, struct.pack("<HH", 1, 0)),
                  _enip(0x0065, session, struct.pack("<HH", 1, 0)))]
    # Identity status: owned, configured, remote RUN keyswitch bits
    exchanges.append((
        _enip_rr(session, bytes([0x0E, 0x03, 0x20, 0x01, 0x24, 0x01,
                                 0x30, 0x05]), 1),
        _enip_rr(session, bytes([0x8E, 0x00, 0x00, 0x00]) +
                 struct.pack("<H", 0x3065), 1)))
    # Symbol object instance list: names of the programs and controller tags
    names = [b"Program:MainProgram", b"Program:Line1", b"Program:Safety",
             b"Line1_Speed_SP", b"Line1_Running"]
    body = b"".join(struct.pack("<IH", k + 1, len(n)) + n +
                    struct.pack("<H", 0x1068 if n.startswith(b"Program:")
                                else 0x00C4)
                    for k, n in enumerate(names))
    exchanges.append((
        _enip_rr(session, bytes([0x55, 0x03, 0x20, 0x6B, 0x25, 0x00, 0x00,
                                 0x00]) + struct.pack("<HHH", 2, 1, 2), 2),
        _enip_rr(session, bytes([0xD5, 0x00, 0x00, 0x00]) + body, 2)))
    # Wall Clock Time object: current time (µs since 1970)
    exchanges.append((
        _enip_rr(session, bytes([0x0E, 0x03, 0x20, 0x8B, 0x24, 0x01,
                                 0x30, 0x0B]), 3),
        _enip_rr(session, bytes([0x8E, 0x00, 0x00, 0x00]) +
                 struct.pack("<Q", _DNP3_EPOCH_MS * 1000), 3)))
    exchanges.append((_enip(0x0066, session, b""), b""))
    return _tcp_flow(ep, _sport(), 44818, exchanges)


# ===========================================================================
# S7comm engineering: block list, upload, download
# ===========================================================================
def _s7_block_userdata(ref: int, subfunc: int, seq: int, req_data: bytes,
                       rsp_data: bytes) -> tuple:
    """Userdata block function (group 3) request (``req_data`` is its whole
    data part) + response carrying ``rsp_data`` as an octet string."""
    req = _s7(7, ref, bytes([0x00, 0x01, 0x12, 0x04, 0x11, 0x43, subfunc,
                             0x00]), req_data)
    rsp = _s7(7, ref, bytes([0x00, 0x01, 0x12, 0x08, 0x12, 0x83, subfunc,
                             seq, 0x00, 0x00, 0x00, 0x00]),
              b"\xff\x09" + struct.pack("!H", len(rsp_data)) + rsp_data)
    return req, rsp


def _mc7_block(btype: int, number: int, code: bytes) -> bytes:
    """An S7 MC7 block: 36-byte header ('pp', language STL), code, footer."""
    hdr = struct.pack("!BBBBBBHI4s6s6sHHHH", 0x70, 0x70, 0x01, 0x01, 0x01,
                      btype, number, 36 + len(code) + 36, b"\x00" * 4,
                      b"\x00" * 6, b"\x00" * 6, 0, 0, 0, len(code))
    return hdr + code + b"\x00" * 36


def s7_eng_flow(ep: Endpoints, count: int) -> List[bytes]:
    """S7comm (102): an engineering session from TIA Portal / STEP 7 — list
    blocks, list the OBs and DBs, upload OB1 (Start upload / Upload / End
    upload) and a planned download of DB10 (Request download, the PLC's
    Download block + Download ended jobs, then PLC Control _INSE to activate
    it). One operation per build, whatever ``count``."""
    exchanges = _s7_connect()
    ref = 0x0100
    # list all blocks: (type, count) for OB DB SDB FC SFC FB SFB
    counts = [(b"08", 3), (b"0A", 12), (b"0B", 9), (b"0C", 18), (b"0D", 74),
              (b"0E", 6), (b"0F", 27)]
    # the request's data part is empty: return code 0x0a, transport NULL
    exchanges.append(_s7_block_userdata(
        ref, 0x01, 1, b"\x0a\x00\x00\x00",
        b"".join(t + struct.pack("!H", n) for t, n in counts)))
    for k, (btype, numbers) in enumerate(((b"08", (1, 35, 100)),
                                          (b"0A", (1, 2, 10, 11)))):
        ref += 1
        exchanges.append(_s7_block_userdata(
            ref, 0x02, 2 + k, b"\xff\x09\x00\x02" + btype,
            b"".join(struct.pack("!HBB", n, 0x22, 0x05) for n in numbers)))

    def filename(btype: str, number: int, fs: str = "P") -> bytes:
        name = f"_{btype}{number:05d}{fs}".encode()
        return bytes([len(name)]) + name

    # upload OB1
    upload_id = 0x00000007
    ob1 = _mc7_block(0x08, 1, bytes(range(0x40, 0x80)))
    ref += 1
    exchanges.append((
        _s7(1, ref, bytes([0x1D, 0x00, 0x00, 0x00]) +
            struct.pack("!I", 0) + filename("08", 1, "A")),
        _s7(3, ref, bytes([0x1D, 0x00, 0x01, 0x00]) +
            struct.pack("!I", upload_id) + b"\x07" +
            f"{len(ob1):07d}".encode())))
    ref += 1
    exchanges.append((
        _s7(1, ref, bytes([0x1E, 0x00, 0x00, 0x00]) +
            struct.pack("!I", upload_id)),
        _s7(3, ref, bytes([0x1E, 0x00]),
            struct.pack("!HH", len(ob1), 0x00FB) + ob1)))
    ref += 1
    exchanges.append((
        _s7(1, ref, bytes([0x1F, 0x00, 0x00, 0x00]) +
            struct.pack("!I", upload_id)),
        _s7(3, ref, bytes([0x1F]))))

    # planned download of DB10: the engineering station asks, the PLC pulls
    db10 = _mc7_block(0x0A, 10, struct.pack("!8f", *(20.0 + n for n in
                                                      range(8))))
    part2 = b"1" + f"{len(db10):06d}".encode() + \
        f"{len(db10) - 72:06d}".encode()
    ref += 1
    exchanges.append((
        _s7(1, ref, bytes([0x1A, 0x00, 0x01, 0x00]) + struct.pack("!I", 0) +
            filename("0A", 10) + bytes([len(part2)]) + part2),
        _s7(3, ref, bytes([0x1A]))))
    plc_ref = 0x0E00
    exchanges.append((b"", _s7(1, plc_ref, bytes([0x1B, 0x00, 0x01, 0x00]) +
                                struct.pack("!I", 0) + filename("0A", 10))))
    exchanges.append((_s7(3, plc_ref, bytes([0x1B, 0x00]),
                          struct.pack("!HH", len(db10), 0x00FB) + db10), b""))
    plc_ref += 1
    exchanges.append((b"", _s7(1, plc_ref, bytes([0x1C, 0x00, 0x00, 0x00]) +
                                struct.pack("!I", 0) + filename("0A", 10))))
    exchanges.append((_s7(3, plc_ref, bytes([0x1C])), b""))
    # PLC Control: PI service _INSE activates the downloaded block
    arg = b"\x01\x00" + b"0A" + b"00010" + b"P"
    ref += 1
    exchanges.append((
        _s7(1, ref, bytes([0x28, 0, 0, 0, 0, 0, 0, 0xFD]) +
            struct.pack("!H", len(arg)) + arg + b"\x05_INSE"),
        _s7(3, ref, bytes([0x28]))))
    return _tcp_flow(ep, _sport(), 102, exchanges)


# ===========================================================================
# DNP3
# ===========================================================================
# Device-attribute variations (group 0) and the meta key carrying each
_DNP3_ATTRS = [(252, "dnp3_vendor"), (250, "dnp3_product"),
               (242, "dnp3_firmware"), (248, "dnp3_serial"),
               (247, "host")]


def dnp3_id_flow(ep: Endpoints, count: int) -> List[bytes]:
    """DNP3 (20000): a master reads the outstation's device attributes
    (group 0): manufacturer name (v252), product name and model (v250),
    software version (v242), serial number (v248) and user-assigned device
    name (v247), each a VSTR. Values from ``ep.meta`` (``dnp3_vendor``,
    ``dnp3_product``, ``dnp3_firmware``, ``dnp3_serial``, ``host``)."""
    m = ep.meta
    defaults = {"dnp3_vendor": "Schweitzer Engineering Laboratories",
                "dnp3_product": "SEL-751", "dnp3_firmware": "R420-V2",
                "dnp3_serial": "1234567890", "host": "RELAY"}
    attrs = [(v, str(m.get(k) or defaults[k]).encode()[:40])
             for v, k in _DNP3_ATTRS]
    exchanges = []
    for i in range(max(1, count)):
        req = b"".join(bytes([0x00, v, 0x00, 0x00, 0x00]) for v, _ in attrs)
        rsp = b"".join(bytes([0x00, v, 0x00, 0x00, 0x00, 0x01, len(s)]) + s
                       for v, s in attrs)
        exchanges.append((_dnp3_req(ep, i, 0x01, req),
                          _dnp3_rsp(ep, i, rsp)))
    return _tcp_flow(ep, _sport(), 20000, exchanges)


def dnp3_time_flow(ep: Endpoints, count: int) -> List[bytes]:
    """DNP3 (20000): the master's time synchronisation — Delay Measure
    (answered by g52v2 with IIN1.4 NEED_TIME set) and a WRITE of the absolute
    time (g50v1); the outstation answers with NEED_TIME cleared. One
    synchronisation per build, whatever ``count``."""
    t = _DNP3_EPOCH_MS + zlib.crc32(P.ip_to_bytes(ep.server_ip)) % 600000
    delay = b"\x34\x02\x07\x01" + struct.pack("<H", 4)    # g52v2: 4 ms
    exchanges = [
        (_dnp3_req(ep, 0, 0x17, b""),
         _dnp3_rsp(ep, 0, delay, iin=b"\x10\x00")),
        (_dnp3_req(ep, 1, 0x02, b"\x32\x01\x07\x01" + _dnp3_time(t + 4)),
         _dnp3_rsp(ep, 1, b"")),
    ]
    return _tcp_flow(ep, _sport(), 20000, exchanges)


# ===========================================================================
# IEC 60870-5-104
# ===========================================================================
def iec104_time_flow(ep: Endpoints, count: int) -> List[bytes]:
    """IEC 60870-5-104 (2404): the SCADA master's clock synchronisation —
    STARTDT, C_CS_NA_1 activation with CP56Time2a and its confirmation, an
    S-frame, STOPDT. One synchronisation per build, whatever ``count``."""
    ca = int(ep.meta.get("common_address", 1))
    t = zlib.crc32(P.ip_to_bytes(ep.server_ip)) % 3000000
    act = _iec104_asdu(103, 6, 0, _cp56(t), ca)
    con = _iec104_asdu(103, 7, 0, _cp56(t), ca)
    exchanges = [
        (_iec104_u(0x07), _iec104_u(0x0B)),               # STARTDT act/con
        (_iec104_i(0, 0, act), _iec104_i(0, 1, con)),
        (_iec104_s(1), b""),
        (_iec104_u(0x13), _iec104_u(0x23)),               # STOPDT act/con
    ]
    return _tcp_flow(ep, _sport(), 2404, exchanges)


# ===========================================================================
# Registry (after the core OT profiles)
# ===========================================================================
_reg("modbus-id", "Modbus Device ID", "OT", "502", "tcp",
     modbus_id_flow, "FC 43/14 Read Device ID: vendor, product code, "
     "revision, model")
_reg("bacnet-id", "BACnet Device ID", "OT", "47808", "udp",
     bacnet_id_flow, "Who-Is/I-Am + ReadPropertyMultiple of the Device object "
     "(vendor, model, firmware)")
_reg("enip-list", "EtherNet/IP Browse", "OT", "44818", "udp",
     enip_list_flow, "RSLinx-style broadcast List Identity + unicast replies, "
     "List Services")
_reg("enip-io", "CIP Implicit I/O", "OT", "2222", "udp", enip_io_flow,
     "Forward_Open + cyclic class-1 I/O on UDP 2222 + Forward_Close")
_reg("dnp3-id", "DNP3 Device Attrs", "OT", "20000", "tcp", dnp3_id_flow,
     "Group 0 reads: manufacturer, model, software version, serial")
# Normal engineering / operations baseline
_reg("s7-eng", "S7 Engineering", "OT", "102", "tcp",
     s7_eng_flow, "Block list, OB1 upload, planned DB10 download + _INSE")
_reg("enip-eng", "CIP Engineering", "OT", "44818", "tcp", enip_eng_flow,
     "Controller mode/status, program list and clock reads")
_reg("modbus-write", "Modbus Operator Write", "OT", "502", "tcp",
     modbus_write_flow, "HMI setpoint/command writes: FC 16, FC 5, FC 15")
_reg("dnp3-time", "DNP3 Time Sync", "OT", "20000", "tcp", dnp3_time_flow,
     "Delay Measure + g50v1 time write from the SCADA master")
_reg("iec104-time", "IEC 104 Clock Sync", "OT", "2404", "tcp",
     iec104_time_flow, "C_CS_NA_1 clock synchronisation from the SCADA master")
