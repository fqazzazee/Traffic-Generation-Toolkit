"""Industrial L2 / substation protocol builders: PROFINET DCP + RT, IEC 61850
GOOSE / Sampled Values / MMS, and IEEE 1588 PTP.

Imported from the bottom of :mod:`tgt.protocols`, which owns the registry; the
builders register themselves with ``_reg`` like every other profile.

Layer-2 note: DCP, PN-RT, GOOSE and SV are raw Ethernet (no IP) and PTP is
link-local multicast (IP TTL 1, or EtherType 0x88f7). None of them can cross a
router, so an environment must only place them between hosts on the same
segment (``transport == "l2"`` is enforced by ``enterprise.Environment``; PTP
registers as ``udp`` and needs the same care). GOOSE / SV carry an 802.1Q tag
with priority 4 (VID = ``ep.vlan`` or 0 = priority-tagged) and PN-RT priority
6, as IEC 61850-8-1 / -9-2 and PROFINET recommend.

Endpoint roles (the field device is always the ``server``, so one endpoint
pair in a scenario is consistently gateway <-> IED across every protocol):
  pn-dcp / pn-dcp-set   client = engineering station, server = IO device/PLC
  pn-rt                 client = IO controller,       server = IO device
  goose / sv            server = publishing IED / merging unit (multicast;
                        the client is the notional subscriber and is silent)
  mms                   client = SCADA / gateway,     server = IED
  ptp / ptp-l2          client = slave clock,         server = grandmaster
"""
from __future__ import annotations

import math
import re
import struct
import time
from typing import List

from . import packet as P
from .packet import Endpoints
from .protocols import _COTP_DT, _der, _der_int, _reg, _sport, _tcp_flow, _tpkt

ETH_P_PROFINET = 0x8892
ETH_P_GOOSE = 0x88B8
ETH_P_SV = 0x88BA
ETH_P_PTP = 0x88F7

_DCP_MCAST = "01:0e:cf:00:00:00"         # PROFINET DCP Identify multicast
_PTP_MCAST_MAC = "01:00:5e:00:01:81"     # 224.0.1.129
_PTP_MCAST_IP = "224.0.1.129"
_PTP_L2_MCAST = "01:1b:19:00:00:00"      # IEEE 1588 L2 (forwardable)


def _l2(dst: str, src: str, ethertype: int, payload: bytes,
        vlan: int | None = None, pcp: int | None = None) -> bytes:
    """Ethernet frame padded to the 60-byte minimum. With ``pcp`` set the frame
    is always 802.1Q-tagged (VID ``vlan`` or 0, i.e. priority-tagged)."""
    if pcp is None:
        frame = P.ethernet(dst, src, ethertype, payload, vlan=vlan)
    else:
        frame = (P.mac_to_bytes(dst) + P.mac_to_bytes(src) +
                 struct.pack("!HHH", P.ETH_P_VLAN,
                             ((pcp & 7) << 13) | ((vlan or 0) & 0x0FFF),
                             ethertype) + payload)
    return frame.ljust(60, b"\x00")


def _ident(ep: Endpoints, key: str, default: str) -> str:
    """A device name from endpoint meta, else ``default``."""
    return str(ep.meta.get(key) or default)


def _station_name(ep: Endpoints) -> str:
    """PROFINET NameOfStation: lower-case DNS label(s)."""
    raw = ep.meta.get("station") or ep.meta.get("host") or "plc-s71500-1"
    name = re.sub(r"[^a-z0-9.-]+", "-", str(raw).lower()).strip("-.")
    return name or "plc-s71500-1"


# ===========================================================================
# PROFINET DCP (0x8892, FrameID 0xFEFD-0xFEFF)
# ===========================================================================
def _dcp(frame_id: int, service: int, stype: int, xid: int, blocks: bytes,
         delay: int = 0) -> bytes:
    return struct.pack("!HBBIHH", frame_id, service, stype, xid, delay,
                       len(blocks)) + blocks


def _dcp_block(opt: int, sub: int, data: bytes) -> bytes:
    blk = struct.pack("!BBH", opt, sub, len(data)) + data
    return blk + (b"\x00" if len(data) & 1 else b"")


def _dcp_device(ep: Endpoints) -> dict:
    return {
        "name": _station_name(ep),
        "vendor": _ident(ep, "dcp_vendor", "S7-1500"),       # DeviceVendorValue
        "vendor_id": int(ep.meta.get("pn_vendor_id", 0x002A)),  # Siemens AG
        "device_id": int(ep.meta.get("pn_device_id", 0x010E)),  # S7-1500 CPU
        "role": int(ep.meta.get("pn_role", 0x02)),           # 0x02 IO-Controller
    }


def _dcp_ip(ep: Endpoints, ip: str | None = None) -> bytes:
    ip = ip or ep.server_ip
    gw = ".".join(ip.split(".")[:3] + ["1"])
    return (P.ip_to_bytes(ip) + P.ip_to_bytes("255.255.255.0") +
            P.ip_to_bytes(gw))


def _dcp_identity_blocks(ep: Endpoints) -> bytes:
    """Identify/Get response blocks: options, vendor, name, ID, role, IP."""
    d = _dcp_device(ep)
    opts = bytes([1, 1, 1, 2, 2, 1, 2, 2, 2, 3, 2, 4, 2, 5, 2, 7,
                  5, 1, 5, 2, 5, 3, 5, 4])
    info = b"\x00\x00"                                # BlockInfo reserved
    return (_dcp_block(2, 5, info + opts) +
            _dcp_block(2, 1, info + d["vendor"].encode()) +
            _dcp_block(2, 2, info + d["name"].encode()) +
            _dcp_block(2, 3, info + struct.pack("!HH", d["vendor_id"],
                                                d["device_id"])) +
            _dcp_block(2, 4, info + bytes([d["role"], 0])) +
            _dcp_block(2, 7, info + b"\x00\x64") +    # device instance 0.100
            _dcp_block(1, 2, b"\x00\x01" + _dcp_ip(ep)))   # IP set (static)


def pn_dcp_flow(ep: Endpoints, count: int) -> List[bytes]:
    """PROFINET DCP Identify All (multicast 01:0e:cf:00:00:00) from an
    engineering station, answered by the device's Identify Response with
    NameOfStation, vendor/device ID, role and IP parameters."""
    frames = []
    for i in range(count):
        xid = 0x01000000 + i + 1
        req = _dcp(0xFEFE, 5, 0, xid, _dcp_block(0xFF, 0xFF, b""), delay=1)
        frames.append(_l2(_DCP_MCAST, ep.client_mac, ETH_P_PROFINET, req,
                          vlan=ep.vlan))
        rsp = _dcp(0xFEFF, 5, 1, xid, _dcp_identity_blocks(ep))
        frames.append(_l2(ep.client_mac, ep.server_mac, ETH_P_PROFINET, rsp,
                          vlan=ep.vlan))
    return frames


def pn_dcp_set_flow(ep: Endpoints, count: int) -> List[bytes]:
    """PROFINET DCP Get (name + IP) then Set IP / Set NameOfStation, each
    answered by the device — the commissioning step behind "IP changed" and
    "device renamed" alerts. The new IP is the device's address + 100 (mod
    254); the new name appends ``-new``."""
    frames = []

    def pair(xid: int, service: int, req_blocks: bytes, rsp_blocks: bytes):
        frames.append(_l2(ep.server_mac, ep.client_mac, ETH_P_PROFINET,
                          _dcp(0xFEFD, service, 0, xid, req_blocks),
                          vlan=ep.vlan))
        frames.append(_l2(ep.client_mac, ep.server_mac, ETH_P_PROFINET,
                          _dcp(0xFEFD, service, 1, xid, rsp_blocks),
                          vlan=ep.vlan))

    def ok(opt: int, sub: int) -> bytes:          # Control/Response, no error
        return _dcp_block(5, 4, bytes([opt, sub, 0]))

    o = ep.server_ip.split(".")
    new_ip = ".".join(o[:3] + [str((int(o[3]) + 100) % 254 or 1)])
    end = _dcp_block(5, 2, b"\x00\x00")           # Control: End Transaction
    for i in range(max(1, count)):
        xid = 0x02000000 + 3 * i
        info = b"\x00\x00"
        pair(xid + 1, 3, bytes([1, 2, 2, 2]),
             _dcp_block(1, 2, b"\x00\x01" + _dcp_ip(ep)) +
             _dcp_block(2, 2, info + _station_name(ep).encode()))
        if i % 2 == 0:                            # Set IP (permanent)
            pair(xid + 2, 4,
                 _dcp_block(1, 2, b"\x00\x01" + _dcp_ip(ep, new_ip)) + end,
                 ok(1, 2) + ok(5, 2))
        else:                                     # Set NameOfStation
            pair(xid + 2, 4,
                 _dcp_block(2, 2, b"\x00\x01" +
                            (_station_name(ep) + "-new").encode()) + end,
                 ok(2, 2) + ok(5, 2))
    return frames


# ===========================================================================
# PROFINET RT cyclic IO data (0x8892, FrameID 0x8000 range, RT_CLASS_1)
# ===========================================================================
def pn_rt_flow(ep: Endpoints, count: int) -> List[bytes]:
    """Cyclic PROFINET RT_CLASS_1 frames: the controller's output CR and the
    device's input CR, 40-byte C_SDU (IOxS good) + cycle counter, data status
    (primary, valid, run, no problem) and transfer status."""
    frames = []
    for i in range(count):
        cycle = (0x1000 + 32 * i) & 0xFFFF        # 1 ms send clock
        for from_ctl, fid in ((True, 0x8000), (False, 0x8001)):
            io = bytes(((i + k) & 0xFF if k % 4 != 3 else 0x80)
                       for k in range(40))
            body = struct.pack("!H", fid) + io + \
                struct.pack("!HBB", cycle, 0x35, 0x00)
            src, dst = ((ep.client_mac, ep.server_mac) if from_ctl else
                        (ep.server_mac, ep.client_mac))
            frames.append(_l2(dst, src, ETH_P_PROFINET, body, vlan=ep.vlan,
                              pcp=6))
    return frames


# ===========================================================================
# IEC 61850 GOOSE (0x88B8) and Sampled Values (0x88BA)
# ===========================================================================
def _utctime(ts: float) -> bytes:
    """IEC 61850 UtcTime: 32-bit seconds, 24-bit fraction, quality (10-bit
    accuracy, clock synchronised)."""
    sec = int(ts)
    frac = int((ts - sec) * (1 << 24)) & 0xFFFFFF
    return struct.pack("!I", sec) + frac.to_bytes(3, "big") + b"\x0a"


def _iec61850_hdr(appid: int, apdu: bytes) -> bytes:
    return struct.pack("!HHHH", appid, 8 + len(apdu), 0, 0) + apdu


def _ied(ep: Endpoints) -> str:
    raw = ep.meta.get("ied") or ep.meta.get("host") or "IED1"
    return re.sub(r"[^A-Za-z0-9_]", "", str(raw))[:32] or "IED1"


def goose_flow(ep: Endpoints, count: int) -> List[bytes]:
    """IEC 61850 GOOSE: a protection IED publishing trip + breaker position.

    State changes every four messages (stNum++, sqNum reset to 0, ``t`` = the
    event time); between them the same state is retransmitted with sqNum++
    and a growing timeAllowedtoLive, like the real fast-repeat back-off."""
    ied = _ied(ep)
    ld = f"{ied}LD0"
    appid = int(ep.meta.get("goose_appid", 0x0001))
    dst = f"01:0c:cd:01:00:{appid & 0xFF:02x}"
    t0 = time.time()
    frames = []
    for i in range(count):
        st, sq = 1 + i // 4, i % 4
        trip = st % 2 == 0
        tal = (20, 40, 80, 2000)[sq] * 2
        q = _der(0x84, b"\x03\x00\x00")              # quality: good (13 bits)
        pos = _der(0x84, b"\x06" + (b"\x40" if trip else b"\x80"))  # off/on
        data = (_der(0x83, b"\xff" if trip else b"\x00") + q + pos + q +
                _der(0x91, _utctime(t0 + st)))
        pdu = (_der(0x80, f"{ld}/LLN0$GO$gcbTrip".encode()) +
               _der_int(tal, 0x81) +
               _der(0x82, f"{ld}/LLN0$dsTrip".encode()) +
               _der(0x83, f"{ied}_Trip".encode()) +
               _der(0x84, _utctime(t0 + st)) +
               _der_int(st, 0x85) + _der_int(sq, 0x86) +
               _der(0x87, b"\x00") +                  # simulation FALSE
               _der_int(1, 0x88) +                    # confRev
               _der(0x89, b"\x00") +                  # ndsCom FALSE
               _der_int(5, 0x8A) +                    # numDatSetEntries
               _der(0xAB, data))
        frames.append(_l2(dst, ep.server_mac, ETH_P_GOOSE,
                          _iec61850_hdr(appid, _der(0x61, pdu)),
                          vlan=ep.vlan, pcp=4))
    return frames


def sv_flow(ep: Endpoints, count: int) -> List[bytes]:
    """IEC 61850-9-2LE Sampled Values from a merging unit: one ASDU per frame
    (80 samples/cycle at 50 Hz) carrying 4 currents + 4 voltages, smpCnt
    incrementing, smpSynch = global (PTP/GPS)."""
    mu = _ied(ep)
    appid = int(ep.meta.get("sv_appid", 0x4001))
    dst = f"01:0c:cd:04:00:{appid & 0xFF:02x}"
    frames = []
    for i in range(count):
        smp = i % 4000
        ph = 2 * math.pi * smp / 80
        vals = []
        for amp, scale in ((100.0, 1000), (11000.0, 100)):   # A (mA), V (10 mV)
            abc = [amp * math.sin(ph - k * 2 * math.pi / 3) for k in range(3)]
            vals += [round(x * scale) for x in abc] + [round(sum(abc) * scale)]
        seq = b"".join(struct.pack("!iI", v, 0) for v in vals)
        asdu = _der(0x30,
                    _der(0x80, f"{mu}MU01".encode()) +
                    _der(0x82, struct.pack("!H", smp)) +
                    _der(0x83, struct.pack("!I", 1)) +
                    _der(0x85, b"\x02") +          # smpSynch: global
                    _der(0x87, seq))
        pdu = _der(0x60, _der_int(1, 0x80) + _der(0xA2, asdu))
        frames.append(_l2(dst, ep.server_mac, ETH_P_SV,
                          _iec61850_hdr(appid, pdu), vlan=ep.vlan, pcp=4))
    return frames


# ===========================================================================
# IEC 61850 MMS over ISO-on-TCP (102): TPKT/COTP/Session/Presentation/ACSE
# ===========================================================================
def _ses_len(n: int) -> bytes:
    return bytes([n]) if n < 255 else b"\xff" + struct.pack("!H", n)


def _ses_param(code: int, value: bytes) -> bytes:
    return bytes([code]) + _ses_len(len(value)) + value


def _spdu(si: int, params: bytes) -> bytes:
    return bytes([si]) + _ses_len(len(params)) + params


_ACSE_CTX, _MMS_CTX = 1, 3
_MMS_APP_CTX = _der(0xA1, _der(0x06, b"\x28\xca\x22\x02\x03"))   # 1.0.9506.2.3
_BER = _der(0x06, b"\x51\x01")                                   # 2.1.1
_AP_TITLE = _der(0x06, b"\x29\x01\x87\x67\x01")                  # 1.1.1.999.1
_AE_QUAL = _der_int(12)


def _pdv(ctx: int, pdu: bytes) -> bytes:
    """Presentation fully-encoded-data: one PDV for context ``ctx``."""
    return _der(0x61, _der(0x30, _der_int(ctx) + _der(0xA0, pdu)))


def _acse_user_info(mms: bytes) -> bytes:
    return _der(0xBE, _der(0x28, _der_int(_MMS_CTX) + _der(0xA0, mms)))


def _mms_init_detail(tag: int, resp: bool) -> bytes:
    """initiate-Request/ResponsePDU (version 1, IEC 61850 CBBs/services)."""
    detail = (_der_int(1, 0x80) + _der(0x81, b"\x05\xf1\x00") +
              _der(0x82, b"\x03\xee\x1c\x00\x00\x04\x08\x00\x00\x79\xef\x18"))
    return _der(tag, _der_int(65000, 0x80) + _der_int(5, 0x81) +
                _der_int(5, 0x82) + _der_int(10, 0x83) + _der(0xA4, detail))


def _mms_associate() -> List[tuple[bytes, bytes]]:
    """COTP CR/CC then Session CONNECT/ACCEPT carrying Presentation CP/CPA,
    ACSE AARQ/AARE and MMS Initiate request/response."""
    params = b"\xc0\x01\x0a\xc1\x02\x00\x01\xc2\x02\x00\x01"   # 1024, TSAP 1/1
    cr = _tpkt(struct.pack("!BBHHB", 6 + len(params), 0xE0, 0, 0x0001, 0) +
               params)
    cc = _tpkt(struct.pack("!BBHHB", 6 + len(params), 0xD0, 0x0001, 0x0001,
                           0) + params)
    aarq = _der(0x60, _MMS_APP_CTX + _der(0xA2, _AP_TITLE) +
                _der(0xA3, _AE_QUAL) + _der(0xA6, _AP_TITLE) +
                _der(0xA7, _AE_QUAL) +
                _acse_user_info(_mms_init_detail(0xA8, False)))
    aare = _der(0x61, _MMS_APP_CTX + _der(0xA2, _der_int(0)) +
                _der(0xA3, _der(0xA1, _der_int(0))) +
                _der(0xA4, _AP_TITLE) + _der(0xA5, _AE_QUAL) +
                _acse_user_info(_mms_init_detail(0xA9, True)))
    psel = b"\x00\x00\x00\x01"
    ctx_list = _der(0xA4,
                    _der(0x30, _der_int(_ACSE_CTX) +
                         _der(0x06, b"\x52\x01\x00\x01") + _der(0x30, _BER)) +
                    _der(0x30, _der_int(_MMS_CTX) +
                         _der(0x06, b"\x28\xca\x22\x02\x01") +
                         _der(0x30, _BER)))
    mode = _der(0xA0, _der_int(1, 0x80))           # normal-mode
    cp = _der(0x31, mode + _der(0xA2, _der(0x81, psel) + _der(0x82, psel) +
                                ctx_list + _pdv(_ACSE_CTX, aarq)))
    accepted = _der(0x30, _der(0x80, b"\x00") + _der(0x81, b"\x51\x01"))
    cpa = _der(0x31, mode + _der(0xA2, _der(0x83, psel) +
                                 _der(0xA5, accepted + accepted) +
                                 _pdv(_ACSE_CTX, aare)))
    base = (_ses_param(0x05, b"\x13\x01\x00\x16\x01\x02") +   # opts, ver 2
            _ses_param(0x14, b"\x00\x02"))                     # duplex
    connect = _spdu(0x0D, base + _ses_param(0x33, b"\x00\x01") +
                    _ses_param(0x34, b"\x00\x01") + _ses_param(0xC1, cp))
    accept = _spdu(0x0E, base + _ses_param(0x34, b"\x00\x01") +
                   _ses_param(0xC1, cpa))
    return [(cr, cc), (_tpkt(_COTP_DT + connect), _tpkt(_COTP_DT + accept))]


def _mms_data(pdu: bytes) -> bytes:
    """MMS PDU in Session Give-Tokens + Data-Transfer, presentation ctx 3."""
    return _tpkt(_COTP_DT + b"\x01\x00\x01\x00" + _pdv(_MMS_CTX, pdu))


def _mms_req(invoke: int, service: bytes) -> bytes:
    return _mms_data(_der(0xA0, _der_int(invoke) + service))


def _mms_rsp(invoke: int, service: bytes) -> bytes:
    return _mms_data(_der(0xA1, _der_int(invoke) + service))


def _vstr(tag: int, s: str) -> bytes:
    return _der(tag, s.encode())


def mms_flow(ep: Endpoints, count: int) -> List[bytes]:
    """IEC 61850 MMS (102): association (COTP/Session/Presentation/ACSE +
    Initiate), Identify (vendor/model/revision from ``ep.meta``),
    GetNameList of domains and of one logical device's variables, then Read
    of MMXU1$MX$TotW (float + quality + timestamp) and Conclude."""
    ied = _ied(ep)
    ld = f"{ied}LD0"
    vendor = _ident(ep, "vendor", "Siemens")
    model = _ident(ep, "model", ep.meta.get("product") or "SIPROTEC 5 7SJ85")
    rev = _ident(ep, "revision", "V08.30")
    t0 = time.time()

    exchanges = _mms_associate()
    inv = 1
    exchanges.append((_mms_req(inv, _der(0x82, b"")),             # identify
                      _mms_rsp(inv, _der(0xA2, _vstr(0x80, vendor) +
                                         _vstr(0x81, model) +
                                         _vstr(0x82, rev)))))
    inv += 1
    exchanges.append((
        _mms_req(inv, _der(0xA1, _der(0xA0, _der_int(9, 0x80)) +   # domain
                           _der(0xA1, _der(0x80, b"")))),          # vmd scope
        _mms_rsp(inv, _der(0xA1, _der(0xA0, _vstr(0x1A, ld) +
                                      _vstr(0x1A, f"{ied}PROT")) +
                           _der(0x81, b"\x00")))))                 # no more
    inv += 1
    names = ["LLN0", "LPHD1", "MMXU1", "MMXU1$MX", "MMXU1$MX$TotW",
             "MMXU1$MX$TotW$mag", "MMXU1$MX$TotW$mag$f", "XCBR1",
             "XCBR1$ST$Pos"]
    exchanges.append((
        _mms_req(inv, _der(0xA1, _der(0xA0, _der_int(0, 0x80)) +   # namedVar
                           _der(0xA1, _vstr(0x81, ld)))),
        _mms_rsp(inv, _der(0xA1, _der(0xA0, b"".join(
            _vstr(0x1A, n) for n in names)) + _der(0x81, b"\x00")))))
    for i in range(count):
        inv += 1
        var = _der(0xA0, _der(0xA1, _vstr(0x1A, ld) +
                              _vstr(0x1A, "MMXU1$MX$TotW")))
        read = _der(0xA4, _der(0xA1, _der(0xA0, _der(0x30, var))))
        watts = 1250.0 + 7.5 * i
        value = _der(0xA2, _der(0xA2, _der(0x87, b"\x08" +
                                           struct.pack("!f", watts))) +
                     _der(0x84, b"\x03\x00\x00") +          # q: good
                     _der(0x91, _utctime(t0 + i)))
        exchanges.append((_mms_req(inv, read),
                          _mms_rsp(inv, _der(0xA4, _der(0xA1, value)))))
    exchanges.append((_mms_data(_der(0x8B, b"")),        # conclude request
                      _mms_data(_der(0x8C, b""))))       # conclude response
    return _tcp_flow(ep, _sport(), 102, exchanges)


# ===========================================================================
# IEEE 1588v2 PTP — UDP 319/320 multicast or L2 EtherType 0x88f7
# ===========================================================================
def _clock_id(mac: str) -> bytes:
    """EUI-64 clock identity from a MAC (inserting ff:fe)."""
    m = P.mac_to_bytes(mac)
    return m[:3] + b"\xff\xfe" + m[3:]


def _ptp_ts(ts: float) -> bytes:
    sec = int(ts)
    return sec.to_bytes(6, "big") + struct.pack("!I", int((ts - sec) * 1e9))


def _ptp(mtype: int, body: bytes, clock: bytes, seq: int, flags: int = 0,
         control: int = 5, interval: int = 0) -> bytes:
    return struct.pack("!BBHBBHqI8sHHBb", mtype & 0x0F, 2, 34 + len(body), 0,
                       0, flags, 0, 0, clock, 1, seq & 0xFFFF, control,
                       interval) + body


def _ptp_messages(ep: Endpoints, count: int):
    """(from_master, event, payload) tuples: Announce, two-step Sync +
    Follow_Up, and an end-to-end Delay_Req / Delay_Resp per interval."""
    gm, slave = _clock_id(ep.server_mac), _clock_id(ep.client_mac)
    t0 = time.time()
    out = []
    for i in range(count):
        t = t0 + i
        if i % 2 == 0:                             # Announce every 2 s
            ann = (_ptp_ts(0) + struct.pack("!hBBBBHB", 37, 0, 128, 6, 0x21,
                                            0x4E5D, 128) +
                   gm + struct.pack("!HB", 0, 0x20))       # steps 0, GPS
            out.append((True, False, _ptp(0x0B, ann, gm, i // 2,
                                          flags=0x003C, interval=1)))
        out.append((True, True, _ptp(0x00, bytes(10), gm, i, flags=0x0200,
                                     control=0, interval=0)))
        out.append((True, False, _ptp(0x08, _ptp_ts(t), gm, i, control=2,
                                      interval=0)))
        out.append((False, True, _ptp(0x01, bytes(10), slave, i, control=1,
                                      interval=0x7F)))
        out.append((True, False, _ptp(0x09, _ptp_ts(t + 0.000412) + slave +
                                      struct.pack("!H", 1), gm, i, control=3,
                                      interval=0)))
    return out


def ptp_flow(ep: Endpoints, count: int) -> List[bytes]:
    """IEEE 1588v2 PTP over UDP multicast 224.0.1.129 (TTL 1): grandmaster
    Announce (GPS, clockClass 6, priority 128/128), Sync + Follow_Up on
    319/320, slave Delay_Req and grandmaster Delay_Resp."""
    frames = []
    for i, (master, event, msg) in enumerate(_ptp_messages(ep, count)):
        mac, ip = ((ep.server_mac, ep.server_ip) if master else
                   (ep.client_mac, ep.client_ip))
        port = 319 if event else 320
        seg = P.udp(ip, _PTP_MCAST_IP, port, port, msg)
        pkt = P.ipv4(ip, _PTP_MCAST_IP, P.IPPROTO_UDP, seg, ttl=1, ident=i)
        frames.append(P.ethernet(_PTP_MCAST_MAC, mac, P.ETH_P_IP, pkt,
                                 vlan=ep.vlan))
    return frames


def ptp_l2_flow(ep: Endpoints, count: int) -> List[bytes]:
    """IEEE 1588v2 PTP over Ethernet (0x88f7, 01:1b:19:00:00:00): the same
    Announce / Sync / Follow_Up / Delay_Req / Delay_Resp exchange."""
    return [_l2(_PTP_L2_MCAST, ep.server_mac if master else ep.client_mac,
                ETH_P_PTP, msg, vlan=ep.vlan)
            for master, _, msg in _ptp_messages(ep, count)]


# ===========================================================================
# Registry
# ===========================================================================
_reg("pn-dcp", "PROFINET DCP Identify", "OT", "-", "l2", pn_dcp_flow,
     "Identify All multicast + device response (name, Siemens ID, role, IP)")
_reg("pn-dcp-set", "PROFINET DCP Get/Set", "OT", "-", "l2", pn_dcp_set_flow,
     "Get name/IP, then Set IP / Set NameOfStation on a device")
_reg("pn-rt", "PROFINET RT cyclic", "OT", "-", "l2", pn_rt_flow,
     "RT_CLASS_1 cyclic IO frames, cycle counter + data status")
_reg("goose", "IEC 61850 GOOSE", "OT", "-", "l2", goose_flow,
     "Trip/breaker GOOSE with stNum/sqNum retransmission, VLAN prio 4")
_reg("sv", "IEC 61850 Sampled Val", "OT", "-", "l2", sv_flow,
     "9-2LE merging-unit ASDUs: 4 currents + 4 voltages, smpCnt")
_reg("mms", "IEC 61850 MMS", "OT", "102", "tcp", mms_flow,
     "ISO assoc + Initiate, Identify, GetNameList, Read of MMXU TotW")
_reg("ptp", "PTP (IEEE 1588v2)", "IT", "319", "udp", ptp_flow,
     "Grandmaster Announce, Sync/Follow_Up, Delay_Req/Resp (UDP multicast)")
_reg("ptp-l2", "PTP over Ethernet", "IT", "-", "l2", ptp_l2_flow,
     "IEEE 1588 L2 (0x88f7) Announce, Sync/Follow_Up, Delay_Req/Resp")
