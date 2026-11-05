"""Vertical-site protocol builders: ring redundancy (MRP, DLR), clinical
(DICOM, HL7 v2 over MLLP), building automation (KNXnet/IP, BACnet COV) and
batch recipe writes (Logix CIP Write Tag).

Imported from the bottom of :mod:`tgt.protocols`, which owns the registry.

* ``mrp``        IEC 62439-2 Media Redundancy Protocol: the ring manager's
  MRP_Test frames (EtherType 0x88e3, to 01:15:4e:00:00:01) out of both ring
  ports. Self-announcement: client = server = the ring manager (MRM).
* ``dlr``        EtherNet/IP Device Level Ring: the active ring supervisor's
  Beacon frames (EtherType 0x80e1, to 01:21:6c:00:00:01) out of both ports.
  Self-announcement: client = server = the supervisor.
* ``dicom``      DICOM upper layer on TCP 104: A-ASSOCIATE-RQ/AC (AE titles,
  implementation class UID + version name), C-ECHO, ``count`` C-STOREs of a
  small CT image (placeholder patient "ANON^TEST") and A-RELEASE. client =
  SCU (modality), server = SCP (PACS).
* ``hl7``        HL7 v2.5.1 over MLLP (TCP 2575): ADT^A01 / ORU^R01 messages
  from the sending application (client) acknowledged by the receiver
  (server) with ACK / MSA|AA.
* ``knxip``      KNXnet/IP (UDP 3671): SEARCH_REQUEST to 224.0.23.12 +
  SEARCH_RESPONSE, DESCRIPTION_REQUEST/RESPONSE (device info, friendly
  name, serial) and ROUTING_INDICATION group writes. client = visualisation
  / ETS, server = KNX IP router. Multicast, so link-local.
* ``bacnet-cov`` BACnet/IP SubscribeCOV (+ SimpleACK) from a BMS supervisor
  and the controller's UnconfirmedCOVNotification stream.
* ``smb-logon``  SMB2 session setup (SPNEGO-wrapped NTLMSSP) naming the
  domain, user and workstation, then a TREE_CONNECT to a share — enough
  for a monitor to see which account a host logs on with (a service account
  shared across hosts, say).
* ``enip-write`` Logix CIP Read Tag / Write Tag (services 0x4C / 0x4D in an
  Unconnected Send to slot 0): a batch recipe parameter download — the event
  behind "recipe changed" / "tag write" alerts.

Identity comes from ``ep.meta``: the server's catalog identity
(:func:`tgt.devices.identity_meta` — ``dicom_*``, ``hl7_*``, ``knx_*``) and,
for DICOM / HL7 where the *client* states who it is, the client's identity
under a ``client_`` prefix (``Environment`` fills both). Every builder has
defaults so it also runs stand-alone.

Timing note: the real MRP test interval is 20 ms (200 ms recovery profile)
or 50 ms (500 ms profile) and the DLR beacon interval 400 µs; the beacon
frames state those protocol values, while environment files declare a slower
emission ``period`` so a capture stays readable (see each site's flows).
"""
from __future__ import annotations

import struct
import zlib
from typing import List

from . import packet as P
from .packet import Endpoints
from .protocols import (LINK_LOCAL, _cpf, _cycle_base, _drift, _enip, _reg,
                        _sport, _tcp_flow)

ETH_P_MRP = 0x88E3
ETH_P_DLR = 0x80E1

_MRP_TEST_MAC = "01:15:4e:00:00:01"
_DLR_BEACON_MAC = "01:21:6c:00:00:01"
_KNX_MCAST_IP = "224.0.23.12"
_KNX_MCAST_MAC = "01:00:5e:00:17:0c"

# 2026-10-06 12:00:00 UTC (the DNP3 / NTP time base used across TGT)
_EPOCH_S = 1791288000


def _l2(dst: str, src: str, ethertype: int, payload: bytes,
        vlan: int | None, pcp: int) -> bytes:
    """802.1Q-tagged (VID ``vlan`` or 0 = priority-tagged) Ethernet frame,
    padded to the 60-byte minimum."""
    frame = (P.mac_to_bytes(dst) + P.mac_to_bytes(src) +
             struct.pack("!HHH", P.ETH_P_VLAN,
                         ((pcp & 7) << 13) | ((vlan or 0) & 0x0FFF),
                         ethertype) + payload)
    return frame.ljust(60, b"\x00")


def _stamp(count: int, i: int, step: int = 1) -> tuple:
    """(Y, M, D, h, m, s) wall clock of message ``i`` this cycle."""
    import time
    t = _EPOCH_S + (_cycle_base(count) + i) * step
    return time.gmtime(t)[:6]


def _hl7_ts(count: int, i: int) -> str:
    return "%04d%02d%02d%02d%02d%02d" % _stamp(count, i, 7)


# ===========================================================================
# MRP — IEC 62439-2 Media Redundancy Protocol (ring manager test frames)
# ===========================================================================
def mrp_flow(ep: Endpoints, count: int) -> List[bytes]:
    """MRP_Test frames from the ring manager: one out of each ring port
    (primary, then secondary) per message, ring state closed, with the
    manager priority, its bridge MAC (MRP_SA), the transition counter and a
    millisecond timestamp, then MRP_Common (sequence id + domain UUID) and
    MRP_End. Tagged priority 7, as IEC 62439-2 asks for MRP PDUs.

    ``ep.meta``: ``mrp_prio`` (default 0x8000, the MRM default),
    ``mrp_domain_uuid`` (32 hex digits; default all-ones, the default
    domain), ``mrp_interval_ms`` (test interval the timestamps advance by,
    default 20), ``mrp_transitions`` (ring open/close count, default 0)."""
    prio = int(ep.meta.get("mrp_prio", 0x8000))
    uuid = bytes.fromhex(str(ep.meta.get("mrp_domain_uuid", "ff" * 16)))
    step = int(ep.meta.get("mrp_interval_ms", 20))
    trans = int(ep.meta.get("mrp_transitions", 0))
    sa = P.mac_to_bytes(ep.server_mac)
    cb = _cycle_base(count)
    up_ms = 0x0C000000 + (zlib.crc32(sa) & 0xFFFFF)   # ~2.3 days since boot
    frames = []
    for i in range(max(1, count)):
        for role in (0, 1):                       # primary, secondary port
            seq = (2 * (cb + i) + role) & 0xFFFF
            ts = (up_ms + (cb + i) * step) & 0xFFFFFFFF
            test = struct.pack("!BBH6sHHHI", 0x02, 18, prio, sa, role, 0x0001,
                               trans, ts)
            common = struct.pack("!BBH", 0x01, 18, seq) + uuid
            pdu = struct.pack("!H", 1) + test + common + b"\x00\x00"
            frames.append(_l2(_MRP_TEST_MAC, ep.server_mac, ETH_P_MRP, pdu,
                              ep.vlan, 7))
    return frames


# ===========================================================================
# DLR — EtherNet/IP Device Level Ring (supervisor beacons)
# ===========================================================================
def dlr_flow(ep: Endpoints, count: int) -> List[bytes]:
    """DLR Beacon frames from the active ring supervisor, one per ring port
    per message: ring state NORMAL, supervisor precedence, beacon interval /
    timeout (µs, as configured — default 400 / 1960) and the supervisor's
    IP. Priority-7 tagged, big-endian fields as on the wire.

    ``ep.meta``: ``dlr_precedence`` (default 0), ``dlr_beacon_interval``,
    ``dlr_beacon_timeout`` (µs), ``dlr_ring_state`` (1 normal, 2 fault)."""
    prec = int(ep.meta.get("dlr_precedence", 0))
    interval = int(ep.meta.get("dlr_beacon_interval", 400))
    timeout = int(ep.meta.get("dlr_beacon_timeout", 1960))
    state = int(ep.meta.get("dlr_ring_state", 1))
    ip = P.ip_to_bytes(ep.server_ip)
    cb = _cycle_base(count)
    frames = []
    for i in range(max(1, count)):
        for port in (1, 2):
            seq = (2 * (cb + i) + port) & 0xFFFFFFFF
            pdu = (struct.pack("!BBBB4sI", 0x02, 0x01, 0x01, port, ip, seq) +
                   struct.pack("!BBII", state, prec, interval, timeout) +
                   bytes(20))
            frames.append(_l2(_DLR_BEACON_MAC, ep.server_mac, ETH_P_DLR, pdu,
                              ep.vlan, 7))
    return frames


# ===========================================================================
# DICOM upper layer (PS3.8) over TCP 104
# ===========================================================================
_DCM_APP_CTX = "1.2.840.10008.3.1.1.1"
_DCM_VERIFY = "1.2.840.10008.1.1"
_DCM_CT = "1.2.840.10008.5.1.4.1.1.2"         # CT Image Storage
_DCM_IMPLICIT = "1.2.840.10008.1.2"
_DCM_EXPLICIT = "1.2.840.10008.1.2.1"
_LONG_VR = ("OB", "OW", "OF", "SQ", "UT", "UN")


def _dcm_uid(uid: str) -> bytes:
    b = uid.encode()
    return b + (b"\x00" if len(b) & 1 else b"")


def _dcm_text(s: str) -> bytes:
    b = s.encode()
    return b + (b" " if len(b) & 1 else b"")


def _dcm_ae(s: str) -> bytes:
    return s.strip().upper()[:16].ljust(16).encode()


def _dcm_item(t: int, data: bytes) -> bytes:
    return struct.pack("!BBH", t, 0, len(data)) + data


def _dcm_assoc(pdu: int, called: str, calling: str, items: bytes) -> bytes:
    body = struct.pack("!HH", 1, 0) + _dcm_ae(called) + _dcm_ae(calling) + \
        bytes(32) + items
    return struct.pack("!BBI", pdu, 0, len(body)) + body


def _dcm_user_info(impl_uid: str, version: str) -> bytes:
    return _dcm_item(0x50,
                     _dcm_item(0x51, struct.pack("!I", 16384)) +
                     _dcm_item(0x52, impl_uid.encode()) +
                     _dcm_item(0x55, version[:16].encode()))


def _dcm_cmd(elems: list) -> bytes:
    """Command set (implicit VR little endian) with its group length."""
    body = b"".join(struct.pack("<HHI", 0, e, len(v)) + v for e, v in elems)
    return struct.pack("<HHII", 0, 0, 4, len(body)) + body


def _dcm_el(group: int, elem: int, vr: str, val: bytes) -> bytes:
    """One explicit-VR little-endian data element."""
    if vr in _LONG_VR:
        return struct.pack("<HH2sHI", group, elem, vr.encode(), 0,
                           len(val)) + val
    return struct.pack("<HH2sH", group, elem, vr.encode(), len(val)) + val


def _dcm_pdata(pcid: int, command: bool, data: bytes) -> bytes:
    """P-DATA-TF with one PDV (the last fragment of a command or data set)."""
    pdv = struct.pack("!IBB", len(data) + 2, pcid, (1 if command else 0) | 2)
    return struct.pack("!BBI", 0x04, 0, len(pdv) + len(data)) + pdv + data


def _uid2(*parts) -> str:
    """A UUID-derived DICOM UID (2.25.<decimal>), stable per ``parts``."""
    n = int.from_bytes(zlib.crc32(repr(parts).encode()).to_bytes(4, "big") +
                       zlib.crc32(repr(parts[::-1]).encode()).to_bytes(4, "big")
                       + zlib.adler32(repr(parts).encode()).to_bytes(4, "big"),
                       "big")
    return f"2.25.{n}"


def _dcm_us(v: int) -> bytes:
    return struct.pack("<H", v)


def dicom_flow(ep: Endpoints, count: int) -> List[bytes]:
    """DICOM (TCP 104): a modality (SCU) associates with the PACS (SCP),
    verifies it with C-ECHO and sends ``count`` CT images with C-STORE,
    then releases the association.

    The A-ASSOCIATE-RQ carries the calling / called AE titles and the
    SCU's implementation class UID + version name; the A-ASSOCIATE-AC the
    SCP's. Each image's data set (explicit VR little endian) names the
    modality's manufacturer, model, station, serial number and software
    version — device identity a monitor can read off the wire — beside a
    placeholder patient (``ANON^TEST``): cleartext PHI by design.

    ``ep.meta`` (server = PACS): ``dicom_ae``, ``dicom_impl_uid``,
    ``dicom_impl_version``; (client = modality, ``client_`` prefix):
    ``client_dicom_ae``, ``client_dicom_impl_uid``,
    ``client_dicom_impl_version``, ``client_dicom_manufacturer``,
    ``client_dicom_model``, ``client_dicom_modality``,
    ``client_dicom_software``, ``client_dicom_serial``; ``dicom_institution``.
    """
    m = ep.meta
    called = str(m.get("dicom_ae") or m.get("host") or "PACS_SCP")
    calling = str(m.get("client_dicom_ae") or m.get("nbname") or "MODALITY")
    rq_uid = str(m.get("client_dicom_impl_uid", "1.2.276.0.7230010.3.0.3.6.7"))
    rq_ver = str(m.get("client_dicom_impl_version", "OFFIS_DCMTK_367"))
    ac_uid = str(m.get("dicom_impl_uid", "1.2.40.0.13.1.3"))
    ac_ver = str(m.get("dicom_impl_version", "dcm4che-5.31.0"))
    maker = str(m.get("client_dicom_manufacturer", "GE MEDICAL SYSTEMS"))
    model = str(m.get("client_dicom_model", "Revolution EVO"))
    modality = str(m.get("client_dicom_modality", "CT"))
    software = str(m.get("client_dicom_software", "Revo_EVO.SP2"))
    serial = str(m.get("client_dicom_serial", "TGT0001"))
    institution = str(m.get("dicom_institution", "TGT GENERAL HOSPITAL"))

    ts = _dcm_item(0x40, _DCM_EXPLICIT.encode())
    rq = _dcm_assoc(0x01, called, calling,
                    _dcm_item(0x10, _DCM_APP_CTX.encode()) +
                    _dcm_item(0x20, bytes([1, 0, 0, 0]) +
                              _dcm_item(0x30, _DCM_VERIFY.encode()) +
                              _dcm_item(0x40, _DCM_IMPLICIT.encode())) +
                    _dcm_item(0x20, bytes([3, 0, 0, 0]) +
                              _dcm_item(0x30, _DCM_CT.encode()) + ts +
                              _dcm_item(0x40, _DCM_IMPLICIT.encode())) +
                    _dcm_user_info(rq_uid, rq_ver))
    ac = _dcm_assoc(0x02, called, calling,
                    _dcm_item(0x10, _DCM_APP_CTX.encode()) +
                    _dcm_item(0x21, bytes([1, 0, 0, 0]) +
                              _dcm_item(0x40, _DCM_IMPLICIT.encode())) +
                    _dcm_item(0x21, bytes([3, 0, 0, 0]) + ts) +
                    _dcm_user_info(ac_uid, ac_ver))
    exchanges = [(rq, ac)]

    cb = _cycle_base(count)
    msg_id = (cb * 2 + 1) & 0xFFFF or 1
    echo = _dcm_cmd([(0x0002, _dcm_uid(_DCM_VERIFY)), (0x0100, _dcm_us(0x0030)),
                     (0x0110, _dcm_us(msg_id)), (0x0800, _dcm_us(0x0101))])
    echo_rsp = _dcm_cmd([(0x0002, _dcm_uid(_DCM_VERIFY)),
                         (0x0100, _dcm_us(0x8030)), (0x0120, _dcm_us(msg_id)),
                         (0x0800, _dcm_us(0x0101)), (0x0900, _dcm_us(0))])
    exchanges.append((_dcm_pdata(1, True, echo), _dcm_pdata(1, True, echo_rsp)))

    y, mo, d, hh, mm, ss = _stamp(count, 0, 60)
    study = _uid2("study", ep.client_ip, cb)
    series = _uid2("series", ep.client_ip, cb)
    pix = bytes((7 * r + 11 * c) & 0xFF for r in range(8) for c in range(8))
    for i in range(max(1, count)):
        mid = (msg_id + 1 + i) & 0xFFFF or 1
        inst = _uid2("sop", ep.client_ip, cb + i)
        cmd = _dcm_cmd([(0x0002, _dcm_uid(_DCM_CT)), (0x0100, _dcm_us(0x0001)),
                        (0x0110, _dcm_us(mid)), (0x0700, _dcm_us(0)),
                        (0x0800, _dcm_us(0x0000)), (0x1000, _dcm_uid(inst))])
        ds = b"".join([
            _dcm_el(0x0008, 0x0005, "CS", _dcm_text("ISO_IR 100")),
            _dcm_el(0x0008, 0x0008, "CS", _dcm_text("ORIGINAL\\PRIMARY\\AXIAL")),
            _dcm_el(0x0008, 0x0016, "UI", _dcm_uid(_DCM_CT)),
            _dcm_el(0x0008, 0x0018, "UI", _dcm_uid(inst)),
            _dcm_el(0x0008, 0x0020, "DA", b"%04d%02d%02d" % (y, mo, d)),
            _dcm_el(0x0008, 0x0030, "TM", b"%02d%02d%02d" % (hh, mm, ss)),
            _dcm_el(0x0008, 0x0050, "SH", _dcm_text(f"ACC{cb % 100000:05d}")),
            _dcm_el(0x0008, 0x0060, "CS", _dcm_text(modality)),
            _dcm_el(0x0008, 0x0070, "LO", _dcm_text(maker)),
            _dcm_el(0x0008, 0x0080, "LO", _dcm_text(institution)),
            _dcm_el(0x0008, 0x1010, "SH", _dcm_text(calling.strip()[:16])),
            _dcm_el(0x0008, 0x1090, "LO", _dcm_text(model)),
            _dcm_el(0x0010, 0x0010, "PN", _dcm_text("ANON^TEST")),
            _dcm_el(0x0010, 0x0020, "LO", _dcm_text(f"TGT{cb % 100000:05d}")),
            _dcm_el(0x0010, 0x0030, "DA", b"19700101"),
            _dcm_el(0x0010, 0x0040, "CS", _dcm_text("O")),
            _dcm_el(0x0018, 0x1000, "LO", _dcm_text(serial)),
            _dcm_el(0x0018, 0x1020, "LO", _dcm_text(software)),
            _dcm_el(0x0020, 0x000D, "UI", _dcm_uid(study)),
            _dcm_el(0x0020, 0x000E, "UI", _dcm_uid(series)),
            _dcm_el(0x0020, 0x0013, "IS", _dcm_text(str(i + 1))),
            _dcm_el(0x0028, 0x0002, "US", _dcm_us(1)),
            _dcm_el(0x0028, 0x0004, "CS", _dcm_text("MONOCHROME2")),
            _dcm_el(0x0028, 0x0010, "US", _dcm_us(8)),
            _dcm_el(0x0028, 0x0011, "US", _dcm_us(8)),
            _dcm_el(0x0028, 0x0100, "US", _dcm_us(8)),
            _dcm_el(0x0028, 0x0101, "US", _dcm_us(8)),
            _dcm_el(0x0028, 0x0102, "US", _dcm_us(7)),
            _dcm_el(0x0028, 0x0103, "US", _dcm_us(0)),
            _dcm_el(0x7FE0, 0x0010, "OB", pix),
        ])
        rsp = _dcm_cmd([(0x0002, _dcm_uid(_DCM_CT)), (0x0100, _dcm_us(0x8001)),
                        (0x0120, _dcm_us(mid)), (0x0800, _dcm_us(0x0101)),
                        (0x0900, _dcm_us(0)), (0x1000, _dcm_uid(inst))])
        exchanges.append((_dcm_pdata(3, True, cmd), b""))
        exchanges.append((_dcm_pdata(3, False, ds), _dcm_pdata(3, True, rsp)))
    rel = struct.pack("!BBI", 0x05, 0, 4) + bytes(4)
    exchanges.append((rel, struct.pack("!BBI", 0x06, 0, 4) + bytes(4)))
    return _tcp_flow(ep, _sport(), 104, exchanges, idle_from=1)


# ===========================================================================
# HL7 v2 over MLLP (TCP 2575)
# ===========================================================================
_HL7_PATIENTS = (("ANON", "TEST", "19700101", "U"),
                 ("SAMPLE", "PATIENT", "19820315", "F"),
                 ("DOE", "JOHN", "19590722", "M"))


def _mllp(segments: List[str]) -> bytes:
    return b"\x0b" + "\r".join(segments).encode() + b"\r\x1c\x0d"


def hl7_flow(ep: Endpoints, count: int) -> List[bytes]:
    """HL7 v2.5.1 over MLLP (TCP 2575): the sending application (client)
    delivers ``count`` messages — ADT^A01 admissions and ORU^R01 vital-sign
    results, per ``ep.meta['hl7_events']`` ("adt", "oru" or "mixed", the
    default) — each acknowledged by the receiver with ACK / MSA|AA. MSH
    names both applications and facilities; PID carries placeholder patient
    demographics in cleartext (the PHI a monitor should flag).

    ``ep.meta``: receiver ``hl7_app`` / ``hl7_facility``; sender
    ``client_hl7_app`` / ``client_hl7_facility`` (default the host names)."""
    m = ep.meta
    r_app = str(m.get("hl7_app") or m.get("host") or "INTERFACE_ENGINE")
    r_fac = str(m.get("hl7_facility", "TGT_HOSP"))
    s_app = str(m.get("client_hl7_app") or m.get("nbname") or "EHR")
    s_fac = str(m.get("client_hl7_facility", r_fac))
    events = str(m.get("hl7_events", "mixed"))
    cb = _cycle_base(count)
    exchanges = []
    for i in range(max(1, count)):
        n = cb + i
        ts = _hl7_ts(count, i)
        ctrl = f"{s_app[:4].upper()}{n + 1:08d}"
        fam, given, dob, sex = _HL7_PATIENTS[n % len(_HL7_PATIENTS)]
        mrn = f"MRN{100000 + n % 900000}"
        pid = (f"PID|1||{mrn}^^^{s_fac}^MR||{fam}^{given}||{dob}|{sex}|||"
               f"1 MAIN ST^^SPRINGFIELD^ST^00000||(555)555-0100")
        oru = events == "oru" or (events == "mixed" and i % 2 == 1)
        if oru:
            trig = "R01"
            hr = 72 + round(6 * _drift(f"hl7hr:{ep.client_ip}", n))
            spo2 = 97 + round(_drift(f"hl7sp:{ep.client_ip}", n))
            body = [pid,
                    f"PV1|1|I|ICU^{101 + n % 12}^A^{s_fac}",
                    f"OBR|1||OBS{n + 1:08d}|VITALS^Vital signs^L|||{ts}",
                    f"OBX|1|NM|8867-4^Heart rate^LN||{hr}|/min^beats per "
                    f"minute^UCUM|60-100||||F|||{ts}",
                    f"OBX|2|NM|59408-5^Oxygen saturation^LN||{spo2}|%^percent"
                    f"^UCUM|90-100||||F|||{ts}"]
            msh9 = "ORU^R01^ORU_R01"
        else:
            trig = "A01"
            body = [f"EVN|A01|{ts}", pid,
                    f"PV1|1|I|MED^{201 + n % 30}^B^{s_fac}||||"
                    f"1234567^ATTENDING^TEST^^^DR|||MED||||1|||"
                    f"1234567^ATTENDING^TEST^^^DR|IN||||||||||||||||||||"
                    f"{s_fac}||||{ts}"]
            msh9 = "ADT^A01^ADT_A01"
        msg = [f"MSH|^~\\&|{s_app}|{s_fac}|{r_app}|{r_fac}|{ts}||{msh9}|"
               f"{ctrl}|P|2.5.1"] + body
        ack = [f"MSH|^~\\&|{r_app}|{r_fac}|{s_app}|{s_fac}|{ts}||ACK^{trig}^"
               f"ACK|ACK{n + 1:08d}|P|2.5.1", f"MSA|AA|{ctrl}"]
        exchanges.append((_mllp(msg), _mllp(ack)))
    return _tcp_flow(ep, _sport(), 2575, exchanges, idle_from=0)


# ===========================================================================
# KNXnet/IP (UDP 3671)
# ===========================================================================
def _knx(service: int, body: bytes) -> bytes:
    return struct.pack("!BBHH", 0x06, 0x10, service, 6 + len(body)) + body


def _knx_hpai(ip: str, port: int) -> bytes:
    return struct.pack("!BB4sH", 8, 1, P.ip_to_bytes(ip), port)


def _knx_addr(s: str) -> int:
    a, b, c = (int(x) for x in str(s).split("."))
    return (a & 0xF) << 12 | (b & 0xF) << 8 | (c & 0xFF)


def _knx_dibs(ep: Endpoints) -> bytes:
    m = ep.meta
    name = str(m.get("knx_name") or m.get("host") or "KNX IP Router")
    serial = int(m.get("knx_serial", zlib.crc32(P.mac_to_bytes(ep.server_mac))))
    dev = struct.pack("!BBBBHH6s4s6s30s", 0x36, 0x01, 0x02, 0x00,
                      _knx_addr(m.get("knx_addr", "1.1.0")), 0x0000,
                      (int(m.get("knx_manufacturer", 0x0083)) << 32 |
                       (serial & 0xFFFFFFFF)).to_bytes(6, "big"),
                      P.ip_to_bytes(_KNX_MCAST_IP), P.mac_to_bytes(ep.server_mac),
                      name.encode()[:29])
    fams = struct.pack("!BB", 10, 0x02) + bytes([0x02, 1, 0x03, 1, 0x04, 1,
                                                 0x05, 1])
    return dev + fams


def _knx_mcast(ep: Endpoints, from_client: bool, payload: bytes,
               ident: int) -> bytes:
    src_ip = ep.client_ip if from_client else ep.server_ip
    src_mac = ep.client_mac if from_client else ep.server_mac
    seg = P.udp(src_ip, _KNX_MCAST_IP, 3671, 3671, payload)
    pkt = P.ipv4(src_ip, _KNX_MCAST_IP, P.IPPROTO_UDP, seg, ttl=16,
                 ident=ident)
    return P.ethernet(_KNX_MCAST_MAC, src_mac, P.ETH_P_IP, pkt, vlan=ep.vlan)


def knxip_flow(ep: Endpoints, count: int) -> List[bytes]:
    """KNXnet/IP: the visualisation server (client) searches for KNX IP
    devices (SEARCH_REQUEST to 224.0.23.12:3671), the router answers with
    its device-information DIB (individual address, serial, MAC, friendly
    name) and supported service families; a DESCRIPTION_REQUEST/RESPONSE
    follows, then ``count`` ROUTING_INDICATIONs on the multicast group —
    cEMI L_Data.ind group-value writes from the KNX line (lighting switch,
    DPT 9 temperature). ``ep.meta``: ``knx_name``, ``knx_addr``
    ("1.1.0"), ``knx_serial``, ``knx_manufacturer`` (default 0x0083 MDT)."""
    sport = 3671
    frames = [
        _knx_mcast(ep, True, _knx(0x0201, _knx_hpai(ep.client_ip, sport)), 1),
        P.udp_frame(ep, False, 3671, sport,
                    _knx(0x0202, _knx_hpai(ep.server_ip, 3671) +
                         _knx_dibs(ep)), ident=1),
        P.udp_frame(ep, True, sport, 3671,
                    _knx(0x0203, _knx_hpai(ep.client_ip, sport)), ident=2),
        P.udp_frame(ep, False, 3671, sport, _knx(0x0204, _knx_dibs(ep)),
                    ident=2),
    ]
    src = _knx_addr(ep.meta.get("knx_line_device", "1.1.21"))
    cb = _cycle_base(count)
    for i in range(max(1, count)):
        n = cb + i
        if i % 2 == 0:                          # 1/0/n switch on/off (DPT 1)
            dst = (1 << 11) | (n % 8)
            apdu = struct.pack("!BB", 0x00, 0x80 | (n // 8) % 2)
        else:                                   # 3/1/n temperature (DPT 9)
            dst = (3 << 11) | (1 << 8) | (n % 8)
            t = 21.0 + _drift(f"knx:{ep.server_ip}:{n % 8}", n)
            mant, exp = int(round(t * 100)), 0
            while mant > 2047:
                mant >>= 1
                exp += 1
            apdu = struct.pack("!BBH", 0x00, 0x80, (exp << 11) | mant)
        cemi = struct.pack("!BBBBHHB", 0x29, 0x00, 0xBC, 0xE0, src, dst,
                           len(apdu) - 1) + apdu
        frames.append(_knx_mcast(ep, False, _knx(0x0530, cemi), 3 + i))
    return frames


# ===========================================================================
# BACnet change-of-value subscriptions
# ===========================================================================
def _bvlc(func: int, npdu: bytes, apdu: bytes) -> bytes:
    return struct.pack("!BBH", 0x81, func, 4 + len(npdu) + len(apdu)) + \
        npdu + apdu


def bacnet_cov_flow(ep: Endpoints, count: int) -> List[bytes]:
    """BACnet/IP COV: the BMS supervisor (client) SubscribeCOVs to an
    analog-input (confirmed, 1 h lifetime; SimpleACK), then the controller
    (server) pushes ``count`` UnconfirmedCOVNotifications with present-value
    and status-flags. Device instance from ``ep.meta['bacnet_instance']``."""
    inst = int(ep.meta.get("bacnet_instance", 1001)) & 0x3FFFFF
    obj = (0 << 22) | 1                        # analog-input,1
    dev = (8 << 22) | inst
    pid = 0x40 + (zlib.crc32(P.ip_to_bytes(ep.client_ip)) & 0x3F)
    cb = _cycle_base(count)
    invoke = (cb + pid) & 0xFF
    sub = (struct.pack("!BBBB", 0x00, 0x05, invoke, 0x05) +
           b"\x09" + bytes([pid]) + b"\x1c" + struct.pack("!I", obj) +
           b"\x29\x00" + b"\x3a\x0e\x10")    # [2] confirmed=FALSE, [3] 3600 s
    frames = [P.udp_frame(ep, True, 47808, 47808,
                          _bvlc(0x0A, b"\x01\x04", sub), ident=0),
              P.udp_frame(ep, False, 47808, 47808,
                          _bvlc(0x0A, b"\x01\x00",
                                struct.pack("!BBB", 0x20, invoke, 0x05)),
                          ident=0)]
    for i in range(max(1, count)):
        v = 22.0 + 1.2 * _drift(f"cov:{ep.server_ip}", cb + i)
        note = (struct.pack("!BB", 0x10, 0x02) +
                b"\x09" + bytes([pid]) +
                b"\x1c" + struct.pack("!I", dev) +
                b"\x2c" + struct.pack("!I", obj) +
                b"\x3a" + struct.pack("!H", 3600 - 60 * (i % 60)) +
                b"\x4e" +
                b"\x09\x55\x2e\x44" + struct.pack("!f", v) + b"\x2f" +
                b"\x09\x6f\x2e\x82\x04\x00\x2f" +
                b"\x4f")
        frames.append(P.udp_frame(ep, False, 47808, 47808,
                                  _bvlc(0x0A, b"\x01\x00", note), ident=1 + i))
    return frames


# ===========================================================================
# Logix CIP Read Tag / Write Tag — batch recipe download
# ===========================================================================
def _sym(name: str) -> bytes:
    b = name.encode()
    seg = bytes([0x91, len(b)]) + b
    return seg + (b"\x00" if len(b) & 1 else b"")


def _tag_path(tag: str) -> bytes:
    path = b"".join(_sym(p) for p in tag.split("."))
    return bytes([len(path) // 2]) + path


def _ucmm(session: int, ctx: int, req: bytes) -> bytes:
    """SendRRData carrying an Unconnected Send (Connection Manager) of
    ``req`` routed to the controller in backplane slot 0."""
    us = (bytes([0x52, 0x02, 0x20, 0x06, 0x24, 0x01, 0x0A, 0xF0]) +
          struct.pack("<H", len(req)) + req +
          (b"\x00" if len(req) & 1 else b"") +
          bytes([0x01, 0x00, 0x01, 0x00]))      # route: port 1 (backplane), slot 0
    return _enip(0x006F, session, struct.pack("<IH", 0, 10) +
                 _cpf((0x0000, b""), (0x00B2, us)), context=ctx)


def _rr(session: int, ctx: int, rsp: bytes) -> bytes:
    return _enip(0x006F, session, struct.pack("<IH", 0, 10) +
                 _cpf((0x0000, b""), (0x00B2, rsp)), context=ctx)


def enip_write_flow(ep: Endpoints, count: int) -> List[bytes]:
    """EtherNet/IP (44818): a batch recipe download to a Logix controller —
    Read Tag of the active recipe id, Write Tag of each phase parameter
    (REAL setpoints, DINT durations) and the download command bit, then a
    read-back. One operation per build, whatever ``count``. The recipe and
    unit come from ``ep.meta['recipe']`` / ``ep.meta['recipe_unit']``."""
    recipe = str(ep.meta.get("recipe", "API_GRAN_V12"))
    unit = str(ep.meta.get("recipe_unit", "BR101"))
    session = 0x52430000 | (zlib.crc32(P.ip_to_bytes(ep.client_ip)) & 0xFFFF)
    params = [(f"{unit}_RCP.Temp_SP", 0xCA, struct.pack("<f", 62.5)),
              (f"{unit}_RCP.Agit_RPM", 0xCA, struct.pack("<f", 120.0)),
              (f"{unit}_RCP.Hold_Min", 0xC4, struct.pack("<i", 45)),
              (f"{unit}_RCP.Charge_Kg", 0xCA, struct.pack("<f", 250.0)),
              (f"{unit}_RCP.Download", 0xC4, struct.pack("<i", 1))]
    ok = lambda svc: bytes([svc | 0x80, 0, 0, 0])      # noqa: E731
    name = recipe.encode()[:32]
    exchanges = [(_enip(0x0065, 0, struct.pack("<HH", 1, 0)),
                  _enip(0x0065, session, struct.pack("<HH", 1, 0)))]
    rd = bytes([0x4C]) + _tag_path(f"{unit}_RCP.Recipe_ID") + b"\x01\x00"
    exchanges.append((_ucmm(session, 1, rd),
                      _rr(session, 1, ok(0x4C) + b"\xc4\x00" +
                          struct.pack("<i", 11))))
    for k, (tag, typ, val) in enumerate(params):
        wr = bytes([0x4D]) + _tag_path(tag) + struct.pack("<HH", typ, 1) + val
        exchanges.append((_ucmm(session, 2 + k, wr),
                          _rr(session, 2 + k, ok(0x4D))))
    # recipe name (STRING: DINT LEN + SINT[82]) as the audit trail sees it
    sval = struct.pack("<i", len(name)) + name.ljust(82, b"\x00")
    wr = bytes([0x4D]) + _tag_path(f"{unit}_RCP.Name") + \
        struct.pack("<HHH", 0xA0, 0x0FCE, 1) + sval
    ctx = 2 + len(params)
    exchanges.append((_ucmm(session, ctx, wr), _rr(session, ctx, ok(0x4D))))
    rd = bytes([0x4C]) + _tag_path(f"{unit}_RCP.Temp_SP") + b"\x01\x00"
    exchanges.append((_ucmm(session, ctx + 1, rd),
                      _rr(session, ctx + 1, ok(0x4C) + b"\xca\x00" +
                          struct.pack("<f", 62.5))))
    exchanges.append((_enip(0x0066, session, b""), b""))
    return _tcp_flow(ep, _sport(), 44818, exchanges)


# ===========================================================================
# SMB2 session setup with NTLMSSP — who logs on to a share
# ===========================================================================
_OID_SPNEGO = b"\x06\x06\x2b\x06\x01\x05\x05\x02"
_OID_NTLM = b"\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
_NTLM_VERSION = struct.pack("<BBHBBBB", 10, 0, 19041, 0, 0, 0, 15)


def _u16(s: str) -> bytes:
    return s.encode("utf-16-le")


def _smb2(cmd: int, mid: int, resp: bool, body: bytes, status: int = 0,
          tid: int = 0, sid: int = 0) -> bytes:
    hdr = b"\xfeSMB" + struct.pack("<HHIHHIIQIIQ", 64, 1, status, cmd,
                                   1 if not resp else 33, 1 if resp else 0,
                                   0, mid, 0xFEFF, tid, sid) + bytes(16)
    msg = hdr + body
    return struct.pack("!I", len(msg)) + msg


def _ntlm_fields(payload: List[bytes], base: int) -> tuple:
    """(len/maxlen/offset field headers, concatenated payload)."""
    hdrs, off = b"", base
    for p in payload:
        hdrs += struct.pack("<HHI", len(p), len(p), off)
        off += len(p)
    return hdrs, b"".join(payload)


def _av_pairs(domain: str, server: str, dns_domain: str, ts: int) -> bytes:
    def av(t: int, v: bytes) -> bytes:
        return struct.pack("<HH", t, len(v)) + v
    host = server.lower()
    return (av(2, _u16(domain)) + av(1, _u16(server)) +
            av(4, _u16(dns_domain)) + av(3, _u16(f"{host}.{dns_domain}")) +
            av(5, _u16(dns_domain)) + av(7, struct.pack("<Q", ts)) +
            av(0, b""))


def smb_logon_flow(ep: Endpoints, count: int) -> List[bytes]:
    """SMB2 (445): NEGOTIATE, SESSION_SETUP with SPNEGO-wrapped NTLMSSP
    (NEGOTIATE / CHALLENGE / AUTHENTICATE — the AUTHENTICATE message names
    the domain, user and workstation in cleartext), TREE_CONNECT to a share,
    ``count`` ECHOs, TREE_DISCONNECT and LOGOFF. ``ep.meta``: ``smb_user``
    (default the client host name + "$"), ``smb_domain`` (default the
    realm's first label), ``smb_share`` (default "share")."""
    from .protocols import _der
    m = ep.meta
    realm = str(m.get("realm", "CORP.LOCAL"))
    domain = str(m.get("smb_domain") or realm.split(".")[0]).upper()
    wks = str(m.get("nbname") or "WORKSTATION").upper()
    user = str(m.get("smb_user") or f"{wks}$")
    server = str(m.get("host") or "FILESERVER").upper()
    share = str(m.get("smb_share", "share"))
    seed = zlib.crc32(f"{ep.client_ip}>{ep.server_ip}:{user}".encode())
    filetime = 134041248000000000 + (_cycle_base(count) * 10_000_000)
    sid = 0x0000100000000000 | (seed & 0xFFFFFFFF) << 4 | 0x9
    tid = 1 + (seed >> 24) % 7

    neg_flags, chal_flags, auth_flags = 0xE2088297, 0xE2898215, 0xE2888215
    ntlm_neg = (b"NTLMSSP\x00" + struct.pack("<II", 1, neg_flags) +
                bytes(16) + _NTLM_VERSION)
    target = _av_pairs(domain, server, realm.lower(), filetime)
    tname = _u16(domain)
    hdrs, payload = _ntlm_fields([tname], 56)
    t_hdr = struct.pack("<HHI", len(target), len(target), 56 + len(tname))
    challenge = struct.pack("<Q", (seed * 0x9E3779B97F4A7C15) & (2**64 - 1))
    ntlm_chal = (b"NTLMSSP\x00" + struct.pack("<I", 2) + hdrs +
                 struct.pack("<I", chal_flags) + challenge + bytes(8) + t_hdr +
                 _NTLM_VERSION + payload + target)
    proof = zlib.crc32(challenge + user.encode()).to_bytes(4, "big") * 4
    cchal = struct.pack("<Q", (seed * 0xC2B2AE3D27D4EB4F) & (2**64 - 1))
    blob = (struct.pack("<BBHIQ", 1, 1, 0, 0, filetime) + cchal + bytes(4) +
            target[:-4] + struct.pack("<HHI", 6, 4, 2) + b"\x00\x00\x00\x00" +
            bytes(4))
    nt_resp = proof + blob
    session_key = zlib.crc32(nt_resp).to_bytes(4, "big") * 4
    fields, payload = _ntlm_fields(
        [bytes(24), nt_resp, _u16(domain), _u16(user), _u16(wks),
         session_key], 88)
    ntlm_auth = (b"NTLMSSP\x00" + struct.pack("<I", 3) + fields +
                 struct.pack("<I", auth_flags) + _NTLM_VERSION + bytes(16) +
                 payload)

    init = _der(0x60, _OID_SPNEGO + _der(0xA0, _der(0x30,
                _der(0xA0, _der(0x30, _OID_NTLM)) +
                _der(0xA2, _der(0x04, ntlm_neg)))))
    resp1 = _der(0xA1, _der(0x30, _der(0xA0, b"\x0a\x01\x01") +
                            _der(0xA1, _OID_NTLM) +
                            _der(0xA2, _der(0x04, ntlm_chal))))
    auth = _der(0xA1, _der(0x30, _der(0xA2, _der(0x04, ntlm_auth))))
    resp2 = _der(0xA1, _der(0x30, _der(0xA0, b"\x0a\x01\x00")))

    def setup(blob_: bytes) -> bytes:
        return struct.pack("<HBBIIHHQ", 25, 0, 1, 1, 0, 88, len(blob_), 0) + \
            blob_

    def setup_rsp(blob_: bytes) -> bytes:
        return struct.pack("<HHHH", 9, 0, 72, len(blob_)) + blob_

    dialects = (0x0202, 0x0210, 0x0300, 0x0302)
    guid = bytes(10) + P.mac_to_bytes(ep.client_mac)
    neg = struct.pack("<HHHHI16sQ", 36, len(dialects), 0x01, 0, 0x7F, guid,
                      0) + struct.pack(f"<{len(dialects)}H", *dialects)
    sguid = bytes(10) + P.mac_to_bytes(ep.server_mac)
    neg_rsp = struct.pack("<HHHH16sIIIIQQHHI", 65, 0x01, 0x0302, 0, sguid,
                          0x2F, 8388608, 8388608, 8388608, filetime, 0, 0x80,
                          0, 0)
    path = _u16(f"\\\\{server}\\{share}")
    tree = struct.pack("<HHHH", 9, 0, 72, len(path)) + path
    tree_rsp = struct.pack("<HBBIII", 16, 1, 0, 0x00000800, 0, 0x001F01FF)
    four = struct.pack("<HH", 4, 0)
    ex = [(_smb2(0, 0, False, neg), _smb2(0, 0, True, neg_rsp)),
          (_smb2(1, 1, False, setup(init)),
           _smb2(1, 1, True, setup_rsp(resp1), 0xC0000016, sid=sid)),
          (_smb2(1, 2, False, setup(auth), sid=sid),
           _smb2(1, 2, True, setup_rsp(resp2), sid=sid)),
          (_smb2(3, 3, False, tree, sid=sid),
           _smb2(3, 3, True, tree_rsp, tid=tid, sid=sid))]
    mid = 4
    for _ in range(max(1, count)):
        ex.append((_smb2(0x0D, mid, False, four, tid=tid, sid=sid),
                   _smb2(0x0D, mid, True, four, tid=tid, sid=sid)))
        mid += 1
    ex.append((_smb2(4, mid, False, four, tid=tid, sid=sid),
               _smb2(4, mid, True, four, tid=tid, sid=sid)))
    ex.append((_smb2(2, mid + 1, False, four, sid=sid),
               _smb2(2, mid + 1, True, four, sid=sid)))
    return _tcp_flow(ep, _sport(), 445, ex)


# ===========================================================================
# Registry
# ===========================================================================
_reg("mrp", "MRP ring (IEC 62439-2)", "OT", "-", "l2", mrp_flow,
     "Ring manager MRP_Test frames from both ring ports (prio, SA, ring "
     "state, transitions), MRP_Common domain UUID")
_reg("dlr", "DLR ring (EtherNet/IP)", "OT", "-", "l2", dlr_flow,
     "Ring supervisor Beacon frames from both ports: ring state, precedence, "
     "beacon interval/timeout, supervisor IP")
_reg("dicom", "DICOM", "OT", "104", "tcp", dicom_flow,
     "A-ASSOCIATE (AE titles, implementation UID/version), C-ECHO, C-STORE "
     "CT images with modality identity + placeholder PHI, A-RELEASE")
_reg("hl7", "HL7 v2 (MLLP)", "IT", "2575", "tcp", hl7_flow,
     "ADT^A01 / ORU^R01 over MLLP with MSH sending/receiving app + facility, "
     "ACK MSA|AA replies (cleartext PHI)")
_reg("knxip", "KNXnet/IP", "OT", "3671", "udp", knxip_flow,
     "SEARCH + DESCRIPTION (device DIB: KNX address, serial, name), "
     "ROUTING_INDICATION group writes on 224.0.23.12")
_reg("bacnet-cov", "BACnet COV", "OT", "47808", "udp", bacnet_cov_flow,
     "SubscribeCOV + SimpleACK, then UnconfirmedCOVNotification "
     "present-value / status-flags pushes")
_reg("enip-write", "CIP Tag Write (recipe)", "OT", "44818", "tcp",
     enip_write_flow,
     "Logix Read/Write Tag via Unconnected Send: batch recipe parameter "
     "download + read-back")

_reg("smb-logon", "SMB2 NTLM logon", "IT", "445", "tcp", smb_logon_flow,
     "NEGOTIATE, SESSION_SETUP with SPNEGO/NTLMSSP (domain\\user + "
     "workstation in cleartext), TREE_CONNECT to a share, ECHO, LOGOFF")

# KNX search / routing ride the 224.0.23.12 group, which is not routed
LINK_LOCAL.add("knxip")
