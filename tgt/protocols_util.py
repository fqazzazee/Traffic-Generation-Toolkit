"""Utility / energy engineering protocol builders (water, power, oil & gas).

Imported from the bottom of :mod:`tgt.protocols`, which owns the registry;
the builders register themselves with ``_reg`` like every other profile.

* ``sel-telnet`` — an SEL relay engineering session over Telnet (23): the
  ASCII command set every SEL protective relay, RTAC and clock answers on its
  front / Ethernet port. ``ACC`` / ``2AC`` access-level logins with the
  factory passwords in cleartext, ``ID`` (the device's FID firmware string,
  part number and serial — its identity on the wire), ``STA``, ``SHO 1`` and
  a settings change (``SET 1`` + save) — what AcSELerator QuickSet does when
  an engineer reads or changes relay settings.

Endpoint roles: client = engineering laptop / workstation, server = the SEL
device. Meta (from the device catalog, see ``devices.identity_meta``):
``sel_model`` / ``sel_firmware`` / ``sel_serial`` (falling back to the
``dnp3_*`` identity keys, then ``product``), ``host`` (the relay ID), and
``sel_password1`` / ``sel_password2`` (default: the factory ``OTTER`` /
``TAIL``).
"""
from __future__ import annotations

import time
import zlib
from typing import List

from .packet import Endpoints
from .protocols import _reg, _sport
from .protocols_eng import _session


def _m(ep: Endpoints, *keys: str, default: str = "") -> str:
    for k in keys:
        v = ep.meta.get(k)
        if v:
            return str(v)
    return default


def _sel_line(text: str) -> str:
    """One SEL ``ID`` response line: the quoted field and its checksum (the
    16-bit sum of the quoted field's characters, as 4 hex digits)."""
    field = f'"{text}"'
    return f'{field},"{sum(field.encode()) & 0xFFFF:04X}"\r\n'


def sel_identity(ep: Endpoints) -> dict:
    """FID / part number / serial an SEL device reports to ``ID``."""
    model = _m(ep, "sel_model", "dnp3_product", "product", default="SEL-751")
    fw = _m(ep, "sel_firmware", "dnp3_firmware", default="R404-V0")
    serial = _m(ep, "sel_serial", "dnp3_serial", default="1234567890")
    h = zlib.crc32(f"{model}|{fw}".encode())
    zcode = f"Z{h % 1000000:06d}"
    date = f"D20{17 + h % 8:02d}{1 + h % 12:02d}{1 + h % 28:02d}"
    digits = "".join(c for c in model if c.isdigit()) or "751"
    return {"model": model, "firmware": fw, "serial": serial,
            "fid": f"{model}-{fw}-{zcode}-{date}",
            "partno": f"{digits}{h % 100000:05d}AA3CA3A85",
            "devid": _m(ep, "host", default="RELAY1").upper()}


def sel_telnet_flow(ep: Endpoints, count: int) -> List[bytes]:
    """SEL ASCII over Telnet: login to access level 1 and 2 (cleartext
    passwords), ``ID``, ``STA``, ``SHO 1``, one settings change saved with
    ``Y``, then ``QUI``. One engineering session per build (``count`` does
    not grow it)."""
    ident = sel_identity(ep)
    pw1 = _m(ep, "sel_password1", default="OTTER")
    pw2 = _m(ep, "sel_password2", default="TAIL")
    model, devid = ident["model"], ident["devid"]
    now = time.gmtime()
    stamp = time.strftime("Date: %m/%d/%Y  Time: %H:%M:%S.000", now)
    head = f"\r\n{devid:<24}{stamp}\r\n{model:<24}\r\n\r\n"
    id_text = "".join(_sel_line(x) for x in (
        f"FID={ident['fid']}", "BFID=BOOTLDR-R500-V0-Z000000-D20120126",
        f"CID={zlib.crc32(ident['fid'].encode()) & 0xFFFF:04X}",
        f"DEVID={devid}", f"PARTNO={ident['partno']}",
        f"SERIALNO={ident['serial']}", "CONFIG=11111100",
        f"iedName={devid.replace(' ', '_')[:16]}"))
    pickup = 4.0 + zlib.crc32(devid.encode()) % 40 / 10
    steps = [
        (False, b"\r\n="),
        (True, b"ACC\r\n"),
        (False, b"ACC\r\nPassword: ? "),
        (True, f"{pw1}\r\n".encode()),
        (False, f"{head}Level 1\r\n=>".encode()),
        (True, b"ID\r\n"),
        (False, f"ID\r\n{id_text}=>".encode()),
        (True, b"STA\r\n"),
        (False, f"STA\r\n{head}FID={ident['fid']}\r\n\r\nSELF TESTS\r\n"
                "W=Warn  F=Fail\r\n\r\n   IA    IB    IC    IN\r\nOS  "
                " 2     1    -1     0\r\nRelay Enabled\r\n=>".encode()),
        (True, b"2AC\r\n"),
        (False, b"2AC\r\nPassword: ? "),
        (True, f"{pw2}\r\n".encode()),
        (False, f"{head}Level 2\r\n=>>".encode()),
        (True, b"SHO 1\r\n"),
        (False, f"SHO 1\r\nGroup 1\r\n\r\nRID      := {devid}\r\n"
                f"TID      := STATION A\r\nCTR      := 120\r\n"
                f"PTR      := 100.00\r\n50P1P    := {pickup:.2f}\r\n"
                "50P1D    := 0.00\r\n51P1P    := 1.20\r\n51P1C    := U3\r\n"
                "51P1TD   := 3.00\r\nE79      := 3\r\n=>>".encode()),
        (True, b"SET 1 50P1P\r\n"),
        (False, f"SET 1 50P1P\r\nGroup 1\r\n\r\n50P1P    := {pickup:.2f}"
                " ? ".encode()),
        (True, f"{pickup + 0.5:.2f}\r\n".encode()),
        (False, b"50P1D    := 0.00 ? "),
        (True, b"END\r\n"),
        (False, b"Save settings (Y,N) ? "),
        (True, b"Y\r\n"),
        (False, b"Y\r\nSettings Saved\r\n=>>"),
        (True, b"QUI\r\n"),
        (False, f"QUI\r\n{head}=".encode()),
    ]
    return _session(ep, _sport(), 23, steps).frames


_reg("sel-telnet", "SEL ASCII (Telnet)", "OT", "23", "tcp", sel_telnet_flow,
     "SEL relay engineering: ACC/2AC cleartext login, ID (FID/serial), "
     "SHO + SET settings change")
