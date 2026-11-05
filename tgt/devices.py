"""Device-profile catalog — one entry per hardware/OS model.

Each :class:`DeviceModel` is keyed by a stable model id (``"rockwell-1756-l83e"``)
and holds everything TGT knows about that product: vendor and MAC OUIs, the
device class and Purdue level, the firmware releases a deployed unit may run,
how its serial number looks, the modules in its rack, the identity values it
reports on each industrial protocol, the banners it serves, whether it is an
embedded device (and so cannot run an EDR agent), and CVEs that apply to it.

An environment host names its model (or it is resolved from the product string
the environment already uses, see :func:`resolve`); the firmware and serial a
host reports are then picked deterministically from its *name*, so the same
host always reports the same revision and serial across runs while two PLCs of
the same model can differ. The same values feed the wire (EtherNet/IP List
Identity, S7 SZL reads) and the ground-truth inventory, so a monitor's asset
list can be scored field by field.

Identity values are real where the vendor publishes them (CIP vendor ids,
BACnet vendor ids, Siemens order numbers, MAC OUIs as listed in Wireshark's
``manuf``). Where no public table exists — Rockwell product codes, most serial
formats, firmware lists — the values are representative of what real units
report. ``known_cves`` lists only advisories that apply to every firmware
choice offered for that model.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class Module:
    """One module in a device's rack/chassis (slot 0 is usually the CPU)."""
    slot: int
    catalog: str          # vendor catalog / order number
    desc: str
    rack: int = 0


@dataclass(frozen=True)
class DeviceModel:
    model_id: str
    vendor: str
    product: str                  # product family / model name
    device_type: str              # plc, drive, meter, relay, rtu, bms-controller,
                                  # bms-supervisor, server-os, workstation-os
    ouis: Tuple[str, ...]         # lowercase "aa:bb:cc"; first is the default
    purdue_level: str             # "0".."4"; "" = set by where the host sits
    os_family: str                # firmware / OS family, human readable
    firmware: Tuple[str, ...]     # releases a deployed unit may run
    serial_format: str = ""       # see :func:`make_serial`; "" = not modeled
    modules: Tuple[Module, ...] = ()
    # protocol -> identity parameters the device reports on that protocol
    # ("cip", "s7", "modbus", "bacnet", "dnp3", "iec104")
    identity: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    # "http" (Server header), "snmp_sysdescr", "snmp_sysobjectid", "smb_os";
    # str.format() templates over {product} {firmware} {serial} {name}
    banners: Dict[str, str] = field(default_factory=dict)
    embedded: bool = True
    edr_capable: bool = False
    known_cves: Tuple[str, ...] = ()
    aliases: Tuple[str, ...] = ()  # product strings that resolve to this model

    def __hash__(self) -> int:     # the dict fields make the default unhashable
        return hash(self.model_id)


# ---------------------------------------------------------------------------
# MAC OUIs (all present in Wireshark's manuf database)
# ---------------------------------------------------------------------------
OUI_VMWARE = "00:50:56"
OUI_DELL = "00:06:5b"
_ROCKWELL = ("00:1d:9c", "00:00:bc", "f4:54:33", "5c:88:16", "e4:90:69",
             "34:c0:f9")
_SIEMENS = ("00:0e:8c", "00:1b:1b", "08:00:06", "28:63:36", "ac:64:17")
_SIEMENS_ENERGY = ("00:0e:8c", "b4:b1:5a")
_SCHNEIDER = ("00:80:f4", "00:00:54")
_JCI = ("00:10:8d",)
_TRIDIUM = ("00:01:f0",)
_SEL = ("00:30:a7",)
_PC = (OUI_VMWARE, OUI_DELL)

# Hardware NICs that say nothing about the software running on them.
_HW_OUI_VENDORS = {OUI_VMWARE: "VMware", OUI_DELL: "Dell"}

# ---------------------------------------------------------------------------
# Serial-number formats: '#' digit, '?' letter A-Z, '%' hex digit, '*' A-Z/0-9;
# anything else is literal.
# ---------------------------------------------------------------------------
_CIP_SERIAL = "%%%%%%%%"           # CIP UDINT, shown as 8 hex digits
_S7_SERIAL = "S C-?#?#########"    # e.g. "S C-H6T437592009"

_ROCKWELL_SNMP = "1.3.6.1.4.1.95"  # Allen-Bradley enterprise arc (representative)
_SIEMENS_SNMP = "1.3.6.1.4.1.4329.6.1.2"
_SIEMENS_SYSDESCR = ("Siemens, SIMATIC S7, {product}, {order}, HW: Version 1, "
                     "FW: Version {firmware}, {serial}")

_WIN_SYSDESCR = ("Hardware: Intel64 Family 6 Model 85 Stepping 7 AT/AT "
                 "COMPATIBLE - Software: Windows Version {ntver} (Build {build} "
                 "Multiprocessor Free)")

CATALOG: Dict[str, DeviceModel] = {}


def _add(m: DeviceModel) -> None:
    if m.model_id in CATALOG:
        raise ValueError(f"duplicate device model {m.model_id}")
    CATALOG[m.model_id] = m


# ---------------------------------------------------------------------------
# Rockwell Automation / Allen-Bradley
# ---------------------------------------------------------------------------
_LOGIX_CVES = ("CVE-2021-22681",)   # Logix Designer key exposure, all versions


def _logix(model_id, product, name, code, fw, aliases, modules=()):
    _add(DeviceModel(
        model_id, "Rockwell Automation", product, "plc", _ROCKWELL, "1",
        "Logix controller firmware", fw, _CIP_SERIAL, modules,
        identity={"cip": {"vendor_id": 1, "device_type": 0x0E,
                          "product_code": code, "product_name": name}},
        banners={"http": "",
                 "snmp_sysdescr": "Rockwell Automation {product} "
                                  "Firmware {firmware}",
                 "snmp_sysobjectid": _ROCKWELL_SNMP},
        known_cves=_LOGIX_CVES, aliases=aliases))


_CLX_RACK = (Module(1, "1756-EN2T", "EtherNet/IP bridge"),
             Module(2, "1756-IB16", "16-pt 24 V DC input"),
             Module(3, "1756-OB16E", "16-pt 24 V DC output"),
             Module(4, "1756-IF8", "8-ch analog input"))

_logix("rockwell-1756-l71", "ControlLogix 5570 1756-L71",
       "1756-L71/B LOGIX5571", 92,
       ("20.055", "24.011", "30.014", "32.011", "33.011"),
       ("1756-L71/B LOGIX5571",),
       (Module(0, "1756-L71", "ControlLogix 5570 controller, 2 MB"),)
       + _CLX_RACK)
_logix("rockwell-1756-l83e", "ControlLogix 5580 1756-L83E",
       "1756-L83E/B", 166,
       ("30.011", "32.011", "33.011", "34.011", "35.011"),
       ("1756-L83E ControlLogix 5580",),
       (Module(0, "1756-L83E", "ControlLogix 5580 controller, 10 MB"),)
       + _CLX_RACK)
_logix("rockwell-1769-l36erm", "CompactLogix 5370 1769-L36ERM",
       "1769-L36ERM/B LOGIX5336ERM", 155,
       ("24.011", "28.012", "30.011", "32.011", "33.011"),
       ("1769-L36ERM CompactLogix",),
       (Module(0, "1769-L36ERM", "CompactLogix 5370 controller"),
        Module(1, "1769-IQ16", "16-pt 24 V DC input"),
        Module(2, "1769-OB16", "16-pt 24 V DC output")))
_logix("rockwell-5069-l320er", "CompactLogix 5380 5069-L320ER",
       "5069-L320ER/A", 187,
       ("31.011", "32.011", "33.011", "34.011", "35.011"),
       ("5069-L320ER CompactLogix 5380",),
       (Module(0, "5069-L320ER", "CompactLogix 5380 controller"),
        Module(1, "5069-IB16", "16-pt 24 V DC input"),
        Module(2, "5069-OB16", "16-pt 24 V DC output")))

_add(DeviceModel(
    "rockwell-powerflex-755", "Rockwell Automation", "PowerFlex 755 AC drive",
    "drive", _ROCKWELL, "0", "PowerFlex drive firmware",
    ("11.003", "12.001", "13.002", "14.002"), _CIP_SERIAL,
    (Module(0, "20-750-ENETR", "Dual-port EtherNet/IP option"),),
    identity={"cip": {"vendor_id": 1, "device_type": 0x02,
                      "product_code": 2192, "product_name": "PowerFlex 755"}},
    banners={"http": "", "snmp_sysdescr": "PowerFlex 755 {firmware}"},
    aliases=("PowerFlex 755",)))

# ---------------------------------------------------------------------------
# Siemens SIMATIC
# ---------------------------------------------------------------------------
_S7_300_CVES = ("CVE-2016-9159",)   # S7-300/400 credential disclosure, all vers.
_S7_1500_CVES = ("CVE-2022-38465",)  # S7-1500 global private key, < V2.9.2


def _s7(model_id, product, order, module, fw, cves, aliases, modules=()):
    _add(DeviceModel(
        model_id, "Siemens", product, "plc", _SIEMENS, "1",
        "SIMATIC S7 firmware", fw, _S7_SERIAL, modules,
        identity={"s7": {"order": order, "module": module}},
        banners={"http": "", "snmp_sysdescr": _SIEMENS_SYSDESCR,
                 "snmp_sysobjectid": _SIEMENS_SNMP},
        known_cves=cves, aliases=aliases))


_s7("siemens-cpu-315-2pndp", "SIMATIC S7-300 CPU 315-2 PN/DP",
    "6ES7 315-2EH14-0AB0", "CPU 315-2 PN/DP",
    ("V3.2.6", "V3.2.8", "V3.2.12", "V3.2.17"), _S7_300_CVES,
    ("6ES7 315-2EH14-0AB0",),
    (Module(2, "6ES7 315-2EH14-0AB0", "CPU 315-2 PN/DP"),
     Module(4, "6ES7 321-1BL00-0AA0", "SM 321 DI32"),
     Module(5, "6ES7 322-1BL00-0AA0", "SM 322 DO32")))
_s7("siemens-cpu-317-2pndp", "SIMATIC S7-300 CPU 317-2 PN/DP",
    "6ES7 317-2EK14-0AB0", "CPU 317-2 PN/DP",
    ("V3.2.6", "V3.2.8", "V3.2.12", "V3.2.17"), _S7_300_CVES,
    ("6ES7 317-2EK14-0AB0",),
    (Module(2, "6ES7 317-2EK14-0AB0", "CPU 317-2 PN/DP"),
     Module(4, "6ES7 331-7KF02-0AB0", "SM 331 AI8")))
_s7("siemens-im151-8-pndp", "SIMATIC ET 200S IM151-8 PN/DP CPU",
    "6ES7 151-8AB01-0AB0", "IM151-8 PN/DP CPU",
    ("V3.2.6", "V3.2.8", "V3.2.12"), _S7_300_CVES,
    ("6ES7 151-8AB01-0AB0",),
    (Module(0, "6ES7 151-8AB01-0AB0", "IM151-8 PN/DP CPU"),
     Module(1, "6ES7 131-4BD01-0AA0", "4DI DC24V")))
_s7("siemens-cpu-1516-3pndp", "SIMATIC S7-1500 CPU 1516-3 PN/DP",
    "6ES7 516-3AN01-0AB0", "CPU 1516-3 PN/DP",
    ("V2.6.1", "V2.8.1", "V2.8.3"), _S7_1500_CVES,
    ("6ES7 516-3AN01-0AB0",),
    (Module(1, "6ES7 516-3AN01-0AB0", "CPU 1516-3 PN/DP"),
     Module(2, "6ES7 521-1BL00-0AB0", "DI 32x24VDC HF"),
     Module(3, "6ES7 522-1BL01-0AB0", "DQ 32x24VDC/0.5A HF")))

_add(DeviceModel(
    "siemens-sicam-cp-8050", "Siemens", "SICAM A8000 CP-8050 master module",
    "rtu", _SIEMENS_ENERGY, "2", "SICAM A8000 firmware (CPCI85)",
    ("CPCI85 V04.80", "CPCI85 V04.92"), "BF#########",
    (Module(0, "6MF2805-0AA00", "CP-8050 master module"),),
    identity={"iec104": {"order": "6MF2805-0AA00", "common_address": 1}},
    banners={"http": "", "snmp_sysdescr": "SICAM A8000 CP-8050 {firmware}",
             "snmp_sysobjectid": "1.3.6.1.4.1.4329"},
    known_cves=("CVE-2023-28489",),   # web server RCE, < CPCI85 V05
    aliases=("SICAM A8000 CP-8050",)))

# ---------------------------------------------------------------------------
# Schneider Electric
# ---------------------------------------------------------------------------
_MODICON_CVES = ("CVE-2021-22779",)  # ModiPwn: UMAS auth bypass, M340 + M580

_add(DeviceModel(
    "schneider-bmx-p34-2020", "Schneider Electric", "Modicon M340 BMX P34 2020",
    "plc", _SCHNEIDER, "1", "Modicon M340 firmware",
    ("V2.90", "V3.10", "V3.20"), "####?####",
    (Module(0, "BMX P34 2020", "M340 CPU, Modbus/TCP"),
     Module(1, "BMX DDI 1602", "16-pt DI"),
     Module(2, "BMX DDO 1602", "16-pt DQ")),
    identity={"modbus": {"vendor": "Schneider Electric",
                         "product_code": "BMX P34 2020",
                         "product_name": "BMX P34 2020"}},
    banners={"http": "Schneider-WEB/V2.1.4",
             "snmp_sysdescr": "Schneider Electric BMX P34 2020 {firmware}",
             "snmp_sysobjectid": "1.3.6.1.4.1.3833.1.7.255.3"},
    known_cves=_MODICON_CVES,
    aliases=("BMX P34 2020 Modicon M340", "BMX P34 2020")))
_add(DeviceModel(
    "schneider-bme-p58-2040", "Schneider Electric", "Modicon M580 BME P58 2040",
    "plc", _SCHNEIDER, "1", "Modicon M580 firmware",
    ("V2.90", "V3.10"), "####?####",
    (Module(0, "BME P58 2040", "M580 CPU, EtherNet/IP + Modbus/TCP"),
     Module(2, "BME NOC 0301", "EtherNet/IP comms module")),
    identity={"modbus": {"vendor": "Schneider Electric",
                         "product_code": "BME P58 2040",
                         "product_name": "BME P58 2040"},
              "cip": {"vendor_id": 243, "device_type": 0x0E,
                      "product_name": "BME P58 2040"}},
    banners={"http": "Schneider-WEB/V2.1.4",
             "snmp_sysdescr": "Schneider Electric BME P58 2040 {firmware}",
             "snmp_sysobjectid": "1.3.6.1.4.1.3833.1.7.255.3"},
    known_cves=_MODICON_CVES,
    aliases=("BME P58 2040 Modicon M580", "BME P58 2040")))
_add(DeviceModel(
    "schneider-pm5560", "Schneider Electric", "PowerLogic PM5560 power meter",
    "meter", _SCHNEIDER, "1", "PowerLogic meter firmware",
    ("V2.3.3", "V2.7.4", "V3.0.2"), "##########",
    identity={"modbus": {"vendor": "Schneider Electric",
                         "product_code": "METSEPM5560",
                         "product_name": "PM5560"}},
    banners={"http": "", "snmp_sysdescr": "PM5560 {firmware}"},
    aliases=("PowerLogic PM5560",)))

# ---------------------------------------------------------------------------
# Building management
# ---------------------------------------------------------------------------
_add(DeviceModel(
    "tridium-jace-8000", "Tridium", "Niagara JACE-8000 controller",
    "bms-supervisor", _TRIDIUM, "2", "QNX / Niagara 4",
    ("4.10.1.36", "4.12.1.16", "4.13.3.48"), "Qnx-TITAN-%%%%-%%%%-%%%%-%%%%",
    identity={"bacnet": {"vendor_id": 36, "model_name": "JACE-8000"}},
    banners={"http": "Niagara Web Server",
             "snmp_sysdescr": "Niagara 4 JACE-8000 {firmware}"},
    aliases=("JACE-8000",)))
_add(DeviceModel(
    "jci-fec2611", "Johnson Controls", "Metasys FEC2611 field equipment "
    "controller", "bms-controller", _JCI, "1", "Metasys FEC firmware",
    ("10.1.0", "11.0.0", "12.0.0"), "##?######",
    identity={"bacnet": {"vendor_id": 5, "model_name": "FEC2611-0"}},
    aliases=("Metasys FEC2611",)))

# ---------------------------------------------------------------------------
# Schweitzer Engineering Laboratories — substation protection + automation
# ---------------------------------------------------------------------------
def _sel(model_id, product, dtype, level, fw, aliases, dnp3):
    _add(DeviceModel(
        model_id, "Schweitzer Engineering Laboratories", product, dtype, _SEL,
        level, "SEL firmware", fw, "##########",
        identity={"dnp3": dnp3},
        banners={"http": "", "snmp_sysdescr": "{product} {firmware}"},
        aliases=aliases))


_sel("sel-751", "SEL-751 feeder protection relay", "relay", "1",
     ("R404-V0", "R416-V1", "R420-V2"), ("SEL-751",),
     {"role": "outstation"})
_sel("sel-487e", "SEL-487E transformer protection relay", "relay", "1",
     ("R318-V1", "R323-V0"), ("SEL-487E",),
     {"role": "outstation"})
_sel("sel-351s", "SEL-351S protection system", "relay", "1",
     ("R516-V1", "R521-V0"), ("SEL-351S",),
     {"role": "outstation"})
_sel("sel-3530", "SEL-3530 Real-Time Automation Controller (RTAC)", "rtu",
     "2", ("R148-V2", "R150-V3", "R151-V1"), ("SEL-3530 RTAC",),
     {"role": "master+outstation"})

# ---------------------------------------------------------------------------
# General-purpose OS families (IT, supervisory, HMIs, engineering stations)
# ---------------------------------------------------------------------------
def _os(model_id, vendor, product, dtype, os_family, fw, banners, edr,
        cves=()):
    _add(DeviceModel(
        model_id, vendor, product, dtype, _PC, "", os_family, fw, "",
        banners=banners, embedded=False, edr_capable=edr, known_cves=cves))


def _win_banners(ntver, build, smb, http="Microsoft-IIS/10.0", server=True):
    return {"http": http, "smb_os": smb,
            "snmp_sysdescr": _WIN_SYSDESCR.replace("{ntver}", ntver)
                                          .replace("{build}", build),
            "snmp_sysobjectid": "1.3.6.1.4.1.311.1.1.3.1." +
                                ("2" if server else "1")}


_os("microsoft-windows-server-2019", "Microsoft", "Windows Server 2019",
    "server-os", "Windows",
    ("10.0.17763.5329", "10.0.17763.5696", "10.0.17763.6054"),
    _win_banners("6.3", "17763", "Windows Server 2019 Standard 17763"), True)
_os("microsoft-windows-server-2012r2", "Microsoft", "Windows Server 2012 R2",
    "server-os", "Windows",
    ("6.3.9600.20778", "6.3.9600.21620"),
    _win_banners("6.3", "9600", "Windows Server 2012 R2 Standard 9600",
                 "Microsoft-IIS/8.5"), True)
_os("microsoft-windows-10", "Microsoft", "Windows 10 Enterprise",
    "workstation-os", "Windows",
    ("10.0.19044.3086", "10.0.19045.3803", "10.0.19045.4291"),
    _win_banners("6.3", "19045", "Windows 10 Enterprise 19045",
                 server=False), True)
# EOL, SMBv1-enabled builds that predate MS17-010 (and BlueKeep's patch)
_os("microsoft-windows-7", "Microsoft", "Windows 7 Professional SP1",
    "workstation-os", "Windows",
    ("6.1.7601.17514", "6.1.7601.23403"),
    _win_banners("6.1", "7601", "Windows 7 Professional 7601 Service Pack 1",
                 server=False), True,
    ("CVE-2017-0144", "CVE-2019-0708"))
_os("microsoft-windows-xp", "Microsoft", "Windows XP Professional SP3",
    "workstation-os", "Windows", ("5.1.2600.5512",),
    _win_banners("5.1", "2600", "Windows 5.1", server=False), False,
    ("CVE-2008-4250", "CVE-2017-0144", "CVE-2019-0708"))
_os("microsoft-windows-2000", "Microsoft", "Windows 2000 SP4",
    "server-os", "Windows", ("5.0.2195.6717",),
    _win_banners("5.0", "2195", "Windows 5.0", "Microsoft-IIS/5.0"), False,
    ("CVE-2008-4250", "CVE-2017-0144"))
_os("canonical-ubuntu-linux", "Canonical", "Ubuntu Server 22.04 LTS",
    "server-os", "Linux",
    ("5.15.0-91-generic", "5.15.0-105-generic", "6.8.0-45-generic"),
    {"http": "Apache", "smb_os": "Unix",
     "snmp_sysdescr": "Linux {name} {firmware} #1 SMP x86_64",
     "snmp_sysobjectid": "1.3.6.1.4.1.8072.3.2.10"}, True)

# The OS-family model a general-purpose host gets from its fingerprint key.
OS_DEFAULT_MODEL: Dict[str, str] = {
    "win2019": "microsoft-windows-server-2019",
    "win2012": "microsoft-windows-server-2012r2",
    "win10": "microsoft-windows-10",
    "win7": "microsoft-windows-7",
    "winxp": "microsoft-windows-xp",
    "win2000": "microsoft-windows-2000",
    "linux": "canonical-ubuntu-linux",
}

_ALIASES: Dict[str, str] = {a: m.model_id for m in CATALOG.values()
                            for a in m.aliases}

# OUI -> vendor, as an analyser labels a MAC prefix
OUI_VENDORS: Dict[str, str] = dict(_HW_OUI_VENDORS)
for _m in CATALOG.values():
    if _m.embedded:
        for _o in _m.ouis:
            OUI_VENDORS.setdefault(_o, _m.vendor)

# OUIs that only ever front embedded devices (PLC/RTU/relay/drive/meter/BMS)
EMBEDDED_OUIS = frozenset(o for m in CATALOG.values() if m.embedded
                          for o in m.ouis)


# ---------------------------------------------------------------------------
# Lookups + per-host derivation
# ---------------------------------------------------------------------------
def get(model_id: str) -> DeviceModel:
    return CATALOG[model_id]


def find(model_id: str) -> Optional[DeviceModel]:
    return CATALOG.get(model_id) if model_id else None


def resolve(product: str) -> str:
    """Model id for a product string an environment uses ("" if unknown)."""
    return _ALIASES.get(product, "")


def os_default(os_key: str) -> str:
    """OS-family model id for a general-purpose fingerprint key ("" if none)."""
    return OS_DEFAULT_MODEL.get(os_key, "")


def _digest(*parts: str) -> bytes:
    return hashlib.sha256("|".join(parts).encode()).digest()


def pick_firmware(model: DeviceModel, host_name: str) -> str:
    """The firmware release ``host_name`` runs — stable per host name."""
    if not model.firmware:
        return ""
    n = int.from_bytes(_digest("firmware", host_name)[:4], "big")
    return model.firmware[n % len(model.firmware)]


_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def make_serial(model: DeviceModel, host_name: str) -> str:
    """The serial number ``host_name`` reports, in the model's format."""
    if not model.serial_format:
        return ""
    stream = _digest("serial", model.model_id, host_name)
    stream += _digest("serial2", model.model_id, host_name)
    out = []
    for i, ch in enumerate(model.serial_format):
        b = stream[i % len(stream)]
        if ch == "#":
            out.append("0123456789"[b % 10])
        elif ch == "?":
            out.append(_ALNUM[b % 26])
        elif ch == "%":
            # a CIP serial with a leading zero nibble reads oddly; avoid it
            out.append("0123456789ABCDEF"[b % 16 if i else 1 + b % 15])
        elif ch == "*":
            out.append(_ALNUM[b % 36])
        else:
            out.append(ch)
    return "".join(out)


def _numbers(firmware: str) -> List[int]:
    """[33, 11] from "33.011", [3, 2, 17] from "V3.2.17", [4, 92] from
    "CPCI85 V04.92" (the last dotted run of digits)."""
    tok = firmware.split()[-1].lstrip("Vv") if firmware else ""
    out = []
    for p in tok.split("."):
        digits = "".join(c for c in p if c.isdigit())
        if not digits:
            break
        out.append(int(digits))
    return out


def cip_revision(firmware: str) -> Tuple[int, int]:
    """CIP Identity revision (major, minor) from a Logix-style release."""
    n = _numbers(firmware) + [0, 0]
    return n[0] & 0xFF, n[1] & 0xFF


def s7_version(firmware: str) -> Tuple[int, int, int]:
    """S7 firmware (major, minor, patch) from "V3.2.17"."""
    n = _numbers(firmware) + [0, 0, 0]
    return n[0] & 0xFF, n[1] & 0xFF, n[2] & 0xFF


def banner(model: DeviceModel, key: str, host_name: str, firmware: str,
           serial: str) -> str:
    """A banner template filled in for one host."""
    tpl = model.banners.get(key, "")
    s7 = model.identity.get("s7", {})
    return tpl.format(product=s7.get("module", model.product),
                      order=s7.get("order", ""), firmware=firmware,
                      serial=serial, name=host_name)


def identity_meta(model: Optional[DeviceModel], firmware: str,
                  serial: str) -> Dict[str, Any]:
    """Endpoint ``meta`` keys the identity builders read for a device
    (``protocols.enip_identity_flow`` / ``protocols.s7_identity_flow``)."""
    if model is None:
        return {}
    meta: Dict[str, Any] = {}
    cip = model.identity.get("cip")
    if cip:
        meta["vendor_id"] = cip["vendor_id"]
        meta["device_type"] = cip["device_type"]
        if "product_code" in cip:
            meta["cip_product_code"] = cip["product_code"]
        if firmware:
            meta["cip_revision"] = cip_revision(firmware)
        if serial and all(c in "0123456789ABCDEF" for c in serial):
            meta["cip_serial"] = int(serial, 16)
    s7 = model.identity.get("s7")
    if s7:
        meta["s7_module"] = s7["module"]
        if firmware:
            meta["s7_firmware"] = s7_version(firmware)
        if serial:
            meta["s7_serial"] = serial
    return meta
