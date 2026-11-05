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
    # TCP/IP stack fingerprint (tgt.stacks key); "" = from the OS fingerprint
    stack: str = ""

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
        known_cves=_LOGIX_CVES, aliases=aliases, stack="rockwell"))


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
    aliases=("PowerFlex 755",), stack="rockwell-drive"))

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
        known_cves=cves, aliases=aliases, stack="siemens"))


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
    aliases=("SICAM A8000 CP-8050",), stack="embedded"))

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
                         "vendor_url": "www.se.com",
                         "product_code": "BMX P34 2020",
                         "product_name": "BMX P34 2020"}},
    banners={"http": "Schneider-WEB/V2.1.4",
             "snmp_sysdescr": "Schneider Electric BMX P34 2020 {firmware}",
             "snmp_sysobjectid": "1.3.6.1.4.1.3833.1.7.255.3"},
    known_cves=_MODICON_CVES,
    aliases=("BMX P34 2020 Modicon M340", "BMX P34 2020"),
    stack="schneider"))
_add(DeviceModel(
    "schneider-bme-p58-2040", "Schneider Electric", "Modicon M580 BME P58 2040",
    "plc", _SCHNEIDER, "1", "Modicon M580 firmware",
    ("V2.90", "V3.10"), "####?####",
    (Module(0, "BME P58 2040", "M580 CPU, EtherNet/IP + Modbus/TCP"),
     Module(2, "BME NOC 0301", "EtherNet/IP comms module")),
    identity={"modbus": {"vendor": "Schneider Electric",
                         "vendor_url": "www.se.com",
                         "product_code": "BME P58 2040",
                         "product_name": "BME P58 2040"},
              "cip": {"vendor_id": 243, "device_type": 0x0E,
                      "product_name": "BME P58 2040"}},
    banners={"http": "Schneider-WEB/V2.1.4",
             "snmp_sysdescr": "Schneider Electric BME P58 2040 {firmware}",
             "snmp_sysobjectid": "1.3.6.1.4.1.3833.1.7.255.3"},
    known_cves=_MODICON_CVES,
    aliases=("BME P58 2040 Modicon M580", "BME P58 2040"),
    stack="schneider"))
_add(DeviceModel(
    "schneider-pm5560", "Schneider Electric", "PowerLogic PM5560 power meter",
    "meter", _SCHNEIDER, "1", "PowerLogic meter firmware",
    ("V2.3.3", "V2.7.4", "V3.0.2"), "##########",
    identity={"modbus": {"vendor": "Schneider Electric",
                         "vendor_url": "www.se.com",
                         "product_code": "METSEPM5560",
                         "product_name": "PM5560"}},
    banners={"http": "", "snmp_sysdescr": "PM5560 {firmware}"},
    aliases=("PowerLogic PM5560",), stack="embedded"))

# ---------------------------------------------------------------------------
# Building management
# ---------------------------------------------------------------------------
_add(DeviceModel(
    "tridium-jace-8000", "Tridium", "Niagara JACE-8000 controller",
    "bms-supervisor", _TRIDIUM, "2", "QNX / Niagara 4",
    ("4.10.1.36", "4.12.1.16", "4.13.3.48"), "Qnx-TITAN-%%%%-%%%%-%%%%-%%%%",
    identity={"bacnet": {"vendor_id": 36, "model_name": "JACE-8000",
                         "app_version": "Niagara {firmware}",
                         "segmentation": 0}},
    banners={"http": "Niagara Web Server",
             "snmp_sysdescr": "Niagara 4 JACE-8000 {firmware}"},
    aliases=("JACE-8000",), stack="embedded"))
_add(DeviceModel(
    "jci-fec2611", "Johnson Controls", "Metasys FEC2611 field equipment "
    "controller", "bms-controller", _JCI, "1", "Metasys FEC firmware",
    ("10.1.0", "11.0.0", "12.0.0"), "##?######",
    identity={"bacnet": {"vendor_id": 5, "model_name": "FEC2611-0"}},
    aliases=("Metasys FEC2611",), stack="embedded"))

# ---------------------------------------------------------------------------
# Schweitzer Engineering Laboratories — substation protection + automation
# ---------------------------------------------------------------------------
def _sel(model_id, product, dtype, level, fw, aliases, dnp3):
    _add(DeviceModel(
        model_id, "Schweitzer Engineering Laboratories", product, dtype, _SEL,
        level, "SEL firmware", fw, "##########",
        identity={"dnp3": {**dnp3, "product_name": aliases[0]}},
        banners={"http": "", "snmp_sysdescr": "{product} {firmware}"},
        aliases=aliases, stack="sel"))


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
# Managed Ethernet switches — LLDP/CDP, SNMP agent, syslog. A switch's Purdue
# level is where it is installed (``Environment.purdue_level`` uses its zone);
# the catalog value is only the typical placement. sysObjectIDs sit under each
# vendor's enterprise arc (9 Cisco, 248 Hirschmann, 8691 Moxa) and are
# representative. ``cdp_platform`` is the CDP Platform TLV (Cisco only).
# ---------------------------------------------------------------------------
_CISCO_ENT = ("70:0f:6a", "a0:3d:6f")       # Catalyst 9300 burned-in MACs
_CISCO_IE = ("f8:7b:20", "58:97:bd")        # IE-4000 burned-in MACs
_HIRSCHMANN = ("ec:e5:55", "00:80:63")
_MOXA = ("00:90:e8",)


def _switch(model_id, vendor, product, ouis, level, os_family, fw, serial,
            sysdescr, objid, platform="", aliases=()):
    banners = {"http": "", "snmp_sysdescr": sysdescr, "snmp_sysobjectid": objid}
    if platform:
        banners["cdp_platform"] = platform
    _add(DeviceModel(model_id, vendor, product, "switch", ouis, level,
                     os_family, fw, serial, banners=banners, aliases=aliases))


_switch("cisco-c9300-48p", "Cisco Systems", "Catalyst 9300-48P", _CISCO_ENT,
        "4", "Cisco IOS XE", ("17.6.5", "17.9.4a", "17.12.3"), "FOC####?###",
        "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software "
        "(CAT9K_IOSXE), Version {firmware}, RELEASE SOFTWARE (fc1)",
        "1.3.6.1.4.1.9.1.2494", "cisco C9300-48P", ("C9300-48P",))
_switch("cisco-ie-4000-8gt4g-e", "Cisco Systems", "Industrial Ethernet "
        "IE-4000-8GT4G-E", _CISCO_IE, "2", "Cisco IOS",
        ("15.2(7)E4", "15.2(7)E6", "15.2(8)E2"), "FDO####?###",
        "Cisco IOS Software, IE4000 Software (IE4000-UNIVERSALK9-M), "
        "Version {firmware}, RELEASE SOFTWARE (fc2)",
        "1.3.6.1.4.1.9.1.2057", "cisco IE-4000-8GT4G-E", ("IE-4000-8GT4G-E",))
_switch("hirschmann-rsp35", "Hirschmann Automation and Control",
        "RSP35 Rail Switch Power", _HIRSCHMANN, "2", "HiOS-3S",
        ("08.7.02", "09.0.04", "09.1.00"), "942######?#########",
        "Hirschmann Rail Switch Power RSP35 HiOS-3S-{firmware}",
        "1.3.6.1.4.1.248.11.2.1.6", aliases=("RSP35",))
_switch("moxa-eds-508a", "Moxa", "EDS-508A managed Ethernet switch", _MOXA,
        "2", "Moxa EDS firmware", ("V3.8", "V3.9", "V3.11"), "T?????#######",
        "EDS-508A {firmware}", "1.3.6.1.4.1.8691.7.6", aliases=("EDS-508A",))


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

# ---------------------------------------------------------------------------
# Vendor engineering-protocol devices (tgt/protocols_eng.py): Omron FINS,
# Mitsubishi SLMP, HART-IP, GE SRTP. FINS model strings, SLMP model codes and
# the HART manufacturer id (Rosemount = 38) are as the vendors document them;
# firmware lists, serial formats and the gateway's expanded device type are
# representative.
# ---------------------------------------------------------------------------
_OMRON = ("00:00:0a", "3c:f7:d1", "80:b5:c6")
_MITSUBISHI = ("00:26:92", "10:4b:46", "38:e0:8e")
_ROSEMOUNT = ("00:26:16", "00:22:e5")
_GE_IP = ("00:09:91",)                   # GE Intelligent Platforms

_add(DeviceModel(
    "omron-nj501-1500", "Omron", "Sysmac NJ501-1500 machine automation "
    "controller", "plc", _OMRON, "1", "Sysmac NJ firmware",
    ("1.40", "1.46", "1.48", "1.60"), "#####?####",
    (Module(0, "NJ501-1500", "NJ5 CPU unit, EtherNet/IP + EtherCAT"),
     Module(1, "NJ-PA3001", "Power supply unit")),
    identity={"fins": {"model": "NJ501-1500"},
              "cip": {"vendor_id": 47, "device_type": 0x0E,
                      "product_name": "NJ501-1500"}},
    banners={"http": "", "snmp_sysdescr": "OMRON NJ501-1500 Ver.{firmware}"},
    aliases=("NJ501-1500",)))
_add(DeviceModel(
    "mitsubishi-r04cpu", "Mitsubishi Electric", "MELSEC iQ-R R04CPU",
    "plc", _MITSUBISHI, "1", "MELSEC iQ-R firmware",
    ("28", "45", "61"), "##########-B",
    (Module(0, "R04CPU", "iQ-R programmable controller CPU"),
     Module(1, "RX40C7", "16-pt DC input"),
     Module(2, "RY40NT5P", "16-pt transistor output")),
    identity={"slmp": {"model": "R04CPU", "model_code": 0x4800}},
    banners={"http": "", "snmp_sysdescr": "MELSEC iQ-R R04CPU"},
    aliases=("R04CPU", "MELSEC iQ-R R04CPU")))
_add(DeviceModel(
    "mitsubishi-q03udvcpu", "Mitsubishi Electric", "MELSEC-Q Q03UDVCPU",
    "plc", _MITSUBISHI, "1", "MELSEC-Q firmware",
    ("19", "23", "27"), "##########-B",
    (Module(0, "Q03UDVCPU", "Universal model high-speed QCPU"),
     Module(1, "QX42", "64-pt DC input")),
    identity={"slmp": {"model": "Q03UDVCPU", "model_code": 0x0366}},
    banners={"http": "", "snmp_sysdescr": "MELSEC-Q Q03UDVCPU"},
    aliases=("Q03UDVCPU", "MELSEC-Q Q03UDVCPU")))
_add(DeviceModel(
    "emerson-1410s-gateway", "Emerson", "Rosemount 1410S Smart Wireless "
    "Gateway (HART-IP)", "rtu", _ROSEMOUNT, "1",
    "Smart Wireless Gateway firmware", ("4.7.98", "4.7.106", "5.0.12"),
    "#######",
    identity={"hart": {"manufacturer_id": 0x0026, "device_type": 0x2690,
                       "device_rev": 3, "sw_rev": 4, "hw_rev": 1}},
    banners={"http": "", "snmp_sysdescr": "Smart Wireless Gateway {firmware}"},
    aliases=("1410S Smart Wireless Gateway", "Smart Wireless Gateway 1410S")))
_add(DeviceModel(
    "ge-rx3i-cpe330", "GE Intelligent Platforms", "PACSystems RX3i CPE330",
    "plc", _GE_IP, "1", "PACSystems firmware",
    ("9.40", "10.30", "10.85"), "?##########",
    (Module(0, "IC695PSD140", "RX3i power supply"),
     Module(1, "IC695CPE330", "RX3i CPU, 1 GHz dual core"),
     Module(3, "IC694MDL660", "32-pt 24 V DC input")),
    identity={"srtp": {"cpu": "IC695CPE330", "r_registers": 32640}},
    banners={"http": "", "snmp_sysdescr": "PACSystems RX3i IC695CPE330 "
                                          "{firmware}"},
    aliases=("IC695CPE330", "PACSystems RX3i CPE330")))

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
                  serial: str, host_name: str = "") -> Dict[str, Any]:
    """Endpoint ``meta`` keys the identity builders read for a device
    (``protocols.enip_identity_flow`` / ``protocols.s7_identity_flow`` and
    the ``tgt.protocols_ot`` Modbus / BACnet / DNP3 identity flows), plus
    the SNMP system description from the model's banners."""
    if model is None:
        return {}
    meta: Dict[str, Any] = {}
    mb = model.identity.get("modbus")
    if mb:
        meta.update({
            "modbus_vendor": mb.get("vendor", model.vendor),
            "modbus_product_code": mb.get("product_code", model.product),
            "modbus_product_name": mb.get("product_name", model.product),
            "modbus_model_name": mb.get("model_name", model.product),
            "modbus_vendor_url": mb.get("vendor_url", ""),
            "modbus_revision": firmware})
    bn = model.identity.get("bacnet")
    if bn:
        meta.update({
            "bacnet_vendor_id": bn["vendor_id"],
            "bacnet_vendor": bn.get("vendor_name", model.vendor),
            "bacnet_model": bn.get("model_name", model.product),
            "bacnet_firmware": firmware,
            "bacnet_app_version": bn.get("app_version", "{firmware}").format(
                firmware=firmware),
            "bacnet_segmentation": bn.get("segmentation", 3),
            "bacnet_serial": serial})
    dn = model.identity.get("dnp3")
    if dn:
        meta.update({"dnp3_vendor": model.vendor,
                     "dnp3_product": dn.get("product_name", model.product),
                     "dnp3_firmware": firmware, "dnp3_serial": serial})
    iec = model.identity.get("iec104")
    if iec and "common_address" in iec:
        meta["common_address"] = iec["common_address"]
    descr = banner(model, "snmp_sysdescr", host_name, firmware, serial)
    if descr:
        meta["snmp_sysdescr"] = descr
        if model.banners.get("snmp_sysobjectid"):
            meta["snmp_sysobjectid"] = model.banners["snmp_sysobjectid"]
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
    # vendor engineering protocols (tgt/protocols_eng.py)
    fins = model.identity.get("fins")
    if fins:
        meta["fins_model"] = fins["model"]
        if firmware:
            meta["fins_version"] = firmware
    slmp = model.identity.get("slmp")
    if slmp:
        meta["slmp_model"] = slmp["model"]
        meta["slmp_model_code"] = slmp["model_code"]
    hart = model.identity.get("hart")
    if hart:
        for k, v in hart.items():
            meta[f"hart_{k}"] = v
        digits = "".join(c for c in serial if c.isdigit())
        if digits:
            meta["hart_device_id"] = int(digits) % (1 << 24)
    cds = model.identity.get("codesys")
    if cds:                     # CODESYS V3 name-service DeviceInfo
        meta.update({"codesys_device": cds.get("device_name", model.product),
                     "codesys_vendor": cds.get("vendor_name", model.vendor),
                     "codesys_target_type": cds.get("target_type", 0x1006),
                     "codesys_target_id": cds.get("target_id", 0x0001),
                     "codesys_firmware": firmware, "codesys_serial": serial})
        if host_name:
            meta["codesys_node"] = host_name
    # IEC 61850 MMS Identify (vendorName / modelName / revision) and the SEL
    # ASCII ID command (tgt/protocols_util.py)
    mms = model.identity.get("mms")
    if mms:
        meta["vendor"] = mms.get("vendor", model.vendor)
        meta["model"] = mms.get("model", model.product)
        if firmware:
            meta["revision"] = firmware
    sel = model.identity.get("sel")
    if sel:
        meta["sel_model"] = sel.get("model", model.product)
        meta["sel_firmware"] = firmware
        meta["sel_serial"] = serial
    desktop = banner(model, "vnc_desktop", host_name, firmware, serial)
    if desktop:                         # a panel HMI's VNC desktop name
        meta["vnc_desktop"] = desktop
    # PROFINET DCP identity and the site protocols (tgt/protocols_site.py)
    pn = model.identity.get("profinet")
    if pn:
        meta.update({"pn_vendor_id": pn["vendor_id"],
                     "pn_device_id": pn["device_id"],
                     "pn_role": pn.get("role", 0x01),
                     "dcp_vendor": pn.get("vendor_value", model.product)})
    for proto in ("dicom", "hl7", "knx"):
        for k, v in model.identity.get(proto, {}).items():
            meta[f"{proto}_{k}"] = v
    if "dicom" in model.identity:
        meta["dicom_software"] = firmware
        meta["dicom_serial"] = serial
    return meta


# ---------------------------------------------------------------------------
# Utility & energy sites (tgt/envs/sites: water-utility, electric-substation,
# oil-gas-pipeline): RTUs, protection IEDs, merging units, clocks, flow
# computers, analyzers, drives, panel HMIs, cellular / VSAT routers and a
# VPN firewall. OUIs are as Wireshark's manuf lists them; the IEC 61850 MMS
# vendor/model strings are what the IEDs report to Identify; firmware lists,
# serial formats, product codes and sysObjectIDs (under each vendor's
# enterprise arc) are representative.
# ---------------------------------------------------------------------------
_UTIL_SCHNEIDER = ("00:00:54", "00:80:f4")
_UTIL_SIEMENS_GRID = ("b4:b1:5a", "00:0e:8c")    # Siemens Energy Management
_UTIL_SIERRA = ("00:a0:d5", "28:a3:31")
_UTIL_DIGI = ("00:40:9d",)
_UTIL_ABB_MV = ("00:21:c1",)                     # ABB Oy Medium Voltage
_UTIL_GE_GRID = ("c4:b5:12",)                    # GE Digital Energy
_UTIL_OUTSTATION = {"role": "outstation"}


def _util(model_id, vendor, product, dtype, ouis, level, os_family, fw,
          serial, identity=None, banners=None, stack="embedded", aliases=(),
          cves=()):
    _add(DeviceModel(model_id, vendor, product, dtype, ouis, level, os_family,
                     fw, serial, identity=identity or {},
                     banners=dict({"http": ""}, **(banners or {})),
                     known_cves=cves, aliases=aliases, stack=stack))


def _modbus_id(vendor, code, name, url=""):
    return {"vendor": vendor, "vendor_url": url, "product_code": code,
            "product_name": name}


# -- water / wastewater: RTUs, drives, analyzers, panel HMIs ----------------
_util("schneider-scadapack-474", "Schneider Electric",
      "SCADAPack 474 smart RTU", "rtu", _UTIL_SCHNEIDER, "1",
      "SCADAPack x70 firmware", ("9.1.1", "9.2.0", "9.4.0"), "D#######",
      {"modbus": _modbus_id("Schneider Electric", "TBUP474",
                            "SCADAPack 474", "www.se.com"),
       "dnp3": dict(_UTIL_OUTSTATION, product_name="SCADAPack 474")},
      aliases=("SCADAPack 474",))
_util("schneider-scadapack-334e", "Schneider Electric",
      "SCADAPack 334E RTU (end of life)", "rtu", _UTIL_SCHNEIDER, "1",
      "SCADAPack 300 firmware", ("2.36", "2.43"), "A#######",
      {"modbus": _modbus_id("Schneider Electric", "SP334E",
                            "SCADAPack 334E", "www.se.com"),
       "dnp3": dict(_UTIL_OUTSTATION, product_name="SCADAPack 334E")},
      aliases=("SCADAPack 334E",))
_util("danfoss-fc202", "Danfoss", "VLT AQUA Drive FC 202 (MCA 122 Modbus "
      "TCP)", "drive", ("00:1b:08",), "0", "VLT drive firmware",
      ("4.48", "5.11", "5.33"), "######G###",
      {"modbus": _modbus_id("Danfoss", "FC-202P", "VLT AQUA Drive FC 202",
                            "www.danfoss.com")},
      aliases=("VLT AQUA Drive FC 202",))
_util("hach-sc4500", "Hach", "SC4500 controller (chlorine / turbidity "
      "analyzers)", "analyzer", ("00:0e:1c",), "1", "Hach SC firmware",
      ("1.30", "1.50", "2.00"), "##########",
      {"modbus": _modbus_id("Hach", "LXV525", "SC4500", "www.hach.com")},
      aliases=("SC4500",))
_util("weintek-cmt3072xh", "Weintek", "cMT3072XH HMI panel", "hmi-panel",
      ("00:0c:26",), "2", "Weintek cMT OS (Linux)",
      ("20210913", "20230118", "20240325"), "#########",
      banners={"vnc_desktop": "cMT3072XH {name}"}, stack="linux",
      aliases=("cMT3072XH",))

# -- cellular / VSAT routers and the VPN firewall ---------------------------
_util("sierra-airlink-rv50x", "Sierra Wireless", "AirLink RV50X LTE gateway",
      "router", _UTIL_SIERRA, "2", "ALEOS (Linux)",
      ("4.13.0.017", "4.14.0.004", "4.16.0.012"), "LA##########",
      banners={"snmp_sysdescr": "Sierra Wireless AirLink RV50X, ALEOS "
                                "{firmware}",
               "snmp_sysobjectid": "1.3.6.1.4.1.20542.9.1"},
      stack="linux", aliases=("AirLink RV50X",))
_util("digi-ix20", "Digi International", "Digi IX20 LTE router", "router",
      _UTIL_DIGI, "2", "Digi Accelerated Linux",
      ("22.11.48.62", "23.6.1.105", "24.3.28.88"), "IX20-######",
      banners={"snmp_sysdescr": "Digi IX20 {firmware}",
               "snmp_sysobjectid": "1.3.6.1.4.1.332.11.6"},
      stack="linux", aliases=("Digi IX20",))
_util("moxa-oncell-g3150a", "Moxa", "OnCell G3150A-LTE cellular gateway",
      "router", ("00:90:e8",), "2", "Moxa OnCell firmware (Linux)",
      ("V1.4", "V1.7", "V2.1"), "TAJCB#######",
      banners={"snmp_sysdescr": "OnCell G3150A-LTE-US {firmware}",
               "snmp_sysobjectid": "1.3.6.1.4.1.8691.15.35"},
      stack="linux", aliases=("OnCell G3150A-LTE",))
_util("hughes-ht2000w", "Hughes Network Systems", "HT2000W VSAT terminal",
      "router", ("00:80:ae",), "2", "Hughes HT firmware (Linux)",
      ("6.9.0.43", "6.10.0.24", "7.1.0.12"), "HT2K##########",
      banners={"snmp_sysdescr": "Hughes HT2000W Satellite Router {firmware}",
               "snmp_sysobjectid": "1.3.6.1.4.1.20048.1.2"},
      stack="linux", aliases=("HT2000W",))
_util("fortinet-fortigate-100f", "Fortinet", "FortiGate 100F firewall / SSL "
      "VPN", "firewall", ("00:09:0f",), "3.5", "FortiOS",
      ("v7.0.15", "v7.2.8", "v7.4.4"), "FG100FTK########",
      banners={"snmp_sysdescr": "FortiGate-100F {firmware}",
               "snmp_sysobjectid": "1.3.6.1.4.1.12356.101.1.1004"},
      stack="linux", aliases=("FortiGate-100F",))

# -- substation: protection IEDs, merging units, the station clock ----------
_util("sel-451", "Schweitzer Engineering Laboratories",
      "SEL-451 protection, automation and bay control", "relay", _SEL, "1",
      "SEL firmware", ("R320-V1", "R322-V0", "R323-V2"), "##########",
      {"dnp3": dict(_UTIL_OUTSTATION, product_name="SEL-451"),
       "mms": {"vendor": "SEL", "model": "SEL-451"},
       "sel": {"model": "SEL-451"}},
      {"snmp_sysdescr": "{product} {firmware}"}, stack="sel",
      aliases=("SEL-451",))
_util("sel-401", "Schweitzer Engineering Laboratories",
      "SEL-401 protection, automation and control merging unit",
      "merging-unit", _SEL, "1", "SEL firmware", ("R100-V2", "R101-V0"),
      "##########",
      {"mms": {"vendor": "SEL", "model": "SEL-401"},
       "sel": {"model": "SEL-401"}}, stack="sel", aliases=("SEL-401",))
_util("sel-2488", "Schweitzer Engineering Laboratories",
      "SEL-2488 satellite-synchronized network clock (PTP grandmaster)",
      "clock", _SEL, "2", "SEL firmware", ("R105-V1", "R107-V0", "R108-V2"),
      "##########",
      {"sel": {"model": "SEL-2488"}},
      {"snmp_sysdescr": "SEL-2488 Satellite-Synchronized Network Clock "
                        "{firmware}",
       "snmp_sysobjectid": "1.3.6.1.4.1.30290.2488"},
      stack="sel", aliases=("SEL-2488",))
_util("abb-ref615", "ABB", "Relion REF615 feeder protection and control",
      "relay", _UTIL_ABB_MV, "1", "Relion 615 series firmware",
      ("5.0.3", "5.0.6", "5.1.2"), "1VHR9#######",
      {"mms": {"vendor": "ABB", "model": "REF615"}}, aliases=("REF615",))
_util("ge-multilin-850", "GE Grid Solutions", "Multilin 850 feeder "
      "protection system", "relay", _UTIL_GE_GRID, "1", "Multilin 8 Series "
      "firmware", ("3.70", "4.10", "4.30"), "ML??#####",
      {"mms": {"vendor": "GE Multilin", "model": "850"}},
      aliases=("Multilin 850",))
_util("siemens-siprotec5-7sj85", "Siemens", "SIPROTEC 5 7SJ85 overcurrent "
      "protection", "relay", _UTIL_SIEMENS_GRID, "1", "SIPROTEC 5 firmware",
      ("V08.30", "V09.40", "V09.50"), "BF#########",
      {"mms": {"vendor": "SIEMENS", "model": "7SJ85"}},
      aliases=("SIPROTEC 5 7SJ85",))
_util("siemens-siprotec5-6mu85", "Siemens", "SIPROTEC 5 6MU85 merging unit",
      "merging-unit", _UTIL_SIEMENS_GRID, "1", "SIPROTEC 5 firmware",
      ("V09.40", "V09.50"), "BF#########",
      {"mms": {"vendor": "SIEMENS", "model": "6MU85"}},
      aliases=("SIPROTEC 5 6MU85",))

# -- oil & gas: flow computers ----------------------------------------------
_util("emerson-roc800", "Emerson", "ROC800 (ROC809) remote operations "
      "controller / flow computer", "flow-computer", ("00:80:74",), "1",
      "ROC800 firmware", ("3.70", "3.80", "3.90"), "W##########",
      {"modbus": _modbus_id("Emerson Process Management", "ROC809",
                            "ROC800", "www.emerson.com")},
      aliases=("ROC809",))
_util("abb-totalflow-xfcg5", "ABB", "Totalflow XFCG5 6413 flow computer",
      "flow-computer", ("00:13:86",), "1", "Totalflow G5 flash",
      ("2105457-033", "2105457-041", "2105457-046"), "XF########",
      {"modbus": _modbus_id("ABB Totalflow", "XFCG5-6413", "XFC G5",
                            "www.abb.com")},
      aliases=("XFCG5 6413",))

# -- rogue / transient devices a substation monitor should notice -----------
# (general-purpose hardware: not embedded OT assets, no EDR)
_add(DeviceModel(
    "omicron-cmc-356", "OMICRON electronics", "CMC 356 protection relay test "
    "set (IEC 61850 GOOSE / SV)", "test-set", ("20:b7:c0",), "",
    "OMICRON Test Universe embedded firmware", ("4.10", "4.20", "4.30"),
    "JE###?", banners={"http": ""}, embedded=False, aliases=("CMC 356",)))
_add(DeviceModel(
    "raspberry-pi-4", "Raspberry Pi Trading", "Raspberry Pi 4 Model B",
    "sbc", ("dc:a6:32", "e4:5f:01", "d8:3a:dd"), "", "Raspberry Pi OS (Linux)",
    ("6.1.21-v8+", "6.6.31-v8+"), "", banners={"http": "Apache"},
    embedded=False, stack="linux", aliases=("Raspberry Pi 4",)))
for _m in (CATALOG["omicron-cmc-356"], CATALOG["raspberry-pi-4"]):
    for _o in _m.ouis:                  # label the MAC prefix all the same
        OUI_VENDORS.setdefault(_o, _m.vendor)

# refresh the derived tables for the models above (idempotent)
_ALIASES.update({a: m.model_id for m in CATALOG.values() for a in m.aliases})
for _m in CATALOG.values():
    if _m.embedded:
        for _o in _m.ouis:
            OUI_VENDORS.setdefault(_o, _m.vendor)
EMBEDDED_OUIS = frozenset(o for m in CATALOG.values() if m.embedded
                          for o in m.ouis)



# ===========================================================================
# Vertical-site devices (tgt/envs/sites: auto-assembly, hospital-iomt,
# smart-building-dc, pharma-batch). OUIs are from Wireshark's manuf
# database; CIP / BACnet / KNX / PROFINET vendor ids, Siemens order numbers,
# DICOM manufacturer strings and the APC sysDescr layout are as published.
# PROFINET device ids, CIP product codes, firmware lists, serial formats and
# DICOM implementation class UIDs (under each vendor's registered root) are
# representative. New ``identity`` sections: ``profinet`` (DCP vendor/device
# id, role, DeviceVendorValue), ``dicom``, ``hl7`` and ``knx`` (see
# identity_meta).
# ===========================================================================
_SIEMENS_BT = ("00:05:19", "00:c0:e4")            # Siemens Building Technologies
_SIEMENS_HC = ("88:4b:39",)                       # Siemens Healthcare
_FANUC = ("00:e0:e4",)
_KUKA = ("00:60:c8",)
_BECKHOFF = ("00:01:05",)
_WAGO = ("00:30:de",)
_PHOENIX = ("00:a0:45", "a8:74:1d")
_GE_HC = ("44:4b:5d",)
_CARESTREAM = ("00:1d:4a",)
_MINDRAY = ("00:0f:14", "38:0b:26")
_ALARIS = ("f8:c6:78", "00:d0:75")                # CareFusion / Alaris (BD)
_RAULAND = ("00:90:5e",)
_APC = ("00:c0:b7",)
_RARITAN = ("00:0d:5d",)
_EMERSON_NP = ("00:09:f5",)                       # Emerson Network Power (Vertiv)
_CARRIER = ("00:02:52", "34:6d:9c")
_AXIS = ("ac:cc:8e", "00:40:8c", "b8:a4:4f")
_HIKVISION = ("44:19:b6", "c0:56:e3", "bc:ad:28")
_MERCURY = ("00:0f:e5",)
_EMERSON_PM = ("00:40:03",)                       # Emerson Process Management

_SITE_SIEMENS_DESCR = ("Siemens, SIMATIC {kind}, {model}, {order}, HW: "
                       "Version 1, FW: Version {{firmware}}, {{serial}}")

# --- Siemens factory automation --------------------------------------------
_add(DeviceModel(
    "siemens-cpu-1515r-2pn", "Siemens", "SIMATIC S7-1500R CPU 1515R-2 PN",
    "plc", _SIEMENS, "1", "SIMATIC S7 firmware",
    ("V2.9.4", "V3.0.3", "V3.1.1"), _S7_SERIAL,
    (Module(1, "6ES7 515-2RM00-0AB0", "CPU 1515R-2 PN (redundant)"),
     Module(2, "6ES7 521-1BL00-0AB0", "DI 32x24VDC HF")),
    identity={"s7": {"order": "6ES7 515-2RM00-0AB0",
                     "module": "CPU 1515R-2 PN"},
              "profinet": {"vendor_id": 0x002A, "device_id": 0x010E,
                           "role": 0x03, "vendor_value": "S7-1500"}},
    banners={"http": "", "snmp_sysdescr": _SIEMENS_SYSDESCR,
             "snmp_sysobjectid": _SIEMENS_SNMP},
    aliases=("6ES7 515-2RM00-0AB0",), stack="siemens"))
_add(DeviceModel(
    "siemens-et200sp-im155-6pn-hf", "Siemens",
    "SIMATIC ET 200SP IM 155-6 PN HF", "remote-io", _SIEMENS, "1",
    "ET 200SP interface module firmware", ("V4.2.1", "V4.2.3", "V6.0.0"),
    _S7_SERIAL,
    (Module(0, "6ES7 155-6AU01-0CN0", "IM 155-6 PN HF"),
     Module(1, "6ES7 131-6BF01-0BA0", "DI 8x24VDC ST"),
     Module(2, "6ES7 132-6BF01-0BA0", "DQ 8x24VDC/0.5A ST"),
     Module(3, "6ES7 134-6GD01-0BA1", "AI 4xI 2-/4-wire ST")),
    identity={"profinet": {"vendor_id": 0x002A, "device_id": 0x0313,
                           "role": 0x01, "vendor_value": "ET200SP"}},
    banners={"http": "",
             "snmp_sysdescr": _SITE_SIEMENS_DESCR.format(
                 kind="ET 200SP", model="IM 155-6 PN HF",
                 order="6ES7 155-6AU01-0CN0"),
             "snmp_sysobjectid": _SIEMENS_SNMP},
    aliases=("IM 155-6 PN HF",), stack="siemens"))
_add(DeviceModel(
    "siemens-scalance-xc208", "Siemens", "SCALANCE XC208 managed switch",
    "switch", _SIEMENS, "2", "SCALANCE X firmware", ("4.3", "4.4", "4.5"),
    "VPK#######",
    identity={"profinet": {"vendor_id": 0x002A, "device_id": 0x0A06,
                           "role": 0x01, "vendor_value": "SCALANCE XC-200"}},
    banners={"http": "", "snmp_sysdescr": _SITE_SIEMENS_DESCR.format(
                 kind="NET", model="SCALANCE XC208",
                 order="6GK5 208-0BA00-2AC2").replace("{firmware}",
                                                      "V{firmware}"),
             "snmp_sysobjectid": "1.3.6.1.4.1.4329.20.1.1.1.1"},
    aliases=("SCALANCE XC208",), stack="siemens"))
_add(DeviceModel(
    "siemens-iot2050", "Siemens", "SIMATIC IOT2050 Advanced edge gateway",
    "gateway", _SIEMENS, "2", "SIMATIC Industrial OS (Debian)",
    ("1.3.1", "1.4.1", "1.5.2"), "PS#######",
    (Module(0, "6ES7 647-0BA00-1YA2", "IOT2050 Advanced"),),
    banners={"http": "", "snmp_sysdescr": "Linux iot2050-debian "
             "5.10.194-cip39 #1 SMP PREEMPT aarch64 (Industrial OS {firmware})"},
    aliases=("SIMATIC IOT2050",), stack="linux"))
_add(DeviceModel(
    "siemens-knx-n146", "Siemens", "KNX IP Router N 146/02", "bms-controller",
    _SIEMENS_BT, "1", "KNX IP router firmware", ("2.1.4", "2.2.0"),
    "00010#######",
    (Module(0, "5WG1146-1AB02", "N 146/02 KNX IP router"),),
    identity={"knx": {"manufacturer": 0x0001, "name": "IP Router N146/02"}},
    banners={"http": ""}, aliases=("N 146/02",), stack="embedded"))
_add(DeviceModel(
    "siemens-desigo-pxc5", "Siemens", "Desigo PXC5.E003 automation station",
    "bms-controller", _SIEMENS_BT, "1", "Desigo PX firmware",
    ("6.20.215", "6.30.012", "7.00.075"), "PXC#########",
    identity={"bacnet": {"vendor_id": 7, "vendor_name": "Siemens Building "
                         "Technologies", "model_name": "PXC5.E003",
                         "app_version": "PX {firmware}"}},
    banners={"http": ""}, aliases=("PXC5.E003",), stack="embedded"))

# --- Rockwell lines -------------------------------------------------------
_add(DeviceModel(
    "rockwell-1734-aentr", "Rockwell Automation",
    "POINT I/O 1734-AENTR dual-port EtherNet/IP adapter", "remote-io",
    _ROCKWELL, "1", "POINT I/O adapter firmware",
    ("5.012", "6.012", "7.001"), _CIP_SERIAL,
    (Module(0, "1734-AENTR", "Dual-port EtherNet/IP adapter (DLR)"),
     Module(1, "1734-IB8", "8-pt 24 V DC sink input"),
     Module(2, "1734-OB8E", "8-pt 24 V DC protected output")),
    identity={"cip": {"vendor_id": 1, "device_type": 0x0C,
                      "product_code": 141, "product_name": "1734-AENTR/B"}},
    banners={"http": "", "snmp_sysdescr": "1734-AENTR/B {firmware}"},
    aliases=("1734-AENTR",), stack="rockwell"))
_add(DeviceModel(
    "rockwell-powerflex-525", "Rockwell Automation", "PowerFlex 525 AC drive",
    "drive", _ROCKWELL, "0", "PowerFlex drive firmware",
    ("5.001", "6.001", "7.001"), _CIP_SERIAL,
    identity={"cip": {"vendor_id": 1, "device_type": 0x02,
                      "product_code": 150, "product_name": "PowerFlex 525"}},
    banners={"http": "", "snmp_sysdescr": "PowerFlex 525 {firmware}"},
    aliases=("PowerFlex 525",), stack="rockwell-drive"))

# --- Robots ---------------------------------------------------------------
_add(DeviceModel(
    "fanuc-r30ib-plus", "FANUC", "R-30iB Plus robot controller", "robot",
    _FANUC, "1", "FANUC robot controller software",
    ("V9.30P/38", "V9.40P/27", "V9.40P/45"), "F######",
    identity={"cip": {"vendor_id": 356, "device_type": 0x0C,
                      "product_code": 2, "product_name": "R-30iB Plus"}},
    banners={"http": "", "snmp_sysdescr": "FANUC R-30iB Plus {firmware}"},
    aliases=("R-30iB Plus",), stack="embedded"))
_add(DeviceModel(
    "kuka-krc4", "KUKA", "KR C4 robot controller", "robot", _KUKA, "1",
    "KUKA System Software on Windows 7 Embedded",
    ("KSS 8.3.48", "KSS 8.6.15", "KSS 8.7.6"), "#######",
    banners={"http": "", "smb_os": "Windows Embedded Standard 7601 "
             "Service Pack 1"},
    known_cves=("CVE-2019-0708",),   # BlueKeep: KSS ships an unpatched Win7
    aliases=("KR C4",), stack="win7"))

# --- Beckhoff / WAGO / Phoenix Contact ------------------------------------
_add(DeviceModel(
    "beckhoff-cx5140", "Beckhoff Automation", "CX5140 Embedded PC (TwinCAT 3)",
    "plc", _BECKHOFF, "1", "TwinCAT 3 on Windows 10 IoT Enterprise",
    ("TC3.1.4024.53", "TC3.1.4024.56", "TC3.1.4026.12"), "######",
    (Module(0, "CX5140-0185", "Embedded PC, Atom E3845"),
     Module(1, "EL1809", "16-ch digital input"),
     Module(2, "EL2809", "16-ch digital output")),
    banners={"http": "", "smb_os": "Windows 10 IoT Enterprise LTSC 17763"},
    aliases=("CX5140",), stack="win10"))
_add(DeviceModel(
    "beckhoff-ek9300", "Beckhoff Automation", "EK9300 PROFINET bus coupler",
    "remote-io", _BECKHOFF, "1", "EK9300 firmware", ("08", "11", "13"),
    "########",
    (Module(0, "EK9300", "PROFINET RT bus coupler"),
     Module(1, "EL1008", "8-ch digital input"),
     Module(2, "EL2008", "8-ch digital output")),
    identity={"profinet": {"vendor_id": 0x0120, "device_id": 0x2453,
                           "role": 0x01, "vendor_value": "EK9300"}},
    banners={"http": ""}, aliases=("EK9300",), stack="embedded"))
_add(DeviceModel(
    "wago-750-8212", "WAGO", "PFC200 750-8212 controller", "plc", _WAGO,
    "1", "WAGO PFC firmware (Linux RT)",
    ("03.10.08(22)", "04.02.13(24)", "04.04.03(26)"), "#############",
    (Module(0, "750-8212", "PFC200 G2 2ETH RS"),
     Module(1, "750-1405", "16-ch digital input"),
     Module(2, "750-1504", "16-ch digital output")),
    identity={"modbus": {"vendor": "WAGO GmbH & Co. KG",
                         "vendor_url": "www.wago.com",
                         "product_code": "750-8212",
                         "product_name": "PFC200 CS 2ETH RS"},
              # e!RUNTIME / CODESYS V3 DeviceInfo (tgt/protocols_codesys.py)
              "codesys": {"device_name": "WAGO 750-8212 PFC200 G2 2ETH RS",
                          "vendor_name": "WAGO", "target_type": 0x1006,
                          "target_id": 0x8212}},
    banners={"http": "lighttpd", "snmp_sysdescr": "WAGO 750-8212 PFC200 CS "
             "2ETH RS FW {firmware}",
             "snmp_sysobjectid": "1.3.6.1.4.1.13576"},
    aliases=("750-8212",), stack="linux"))
_add(DeviceModel(
    "phoenix-axc-f-2152", "Phoenix Contact", "PLCnext Control AXC F 2152",
    "plc", _PHOENIX, "1", "PLCnext firmware (Linux)",
    ("2023.0.4", "2024.0.2", "2025.0.1"), "#######",
    (Module(0, "2404267", "AXC F 2152 controller"),),
    identity={"profinet": {"vendor_id": 0x00B0, "device_id": 0x0170,
                           "role": 0x03, "vendor_value": "AXC F 2152"}},
    banners={"http": "", "snmp_sysdescr": "Phoenix Contact AXC F 2152 "
             "PLCnext {firmware}", "snmp_sysobjectid": "1.3.6.1.4.1.4346"},
    aliases=("AXC F 2152",), stack="linux"))

# --- Healthcare: imaging, monitoring, infusion, nurse call ----------------
_add(DeviceModel(
    "ge-revolution-evo", "GE Healthcare", "Revolution EVO CT scanner console",
    "modality", _GE_HC, "2", "GE CT console (Linux)",
    ("Revo_EVO.SP2", "Revo_EVO.SP4", "Revo_EVO.SP5"), "######CN#",
    identity={"dicom": {"manufacturer": "GE MEDICAL SYSTEMS",
                        "model": "Revolution EVO", "modality": "CT",
                        "impl_uid": "1.2.840.113619.6.374",
                        "impl_version": "REVO_EVO_SP"}},
    banners={"http": ""}, aliases=("Revolution EVO",), stack="linux"))
_add(DeviceModel(
    "siemens-magnetom-vida", "Siemens Healthineers", "MAGNETOM Vida 3T MRI",
    "modality", _SIEMENS_HC, "2", "syngo MR XA (Windows 10)",
    ("syngo MR XA31", "syngo MR XA50", "syngo MR XA51"), "######",
    identity={"dicom": {"manufacturer": "SIEMENS", "model": "MAGNETOM Vida",
                        "modality": "MR", "impl_uid": "1.3.12.2.1107.5.2",
                        "impl_version": "MR_XA50"}},
    banners={"http": "", "smb_os": "Windows 10 Enterprise LTSC 17763"},
    aliases=("MAGNETOM Vida",), stack="win10"))
_add(DeviceModel(
    "carestream-directview-cr975", "Carestream Health",
    "DirectView CR 975 computed radiography", "modality", _CARESTREAM, "2",
    "Windows XP Embedded", ("5.7.412", "5.8.111"), "CR975####",
    identity={"dicom": {"manufacturer": "Carestream Health",
                        "model": "DirectView CR 975", "modality": "CR",
                        "impl_uid": "1.2.276.0.7230010.3.0.3.5.4",
                        "impl_version": "OFFIS_DCMTK_354"}},
    banners={"http": "", "smb_os": "Windows 5.1"},
    known_cves=("CVE-2008-4250", "CVE-2017-0144", "CVE-2019-0708"),
    aliases=("DirectView CR 975",), stack="winxp"))
_add(DeviceModel(
    "mindray-benevision-n17", "Mindray", "BeneVision N17 patient monitor",
    "patient-monitor", _MINDRAY, "1", "Mindray monitor firmware",
    ("01.38.00", "01.42.01", "02.03.00"), "??-#######",
    identity={"hl7": {"app": "MINDRAY_N17"}},
    banners={"http": ""}, aliases=("BeneVision N17",), stack="embedded"))
_add(DeviceModel(
    "bd-alaris-8015", "BD (CareFusion)", "Alaris PC Unit 8015 infusion system",
    "infusion-pump", _ALARIS, "1", "Alaris PC unit firmware",
    ("9.33", "12.1.2", "12.3.0"), "#########",
    banners={"http": ""}, aliases=("Alaris 8015",), stack="embedded"))
_add(DeviceModel(
    "rauland-responder5", "Rauland-Borg", "Responder 5 nurse call server",
    "nurse-call", _RAULAND, "2", "Responder 5 (Linux appliance)",
    ("5.6.1", "5.7.2", "5.8.0"), "R5-######",
    identity={"hl7": {"app": "RESPONDER5"}},
    banners={"http": "nginx"}, aliases=("Responder 5",), stack="linux"))

# --- Data centre power + cooling, building systems, cameras, access -------
_APC_NMC = ("APC Web/SNMP Management Card (MB:v4.5.4 PF:v{firmware} "
            "PN:apc_hw{hw}_aos_{firmware}.bin AF1:v{firmware} "
            "AN1:apc_hw{hw}_{app}_{firmware}.bin MN:{mn} HR:{hr} SN: {serial} "
            "MD:{md}) (Embedded PowerNet SNMP Agent SW v2.2 compatible)")
_add(DeviceModel(
    "apc-srt-ap9641", "Schneider Electric (APC)",
    "Smart-UPS SRT 10kVA with NMC3 AP9641", "ups", _APC, "1",
    "APC NMC3 (Linux)", ("2.2.0.6", "2.4.1.1", "2.5.0.8"), "ZA##########",
    banners={"http": "",
             "snmp_sysdescr": _APC_NMC.replace("{hw}", "21")
             .replace("{app}", "su").replace("{mn}", "AP9641")
             .replace("{hr}", "A01").replace("{md}", "09/20/2022"),
             "snmp_sysobjectid": "1.3.6.1.4.1.318.1.3.27"},
    aliases=("AP9641",), stack="linux"))
_add(DeviceModel(
    "apc-ap8853", "Schneider Electric (APC)", "Rack PDU 2G switched AP8853",
    "pdu", _APC, "1", "APC NMC2 (AOS)", ("6.8.2", "6.9.6", "7.0.6"),
    "5A##########",
    banners={"http": "",
             "snmp_sysdescr": _APC_NMC.replace("{hw}", "05")
             .replace("{app}", "rpdu2g").replace("{mn}", "AP8853")
             .replace("{hr}", "02").replace("{md}", "05/14/2019"),
             "snmp_sysobjectid": "1.3.6.1.4.1.318.1.3.4.6"},
    aliases=("AP8853",), stack="embedded"))
_add(DeviceModel(
    "raritan-px3-5190r", "Raritan", "PX3-5190R intelligent rack PDU", "pdu",
    _RARITAN, "1", "Raritan Xerus (Linux)",
    ("3.6.20.5-48233", "4.0.20.5-49038", "4.1.0.5-49500"), "1INT#######",
    banners={"http": "", "snmp_sysdescr": "Raritan PX3-5190R, Firmware "
             "Version {firmware}",
             "snmp_sysobjectid": "1.3.6.1.4.1.13742.6"},
    aliases=("PX3-5190R",), stack="linux"))
_add(DeviceModel(
    "vertiv-liebert-cw-unity", "Vertiv", "Liebert CW CRAH with IntelliSlot "
    "Unity card", "hvac", _EMERSON_NP, "1", "Liebert Unity firmware (Linux)",
    ("7.6.1.0", "8.0.4.0", "8.2.1.0"), "####?#####",
    identity={"modbus": {"vendor": "Vertiv", "vendor_url": "www.vertiv.com",
                         "product_code": "IS-UNITY-DP",
                         "product_name": "Liebert CW"}},
    banners={"http": "", "snmp_sysdescr": "Liebert CW IntelliSlot Unity "
             "Card {firmware}", "snmp_sysobjectid": "1.3.6.1.4.1.476.1.42"},
    aliases=("Liebert CW",), stack="linux"))
_add(DeviceModel(
    "carrier-30xa-prodialog", "Carrier", "AquaForce 30XA chiller "
    "(PRO-DIALOG+ control)", "hvac", _CARRIER, "1", "PRO-DIALOG+ firmware",
    ("SR-1.43", "SR-1.52"), "####Q#####",
    identity={"modbus": {"vendor": "Carrier", "vendor_url": "www.carrier.com",
                         "product_code": "30XA-PD+",
                         "product_name": "AquaForce 30XA"}},
    banners={"http": ""}, aliases=("30XA PRO-DIALOG+",), stack="embedded"))
_add(DeviceModel(
    "axis-p3245-v", "Axis Communications", "AXIS P3245-V network camera",
    "camera", _AXIS, "1", "AXIS OS (Linux)",
    ("10.12.199", "11.8.64", "11.11.73"), "ACCC8E%%%%%%",
    banners={"http": ""}, aliases=("AXIS P3245-V",), stack="linux"))
_add(DeviceModel(
    "hikvision-ds-2cd2143g2", "Hikvision", "DS-2CD2143G2-IU network camera",
    "camera", _HIKVISION, "1", "Hikvision embedded Linux",
    ("V5.7.3 build 220112", "V5.7.15 build 230726"), "DS-2CD2143G2-IU2022##",
    banners={"http": "App-webs/"}, aliases=("DS-2CD2143G2-IU",),
    stack="linux"))
_add(DeviceModel(
    "mercury-lp4502", "Mercury Security", "LP4502 intelligent access "
    "controller", "access-control", _MERCURY, "1", "Mercury LP firmware",
    ("1.29.1", "1.31.0", "2.2.2"), "########", banners={"http": ""},
    aliases=("LP4502",), stack="linux"))

# --- Pharma DCS -----------------------------------------------------------
_add(DeviceModel(
    "emerson-deltav-pk", "Emerson", "DeltaV PK Controller", "plc",
    _EMERSON_PM, "1", "DeltaV controller firmware",
    ("14.3.1", "14.FP3", "15.FP1"), "PK########",
    (Module(0, "VE3008", "PK Controller"),),
    banners={"http": ""}, aliases=("DeltaV PK",), stack="embedded"))


def _site_reindex() -> None:
    """Refresh the derived lookups for the models added above."""
    global EMBEDDED_OUIS
    for m in CATALOG.values():
        for a in m.aliases:
            _ALIASES.setdefault(a, m.model_id)
        if m.embedded:
            for o in m.ouis:
                OUI_VENDORS.setdefault(o, m.vendor)
    EMBEDDED_OUIS = frozenset(o for m in CATALOG.values() if m.embedded
                              for o in m.ouis)


_site_reindex()


# ---------------------------------------------------------------------------
# CODESYS V3 controllers (tgt/protocols_codesys.py). The ``codesys``
# identity is what the runtime's name-service DeviceInfo reply carries:
# device and vendor name strings plus target type / id. OUIs are as
# Wireshark's manuf lists them (Schneider M2xx: Telemecanique 00:80:f4;
# Eaton XC300: Eaton Industries GmbH, ex Moeller, 00:80:99). Device-name
# strings, target types / ids, firmware lists and serial formats are
# representative.
# ---------------------------------------------------------------------------
_EATON_IND = ("00:80:99",)
_M2XX = ("00:80:f4",)

_add(DeviceModel(
    "schneider-tm251mese", "Schneider Electric", "Modicon M251 TM251MESE "
    "logic controller", "plc", _M2XX, "1", "Modicon M251 firmware "
    "(CODESYS V3 runtime)", ("5.1.9.34", "5.2.11.24", "5.3.6.2"),
    "##############",
    (Module(0, "TM251MESE", "M251 logic controller, 2 Ethernet ports"),
     Module(1, "TM3DI16", "TM3 16-ch digital input"),
     Module(2, "TM3DQ16T", "TM3 16-ch transistor output")),
    identity={"codesys": {"device_name": "TM251MESE",
                          "vendor_name": "Schneider Electric",
                          "target_type": 0x1003, "target_id": 0x0251}},
    banners={"http": ""}, aliases=("TM251MESE",), stack="embedded"))
_add(DeviceModel(
    "schneider-tm241cec24t", "Schneider Electric", "Modicon M241 "
    "TM241CEC24T logic controller", "plc", _M2XX, "1",
    "Modicon M241 firmware (CODESYS V3 runtime)",
    ("5.1.9.34", "5.2.11.24"), "##############",
    (Module(0, "TM241CEC24T", "M241 logic controller, Ethernet + CANopen"),),
    identity={"codesys": {"device_name": "TM241CEC24T/U",
                          "vendor_name": "Schneider Electric",
                          "target_type": 0x1003, "target_id": 0x0241}},
    banners={"http": ""}, aliases=("TM241CEC24T",), stack="embedded"))
_add(DeviceModel(
    "eaton-xc-303", "Eaton", "XC300 modular PLC XC-303-C32-002", "plc",
    _EATON_IND, "1", "XC300 firmware (Linux, CODESYS V3 runtime)",
    ("1.03.024", "1.04.008", "1.05.012"), "#########",
    (Module(0, "XC-303-C32-002", "XC300 CPU, 2 Ethernet, OPC UA"),
     Module(1, "XN300-16DI", "XN300 16-ch digital input")),
    identity={"codesys": {"device_name": "XC-303-C32-002",
                          "vendor_name": "Eaton",
                          "target_type": 0x1006, "target_id": 0x0303}},
    banners={"http": ""}, aliases=("XC-303-C32-002",), stack="linux"))


# ===========================================================================
# Serial-to-Ethernet gateways and IIoT (tgt/protocols_iiot.py, site
# iiot-retrofit): Moxa / Lantronix device servers and a Modbus gateway, LoRa
# gateways, a BACnet/SC hub, and the field devices that sit behind them
# (serial slaves and LoRaWAN sensors: no IP of their own — their OUI is the
# vendor's, the prefix of a LoRaWAN sensor's DevEUI). OUIs are from
# Wireshark's manuf database; product names are the vendors'; firmware lists,
# serial formats, sysDescr strings, sysObjectIDs and Moxa search product ids
# are representative. ``moxa`` identity: ``product_id`` the device-search
# reply carries.
# ===========================================================================
_LANTRONIX = ("00:80:a3", "00:c0:f2")
_KERLINK = ("70:76:ff",)
_MULTITECH = ("00:08:00",)
_CONTEMPORARY = ("00:50:db",)
_MILESIGHT = ("24:e1:24", "c0:ba:1f")
_DRAGINO = ("a8:40:41",)
_ABB_DRIVES = ("00:1c:01",)


def _gw(model_id, vendor, product, dtype, ouis, level, os_family, fw, serial,
        identity=None, banners=None, stack="embedded", aliases=()):
    _add(DeviceModel(model_id, vendor, product, dtype, ouis, level, os_family,
                     fw, serial, identity=identity or {},
                     banners=dict({"http": ""}, **(banners or {})),
                     aliases=aliases, stack=stack))


# -- serial device servers / gateways ---------------------------------------
_gw("moxa-nport-5150", "Moxa", "NPort 5150 1-port RS-232/422/485 serial "
    "device server", "serial-gateway", _MOXA, "1", "Moxa NPort firmware",
    ("V3.9", "V3.10", "V3.11"), "TAGBB#######",
    {"moxa": {"product_id": 0x5150}},
    {"snmp_sysdescr": "NPort 5150", "snmp_sysobjectid": "1.3.6.1.4.1.8691.2.7"},
    aliases=("NPort 5150",))
_gw("moxa-nport-5650-16", "Moxa", "NPort 5650-16 16-port rackmount RS-232/"
    "422/485 serial device server", "serial-gateway", _MOXA, "1",
    "Moxa NPort firmware", ("V3.9", "V3.11", "V3.12"), "TAHCB#######",
    {"moxa": {"product_id": 0x5650}},
    {"snmp_sysdescr": "NPort 5650-16",
     "snmp_sysobjectid": "1.3.6.1.4.1.8691.2.8"},
    aliases=("NPort 5650-16",))
_gw("moxa-mgate-mb3170", "Moxa", "MGate MB3170 1-port Modbus TCP to RTU/ASCII "
    "gateway", "protocol-gateway", _MOXA, "1", "Moxa MGate firmware",
    ("V4.2", "V4.3", "V4.4"), "TAIDB#######",
    {"moxa": {"product_id": 0x3170}},
    {"snmp_sysdescr": "MGate MB3170",
     "snmp_sysobjectid": "1.3.6.1.4.1.8691.21.1"},
    aliases=("MGate MB3170",))
_gw("lantronix-uds1100", "Lantronix", "UDS1100 1-port serial device server",
    "serial-gateway", _LANTRONIX, "1", "Lantronix device server firmware",
    ("6.10.0.1", "6.11.0.4", "6.11.0.7"), "########",
    aliases=("UDS1100",))
# -- LoRaWAN gateways (Semtech UDP packet forwarder) --------------------------
_gw("kerlink-wirnet-istation", "Kerlink", "Wirnet iStation LoRaWAN gateway",
    "lora-gateway", _KERLINK, "2", "KerOS (Linux)",
    ("5.9.1", "5.10.4", "6.1.2"), "########",
    banners={"snmp_sysdescr": "Linux {name} KerOS {firmware} armv7l"},
    stack="linux", aliases=("Wirnet iStation",))
_gw("multitech-conduit-mtcdt", "Multitech", "MultiTech Conduit MTCDT "
    "LoRaWAN gateway", "lora-gateway", _MULTITECH, "2", "mPower (Linux)",
    ("5.3.8", "6.0.2", "6.3.0"), "########",
    banners={"snmp_sysdescr": "MultiTech Conduit mPower {firmware}"},
    stack="linux", aliases=("Conduit MTCDT",))
# -- BACnet/SC hub -----------------------------------------------------------
_gw("contemporary-basrouter-sc", "Contemporary Controls",
    "BASrouterSC BACnet/SC router and hub", "bacnet-sc-hub", _CONTEMPORARY,
    "2", "BASrouterSC firmware (Linux)", ("1.0.6", "1.1.2", "1.2.0"),
    "BRSC######", stack="linux", aliases=("BASrouterSC",))
# -- field devices behind gateways (no IP of their own) ----------------------
_gw("schneider-pm5330", "Schneider Electric", "PowerLogic PM5330 power meter "
    "(RS-485 Modbus RTU)", "meter", _SCHNEIDER, "0", "PM5000 firmware",
    ("2.2.1", "2.3.4", "3.0.2"), "#########",
    {"modbus": _modbus_id("Schneider Electric", "METSEPM5330",
                          "PM5330", "www.se.com")},
    aliases=("PM5330",))
_gw("abb-acs580", "ABB", "ACS580 general-purpose drive (embedded fieldbus, "
    "Modbus RTU)", "drive", _ABB_DRIVES, "0", "ACS580 primary control "
    "firmware", ("2.15.0.1", "2.16.0.4", "2.19.0.2"), "#########",
    {"modbus": _modbus_id("ABB", "ACS580-01", "ACS580", "new.abb.com")},
    aliases=("ACS580",))
_gw("milesight-em300-th", "Milesight", "EM300-TH LoRaWAN temperature and "
    "humidity sensor", "sensor", _MILESIGHT, "0", "Milesight EM300 firmware",
    ("1.2", "1.3", "1.5"), "6136?#########", aliases=("EM300-TH",))
_gw("dragino-lht65n", "Dragino", "LHT65N LoRaWAN temperature and humidity "
    "sensor", "sensor", _DRAGINO, "0", "Dragino LHT65N firmware",
    ("1.2.3", "1.2.5", "1.3.0"), "A84041########", aliases=("LHT65N",))

_site_reindex()


# ---------------------------------------------------------------------------
# Secure protocol variants (tgt/protocols_sec.py)
# ---------------------------------------------------------------------------
# model id -> {secure protocol: minimum firmware, as _numbers() reads it;
# () = every release}. A model listed with {} is known NOT to speak any (a
# ControlLogix 5570 needs a 1756-EN4TR module for CIP Security; S7-300 has
# no TLS). Models not listed are unknown: an environment may opt them in.
SECURE: Dict[str, Dict[str, Tuple[int, ...]]] = {
    # CIP Security on the controller's embedded Ethernet port: ControlLogix
    # 5580 and CompactLogix 5380 from firmware v32
    "rockwell-1756-l83e": {"enip-tls": (32,), "enip-dtls": (32,)},
    "rockwell-5069-l320er": {"enip-tls": (32,), "enip-dtls": (32,)},
    "rockwell-1756-l71": {},
    "rockwell-1769-l36erm": {},
    # S7-1500: secure PG/HMI communication (TLS 1.3) from V2.9 (TIA Portal
    # V17); the CPU's OPC UA server offers Basic256Sha256 from V2.0
    "siemens-cpu-1516-3pndp": {"s7plus-tls": (2, 9),
                               "opcua-sign-encrypt": (2, 0)},
    "siemens-cpu-1515r-2pn": {"s7plus-tls": (2, 9),
                              "opcua-sign-encrypt": (2, 0)},
    "siemens-cpu-315-2pndp": {},
    "siemens-cpu-317-2pndp": {},
    "siemens-im151-8-pndp": {},
    # IEC 60870-5-104 secured per IEC 62351-3 (SICAM A8000), DNP3 over TLS
    # (SEL RTAC)
    "siemens-sicam-cp-8050": {"iec104-tls": ()},
    "sel-3530": {"dnp3-tls": ()},
    # embedded OPC UA servers with SignAndEncrypt endpoints
    "phoenix-axc-f-2152": {"opcua-sign-encrypt": ()},
    "beckhoff-cx5140": {"opcua-sign-encrypt": ()},
}


def secure_support(model: Optional[DeviceModel], firmware: str,
                   proto: str) -> Optional[bool]:
    """Whether a device of ``model`` running ``firmware`` speaks the secure
    variant ``proto``: True / False from :data:`SECURE`, ``None`` when the
    catalog does not know (no model, or a model not listed)."""
    if model is None or model.model_id not in SECURE:
        return None
    floor = SECURE[model.model_id].get(proto)
    if floor is None:
        return False
    return not floor or _numbers(firmware) >= list(floor)


def secure_protocols(model: Optional[DeviceModel],
                     firmware: str) -> List[str]:
    """The secure variants a device of ``model`` at ``firmware`` supports."""
    if model is None:
        return []
    return sorted(p for p in SECURE.get(model.model_id, {})
                  if secure_support(model, firmware, p))
