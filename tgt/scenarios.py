"""Named scenarios — curated multi-protocol mixes for common test goals."""
from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass
class Scenario:
    key: str
    name: str
    profiles: List[str]
    desc: str


SCENARIOS = {
    "ot-baseline": Scenario(
        "ot-baseline", "OT Baseline",
        ["modbus", "s7comm", "enip", "dnp3"],
        "Steady industrial polling across the common ICS protocols — the "
        "'normal day' a monitor should learn as a baseline."),
    "ot-full": Scenario(
        "ot-full", "OT Full Sweep",
        ["modbus", "dnp3", "enip", "s7comm", "iec104", "bacnet", "opcua"],
        "Every supported OT protocol, exercising the widest classifier coverage."),
    "mixed-site": Scenario(
        "mixed-site", "Mixed IT/OT Site",
        ["modbus", "s7comm", "http", "dns", "ntp", "arp"],
        "Realistic plant-floor blend of control traffic and IT background "
        "chatter (web HMI, name resolution, time sync, ARP)."),
    "discovery": Scenario(
        "discovery", "Discovery / Asset Detection",
        ["arp", "icmp", "dns", "enip"],
        "ARP + ping + DNS + EtherNet/IP list-identity style traffic to drive "
        "asset-discovery and inventory features."),
    "it-noise": Scenario(
        "it-noise", "IT Background Noise",
        ["http", "dns", "ntp", "icmp", "arp"],
        "Non-OT traffic only — useful to confirm the sensor separates IT from "
        "OT and does not misclassify."),
    "substation": Scenario(
        "substation", "IEC 61850 Substation",
        ["goose", "sv", "mms", "ptp", "iec104", "dnp3"],
        "Station bus + process bus: GOOSE trips, 9-2LE sampled values, MMS "
        "client/server with IED identity, PTP time, and IEC 104 / DNP3 "
        "telecontrol to the SCADA gateway. GOOSE/SV/PTP are link-local."),
    "profinet-cell": Scenario(
        "profinet-cell", "PROFINET Cell",
        ["pn-dcp", "pn-dcp-set", "pn-rt", "s7comm", "s7-id"],
        "Siemens PROFINET cell: DCP Identify discovery, a DCP Set (IP / "
        "NameOfStation change), cyclic RT IO data and S7 engineering "
        "access. DCP/RT are raw Layer 2."),
}


def get(key: str) -> Scenario:
    return SCENARIOS[key]


def all_scenarios() -> List[Scenario]:
    return list(SCENARIOS.values())
