"""Time-model defaults for the timed scheduler (``tgt run --schedule timed``).

Everything here is a plain table meant to be edited:

* :data:`PERIODS` — how often each protocol's conversation recurs, how much
  each occurrence jitters, how many exchanges an occurrence carries and which
  day-profile activity class it follows.
* :data:`PERSISTENT` — protocols polled over one long-lived TCP connection
  (handshake once, every poll reuses it) and how to cut a builder's session
  into its connection-setup, poll and teardown exchanges.
* :data:`RTT` / :data:`PROCESSING` — request -> response latency by network
  path and how long the answering device takes.
* :data:`DAY_PROFILES` — hour-by-hour activity factors per class
  (``--day-profile shift``).

An environment file's per-flow ``period`` / ``jitter`` override the table.
"""
from __future__ import annotations

import datetime
import math
import re
import zlib
from typing import Dict, Optional, Tuple

# ---------------------------------------------------------------------------
# Per-protocol recurrence
# ---------------------------------------------------------------------------
# key: (period_lo_s, period_hi_s, jitter, exchanges per occurrence, class)
#
# Each conversation gets one period, picked log-uniformly in [lo, hi] from a
# stable hash of (client, server, protocol) — so the same conversation always
# polls at the same rate, but a plant's pollers do not all tick together.
# ``jitter`` is the +/- fraction each interval varies by (timer-driven pollers
# a few %, humans a lot). Classes (see DAY_PROFILES): ``ot`` and ``infra`` are
# steady 24/7; ``office`` follows the working day; ``eng`` happens in the day
# shift only; ``operator`` is 24/7 with a day bias; ``backup`` peaks at night.
PERIODS: Dict[str, Tuple[float, float, float, int, str]] = {
    # HMI / SCADA / historian polling (persistent sessions, see PERSISTENT)
    "modbus": (0.5, 2.0, 0.03, 1, "ot"),
    "enip": (0.5, 2.0, 0.03, 1, "ot"),
    "s7comm": (0.5, 2.0, 0.03, 1, "ot"),
    "s7plus": (0.5, 2.0, 0.03, 1, "ot"),
    "opcua": (1.0, 1.0, 0.02, 1, "ot"),       # 1 s publishing interval
    "mms": (2.0, 5.0, 0.03, 1, "ot"),
    "slmp": (0.5, 2.0, 0.03, 1, "ot"),
    "srtp": (0.5, 2.0, 0.03, 1, "ot"),
    "fins": (0.5, 2.0, 0.03, 1, "ot"),
    "hart-ip": (5.0, 15.0, 0.05, 1, "ot"),
    "dnp3": (2.0, 10.0, 0.05, 1, "ot"),       # event polls (+ integrity)
    "iec104": (2.0, 10.0, 0.30, 1, "ot"),     # spontaneous + TESTFR
    "bacnet": (30.0, 60.0, 0.05, 1, "ot"),
    "mqtt": (10.0, 60.0, 0.05, 1, "ot"),
    "sparkplug": (10.0, 60.0, 0.05, 1, "ot"),
    # cyclic / L2 industrial (one occurrence = one builder burst)
    "enip-io": (0.02, 0.1, 0.01, 1, "ot"),    # class-1 RPI 20-100 ms
    "pn-rt": (0.5, 0.5, 0.01, 1, "ot"),
    "goose": (1.0, 2.0, 0.01, 1, "ot"),       # GOOSE heartbeat
    "sv": (1.0, 1.0, 0.01, 1, "ot"),
    "ptp": (1.0, 1.0, 0.01, 1, "infra"),      # Sync interval
    "ptp-l2": (1.0, 1.0, 0.01, 1, "infra"),
    "pn-dcp": (300.0, 900.0, 0.10, 1, "infra"),
    # asset-management / identity reads
    "enip-id": (600.0, 1800.0, 0.10, 1, "infra"),
    "s7-id": (600.0, 1800.0, 0.10, 1, "infra"),
    "modbus-id": (600.0, 1800.0, 0.10, 1, "infra"),
    "bacnet-id": (600.0, 1800.0, 0.10, 1, "infra"),
    "dnp3-id": (600.0, 1800.0, 0.10, 1, "infra"),
    "enip-list": (600.0, 1800.0, 0.10, 1, "infra"),
    # engineering + operator activity: a few per hour
    "s7-eng": (1200.0, 3600.0, 0.50, 1, "eng"),
    "enip-eng": (1200.0, 3600.0, 0.50, 1, "eng"),
    "pn-dcp-set": (3600.0, 7200.0, 0.50, 1, "eng"),
    "modbus-write": (300.0, 1800.0, 0.50, 1, "operator"),
    "dnp3-time": (3600.0, 3600.0, 0.02, 1, "infra"),
    "iec104-time": (3600.0, 3600.0, 0.02, 1, "infra"),
    "ftp": (3600.0, 14400.0, 0.50, 1, "eng"),
    "tftp": (3600.0, 14400.0, 0.50, 1, "eng"),
    "http-fw": (7200.0, 28800.0, 0.50, 1, "eng"),
    "ssh": (900.0, 3600.0, 0.50, 1, "eng"),
    "rdp": (1800.0, 7200.0, 0.50, 1, "eng"),
    "vnc": (1800.0, 7200.0, 0.50, 1, "eng"),
    "telnet": (1800.0, 7200.0, 0.50, 1, "eng"),
    # IT, user-driven
    "http": (30.0, 120.0, 0.60, 3, "office"),
    "https": (20.0, 90.0, 0.60, 2, "office"),
    "smb": (60.0, 300.0, 0.50, 2, "office"),
    "kerberos": (600.0, 3600.0, 0.30, 1, "office"),
    "ldap": (300.0, 900.0, 0.30, 1, "office"),
    "dns": (10.0, 60.0, 0.60, 1, "office"),   # on demand
    "icmp": (60.0, 300.0, 0.30, 1, "infra"),
    # infrastructure
    "dhcp": (14400.0, 14400.0, 0.05, 1, "infra"),   # renew at T1 of 8 h lease
    "netbios": (720.0, 720.0, 0.10, 1, "infra"),    # 12-minute announce
    "ntp": (64.0, 1024.0, 0.05, 1, "infra"),
    "snmp": (300.0, 300.0, 0.02, 1, "infra"),
    "snmpv3": (300.0, 300.0, 0.02, 1, "infra"),
    "lldp": (30.0, 30.0, 0.02, 1, "infra"),
    "cdp": (60.0, 60.0, 0.02, 1, "infra"),
    "syslog": (60.0, 600.0, 0.80, 1, "infra"),
    "mdns": (60.0, 300.0, 0.50, 1, "infra"),
    "ssdp": (60.0, 300.0, 0.50, 1, "infra"),
    "llmnr": (60.0, 300.0, 0.50, 1, "infra"),
    "nbns": (60.0, 300.0, 0.50, 1, "infra"),
    "arp": (30.0, 120.0, 0.20, 1, "infra"),   # per host: cache timeout
    "edr": (30.0, 60.0, 0.20, 1, "infra"),    # Falcon heartbeat
    "edr-bulk": (600.0, 1800.0, 0.30, 1, "infra"),  # telemetry upload / pulls
    # serial-to-Ethernet gateways and IIoT (tgt/protocols_iiot.py): a serial
    # master polls slower than an Ethernet one (each poll waits on the line)
    "modbus-rtu-tcp": (1.0, 5.0, 0.05, 1, "ot"),
    "dnp3-serial": (2.0, 10.0, 0.05, 1, "ot"),
    "realcom": (1.0, 5.0, 0.05, 1, "ot"),
    "realcom-cmd": (10.0, 30.0, 0.05, 1, "infra"),   # POLLING / ALIVE
    "moxa-discovery": (1800.0, 7200.0, 0.50, 1, "eng"),
    "bacnet-sc": (30.0, 300.0, 0.02, 1, "ot"),    # heartbeat <= 300 s timeout
    "lorawan-udp": (10.0, 60.0, 0.30, 1, "ot"),   # PULL_DATA 10 s + uplinks
}
DEFAULT_PERIOD = (60.0, 300.0, 0.30, 1, "infra")

# ARP refresh by host kind: (lo, hi) seconds. Windows reachable time is
# 15-45 s, Linux ~30 s plus GC; embedded stacks keep entries for minutes.
ARP_PERIODS = {"windows": (30.0, 60.0), "linux": (45.0, 120.0),
               "embedded": (300.0, 1200.0)}

# Sprinkled / incident attack traffic: how often each attack flow recurs.
ATTACK_PERIODS: Dict[str, Tuple[float, float, float]] = {
    "c2-beacon": (60.0, 60.0, 0.20),
    "https-c2": (60.0, 120.0, 0.20),
    "dga-dns": (120.0, 300.0, 0.30),
    "dns-tunnel": (30.0, 60.0, 0.30),
}
DEFAULT_ATTACK_PERIOD = (600.0, 1200.0, 0.30)

# ---------------------------------------------------------------------------
# Persistent sessions
# ---------------------------------------------------------------------------
# key: (setup exchanges, teardown exchanges, (lifetime lo, hi) seconds)
#
# The flow builder's session is cut into exchanges (the handshake is one;
# FIN/RST starts the last): the first ``setup`` open the connection (TCP
# handshake, RegisterSession, COTP + Setup Communication, Hello/OPN/
# CreateSession, Forward_Open...), the last ``teardown`` close it; the rest are
# polls, one per occurrence. The connection stays up for ``lifetime`` (picked
# per conversation; 0 = forever) and then reconnects. selftest checks this
# table against the builders.
PERSISTENT: Dict[str, Tuple[int, int, Tuple[float, float]]] = {
    "modbus": (1, 1, (43200.0, 172800.0)),
    "enip": (2, 2, (43200.0, 172800.0)),
    "s7comm": (3, 1, (43200.0, 172800.0)),
    "s7plus": (4, 2, (43200.0, 172800.0)),
    "opcua": (6, 3, (43200.0, 172800.0)),
    "mms": (6, 2, (43200.0, 172800.0)),
    "slmp": (2, 1, (43200.0, 172800.0)),
    "srtp": (2, 2, (43200.0, 172800.0)),
    "hart-ip": (4, 2, (43200.0, 172800.0)),
    "dnp3": (1, 1, (0.0, 0.0)),
    "iec104": (3, 1, (0.0, 0.0)),
    "enip-io": (3, 3, (0.0, 0.0)),
    "edr": (3, 1, (21600.0, 86400.0)),
    "dhcp": (2, 0, (0.0, 0.0)),      # DORA once, then a renewal per period
    "modbus-rtu-tcp": (1, 1, (43200.0, 172800.0)),
    "dnp3-serial": (1, 1, (0.0, 0.0)),
    "realcom": (1, 1, (0.0, 0.0)),
    "realcom-cmd": (2, 1, (0.0, 0.0)),   # PORT_INIT, then keep-alives
    "bacnet-sc": (4, 2, (0.0, 0.0)),     # TLS, upgrade, Connect / Disconnect
}
# Polls built per builder call (a chunk) for a persistent session.
CHUNK = 256

# key: (period seconds, index of the setup exchange to repeat)
#
# A setup exchange that recurs on the open connection instead of a poll: the
# IEC 104 master's station (general) interrogation, C_IC_NA_1, every 15 min.
REFRESH: Dict[str, Tuple[float, int]] = {
    "iec104": (900.0, 2),
}

# ---------------------------------------------------------------------------
# Latency
# ---------------------------------------------------------------------------
# request -> response round trip (seconds) by path: both hosts on one
# segment (switched), different internal segments (routed through the core),
# or one side outside the site (internet / cloud).
RTT: Dict[str, Tuple[float, float]] = {
    "segment": (0.00015, 0.0006),
    "routed": (0.001, 0.005),
    "wan": (0.02, 0.08),
}
# time the answering side spends before replying (seconds): an embedded
# controller answers after a scan, a server almost at once
PROCESSING: Dict[str, Tuple[float, float]] = {
    "embedded": (0.001, 0.008),
    "host": (0.0001, 0.0015),
    # a protocol key overrides both: a serial gateway answers only once the
    # request has crossed the line (9600 baud: ~1 ms a byte), the slave has
    # turned it around and its reply has come back
    "modbus-rtu-tcp": (0.03, 0.12),
    "dnp3-serial": (0.05, 0.25),
    "realcom": (0.03, 0.12),
}
# a client's turn-around between receiving a reply and its next segment
THINK = (0.00005, 0.0005)
# back-to-back segments from one side (serialisation + stack)
GAP = 0.00002
# delayed-ACK timer by default (stacks.py's per-OS delack_ms wins)
DELACK = 0.04

# ---------------------------------------------------------------------------
# Day / week activity profiles
# ---------------------------------------------------------------------------
# profile -> class -> (weekday factors by local hour 0-23, weekend factors).
# A factor scales the class's occurrence rate (1 = the table period). Classes
# not listed (ot, infra) stay at 1 around the clock.
_OFFICE_WD = [0.02, 0.02, 0.02, 0.02, 0.02, 0.05, 0.3, 2.5,   # logons ~07:00
              1.2, 1.0, 1.0, 1.0, 0.45, 0.9, 1.0, 1.0,      # lunch dip
              0.8, 0.4, 0.15, 0.08, 0.05, 0.04, 0.03, 0.02]
_ENG_WD = [0.0] * 7 + [1.0] * 5 + [0.3] + [1.0] * 4 + [0.0] * 7   # 07-17
_OPER_WD = [0.4] * 6 + [1.0] * 12 + [0.5] * 6
_BACKUP = [0.05, 0.05, 6.0, 2.0] + [0.05] * 20               # backups ~02:00
DAY_PROFILES: Dict[str, Dict[str, Tuple[list, list]]] = {
    "flat": {},
    "shift": {
        "office": (_OFFICE_WD, [0.03] * 24),        # quiet weekends
        "eng": (_ENG_WD, [0.0] * 24),
        "operator": (_OPER_WD, [0.5] * 24),
        "backup": (_BACKUP, _BACKUP),
    },
}

_UNIT = {"ms": 0.001, "s": 1.0, "m": 60.0, "min": 60.0, "h": 3600.0,
         "d": 86400.0, "w": 604800.0}


def parse_duration(text) -> float:
    """``90`` / ``"90s"`` / ``"500ms"`` / ``"30m"`` / ``"4h"`` / ``"7d"`` /
    ``"1h30m"`` -> seconds."""
    if isinstance(text, (int, float)):
        return float(text)
    t = str(text).strip().lower()
    try:
        return float(t)
    except ValueError:
        pass
    parts = re.findall(r"(\d+(?:\.\d+)?)\s*(ms|min|s|m|h|d|w)", t)
    if not parts or re.sub(r"(\d+(?:\.\d+)?)\s*(ms|min|s|m|h|d|w)|\s", "", t):
        raise ValueError(f"bad duration {text!r}: use e.g. 90, 30s, 15m, "
                         "4h, 7d")
    return sum(float(n) * _UNIT[u] for n, u in parts)


def _h(*parts) -> float:
    """Stable hash of ``parts`` -> [0, 1)."""
    return zlib.crc32(":".join(map(str, parts)).encode()) / 4294967296.0


def pick(lo: float, hi: float, *key) -> float:
    """A value in [lo, hi], log-uniform, fixed by ``key``."""
    if hi <= lo or lo <= 0:
        return lo
    return math.exp(math.log(lo) + (math.log(hi) - math.log(lo)) * _h(*key))


def spec(proto: str) -> Tuple[float, float, float, int, str]:
    return PERIODS.get(proto, DEFAULT_PERIOD)


def activity_class(proto: str, client_role: str = "",
                   server_role: str = "") -> str:
    """Day-profile class of a conversation: the table's, refined by who is
    talking — user traffic from servers is unattended (``infra``), from an
    HMI it is the operator's (24/7), and SMB from servers to a file share or
    historian is a nightly backup."""
    cls = spec(proto)[4]
    if cls == "office":
        if proto in ("smb", "ftp") and server_role in ("file", "hist") \
                and client_role not in ("ws", "jump"):
            return "backup"
        if client_role in ("hmi", "scada"):
            return "operator"
        if client_role not in ("ws", "jump", "eng", ""):
            return "infra"
    return cls


def conversation_timing(env, conv) -> Dict[str, float]:
    """Nominal ``{"period": s, "jitter": frac}`` of one environment
    conversation ``(client, server, proto)``: the env file's values, else the
    protocol table's (period fixed per conversation)."""
    c, s, proto = conv
    lo, hi, jit, _, _ = spec(proto)
    out = {"period": pick(lo, hi, c, s, proto), "jitter": jit}
    over = (getattr(env, "timing", None) or {}).get(tuple(conv)) or {}
    for k in ("period", "jitter"):
        if over.get(k) is not None:
            out[k] = float(over[k])
    return out


def arp_period(host) -> float:
    kind = ("embedded" if host.embedded else
            "windows" if host.os.startswith("win") else "linux")
    lo, hi = ARP_PERIODS[kind]
    return pick(lo, hi, host.name, "arp")


def path_kind(seg_a, seg_b) -> str:
    """``segment`` / ``routed`` / ``wan`` for two hosts' segments (``None`` =
    outside the site)."""
    if seg_a is None or seg_b is None:
        return "wan"
    return "segment" if seg_a is seg_b else "routed"


def factor(profile: Optional[str], cls: str, epoch: float,
           utc_offset: float = 0.0) -> float:
    """Activity factor of ``cls`` at ``epoch`` (seconds) under ``profile``."""
    table = DAY_PROFILES.get(profile or "flat", {}).get(cls)
    if not table:
        return 1.0
    t = datetime.datetime.fromtimestamp(epoch + utc_offset * 3600.0,
                                        datetime.timezone.utc)
    hours = table[1] if t.weekday() >= 5 else table[0]
    return hours[t.hour]


def peak(profile: Optional[str], cls: str) -> float:
    """Largest factor ``cls`` reaches under ``profile`` (thinning bound)."""
    table = DAY_PROFILES.get(profile or "flat", {}).get(cls)
    if not table:
        return 1.0
    return max(max(table[0]), max(table[1])) or 1.0
