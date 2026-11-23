"""EDR traffic profiles: who a covered host's sensor talks to, and how.

A :class:`Profile` is one EDR product (key, label, vendor, TLS client
template) with one or more :class:`Region` clouds. A region names an FQDN per
channel and a cloud IP pool, and records where each came from:

* ``ip_provenance``: ``published`` (the vendor's published list) or
  ``documentation`` (RFC 5737 placeholders, never real servers);
* ``host_provenance``: per channel, ``vendor-docs``, ``mirrored-docs`` or
  ``unverified``.

Channels: ``sensor`` (a long-lived, low-rate heartbeat on every covered host),
``upload`` (client-heavy telemetry), ``download`` (server-heavy content and
policy) and ``api`` (management, from one anchor host only).

Everything here only crafts frames. Application data is opaque seeded bytes:
no customer IDs, tokens, agent IDs or sensor protocol content, and no code
path opens a connection to a vendor service.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

CHANNELS = ("sensor", "upload", "download", "api")
IP_PROVENANCE = ("published", "documentation")
HOST_PROVENANCE = ("mirrored-docs", "vendor-docs", "unverified")
DEFAULT_PROFILE = "crowdstrike"
DEFAULT_PROXY_PORT = 8080

# CrowdStrike's EU-1 cloud (AWS eu-central-1 / Frankfurt): the sensor reaches
# it by FQDN, and each name resolves to many addresses from this published
# egress set.
CROWDSTRIKE_FQDNS = {
    "ts": "ts01-lanner-lion.cloudsink.net",        # sensor channel
    "up": "lfoup01-lanner-lion.cloudsink.net",     # telemetry upload
    "down": "lfodown01-lanner-lion.cloudsink.net",  # content / policy download
    "api": "api.eu-1.crowdstrike.com",             # OAuth2 API / console
}

CROWDSTRIKE_CLOUD_IPS = [
    "18.158.187.80", "18.198.53.88", "3.121.187.176", "3.121.238.86",
    "3.121.6.180", "3.125.15.130", "18.194.222.197", "18.197.35.253",
    "3.122.135.178", "35.157.198.104", "63.179.114.102", "63.179.203.249",
    "18.196.94.202", "3.121.28.37", "52.29.26.172", "18.158.141.230",
    "18.184.139.200", "18.195.129.87", "3.64.87.158", "3.73.169.253",
    "3.79.224.18", "52.28.120.115", "52.57.246.231", "3.123.89.179",
    "3.126.96.195", "3.69.129.49", "18.184.114.155", "18.194.8.224",
    "3.121.13.180", "3.123.240.202", "3.78.32.129", "35.156.219.65",
    "3.69.184.79", "3.76.143.53", "3.77.82.22",
]

_RFC5737 = tuple(ipaddress.ip_network(n) for n in
                 ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))


@dataclass(frozen=True)
class Region:
    key: str
    fqdns: Dict[str, str]              # channel -> hostname
    ips: Tuple[str, ...]
    ip_provenance: str
    host_provenance: Dict[str, str]    # channel -> provenance


@dataclass(frozen=True)
class Profile:
    key: str
    label: str
    vendor: str
    tls_client: str                    # a tgt.tls.TEMPLATES key
    regions: Dict[str, Region]
    default_region: str


def _doc_pool(prefix: str, first: int, n: int = 8) -> Tuple[str, ...]:
    return tuple(f"{prefix}.{first + i}" for i in range(n))


def _cs_region(key: str, tag: str, api: str, ips, ip_prov: str,
               sensor_prov: str = "mirrored-docs") -> Region:
    return Region(
        key,
        {"sensor": f"ts01-{tag}.cloudsink.net",
         "upload": f"lfoup01-{tag}.cloudsink.net",
         "download": f"lfodown01-{tag}.cloudsink.net", "api": api},
        tuple(ips), ip_prov,
        {"sensor": sensor_prov, "upload": sensor_prov,
         "download": sensor_prov, "api": "vendor-docs"})


# The placeholder pools avoid the addresses the incident library uses for its
# synthetic C2 (198.51.100.20-44, 203.0.113.10), so EDR and attack traffic
# never share an endpoint.
PROFILES: Dict[str, Profile] = {
    "crowdstrike": Profile(
        "crowdstrike", "CrowdStrike Falcon", "CrowdStrike", "falcon",
        {r.key: r for r in (
            _cs_region("us-1", "b", "api.crowdstrike.com",
                       _doc_pool("192.0.2", 64), "documentation"),
            _cs_region("us-2", "gyr-maverick", "api.us-2.crowdstrike.com",
                       _doc_pool("198.51.100", 64), "documentation"),
            Region("eu-1",
                   {"sensor": CROWDSTRIKE_FQDNS["ts"],
                    "upload": CROWDSTRIKE_FQDNS["up"],
                    "download": CROWDSTRIKE_FQDNS["down"],
                    "api": CROWDSTRIKE_FQDNS["api"]},
                   tuple(CROWDSTRIKE_CLOUD_IPS), "published",
                   {"sensor": "mirrored-docs", "upload": "mirrored-docs",
                    "download": "mirrored-docs", "api": "vendor-docs"}),
            # public copies of the requirements disagree on these sensor
            # hostnames, so they stay marked unverified
            _cs_region("us-gov-1", "laggar-gcw",
                       "api.laggar.gcw.crowdstrike.com",
                       _doc_pool("203.0.113", 64), "documentation",
                       sensor_prov="unverified"),
        )}, "eu-1"),
    "generic": Profile(
        "generic", "Generic EDR (vendor-neutral)", "Generic EDR",
        "edr-generic",
        {"lab": Region(
            "lab",
            {"sensor": "sensor.edr.example", "upload": "upload.edr.example",
             "download": "download.edr.example", "api": "api.edr.example"},
            _doc_pool("192.0.2", 128), "documentation",
            {c: "unverified" for c in CHANNELS})}, "lab"),
}
