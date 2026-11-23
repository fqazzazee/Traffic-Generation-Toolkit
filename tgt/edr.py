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

import copy
import ipaddress
import json
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


# ---------------------------------------------------------------------------
# The "edr" block (env file, CLI)
# ---------------------------------------------------------------------------
_BLOCK_KEYS = {"enabled", "profile", "region", "proxy", "proxy_port"}
_CUSTOM_KEYS = {"vendor", "label", "fqdns", "ips", "tls_client"}
_HOSTNAME = re.compile(r"(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+"
                       r"[a-z]([a-z0-9-]{0,61}[a-z0-9])?", re.I)


class EdrError(ValueError):
    """A bad EDR setting; ``path`` is the key inside the block."""

    def __init__(self, path: str, msg: str) -> None:
        super().__init__(f"{path}: {msg}" if path else msg)
        self.path, self.msg = path, msg


@dataclass(frozen=True)
class Setup:
    """An explicit EDR configuration, resolved. ``block`` is what the env
    file holds and what an export writes back."""
    enabled: bool
    block: Dict[str, Any]
    profile: Optional[Profile] = None
    region: Optional[Region] = None
    proxy: Optional[str] = None
    proxy_port: int = DEFAULT_PROXY_PORT


def _text(block: Dict[str, Any], key: str) -> str:
    v = block[key]
    if not isinstance(v, str) or not v:
        raise EdrError(key, f"expected a non-empty string, got {v!r}")
    return v


def _custom_region(block: Dict[str, Any]) -> Region:
    for k in ("vendor", "fqdns", "ips"):
        if k not in block:
            raise EdrError("", f"profile 'custom' needs {k!r}")
    fqdns = block["fqdns"]
    if not isinstance(fqdns, dict):
        raise EdrError("fqdns", "expected an object of channel: hostname")
    extra = sorted(set(fqdns) - set(CHANNELS))
    if extra:
        raise EdrError(f"fqdns.{extra[0]}", "unknown channel (allowed: "
                       f"{', '.join(CHANNELS)})")
    for c in CHANNELS:
        if c not in fqdns:
            raise EdrError("fqdns", f"missing channel {c!r}")
        if not isinstance(fqdns[c], str) or not _HOSTNAME.fullmatch(fqdns[c]):
            raise EdrError(f"fqdns.{c}", f"not a hostname: {fqdns[c]!r}")
    ips = block["ips"]
    if not isinstance(ips, list) or not ips:
        raise EdrError("ips", "expected a non-empty list of IPv4 addresses")
    for i, ip in enumerate(ips):
        p = f"ips[{i}]"
        try:
            a = ipaddress.IPv4Address(ip)
        except (ipaddress.AddressValueError, ValueError):
            raise EdrError(p, f"not an IPv4 address: {ip!r}") from None
        if (a.is_multicast or a.is_loopback or a.is_unspecified
                or a.is_link_local or a.is_reserved):
            raise EdrError(p, f"{ip} is not a unicast cloud address")
        if ip in ips[:i]:
            raise EdrError(p, f"duplicate address {ip}")
    doc = all(any(ipaddress.ip_address(ip) in n for n in _RFC5737)
              for ip in ips)
    return Region(str(block.get("region", "custom")),
                  {c: fqdns[c] for c in CHANNELS}, tuple(ips),
                  "documentation" if doc else "published",
                  {c: "unverified" for c in CHANNELS})


def _custom_profile(block: Dict[str, Any]) -> Profile:
    from . import tls
    region = _custom_region(block)
    vendor = _text(block, "vendor")
    label = _text(block, "label") if "label" in block else f"{vendor} (custom)"
    key = _text(block, "tls_client") if "tls_client" in block \
        else "edr-generic"
    tpl = tls.TEMPLATES.get(key)
    if tpl is None:
        raise EdrError("tls_client", f"{key!r} is not one of "
                       f"{', '.join(sorted(tls.TEMPLATES))}")
    if tls.handshake(tpl, tls.SERVERS["openssl"], "probe.edr.example",
                     ("edr-probe",))[1].cs is None:
        raise EdrError("tls_client", f"{key!r} cannot negotiate TLS with a "
                       "current server")
    return Profile("custom", label, vendor, key, {region.key: region},
                   region.key)


def resolve(raw: Any) -> Setup:
    """Validate an ``edr`` block (everything that needs no environment)."""
    if not isinstance(raw, dict):
        raise EdrError("", "expected an object, got "
                       f"{type(raw).__name__}")
    extra = sorted(set(raw) - _BLOCK_KEYS - _CUSTOM_KEYS)
    if extra:
        raise EdrError(extra[0], "unknown key (allowed: "
                       f"{', '.join(sorted(_BLOCK_KEYS | _CUSTOM_KEYS))})")
    block = copy.deepcopy(raw)
    enabled = block.get("enabled", True)
    if not isinstance(enabled, bool):
        raise EdrError("enabled", f"expected true or false, got {enabled!r}")
    if not enabled:
        return Setup(False, block)
    key = _text(block, "profile") if "profile" in block else DEFAULT_PROFILE
    if key == "custom":
        profile = _custom_profile(block)
    else:
        if key not in PROFILES:
            raise EdrError("profile", f"{key!r} is not one of "
                           f"{', '.join(list(PROFILES) + ['custom'])}")
        stray = sorted(set(block) & _CUSTOM_KEYS)
        if stray:
            raise EdrError(stray[0], "only valid with profile 'custom'")
        profile = PROFILES[key]
    rkey = _text(block, "region") if "region" in block \
        else profile.default_region
    if rkey not in profile.regions:
        raise EdrError("region", f"{rkey!r} is not a region of {key} (use "
                       f"{', '.join(profile.regions)})")
    proxy = _text(block, "proxy") if "proxy" in block else None
    port = block.get("proxy_port", DEFAULT_PROXY_PORT)
    if isinstance(port, bool) or not isinstance(port, int) \
            or not 1 <= port <= 65535:
        raise EdrError("proxy_port",
                       f"expected an integer 1..65535, got {port!r}")
    if "proxy_port" in block and proxy is None:
        raise EdrError("proxy_port", "needs 'proxy'")
    return Setup(True, block, profile, profile.regions[rkey], proxy, port)


def check(env, setup: Setup) -> None:
    """Validate ``setup`` against an environment's hosts and segments."""
    if not setup.enabled:
        return
    if setup.proxy is not None and \
            not any(h.name == setup.proxy for h in env.hosts):
        raise EdrError("proxy", f"no host named {setup.proxy!r} in "
                       f"environment {env.key}")
    taken = {h.ip: h.name for h in list(env.hosts) + list(env.external)}
    path = "ips" if setup.profile.key == "custom" else "region"
    for ip in setup.region.ips:
        if ip in taken:
            raise EdrError(path, f"cloud address {ip} is already used by "
                           f"{taken[ip]}")
        seg = next((s for s in env.segments if s.contains(ip)), None)
        if seg is not None:
            raise EdrError(path, f"cloud address {ip} is inside segment "
                           f"{seg.name}")


def apply(env, raw: Any):
    """A view of ``env`` running the EDR setup ``raw``; ``env`` is unchanged.
    With EDR off, declared ``edr`` flows are dropped as well."""
    setup = resolve(raw)
    check(env, setup)
    new = copy.copy(env)
    new.edr = setup
    new._edr_cache = None
    if not setup.enabled:
        new.conversations = [c for c in env.conversations if c[2] != "edr"]
    return new


_APPLIED: Dict[Tuple[int, str], Tuple[Any, Any]] = {}


def applied(env, raw: Any):
    """:func:`apply`, one object per (environment, block): the engine, the
    manifest and the scheduler then all see the same view."""
    key = (id(env), json.dumps(raw, sort_keys=True))
    hit = _APPLIED.get(key)
    if hit is None:
        hit = _APPLIED.setdefault(key, (env, apply(env, raw)))
    return hit[1]
