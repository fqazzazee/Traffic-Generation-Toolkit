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
from dataclasses import dataclass, replace
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
            if not isinstance(ip, str):     # IPv4Address(5) would be 0.0.0.5
                raise ValueError
            a = ipaddress.IPv4Address(ip)
        except (ipaddress.AddressValueError, ValueError):
            raise EdrError(p, f"not an IPv4 address: {ip!r}") from None
        if (a.is_multicast or a.is_loopback or a.is_unspecified
                or a.is_link_local or a.is_reserved
                or a in ipaddress.ip_network("0.0.0.0/8")):
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
    from .incidents import INCIDENTS
    # an attack's address never doubles as an EDR endpoint: its traffic would
    # read as EDR in the ground truth
    taken = {h.ip: f"incident {i.key}" for i in INCIDENTS.values()
             for h in i.hosts}
    taken.update({s.nat["outside_ip"]: f"the NAT of {s.name}"
                  for s in env.segments if s.nat})
    taken.update({h.ip: h.name for h in list(env.hosts) + list(env.external)})
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


def cli_block(current: Optional[Dict[str, Any]], spec: Optional[str],
              proxy: Optional[str]) -> Dict[str, Any]:
    """The ``edr`` block for ``--edr PROFILE[:REGION]|off`` and
    ``--edr-proxy HOST`` over the environment's own block (``current``).
    A new profile keeps the block's proxy. Only the block can define a
    custom profile, so ``--edr custom`` needs one."""
    base = copy.deepcopy(current or {})
    if spec == "off":
        if proxy:
            raise EdrError("", "--edr off and --edr-proxy contradict")
        return {"enabled": False}
    if spec is None:
        if base.get("enabled") is False:
            raise EdrError("", "--edr-proxy needs EDR on, but the environment "
                           "has it off; add --edr PROFILE")
        block = base
    else:
        key, colon, region = spec.partition(":")
        if colon and not region:
            raise EdrError("", f"{spec!r}: empty region, use PROFILE[:REGION]")
        if key == "custom":
            if base.get("profile") != "custom":
                raise EdrError("", "profile 'custom' is defined by the "
                               "environment file's edr block, and this "
                               "environment has none")
            block = base
            block.pop("enabled", None)
        else:
            block = {k: base[k] for k in ("proxy", "proxy_port") if k in base}
            block["profile"] = key
        if region:
            block["region"] = region
    if proxy is not None:
        block["proxy"] = proxy
    return block


def describe() -> List[str]:
    """``tgt edr list``: profiles, regions, hostnames and provenance."""
    lines: List[str] = []
    for p in PROFILES.values():
        lines.append(f"{p.key}: {p.label} (vendor {p.vendor}, TLS client "
                     f"{p.tls_client}, default region {p.default_region})")
        for r in p.regions.values():
            what = ("published list" if r.ip_provenance == "published"
                    else "RFC 5737 placeholders")
            lines.append(f"  {r.key}: {len(r.ips)} IPs, {r.ip_provenance} "
                         f"({what})")
            for c in CHANNELS:
                lines.append(f"    {c:9}{r.fqdns[c]}  "
                             f"[{r.host_provenance[c]}]")
    lines.append("custom: bring your own through the env file's edr block "
                 "(docs/edr.md)")
    return lines


# ---------------------------------------------------------------------------
# Who connects where
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Path:
    """One EDR channel of one host. ``proxy`` is the host relaying it, and
    ``dns`` the lookups it needs: (client, resolver, name, answer)."""
    host: Any
    channel: str
    fqdn: str
    ip: str
    bulk: bool
    proxy: Any = None
    dns: Tuple[Tuple[Any, Any, str, str], ...] = ()


def _resolver(env, host):
    """The DNS server ``host`` uses: its own DNS flow's, else the nearest
    server in the site (same segment, same zone, any). ``None`` without one,
    or when ``host`` is the only one."""
    names = {h.name for h in env.hosts}
    for c, sv, proto in env.conversations:
        if proto == "dns" and c == host.name and sv != c and sv in names:
            return env.host(sv)
    served = {sv for _, sv, p in env.conversations if p == "dns"}
    pool = [h for h in env.hosts if h.name != host.name
            and (h.role == "dns" or h.name in served)]
    if not pool:
        return None
    seg = env.segment_of(host)
    return next((h for h in pool if env.segment_of(h) is seg),
                next((h for h in pool if env.segment_of(h).zone == seg.zone),
                     pool[0]))


def paths(env) -> List[Path]:
    """Every EDR channel of the fleet: one sensor flow per host spread over
    the region's pool; one anchor host also uploads, downloads and is the
    only one that touches the management API."""
    from .enterprise import DNS_DOMAIN
    setup = env.edr
    fleet = env.edr_hosts()
    if setup is None or not setup.enabled or not fleet:
        return []
    fq, ips = setup.region.fqdns, setup.region.ips
    via = env.host(setup.proxy) if setup.proxy else None

    def path(h, channel: str, ip: str) -> Path:
        name = fq[channel]
        proxy = via if via is not None and via.name != h.name else None
        dns = []
        own = _resolver(env, h)
        if proxy is None:
            if own is not None:
                dns.append((h, own, name, ip))
        else:
            if own is not None:
                # the address h really connects to (a NAT site's outside IP)
                dns.append((h, own, f"{proxy.name.lower()}.{DNS_DOMAIN}",
                            env.nat_view(h, proxy)[1].ip))
            up = _resolver(env, proxy)
            if up is not None:
                dns.append((proxy, up, name, ip))
        return Path(h, channel, name, ip, channel in ("upload", "download"),
                    proxy, tuple(dns))

    out = [path(h, "sensor", ips[i % len(ips)]) for i, h in enumerate(fleet)]
    anchor = next((h for h in fleet
                   if h.role in ("hist", "file", "dc", "scada")), fleet[0])
    out += [path(anchor, "upload", ips[-1 % len(ips)]),
            path(anchor, "download", ips[-2 % len(ips)]),
            path(anchor, "api", ips[-3 % len(ips)])]
    return out


def legs(env) -> List[Tuple[Any, Any, str, Optional[str], int]]:
    """Every distinct conversation the EDR setup puts on the wire, as
    (client, server, protocol, cloud IP or None, server port)."""
    out: Dict[tuple, tuple] = {}

    def add(c, s, proto, ip, port) -> None:
        out.setdefault((c.name, s.name, proto), (c, s, proto, ip, port))

    for p in env.edr_paths():
        cloud = cloud_host(env.edr, p.ip, p.fqdn)
        if p.proxy is None:
            add(p.host, cloud, "edr", p.ip, 443)
        else:
            add(p.host, p.proxy, "edr", None, env.edr.proxy_port)
            add(p.proxy, cloud, "edr", p.ip, 443)
        for c, r, _, _ in p.dns:
            add(c, r, "dns", None, 53)
    return list(out.values())


def summary(env) -> Dict[str, Any]:
    """The active setup as the inventory reports it."""
    s = env.edr
    return {"profile": s.profile.key, "label": s.profile.label,
            "vendor": s.profile.vendor, "region": s.region.key,
            "fqdns": dict(s.region.fqdns),
            "ip_provenance": s.region.ip_provenance,
            "host_provenance": dict(s.region.host_provenance),
            "proxy": s.proxy,
            "proxy_port": s.proxy_port if s.proxy else None}


def cloud_host(setup: Setup, ip: str, fqdn: str):
    """An on-the-fly cloud endpoint; its MAC is cosmetic (``place`` rewrites
    it to the gateway as it egresses)."""
    from .enterprise import Host
    o = [int(x) for x in ip.split(".")]
    return Host(f"EDR-CLOUD-{ip}", ip,
                "02:00:5c:%02x:%02x:%02x" % tuple(o[1:]), "edr", "linux",
                setup.profile.vendor, fqdn, fqdn=fqdn)


# ---------------------------------------------------------------------------
# Frames
# ---------------------------------------------------------------------------
# Application record sizes per channel: (client, server) byte ranges
_SHAPES = {"sensor": ((60, 220), (60, 160)),
           "upload": ((1000, 1400), (60, 180)),
           "download": ((120, 320), (1000, 1400)),
           "api": ((220, 520), (400, 900))}
BULK_MESSAGES = 3      # enough records for the channel's shape to dominate


def endpoints(setup: Setup, path: Path, client, server, dport: int = 443,
              connect: bool = False):
    """Endpoints of one TCP leg of ``path``. Both legs of a proxied channel
    carry one TLS session, so they share its seed."""
    from .packet import Endpoints
    meta = {"sni": path.fqdn, "tls_client": setup.profile.tls_client,
            "edr_channel": path.channel, "edr_dport": dport,
            "edr_seed": f"{path.host.ip}|{path.ip}|{path.fqdn}|{path.channel}"}
    if connect:
        meta["edr_connect"] = f"{path.fqdn}:443"
    return Endpoints(client_mac=client.mac, client_ip=client.ip,
                     server_mac=server.mac, server_ip=server.ip,
                     ttl_client=client.fp.ttl, ttl_server=server.fp.ttl,
                     meta=meta, stack_client=client.stack,
                     stack_server=server.stack)


def channel_flow(ep, count: int) -> List[bytes]:
    """One TCP connection of a channel. With ``edr_connect`` it opens with
    HTTP CONNECT; the TLS session follows inside the tunnel. Application
    records are opaque seeded bytes. Callers hold ``protocols.BUILD_LOCK``."""
    from . import protocols, tls
    m = ep.meta
    up, down = _SHAPES[m["edr_channel"]]
    tpl = replace(tls.TEMPLATES[m["tls_client"]], upload=up, download=down)
    seed = ("edr", m["edr_seed"], protocols.build_context().cycle)
    exchanges, hs = tls.session(tpl, tls.SERVERS["openssl"], m["sni"], count,
                                seed)
    target = m.get("edr_connect")
    if target:
        req = (f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
               "Proxy-Connection: Keep-Alive\r\n\r\n").encode()
        exchanges.insert(0, (req, b"HTTP/1.1 200 Connection established"
                                  b"\r\n\r\n"))
        hs += 1
    return protocols._tcp_flow(ep, protocols._sport(), m["edr_dport"],
                               exchanges, idle_from=hs)


def setup_exchanges(setup: Setup) -> int:
    """Exchanges that open a direct channel: TCP plus the TLS handshake."""
    from . import tls
    tpl = tls.TEMPLATES[setup.profile.tls_client]
    return 1 + tls.session(tpl, tls.SERVERS["openssl"], "probe.edr.example",
                           1, ("edr-probe",))[1]


def dns_endpoints(env, client, resolver, name: str, ip: str):
    ep = env.conv_endpoints(client, resolver, "dns")
    ep.meta["dns_names"] = [(name, ip)]
    return ep


def _halves(group: List[bytes], cmac: bytes):
    """One exchange cut at the server's first data segment."""
    from .schedule import view
    for i, f in enumerate(group):
        frm, _, plen = view(f, cmac)[:3]
        if not frm and plen > 0:
            return group[:i], group[i:]
    return group, []


def _interleave(client: List[bytes], upstream: List[bytes], ccmac: bytes,
                ucmac: bytes, lookup: List[bytes]):
    """The two legs of a tunnel in causal order, as (leg, frame): CONNECT,
    the proxy's lookup and upstream handshake, its 200, then each request
    relayed up and each response relayed back."""
    from .schedule import exchanges
    cg, ug = exchanges(client, ccmac), exchanges(upstream, ucmac)
    out = [("c", f) for f in cg[0]]
    req, rsp = _halves(cg[1], ccmac)
    out += [("c", f) for f in req] + [("d", f) for f in lookup]
    out += [("u", f) for f in ug[0]] + [("c", f) for f in rsp]
    for c, u in zip(cg[2:-1], ug[1:-1]):
        creq, crsp = _halves(c, ccmac)
        ureq, ursp = _halves(u, ucmac)
        out += [("c", f) for f in creq] + [("u", f) for f in ureq]
        out += [("u", f) for f in ursp] + [("c", f) for f in crsp]
    out += [("c", f) for f in cg[-1]] + [("u", f) for f in ug[-1]]
    return out


def cycle_streams(env, messages: int, span: str):
    """The cycle builder's EDR streams; each is one channel, its lookups
    first, and a proxied channel's two legs in causal order. Runs inside the
    caller's build (``protocols.BUILD_LOCK``)."""
    from . import protocols
    from .packet import mac_to_bytes
    setup = env.edr
    seg = env.segment_or_none
    dns = protocols.get("dns").build
    out = []

    def placed(key, frames, c, s):
        return [(key, g) for g in (env.place(f, c, s, span, seg)
                                   for f in frames) if g]

    for p in env.edr_paths():
        n = max(BULK_MESSAGES, messages) if p.bulk else 1
        cloud = cloud_host(setup, p.ip, p.fqdn)
        items = []
        for c, r, name, ip in p.dns:
            if c is p.host:
                items += placed("dns", dns(dns_endpoints(env, c, r, name, ip),
                                           1), c, r)
        if p.proxy is None:
            ep = endpoints(setup, p, p.host, cloud)
            items += placed("edr", channel_flow(ep, n), p.host, cloud)
        else:
            cl = channel_flow(endpoints(setup, p, p.host, p.proxy,
                                        setup.proxy_port, connect=True), n)
            up = channel_flow(endpoints(setup, p, p.proxy, cloud), n)
            look: List[bytes] = []
            lookup_ends = None
            for c, r, name, ip in p.dns:
                if c is p.proxy:
                    look = dns(dns_endpoints(env, c, r, name, ip), 1)
                    lookup_ends = (c, r)
            for leg, f in _interleave(cl, up, mac_to_bytes(p.host.mac),
                                      mac_to_bytes(p.proxy.mac), look):
                if leg == "c":
                    items += placed("edr", [f], p.host, p.proxy)
                elif leg == "u":
                    items += placed("edr", [f], p.proxy, cloud)
                else:
                    items += placed("dns", [f], *lookup_ends)
        out.append(items)
    return out
