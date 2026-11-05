"""Data-defined environments — a site described in a JSON (or TOML) file.

``tgt run --env-file site.json``, ``tgt inventory --env-file site.json`` and
any file in an environment directory (``TGT_ENV_PATH``, then
``~/.config/tgt/envs/``) turn the file into an :class:`~tgt.enterprise.
Environment`, validated like the built-in ones. ``tgt env export KEY``
writes any environment out in this format; ``tgt/envs/`` holds exports of the
built-ins plus a hand-written ``example-site.json`` as references (the Python
definitions in :mod:`tgt.enterprise` stay the source of truth for built-ins).

TOML files (``.toml``) use the same schema and need Python 3.11+ (``tomllib``).

Schema (unknown keys are errors, so typos surface)::

    {
      "key": "my-plant",                 # [A-Za-z0-9._-], used with --env
      "name": "My Plant",
      "category": "OT",                  # IT | OT | mixed
      "description": "free text",
      "options": {...},                  # optional, see below
      "segments": [
        {"name": "AREA-PACKAGING", "vlan": 110, "subnet": "10.100.10.0/24",
         "zone": "OT-CELL",              # IT | DMZ | OT-SUPERVISORY | OT-CELL
         "gateway": "10.100.10.1"}       # optional, default: first address
      ],
      "hosts": [
        {"name": "HMI-PK1", "ip": "10.100.10.10", "role": "hmi", "os": "win10"},
        {"name": "PLC-PK{n:02}", "count": 4, "ip_start": "10.100.10.21",
         "model": "rockwell-1756-l71"},  # PLC-PK01..04 at .21-.24
        ...
      ],
      "flows": [
        {"client": "HMI-PK1", "server": "PLC-PK01", "proto": "enip"},
        {"from": "role:hmi@AREA-PACKAGING", "to": "role:plc@AREA-PACKAGING",
         "proto": "enip", "mode": "round-robin", "period": "1s", "jitter": "5%"},
        {"from": "role:ws", "proto": "netbios"}      # no "to": self-announce
      ]
    }

**hosts[]** — ``name``, ``ip``, ``role`` and ``os`` (a fingerprint key such as
``win10``, ``linux``, ``rockwell``, ``siemens``, ``ios``) are the basics.
``model`` names a :mod:`tgt.devices` catalog entry; with it ``role``, ``os``,
``vendor``, ``product`` and the MAC OUI default from the catalog. Optional
overrides: ``vendor``, ``product``, ``mac`` (default: the model's — else
VMware's — OUI + the last three IP octets), ``firmware``, ``serial``,
``fqdn``. ``count`` repeats the entry: ``name`` is a ``str.format`` template
over ``n`` (``start``, default 1, upward), addresses count up from
``ip_start`` (and from ``mac``, when given). ``meta`` / ``client_meta`` are
endpoint-meta overrides used when the host is the server / client of a flow
(e.g. ``{"snmp_sysdescr": "..."}``).

**flows[]** — explicit ``client`` + ``server`` names, or selector rules
``from`` [+ ``to``]. A selector is ``[kind:]value[@SEGMENT]``: a host name
(``*``/``?`` globs allowed), ``role:hmi``, ``zone:OT-CELL``,
``model:rockwell-1756-l71``, or ``*`` (every host); ``@SEGMENT`` keeps only
hosts in that segment (``@AREA-PACKAGING`` alone selects the whole segment).
``mode`` ``all`` (default) pairs every ``from`` host with every ``to`` host;
``round-robin`` gives each ``to`` host one client, cycling through the
``from`` hosts. Without ``to`` each ``from`` host talks to itself (NetBIOS /
LLDP announcements). ``proto`` is a protocol key (``tgt list``). A selector
that matches nothing is an error. Optional ``period`` (seconds, or "500ms",
"1s", "2m", or "1s±5%") and ``jitter`` ("5%" or a fraction) are kept on the
environment's ``timing`` map for a later time model; the cycle builder does
not use them yet.

**segments[]** optional keys — ``gateway_mac`` (the gateway's MAC when it
is not the HSRP virtual MAC), ``wan_rtt_ms`` (round-trip time of the WAN
link that reaches the segment, a time-model hint), and ``nat``:
``{"outside_ip": IP, "outside_mac"?: MAC, "local"?: bool}`` — a remote site
behind a NAT router. Its hosts appear as ``outside_ip`` (with the router's
MAC) in every frame that leaves the site; ``outside_ip`` may be a host in
another segment (a cellular modem on a WAN VLAN, whose MAC is then used) or
an address outside every segment (a carrier / internet address, reached
through the HQ gateway). Site-internal frames (LAN traffic, ARP) are not on
the HQ capture and are dropped unless ``local`` is true. See
:class:`tgt.enterprise.Environment`.

**findings[]** — optional ground truth for planted issues: ``{"id", "title",
"severity"?: info|low|medium|high|critical, "category"?, "hosts"?: [NAME...],
"flows"?: [{"client", "server", "proto"}...], "detail"?}``; flows must be
among the environment's flows. ``tgt inventory -f json`` lists them.

**options** — ``arp`` (default true: start-of-cycle ARP for gateway and
peers), ``flat`` (one VLAN for every segment), ``dual_homed`` (list of
``{"host": NAME, "ip": IP, "mac"?: MAC, "flows"?: [[SERVER, PROTO], ...]}``),
``snmp_community`` (string), ``default_snmp_community`` (true: polls use
"public"/"private"). See :class:`tgt.enterprise.Environment`.
"""
from __future__ import annotations

import copy
import fnmatch
import ipaddress
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

from . import devices, enterprise, protocols
from .enterprise import Conversation, Environment, Host, Segment

ZONES = ("IT", "DMZ", "OT-SUPERVISORY", "OT-CELL")
CATEGORIES = ("IT", "OT", "mixed")
_TOP_KEYS = {"key", "name", "category", "description", "options", "segments",
             "hosts", "flows", "findings"}
_SEG_KEYS = {"name", "vlan", "subnet", "zone", "gateway", "gateway_mac", "nat",
             "wan_rtt_ms"}
_NAT_KEYS = {"outside_ip", "outside_mac", "local"}
_FINDING_KEYS = {"id", "title", "severity", "category", "hosts", "flows",
                 "detail"}
SEVERITIES = ("info", "low", "medium", "high", "critical")
_HOST_KEYS = {"name", "ip", "role", "os", "model", "vendor", "product", "mac",
              "firmware", "serial", "fqdn", "count", "start", "ip_start",
              "meta", "client_meta"}
_FLOW_KEYS = {"client", "server", "from", "to", "proto", "mode", "period",
              "jitter"}
_OPTION_KEYS = {"arp", "flat", "dual_homed", "snmp_community",
                "default_snmp_community"}
_DUAL_KEYS = {"host", "ip", "mac", "flows"}

# catalog device class -> host role, and embedded vendor -> OS fingerprint,
# for hosts that only name a model
_ROLE_OF_TYPE = {"plc": "plc", "drive": "drive", "meter": "meter",
                 "relay": "relay", "rtu": "rtu", "bms-controller": "bms",
                 "bms-supervisor": "bms", "switch": "switch"}
_OS_OF_VENDOR = {"Rockwell Automation": "rockwell", "Siemens": "siemens",
                 "Schneider Electric": "schneider", "Johnson Controls": "bacnet",
                 "Tridium": "linux",
                 "Schweitzer Engineering Laboratories": "sel",
                 "Cisco Systems": "ios",
                 "Hirschmann Automation and Control": "hios", "Moxa": "moxa"}
_OS_OF_MODEL = {m: k for k, m in devices.OS_DEFAULT_MODEL.items()}

# the environments defined in Python (a directory file may not shadow them)
BUILTIN_KEYS = frozenset(enterprise.ENVIRONMENTS)


class EnvFileError(ValueError):
    """A malformed environment file; the message names the offending path
    (``site.json: hosts[3].ip: ...``)."""


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------
def load(path: str) -> Environment:
    """Parse + validate one environment file (``.json`` or ``.toml``)."""
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        raise EnvFileError(f"{path}: cannot read: {e.strerror or e}") from None
    fmt = "toml" if path.lower().endswith(".toml") else "json"
    env = loads(text, fmt, source=path)
    env.source = path               # type: ignore[attr-defined]
    return env


def loads(text: str, fmt: str = "json", source: str = "<env>") -> Environment:
    return from_dict(_parse(text, fmt, source), source)


def _parse(text: str, fmt: str, source: str) -> Any:
    if fmt == "toml":
        try:
            import tomllib            # Python 3.11+
        except ImportError:
            raise EnvFileError(
                f"{source}: TOML environment files need Python 3.11+ "
                f"(tomllib); this is {sys.version.split()[0]} — use JSON "
                "instead (tgt env export writes it)") from None
        try:
            return tomllib.loads(text)
        except tomllib.TOMLDecodeError as e:
            raise EnvFileError(f"{source}: invalid TOML: {e}") from None
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise EnvFileError(f"{source}: invalid JSON at line {e.lineno} "
                           f"column {e.colno}: {e.msg}") from None


class _Ctx:
    def __init__(self, source: str):
        self.source = source

    def err(self, path: str, msg: str) -> EnvFileError:
        return EnvFileError(f"{self.source}: {path}: {msg}" if path
                            else f"{self.source}: {msg}")

    def obj(self, v: Any, path: str, allowed: set,
            required: Tuple[str, ...] = ()) -> Dict[str, Any]:
        if not isinstance(v, dict):
            raise self.err(path, f"expected an object, got {_tname(v)}")
        extra = sorted(set(v) - allowed)
        if extra:
            raise self.err(f"{path}.{extra[0]}" if path else extra[0],
                           f"unknown key (allowed: {', '.join(sorted(allowed))})")
        for k in required:
            if k not in v:
                raise self.err(path, f"missing required key {k!r}")
        return v

    def list(self, v: Any, path: str) -> list:
        if not isinstance(v, list):
            raise self.err(path, f"expected a list, got {_tname(v)}")
        return v

    def str(self, v: Any, path: str, allow_empty: bool = False) -> str:
        if not isinstance(v, str) or (not v and not allow_empty):
            raise self.err(path, f"expected a non-empty string, got {v!r}")
        return v

    def int(self, v: Any, path: str, lo: int, hi: int) -> int:
        if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
            raise self.err(path, f"expected an integer {lo}..{hi}, got {v!r}")
        return v

    def bool(self, v: Any, path: str) -> bool:
        if not isinstance(v, bool):
            raise self.err(path, f"expected true or false, got {v!r}")
        return v

    def ip(self, v: Any, path: str) -> ipaddress.IPv4Address:
        try:
            return ipaddress.IPv4Address(self.str(v, path))
        except ipaddress.AddressValueError:
            raise self.err(path, f"not an IPv4 address: {v!r}") from None

    def mac(self, v: Any, path: str) -> str:
        s = self.str(v, path).lower().replace("-", ":")
        if not re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", s):
            raise self.err(path, f"not a MAC address (aa:bb:cc:dd:ee:ff): {v!r}")
        return s


def _tname(v: Any) -> str:
    return {dict: "an object", list: "a list", str: "a string",
            bool: "a boolean", int: "a number", float: "a number",
            type(None): "null"}.get(type(v), type(v).__name__)


def from_dict(doc: Any, source: str = "<env>") -> Environment:
    """Build an :class:`Environment` from a parsed env-file document."""
    cx = _Ctx(source)
    doc = cx.obj(doc, "", _TOP_KEYS, ("key", "segments", "hosts"))
    key = cx.str(doc["key"], "key")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", key):
        raise cx.err("key", f"{key!r}: use letters, digits, '.', '_' or '-'")
    name = cx.str(doc.get("name", key), "name")
    category = doc.get("category", "mixed")
    if category not in CATEGORIES:
        raise cx.err("category", f"{category!r} is not one of "
                     f"{', '.join(CATEGORIES)}")
    desc = cx.str(doc.get("description", ""), "description", allow_empty=True)

    segments = [_segment(cx, s, f"segments[{i}]")
                for i, s in enumerate(cx.list(doc["segments"], "segments"))]
    if not segments:
        raise cx.err("segments", "at least one segment is required")
    for attr in ("name", "vlan"):
        seen: Dict[Any, int] = {}
        for i, s in enumerate(segments):
            v = getattr(s, attr)
            if v in seen and not (attr == "vlan" and
                                  (doc.get("options") or {}).get("flat")):
                raise cx.err(f"segments[{i}].{attr}", f"duplicate {attr} {v!r} "
                             f"(also segments[{seen[v]}])")
            seen.setdefault(v, i)

    hosts: List[Host] = []
    host_meta: Dict[str, Dict[str, Dict[str, Any]]] = {}
    where: Dict[str, str] = {}             # host name -> path, for messages
    seg_of: Dict[str, Segment] = {}
    by_ip: Dict[str, str] = {}
    for i, raw in enumerate(cx.list(doc["hosts"], "hosts")):
        path = f"hosts[{i}]"
        for h, meta in _hosts(cx, raw, path):
            if h.name in where:
                raise cx.err(f"{path}.name", f"duplicate host name {h.name!r} "
                             f"(also {where[h.name]})")
            if h.ip in by_ip:
                raise cx.err(f"{path}.ip", f"{h.ip} already used by "
                             f"{by_ip[h.ip]}")
            hit = [s for s in segments if s.contains(h.ip)]
            if len(hit) != 1:
                raise cx.err(f"{path}.ip", f"{h.name} ({h.ip}) is inside "
                             f"{len(hit)} segments, expected exactly 1")
            if h.ip == hit[0].gateway:
                raise cx.err(f"{path}.ip", f"{h.name} uses the gateway "
                             f"address of {hit[0].name}")
            where[h.name], by_ip[h.ip], seg_of[h.name] = path, h.ip, hit[0]
            hosts.append(h)
            if meta:
                host_meta[h.name] = meta
    if not hosts:
        raise cx.err("hosts", "at least one host is required")

    conv: List[Conversation] = []
    timing: Dict[Conversation, Dict[str, Any]] = {}
    for i, raw in enumerate(cx.list(doc.get("flows", []), "flows")):
        path = f"flows[{i}]"
        pairs, t = _flows(cx, raw, path, hosts, seg_of, segments)
        conv += pairs
        if t:
            for c in pairs:
                timing[c] = dict(t)

    options = _options(cx, doc.get("options", {}), "options", where, segments)
    findings = [_finding(cx, f, f"findings[{i}]", where, conv)
                for i, f in enumerate(cx.list(doc.get("findings", []),
                                              "findings"))]
    ids = [f["id"] for f in findings]
    for i, fid in enumerate(ids):
        if fid in ids[:i]:
            raise cx.err(f"findings[{i}].id", f"duplicate finding id {fid!r}")
    try:
        env = Environment(key, name, category, desc, hosts, conv, segments,
                          options, host_meta, timing, findings)
    except ValueError as e:
        raise EnvFileError(f"{source}: {e}") from None
    env.source = source             # type: ignore[attr-defined]
    return env


def _segment(cx: _Ctx, raw: Any, path: str) -> Segment:
    d = cx.obj(raw, path, _SEG_KEYS, ("name", "vlan", "subnet", "zone"))
    name = cx.str(d["name"], f"{path}.name")
    vlan = cx.int(d["vlan"], f"{path}.vlan", 1, 4094)
    try:
        net = ipaddress.IPv4Network(cx.str(d["subnet"], f"{path}.subnet"))
    except ValueError as e:
        raise cx.err(f"{path}.subnet", f"{d['subnet']!r}: {e}") from None
    zone = d["zone"]
    if zone not in ZONES:
        raise cx.err(f"{path}.zone", f"{zone!r} is not one of "
                     f"{', '.join(ZONES)}")
    if "gateway" in d:
        gw = cx.ip(d["gateway"], f"{path}.gateway")
        if gw not in net:
            raise cx.err(f"{path}.gateway", f"{gw} is outside {net}")
    else:
        gw = net.network_address + 1
    opts: Dict[str, Any] = {}
    if "gateway_mac" in d:
        opts["gateway_mac"] = cx.mac(d["gateway_mac"], f"{path}.gateway_mac")
    if "wan_rtt_ms" in d:
        v = d["wan_rtt_ms"]
        if isinstance(v, bool) or not isinstance(v, (int, float)) or \
                not 0 < v <= 60000:
            raise cx.err(f"{path}.wan_rtt_ms", "expected a round-trip time "
                         f"in milliseconds (0 < ms <= 60000), got {v!r}")
        opts["wan_rtt_ms"] = v
    if "nat" in d:
        p = f"{path}.nat"
        n = cx.obj(d["nat"], p, _NAT_KEYS, ("outside_ip",))
        out = cx.ip(n["outside_ip"], f"{p}.outside_ip")
        if out in net:
            raise cx.err(f"{p}.outside_ip", f"{out} is inside the NAT'd "
                         f"subnet {net}")
        nat: Dict[str, Any] = {"outside_ip": str(out)}
        if "outside_mac" in n:
            nat["outside_mac"] = cx.mac(n["outside_mac"], f"{p}.outside_mac")
        if "local" in n:
            nat["local"] = cx.bool(n["local"], f"{p}.local")
        opts["nat"] = nat
    return Segment(name, vlan, str(net), zone, str(gw), opts)


def _finding(cx: _Ctx, raw: Any, path: str, where: Dict[str, str],
             conv: List[Conversation]) -> Dict[str, Any]:
    """One planted finding: who/what a monitor should flag (ground truth)."""
    d = cx.obj(raw, path, _FINDING_KEYS, ("id", "title"))
    out: Dict[str, Any] = {"id": cx.str(d["id"], f"{path}.id"),
                           "title": cx.str(d["title"], f"{path}.title")}
    if "severity" in d:
        if d["severity"] not in SEVERITIES:
            raise cx.err(f"{path}.severity", f"{d['severity']!r} is not one "
                         f"of {', '.join(SEVERITIES)}")
        out["severity"] = d["severity"]
    for k in ("category", "detail"):
        if k in d:
            out[k] = cx.str(d[k], f"{path}.{k}")
    out["hosts"] = []
    for i, h in enumerate(cx.list(d.get("hosts", []), f"{path}.hosts")):
        if cx.str(h, f"{path}.hosts[{i}]") not in where:
            raise cx.err(f"{path}.hosts[{i}]", f"no host named {h!r}")
        out["hosts"].append(h)
    out["flows"] = []
    known = set(conv)
    for i, f in enumerate(cx.list(d.get("flows", []), f"{path}.flows")):
        fp = f"{path}.flows[{i}]"
        f = cx.obj(f, fp, {"client", "server", "proto"},
                   ("client", "server", "proto"))
        if (f["client"], f["server"], f["proto"]) not in known:
            raise cx.err(fp, f"{f['client']} -> {f['server']} "
                         f"{f['proto']} is not one of the flows")
        out["flows"].append({"client": f["client"], "server": f["server"],
                             "proto": f["proto"]})
    if not out["hosts"] and not out["flows"]:
        raise cx.err(path, "a finding needs 'hosts' and/or 'flows'")
    return out


def _hosts(cx: _Ctx, raw: Any, path: str):
    """Yield (Host, meta) for one hosts[] entry (``count`` expands it)."""
    d = cx.obj(raw, path, _HOST_KEYS, ("name",))
    model = d.get("model", "")
    dev = None
    if model:
        dev = devices.find(cx.str(model, f"{path}.model"))
        if dev is None:
            raise cx.err(f"{path}.model", f"unknown device model {model!r} "
                         "(see tgt/devices.py CATALOG)")
    role = d.get("role") or (dev and _ROLE_OF_TYPE.get(dev.device_type))
    if not role:
        raise cx.err(path, "missing required key 'role'")
    role = cx.str(role, f"{path}.role")
    os_ = d.get("os") or (dev and (_OS_OF_MODEL.get(dev.model_id) or
                                   (_OS_OF_VENDOR.get(dev.vendor)
                                    if dev.embedded else "")))
    if not os_:
        raise cx.err(path, "missing required key 'os'")
    if os_ not in enterprise.FINGERPRINTS:
        raise cx.err(f"{path}.os", f"unknown OS fingerprint {os_!r} (one of "
                     f"{', '.join(enterprise.FINGERPRINTS)})")
    embedded_dev = dev is not None and dev.embedded
    vendor = cx.str(d["vendor"], f"{path}.vendor", True) if "vendor" in d \
        else (dev.vendor if embedded_dev else "")
    product = cx.str(d["product"], f"{path}.product", True) if "product" in d \
        else ((dev.aliases[0] if dev.aliases else dev.product)
              if embedded_dev else "")
    extra = {}
    for k in ("firmware", "serial", "fqdn"):
        if k in d:
            extra[k] = cx.str(d[k], f"{path}.{k}")
    meta: Dict[str, Dict[str, Any]] = {}
    for k, side in (("meta", "server"), ("client_meta", "client")):
        if k in d:
            if not isinstance(d[k], dict):
                raise cx.err(f"{path}.{k}", "expected an object")
            meta[side] = dict(d[k])
    oui = dev.ouis[0] if dev is not None else enterprise.OUI_WIN

    if "count" in d:
        count = cx.int(d["count"], f"{path}.count", 1, 65535)
        start = cx.int(d.get("start", 1), f"{path}.start", 0, 1 << 20)
        if "ip_start" not in d:
            raise cx.err(path, "'count' needs 'ip_start'")
        if "ip" in d:
            raise cx.err(f"{path}.ip", "use 'ip_start' with 'count'")
        ip0 = cx.ip(d["ip_start"], f"{path}.ip_start")
        mac0 = cx.mac(d["mac"], f"{path}.mac") if "mac" in d else None
        tpl = cx.str(d["name"], f"{path}.name")
        names = []
        for k in range(count):
            try:
                names.append(tpl.format(n=start + k))
            except (KeyError, IndexError, ValueError) as e:
                raise cx.err(f"{path}.name", f"bad name template {tpl!r}: "
                             f"{e!r} (use {{n}}, e.g. \"PLC-{{n:02}}\")") from None
        if len(set(names)) != count:
            raise cx.err(f"{path}.name", f"template {tpl!r} does not number "
                         "the hosts (use {n})")
        for k, nm in enumerate(names):
            ip = str(ip0 + k)
            mac = _mac_add(mac0, k) if mac0 else _auto_mac(oui, ip)
            yield _host(cx, f"{path}", nm, ip, mac, role, os_, vendor,
                        product, model, extra), meta
        return
    if "start" in d or "ip_start" in d:
        raise cx.err(path, "'start'/'ip_start' only apply with 'count'")
    if "ip" not in d:
        raise cx.err(path, "missing required key 'ip'")
    ip = str(cx.ip(d["ip"], f"{path}.ip"))
    mac = cx.mac(d["mac"], f"{path}.mac") if "mac" in d else _auto_mac(oui, ip)
    yield _host(cx, path, cx.str(d["name"], f"{path}.name"), ip, mac, role,
                os_, vendor, product, model, extra), meta


def _host(cx: _Ctx, path, name, ip, mac, role, os_, vendor, product, model,
          extra) -> Host:
    try:
        return Host(name, ip, mac, role, os_, vendor, product, model=model,
                    **extra)
    except (ValueError, KeyError) as e:
        raise cx.err(path, f"{name}: {e}") from None


def _auto_mac(oui: str, ip: str) -> str:
    o = ip.split(".")
    return "%s:%02x:%02x:%02x" % (oui, int(o[1]), int(o[2]), int(o[3]))


def _mac_add(mac: str, k: int) -> str:
    n = (int(mac.replace(":", ""), 16) + k) & ((1 << 48) - 1)
    return ":".join(f"{(n >> s) & 0xFF:02x}" for s in range(40, -8, -8))


# ---------------------------------------------------------------------------
# Flows: explicit pairs and selector rules
# ---------------------------------------------------------------------------
_SEL_KINDS = ("name", "role", "zone", "model", "os", "vendor")


def select(sel: str, hosts: List[Host], seg_of: Dict[str, Segment],
           segments: List[Segment]) -> List[Host]:
    """Hosts matching a selector (``role:plc@AREA-PACKAGING`` etc.), in host
    order. Raises ``ValueError`` for a malformed selector."""
    base, _, seg = sel.partition("@")
    if seg and seg not in {s.name for s in segments}:
        raise ValueError(f"unknown segment {seg!r} after '@'")
    kind, _, value = base.rpartition(":") if ":" in base else ("name", "", base)
    if kind not in _SEL_KINDS:
        raise ValueError(f"unknown selector kind {kind!r} (one of "
                         f"{', '.join(_SEL_KINDS)})")
    out = []
    for h in hosts:
        if seg and seg_of[h.name].name != seg:
            continue
        if not value and seg:
            out.append(h)
            continue
        field = {"name": h.name, "role": h.role, "zone": seg_of[h.name].zone,
                 "model": h.model, "os": h.os, "vendor": h.vendor}[kind]
        if (value == "*" or field == value or
                (kind == "name" and fnmatch.fnmatchcase(field, value))):
            out.append(h)
    if not value and not seg:
        raise ValueError("empty selector")
    return out


def _flows(cx: _Ctx, raw: Any, path: str, hosts: List[Host],
           seg_of: Dict[str, Segment], segments: List[Segment]):
    d = cx.obj(raw, path, _FLOW_KEYS, ("proto",))
    proto = cx.str(d["proto"], f"{path}.proto")
    if proto not in protocols.PROFILES:
        raise cx.err(f"{path}.proto", f"unknown protocol {proto!r} (see "
                     "'tgt list')")
    names = {h.name for h in hosts}
    timing = _timing(cx, d, path)
    if "client" in d or "server" in d:
        for k in ("from", "to", "mode"):
            if k in d:
                raise cx.err(f"{path}.{k}", "use either client/server or "
                             "from/to selectors, not both")
        for k in ("client", "server"):
            if k not in d:
                raise cx.err(path, f"missing required key {k!r}")
            if cx.str(d[k], f"{path}.{k}") not in names:
                raise cx.err(f"{path}.{k}", f"no host named {d[k]!r}")
        return [(d["client"], d["server"], proto)], timing
    if "from" not in d:
        raise cx.err(path, "needs client + server, or a 'from' selector")

    def pick(k: str) -> List[Host]:
        sel = cx.str(d[k], f"{path}.{k}")
        try:
            got = select(sel, hosts, seg_of, segments)
        except ValueError as e:
            raise cx.err(f"{path}.{k}", f"{sel!r}: {e}") from None
        if not got:
            raise cx.err(f"{path}.{k}", f"selector {sel!r} matches no host")
        return got

    clients = pick("from")
    if "to" not in d:
        if "mode" in d:
            raise cx.err(f"{path}.mode", "'mode' needs a 'to' selector")
        return [(h.name, h.name, proto) for h in clients], timing
    servers = pick("to")
    mode = d.get("mode", "all")
    if mode == "all":
        pairs = [(c.name, s.name, proto) for c in clients for s in servers
                 if c.name != s.name]
    elif mode == "round-robin":
        pairs = []
        for i, s in enumerate(servers):
            cands = [c for c in clients if c.name != s.name]
            if cands:
                pairs.append((cands[i % len(cands)].name, s.name, proto))
    else:
        raise cx.err(f"{path}.mode", f"{mode!r} is not 'all' or 'round-robin'")
    if not pairs:
        raise cx.err(path, "from/to select only the same host")
    return pairs, timing


_DUR = re.compile(r"\s*([0-9]*\.?[0-9]+)\s*(ms|s|m|h)?\s*$")
_PCT = re.compile(r"\s*([0-9]*\.?[0-9]+)\s*%\s*$")


def _seconds(cx: _Ctx, v: Any, path: str) -> float:
    if isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0:
        return float(v)
    m = _DUR.match(v) if isinstance(v, str) else None
    if not m or float(m.group(1)) <= 0:
        raise cx.err(path, f"expected a duration like 1, \"500ms\", \"2s\", "
                     f"\"5m\", got {v!r}")
    return float(m.group(1)) * {"ms": 0.001, "s": 1, None: 1, "m": 60,
                                "h": 3600}[m.group(2)]


def _fraction(cx: _Ctx, v: Any, path: str) -> float:
    if isinstance(v, (int, float)) and not isinstance(v, bool) and 0 <= v < 1:
        return float(v)
    m = _PCT.match(v) if isinstance(v, str) else None
    if not m or float(m.group(1)) >= 100:
        raise cx.err(path, f"expected a jitter like \"5%\" or 0.05, got {v!r}")
    return float(m.group(1)) / 100


def _timing(cx: _Ctx, d: Dict[str, Any], path: str) -> Dict[str, float]:
    t: Dict[str, float] = {}
    if "period" in d:
        p = d["period"]
        if isinstance(p, str) and "±" in p:
            p, j = p.split("±", 1)
            if "jitter" in d:
                raise cx.err(f"{path}.jitter", "jitter given twice (also "
                             "in period)")
            t["jitter"] = _fraction(cx, j, f"{path}.period")
        t["period"] = _seconds(cx, p, f"{path}.period")
    if "jitter" in d:
        t["jitter"] = _fraction(cx, d["jitter"], f"{path}.jitter")
    return t


def _options(cx: _Ctx, raw: Any, path: str, where: Dict[str, str],
             segments: List[Segment]) -> Dict[str, Any]:
    d = cx.obj(raw, path, _OPTION_KEYS)
    out: Dict[str, Any] = {}
    for k in ("arp", "flat", "default_snmp_community"):
        if k in d:
            out[k] = cx.bool(d[k], f"{path}.{k}")
    if "snmp_community" in d:
        out["snmp_community"] = cx.str(d["snmp_community"],
                                       f"{path}.snmp_community")
    if "dual_homed" in d:
        dual = []
        for i, e in enumerate(cx.list(d["dual_homed"], f"{path}.dual_homed")):
            p = f"{path}.dual_homed[{i}]"
            e = cx.obj(e, p, _DUAL_KEYS, ("host", "ip"))
            if cx.str(e["host"], f"{p}.host") not in where:
                raise cx.err(f"{p}.host", f"no host named {e['host']!r}")
            ip = str(cx.ip(e["ip"], f"{p}.ip"))
            if not any(s.contains(ip) for s in segments):
                raise cx.err(f"{p}.ip", f"{ip} is not inside any segment")
            item: Dict[str, Any] = {"host": e["host"], "ip": ip}
            if "mac" in e:
                item["mac"] = cx.mac(e["mac"], f"{p}.mac")
            if "flows" in e:
                fl = []
                for j, f in enumerate(cx.list(e["flows"], f"{p}.flows")):
                    if isinstance(f, dict):
                        f = [f.get("server"), f.get("proto")]
                    fp = f"{p}.flows[{j}]"
                    if (not isinstance(f, list) or len(f) != 2
                            or f[0] not in where
                            or f[1] not in protocols.PROFILES):
                        raise cx.err(fp, f"expected [SERVER, PROTO] with a "
                                     f"known host and protocol, got {f!r}")
                    fl.append([f[0], f[1]])
                item["flows"] = fl
            dual.append(item)
        out["dual_homed"] = dual
    return out


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------
def _auto_model(h: Host) -> str:
    return devices.resolve(h.product) or (
        "" if h.vendor else devices.os_default(h.os))


def _host_dict(env: Environment, h: Host) -> Dict[str, Any]:
    d: Dict[str, Any] = {"name": h.name, "ip": h.ip, "mac": h.mac,
                         "role": h.role, "os": h.os}
    explicit_model = h.model != _auto_model(h)
    if h.vendor or explicit_model:
        d["vendor"] = h.vendor
    if h.product or explicit_model:
        d["product"] = h.product
    if explicit_model:
        d["model"] = h.model
    dev = h.device
    if dev is not None:
        if h.firmware != devices.pick_firmware(dev, h.name):
            d["firmware"] = h.firmware
        if h.serial != devices.make_serial(dev, h.name):
            d["serial"] = h.serial
        if h.modules != dev.modules:
            raise ValueError(f"{env.key}: {h.name} has custom modules, which "
                             "the env-file format cannot express")
    if h.fqdn != f"{h.name.lower()}.{enterprise.DOMAIN}":
        d["fqdn"] = h.fqdn
    meta = env.host_meta.get(h.name, {})
    if meta.get("server"):
        d["meta"] = copy.deepcopy(meta["server"])
    if meta.get("client"):
        d["client_meta"] = copy.deepcopy(meta["client"])
    return d


def to_dict(env: Environment) -> Dict[str, Any]:
    """An environment as an env-file document (explicit flows; the hosts,
    flows and segments as declared, before ``options`` rewrite them)."""
    hosts, conv, segments = env.spec
    doc: Dict[str, Any] = {"key": env.key, "name": env.name,
                           "category": env.category, "description": env.desc}
    if env.options:
        doc["options"] = copy.deepcopy(env.options)
    doc["segments"] = [dict({"name": s.name, "vlan": s.vlan,
                             "subnet": s.subnet, "zone": s.zone,
                             "gateway": s.gateway},
                            **copy.deepcopy(s.options))
                       for s in segments]
    doc["hosts"] = [_host_dict(env, h) for h in hosts]
    flows = []
    for c in conv:
        f: Dict[str, Any] = {"client": c[0], "server": c[1], "proto": c[2]}
        f.update(env.timing.get(c, {}))
        flows.append(f)
    doc["flows"] = flows
    if env.findings:
        doc["findings"] = copy.deepcopy(env.findings)
    return doc


def dumps(doc: Dict[str, Any]) -> str:
    """JSON with one host / segment / flow per line (diff- and grep-able)."""
    lines = ["{"]
    items = list(doc.items())
    for i, (k, v) in enumerate(items):
        comma = "," if i < len(items) - 1 else ""
        if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
            lines.append(f"  {json.dumps(k)}: [")
            lines += [f"    {json.dumps(x, ensure_ascii=False)}"
                      f"{',' if j < len(v) - 1 else ''}"
                      for j, x in enumerate(v)]
            lines.append(f"  ]{comma}")
        else:
            lines.append(f"  {json.dumps(k)}: "
                         f"{json.dumps(v, ensure_ascii=False)}{comma}")
    lines.append("}")
    return "\n".join(lines) + "\n"


def export(env: Environment) -> str:
    return dumps(to_dict(env))


# ---------------------------------------------------------------------------
# Registration + environment directories
# ---------------------------------------------------------------------------
def register(env: Environment) -> Environment:
    """Make ``env`` available by key (``--env``, ``tgt list``, the TUI)."""
    enterprise.ENVIRONMENTS[env.key] = env
    return env


# Modeled sites that ship with TGT as data files (one per vertical: water
# utility, substation, ...). They load like user env files but come first,
# so a user file cannot shadow one.
SITES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "envs", "sites")


def search_path() -> List[str]:
    """Directories (or files) environments are auto-loaded from: the packaged
    sites (:data:`SITES_DIR`), ``TGT_ENV_PATH`` (os.pathsep-separated), then
    ``$XDG_CONFIG_HOME/tgt/envs`` (default ``~/.config/tgt/envs``)."""
    out = [SITES_DIR]
    out += [p for p in os.environ.get("TGT_ENV_PATH", "").split(os.pathsep)
            if p]
    cfg = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config")
    out.append(os.path.join(cfg, "tgt", "envs"))
    return out


_ENV_EXT = (".json", ".toml")
_user_loaded = False


def load_user_envs(warn=None, force: bool = False) -> List[str]:
    """Register every env file on :func:`search_path` (once per process
    unless ``force``). Bad files and keys that clash with a built-in or an
    earlier file are skipped with a warning (``warn(msg)``, default stderr).
    Returns the keys registered."""
    global _user_loaded
    if _user_loaded and not force:
        return []
    _user_loaded = True
    if warn is None:
        def warn(msg: str) -> None:
            print(f"tgt: warning: {msg}", file=sys.stderr)
    files: List[str] = []
    for p in search_path():
        if os.path.isfile(p):
            files.append(p)
        elif os.path.isdir(p):
            files += [os.path.join(p, f) for f in sorted(os.listdir(p))
                      if f.lower().endswith(_ENV_EXT)]
    got: List[str] = []
    for path in files:
        try:
            env = load(path)
        except EnvFileError as e:
            warn(f"skipping environment file: {e}")
            continue
        if env.key in BUILTIN_KEYS or env.key in got:
            warn(f"skipping {path}: environment key {env.key!r} is already "
                 "defined")
            continue
        register(env)
        got.append(env.key)
    return got


def source_of(env: Environment) -> Optional[str]:
    """The file an environment was loaded from (None for built-ins)."""
    return getattr(env, "source", None)
