"""``tgt score`` — grade a network monitor's export against TGT ground truth.

Inputs:

* ground truth — a run manifest (``tgt run --manifest``, schema
  ``tgt-manifest/1``) or a plain ``tgt inventory -f json`` document;
* the monitor's asset export (CSV / JSON / NDJSON / Zeek log) plus a column
  *map* (``tgt/scoremaps/*.json``) naming which column holds the IP, MAC,
  VLAN, name, vendor, model, firmware, serial, OS, protocols, first-seen;
* optionally Zeek logs (``--zeek DIR``: baseline-flow coverage from
  ``conn.log``) and the monitor's alerts (``--alerts`` + ``--alert-map``: each
  alert title is mapped by regex onto TGT's generic event categories and
  matched against the manifest's ``events``).

Output: a terminal summary, ``--json`` (everything) and ``--html`` (a
single self-contained page). Standard library only.
"""
from __future__ import annotations

import csv
import datetime as _dt
import difflib
import gzip
import html
import io
import ipaddress
import json
import os
import re
import statistics
import sys
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

SCHEMA = "tgt-score/1"
SCOREMAPS = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "scoremaps")
# name -> mapping file registered by a plugin (tgt.plugins.register_scoremap)
PLUGIN_MAPS: Dict[str, str] = {}
FIELDS = ("vendor", "model", "firmware", "serial", "os")
METHODS = ("mac", "vlan-ip", "ip", "name")          # strongest first
CATEGORIES = (
    "new-asset", "asset-offline", "ip-change", "firmware-change",
    "new-conversation", "cross-zone", "new-protocol", "ot-write",
    "plc-mode-change", "plc-program", "scan", "c2", "exploit-attempt",
    "lateral-movement", "remote-access", "legacy-os", "default-credentials",
    "cleartext-credentials")
UTC = _dt.timezone.utc


class ScoreError(Exception):
    """Bad input (unreadable file, unknown format, …) — exit code 2."""


# --------------------------------------------------------------------------
# value normalisation

def _key(s: Any) -> str:
    """Case/whitespace/punctuation-insensitive comparison key."""
    return re.sub(r"[^0-9a-z]", "", str(s).lower())


_CORP = {"inc", "incorporated", "corp", "corporation", "co", "company", "ltd",
         "limited", "llc", "gmbh", "ag", "sa", "se", "bv", "nv", "kg", "srl",
         "spa", "oy", "ab", "as"}


def _vendor_key(s: Any) -> str:
    words = re.findall(r"[0-9a-z]+", str(s).lower())
    while len(words) > 1 and words[-1] in _CORP:
        words.pop()
    return "".join(words)


def _serial_key(s: Any) -> str:
    k = str(s).strip().lower()
    if k.startswith("0x"):
        k = k[2:]
    return _key(k).lstrip("0") or "0"


def _field_key(field: str, s: Any) -> str:
    if field == "vendor":
        return _vendor_key(s)
    if field == "serial":
        return _serial_key(s)
    return _key(s)


def norm_mac(s: Any) -> Optional[str]:
    h = re.sub(r"[^0-9a-f]", "", str(s).lower())
    if len(h) != 12 or h == "0" * 12:
        return None
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def norm_ip(s: Any) -> Optional[str]:
    t = str(s).strip().strip("[]")
    if not t:
        return None
    t = t.split("/")[0].split("%")[0]
    try:
        return str(ipaddress.ip_address(t))
    except ValueError:
        return None


def _vlan(v: Any) -> Optional[int]:
    if v is None or isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    m = re.search(r"\d+", str(v))
    return int(m.group()) if m else None


def _is_group(ip: str) -> bool:
    """Broadcast/multicast/unspecified destination (not one host)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (a.is_multicast or a.is_unspecified or ip.endswith(".255")
            or ip == "255.255.255.255")


# protocol name aliases: canonical -> spellings seen in monitor exports
_PROTO_ALIASES = {
    "enip": ["enip", "enip-id", "ethernet/ip", "ethernetip", "cip", "eip",
             "cip/enip", "enip/cip", "ethernet/ip cip", "cip-io"],
    "s7comm": ["s7comm", "s7-id", "s7", "siemens s7", "s7 comm", "iso-tsap",
               "s7comm-plus", "s7plus", "s7 plus", "siemens s7comm"],
    "modbus": ["modbus", "modbus/tcp", "modbus tcp", "modbus-tcp", "mbtcp",
               "modbus/ip"],
    "bacnet": ["bacnet", "bacnet/ip", "bacnet-ip", "bvlc", "bacnet ip"],
    "dnp3": ["dnp3", "dnp 3", "dnp", "dnp3/tcp", "dnp3 tcp"],
    "iec104": ["iec104", "iec 104", "iec-104", "iec 60870-5-104",
               "iec60870-5-104", "iec-60870-5-104", "iec 60870 5 104"],
    "opcua": ["opcua", "opc ua", "opc-ua", "opc ua binary", "opc-ua-tcp",
              "opcua-binary"],
    "https": ["https", "tls", "ssl", "ssl/tls", "tls/ssl", "edr", "http/s",
              "https/tls"],
    "http": ["http", "http/1.1", "www"],
    "smb": ["smb", "smb2", "smb3", "smbv1", "smbv2", "cifs", "microsoft-ds",
            "smb/cifs"],
    "netbios": ["netbios", "netbios-ns", "nbns", "netbios name service",
                "nbt", "nbstat", "netbios-dgm", "nbdgm"],
    "dns": ["dns", "domain"],
    "dhcp": ["dhcp", "bootp", "bootps", "dhcpv4"],
    "ldap": ["ldap", "cldap"],
    "kerberos": ["kerberos", "krb", "krb5", "kerberos5", "kerberos v5"],
    "ntp": ["ntp", "sntp"],
    "icmp": ["icmp", "icmpv4", "ping"],
    "arp": ["arp"],
    "tristation": ["tristation", "triconex", "tsaa"],
    "goose": ["goose", "iec 61850 goose", "iec61850-goose", "iec-goose"],
    "sv": ["sv", "sampled values", "iec 61850 sv", "iec61850-sv"],
    "mms": ["mms", "iec 61850 mms", "iec61850-mms", "iec-mms"],
    "profinet": ["profinet", "pnio", "pn-io", "profinet io", "profinet-io",
                 "pn-dcp", "profinet dcp", "pn-rt"],
    "ptp": ["ptp", "ieee 1588", "ieee1588", "ptpv2"],
    "snmp": ["snmp", "snmpv1", "snmpv2", "snmpv2c", "snmpv3", "snmp trap"],
    "syslog": ["syslog"],
    "mdns": ["mdns", "bonjour"],
    "ssdp": ["ssdp", "upnp"],
    "llmnr": ["llmnr"],
    "lldp": ["lldp"],
    "cdp": ["cdp"],
    "mqtt": ["mqtt"],
    "sparkplug": ["sparkplug", "sparkplug b", "sparkplugb"],
    "rdp": ["rdp", "ms-rdp", "ms-wbt-server"],
    "ssh": ["ssh"],
}
_PROTO_BY_KEY = {_key(a): canon for canon, al in _PROTO_ALIASES.items()
                 for a in al}


def norm_protocol(name: str) -> str:
    """'EtherNet/IP' -> 'enip', 'modbus 502/tcp' -> 'modbus', 'TLS' -> 'https'."""
    s = str(name).strip().lower()
    s = re.sub(r"\s+\d+/(tcp|udp)$", "", s)          # inventory 'serves' form
    s = re.sub(r"\s*\((tcp|udp)\)$", "", s)
    return _PROTO_BY_KEY.get(_key(s), s)


# --------------------------------------------------------------------------
# time

_ISO = re.compile(
    r"^(\d{4})-(\d\d)-(\d\d)(?:[T ](\d\d):(\d\d)(?::(\d\d)(?:[.,](\d+))?)?)?"
    r"\s*(Z|UTC|GMT|[+-]\d\d(?::?\d\d)?)?$", re.I)
_FORMATS = ("%m/%d/%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M",
            "%Y/%m/%d %H:%M:%S", "%b %d, %Y %H:%M:%S", "%b %d, %Y %I:%M:%S %p",
            "%d %b %Y %H:%M:%S", "%a %b %d %H:%M:%S %Y")


def parse_time(v: Any, utc_offset: Optional[_dt.timedelta] = None,
               fmt: Optional[str] = None) -> Optional[_dt.datetime]:
    """ISO-8601 / epoch seconds or ms / a few common export formats ->
    aware UTC datetime. Naive values are local time at ``utc_offset``
    (default UTC)."""
    if v is None or isinstance(v, bool):
        return None
    if isinstance(v, (int, float)) or re.fullmatch(r"\s*\d{9,}(\.\d+)?\s*",
                                                   str(v)):
        x = float(v)
        if x > 1e11:                                  # milliseconds
            x /= 1000.0
        return _dt.datetime.fromtimestamp(x, UTC)
    s = str(v).strip()
    if not s or s in ("-", "(empty)"):
        return None
    t: Optional[_dt.datetime] = None
    if fmt:
        t = _dt.datetime.strptime(s, fmt)
    else:
        m = _ISO.match(s)
        if m:
            y, mo, d, hh, mm, ss, frac, tz = m.groups()
            us = int((frac or "0")[:6].ljust(6, "0"))
            t = _dt.datetime(int(y), int(mo), int(d), int(hh or 0),
                             int(mm or 0), int(ss or 0), us)
            if tz:
                if tz.upper() in ("Z", "UTC", "GMT"):
                    t = t.replace(tzinfo=UTC)
                else:
                    sign = -1 if tz[0] == "-" else 1
                    digits = tz[1:].replace(":", "")
                    off = _dt.timedelta(hours=int(digits[:2]),
                                        minutes=int(digits[2:4] or 0))
                    t = t.replace(tzinfo=_dt.timezone(sign * off))
        else:
            for f in _FORMATS:
                try:
                    t = _dt.datetime.strptime(s, f)
                    break
                except ValueError:
                    continue
    if t is None:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=_dt.timezone(utc_offset or _dt.timedelta(0)))
    return t.astimezone(UTC)


def _offset(spec: Any) -> Optional[_dt.timedelta]:
    """'+02:00' / '-0500' / 2 (hours) -> timedelta."""
    if spec in (None, ""):
        return None
    if isinstance(spec, (int, float)):
        return _dt.timedelta(hours=spec)
    m = re.fullmatch(r"\s*([+-])?(\d{1,2}):?(\d\d)?\s*", str(spec))
    if not m:
        raise ScoreError(f"bad utc_offset {spec!r} (want e.g. '+02:00')")
    off = _dt.timedelta(hours=int(m.group(2)), minutes=int(m.group(3) or 0))
    return -off if m.group(1) == "-" else off


def _iso(t: Optional[_dt.datetime]) -> Optional[str]:
    return t.strftime("%Y-%m-%dT%H:%M:%S.%fZ") if t else None


def _ratio(a: int, b: int) -> Optional[float]:
    return round(a / b, 4) if b else None


def _median(xs: Sequence[float]) -> Optional[float]:
    return round(statistics.median(xs), 3) if xs else None


# --------------------------------------------------------------------------
# reading tables (CSV / JSON / NDJSON / Zeek TSV)

def _open_text(path: str):
    if path.endswith(".gz"):
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8-sig",
                                errors="replace")
    return open(path, encoding="utf-8-sig", errors="replace", newline="")


def read_zeek(path: str) -> List[Dict[str, Any]]:
    """Zeek log (TSV with ``#fields`` header, or JSON lines) -> rows."""
    rows: List[Dict[str, Any]] = []
    sep, fields, unset, empty = "\t", None, "-", "(empty)"
    with _open_text(path) as f:
        for line in f:
            line = line.rstrip("\r\n")
            if not line:
                continue
            if line.startswith("{"):
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    pass
                continue
            if line.startswith("#"):
                if line.startswith("#separator"):
                    raw = line.split(None, 1)[1] if " " in line else "\\x09"
                    sep = raw.encode().decode("unicode_escape")
                else:
                    parts = line.split(sep)
                    tag = parts[0]
                    if tag == "#fields":
                        fields = parts[1:]
                    elif tag == "#unset_field" and len(parts) > 1:
                        unset = parts[1]
                    elif tag == "#empty_field" and len(parts) > 1:
                        empty = parts[1]
                continue
            if fields is None:
                continue
            vals = line.split(sep)
            row = {}
            for k, v in zip(fields, vals):
                row[k] = None if v == unset else ("" if v == empty else v)
            rows.append(row)
    return rows


def _walk(doc: Any, path: str) -> Any:
    for part in [p for p in (path or "").split(".") if p]:
        if isinstance(doc, dict):
            doc = doc.get(part)
        else:
            return None
    return doc


def read_table(path: str, fmt: str = "auto", json_path: str = "",
               delimiter: Optional[str] = None) -> List[Dict[str, Any]]:
    if not os.path.isfile(path):
        raise ScoreError(f"no such file: {path}")
    fmt = (fmt or "auto").lower()
    if fmt == "auto":
        low = path.lower().replace(".gz", "")
        fmt = ("json" if low.endswith((".json", ".ndjson", ".jsonl")) else
               "zeek" if low.endswith(".log") else
               "tsv" if low.endswith(".tsv") else "csv")
    if fmt == "zeek":
        return read_zeek(path)
    if fmt in ("csv", "tsv"):
        with _open_text(path) as f:
            text = f.read()
        delim = delimiter or ("\t" if fmt == "tsv" else ",")
        return [dict(r) for r in csv.DictReader(io.StringIO(text),
                                                 delimiter=delim)]
    if fmt == "json":
        with _open_text(path) as f:
            text = f.read()
        try:
            doc = json.loads(text)
        except ValueError:                    # NDJSON / JSON lines
            doc = [json.loads(ln) for ln in text.splitlines()
                   if ln.strip().startswith("{")]
        rows = _walk(doc, json_path) if json_path else doc
        if isinstance(rows, dict):
            # {"assets": [...]} without json_path, or {id: {...}, ...}
            lists = [v for v in rows.values() if isinstance(v, list)]
            rows = lists[0] if len(lists) == 1 else list(rows.values())
        if not isinstance(rows, list):
            raise ScoreError(f"{path}: json_path {json_path!r} is not a list")
        return [r for r in rows if isinstance(r, dict)]
    raise ScoreError(f"unknown format {fmt!r} (csv, tsv, json, zeek)")


def _getter(row: Dict[str, Any]):
    low = {str(k).strip().lower(): k for k in row}

    def get(spec: Any) -> Any:
        if not spec:
            return None
        for name in ([spec] if isinstance(spec, str) else spec):
            if name in row:
                return row[name]
            k = low.get(str(name).strip().lower())
            if k is not None:
                return row[k]
            if "." in name:
                v = _walk(row, name)
                if v is not None:
                    return v
        return None
    return get


def _has_column(rows: List[Dict[str, Any]], spec: Any) -> bool:
    if not spec or not rows:
        return False
    names = [spec] if isinstance(spec, str) else list(spec)
    return any(_getter(r)(names) is not None for r in rows[:50])


def _items(v: Any, sep: str) -> List[str]:
    if v is None:
        return []
    if isinstance(v, (list, tuple, set)):
        out: List[str] = []
        for x in v:
            out.extend(_items(x, sep))
        return out
    if isinstance(v, dict):
        return [str(x) for x in v.values() if x not in (None, "")]
    return [x.strip() for x in re.split(sep, str(v)) if x.strip()]


def _text(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (list, tuple)):
        return "; ".join(str(x) for x in v if x not in (None, ""))
    s = str(v).strip()
    return "" if s in ("-", "(empty)", "N/A", "n/a", "None", "null") else s


# --------------------------------------------------------------------------
# mapping files

def load_json_spec(spec: str, kind: str = "map") -> Dict[str, Any]:
    """A mapping file by path, or by name from tgt/scoremaps/."""
    cands = [spec]
    if os.path.sep not in spec:
        if spec in PLUGIN_MAPS:
            cands.append(PLUGIN_MAPS[spec])
        cands += [os.path.join(SCOREMAPS, spec),
                  os.path.join(SCOREMAPS, spec + ".json")]
    for p in cands:
        if os.path.isfile(p):
            try:
                with open(p, encoding="utf-8") as f:
                    doc = json.load(f)
            except ValueError as e:
                raise ScoreError(f"{p}: invalid JSON: {e}")
            if not isinstance(doc, dict):
                raise ScoreError(f"{p}: {kind} must be a JSON object")
            doc.setdefault("_path", p)
            return doc
    names = sorted(n[:-5] for n in os.listdir(SCOREMAPS)
                   if n.endswith(".json")) if os.path.isdir(SCOREMAPS) else []
    names += sorted(PLUGIN_MAPS)
    raise ScoreError(f"{kind} not found: {spec} (bundled: {', '.join(names)})")


def _normalizer(mapping: Dict[str, Any]):
    tables = {f: {str(k).strip().lower(): v for k, v in (t or {}).items()}
              for f, t in (mapping.get("normalize") or {}).items()}

    def norm(field: str, v: str) -> str:
        t = tables.get(field)
        if not t or not v:
            return v
        return t.get(v.strip().lower(), v)
    return norm


def read_export(path: str, mapping: Dict[str, Any]) -> Tuple[List[Dict], Dict]:
    """Export rows -> normalised records + facts about which fields exist."""
    rows = read_table(path, mapping.get("format", "auto"),
                      mapping.get("json_path", ""), mapping.get("delimiter"))
    cols = mapping.get("columns") or {}
    split = mapping.get("split") or {}
    norm = _normalizer(mapping)
    off = _offset(mapping.get("utc_offset"))
    tfmt = mapping.get("time_format")
    ignore = {norm_protocol(p) for p in mapping.get("protocol_ignore",
                                                    ["arp"])}

    def sep(field: str, default: str) -> str:
        s = split.get(field)
        return re.escape(s) if s else default

    present = {f: _has_column(rows, cols.get(f)) for f in
               ("ip", "mac", "vlan", "name", "protocols", "first_seen") +
               FIELDS}
    out = []
    for i, row in enumerate(rows):
        get = _getter(row)
        ips = [x for x in (norm_ip(s) for s in
                           _items(get(cols.get("ip")), sep("ip", r"[,;|\s]+")))
               if x]
        macs = [x for x in (norm_mac(s) for s in
                            _items(get(cols.get("mac")),
                                   sep("mac", r"[,;|\s]+"))) if x]
        rec: Dict[str, Any] = {
            "row": i + 1, "ips": list(dict.fromkeys(ips)),
            "macs": list(dict.fromkeys(macs)),
            "vlan": _vlan(get(cols.get("vlan"))),
            "name": norm("name", _text(get(cols.get("name")))),
        }
        for f in FIELDS:
            rec[f] = norm(f, _text(get(cols.get(f))))
        if present["protocols"]:
            protos = {norm_protocol(norm("protocols", p)) for p in
                      _items(get(cols.get("protocols")),
                             sep("protocols", r"\s*[;,|]\s*"))}
            rec["protocols"] = sorted(protos - ignore - {""})
        else:
            rec["protocols"] = None
        fs = get(cols.get("first_seen"))
        try:
            rec["first_seen"] = parse_time(fs, off, tfmt)
        except ValueError:
            rec["first_seen"] = None
        if rec["ips"] or rec["macs"] or rec["name"]:
            out.append(rec)
    return out, {"rows": len(rows), "columns": present,
                 "protocol_ignore": sorted(ignore)}


# --------------------------------------------------------------------------
# ground truth

def _model_cands(h: Dict, obs: Dict) -> List[str]:
    slug = (obs.get("model") or {}).get("value") or h.get("model") or ""
    prod = (obs.get("product") or {}).get("value") or h.get("product") or ""
    c = [slug, slug.split("-", 1)[1] if "-" in slug else "", prod]
    return [x for x in dict.fromkeys(c) if x]


def _not_an_asset(ip: Optional[str], external: Dict, infra: List[Dict],
                  have_inventory: bool) -> bool:
    """A manifest ``first_seen`` key that names no inventory host and is not
    something a monitor should list as an asset: a known external endpoint
    (EDR cloud), a gateway, or — when an inventory exists — any public IP
    (sprinkle C2 / attacker infrastructure)."""
    if not ip:
        return False
    if ip in external or any(x["ip"] == ip for x in infra):
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # documentation ranges (198.51.100/24 …) are not "global" to Python but
    # are what TGT uses for synthetic C2, so test "internal" explicitly
    return have_inventory and not any(addr in n for n in _INTERNAL_NETS)


_INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
    "169.254.0.0/16", "127.0.0.0/8")]


def _truth_asset(h: Dict, new: bool = False) -> Dict[str, Any]:
    obs = h.get("observability") or {}

    def ob(f: str) -> bool:
        return bool((obs.get(f) or {}).get("observable"))

    def val(f: str) -> str:
        return str((obs.get(f) or {}).get("value") or h.get(f) or "")

    vendor = [x for x in dict.fromkeys([val("vendor"), h.get("vendor") or "",
                                        h.get("mac_vendor") or ""]) if x]
    fields = {
        "vendor": (vendor, ob("vendor")),
        "model": (_model_cands(h, obs), ob("model") or ob("product")),
        "firmware": ([val("firmware")] if val("firmware") else [],
                     ob("firmware")),
        "serial": ([val("serial")] if val("serial") else [], ob("serial")),
        "os": ([val("os")] if val("os") else [], ob("os")),
    }
    protos = set()
    for s in list(h.get("serves") or []) + list(h.get("uses") or []):
        protos.add(norm_protocol(s))
    ip = norm_ip(h.get("ip") or "")
    return {
        "id": h.get("asset_id") or h.get("name") or ip,
        "name": h.get("name") or ip or "",
        "fqdn": h.get("fqdn") or "",
        "ip": ip, "mac": norm_mac(h.get("mac") or ""),
        "vlan": _vlan(h.get("vlan")), "role": h.get("role", ""),
        "fields": fields, "protocols": protos, "new": new,
        "emitted": True, "first_seen": None,
    }


class Truth:
    def __init__(self, doc: Dict[str, Any], source: str = "") -> None:
        self.source = source
        self.mode = ("manifest" if str(doc.get("schema", "")).startswith(
            "tgt-manifest/") else "inventory")
        if self.mode == "inventory" and "hosts" not in doc:
            raise ScoreError(f"{source}: neither a tgt manifest "
                             "(schema tgt-manifest/1) nor a tgt inventory "
                             "JSON (no 'hosts')")
        inv = doc.get("inventory") if self.mode == "manifest" else doc
        inv = inv or {}
        self.env = inv.get("env") or doc.get("env")
        self.start = parse_time(doc.get("start"))
        self.end = parse_time(doc.get("end"))
        self.assets: List[Dict[str, Any]] = [
            _truth_asset(h) for h in inv.get("hosts") or []]
        self.assets += [_truth_asset(h, new=True)
                        for h in inv.get("new_assets") or []]
        self.infra = [{"ip": norm_ip(x.get("ip") or ""),
                       "mac": norm_mac(x.get("mac") or ""),
                       "vlan": _vlan(x.get("vlan")), "kind": x.get("kind")}
                      for x in inv.get("infrastructure") or []]
        self.external = {norm_ip(x.get("ip")): x
                         for x in inv.get("external") or []
                         if norm_ip(x.get("ip") or "")}
        self.events = list(doc.get("events") or [])
        by_name = {a["name"]: a for a in self.assets}
        by_id = {a["id"]: a for a in self.assets}

        # who emitted traffic: manifest first_seen keys (asset ids or IPs)
        self.population_basis = "inventory hosts"
        fs = doc.get("first_seen") if self.mode == "manifest" else None
        if fs:
            self.population_basis = "manifest first_seen"
            by_ip = {a["ip"]: a for a in self.assets if a["ip"]}
            for a in self.assets:
                a["emitted"] = False
            for k, ts in fs.items():
                a = by_id.get(k) or by_ip.get(norm_ip(k) or "") or \
                    by_name.get(k)
                if a is None and _not_an_asset(norm_ip(k), self.external,
                                               self.infra, bool(by_name)):
                    continue                          # cloud / C2 / gateway
                if a is None and norm_ip(k):          # non-env run: IP ids
                    a = _truth_asset({"asset_id": k, "name": k, "ip": k})
                    self.assets.append(a)
                    by_id[k] = a
                    by_ip[a["ip"]] = a
                if a is not None:
                    a["emitted"] = True
                    a["first_seen"] = parse_time(ts)
        elif self.mode == "manifest":
            self.population_basis = "inventory hosts (manifest has no first_seen)"

        # expected flows (for --zeek): flows_seen if the manifest has them
        ports = {}
        for fl in inv.get("flows") or []:
            ports.setdefault(fl.get("protocol"),
                             (fl.get("dport"), fl.get("transport")))
        self.flows: List[Dict[str, Any]] = []

        def resolve(x: str) -> Optional[Dict]:
            a = by_id.get(x) or by_name.get(x)
            if a is None and norm_ip(x):
                a = {"id": x, "name": x, "ip": norm_ip(x)}
            return a

        seen = doc.get("flows_seen") if self.mode == "manifest" else None
        self.flow_basis = "manifest flows_seen" if seen else "inventory flows"
        for fl in (seen or inv.get("flows") or []):
            proto = fl.get("protocol", "")
            dport, transport = fl.get("dport"), fl.get("transport")
            if transport is None:
                dport, transport = ports.get(proto) or _proto_port(proto)
            c, s = resolve(fl.get("client", "")), resolve(fl.get("server", ""))
            if not c or not s or not c.get("ip") or transport == "l2":
                continue
            self.flows.append({
                "client": c["name"], "server": s["name"], "protocol": proto,
                "cip": c["ip"], "sip": s["ip"], "dport": dport,
                "transport": "icmp" if transport == "ip" else transport,
                "self": c["id"] == s["id"]})
        for ip, e in self.external.items():       # EDR beacons to the cloud
            if e.get("kind") != "edr-cloud":
                continue
            for t in e.get("talkers") or []:
                c = by_name.get(t)
                if c and c.get("ip"):
                    self.flows.append({
                        "client": c["name"], "server": ip, "protocol": "edr",
                        "cip": c["ip"], "sip": ip, "dport": 443,
                        "transport": "tcp", "self": False})

    def population(self) -> List[Dict[str, Any]]:
        return [a for a in self.assets if a["emitted"]]


def _proto_port(proto: str) -> Tuple[Optional[int], Optional[str]]:
    try:
        from . import protocols
        p = protocols.get(proto)
    except Exception:  # noqa: BLE001 — unknown / attack-only protocol
        return None, None
    return (int(p.port) if p.port.isdigit() else None), p.transport


def load_truth(path: str) -> Truth:
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except OSError as e:
        raise ScoreError(f"cannot read {path}: {e}")
    except ValueError as e:
        raise ScoreError(f"{path}: invalid JSON: {e}")
    if not isinstance(doc, dict):
        raise ScoreError(f"{path}: not a JSON object")
    return Truth(doc, path)


# --------------------------------------------------------------------------
# asset matching

def _name_keys(a: Dict) -> List[str]:
    ks = [_key(a["name"])]
    if a.get("fqdn"):
        ks += [_key(a["fqdn"]), _key(a["fqdn"].split(".")[0])]
    return [k for k in dict.fromkeys(ks) if k]


def match_assets(truth: Truth, rows: List[Dict],
                 fuzzy: float = 0.85) -> Dict[str, Any]:
    by_mac: Dict[str, List[Dict]] = defaultdict(list)
    by_vip: Dict[Tuple[int, str], List[Dict]] = defaultdict(list)
    by_ip: Dict[str, List[Dict]] = defaultdict(list)
    by_name: Dict[str, List[Dict]] = defaultdict(list)
    for a in truth.assets:
        if a["mac"]:
            by_mac[a["mac"]].append(a)
        if a["ip"]:
            by_ip[a["ip"]].append(a)
            if a["vlan"] is not None:
                by_vip[(a["vlan"], a["ip"])].append(a)
        for k in _name_keys(a):
            by_name[k].append(a)
    infra_macs = {x["mac"] for x in truth.infra if x["mac"]}
    infra_ips = {x["ip"] for x in truth.infra if x["ip"]}

    def pick(cands: List[Dict], r: Dict) -> Optional[Dict]:
        if len(cands) == 1:
            return cands[0]
        same = [a for a in cands if a["ip"] in r["ips"]]
        return same[0] if len(same) == 1 else None

    for r in rows:
        a, how, bucket = None, None, None
        for m in r["macs"]:
            if m in infra_macs or m not in by_mac:
                continue
            a = pick(by_mac[m], r)
            if a:
                how = "mac"
                break
        if a is None and r["vlan"] is not None:
            for ip in r["ips"]:
                c = by_vip.get((r["vlan"], ip))
                if c and len(c) == 1:
                    a, how = c[0], "vlan-ip"
                    break
        if a is None:
            for ip in r["ips"]:
                c = by_ip.get(ip)
                if c and len(c) == 1:
                    a, how = c[0], "ip"
                    break
        if a is None:
            if any(ip in truth.external for ip in r["ips"]):
                bucket = "external"
            elif (any(ip in infra_ips for ip in r["ips"]) or
                  any(m in infra_macs for m in r["macs"])):
                bucket = "infrastructure"
        if a is None and bucket is None and r["name"] and \
                not norm_ip(r["name"]):
            k = _key(r["name"].split(".")[0])
            c = by_name.get(k) or by_name.get(_key(r["name"]))
            if c and len(c) == 1:
                a, how = c[0], "name"
            elif k and not c:
                scored = sorted(((difflib.SequenceMatcher(None, k, nk).ratio(),
                                  nk) for nk in by_name), reverse=True)
                if scored and scored[0][0] >= fuzzy and \
                        (len(scored) == 1 or scored[1][0] < scored[0][0]) \
                        and len(by_name[scored[0][1]]) == 1:
                    a, how = by_name[scored[0][1]][0], "name"
        r["asset"] = a["id"] if a else None
        r["method"] = how
        r["bucket"] = "matched" if a else (bucket or "false-positive")

    groups: Dict[str, List[Dict]] = defaultdict(list)
    for r in rows:
        if r["asset"]:
            groups[r["asset"]].append(r)
    primary: Dict[str, Dict] = {}
    for aid, rs in groups.items():
        best = min(rs, key=lambda r: (METHODS.index(r["method"]), r["row"]))
        primary[aid] = best
        for r in rs:
            if r is not best:
                r["bucket"] = "duplicate"
    return primary


# --------------------------------------------------------------------------
# field comparison

def compare(field: str, got: str, cands: Sequence[str]) -> str:
    """'correct' | 'partial' | 'wrong' — after case/space/punctuation (and,
    for vendors, corporate-suffix) normalisation; firmware also compares its
    numeric components ('V3.2.8' == '3.2.8'); 'partial' = one value is a
    substring of the other ('1756-L83E' vs '1756-L83E/B')."""
    gk = _field_key(field, got)
    if not gk:
        return "wrong"
    keys = [_field_key(field, c) for c in cands if _field_key(field, c)]
    if gk in keys:
        return "correct"
    if field == "firmware":
        gn = [int(x) for x in re.findall(r"\d+", got)]
        if gn and any(gn == [int(x) for x in re.findall(r"\d+", c)]
                      for c in cands):
            return "correct"
    for ck in keys:
        short, long_ = sorted((gk, ck), key=len)
        if len(short) >= 3 and short in long_:
            return "partial"
    return "wrong"


# --------------------------------------------------------------------------
# Zeek baseline coverage

def _zeek_files(path: str, log: str = "conn") -> List[str]:
    if os.path.isfile(path):
        return [path]
    if not os.path.isdir(path):
        raise ScoreError(f"--zeek: no such file or directory: {path}")
    out = []
    for n in sorted(os.listdir(path)):
        if (n.startswith(log + ".") or n.startswith(log + "_")) and \
                ".log" in n:
            out.append(os.path.join(path, n))
    if not out:
        raise ScoreError(f"--zeek: no {log}.log in {path}")
    return out


def _conns(path: str) -> List[Dict[str, Any]]:
    out = []
    for p in _zeek_files(path):
        for r in read_zeek(p):
            g = _getter(r)
            o, d = norm_ip(g("id.orig_h") or ""), norm_ip(g("id.resp_h") or "")
            if not o or not d:
                continue
            try:
                op, dp = int(g("id.orig_p") or 0), int(g("id.resp_p") or 0)
            except (TypeError, ValueError):
                continue
            out.append({"o": o, "d": d, "op": op, "dp": dp,
                        "proto": str(g("proto") or "").lower()})
    return out


def _flow_hits(fl: Dict, c: Dict) -> bool:
    if fl["transport"] != c["proto"]:
        return False
    port = fl["dport"]
    fwd = (c["o"] == fl["cip"] and (port is None or c["dp"] == port) and
           (c["d"] == fl["sip"] or ((fl["self"] or fl["transport"] == "udp")
                                    and _is_group(c["d"]))))
    rev = (c["o"] == fl["sip"] and c["d"] == fl["cip"] and
           (port is None or c["op"] == port))
    return fwd or rev


def baseline(truth: Truth, zeek: str) -> Dict[str, Any]:
    conns = _conns(zeek)
    exp: Dict[Tuple, Dict] = {}
    for fl in truth.flows:
        exp.setdefault((fl["cip"], fl["sip"], fl["dport"], fl["transport"]),
                       fl)
    flows = list(exp.values())
    hit = [False] * len(flows)
    by_cip: Dict[str, List[int]] = defaultdict(list)
    for i, fl in enumerate(flows):
        by_cip[fl["cip"]].append(i)
        by_cip[fl["sip"]].append(i)
    unexpected: Dict[Tuple, int] = defaultdict(int)
    known_ports = {(fl["dport"], fl["transport"]) for fl in flows}
    for c in conns:
        ok = False
        for i in by_cip.get(c["o"], ()):
            if _flow_hits(flows[i], c):
                hit[i] = ok = True
        if ok:
            continue
        if ipaddress.ip_address(c["o"]).is_unspecified and \
                (c["dp"], c["proto"]) in known_ports:
            continue                          # DHCP Discover/Request
        unexpected[(c["o"], c["d"], c["dp"], c["proto"])] += 1
    missed = [fl for fl, h in zip(flows, hit) if not h]
    names = {a["ip"]: a["name"] for a in truth.assets if a["ip"]}
    return {
        "basis": truth.flow_basis, "conn_records": len(conns),
        "expected": len(flows), "seen": sum(hit),
        "coverage": _ratio(sum(hit), len(flows)),
        "missed": [{k: fl[k] for k in ("client", "server", "protocol",
                                       "cip", "sip", "dport", "transport")}
                   for fl in missed],
        "unexpected": [{"orig": o, "resp": d, "orig_name": names.get(o, ""),
                        "resp_name": names.get(d, ""), "dport": p,
                        "proto": pr, "conns": n}
                       for (o, d, p, pr), n in sorted(
                           unexpected.items(), key=lambda kv: (-kv[1], kv[0]))],
    }


# --------------------------------------------------------------------------
# detections

def read_alerts(path: str, amap: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = read_table(path, amap.get("format", "auto"),
                      amap.get("json_path", ""), amap.get("delimiter"))
    cols = amap.get("columns") or {}
    off = _offset(amap.get("utc_offset"))
    tfmt = amap.get("time_format")
    rules = []
    for pat, cat in (amap.get("categories") or {}).items():
        try:
            rules.append((re.compile(pat, re.I), cat))
        except re.error as e:
            raise ScoreError(f"alert-map: bad regex {pat!r}: {e}")
    out = []
    for i, r in enumerate(rows):
        get = _getter(r)
        title = _text(get(cols.get("title")))
        raw_cat = _text(get(cols.get("category")))
        cat = None
        for rx, c in rules:
            if rx.search(title) or (raw_cat and rx.search(raw_cat)):
                cat = c
                break
        if cat is None and raw_cat.lower() in CATEGORIES:
            cat = raw_cat.lower()
        try:
            t = parse_time(get(cols.get("time")), off, tfmt)
        except ValueError:
            t = None
        out.append({"row": i + 1, "time": t, "title": title,
                    "raw_category": raw_cat, "category": cat,
                    "src": _text(get(cols.get("src"))),
                    "dst": _text(get(cols.get("dst")))})
    return out


def detections(truth: Truth, alerts: List[Dict], tolerance: float,
               skew: float) -> Dict[str, Any]:
    ip_of: Dict[str, str] = {}
    for a in truth.assets:
        if a["ip"]:
            for k in [a["id"], a["name"]] + _name_keys(a):
                ip_of.setdefault(_key(k), a["ip"])
                ip_of.setdefault(str(k), a["ip"])

    def ips(*vals: Any) -> set:
        out = set()
        for v in vals:
            for x in _items(v, r"[,;|\s]+"):
                ip = norm_ip(x) or ip_of.get(x) or ip_of.get(_key(x))
                if ip:
                    out.add(ip)
        return out

    for al in alerts:
        al["ips"] = ips(al["src"], al["dst"])
    used = set()
    per_cat: Dict[str, Dict[str, Any]] = {}
    results = []
    for ev in sorted(truth.events, key=lambda e: str(e.get("t_start", ""))):
        cat = ev.get("category", "")
        t0, t1 = parse_time(ev.get("t_start")), parse_time(ev.get("t_end"))
        t1 = t1 or t0
        hosts = ips(ev.get("hosts") or [], ev.get("src"), ev.get("dst"))
        best = None
        if t0 is not None:
            lo = t0 - _dt.timedelta(seconds=skew)
            hi = t1 + _dt.timedelta(seconds=tolerance)
            for al in alerts:
                if al["category"] != cat or al["time"] is None or \
                        not lo <= al["time"] <= hi:
                    continue
                if hosts and al["ips"] and not hosts & al["ips"]:
                    continue
                if best is None or al["time"] < best["time"]:
                    best = al
                used.add(al["row"])
        ttd = (best["time"] - t0).total_seconds() if best else None
        results.append({"id": ev.get("id"), "category": cat,
                        "t_start": ev.get("t_start"), "t_end": ev.get("t_end"),
                        "hosts": sorted(hosts), "detail": ev.get("detail", ""),
                        "source": ev.get("source", ""),
                        "detected": best is not None,
                        "alert_row": best["row"] if best else None,
                        "alert_title": best["title"] if best else None,
                        "ttd_s": ttd})
        pc = per_cat.setdefault(cat, {"events": 0, "detected": 0, "_t": []})
        pc["events"] += 1
        if best:
            pc["detected"] += 1
            pc["_t"].append(ttd)
    for pc in per_cat.values():
        pc["rate"] = _ratio(pc["detected"], pc["events"])
        pc["median_ttd_s"] = _median(pc.pop("_t"))
    unmapped: Dict[str, int] = defaultdict(int)
    for al in alerts:
        if al["category"] is None:
            unmapped[al["title"] or al["raw_category"] or "(untitled)"] += 1
    false = [al for al in alerts if al["category"] and al["row"] not in used]
    det = [r for r in results if r["detected"]]
    return {
        "events": len(results), "detected": len(det),
        "rate": _ratio(len(det), len(results)),
        "median_ttd_s": _median([r["ttd_s"] for r in det]),
        "tolerance_s": tolerance, "skew_s": skew,
        "alerts": len(alerts),
        "mapped_alerts": sum(1 for a in alerts if a["category"]),
        "matched_alerts": len(used),
        "per_category": dict(sorted(per_cat.items())),
        "missed": [r for r in results if not r["detected"]],
        "events_detail": results,
        "false_alerts": [{"row": a["row"], "time": _iso(a["time"]),
                          "title": a["title"], "category": a["category"],
                          "src": a["src"], "dst": a["dst"]} for a in false],
        "unmapped_alerts": sum(unmapped.values()),
        "unmapped_titles": [{"title": t, "count": n} for t, n in
                            sorted(unmapped.items(),
                                   key=lambda kv: (-kv[1], kv[0]))],
    }


# --------------------------------------------------------------------------
# scoring

def score(truth: Truth, rows: List[Dict], export_info: Dict[str, Any],
          zeek: Optional[str] = None, alerts: Optional[List[Dict]] = None,
          tolerance: float = 300.0, skew: float = 5.0,
          fuzzy: float = 0.85) -> Dict[str, Any]:
    primary = match_assets(truth, rows, fuzzy)
    pop = truth.population()
    found = [a for a in pop if a["id"] in primary]
    buckets: Dict[str, int] = defaultdict(int)
    for r in rows:
        buckets[r["bucket"]] += 1
    tp = len(primary)
    denom = tp + buckets["duplicate"] + buckets["false-positive"]
    by_method: Dict[str, int] = defaultdict(int)
    for r in primary.values():
        by_method[r["method"]] += 1

    def row_brief(r: Dict) -> Dict:
        return {"row": r["row"], "ip": ", ".join(r["ips"]),
                "mac": ", ".join(r["macs"]), "vlan": r["vlan"],
                "name": r["name"], "asset": r.get("asset")}

    discovery = {
        "population": len(pop), "population_basis": truth.population_basis,
        "found": len(found), "recall": _ratio(len(found), len(pop)),
        "matched_assets": tp, "duplicates": buckets["duplicate"],
        "false_positives": buckets["false-positive"],
        "precision": _ratio(tp, denom),
        "infrastructure": buckets["infrastructure"],
        "external": buckets["external"],
        "by_method": {m: by_method.get(m, 0) for m in METHODS},
        "missed": [a["id"] for a in pop if a["id"] not in primary],
        "false_positive_rows": [row_brief(r) for r in rows
                                if r["bucket"] == "false-positive"],
        "duplicate_rows": [row_brief(r) for r in rows
                           if r["bucket"] == "duplicate"],
        "infrastructure_rows": [row_brief(r) for r in rows
                                if r["bucket"] == "infrastructure"],
        "external_rows": [row_brief(r) for r in rows
                          if r["bucket"] == "external"],
    }

    cols = export_info["columns"]
    fields: Dict[str, Dict] = {}
    for f in FIELDS:
        fields[f] = {"exported": cols.get(f, False),
                     "observable": {"n": 0, "correct": 0, "partial": 0,
                                    "wrong": 0, "missing": 0},
                     "inferred": {"n": 0, "reported": 0, "correct": 0,
                                  "partial": 0, "wrong": 0}}
    proto = {"assets": 0, "tp": 0, "exported": 0, "truth": 0}
    ttds = []
    per_asset = []
    for a in truth.assets:
        r = primary.get(a["id"])
        if r is None and not a["emitted"]:
            continue
        ent: Dict[str, Any] = {
            "id": a["id"], "name": a["name"], "ip": a["ip"], "mac": a["mac"],
            "vlan": a["vlan"], "role": a["role"], "new": a["new"],
            "emitted": a["emitted"],
            "status": "found" if r else "missed", "method": None,
            "rows": [x["row"] for x in rows if x.get("asset") == a["id"]],
            "fields": {}, "protocols": None, "ttd_s": None}
        if r is None:
            per_asset.append(ent)
            continue
        if not a["emitted"]:
            ent["status"] = "found (not emitted)"
        ent["method"] = r["method"]
        for f in FIELDS:
            cands, observable = a["fields"][f]
            if not cands or not cols.get(f):
                continue
            got = r[f]
            outcome = compare(f, got, cands) if got else "missing"
            ent["fields"][f] = {"truth": cands[0], "got": got,
                                "observable": observable, "outcome": outcome}
            agg = fields[f]["observable" if observable else "inferred"]
            agg["n"] += 1
            if observable:
                agg[outcome] += 1
            elif got:
                agg["reported"] += 1
                agg[outcome] += 1
        if r["protocols"] is not None:
            got = set(r["protocols"])
            want = a["protocols"] - set(export_info["protocol_ignore"])
            hit = got & want
            proto["assets"] += 1
            proto["tp"] += len(hit)
            proto["exported"] += len(got)
            proto["truth"] += len(want)
            ent["protocols"] = {
                "truth": sorted(want), "got": sorted(got),
                "missing": sorted(want - got), "extra": sorted(got - want),
                "precision": _ratio(len(hit), len(got)),
                "recall": _ratio(len(hit), len(want))}
        if r["first_seen"] and a["first_seen"]:
            ent["ttd_s"] = (r["first_seen"] - a["first_seen"]).total_seconds()
            ttds.append(ent["ttd_s"])
        per_asset.append(ent)
    for f in FIELDS:
        o = fields[f]["observable"]
        o["accuracy"] = _ratio(o["correct"], o["n"])
        o["accuracy_with_partial"] = _ratio(o["correct"] + o["partial"],
                                            o["n"])

    new = [a for a in truth.assets if a["new"]]
    res: Dict[str, Any] = {
        "schema": SCHEMA,
        "truth": {"mode": truth.mode, "source": truth.source,
                  "env": truth.env, "assets": len(truth.assets),
                  "start": _iso(truth.start), "end": _iso(truth.end)},
        "export": {"source": export_info.get("source"),
                   "map": export_info.get("map"),
                   "rows": export_info["rows"],
                   "records": len(rows), "columns": cols},
        "discovery": discovery,
        "fields": fields,
        "protocols": dict(proto, precision=_ratio(proto["tp"],
                                                  proto["exported"]),
                          recall=_ratio(proto["tp"], proto["truth"]))
        if proto["assets"] else None,
        "new_assets": {"total": len(new),
                       "detected": [a["id"] for a in new if a["id"] in primary],
                       "missed": [a["id"] for a in new
                                  if a["id"] not in primary]} if new else None,
        "time_to_discover": {"n": len(ttds), "median_s": _median(ttds),
                             "min_s": min(ttds), "max_s": max(ttds)}
        if ttds else None,
        "baseline": baseline(truth, zeek) if zeek else None,
        "detections": None,
        "assets": sorted(per_asset, key=lambda e: (
            e["status"] != "missed", e["name"])),
    }
    if alerts is not None:
        if truth.events or truth.mode == "manifest":
            res["detections"] = detections(truth, alerts, tolerance, skew)
        else:
            res["detections"] = {"note": "detections need a run manifest "
                                         "with events (--manifest)",
                                 "alerts": len(alerts)}
    return res


# --------------------------------------------------------------------------
# rendering

def _pct(x: Optional[float]) -> str:
    return "n/a" if x is None else f"{100 * x:.1f}%"


def _secs(x: Optional[float]) -> str:
    return "n/a" if x is None else f"{x:.1f}s"


def summary(res: Dict[str, Any]) -> str:
    t, d = res["truth"], res["discovery"]
    lines = [f"tgt score — {t['env'] or 'run'} ({t['mode']} {t['source']}) "
             f"vs {res['export']['source']} [{res['export']['map']}]"]
    lines.append(
        f"discovery   recall {d['found']}/{d['population']} "
        f"{_pct(d['recall'])}   precision {d['matched_assets']}/"
        f"{d['matched_assets'] + d['duplicates'] + d['false_positives']} "
        f"{_pct(d['precision'])}   (dup {d['duplicates']}, fp "
        f"{d['false_positives']}, infra {d['infrastructure']}, external "
        f"{d['external']})")
    parts = []
    for f, v in res["fields"].items():
        o = v["observable"]
        if v["exported"] and o["n"]:
            parts.append(f"{f} {o['correct']}/{o['n']} {_pct(o['accuracy'])}"
                         + (f" (+{o['partial']} partial)" if o["partial"]
                            else ""))
    if parts:
        lines.append("fields      " + " | ".join(parts))
    inf = [f"{f} {v['inferred']['correct']}" for f, v in res["fields"].items()
           if v["inferred"]["correct"]]
    if inf:
        lines.append("inferred    correct on non-observable fields: " +
                     ", ".join(inf))
    p = res["protocols"]
    if p:
        lines.append(f"protocols   precision {_pct(p['precision'])}  recall "
                     f"{_pct(p['recall'])}  over {p['assets']} assets")
    n = res["new_assets"]
    if n:
        lines.append(f"new assets  {len(n['detected'])}/{n['total']} detected"
                     + (f"; missed {', '.join(n['missed'])}"
                        if n["missed"] else ""))
    t2 = res["time_to_discover"]
    if t2:
        lines.append(f"discover    median {_secs(t2['median_s'])}  max "
                     f"{_secs(t2['max_s'])}  (n={t2['n']})")
    b = res["baseline"]
    if b:
        lines.append(f"baseline    {b['seen']}/{b['expected']} expected flows "
                     f"in conn.log ({_pct(b['coverage'])}), "
                     f"{len(b['unexpected'])} unexpected")
    det = res["detections"]
    if det and "note" in det:
        lines.append(f"detections  {det['note']}")
    elif det:
        lines.append(f"detections  {det['detected']}/{det['events']} events "
                     f"({_pct(det['rate'])}), median ttd "
                     f"{_secs(det['median_ttd_s'])}; "
                     f"{len(det['false_alerts'])} false, "
                     f"{det['unmapped_alerts']} unmapped alerts")
    if d["missed"]:
        more = len(d["missed"]) - 8
        lines.append("missed      " + ", ".join(d["missed"][:8]) +
                     (f" (+{more} more)" if more > 0 else ""))
    return "\n".join(lines)


_CSS = """
:root{--bg:#fbfbfa;--fg:#1d1d1f;--muted:#6b6b70;--line:#e3e3e0;--card:#fff;
--ok:#1a7f37;--part:#9a6700;--bad:#c62828;--chip:#f1f1ef}
@media (prefers-color-scheme:dark){:root{--bg:#141416;--fg:#e8e8ea;
--muted:#9a9aa2;--line:#2c2c31;--card:#1c1c20;--ok:#4cc26a;--part:#e3b341;
--bad:#ff6b6b;--chip:#26262b}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1180px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:32px 0 8px}
.sub{color:var(--muted);margin:0 0 20px}
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));
gap:10px}.tile{background:var(--card);border:1px solid var(--line);
border-radius:8px;padding:12px}.tile b{display:block;font-size:22px;
font-variant-numeric:tabular-nums}.tile span{color:var(--muted);font-size:12px}
.wrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px;
background:var(--card)}table{border-collapse:collapse;width:100%}
th,td{padding:6px 10px;border-bottom:1px solid var(--line);text-align:left;
vertical-align:top;white-space:nowrap}td.w{white-space:normal}
th{font-weight:600;color:var(--muted);font-size:12px}
tr:last-child td{border-bottom:0}td.n{text-align:right;
font-variant-numeric:tabular-nums}
.correct,.found{color:var(--ok)}.partial{color:var(--part)}
.wrong,.missed,.missing{color:var(--bad)}.dim{color:var(--muted)}
code{background:var(--chip);padding:1px 4px;border-radius:4px}
"""


def _h(x: Any) -> str:
    return html.escape("" if x is None else str(x))


def _table(head: Sequence[str], rows: Iterable[Sequence[Any]],
           numeric: Sequence[int] = ()) -> str:
    out = ["<div class=wrap><table><thead><tr>"]
    out += [f"<th>{_h(c)}</th>" for c in head]
    out.append("</tr></thead><tbody>")
    n = 0
    for r in rows:
        n += 1
        out.append("<tr>")
        for i, c in enumerate(r):
            cls = ' class="n"' if i in numeric else ""
            if isinstance(c, tuple):                 # (text, css class)
                out.append(f'<td class="{_h(c[1])}">{_h(c[0])}</td>')
            else:
                out.append(f"<td{cls}>{_h(c)}</td>")
        out.append("</tr>")
    if not n:
        out.append(f'<tr><td class=dim colspan={len(head)}>none</td></tr>')
    out.append("</tbody></table></div>")
    return "".join(out)


def to_html(res: Dict[str, Any]) -> str:
    t, d = res["truth"], res["discovery"]
    tiles = [("Discovery recall", _pct(d["recall"]),
              f"{d['found']} of {d['population']} assets"),
             ("Discovery precision", _pct(d["precision"]),
              f"{d['duplicates']} dup, {d['false_positives']} false")]
    obs = [v["observable"] for v in res["fields"].values() if v["exported"]]
    n_obs = sum(o["n"] for o in obs)
    if n_obs:
        tiles.append(("Field accuracy", _pct(_ratio(
            sum(o["correct"] for o in obs), n_obs)),
            f"observable fields, {sum(o['partial'] for o in obs)} partial"))
    if res["protocols"]:
        p = res["protocols"]
        tiles.append(("Protocol recall", _pct(p["recall"]),
                      f"precision {_pct(p['precision'])}"))
    if res["new_assets"]:
        n = res["new_assets"]
        tiles.append(("New assets", f"{len(n['detected'])}/{n['total']}",
                      "detected"))
    if res["time_to_discover"]:
        tiles.append(("Time to discover",
                      _secs(res["time_to_discover"]["median_s"]), "median"))
    if res["baseline"]:
        b = res["baseline"]
        tiles.append(("Baseline coverage", _pct(b["coverage"]),
                      f"{b['seen']} of {b['expected']} flows"))
    det = res["detections"]
    if det and "note" not in det:
        tiles.append(("Detection rate", _pct(det["rate"]),
                      f"{det['detected']} of {det['events']} events"))
    body = [f"<h1>TGT score — {_h(t['env'] or 'run')}</h1>",
            f"<p class=sub>Ground truth: {_h(t['mode'])} <code>"
            f"{_h(t['source'])}</code> · export <code>"
            f"{_h(res['export']['source'])}</code> · map <code>"
            f"{_h(res['export']['map'])}</code> · {d['population_basis']}</p>",
            "<div class=tiles>"]
    body += [f"<div class=tile><span>{_h(a)}</span><b>{_h(b)}</b>"
             f"<span>{_h(c)}</span></div>" for a, b, c in tiles]
    body.append("</div>")

    body.append("<h2>Field accuracy</h2><p class=sub>Scored only where the "
                "field is observable from the traffic TGT sent; correct "
                "values for non-observable fields are listed as inferred.</p>")
    rows = []
    for f, v in res["fields"].items():
        o, i = v["observable"], v["inferred"]
        if not v["exported"]:
            rows.append((f, ("not exported", "dim"), "", "", "", "", "", ""))
            continue
        rows.append((f, o["n"], o["correct"], o["partial"], o["wrong"],
                     o["missing"], _pct(o["accuracy"]),
                     f"{i['correct']} of {i['reported']} reported"))
    body.append(_table(("Field", "Observable", "Correct", "Partial", "Wrong",
                        "Missing", "Accuracy", "Inferred"), rows,
                       numeric=(1, 2, 3, 4, 5, 6)))

    body.append("<h2>Assets</h2>")
    rows = []
    for a in res["assets"]:
        cells = [a["name"], a["ip"] or "", (a["status"], a["status"].split()[0]),
                 a["method"] or "", len(a["rows"]) or ""]
        for f in FIELDS:
            fv = a["fields"].get(f)
            if fv is None:
                cells.append(("", "dim"))
            else:
                txt = fv["got"] or "(missing)"
                cls = fv["outcome"] if fv["observable"] else "dim"
                cells.append((txt if fv["outcome"] == "correct" else
                              f"{txt} ≠ {fv['truth']}", cls))
        pr = a["protocols"]
        cells.append("" if pr is None else
                     f"{_pct(pr['recall'])} / {_pct(pr['precision'])}")
        cells.append(_secs(a["ttd_s"]) if a["ttd_s"] is not None else "")
        rows.append(cells)
    body.append(_table(("Asset", "IP", "Status", "Match", "Rows") + FIELDS +
                       ("Proto R/P", "TTD"), rows, numeric=(4,)))

    body.append("<h2>Misses and extras</h2>")
    miss = [(x, "missed asset") for x in d["missed"]]
    miss += [(f"row {r['row']}: {r['ip'] or r['mac'] or r['name']}",
              "false positive") for r in d["false_positive_rows"]]
    miss += [(f"row {r['row']}: {r['asset']}", "duplicate")
             for r in d["duplicate_rows"]]
    miss += [(f"row {r['row']}: {r['ip'] or r['mac']}", "infrastructure "
              "(unscored)") for r in d["infrastructure_rows"]]
    miss += [(f"row {r['row']}: {r['ip']}", "external (unscored)")
             for r in d["external_rows"]]
    body.append(_table(("Item", "Kind"), miss))

    if det and "note" not in det:
        body.append("<h2>Detections</h2>")
        body.append(_table(
            ("Category", "Events", "Detected", "Rate", "Median TTD"),
            [(c, v["events"], v["detected"], _pct(v["rate"]),
              _secs(v["median_ttd_s"])) for c, v in
             det["per_category"].items()], numeric=(1, 2, 3, 4)))
        body.append("<h2>Missed events</h2>")
        body.append(_table(("Event", "Category", "Start", "Hosts", "Detail"),
                           [(e["id"], e["category"], e["t_start"],
                             ", ".join(e["hosts"]), e["detail"])
                            for e in det["missed"]]))
        body.append("<h2>False and unmapped alerts</h2>")
        body.append(_table(("Row", "Time", "Title", "Category", "Src", "Dst"),
                           [(a["row"], a["time"], a["title"], a["category"],
                             a["src"], a["dst"]) for a in det["false_alerts"]]
                           + [("", "", u["title"], f"unmapped x{u['count']}",
                               "", "") for u in det["unmapped_titles"]]))
    b = res["baseline"]
    if b:
        body.append("<h2>Baseline flows not seen in conn.log</h2>")
        body.append(_table(("Client", "Server", "Protocol", "Port"),
                           [(f["client"], f["server"], f["protocol"],
                             f"{f['dport'] or ''}/{f['transport']}")
                            for f in b["missed"]]))
        body.append("<h2>Unexpected flows</h2>")
        body.append(_table(("Orig", "Resp", "Port", "Conns"),
                           [(f"{u['orig']} {u['orig_name']}".strip(),
                             f"{u['resp']} {u['resp_name']}".strip(),
                             f"{u['dport']}/{u['proto']}", u["conns"])
                            for u in b["unexpected"]], numeric=(3,)))
    return ("<!doctype html><html lang=en><head><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>TGT score</title><style>{_CSS}</style></head><body>"
            f"<main>{''.join(body)}</main></body></html>\n")


# --------------------------------------------------------------------------
# CLI

def add_arguments(p) -> None:
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--manifest", metavar="RUN.json",
                     help="run manifest from 'tgt run --manifest'")
    src.add_argument("--truth", metavar="INVENTORY.json",
                     help="'tgt inventory -f json' document")
    p.add_argument("--assets", required=True, metavar="EXPORT",
                   help="the monitor's asset export (CSV/JSON/Zeek log)")
    p.add_argument("--map", required=True, metavar="MAP",
                   help="column map: a path or a bundled name (generic, "
                        "zeek-known-hosts, claroty-ctd, nozomi)")
    p.add_argument("--zeek", metavar="DIR",
                   help="Zeek log dir (or conn.log): baseline-flow coverage")
    p.add_argument("--alerts", metavar="FILE",
                   help="the monitor's alert export (CSV/JSON)")
    p.add_argument("--alert-map", metavar="MAP",
                   help="alert columns + title regex -> generic category")
    p.add_argument("--tolerance", type=float, default=300.0, metavar="SEC",
                   help="alert may trail the event end by this much "
                        "(default 300)")
    p.add_argument("--skew", type=float, default=5.0, metavar="SEC",
                   help="alert may precede the event start by this much "
                        "(clock skew, default 5)")
    p.add_argument("--fuzzy", type=float, default=0.85, metavar="RATIO",
                   help="name-similarity threshold for name matching")
    p.add_argument("--json", metavar="FILE", help="write full results here")
    p.add_argument("--html", metavar="FILE",
                   help="write a self-contained HTML report here")


def run(args) -> int:
    try:
        truth = load_truth(args.manifest or args.truth)
        mapping = load_json_spec(args.map, "map")
        rows, info = read_export(args.assets, mapping)
        info["source"] = args.assets
        info["map"] = os.path.basename(mapping["_path"])
        alerts = None
        if args.alerts:
            if not args.alert_map:
                raise ScoreError("--alerts needs --alert-map")
            alerts = read_alerts(args.alerts,
                                 load_json_spec(args.alert_map, "alert map"))
        res = score(truth, rows, info, zeek=args.zeek, alerts=alerts,
                    tolerance=args.tolerance, skew=args.skew,
                    fuzzy=args.fuzzy)
    except ScoreError as e:
        print(f"tgt score: {e}", file=sys.stderr)
        return 2
    print(summary(res))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=2, default=str)
            f.write("\n")
        print(f"wrote {args.json}", file=sys.stderr)
    if args.html:
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(to_html(res))
        print(f"wrote {args.html}", file=sys.stderr)
    return 0
