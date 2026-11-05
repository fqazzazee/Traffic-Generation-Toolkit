"""MITRE ATT&CK technique tags for TGT's attack flows and incidents.

The technique table (ID -> name, tactics, matrix) is data, in
``tgt/attack_ics.json``: ATT&CK for ICS IDs (``T08xx``) plus the Enterprise
IDs for the IT stages (discovery, lateral movement, C2, exfiltration).
This module maps each attack builder in :data:`tgt.incidents.ATTACKS` onto
the techniques its traffic plainly shows on the wire, and adds a few
per-incident extras where an incident's flow shows more than the bare
builder does (DGA lookups, an IOA sweep, an external scan...).

A tag means "this traffic is what a sensor would see when an adversary uses
the technique" — the flows stay signature-level synthetic (see
:mod:`tgt.incidents`). Techniques that leave no wire trace (encryption for
impact, process kills on a host) are deliberately not tagged.

Run manifests carry ``techniques`` on each attack event (see
:func:`for_event`) and ``tgt score`` reports detection coverage per
technique.
"""
from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Optional, Sequence, Tuple

TABLE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "attack_ics.json")

# attack builder (incidents.ATTACKS key) -> techniques its frames show
ATTACK_TECHNIQUES: Dict[str, Tuple[str, ...]] = {
    "port-scan": ("T0846", "T1046"),           # SYN sweep of service ports
    "eternalblue": ("T0866", "T1210"),         # SMBv1 exploit attempt
    "c2-beacon": ("T0869", "T1071.001"),       # HTTP implant check-in
    "dga-dns": ("T0869", "T1071.004"),         # C2 / IOC domain lookups
    "telnet-brute": ("T0812", "T0886", "T1110.001"),
    "log4shell": ("T0819", "T1190"),           # JNDI string to a web app
    "s7-control": ("T0855", "T0858"),          # S7 PLC STOP job
    "iec104-command": ("T0855",),              # breaker single commands
    "tristation": ("T0843", "T0868"),          # download + get CP status
    "dns-tunnel": ("T0869", "T1048", "T1071.004"),
    "https-c2": ("T0869", "T1071.001", "T1573"),
    "rdp-brute": ("T0886", "T1110.003"),       # mstshash password spray
    "smb-lateral": ("T0886", "T1021.002"),     # ADMIN$ / IPC$ tree connects
    "modbus-write": ("T0836", "T0855"),        # FC16 forced setpoints
}

# incident -> {attack: extra techniques} where the incident's flow shows more
# than the builder alone (its meta makes the lookups DGA names, ...)
INCIDENT_EXTRAS: Dict[str, Dict[str, Tuple[str, ...]]] = {
    "sunburst": {"dga-dns": ("T1568.002",)},     # avsvmcloud.com DGA names
    "conficker": {"dga-dns": ("T1568.002",)},    # generated .info/.biz names
    "industroyer": {"iec104-command": ("T0806",)},   # IOA-by-IOA sweep
    "log4shell": {"port-scan": ("T1595",),       # scan from the internet
                  "c2-beacon": ("T1105",)},      # fetch of the /Exploit class
}

_TID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)
_table: Optional[Dict[str, Dict]] = None


def load() -> Dict[str, Dict]:
    """The technique table: {ID: {"name", "tactic": [...], "matrix"}}."""
    global _table
    if _table is None:
        with open(TABLE_PATH, encoding="utf-8") as f:
            doc = json.load(f)
        _table = {k: v for k, v in doc.items() if not k.startswith("_")}
    return _table


def name(tid: str) -> str:
    """Official technique name, ``""`` if the ID is not in the table."""
    return load().get(tid, {}).get("name", "")


def tactics(tid: str) -> List[str]:
    return list(load().get(tid, {}).get("tactic", []))


def for_attack(attack_key: str) -> List[str]:
    """Techniques an attack builder's traffic shows (sorted, maybe empty)."""
    return sorted(set(ATTACK_TECHNIQUES.get(attack_key, ())))


def for_flow(attack_key: str, incident_key: Optional[str] = None) -> List[str]:
    """Techniques of one incident flow: the builder's plus the incident's
    extras for that attack."""
    extra = INCIDENT_EXTRAS.get(incident_key or "", {}).get(attack_key, ())
    return sorted(set(ATTACK_TECHNIQUES.get(attack_key, ())) | set(extra))


def for_incident(incident_key: str) -> List[str]:
    """Every technique an incident's flows show (sorted unique)."""
    from . import incidents
    inc = incidents.INCIDENTS.get(incident_key)
    if inc is None:
        return []
    out = set()
    for _, _, atk, _ in inc.flows:
        out.update(for_flow(atk, incident_key))
    return sorted(out)


def incident_of(source: str) -> Optional[str]:
    """The incident key in a frame source label (``incident:<key>``,
    ``sprinkle:<key>``, ``inject:<key>#<id>``), else None."""
    kind, _, rest = (source or "").partition(":")
    if kind not in ("incident", "sprinkle", "inject") or not rest:
        return None
    return rest.split("#", 1)[0]


def for_event(attack_key: str, source: str = "") -> List[str]:
    """Techniques of a manifest attack event: its attack, plus the extras of
    the incident named by its source label."""
    return for_flow(attack_key, incident_of(source))


def parse_ids(text: str) -> List[str]:
    """Technique IDs found in free text (``"T0855, t1071.001"``), upper-cased,
    in order of appearance, unique."""
    return list(dict.fromkeys(m.upper() for m in _TID.findall(text or "")))


def _parent(tid: str) -> str:
    return tid.split(".", 1)[0]


def shares(a: Sequence[str], b: Sequence[str]) -> bool:
    """Whether two technique lists share a technique. A parent technique
    matches its own sub-techniques (T1071 ~ T1071.001); sibling
    sub-techniques (T1110.001 vs T1110.003) do not match."""
    for x in a:
        for y in b:
            if x == y or (x == _parent(y) and "." not in x) or \
                    (y == _parent(x) and "." not in y):
                return True
    return False


def validate() -> List[str]:
    """Problems with the mapping: attacks without techniques, IDs not in
    the table, extras for unknown incidents / attacks."""
    from . import incidents
    tab = load()
    out = []
    for atk in incidents.ATTACKS:
        if not ATTACK_TECHNIQUES.get(atk):
            out.append(f"attack {atk}: no techniques")
    ids = [(f"attack {a}", t) for a, ts in ATTACK_TECHNIQUES.items()
           for t in ts]
    for inc, extra in INCIDENT_EXTRAS.items():
        known = incidents.INCIDENTS.get(inc)
        if known is None:
            out.append(f"extras: unknown incident {inc}")
            continue
        used = {f[2] for f in known.flows}
        for atk, ts in extra.items():
            if atk not in used:
                out.append(f"extras {inc}: incident has no {atk} flow")
            ids += [(f"extras {inc}/{atk}", t) for t in ts]
    out += [f"{where}: {t} not in {os.path.basename(TABLE_PATH)}"
            for where, t in ids if t not in tab]
    return out
