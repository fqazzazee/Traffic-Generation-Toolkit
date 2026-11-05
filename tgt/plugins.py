"""Plugins — site-specific protocols, scenarios, environments, incidents,
device models and score maps that live outside the TGT tree.

Discovery: every ``*.py`` file (not starting with ``_`` or ``.``) in

1. each directory of ``TGT_PLUGIN_PATH`` (``os.pathsep``-separated), in order;
2. ``$XDG_CONFIG_HOME/tgt/plugins/`` (default ``~/.config/tgt/plugins/``)

is imported once at startup — by ``tgt list``, ``tgt run``, the TUI,
``tgt inventory`` and ``tgt score`` — directory by directory, files in name
order. A file whose name was already loaded from an earlier directory is
skipped (like ``PATH``). A plugin that fails to import, or whose registration
raises, is reported (``tgt list`` shows it) and skipped; it never stops TGT.
``TGT_NO_PLUGINS=1`` disables loading.

A plugin is a plain module that calls the functions below at import time::

    from tgt import plugins

    def my_flow(ep, count):          # (Endpoints, int) -> List[bytes]
        ...
    plugins.register_protocol("my-proto", "My Protocol", "OT", "5555", "udp",
                              my_flow, "what it does", dissector="myproto")
    plugins.register_scenario("my-mix", "My Mix", ["my-proto", "modbus"],
                              "a scenario using it")
    plugins.register_env_file(os.path.join(os.path.dirname(__file__),
                                            "my-site.json"))

See ``examples/plugins/acme_plant.py`` for a complete, self-testing example.

API (all return what they registered; keys must not clash with built-ins or
earlier plugins unless ``replace=True``):

* :func:`register_protocol` — a flow builder (``protocols._reg``);
  ``dissector`` is the tshark layer it decodes as (selftest checks it), or
  ``None`` when Wireshark has none; ``link_local`` keeps it on one segment.
* :func:`register_scenario` — a named protocol mix.
* :func:`register_environment` / :func:`register_env_file` — an
  :class:`~tgt.enterprise.Environment` object or an env file (JSON/TOML,
  schema in :mod:`tgt.envfile`).
* :func:`register_attack` — an attack builder incidents can use, with its
  generic manifest category, registry protocol and victim service.
* :func:`register_incident` — an :class:`~tgt.incidents.Incident`.
* :func:`register_device_model` — a :class:`~tgt.devices.DeviceModel`.
* :func:`register_scoremap` — a ``tgt score`` mapping file by name.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import traceback
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

API_VERSION = 1

# protocol key -> tshark layer (None: no Wireshark dissector) for plugin
# protocols; tests/selftest.py checks these like its own _DISSECTS_AS table
DISSECTORS: Dict[str, Optional[str]] = {}
LOADED: List[Tuple[str, str]] = []          # (module name, path)
ERRORS: List[Tuple[str, str]] = []          # (path, message)

_loaded = False
_current: Optional[str] = None              # plugin being imported
# undo journal: (dict-like, key, previous value or _MISSING)
_MISSING = object()
_journal: List[Tuple[Any, Any, Any]] = []
# key -> plugin path, per kind (for clash messages and `tgt list`)
OWNERS: Dict[str, Dict[str, str]] = {}


class PluginError(Exception):
    pass


def search_path() -> List[str]:
    """Plugin directories in load order."""
    out = [p for p in os.environ.get("TGT_PLUGIN_PATH", "").split(os.pathsep)
           if p]
    cfg = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config")
    out.append(os.path.join(cfg, "tgt", "plugins"))
    return out


def plugin_files(paths: Optional[List[str]] = None) -> List[str]:
    """The plugin files :func:`load_plugins` would import, in order."""
    files, seen = [], set()
    for d in (search_path() if paths is None else paths):
        if os.path.isfile(d) and d.endswith(".py"):
            cands = [d]
        elif os.path.isdir(d):
            cands = [os.path.join(d, f) for f in sorted(os.listdir(d))
                     if f.endswith(".py") and not f.startswith(("_", "."))]
        else:
            continue
        for path in cands:
            stem = os.path.basename(path)[:-3]
            if stem in seen:
                continue
            seen.add(stem)
            files.append(path)
    return files


def load_plugins(paths: Optional[List[str]] = None, force: bool = False,
                 warn: Optional[Callable[[str], None]] = None) -> List[str]:
    """Import every plugin file (once per process unless ``force``).
    Returns the module names loaded; failures go to :data:`ERRORS` and
    ``warn`` (default: stderr)."""
    global _loaded, _current
    if (_loaded and not force) or os.environ.get("TGT_NO_PLUGINS"):
        return []
    _loaded = True
    if warn is None:
        def warn(msg: str) -> None:
            print(f"tgt: warning: {msg}", file=sys.stderr)
    got = []
    for path in plugin_files(paths):
        stem = os.path.basename(path)[:-3]
        name = "tgt_plugin_" + "".join(c if c.isalnum() else "_" for c in stem)
        if any(p == path for _, p in LOADED):
            continue
        mark = len(_journal)
        _current = path
        try:
            spec = importlib.util.spec_from_file_location(name, path)
            if spec is None or spec.loader is None:
                raise PluginError("not importable")
            mod = importlib.util.module_from_spec(spec)
            sys.modules[name] = mod
            spec.loader.exec_module(mod)
        except Exception as e:  # noqa: BLE001 - a plugin never breaks TGT
            sys.modules.pop(name, None)
            _rollback(mark)                 # half-registered plugin: undo
            tb = traceback.extract_tb(e.__traceback__)
            where = next((f"{os.path.basename(f.filename)}:{f.lineno}"
                          for f in reversed(tb) if f.filename == path), "")
            msg = f"{type(e).__name__}: {e}" + (f" ({where})" if where else "")
            ERRORS.append((path, msg))
            warn(f"plugin {path} not loaded: {msg}")
            continue
        finally:
            _current = None
        LOADED.append((name, path))
        got.append(name)
    return got


def _rollback(mark: int) -> None:
    while len(_journal) > mark:
        target, key, prev = _journal.pop()
        if prev is _MISSING:
            if isinstance(target, set):
                target.discard(key)
            else:
                target.pop(key, None)
        elif isinstance(target, set):
            target.add(key)
        else:
            target[key] = prev


def unload_all() -> None:
    """Undo every registration made by plugins (tests; the modules stay
    imported) and allow :func:`load_plugins` to run again."""
    global _loaded
    _rollback(0)
    for name, _ in LOADED:
        sys.modules.pop(name, None)
    LOADED.clear()
    ERRORS.clear()
    OWNERS.clear()
    _loaded = False


def _put(kind: str, target: Any, key: Any, value: Any = None,
         replace: bool = False) -> None:
    """Journalled ``target[key] = value`` (or set.add) with clash check."""
    if isinstance(target, set):
        exists = key in target
        if exists and not replace:
            return
        _journal.append((target, key, key if exists else _MISSING))
        target.add(key)
        return
    exists = key in target
    if exists and not replace and kind:
        owner = OWNERS.get(kind, {}).get(key)
        raise PluginError(f"{kind} {key!r} is already defined"
                          + (f" (by {owner})" if owner else " (built in)"))
    _journal.append((target, key, target[key] if exists else _MISSING))
    target[key] = value
    if kind:
        owners = OWNERS.setdefault(kind, {})
        _journal.append((owners, key, owners.get(key, _MISSING)))
        owners[key] = _current or "<api>"


# ---------------------------------------------------------------------------
# registration API
# ---------------------------------------------------------------------------
def register_protocol(key: str, name: str, category: str, port: str,
                      transport: str, build: Callable, desc: str, *,
                      dissector: Optional[str] = None,
                      link_local: bool = False, replace: bool = False):
    """A protocol profile: ``build(ep: Endpoints, count: int) -> [frames]``.
    ``category`` OT | IT, ``transport`` tcp | udp | ip | l2, ``port`` text
    shown by ``tgt list``. Usable by ``--profile``, scenarios, env flows."""
    from . import protocols
    if transport not in ("tcp", "udp", "ip", "l2"):
        raise PluginError(f"protocol {key}: transport must be tcp, udp, ip "
                          "or l2")
    prof = protocols.Profile(key, name, category, str(port), transport, build,
                             desc)
    _put("protocol", protocols.PROFILES, key, prof, replace)
    _put("", DISSECTORS, key, dissector, True)
    if link_local:
        _put("", protocols.LINK_LOCAL, key)
    return prof


def register_scenario(key: str, name: str, profiles: List[str], desc: str,
                      *, replace: bool = False):
    from . import protocols, scenarios
    for p in profiles:
        if p not in protocols.PROFILES:
            raise PluginError(f"scenario {key}: unknown protocol {p!r}")
    sc = scenarios.Scenario(key, name, list(profiles), desc)
    _put("scenario", scenarios.SCENARIOS, key, sc, replace)
    return sc


def register_environment(env, *, replace: bool = False):
    """An :class:`~tgt.enterprise.Environment` (validated by the caller or
    built with :mod:`tgt.envfile`)."""
    from . import enterprise
    _put("environment", enterprise.ENVIRONMENTS, env.key, env, replace)
    return env


def register_env_file(path: str, *, replace: bool = False):
    """Load an env file (JSON / TOML, see :mod:`tgt.envfile`) and register
    it. Raises the env file's error (the plugin is then reported)."""
    from . import envfile
    env = envfile.load(path)
    return register_environment(env, replace=replace)


def register_attack(key: str, build: Callable, desc: str, *, category: str,
                    protocol: Optional[str] = None,
                    service: Optional[str] = None, replace: bool = False,
                    techniques: Sequence[str] = ()):
    """An attack builder ``build(ep, count) -> [frames]`` for incident flows.
    ``category`` is the vendor-neutral manifest category (``scan``,
    ``exploit-attempt``, ``c2``, ``ot-write``, ``plc-program`` ...),
    ``protocol`` the registry protocol the traffic is (None = attack-only),
    ``service`` what the victim must serve for an incident to map onto an
    environment host (None = nothing, like a scan), ``techniques`` the
    MITRE ATT&CK IDs the traffic shows (each must be in
    ``tgt/attack_ics.json``; see :mod:`tgt.techniques`)."""
    from . import incidents, manifest, techniques as tech
    bad = [t for t in techniques if t not in tech.load()]
    if bad:
        raise PluginError(f"attack {key!r}: unknown technique(s) "
                          f"{', '.join(bad)} (see tgt/attack_ics.json)")
    _put("attack", incidents.ATTACKS, key, (build, desc), replace)
    _put("", tech.ATTACK_TECHNIQUES, key, tuple(techniques), True)
    _put("", incidents.ATTACK_PROTOCOLS, key, protocol, True)
    _put("", incidents._ATTACK_SERVICE, key, service, True)
    _put("", manifest.ATTACK_CATEGORY, key, category, True)
    return key


def register_incident(incident, *, replace: bool = False):
    """An :class:`~tgt.incidents.Incident` (hosts + flows over registered
    attacks)."""
    from . import incidents
    for _, _, atk, _ in incident.flows:
        if atk not in incidents.ATTACKS:
            raise PluginError(f"incident {incident.key}: unknown attack "
                              f"{atk!r} (register_attack it first)")
    _put("incident", incidents.INCIDENTS, incident.key, incident, replace)
    return incident


def register_device_model(model, *, replace: bool = False):
    """A :class:`~tgt.devices.DeviceModel`; its ``aliases`` resolve host
    ``product`` strings to it, like the built-in catalog."""
    from . import devices
    _put("device model", devices.CATALOG, model.model_id, model, replace)
    for a in model.aliases:
        _put("", devices._ALIASES, a, model.model_id, True)
    return model


def register_scoremap(name: str, path: str, *, replace: bool = False) -> str:
    """A ``tgt score`` mapping file (``--map`` / ``--alert-map NAME``; JSON,
    see tgt/scoremaps/)."""
    from . import score
    if not os.path.isfile(path):
        raise PluginError(f"score map {name}: no such file {path}")
    _put("score map", score.PLUGIN_MAPS, name, os.path.abspath(path),
         replace)
    return name
