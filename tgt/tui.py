"""TGT text UI — a live SPAN traffic-flow diagram you can navigate and drive.

The centrepiece is the flow diagram, drawn for how frames reach the sensor:

    veth pair        TGT ENGINE ─▶ tgt0 (send) ─▶ tgt0-mon (monitor) ─▶ SENSOR
    real interface   TGT ENGINE ─▶ eth0 (send) ┈▶ SENSOR   (via a SPAN)
    pcap only        TGT ENGINE ─▶ PCAP ┈▶ SENSOR          (imported)

Each box carries live data — the traffic mix (malware always visible), packets,
bytes and errors on the send side, the SPAN view and VLAN tagging at the
monitor — and packets animate along the path while it generates. Four tabbed
panels below drive it: Run (preset, SPAN view, malware, rate, output), Traffic
(protocol mix), Interfaces (veth pair + sensor) and Service.

Pure curses, no dependencies. Works over SSH and inside WSL/Podman terminals.
"""
from __future__ import annotations

import curses
import ipaddress
import os
import textwrap
import time
from typing import Callable, Dict, List, Optional, Tuple, Union

from . import enterprise, incidents, net, protocols, scenarios, service
from .config import RunConfig
from .engine import Engine
from .packet import Endpoints

# ── colour pairs ────────────────────────────────────────────────────────────
C_CYAN, C_GREEN, C_YELLOW, C_MAGENTA, C_RED, C_BLUE, C_DIM = range(1, 8)

BOX = dict(tl="╭", tr="╮", bl="╰", br="╯", h="─", v="│")
DOT = "•"
ARROW = "▶"
BAR = "▇"

PANELS = ["Run", "Traffic", "Interfaces", "Service"]

RATE_STEPS = [1, 5, 10, 20, 50, 100, 200, 500, 1000, 0]        # 0 = max
RATIO_STEPS = [0.0, 0.01, 0.02, 0.05, 0.1, 0.2, 0.3, 0.5]

Value = Union[str, Tuple[str, int]]


# ── state ───────────────────────────────────────────────────────────────────
class UI:
    def __init__(self):
        self.sys = net.detect_env()          # cached: it reads /proc and PATH
        self.ifaces: Dict[str, dict] = {}
        self._if_poll = 0.0
        self.refresh(force=True)
        pref = next((n for n in self.ifaces
                     if n.startswith("tgt") and not n.endswith("-mon")), None)
        self.send_iface: Optional[str] = pref
        self.sensor_label = "Zeek/Suricata"
        self.selected: List[str] = ["modbus", "s7comm"]
        self.scenario: Optional[str] = None
        self.env: Optional[str] = None       # modeled environment (overrides protos)
        self.span = "access"                 # env capture point: access | core
        self.incident: Optional[str] = None  # attack scenario (overrides protos)
        self.replay: Optional[str] = None    # pcap to replay (overrides all)
        self.sprinkle_on = False             # mix malware into the base traffic
        self.sprinkle_variant = incidents.all_incidents()[0].key
        self.sprinkle_random = False         # random variant + jittered placement
        self.sprinkle_ratio = 0.0            # 0 = natural minority; else target fraction
        self.rate = 20.0
        self.messages = 5
        self.loop = True
        self.pcap: Optional[str] = None
        self.ep = Endpoints()

        self.engine: Optional[Engine] = None
        self.log: List[str] = []
        self.focus = 0                 # index into PANELS
        self.row = 0                   # selected (visible) row within panel
        self.frame = 0                 # animation tick
        self.help_open = False
        self._warned_restart = False
        self._load_service_config()

    # -- helpers -----------------------------------------------------------
    def add_log(self, msg: str):
        self.log.append(f"{time.strftime('%H:%M:%S')} {msg}")
        self.log = self.log[-300:]

    def running(self) -> bool:
        return bool(self.engine and self.engine.is_alive())

    def stats(self):
        return self.engine.stats if self.engine else None

    def refresh(self, force: bool = False):
        """Poll the service and interfaces every 2 s, not every frame."""
        now = time.time()
        if force or now - self._if_poll > 2.0:
            self.svc = service.service_state()
            self.ifaces = {i["name"]: i for i in net.list_interfaces()
                           if i["name"] != "lo"}
            self._if_poll = now

    def iface_state(self, name: Optional[str]) -> Tuple[str, int]:
        if not name:
            return "", C_DIM
        info = self.ifaces.get(name)
        if info is None:
            return "✕ missing", C_RED
        st = info.get("state") or "unknown"
        if st == "up":
            return "● up", C_GREEN
        if st == "unknown":                  # dummy/tun report "unknown"
            return "● unknown", C_YELLOW
        return f"○ {st}", C_YELLOW

    def link_kind(self) -> str:
        """How frames reach the sensor: ``veth`` (a pair on this host),
        ``nic`` (a real interface — a switch/vSwitch SPAN must mirror it),
        ``pcap`` (file only) or ``none`` (nothing mapped yet)."""
        if self.send_iface:
            info = self.ifaces.get(self.send_iface)
            return "veth" if info and info.get("kind") == "veth" else "nic"
        return "pcap" if self.pcap else "none"

    @property
    def mon_iface(self) -> Optional[str]:
        """The veth peer the sensor captures on (None if not a local veth)."""
        info = self.ifaces.get(self.send_iface or "")
        return info.get("peer") if info and info.get("kind") == "veth" else None

    def _load_service_config(self):
        cfg = service.read_config()
        if cfg.get("TGT_IFACE") and not self.send_iface:
            self.send_iface = cfg["TGT_IFACE"]

    # -- mode --------------------------------------------------------------
    def mode(self) -> str:
        return ("replay" if self.replay else "incident" if self.incident else
                "env" if self.env else "scenario" if self.scenario else "custom")

    def _clear_modes(self):
        self.scenario = self.env = self.incident = self.replay = None

    def set_scenario(self, key: Optional[str]):
        self._clear_modes()
        self.scenario = key
        if key:
            self.selected = list(scenarios.get(key).profiles)

    def set_env(self, key: Optional[str]):
        self._clear_modes()
        self.env = key

    def set_incident(self, key: Optional[str]):
        self._clear_modes()
        self.incident = key

    def set_replay(self, path: str):
        self._clear_modes()
        self.replay = path

    def toggle_proto(self, key: str):
        if key in self.selected:
            self.selected.remove(key)
        else:
            self.selected.append(key)
        self._clear_modes()             # manual edit => custom protocols

    def sprinkle_list(self) -> List[str]:
        # random picks from all incidents (variant ignored); else the chosen one
        if self.sprinkle_on and not self.sprinkle_random:
            return [self.sprinkle_variant]
        return []

    def build_config(self) -> RunConfig:
        return RunConfig(
            profiles=list(self.selected) or ["modbus"], env=self.env,
            span=self.span, incident=self.incident,
            sprinkle=self.sprinkle_list(),
            sprinkle_random=self.sprinkle_on and self.sprinkle_random,
            sprinkle_ratio=self.sprinkle_ratio if self.sprinkle_on else 0.0,
            replay_path=self.replay,
            iface=self.send_iface, pcap_path=self.pcap,
            rate=self.rate, messages=self.messages, loop=self.loop,
            endpoints=self.ep)

    def run_args(self) -> str:
        """The same selection as a `tgt run` argument string (for the service)."""
        return service.build_run_args(
            self.scenario, self.selected, self.rate, self.messages,
            env=self.env, incident=self.incident, replay=self.replay,
            sprinkle=self.sprinkle_list() or None,
            sprinkle_random=self.sprinkle_on and self.sprinkle_random,
            sprinkle_ratio=self.sprinkle_ratio if self.sprinkle_on else 0.0,
            span=self.span)

    def start_stop(self):
        if self.running():
            self.engine.stop()
            self.add_log("stop requested")
            return
        if self.mode() == "custom" and not self.selected:
            self.add_log("no protocols selected — pick some on the Traffic tab")
            return
        if not self.send_iface and not self.pcap:
            self.add_log("set a send interface (Interfaces) or a PCAP output "
                         "(Run) first")
            return
        cfg = self.build_config()
        self.add_log(f"start: {cfg.summary()}")
        self._warned_restart = False
        self.engine = Engine(cfg, on_log=self.add_log)
        self.engine.start()

    def changed(self):
        """A setting changed; say once per run that it applies on restart."""
        if self.running() and not self._warned_restart:
            self.add_log("changes apply on the next start (s to stop, s again)")
            self._warned_restart = True


# ── formatting ──────────────────────────────────────────────────────────────
def _fit(text: str, n: int, left: bool = False) -> str:
    """Truncate to n columns with an ellipsis (on the left for paths)."""
    if n <= 0:
        return ""
    if len(text) <= n:
        return text
    if n == 1:
        return "…"
    return "…" + text[-(n - 1):] if left else text[:n - 1] + "…"


def _human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def _clock(sec: float) -> str:
    sec = int(sec)
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


def _onoff(flag: bool, on: str = "on", off: str = "off") -> Tuple[str, int]:
    return (on, C_GREEN) if flag else (off, C_DIM)


# ── safe drawing helpers ────────────────────────────────────────────────────
def _put(win, y, x, text, attr=0):
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x >= w:
        return
    if x < 0:
        text = text[-x:]
        x = 0
    maxw = w - x - (1 if y == h - 1 else 0)
    if maxw <= 0:
        return
    try:
        win.addstr(y, x, text[:maxw], attr)
    except curses.error:
        pass


def _cattr(color: int, extra=0):
    if curses.has_colors():
        return curses.color_pair(color) | extra
    return extra


def _box(win, y, x, h, w, title, color, focused=False):
    if w < 2 or h < 2:
        return
    ca = _cattr(color)
    _put(win, y, x, BOX["tl"] + BOX["h"] * (w - 2) + BOX["tr"], ca)
    _put(win, y + h - 1, x, BOX["bl"] + BOX["h"] * (w - 2) + BOX["br"], ca)
    for i in range(1, h - 1):
        _put(win, y + i, x, BOX["v"], ca)
        _put(win, y + i, x + w - 1, BOX["v"], ca)
    if title:
        tattr = _cattr(color, curses.A_REVERSE if focused else curses.A_BOLD)
        _put(win, y, x + 2, f" {title} ", tattr)


# ── the flow diagram ────────────────────────────────────────────────────────
def _mix(ui: UI, slots: int) -> Tuple[List[Tuple[str, int]], int, int]:
    """(key, count) rows for the engine box, biggest first, plus the number
    hidden and the total. Malware rows are always kept on screen — a thin
    minority is exactly what you are testing for."""
    s = ui.stats()
    counts = dict(s.per_profile) if s and s.per_profile else {}
    total = sum(counts.values())
    if not counts:
        return [], 0, 0
    mal = set(incidents.ATTACKS)
    by_count = sorted(counts, key=lambda k: -counts[k])
    if len(by_count) > slots:
        slots = max(0, slots - 1)                 # room for "+N more"
    keep = ([k for k in by_count if k in mal] +
            [k for k in by_count if k not in mal])[:slots]
    shown = [k for k in by_count if k in keep]
    return [(k, counts[k]) for k in shown], len(by_count) - len(shown), total


def _engine_idle_lines(ui: UI) -> List[Tuple[str, int]]:
    """What the engine box says before anything has been generated."""
    m = ui.mode()
    if m == "env":
        e = enterprise.get(ui.env)
        return [(f"{len(e.hosts)} hosts", C_DIM),
                (f"{len(e.segments)} VLANs", C_DIM),
                (f"{len(e.conversations)} flows", C_DIM)]
    if m == "incident":
        inc = incidents.get(ui.incident)
        return [(f"{inc.name}", C_DIM), (f"{inc.category} · {inc.year}", C_DIM)]
    if m == "replay":
        return [(_fit(os.path.basename(ui.replay), 30), C_DIM)]
    return [(k, C_DIM) for k in ui.selected] or [("no protocols", C_DIM)]


Line = Tuple[str, int]                     # (text, curses attribute)
Node = Tuple[int, str, str, List[Line]]    # (colour, title, short name, lines)
Link = Tuple[str, bool, bool]              # (label, dotted, animated)


def _diagram_height(ui: UI, H: int, top: int, others: int) -> int:
    """Box height: just enough for the engine's content (header, traffic mix
    or idle summary, status) and the tallest other box, capped by the
    terminal."""
    s = ui.stats()
    n = len(s.per_profile) if s and s.per_profile else \
        len(_engine_idle_lines(ui))
    headers = 1 + (ui.sprinkle_on and ui.mode() != "replay")
    want = max(6, headers + n + 1, others) + 2
    return max(7, min(want, 16, H - top - 15))


def _engine_lines(ui: UI, rows: int, inner: int) -> List[Line]:
    """Mode header, malware badge, traffic mix (or idle summary); the status
    line is always the last row."""
    s = ui.stats()
    m = ui.mode()
    head = {"env": (f"env {ui.env}", C_GREEN),
            "incident": (f"☣ {ui.incident}", C_RED),
            "replay": ("⟳ replay", C_YELLOW),
            "scenario": (f"scenario {ui.scenario}", C_CYAN),
            "custom": (f"{len(ui.selected)} protocols", C_CYAN)}[m]
    out: List[Line] = [(head[0], _cattr(head[1], curses.A_BOLD))]
    if ui.sprinkle_on and m != "replay":
        v = "random" if ui.sprinkle_random else ui.sprinkle_variant
        out.append((f"☣ +{v}", _cattr(C_RED, curses.A_BOLD)))
    slots = max(0, rows - len(out) - 1)
    mix, hidden, total = _mix(ui, slots)
    mal = set(incidents.ATTACKS)
    if mix:
        name_w = max(4, inner - 7)
        for k, cnt in mix:
            bad = k in mal
            pct = f"{100 * cnt / total:5.1f}%" if total else ""
            out.append((f"{'☣' if bad else ' '}{_fit(k, name_w):<{name_w}}"
                        f"{pct:>6}", _cattr(C_RED if bad else C_GREEN,
                                            curses.A_BOLD if bad else 0)))
        if hidden:
            out.append((f" +{hidden} more…", _cattr(C_DIM)))
    else:
        out += [(f" {t}", _cattr(c)) for t, c in _engine_idle_lines(ui)[:slots]]
    out = out[:max(0, rows - 1)]
    out += [("", 0)] * (rows - 1 - len(out))
    if ui.running():
        out.append((f"{s.pps:6.1f} pps  {_clock(s.elapsed)}",
                    _cattr(C_GREEN, curses.A_BOLD)))
    else:
        out.append(("idle — press s" if s is None else "stopped",
                    _cattr(C_DIM)))
    return out


def _counter_lines(ui: UI) -> List[Line]:
    s = ui.stats()
    errs = s.errors if s else 0
    out = [(f"{s.packets if s else 0:,} pkts", _cattr(C_CYAN)),
           (f"{_human(s.bytes if s else 0)} {s.mbps if s else 0:.2f}Mb/s",
            _cattr(C_DIM)),
           (f"errors {errs}", _cattr(C_RED if errs else C_DIM,
                                     curses.A_BOLD if errs else 0))]
    if s and s.cycle_frames:
        out.append((f"{s.cycle_frames:,} /cycle", _cattr(C_DIM)))
    return out


def _tagging_lines(ui: UI) -> List[Line]:
    if ui.mode() == "env":
        e = enterprise.get(ui.env)
        out = [(f"SPAN {ui.span}", _cattr(C_YELLOW)),
               (f"{len(e.segments)} VLANs tagged", _cattr(C_DIM))]
        if ui.span == "core":
            out.append(("+ routed hops", _cattr(C_DIM)))
        return out
    return [("untagged", _cattr(C_DIM))]


def _diagram_nodes(ui: UI) -> Tuple[List[Node], List[Link]]:
    """The boxes after the engine, and the links between all boxes, for how
    frames reach the sensor (see :meth:`UI.link_kind`):

    veth  ENGINE ─▶ SEND ─▶ MONITOR (peer) ─▶ SENSOR
    nic   ENGINE ─▶ SEND ┈▶ SENSOR    (a switch / vSwitch SPAN mirrors it)
    pcap  ENGINE ─▶ PCAP ┈▶ SENSOR    (imported offline — never animated)
    """
    kind = ui.link_kind()
    running = ui.running()
    send = ui.send_iface or ""
    pcap = os.path.basename(ui.pcap) if ui.pcap else ""
    label: Line = (ui.sensor_label, _cattr(C_MAGENTA, curses.A_BOLD))
    if kind == "pcap":
        box = [("pcap file", _cattr(C_CYAN, curses.A_BOLD)),
               (pcap, _cattr(C_CYAN))] + _counter_lines(ui)
        sensor = [label, ("imports", _cattr(C_DIM)),
                  (pcap, _cattr(C_MAGENTA))] + _tagging_lines(ui)
        return ([(C_CYAN, "PCAP", pcap, box),
                 (C_MAGENTA, "SENSOR", ui.sensor_label, sensor)],
                [("write", False, running), ("import", True, False)])
    if kind == "none":
        box = [("no interface", _cattr(C_DIM)),
               ("set one or a pcap", _cattr(C_YELLOW))] + _counter_lines(ui)
        return ([(C_CYAN, "SEND", "unmapped", box),
                 (C_MAGENTA, "SENSOR", ui.sensor_label,
                  [label, ("-", _cattr(C_DIM))])],
                [("emit", False, False), ("", True, False)])
    st, col = ui.iface_state(send)
    box = [(send, _cattr(C_CYAN, curses.A_BOLD)),
           (f"{st} · {'veth' if kind == 'veth' else 'interface'}",
            _cattr(col))]
    if pcap:
        box.append(("+ " + pcap, _cattr(C_DIM)))
    box += _counter_lines(ui)
    if kind == "veth":
        peer = ui.mon_iface
        if peer:
            pst, pcol = ui.iface_state(peer)
            mon = [(peer, _cattr(C_YELLOW, curses.A_BOLD)), (pst, _cattr(pcol))]
        else:
            mon = [("peer elsewhere", _cattr(C_YELLOW, curses.A_BOLD)),
                   ("other namespace", _cattr(C_DIM))]
        mon += _tagging_lines(ui)
        sensor = [label, ("listens on", _cattr(C_DIM)),
                  (peer or "the veth peer", _cattr(C_MAGENTA))]
        return ([(C_CYAN, "SEND", send, box),
                 (C_YELLOW, "MONITOR", peer or "peer", mon),
                 (C_MAGENTA, "SENSOR", ui.sensor_label, sensor)],
                [("emit", False, running), ("veth", False, running),
                 ("ingest", False, running and peer is not None)])
    # a real interface: something outside this host must mirror it
    up = ui.iface_state(send)[0].startswith("●")
    sensor = [label, ("gets a SPAN of", _cattr(C_DIM)),
              (send, _cattr(C_MAGENTA))] + _tagging_lines(ui)
    return ([(C_CYAN, "SEND", send, box),
             (C_MAGENTA, "SENSOR", ui.sensor_label, sensor)],
            [("emit", False, running), ("SPAN", True, running and up)])


def _draw_diagram(win, ui: UI, top: int, w: int) -> int:
    H, _ = win.getmaxyx()
    nodes, links = _diagram_nodes(ui)
    n = len(nodes) + 1
    margin, gap = (2, 6) if w >= 100 else (1, 4)
    box_w = (w - 2 * margin - (n - 1) * gap) // n
    if box_w < 16:
        return _draw_strip(win, ui, top, w, nodes, links)
    if box_w > 34:                       # fewer boxes: longer links instead
        box_w = 34
        gap = (w - 2 * margin - n * box_w) // (n - 1)
    bh = _diagram_height(ui, H, top, max(len(nd[3]) for nd in nodes))
    rows, inner = bh - 2, box_w - 2
    boxes = [(C_GREEN, "TGT ENGINE", "ENGINE",
              _engine_lines(ui, rows, inner))] + nodes
    xs = [margin + i * (box_w + gap) for i in range(n)]
    by = top + 1
    mid = by + bh // 2
    for i, (color, title, _short, lines) in enumerate(boxes):
        _box(win, by, xs[i], bh, box_w, title, color)
        for r, (text, attr) in enumerate(lines[:rows]):
            _put(win, by + 1 + r, xs[i] + 1, _fit(text, inner), attr)

    s = ui.stats()
    pps = s.pps if s else 0.0
    for i, (label, dotted, live) in enumerate(links):
        g0 = xs[i] + box_w
        glen = xs[i + 1] - g0
        _put(win, mid, g0, ("┈" if dotted else BOX["h"]) * (glen - 1),
             _cattr(C_DIM))
        _put(win, mid, g0 + glen - 1, ARROW,
             _cattr(C_GREEN if live else C_DIM, curses.A_BOLD if live else 0))
        if live and pps > 0:
            ndots = max(1, min(glen - 2, 1 + int(pps / 15)))
            step = max(1, (glen - 1) // ndots)
            for k in range(ndots):
                pos = (ui.frame + k * step) % (glen - 1)
                _put(win, mid, g0 + pos, DOT, _cattr(C_GREEN, curses.A_BOLD))
        if label and len(label) <= glen:          # skip if it won't fit
            _put(win, mid + 1, g0 + (glen - len(label)) // 2, label,
                 _cattr(C_DIM))
    return by + bh + 1


def _draw_strip(win, ui: UI, top: int, w: int, nodes: List[Node],
                links: List[Link]) -> int:
    """Narrow terminals: the same flow as one line plus a counters line."""
    s = ui.stats()
    x = 2
    parts = [("ENGINE", C_GREEN)]
    for (color, _title, short, _lines), (_l, dotted, _a) in zip(nodes, links):
        parts += [(" ┈▶ " if dotted else " ━▶ ", C_DIM), (short, color)]
    for text, col in parts:
        _put(win, top + 1, x, text, _cattr(col, curses.A_BOLD))
        x += len(text)
    if s:
        info = (f"{s.packets:,} pkts · {s.pps:.1f} pps · {_human(s.bytes)} · "
                f"errors {s.errors}")
    else:
        info = "idle — press s to start"
    _put(win, top + 2, 2, _fit(info, w - 4),
         _cattr(C_GREEN if ui.running() else C_DIM))
    return top + 4


# ── panel model ─────────────────────────────────────────────────────────────
class Field:
    """One row of a panel: a label, a live value, what the keys do, help."""

    def __init__(self, label: str, value: Callable[[UI], Value],
                 act: Optional[Callable] = None, help: Union[str, Callable] = "",
                 show: Optional[Callable[[UI], bool]] = None,
                 toggle: bool = False, keys: str = "",
                 space: Optional[Callable] = None):
        self.label = label
        self.value = value
        self.act = act                  # act(stdscr, ui, step): step -1/+1/0
        self._help = help
        self.show = show or (lambda ui: True)
        self.toggle = toggle            # Space activates it
        self.space = space              # or does this instead
        self.keys = keys or ("Space toggle" if toggle else
                             "Enter run" if act else "")

    def help(self, ui: UI) -> str:
        return self._help(ui) if callable(self._help) else self._help


def _cycle(seq: list, cur, step: int):
    try:
        i = seq.index(cur)
    except ValueError:
        i = -1 if step >= 0 else 0
    return seq[(i + (step or 1)) % len(seq)]


# -- Run panel ---------------------------------------------------------------
def _preset_value(ui: UI) -> Value:
    m = ui.mode()
    if m == "replay":
        return f"⟳ replay {os.path.basename(ui.replay)}", C_YELLOW
    if m == "incident":
        return f"☣ incident: {ui.incident}", C_RED
    if m == "env":
        return f"env: {ui.env}", C_GREEN
    if m == "scenario":
        return f"scenario: {ui.scenario}", C_CYAN
    return f"custom mix ({len(ui.selected)} protocols)", 0


def _preset_items(ui: UI) -> list:
    items = [("Custom", ("c", None), "custom protocol mix",
              f"Your own selection on the Traffic tab "
              f"({len(ui.selected)} selected).")]
    items += [("Scenarios", ("s", s.key), f"{s.key:16} {s.name}",
               f"{s.desc}  [{', '.join(s.profiles)}]")
              for s in scenarios.all_scenarios()]
    items += [("Environments", ("e", e.key), f"{e.key:16} {e.name}",
               f"{e.desc}  ({e.summary()})")
              for e in enterprise.all_environments()]
    items += [("Incidents", ("i", x.key), f"{x.key:16} {x.name} ({x.year})",
               f"{x.desc}  Signals: {'; '.join(x.indicators())}")
              for x in incidents.all_incidents()]
    items += [("Replay", ("r", None), "replay a pcap file…",
               "Send the frames of an existing capture instead of "
               "generating traffic.")]
    return items


def _current_preset(ui: UI):
    m = ui.mode()
    return {"env": ("e", ui.env), "incident": ("i", ui.incident),
            "scenario": ("s", ui.scenario), "replay": ("r", None),
            "custom": ("c", None)}[m]


def _apply_preset(stdscr, ui: UI, choice):
    kind, key = choice
    if kind == "r":
        path = _prompt(stdscr, "Replay pcap path", ui.replay or "")
        if path and os.path.exists(path):
            ui.set_replay(path)
            ui.add_log(f"replay: {path}")
        elif path:
            ui.add_log(f"replay file not found: {path}")
        return
    {"i": ui.set_incident, "e": ui.set_env, "s": ui.set_scenario}.get(
        kind, lambda k: ui._clear_modes())(key)


def _act_preset(stdscr, ui: UI, step: int):
    if step == 0:
        choice = _pick(stdscr, "Preset — base traffic", _preset_items(ui),
                       _current_preset(ui))
        if choice is not None:
            _apply_preset(stdscr, ui, choice)
        return
    opts = [it[1] for it in _preset_items(ui) if it[1][0] != "r"]
    _apply_preset(stdscr, ui, _cycle(opts, _current_preset(ui), step))


def _act_span(stdscr, ui: UI, step: int):
    ui.span = "core" if ui.span == "access" else "access"


def _act_sprinkle(stdscr, ui: UI, step: int):
    ui.sprinkle_on = not ui.sprinkle_on
    ui.add_log(f"malware sprinkle "
               f"{'ON: ' + ui.sprinkle_variant if ui.sprinkle_on else 'off'}")


def _variant_items() -> list:
    return [(x.category, x.key, f"{x.key:14} {x.name} ({x.year})",
             f"{x.desc}  Signals: {'; '.join(x.indicators())}")
            for x in incidents.all_incidents()]


def _act_variant(stdscr, ui: UI, step: int):
    if step == 0:
        v = _pick(stdscr, "Malware to sprinkle", _variant_items(),
                  ui.sprinkle_variant)
        if v is None:
            return
    else:
        v = _cycle([x.key for x in incidents.all_incidents()],
                   ui.sprinkle_variant, step)
    ui.sprinkle_variant = v
    ui.sprinkle_random = False


def _act_random(stdscr, ui: UI, step: int):
    ui.sprinkle_random = not ui.sprinkle_random


def _act_ratio(stdscr, ui: UI, step: int):
    if step:
        steps = RATIO_STEPS
        cur = min(steps, key=lambda r: abs(r - ui.sprinkle_ratio))
        i = max(0, min(len(steps) - 1, steps.index(cur) + step))
        ui.sprinkle_ratio = steps[i]
        return
    v = _prompt(stdscr, "Malware fraction 0–0.9 (0 = natural minority)",
                f"{ui.sprinkle_ratio:g}")
    try:
        ui.sprinkle_ratio = min(0.9, max(0.0, float(v)))
    except (TypeError, ValueError):
        ui.add_log(f"not a number: {v}")


def _act_rate(stdscr, ui: UI, step: int):
    if step:
        steps = RATE_STEPS
        cur = 0 if ui.rate == 0 else min(steps[:-1],
                                         key=lambda r: abs(r - ui.rate))
        i = max(0, min(len(steps) - 1, steps.index(cur) + step))
        ui.rate = float(steps[i])
        return
    v = _prompt(stdscr, "Packets per second (0 = as fast as possible)",
                f"{ui.rate:g}")
    try:
        ui.rate = max(0.0, float(v))
    except (TypeError, ValueError):
        ui.add_log(f"not a number: {v}")


def _act_msgs(stdscr, ui: UI, step: int):
    if step:
        ui.messages = max(1, ui.messages + step)
        return
    v = _prompt(stdscr, "Protocol exchanges per flow per cycle",
                str(ui.messages))
    try:
        ui.messages = max(1, int(v))
    except (TypeError, ValueError):
        ui.add_log(f"not a whole number: {v}")


def _act_loop(stdscr, ui: UI, step: int):
    ui.loop = not ui.loop


def _act_pcap(stdscr, ui: UI, step: int):
    v = _prompt(stdscr, "Write frames to this pcap (blank = off)",
                ui.pcap or "tgt-out.pcap")
    ui.pcap = v if v and v != "(off)" else None


def _act_pcap_off(stdscr, ui: UI, step: int):
    """Space: switch the pcap output off, or ask for a path when it is off."""
    if ui.pcap:
        ui.pcap = None
    else:
        _act_pcap(stdscr, ui, 0)


def _ip_prompt(stdscr, ui: UI, label: str, cur: str) -> str:
    v = _prompt(stdscr, label, cur) or cur
    try:
        ipaddress.ip_address(v)
        return v
    except ValueError:
        ui.add_log(f"not an IPv4 address: {v}")
        return cur


def _act_client(stdscr, ui: UI, step: int):
    ui.ep.client_ip = _ip_prompt(stdscr, ui, "Client IP", ui.ep.client_ip)


def _act_server(stdscr, ui: UI, step: int):
    ui.ep.server_ip = _ip_prompt(stdscr, ui, "Server IP", ui.ep.server_ip)


def _manual(ui: UI) -> bool:
    return ui.mode() in ("custom", "scenario")


def _sprinkle_detail(ui: UI) -> bool:
    return ui.sprinkle_on and ui.mode() != "replay"


RUN_FIELDS = [
    Field("Preset", _preset_value, _act_preset,
          "Base traffic: a protocol mix, a scenario, a modeled environment "
          "(hosts, VLANs, fingerprints), an incident, or a pcap replay.",
          keys="Enter pick · ←→ cycle"),
    Field("SPAN view",
          lambda ui: (f"‹ {ui.span} ›", C_CYAN), _act_span,
          "Where the sensor taps the environment: access = each frame once, on "
          "its sender's VLAN; core = also the router's copy on the receiver's "
          "VLAN (gateway MAC, TTL-1).",
          show=lambda ui: ui.mode() == "env", toggle=True,
          keys="←→/Space switch"),
    Field("Malware sprinkle",
          lambda ui: _onoff(ui.sprinkle_on, "☣ ON", "off"), _act_sprinkle,
          "Mix an attack into the base traffic as a thin minority. On an "
          "environment, its hosts are re-addressed onto real assets of the same "
          "role and vendor.",
          show=lambda ui: ui.mode() != "replay", toggle=True),
    Field("  variant",
          lambda ui: (incidents.get(ui.sprinkle_variant).name, C_RED),
          _act_variant, "Which incident to sprinkle.",
          show=lambda ui: _sprinkle_detail(ui) and not ui.sprinkle_random,
          keys="Enter pick · ←→ cycle"),
    Field("  random pick", lambda ui: _onoff(ui.sprinkle_random), _act_random,
          "Pick a random incident each cycle and jitter where it lands.",
          show=_sprinkle_detail, toggle=True),
    Field("  ratio",
          lambda ui: (f"{ui.sprinkle_ratio:.0%}" if ui.sprinkle_ratio > 0
                      else "natural minority"),
          _act_ratio,
          "Target malware fraction of all frames. 0 = one natural cycle per "
          "variant (a few percent).",
          show=_sprinkle_detail, keys="←→ step · Enter type"),
    Field("Rate",
          lambda ui: f"{ui.rate:g} pps" if ui.rate else ("max", C_YELLOW),
          _act_rate, "Packets per second (0 = as fast as the system allows).",
          keys="←→ step · Enter type"),
    Field("Messages / flow", lambda ui: str(ui.messages), _act_msgs,
          "Protocol exchanges in each flow per cycle. Larger = longer sessions "
          "and a bigger cycle.", keys="←→ ±1 · Enter type"),
    Field("Loop", lambda ui: _onoff(ui.loop, "repeat", "one cycle"), _act_loop,
          "Rebuild and resend continuously, or send one cycle and stop.",
          toggle=True),
    Field("PCAP output",
          lambda ui: (ui.pcap, C_CYAN) if ui.pcap else ("off", C_DIM),
          _act_pcap,
          "Also (or only) write every frame to a pcap file — no root needed. "
          "Space switches it off.",
          keys="Enter path · Space on/off", space=_act_pcap_off),
    Field("Client IP", lambda ui: ui.ep.client_ip, _act_client,
          "Client address for a custom mix or scenario (environments and "
          "incidents bring their own hosts).", show=_manual, keys="Enter edit"),
    Field("Server IP", lambda ui: ui.ep.server_ip, _act_server,
          "Server address for a custom mix or scenario.", show=_manual,
          keys="Enter edit"),
]


# -- Traffic panel -----------------------------------------------------------
def _traffic_fields(ui: UI) -> List[Field]:
    s = ui.stats()
    fields = []
    for prof in protocols.all_profiles():
        def value(ui, prof=prof):
            cnt = s.per_profile.get(prof.key, 0) if s else 0
            port = f"{prof.port}/{prof.transport}" if prof.port != "-" \
                else prof.transport
            text = f"{prof.category}  {port:<10} {cnt:>7,}" if cnt else \
                f"{prof.category}  {port}"
            return text, (C_GREEN if prof.key in ui.selected else C_DIM)

        def act(stdscr, ui, step, prof=prof):
            ui.toggle_proto(prof.key)

        def help_(ui, prof=prof):
            note = ("" if ui.mode() == "custom" else
                    "  (Toggling switches the preset to a custom mix.)")
            return f"{prof.name} — {prof.desc}.{note}"

        mark = "◉" if prof.key in ui.selected else "○"
        fields.append(Field(f"{mark} {prof.key}", value, act, help_,
                            toggle=True, keys="Space/Enter toggle"))
    return fields


# -- Interfaces panel --------------------------------------------------------
def _act_send(stdscr, ui: UI, step: int):
    opts = [None] + [n for n in ui.ifaces if not n.endswith("-mon")]
    ui.send_iface = _cycle(opts, ui.send_iface, step)


def _act_sensor(stdscr, ui: UI, step: int):
    ui.sensor_label = _prompt(stdscr, "Sensor label",
                              ui.sensor_label) or ui.sensor_label


def _act_create(stdscr, ui: UI, step: int):
    name = _prompt(stdscr, "New veth pair name (peer gets -mon)",
                   ui.send_iface or "tgt0")
    if not name:
        return
    ui.add_log(f"creating veth {name} <-> {name}-mon …")
    res = net.create_veth(name)
    for ln in res.log:
        ui.add_log(ln)
    ui.refresh(force=True)
    if res.ok:
        ui.send_iface = name


def _act_delete(stdscr, ui: UI, step: int):
    name = ui.send_iface
    if not name:
        ui.add_log("no send interface selected")
        return
    typed = _prompt(stdscr, f"Type '{name}' to delete it (and its peer)", "")
    if typed != name:
        ui.add_log("delete cancelled")
        return
    res = net.delete_interface(name)
    for ln in res.log:
        ui.add_log(ln)
    ui.refresh(force=True)
    if res.ok:
        ui.send_iface = None


def _iface_value(ui: UI) -> Value:
    if not ui.send_iface:
        return "none — pcap only", C_DIM
    st, col = ui.iface_state(ui.send_iface)
    return f"{ui.send_iface}  {st}", col


def _link_value(ui: UI) -> Value:
    if ui.link_kind() == "veth":
        return ((f"veth pair ↔ {ui.mon_iface}", C_GREEN) if ui.mon_iface
                else ("veth, peer in another namespace", C_GREEN))
    return "real interface — needs a SPAN", C_YELLOW


def _link_help(ui: UI) -> str:
    if ui.link_kind() == "veth":
        return ("A virtual cable on this host: the sensor captures on the peer. "
                "It must share this kernel — this host, a container, or a "
                "network namespace.")
    return ("Frames leave this interface for real. The sensor sees them only if "
            "a switch or hypervisor port mirror copies this port or VLAN to "
            "its monitor port (README: 'Sensor on another machine or VM').")


IFACE_FIELDS = [
    Field("Send interface", _iface_value, _act_send,
          "Where TGT transmits (needs root/CAP_NET_RAW): a veth for a sensor on "
          "this host, or a real interface a SPAN mirrors to the sensor. With "
          "none, use a PCAP output on the Run tab.", keys="←→/Enter cycle"),
    Field("Link to sensor", _link_value, None, _link_help,
          show=lambda ui: bool(ui.send_iface)),
    Field("Monitor (peer)",
          lambda ui: ((f"{ui.mon_iface}  {ui.iface_state(ui.mon_iface)[0]}",
                       ui.iface_state(ui.mon_iface)[1]) if ui.mon_iface
                      else ("none", C_DIM)),
          None, "The veth peer your sensor listens on: every frame sent on the "
          "send interface appears here.",
          show=lambda ui: ui.link_kind() == "veth"),
    Field("Sensor label", lambda ui: ui.sensor_label, _act_sensor,
          "Name shown in the SENSOR box (e.g. Claroty CTD, Zeek, Suricata).",
          keys="Enter edit"),
    Field("Create veth pair", lambda ui: ("press Enter", C_DIM), _act_create,
          "Create <name> and <name>-mon (needs iproute2 and sudo)."),
    Field("Delete veth pair", lambda ui: ("press Enter", C_DIM), _act_delete,
          "Delete the veth pair (both ends). Asks you to type the name. Real "
          "interfaces are never offered for deletion.",
          show=lambda ui: ui.link_kind() == "veth"),
]


# -- Service panel -----------------------------------------------------------
def _act_save(stdscr, ui: UI, step: int):
    ok, msg = service.write_config(ui.send_iface or "tgt0", ui.run_args())
    ui.add_log(("saved: " if ok else "error: ") + msg)


def _svc(action: str):
    def act(stdscr, ui: UI, step: int):
        ui.add_log(f"service {action} …")
        ok, msg = service.service_action(action)
        ui.add_log(("service " if ok else "service FAILED: ") + msg)
        ui.refresh(force=True)
    return act


def _svc_value(ui: UI) -> Value:
    st = ui.svc
    col = {"active": C_GREEN, "failed": C_RED}.get(st.status, C_DIM)
    return f"{st.status} ({st.mode})", col


SERVICE_FIELDS = [
    Field("Status", _svc_value, None,
          "The background service runs `tgt run` from the saved config, and "
          "survives logout/reboot."),
    Field("Would run", lambda ui: ui.run_args(), None,
          lambda ui: f"tgt run -i {ui.send_iface or 'tgt0'} {ui.run_args()}"),
    Field("Config file", lambda ui: (service.CONF_PATH, C_DIM), None,
          lambda ui: service.CONF_PATH),
    Field("Save config", lambda ui: ("press Enter", C_DIM), _act_save,
          "Write the current Run/Traffic selection as the service's config."),
    Field("Start service", lambda ui: ("press Enter", C_DIM), _svc("start"),
          "Start the background service."),
    Field("Stop service", lambda ui: ("press Enter", C_DIM), _svc("stop"),
          "Stop the background service."),
    Field("Restart service", lambda ui: ("press Enter", C_DIM),
          _svc("restart"), "Restart it to pick up a newly saved config."),
]


def _fields(ui: UI) -> List[Field]:
    """Visible rows of the focused panel."""
    p = PANELS[ui.focus]
    fields = {"Run": RUN_FIELDS, "Interfaces": IFACE_FIELDS,
              "Service": SERVICE_FIELDS}.get(p) or _traffic_fields(ui)
    return [f for f in fields if f.show(ui)]


def _context(ui: UI) -> Optional[Tuple[str, int]]:
    """One line under the tabs describing what the preset will generate."""
    if PANELS[ui.focus] == "Traffic":
        return (f"{len(ui.selected)} of {len(protocols.PROFILES)} selected"
                + ("" if ui.mode() == "custom" else
                   f" — preset is {ui.mode()}"), C_DIM)
    if PANELS[ui.focus] != "Run":
        return None
    m = ui.mode()
    if m == "env":
        e = enterprise.get(ui.env)
        return (f"{len(e.hosts)} hosts · {len(e.segments)} VLANs · "
                f"{len(e.conversations)} flows · {len(e.legacy_hosts())} at-risk",
                C_GREEN)
    if m == "incident":
        inc = incidents.get(ui.incident)
        return f"{inc.name} ({inc.year}) · {len(inc.hosts)} hosts", C_RED
    if m == "scenario":
        return ", ".join(scenarios.get(ui.scenario).profiles), C_CYAN
    if m == "replay":
        return ui.replay, C_YELLOW
    return (", ".join(ui.selected) or "nothing selected — see Traffic"), C_DIM


def _tab_label(ui: UI, name: str, short: bool = False) -> str:
    if short:
        return {"Interfaces": "Ifaces"}.get(name, name)
    if name == "Traffic":
        return f"Traffic {len(ui.selected)}"
    return name


def _draw_panel(win, ui: UI, y0, x0, h, w):
    short = sum(len(_tab_label(ui, n)) + 3 for n in PANELS) > w
    tx = x0
    for i, name in enumerate(PANELS):
        active = i == ui.focus
        label = f" {_tab_label(ui, name, short)} "
        _put(win, y0, tx, _fit(label, x0 + w - tx),
             _cattr(C_CYAN, curses.A_REVERSE) if active else _cattr(C_DIM))
        tx += len(label) + 1

    fields = _fields(ui)
    ui.row = max(0, min(ui.row, len(fields) - 1))
    top = y0 + 1
    ctx = _context(ui)
    if ctx:
        _put(win, top, x0, _fit(ctx[0], w), _cattr(ctx[1]))
    top += 1

    help_text = fields[ui.row].help(ui) if fields else ""
    # rows first; help gets what's left (1-4 lines, ellipsis if cut short)
    wrapped = textwrap.wrap(help_text, max(10, w - 2))
    room = max(1, min(4, h - 3 - len(fields) - 1))
    help_lines = wrapped[:room]
    if len(wrapped) > room:
        help_lines[-1] = _fit(help_lines[-1] + " …", w - 2)
    avail = max(1, h - 3 - len(help_lines))
    shown_rows = min(len(fields), avail)
    start = max(0, ui.row - avail + 1)
    label_w = 18
    for idx in range(start, min(len(fields), start + avail)):
        f = fields[idx]
        yy = top + (idx - start)
        sel = idx == ui.row
        val = f.value(ui)
        text, col = (val if isinstance(val, tuple) else (val, 0))
        shown = _fit(text, w - label_w - 3, left=f.label == "PCAP output")
        if sel:
            _put(win, yy, x0, f"▸ {f.label:<{label_w}} {shown}".ljust(w),
                 _cattr(C_CYAN, curses.A_REVERSE))
        else:
            _put(win, yy, x0, f"  {f.label:<{label_w}}", curses.A_BOLD)
            _put(win, yy, x0 + label_w + 3, shown, _cattr(col) if col else 0)
    if len(fields) > avail:
        more = len(fields) - start - avail
        if more > 0:
            _put(win, top + avail - 1, x0 + w - 8, f"↓ {more} more",
                 _cattr(C_DIM))
    for j, ln in enumerate(help_lines):
        _put(win, top + shown_rows + 1 + j, x0 + 1, ln, _cattr(C_DIM))


def _log_color(msg: str) -> int:
    low = msg.lower()
    if any(w in low for w in ("error", "cannot", "failed", "not found",
                              "not a ")):
        return C_RED
    if "malware" in low or "☣" in msg:
        return C_YELLOW
    if low.startswith(("start", "done", "saved", "built", "replaying",
                       "writing")):
        return C_GREEN
    return 0


def _draw_log(win, ui: UI, y0, x0, h, w):
    _put(win, y0, x0, "─ Log ", _cattr(C_BLUE, curses.A_BOLD))
    lines: List[Tuple[str, str, int]] = []
    for entry in ui.log[-(h * 2):]:
        ts, _, msg = entry.partition(" ")
        wrapped = textwrap.wrap(msg, max(10, w - len(ts) - 2)) or [""]
        col = _log_color(msg)
        for k, part in enumerate(wrapped):
            lines.append((ts if k == 0 else "", part, col))
    for j, (ts, part, col) in enumerate(lines[-(h - 1):]):
        _put(win, y0 + 1 + j, x0, ts, _cattr(C_DIM))
        _put(win, y0 + 1 + j, x0 + 9, part, _cattr(col) if col else 0)


# ── modal inputs ────────────────────────────────────────────────────────────
def _prompt(stdscr, label: str, default: str = "") -> Optional[str]:
    curses.echo()
    curses.curs_set(1)
    h, w = stdscr.getmaxyx()
    width = max(30, min(w - 4, 100))
    win = curses.newwin(3, width, h // 2 - 1, (w - width) // 2)
    win.box()
    hint = f" {label}  [Enter = {default}] " if default else f" {label} "
    _put(win, 0, 2, _fit(hint, width - 4), _cattr(C_CYAN, curses.A_BOLD))
    _put(win, 1, 2, "> ")
    win.refresh()
    try:
        raw = win.getstr(1, 4, width - 6)
        val = raw.decode(errors="ignore").strip()
    except Exception:
        val = ""
    curses.noecho()
    curses.curs_set(0)
    return val or (default or None)


def _best_match(items: list, query: str) -> int:
    """Index (among the filtered items) of the best hit for ``query``: a label
    starting with it, then a label containing it, then only the description.
    Display order stays grouped; this only decides where the cursor lands."""
    q = query.lower()
    shown = [it for it in items if q in f"{it[0]} {it[2]} {it[3]}".lower()]
    if not q or not shown:
        return 0

    def rank(it):
        label = it[2].lower().strip()
        return 0 if label.startswith(q) else 1 if q in label else 2
    return min(range(len(shown)), key=lambda i: (rank(shown[i]), i))


def _pick(stdscr, title: str, items: list, current=None):
    """Modal list: items are (group, value, label, description). Type to
    filter, ↑↓ to move, Enter to choose, Esc to cancel. Returns the value, or
    None on cancel."""
    H, W = stdscr.getmaxyx()
    width = min(W - 4, 96)
    height = min(H - 2, 30)
    win = curses.newwin(height, width, (H - height) // 2, (W - width) // 2)
    win.keypad(True)
    query = ""
    sel = next((i for i, it in enumerate(items) if it[1] == current), 0)
    while True:
        shown = [it for it in items if query.lower() in
                 f"{it[0]} {it[2]} {it[3]}".lower()]
        sel = max(0, min(sel, len(shown) - 1))
        # display lines: group headers + items
        disp: List[Tuple[Optional[int], str]] = []
        last = None
        for i, it in enumerate(shown):
            if it[0] != last:
                disp.append((None, it[0]))
                last = it[0]
            disp.append((i, it[2]))
        desc_lines = (textwrap.wrap(shown[sel][3], width - 4)[:3]
                      if shown else ["no match"])
        list_h = height - 5 - len(desc_lines)
        cur_line = next((j for j, (i, _) in enumerate(disp) if i == sel), 0)
        first = max(0, min(cur_line - list_h // 2, len(disp) - list_h))
        win.erase()
        win.attron(_cattr(C_CYAN))
        win.box()
        win.attroff(_cattr(C_CYAN))
        _put(win, 0, 2, f" {title} ", _cattr(C_CYAN, curses.A_BOLD))
        _put(win, 1, 2, f"filter: {query}▏", _cattr(C_YELLOW))
        for j, (i, text) in enumerate(disp[first:first + list_h]):
            y = 2 + j
            if i is None:
                _put(win, y, 2, text.upper(), _cattr(C_DIM, curses.A_BOLD))
            elif i == sel:
                _put(win, y, 3, _fit(f"▸ {text}", width - 6).ljust(width - 6),
                     _cattr(C_CYAN, curses.A_REVERSE))
            else:
                _put(win, y, 3, _fit(f"  {text}", width - 6))
        _put(win, height - 2 - len(desc_lines), 2, "─" * (width - 4),
             _cattr(C_DIM))
        for j, ln in enumerate(desc_lines):
            _put(win, height - 1 - len(desc_lines) + j, 2, ln, _cattr(C_DIM))
        _put(win, height - 1, 2, " type to filter · ↑↓ move · Enter choose · "
             "Esc cancel ", _cattr(C_CYAN))
        win.refresh()
        c = win.getch()
        if c in (27,):
            return None
        if c in (curses.KEY_ENTER, 10, 13):
            return shown[sel][1] if shown else None
        if c in (curses.KEY_UP,):
            sel = (sel - 1) % max(1, len(shown))
        elif c in (curses.KEY_DOWN, 9):
            sel = (sel + 1) % max(1, len(shown))
        elif c in (curses.KEY_BACKSPACE, 127, 8):
            query = query[:-1]
            sel = _best_match(items, query)
        elif 32 <= c < 127:
            query += chr(c)
            sel = _best_match(items, query)


def _draw_help(stdscr):
    H, W = stdscr.getmaxyx()
    lines = [
        ("Keys", None),
        ("Tab / Shift-Tab", "next / previous panel"),
        ("↑ ↓  (j k)", "move between rows"),
        ("← →", "change the value (cycle, step, switch)"),
        ("Enter", "pick from a list, type a value, or run the action"),
        ("Space", "toggle on/off rows and protocols"),
        ("s", "start / stop generating"),
        ("c", "clear the log"),
        ("?", "this help"),
        ("q", "quit (stops the engine)"),
        ("", ""),
        ("Panels", None),
        ("Run", "preset, SPAN view, malware sprinkle, rate, pcap output"),
        ("Traffic", "the protocol mix for a custom preset"),
        ("Interfaces", "send interface, its -mon peer, the sensor"),
        ("Service", "save the selection and run it in the background"),
        ("", ""),
        ("Tip", "send on <name>, point the sensor at <name>-mon"),
    ]
    width = min(W - 4, 84)
    height = min(H - 2, len(lines) + 4)
    win = curses.newwin(height, width, (H - height) // 2, (W - width) // 2)
    win.attron(_cattr(C_CYAN))
    win.box()
    win.attroff(_cattr(C_CYAN))
    _put(win, 0, 2, " TGT help ", _cattr(C_CYAN, curses.A_BOLD))
    for j, (k, v) in enumerate(lines[:height - 3]):
        if v is None:
            _put(win, 1 + j, 2, k.upper(), _cattr(C_YELLOW, curses.A_BOLD))
        else:
            _put(win, 1 + j, 3, f"{k:<16}", curses.A_BOLD)
            _put(win, 1 + j, 20, _fit(v, width - 23))
    _put(win, height - 1, 2, " any key closes ", _cattr(C_CYAN))
    win.refresh()


# ── actions ─────────────────────────────────────────────────────────────────
def _activate(stdscr, ui: UI, step: int):
    fields = _fields(ui)
    if not fields:
        return
    f = fields[ui.row]
    if f.act is None:
        return
    f.act(stdscr, ui, step)
    if PANELS[ui.focus] in ("Run", "Traffic"):
        ui.changed()
    # keep the cursor on the same field if rows appeared/disappeared
    after = _fields(ui)
    labels = [g.label for g in after]
    key = f.label if PANELS[ui.focus] != "Traffic" else f.label[2:]
    for i, lab in enumerate(labels):
        if (lab if PANELS[ui.focus] != "Traffic" else lab[2:]) == key:
            ui.row = i
            break


# ── main render + loop ───────────────────────────────────────────────────────
def _draw(stdscr, ui: UI):
    stdscr.erase()
    h, w = stdscr.getmaxyx()
    if w < 60 or h < 20:
        _put(stdscr, 0, 0, "Terminal too small — need at least 60x20.")
        stdscr.refresh()
        return

    # title bar: name · state · elapsed
    _put(stdscr, 0, 0, " TGT · Traffic Generation Toolkit".ljust(w),
         _cattr(C_CYAN, curses.A_REVERSE))
    s = ui.stats()
    if ui.running():
        word, col = f"● GENERATING {_clock(s.elapsed)}", C_GREEN
    elif s and s.packets:
        word, col = f"■ stopped · {s.packets:,} sent", C_YELLOW
    else:
        word, col = "○ idle", C_DIM
    _put(stdscr, 0, w - len(word) - 2, word,
         _cattr(col, curses.A_BOLD | curses.A_REVERSE))

    # system line + malware badge
    e = ui.sys
    sysline = (f"{e.kind} · {'root' if e.is_root else 'no root (live send needs sudo)'}"
               f" · iproute2 {'✓' if e.has_ip else '✗'} · service {ui.svc.status}")
    _put(stdscr, 1, 2, sysline, _cattr(C_DIM))
    if ui.sprinkle_on and ui.mode() != "replay":
        variant = "random" if ui.sprinkle_random else ui.sprinkle_variant
        pct = f" @{ui.sprinkle_ratio:.0%}" if ui.sprinkle_ratio > 0 else ""
        mal = f" ☣ malware: {variant}{pct} "
        _put(stdscr, 1, w - len(mal) - 2, mal,
             _cattr(C_RED, curses.A_BOLD | curses.A_REVERSE))

    panel_top = _draw_diagram(stdscr, ui, 2, w)

    lower_h = h - panel_top - 1
    if lower_h >= 4:
        split = max(40, w * 52 // 100)
        _draw_panel(stdscr, ui, panel_top, 2, lower_h, split - 4)
        for yy in range(panel_top, h - 1):
            _put(stdscr, yy, split - 1, BOX["v"], _cattr(C_DIM))
        _draw_log(stdscr, ui, panel_top, split + 1, lower_h, w - split - 2)

    # key bar: what the keys do on this row
    fields = _fields(ui)
    hint = fields[ui.row].keys if fields and ui.row < len(fields) else ""
    keys = " · ".join(x for x in (
        "Tab panel", "↑↓ move", hint,
        f"s {'stop' if ui.running() else 'start'}", "? help", "q quit") if x)
    _put(stdscr, h - 1, 0, (" " + keys).ljust(w)[:w - 1],
         _cattr(C_CYAN, curses.A_REVERSE))
    stdscr.refresh()
    if ui.help_open:
        _draw_help(stdscr)


def _init_colors():
    if not curses.has_colors():
        return
    curses.start_color()
    try:
        curses.use_default_colors()
        bg = -1
    except curses.error:
        bg = curses.COLOR_BLACK
    curses.init_pair(C_CYAN, curses.COLOR_CYAN, bg)
    curses.init_pair(C_GREEN, curses.COLOR_GREEN, bg)
    curses.init_pair(C_YELLOW, curses.COLOR_YELLOW, bg)
    curses.init_pair(C_MAGENTA, curses.COLOR_MAGENTA, bg)
    curses.init_pair(C_RED, curses.COLOR_RED, bg)
    curses.init_pair(C_BLUE, curses.COLOR_BLUE, bg)
    curses.init_pair(C_DIM, curses.COLOR_WHITE, bg)


def _handle_key(stdscr, ui: UI, c: int) -> bool:
    """Apply one keypress. Returns False when the UI should exit."""
    if ui.help_open:
        ui.help_open = False
        return True
    fields = _fields(ui)
    if c == 9:                                         # Tab
        ui.focus = (ui.focus + 1) % len(PANELS)
        ui.row = 0
    elif c == curses.KEY_BTAB:                         # Shift-Tab
        ui.focus = (ui.focus - 1) % len(PANELS)
        ui.row = 0
    elif c in (curses.KEY_UP, ord('k')):
        ui.row = (ui.row - 1) % max(1, len(fields))
    elif c in (curses.KEY_DOWN, ord('j')):
        ui.row = (ui.row + 1) % max(1, len(fields))
    elif c == curses.KEY_LEFT:
        _activate(stdscr, ui, -1)
    elif c == curses.KEY_RIGHT:
        _activate(stdscr, ui, +1)
    elif c in (curses.KEY_ENTER, 10, 13):
        _activate(stdscr, ui, 0)
    elif c == ord(' ') and fields:
        f = fields[ui.row]
        if f.space:
            f.space(stdscr, ui, 0)
            if PANELS[ui.focus] in ("Run", "Traffic"):
                ui.changed()
        elif f.toggle:
            _activate(stdscr, ui, 0)
    elif c == ord('?'):
        ui.help_open = True
    elif c == ord('s'):
        ui.start_stop()
    elif c == ord('c'):
        ui.log.clear()
    elif c == ord('q'):
        return False
    return True


def _loop(stdscr):
    curses.curs_set(0)
    _init_colors()
    stdscr.nodelay(True)
    stdscr.timeout(90)                 # ~11 fps animation
    ui = UI()
    ui.add_log("welcome — pick a preset on Run, set an interface or pcap, "
               "press s (? for help)")

    while True:
        ui.frame += 1
        ui.refresh()
        try:
            _draw(stdscr, ui)
        except curses.error:
            pass
        c = stdscr.getch()
        if c == -1:
            continue
        if not _handle_key(stdscr, ui, c):
            if ui.running():
                ui.engine.stop()
                ui.engine.join(timeout=2)
            break
        stdscr.nodelay(True)
        stdscr.timeout(90)


def run() -> int:
    curses.wrapper(_loop)
    return 0
