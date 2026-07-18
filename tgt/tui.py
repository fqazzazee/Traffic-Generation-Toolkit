"""TGT text UI — a live SPAN traffic-flow diagram you can navigate and drive.

The centrepiece is the flow diagram:

    TGT ENGINE ─▶ tgt0 (send) ┈▶ tgt0-mon (monitor) ─▶ SENSOR

Packets animate along the veth path in real time while it generates. Four tabbed
panels below the diagram let you map interfaces, toggle protocols, edit run
settings, and control the persistent background service — all from one screen.

Pure curses, no dependencies. Works over SSH and inside WSL/Podman terminals.
"""
from __future__ import annotations

import curses
import time
from typing import List, Optional

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

PANELS = ["Map", "Protocols", "Settings", "Service"]


# ── state ───────────────────────────────────────────────────────────────────
class UI:
    def __init__(self):
        ifaces = [i["name"] for i in net.list_interfaces()
                  if i["name"] not in ("lo",)]
        # prefer an existing tgt* interface if present
        pref = next((n for n in ifaces if n.startswith("tgt")), None)
        self.send_iface: Optional[str] = pref
        self.sensor_label = "Claroty CTD"
        self.selected: List[str] = ["modbus", "s7comm"]
        self.scenario: Optional[str] = None
        self.env: Optional[str] = None      # modeled environment (overrides protos)
        self.incident: Optional[str] = None  # attack scenario (overrides protos)
        self.replay: Optional[str] = None    # pcap to replay (overrides all)
        self.sprinkle_on = False             # mix malware into the base traffic
        self.sprinkle_variant = incidents.all_incidents()[0].key
        self.rate = 20.0
        self.messages = 5
        self.loop = True
        self.pcap: Optional[str] = None
        self.ep = Endpoints()

        self.engine: Optional[Engine] = None
        self.log: List[str] = []
        self.focus = 0                 # index into PANELS
        self.row = 0                   # selected row within panel
        self.frame = 0                 # animation tick
        self.svc = service.service_state()
        self._svc_poll = 0.0
        self._load_service_config()

    # -- helpers -----------------------------------------------------------
    def add_log(self, msg: str):
        self.log.append(f"{time.strftime('%H:%M:%S')} {msg}")
        self.log = self.log[-300:]

    def running(self) -> bool:
        return bool(self.engine and self.engine.is_alive())

    def stats(self):
        return self.engine.stats if self.engine else None

    @property
    def mon_iface(self) -> str:
        if not self.send_iface:
            return ""
        cand = f"{self.send_iface}-mon"
        return cand if net.interface_exists(cand) else "(no peer)"

    def _load_service_config(self):
        cfg = service.read_config()
        if cfg.get("TGT_IFACE") and not self.send_iface:
            self.send_iface = cfg["TGT_IFACE"]

    def refresh_service(self):
        now = time.time()
        if now - self._svc_poll > 2.0:
            self.svc = service.service_state()
            self._svc_poll = now

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

    def toggle_proto(self, key: str):
        if key in self.selected:
            self.selected.remove(key)
        else:
            self.selected.append(key)
        self._clear_modes()             # manual edit => custom protocols

    def build_config(self) -> RunConfig:
        sprinkle = ([self.sprinkle_variant]
                    if self.sprinkle_on and self.sprinkle_variant else [])
        return RunConfig(
            profiles=list(self.selected) or ["modbus"], env=self.env,
            incident=self.incident, sprinkle=sprinkle, replay_path=self.replay,
            iface=self.send_iface, pcap_path=self.pcap,
            rate=self.rate, messages=self.messages, loop=self.loop,
            endpoints=self.ep)

    def start_stop(self):
        if self.running():
            self.engine.stop()
            self.add_log("stop requested")
            return
        if not (self.env or self.incident or self.replay or self.selected):
            self.add_log("no protocols selected")
            return
        if not self.send_iface and not self.pcap:
            self.add_log("map a send interface or set a pcap path first")
            return
        cfg = self.build_config()
        self.add_log(f"start: {cfg.summary()}")
        self.engine = Engine(cfg, on_log=self.add_log)
        self.engine.start()


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
def _draw_diagram(win, ui: UI, top: int, w: int):
    s = ui.stats()
    running = ui.running()
    pps = s.pps if s else 0.0
    pkts = s.packets if s else 0

    margin = 2
    usable = w - 2 * margin
    cell = max(16, usable // 4)
    box_w = max(11, cell - 8)
    xs = [margin + i * cell for i in range(4)]
    bh = 7
    by = top + 1
    mid = by + bh // 2

    # node colours + titles
    nodes = [
        (C_GREEN, "TGT ENGINE"),
        (C_CYAN, "SEND"),
        (C_YELLOW, "MONITOR"),
        (C_MAGENTA, "SENSOR"),
    ]
    for i, (color, title) in enumerate(nodes):
        _box(win, by, xs[i], bh, box_w, title, color)

    inner = box_w - 2

    # ENGINE box: active protocols with live bars. In env/incident/replay modes
    # the active list is the busiest labels seen from the generated traffic.
    mode = None
    if ui.replay:
        mode = f"replay:{ui.replay.split('/')[-1]}"
    elif ui.incident:
        mode = f"⚠ {ui.incident}"
    elif ui.env:
        mode = f"env:{ui.env}"
    if mode:
        if s and s.per_profile:
            active = [k for k, _ in sorted(s.per_profile.items(),
                      key=lambda kv: -kv[1])][:3]
        else:
            active = []
        _put(win, by + 1, xs[0] + 1, mode[:inner],
             _cattr(C_RED if ui.incident else C_GREEN, curses.A_BOLD))
        base_row = by + 2
    else:
        active = ui.selected[:4]
        base_row = by + 1
    maxc = 1
    if s and s.per_profile:
        maxc = max([s.per_profile.get(k, 0) for k in active] + [1])
    for j, k in enumerate(active):
        if base_row + j >= by + bh - 2:
            break
        cnt = s.per_profile.get(k, 0) if s else 0
        blen = int((cnt / maxc) * max(3, inner - 8)) if maxc else 0
        _put(win, base_row + j, xs[0] + 1, f"{k[:6]:6}", _cattr(C_GREEN))
        _put(win, base_row + j, xs[0] + 8, (BAR * blen)[:inner - 8],
             _cattr(C_GREEN))
    if not active and not ui.env:
        _put(win, by + 2, xs[0] + 1, "no protocols", _cattr(C_DIM))
    _put(win, by + bh - 2, xs[0] + 1,
         (f"{pps:6.1f} pps" if running else "idle"),
         _cattr(C_GREEN, curses.A_BOLD if running else 0))

    # SEND box
    send_name = ui.send_iface or "(unmapped)"
    _put(win, by + 1, xs[1] + 1, send_name[:inner], _cattr(C_CYAN, curses.A_BOLD))
    _put(win, by + 2, xs[1] + 1, f"{ARROW} out", _cattr(C_CYAN))
    _put(win, by + 4, xs[1] + 1, f"{pkts}"[:inner], _cattr(C_CYAN))
    _put(win, by + 5, xs[1] + 1, "packets", _cattr(C_DIM))

    # MONITOR box
    _put(win, by + 1, xs[2] + 1, (ui.mon_iface or "-")[:inner],
         _cattr(C_YELLOW, curses.A_BOLD))
    _put(win, by + 2, xs[2] + 1, "capture pt", _cattr(C_YELLOW))
    _put(win, by + 4, xs[2] + 1, "◀ SPAN", _cattr(C_DIM))

    # SENSOR box
    _put(win, by + 1, xs[3] + 1, ui.sensor_label[:inner],
         _cattr(C_MAGENTA, curses.A_BOLD))
    _put(win, by + 2, xs[3] + 1, "ingest", _cattr(C_MAGENTA))
    _put(win, by + 4, xs[3] + 1, "◀ in", _cattr(C_DIM))

    # animated flow in the gaps
    labels = ["emit", "mirror", "ingest"]
    for i in range(3):
        gap_start = xs[i] + box_w
        gap_end = xs[i + 1]
        glen = gap_end - gap_start
        if glen < 2:
            continue
        # base line
        _put(win, mid, gap_start, BOX["h"] * (glen - 1), _cattr(C_DIM))
        _put(win, mid, gap_end - 1, ARROW,
             _cattr(C_GREEN if running else C_DIM,
                    curses.A_BOLD if running else 0))
        # moving dots
        if running and pps > 0:
            ndots = max(1, min(glen - 1, 1 + int(pps / 15)))
            step = max(1, glen // max(1, ndots))
            for kdot in range(ndots):
                pos = (ui.frame + kdot * step) % (glen - 1)
                _put(win, mid, gap_start + pos, DOT,
                     _cattr(C_GREEN, curses.A_BOLD))
        # gap label
        _put(win, mid + 1, gap_start + max(0, (glen - len(labels[i])) // 2),
             labels[i], _cattr(C_DIM))

    return by + bh + 1


# ── panels ──────────────────────────────────────────────────────────────────
def _iface_list(ui: UI) -> List[str]:
    return [i["name"] for i in net.list_interfaces() if i["name"] != "lo"]


def _panel_rows(ui: UI) -> List[tuple]:
    """Return rows for the active panel as (label, value) tuples."""
    p = PANELS[ui.focus]
    if p == "Map":
        return [
            ("Send interface", ui.send_iface or "(none — pcap only)"),
            ("Monitor (peer)", ui.mon_iface or "-"),
            ("Sensor label", ui.sensor_label),
            ("Create veth pair", "press Enter"),
            ("Delete send iface", "press Enter"),
        ]
    if p == "Protocols":
        rows = []
        s = ui.stats()
        for prof in protocols.all_profiles():
            mark = "◉" if prof.key in ui.selected else "○"
            cnt = s.per_profile.get(prof.key, 0) if s else 0
            val = f"{prof.port:>6}/{prof.transport:3} {cnt if cnt else ''}"
            rows.append((f"{mark} {prof.key}", val))
        return rows
    if p == "Settings":
        if ui.replay:
            preset = f"replay: {ui.replay.split('/')[-1]}"
        elif ui.incident:
            preset = f"incident: {ui.incident}"
        elif ui.env:
            preset = f"env: {ui.env}"
        elif ui.scenario:
            preset = f"scenario: {ui.scenario}"
        else:
            preset = "(custom protocols)"
        return [
            ("Preset", preset),
            ("Replay pcap", ui.replay or "(off — Enter to set)"),
            ("Sprinkle malware", "ON" if ui.sprinkle_on else "off"),
            ("  variant", f"⚠ {ui.sprinkle_variant}" if ui.sprinkle_on
             else "(enable above)"),
            ("Rate (pps)", f"{ui.rate:g}  (0 = max)"),
            ("Msgs / cycle", str(ui.messages)),
            ("Loop", "yes" if ui.loop else "no"),
            ("PCAP output", ui.pcap or "(off)"),
            ("Client IP", ui.ep.client_ip),
            ("Server IP", ui.ep.server_ip),
        ]
    if p == "Service":
        st = ui.svc
        run_args = service.build_run_args(ui.scenario, ui.selected, ui.rate,
                                          ui.messages, env=ui.env,
                                          incident=ui.incident, replay=ui.replay,
                                          sprinkle=[ui.sprinkle_variant] if ui.sprinkle_on else None)
        return [
            ("Status", f"{st.status} ({st.mode})"),
            ("Config file", service.CONF_PATH),
            ("Would run", run_args),
            ("Save config", "press Enter"),
            ("Start service", "press Enter"),
            ("Stop service", "press Enter"),
            ("Restart service", "press Enter"),
        ]
    return []


def _draw_panel(win, ui: UI, y0, x0, h, w):
    # tab strip
    tx = x0
    for i, name in enumerate(PANELS):
        active = i == ui.focus
        attr = _cattr(C_CYAN, curses.A_REVERSE if active else curses.A_BOLD)
        label = f" {name} "
        _put(win, y0, tx, label, attr if active else _cattr(C_DIM))
        tx += len(label) + 1
    # rows
    rows = _panel_rows(ui)
    ui.row = max(0, min(ui.row, len(rows) - 1))
    top = y0 + 2
    avail = h - 3
    start = max(0, ui.row - avail + 1)
    for idx in range(start, min(len(rows), start + avail)):
        label, value = rows[idx]
        yy = top + (idx - start)
        sel = idx == ui.row
        # colour protocol markers
        base = _cattr(C_GREEN if (PANELS[ui.focus] == "Protocols"
                     and label.startswith("◉")) else C_DIM)
        lattr = _cattr(C_CYAN, curses.A_REVERSE) if sel else curses.A_BOLD
        _put(win, yy, x0, f"{label:20}", lattr if sel else base)
        _put(win, yy, x0 + 21, str(value)[:w - 22],
             _cattr(C_CYAN, curses.A_REVERSE) if sel else 0)


def _draw_log(win, ui: UI, y0, x0, h, w):
    _put(win, y0, x0, "─ Live log ", _cattr(C_BLUE, curses.A_BOLD))
    visible = ui.log[-(h - 1):]
    for j, line in enumerate(visible):
        ts, _, rest = line.partition(" ")
        _put(win, y0 + 1 + j, x0, ts, _cattr(C_DIM))
        _put(win, y0 + 1 + j, x0 + len(ts) + 1, rest[:w - len(ts) - 2])


# ── input prompts ───────────────────────────────────────────────────────────
def _prompt(stdscr, label: str, default: str = "") -> Optional[str]:
    curses.echo()
    curses.curs_set(1)
    h, w = stdscr.getmaxyx()
    width = max(30, w - 4)
    win = curses.newwin(3, width, h // 2 - 1, 2)
    win.box()
    hint = f" {label}  [Enter = {default}] " if default else f" {label} "
    _put(win, 0, 2, hint[:width - 4], _cattr(C_CYAN, curses.A_BOLD))
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


# ── panel actions ───────────────────────────────────────────────────────────
def _act_map(stdscr, ui: UI):
    r = ui.row
    if r == 0:                                   # cycle send iface
        opts = [None] + _iface_list(ui)
        try:
            i = opts.index(ui.send_iface)
        except ValueError:
            i = 0
        ui.send_iface = opts[(i + 1) % len(opts)]
    elif r == 2:                                 # sensor label
        ui.sensor_label = _prompt(stdscr, "Sensor label",
                                  ui.sensor_label) or ui.sensor_label
    elif r == 3:                                 # create veth
        name = _prompt(stdscr, "veth interface name", ui.send_iface or "tgt0")
        if name:
            ui.add_log(f"creating veth {name} <-> {name}-mon …")
            res = net.create_veth(name)
            for ln in res.log:
                ui.add_log(ln)
            if res.ok:
                ui.send_iface = name
    elif r == 4:                                 # delete
        if ui.send_iface:
            res = net.delete_interface(ui.send_iface)
            for ln in res.log:
                ui.add_log(ln)


def _act_settings(stdscr, ui: UI):
    r = ui.row
    if r == 0:                        # preset: custom → scenarios → envs → incidents
        scen = [("s", s.key) for s in scenarios.all_scenarios()]
        envs = [("e", e.key) for e in enterprise.all_environments()]
        incs = [("i", x.key) for x in incidents.all_incidents()]
        opts = [("", None)] + scen + envs + incs
        cur = (("i", ui.incident) if ui.incident else ("e", ui.env) if ui.env
               else ("s", ui.scenario) if ui.scenario else ("", None))
        try:
            i = opts.index(cur)
        except ValueError:
            i = 0
        kind, key = opts[(i + 1) % len(opts)]
        {"i": ui.set_incident, "e": ui.set_env}.get(kind, ui.set_scenario)(key)
    elif r == 1:                                  # replay pcap
        v = _prompt(stdscr, "Replay pcap path (blank = off)", ui.replay or "")
        if v:
            ui._clear_modes()
            ui.replay = v
            ui.add_log(f"replay set: {v}")
        else:
            ui.replay = None
    elif r == 2:                                  # sprinkle malware toggle
        ui.sprinkle_on = not ui.sprinkle_on
        ui.add_log(f"malware sprinkle {'ON: ' + ui.sprinkle_variant if ui.sprinkle_on else 'off'}")
    elif r == 3:                                  # malware variant cycle
        keys = [x.key for x in incidents.all_incidents()]
        try:
            i = keys.index(ui.sprinkle_variant)
        except ValueError:
            i = 0
        ui.sprinkle_variant = keys[(i + 1) % len(keys)]
        ui.sprinkle_on = True
    elif r == 4:
        v = _prompt(stdscr, "Rate pps (0 = max)", f"{ui.rate:g}")
        try:
            ui.rate = max(0.0, float(v))
        except (TypeError, ValueError):
            pass
    elif r == 5:
        v = _prompt(stdscr, "Messages per cycle", str(ui.messages))
        try:
            ui.messages = max(1, int(v))
        except (TypeError, ValueError):
            pass
    elif r == 6:
        ui.loop = not ui.loop
    elif r == 7:
        v = _prompt(stdscr, "PCAP path (blank = off)", ui.pcap or "tgt-out.pcap")
        ui.pcap = v if v and v != "(off)" else None
    elif r == 8:
        ui.ep.client_ip = _prompt(stdscr, "Client IP", ui.ep.client_ip) or ui.ep.client_ip
    elif r == 9:
        ui.ep.server_ip = _prompt(stdscr, "Server IP", ui.ep.server_ip) or ui.ep.server_ip


def _act_service(stdscr, ui: UI):
    r = ui.row
    if r == 3:                                   # save config
        args = service.build_run_args(ui.scenario, ui.selected, ui.rate,
                                      ui.messages, env=ui.env,
                                      incident=ui.incident, replay=ui.replay,
                                      sprinkle=[ui.sprinkle_variant] if ui.sprinkle_on else None)
        ok, msg = service.write_config(ui.send_iface or "tgt0", args)
        ui.add_log(("saved: " if ok else "error: ") + msg)
    elif r in (4, 5, 6):
        action = {4: "start", 5: "stop", 6: "restart"}[r]
        ui.add_log(f"service {action} …")
        ok, msg = service.service_action(action)
        ui.add_log(("service " if ok else "service FAILED: ") + msg)
        ui.svc = service.service_state()


def _activate(stdscr, ui: UI):
    p = PANELS[ui.focus]
    if p == "Map":
        _act_map(stdscr, ui)
    elif p == "Protocols":
        prof = protocols.all_profiles()[ui.row]
        ui.toggle_proto(prof.key)
    elif p == "Settings":
        _act_settings(stdscr, ui)
    elif p == "Service":
        _act_service(stdscr, ui)


# ── main render + loop ───────────────────────────────────────────────────────
def _status_word(ui: UI):
    if ui.running():
        return "● GENERATING", C_GREEN
    return "○ idle", C_DIM


def _draw(stdscr, ui: UI):
    stdscr.erase()
    h, w = stdscr.getmaxyx()
    if w < 62 or h < 20:
        _put(stdscr, 0, 0, "Terminal too small — need at least 62x20.")
        stdscr.refresh()
        return

    env = net.detect_env()
    title = " TGT · Traffic Generation Toolkit "
    _put(stdscr, 0, 0, title.ljust(w), _cattr(C_CYAN, curses.A_REVERSE))
    word, wcolor = _status_word(ui)
    _put(stdscr, 0, w - len(word) - 2, word, _cattr(wcolor, curses.A_BOLD | curses.A_REVERSE))

    priv = "root" if env.is_root else "no-root"
    envline = f"env: {env.kind} · {priv} · ip:{'yes' if env.has_ip else 'no'} · service:{ui.svc.status}"
    _put(stdscr, 1, 2, envline, _cattr(C_DIM))
    if ui.sprinkle_on:
        mal = f"⚠ malware: {ui.sprinkle_variant} "
        _put(stdscr, 1, w - len(mal) - 2, mal,
             _cattr(C_RED, curses.A_BOLD | curses.A_REVERSE))

    # diagram
    panel_top = _draw_diagram(stdscr, ui, 2, w)

    # split lower area: panel (left) + log (right)
    lower_h = h - panel_top - 1
    if lower_h < 4:
        stdscr.refresh()
        return
    split = max(34, w * 45 // 100)
    _draw_panel(stdscr, ui, panel_top, 2, lower_h, split - 3)
    # vertical divider
    for yy in range(panel_top, h - 1):
        _put(stdscr, yy, split - 1, BOX["v"], _cattr(C_DIM))
    _draw_log(stdscr, ui, panel_top, split + 1, lower_h, w - split - 2)

    # key bar
    keys = ("Tab panel · ↑↓ move · ←→/Enter change · Space toggle · "
            "s start/stop · c clear · q quit")
    _put(stdscr, h - 1, 0, keys.ljust(w)[:w - 1], _cattr(C_CYAN, curses.A_REVERSE))
    stdscr.refresh()


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


def _loop(stdscr):
    curses.curs_set(0)
    _init_colors()
    stdscr.nodelay(True)
    stdscr.timeout(90)                 # ~11 fps animation
    ui = UI()
    ui.add_log("welcome — map an interface, pick protocols, press s to generate")

    while True:
        ui.frame += 1
        ui.refresh_service()
        try:
            _draw(stdscr, ui)
        except curses.error:
            pass
        c = stdscr.getch()
        if c == -1:
            continue
        rows = _panel_rows(ui)
        if c in (9,):                                  # Tab
            ui.focus = (ui.focus + 1) % len(PANELS)
            ui.row = 0
        elif c in (curses.KEY_BTAB,):                  # Shift-Tab
            ui.focus = (ui.focus - 1) % len(PANELS)
            ui.row = 0
        elif c in (curses.KEY_UP, ord('k')):
            ui.row = (ui.row - 1) % max(1, len(rows))
        elif c in (curses.KEY_DOWN, ord('j')):
            ui.row = (ui.row + 1) % max(1, len(rows))
        elif c in (curses.KEY_LEFT, curses.KEY_RIGHT, curses.KEY_ENTER, 10, 13):
            _activate(stdscr, ui)
            stdscr.nodelay(True)
            stdscr.timeout(90)
        elif c == ord(' '):
            if PANELS[ui.focus] == "Protocols":
                _activate(stdscr, ui)
            elif PANELS[ui.focus] == "Settings" and ui.row in (2, 3, 6):
                _act_settings(stdscr, ui)
        elif c == ord('s'):
            ui.start_stop()
        elif c == ord('c'):
            ui.log.clear()
        elif c in (ord('q'), 27):
            if ui.running():
                ui.engine.stop()
                ui.engine.join(timeout=2)
            break


def run() -> int:
    curses.wrapper(_loop)
    return 0
