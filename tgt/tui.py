"""Curses text UI for TGT — zero external dependencies.

A single-screen dashboard: pick an interface / pcap target, toggle protocols or
a scenario, tune rate and stop conditions, then Start.  While running it shows
live throughput and a per-protocol counter.  All keyboard-driven; works over
plain SSH and inside WSL/Podman terminals.
"""
from __future__ import annotations

import curses
import time
from typing import List, Optional

from . import net, protocols, scenarios
from .config import RunConfig
from .engine import Engine
from .packet import Endpoints

KEYHINT = ("↑/↓ move  ·  ←/→ or Enter change  ·  Space toggle proto  ·  "
           "s Start/Stop  ·  c clear log  ·  q quit")


class State:
    def __init__(self):
        self.iface: Optional[str] = None
        self.pcap: Optional[str] = None
        self.selected: List[str] = ["modbus"]
        self.rate: float = 20.0
        self.messages: int = 5
        self.count: int = 0
        self.duration: float = 0.0
        self.loop: bool = True
        self.ep = Endpoints()
        self.log: List[str] = []
        self.engine: Optional[Engine] = None

    def add_log(self, msg: str):
        stamp = time.strftime("%H:%M:%S")
        self.log.append(f"{stamp} {msg}")
        self.log = self.log[-200:]

    def running(self) -> bool:
        return bool(self.engine and self.engine.is_alive())


def _prompt(stdscr, label: str, default: str = "") -> Optional[str]:
    curses.echo()
    curses.curs_set(1)
    h, w = stdscr.getmaxyx()
    width = max(30, w - 4)
    win = curses.newwin(3, width, h // 2 - 1, 2)
    win.box()
    hint = f" {label}  [Enter = {default}] " if default else f" {label} "
    win.addstr(0, 2, hint[:width - 4])
    win.addstr(1, 2, "> ")
    win.refresh()
    try:
        raw = win.getstr(1, 4, width - 6)
        val = raw.decode(errors="ignore").strip()
    except Exception:
        val = ""
    curses.noecho()
    curses.curs_set(0)
    return val or (default or None)


def _cycle_interfaces(state: State):
    ifaces = [i["name"] for i in net.list_interfaces()]
    options = [None] + ifaces  # None => pcap-only
    try:
        idx = options.index(state.iface)
    except ValueError:
        idx = 0
    state.iface = options[(idx + 1) % len(options)]


# menu row types --------------------------------------------------------------
ROWS = [
    "iface", "pcap", "protocols", "scenario",
    "rate", "messages", "count", "duration", "loop",
    "endpoints", "action",
]


def _row_text(state: State, key: str) -> tuple[str, str]:
    if key == "iface":
        return "Send interface", state.iface or "(none — pcap only)"
    if key == "pcap":
        return "PCAP output", state.pcap or "(disabled)"
    if key == "protocols":
        return "Protocols", ", ".join(state.selected) or "(none)"
    if key == "scenario":
        return "Load scenario", "press Enter to pick…"
    if key == "rate":
        return "Rate (pps)", f"{state.rate:g}  (0 = max)"
    if key == "messages":
        return "Msgs / cycle", str(state.messages)
    if key == "count":
        return "Stop after count", str(state.count) if state.count else "(off)"
    if key == "duration":
        return "Stop after secs", f"{state.duration:g}" if state.duration else "(off)"
    if key == "loop":
        return "Loop", "yes" if state.loop else "no"
    if key == "endpoints":
        e = state.ep
        return "Endpoints", f"{e.client_ip} → {e.server_ip}"
    if key == "action":
        return "▶ START / STOP", "running…" if state.running() else "ready"
    return key, ""


def _activate(stdscr, state: State, key: str):
    if key == "iface":
        _cycle_interfaces(state)
    elif key == "pcap":
        val = _prompt(stdscr, "PCAP path (blank to disable)",
                      state.pcap or "tgt-out.pcap")
        state.pcap = val if val and val != "(disabled)" else None
    elif key == "protocols":
        _protocol_picker(stdscr, state)
    elif key == "scenario":
        _scenario_picker(stdscr, state)
    elif key == "rate":
        val = _prompt(stdscr, "Rate in pps (0 = max)", f"{state.rate:g}")
        try:
            state.rate = max(0.0, float(val))
        except (TypeError, ValueError):
            pass
    elif key == "messages":
        val = _prompt(stdscr, "Messages per cycle", str(state.messages))
        try:
            state.messages = max(1, int(val))
        except (TypeError, ValueError):
            pass
    elif key == "count":
        val = _prompt(stdscr, "Stop after N packets (0 = off)", str(state.count))
        try:
            state.count = max(0, int(val))
        except (TypeError, ValueError):
            pass
    elif key == "duration":
        val = _prompt(stdscr, "Stop after N seconds (0 = off)",
                      f"{state.duration:g}")
        try:
            state.duration = max(0.0, float(val))
        except (TypeError, ValueError):
            pass
    elif key == "loop":
        state.loop = not state.loop
    elif key == "endpoints":
        _endpoint_editor(stdscr, state)
    elif key == "action":
        _toggle_run(state)


def _protocol_picker(stdscr, state: State):
    profs = protocols.all_profiles()
    idx = 0
    while True:
        stdscr.erase()
        stdscr.addstr(0, 2, "Select protocols — Space toggle, Enter done",
                      curses.A_BOLD)
        for i, p in enumerate(profs):
            mark = "[x]" if p.key in state.selected else "[ ]"
            attr = curses.A_REVERSE if i == idx else curses.A_NORMAL
            stdscr.addstr(2 + i, 2,
                          f"{mark} {p.key:10} {p.name:22} {p.category} "
                          f"{p.port:>6}/{p.transport}", attr)
        stdscr.refresh()
        c = stdscr.getch()
        if c in (curses.KEY_UP, ord('k')):
            idx = (idx - 1) % len(profs)
        elif c in (curses.KEY_DOWN, ord('j')):
            idx = (idx + 1) % len(profs)
        elif c == ord(' '):
            k = profs[idx].key
            if k in state.selected:
                state.selected.remove(k)
            else:
                state.selected.append(k)
        elif c in (curses.KEY_ENTER, 10, 13, 27, ord('q')):
            break


def _scenario_picker(stdscr, state: State):
    scen = scenarios.all_scenarios()
    idx = 0
    while True:
        stdscr.erase()
        stdscr.addstr(0, 2, "Load a scenario — Enter to apply, q to cancel",
                      curses.A_BOLD)
        row = 2
        for i, s in enumerate(scen):
            attr = curses.A_REVERSE if i == idx else curses.A_NORMAL
            stdscr.addstr(row, 2, f"{s.name:26} [{', '.join(s.profiles)}]", attr)
            stdscr.addstr(row + 1, 4, s.desc[:curses.COLS - 6], curses.A_DIM)
            row += 3
        stdscr.refresh()
        c = stdscr.getch()
        if c in (curses.KEY_UP, ord('k')):
            idx = (idx - 1) % len(scen)
        elif c in (curses.KEY_DOWN, ord('j')):
            idx = (idx + 1) % len(scen)
        elif c in (curses.KEY_ENTER, 10, 13):
            state.selected = list(scen[idx].profiles)
            state.add_log(f"loaded scenario '{scen[idx].key}'")
            break
        elif c in (27, ord('q')):
            break


def _endpoint_editor(stdscr, state: State):
    e = state.ep
    e.client_ip = _prompt(stdscr, "Client IP", e.client_ip) or e.client_ip
    e.server_ip = _prompt(stdscr, "Server IP", e.server_ip) or e.server_ip
    e.client_mac = _prompt(stdscr, "Client MAC", e.client_mac) or e.client_mac
    e.server_mac = _prompt(stdscr, "Server MAC", e.server_mac) or e.server_mac


def _toggle_run(state: State):
    if state.running():
        state.engine.stop()
        state.add_log("stop requested")
        return
    if not state.selected:
        state.add_log("no protocols selected")
        return
    if not state.iface and not state.pcap:
        state.add_log("set an interface or a pcap path first")
        return
    cfg = RunConfig(
        profiles=list(state.selected), iface=state.iface, pcap_path=state.pcap,
        rate=state.rate, count=state.count, duration=state.duration,
        messages=state.messages, loop=state.loop, endpoints=state.ep,
    )
    state.add_log(f"start: {cfg.summary()}")
    state.engine = Engine(cfg, on_log=state.add_log)
    state.engine.start()


def _draw(stdscr, state: State, cursor: int):
    stdscr.erase()
    h, w = stdscr.getmaxyx()
    env = net.detect_env()
    title = " TGT · Traffic Generation Toolkit "
    stdscr.addstr(0, 0, title.center(w)[:w - 1], curses.A_REVERSE)
    priv = "root" if env.is_root else "no-root (send needs sudo)"
    stdscr.addstr(1, 2, f"env: {env.kind} · {priv} · ip:"
                        f"{'yes' if env.has_ip else 'no'}", curses.A_DIM)

    # left: config rows
    top = 3
    for i, key in enumerate(ROWS):
        label, val = _row_text(state, key)
        attr = curses.A_REVERSE if i == cursor else curses.A_NORMAL
        if key == "action":
            attr |= curses.A_BOLD
        line = f" {label:18}: {val}"
        stdscr.addstr(top + i, 2, line[:w // 2 - 2].ljust(w // 2 - 3), attr)

    # right: live stats
    rx = w // 2 + 1
    stdscr.addstr(3, rx, "── Live ──", curses.A_BOLD)
    s = state.engine.stats if state.engine else None
    if s:
        rows = [
            f"state   : {'RUNNING' if s.running else 'stopped'}",
            f"packets : {s.packets}",
            f"bytes   : {s.bytes}",
            f"pps     : {s.pps:.1f}",
            f"Mbps    : {s.mbps:.2f}",
            f"errors  : {s.errors}",
            f"elapsed : {s.elapsed:.1f}s",
        ]
        for j, r in enumerate(rows):
            stdscr.addstr(4 + j, rx, r[:w - rx - 1])
        pr_row = 12
        stdscr.addstr(pr_row, rx, "per-protocol:", curses.A_DIM)
        for j, (k, v) in enumerate(sorted(s.per_profile.items())):
            if pr_row + 1 + j < h - 8:
                stdscr.addstr(pr_row + 1 + j, rx, f"  {k:10} {v}"[:w - rx - 1])
        if s.last_error:
            stdscr.addstr(min(h - 9, pr_row + 8), rx,
                          f"err: {s.last_error}"[:w - rx - 1], curses.A_DIM)
    else:
        stdscr.addstr(4, rx, "no run yet", curses.A_DIM)

    # bottom: log
    log_top = min(top + len(ROWS) + 1, h - 7)
    stdscr.addstr(log_top, 2, "── Log ──", curses.A_BOLD)
    visible = state.log[-(h - log_top - 3):]
    for j, line in enumerate(visible):
        stdscr.addstr(log_top + 1 + j, 2, line[:w - 3])

    stdscr.addstr(h - 1, 0, KEYHINT.center(w)[:w - 1], curses.A_REVERSE)
    stdscr.refresh()


def _loop(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(250)
    state = State()
    state.add_log("welcome — pick protocols, set an interface or pcap, press s")
    cursor = 0
    while True:
        try:
            _draw(stdscr, state, cursor)
        except curses.error:
            pass  # terminal too small; keep going
        c = stdscr.getch()
        if c == -1:
            continue
        if c in (curses.KEY_UP, ord('k')):
            cursor = (cursor - 1) % len(ROWS)
        elif c in (curses.KEY_DOWN, ord('j')):
            cursor = (cursor + 1) % len(ROWS)
        elif c in (curses.KEY_ENTER, 10, 13, curses.KEY_RIGHT, curses.KEY_LEFT):
            _activate(stdscr, state, ROWS[cursor])
            stdscr.nodelay(True)
            stdscr.timeout(250)
        elif c == ord(' ') and ROWS[cursor] == "protocols":
            _activate(stdscr, state, "protocols")
        elif c == ord('s'):
            _toggle_run(state)
        elif c == ord('c'):
            state.log.clear()
        elif c == ord('q'):
            if state.running():
                state.engine.stop()
                state.engine.join(timeout=2)
            break


def run() -> int:
    curses.wrapper(_loop)
    return 0
