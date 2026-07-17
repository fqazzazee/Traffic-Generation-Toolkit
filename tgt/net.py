"""Virtual interface management + environment detection.

TGT sends onto a virtual interface so a monitoring tool (Claroty CTD, Wireshark,
Zeek, ...) can capture it exactly as it would a physical SPAN/mirror port.

The recommended layout is a **veth pair**::

    tgt0  <--->  tgt0-mon
     |             |
   generate      capture here (point CTD / tcpdump at tgt0-mon)

Frames written to one end appear on the other, which faithfully mimics a span
session without touching any real network.  A ``dummy`` interface is offered as
a simpler single-NIC alternative.

Interface *listing* uses ``/sys/class/net`` and needs no tools.  Interface
*creation* shells out to ``ip`` (iproute2), which ships on Ubuntu, WSL and the
common Podman base images; root/CAP_NET_ADMIN is required for that step only.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Env:
    kind: str            # "wsl" | "podman" | "container" | "native"
    detail: str
    is_root: bool
    has_ip: bool


def detect_env() -> Env:
    detail = []
    kind = "native"

    # WSL exposes "microsoft" / "WSL" in /proc/version
    try:
        with open("/proc/version") as fh:
            ver = fh.read().lower()
        if "microsoft" in ver or "wsl" in ver:
            kind = "wsl"
            detail.append("WSL kernel")
    except OSError:
        pass

    # Container hints
    if os.path.exists("/run/.containerenv"):
        kind = "podman"
        detail.append("/run/.containerenv present")
    elif os.path.exists("/.dockerenv"):
        kind = "container"
        detail.append("/.dockerenv present")
    elif os.environ.get("container"):
        kind = kind if kind == "wsl" else "container"
        detail.append(f"container={os.environ['container']}")

    is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
    has_ip = shutil.which("ip") is not None
    return Env(kind=kind, detail=", ".join(detail) or "generic Linux",
               is_root=is_root, has_ip=has_ip)


def list_interfaces() -> List[dict]:
    """Enumerate interfaces from /sys/class/net (no external tools needed)."""
    base = "/sys/class/net"
    out = []
    if not os.path.isdir(base):
        return out
    for name in sorted(os.listdir(base)):
        info = {"name": name, "mac": "", "state": "", "mtu": ""}
        for attr, key in (("address", "mac"), ("operstate", "state"),
                          ("mtu", "mtu")):
            try:
                with open(os.path.join(base, name, attr)) as fh:
                    info[key] = fh.read().strip()
            except OSError:
                pass
        out.append(info)
    return out


def interface_exists(name: str) -> bool:
    return os.path.isdir(f"/sys/class/net/{name}")


def _run(cmd: List[str], use_sudo: bool) -> subprocess.CompletedProcess:
    if use_sudo and (not hasattr(os, "geteuid") or os.geteuid() != 0):
        cmd = ["sudo"] + cmd
    return subprocess.run(cmd, capture_output=True, text=True)


def veth_commands(name: str, peer: str, mtu: int = 1500) -> List[List[str]]:
    return [
        ["ip", "link", "add", name, "type", "veth", "peer", "name", peer],
        ["ip", "link", "set", name, "mtu", str(mtu)],
        ["ip", "link", "set", peer, "mtu", str(mtu)],
        ["ip", "link", "set", name, "up"],
        ["ip", "link", "set", peer, "up"],
    ]


def dummy_commands(name: str, mtu: int = 1500) -> List[List[str]]:
    return [
        ["ip", "link", "add", name, "type", "dummy"],
        ["ip", "link", "set", name, "mtu", str(mtu)],
        ["ip", "link", "set", name, "up"],
    ]


def delete_commands(name: str) -> List[List[str]]:
    return [["ip", "link", "del", name]]


@dataclass
class OpResult:
    ok: bool
    log: List[str]


def _apply(cmds: List[List[str]], use_sudo: bool) -> OpResult:
    log = []
    if not shutil.which("ip"):
        return OpResult(False, ["'ip' (iproute2) not found — install it or run "
                                "the printed commands on a host that has it."])
    for cmd in cmds:
        shown = ("sudo " if use_sudo else "") + " ".join(cmd)
        proc = _run(cmd, use_sudo)
        if proc.returncode != 0:
            log.append(f"FAIL: {shown}")
            err = (proc.stderr or proc.stdout).strip()
            if err:
                log.append(f"      {err}")
            return OpResult(False, log)
        log.append(f"ok:   {shown}")
    return OpResult(True, log)


def create_veth(name: str, peer: Optional[str] = None, mtu: int = 1500,
                use_sudo: bool = True) -> OpResult:
    peer = peer or f"{name}-mon"
    if interface_exists(name):
        return OpResult(True, [f"{name} already exists — reusing"])
    return _apply(veth_commands(name, peer, mtu), use_sudo)


def create_dummy(name: str, mtu: int = 1500,
                 use_sudo: bool = True) -> OpResult:
    if interface_exists(name):
        return OpResult(True, [f"{name} already exists — reusing"])
    return _apply(dummy_commands(name, mtu), use_sudo)


def delete_interface(name: str, use_sudo: bool = True) -> OpResult:
    if not interface_exists(name):
        return OpResult(True, [f"{name} does not exist"])
    return _apply(delete_commands(name), use_sudo)
