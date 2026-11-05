"""Read/write the TGT service config and query/control the service.

Lets the TUI act as the single control surface: edit what the background service
generates (``/etc/tgt/tgt.conf``) and start/stop/restart it, using systemd when
present and the tgtctl PID-file daemon otherwise.
"""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional

from .packet import Endpoints

CONF_PATH = "/etc/tgt/tgt.conf"
_DEFAULT_EP = Endpoints()          # `tgt run` defaults; omitted when unchanged
PID_PATHS = ("/run/tgt.pid", "/tmp/tgt.pid")


@dataclass
class ServiceState:
    installed: bool
    mode: str          # "systemd" | "daemon" | "none"
    status: str        # active | inactive | failed | not-installed | unknown
    detail: str = ""


def _have_systemd() -> bool:
    return shutil.which("systemctl") is not None and os.path.isdir(
        "/run/systemd/system")


def read_config(path: str = CONF_PATH) -> dict:
    """Parse the shell-style config into {TGT_IFACE, TGT_RUN_ARGS}."""
    out: dict[str, str] = {}
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                try:                    # undo shell quoting, as `.` would
                    val = "".join(shlex.split(val, comments=True))
                except ValueError:
                    val = val.strip().strip('"').strip("'")
                out[key.strip()] = val
    except OSError:
        pass
    return out


def write_config(iface: str, run_args: str, path: str = CONF_PATH) -> tuple[bool, str]:
    # The file is sourced by /bin/sh (tgtctl.sh, the systemd unit), so every
    # value is shell-quoted: a path with spaces, quotes or `$(…)` stays data.
    # TGT_RUN_ARGS itself is a shell-quoted argument list (see build_run_args)
    # that the consumers expand with `eval set -- $TGT_RUN_ARGS`.
    body = (
        "# TGT service configuration — managed by the TGT TUI.\n"
        f"TGT_IFACE={shlex.quote(iface)}\n"
        f"TGT_RUN_ARGS={shlex.quote(run_args)}\n"
    )
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(body)
        return True, f"saved {path}"
    except PermissionError:
        return False, f"permission denied writing {path} (run as root)"
    except OSError as e:
        return False, f"error writing {path}: {e}"


def service_state() -> ServiceState:
    if _have_systemd():
        try:
            r = subprocess.run(["systemctl", "is-active", "tgt.service"],
                               capture_output=True, text=True, timeout=5)
            status = r.stdout.strip() or "unknown"
            enabled = subprocess.run(["systemctl", "is-enabled", "tgt.service"],
                                     capture_output=True, text=True, timeout=5)
            installed = "not-found" not in (enabled.stdout + enabled.stderr)
            if not installed and status == "inactive":
                return ServiceState(False, "systemd", "not-installed")
            return ServiceState(True, "systemd", status,
                                enabled.stdout.strip())
        except Exception as e:  # noqa: BLE001
            return ServiceState(False, "systemd", "unknown", str(e))
    # daemon fallback: pid file
    for p in PID_PATHS:
        if os.path.exists(p):
            try:
                pid = int(open(p).read().strip())
                os.kill(pid, 0)
                return ServiceState(True, "daemon", "active", f"pid {pid}")
            except (ValueError, ProcessLookupError, PermissionError, OSError):
                return ServiceState(True, "daemon", "inactive")
    return ServiceState(False, "none", "not-installed")


def service_action(action: str) -> tuple[bool, str]:
    """action in {start, stop, restart}. Uses systemctl or tgtctl.sh."""
    if _have_systemd():
        cmd = ["systemctl", action, "tgt.service"]
    else:
        script = _find_tgtctl()
        if not script:
            return False, "tgtctl.sh not found for daemon control"
        cmd = [script, action]
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        cmd = ["sudo", "-n"] + cmd    # non-interactive; fails cleanly if no sudo
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        ok = r.returncode == 0
        msg = (r.stdout + r.stderr).strip().splitlines()
        return ok, (msg[-1] if msg else f"{action} rc={r.returncode}")
    except Exception as e:  # noqa: BLE001
        return False, str(e)


def _find_tgtctl() -> Optional[str]:
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cand = os.path.join(here, "scripts", "tgtctl.sh")
    return cand if os.path.exists(cand) else shutil.which("tgtctl.sh")


def build_run_args(scenario: Optional[str], profiles: List[str], rate: float,
                   messages: int, env: Optional[str] = None,
                   incident: Optional[str] = None,
                   replay: Optional[str] = None,
                   sprinkle: Optional[List[str]] = None,
                   sprinkle_random: bool = False,
                   sprinkle_ratio: float = 0.0,
                   span: str = "access",
                   replay_realtime: bool = False,
                   pcap: Optional[str] = None,
                   once: bool = False,
                   client_ip: Optional[str] = None,
                   server_ip: Optional[str] = None,
                   seed: Optional[int] = None,
                   manifest: Optional[str] = None,
                   schedule: str = "cycle",
                   speed: float = 1.0,
                   day_profile: Optional[str] = None,
                   min_period: float = 0.0,
                   duration: float = 0.0,
                   clock: str = "wall") -> str:
    """Serialize a selection into a `tgt run` argument string for the service.

    The result is shell-quoted (``shlex.split`` gives the argv back), so
    paths containing spaces or quotes survive the round trip. ``seed`` makes
    the service's traffic reproducible and ``manifest`` keeps its ground
    truth; ``schedule="timed"`` (with ``speed``, ``day_profile``,
    ``min_period``) selects the time model, in which ``rate`` is only a cap.
    """
    parts: List[str] = []
    if replay:
        parts += ["--replay", replay]
        if replay_realtime:
            parts += ["--replay-realtime"]
    elif incident:
        parts += ["--incident", incident]
    elif env:
        parts += ["--env", env]
        if span and span != "access":
            parts += ["--span", span]
    elif scenario:
        parts += ["--scenario", scenario]
    elif profiles:
        parts += ["--profile", ",".join(profiles)]
    if not replay:
        if sprinkle:
            parts += ["--sprinkle", ",".join(sprinkle)]
        if sprinkle_random:
            parts += ["--sprinkle-random"]
        if sprinkle_ratio and sprinkle_ratio > 0:
            parts += ["--sprinkle-ratio", f"{sprinkle_ratio:g}"]
    if schedule and schedule != "cycle" and not replay:
        parts += ["--schedule", schedule]
        if speed and speed != 1.0:
            parts += ["--speed", f"{speed:g}"]
        if day_profile:
            parts += ["--day-profile", day_profile]
        if min_period and min_period > 0:
            parts += ["--min-period", f"{min_period:g}"]
    parts += ["--rate", f"{rate:g}"]
    if seed is not None:
        parts += ["--seed", str(int(seed))]
    if duration and duration > 0:
        parts += ["--duration", f"{duration:g}"]
    if clock and clock != "wall":
        parts += ["--clock", clock]
    if manifest:
        parts += ["--manifest", manifest]
    if messages and messages != 5:
        parts += ["--messages", str(messages)]
    if client_ip and client_ip != _DEFAULT_EP.client_ip:
        parts += ["--client-ip", client_ip]
    if server_ip and server_ip != _DEFAULT_EP.server_ip:
        parts += ["--server-ip", server_ip]
    if pcap:
        parts += ["--pcap", pcap]
    if once:
        parts += ["--once"]
    return " ".join(shlex.quote(p) for p in parts)
