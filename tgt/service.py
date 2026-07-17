"""Read/write the TGT service config and query/control the service.

Lets the TUI act as the single control surface: edit what the background service
generates (``/etc/tgt/tgt.conf``) and start/stop/restart it, using systemd when
present and the tgtctl PID-file daemon otherwise.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional

CONF_PATH = "/etc/tgt/tgt.conf"
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
                val = val.strip().strip('"').strip("'")
                out[key.strip()] = val
    except OSError:
        pass
    return out


def write_config(iface: str, run_args: str, path: str = CONF_PATH) -> tuple[bool, str]:
    body = (
        "# TGT service configuration — managed by the TGT TUI.\n"
        f"TGT_IFACE={iface}\n"
        f'TGT_RUN_ARGS="{run_args}"\n'
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
                   messages: int) -> str:
    """Serialize a selection into a `tgt run` argument string for the service."""
    parts: List[str] = []
    if scenario:
        parts += ["--scenario", scenario]
    elif profiles:
        parts += ["--profile", ",".join(profiles)]
    parts += ["--rate", f"{rate:g}"]
    if messages and messages != 5:
        parts += ["--messages", str(messages)]
    return " ".join(parts)
