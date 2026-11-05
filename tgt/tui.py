"""TGT text UI — a live SPAN traffic-flow diagram you can navigate and drive.

The centrepiece is the flow diagram, drawn for how frames reach the sensor:

    veth pair        TGT ENGINE ─▶ tgt0 (send) ─▶ tgt0-mon (monitor) ─▶ SENSOR
    real interface   TGT ENGINE ─▶ eth0 (send) ┈▶ SENSOR   (via a SPAN)
    pcap only        TGT ENGINE ─▶ PCAP ┈▶ SENSOR          (imported)

Each box carries live data — the traffic mix (malware always visible), packets,
bytes and errors on the send side, the SPAN view and VLAN tagging at the
monitor — and packets animate along the path while it generates. Four tabbed
panels below drive it: Run (preset, campaign, schedule, malware, rate, clock,
seed, manifest, control API, output), Traffic (protocol mix, grouped by
family), Interfaces (send interface(s), veth pair, sensor) and Service.

While a run is live, ``i`` injects an incident for a while (the same
:mod:`tgt.control` path as ``tgt ctl inject``), ``p`` pauses it, and the API
row lets ``tgt ctl`` drive a TUI-started run.

Pure curses, no dependencies. Works over SSH and inside WSL/Podman terminals.
"""
from __future__ import annotations

import curses
import ipaddress
import os
import shlex
import textwrap
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple, Union

from . import (enterprise, incidents, net, protocols, scenarios, service,
               techniques)
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
SPEED_STEPS = [1, 2, 5, 10, 30, 60, 120, 360, 720, 1440, 3600]
MIN_PERIOD_STEPS = [0, 0.5, 1, 2, 5, 10, 30, 60, 300]
DURATION_STEPS = [0, 60, 300, 900, 1800, 3600, 4 * 3600, 8 * 3600, 86400,
                  7 * 86400]                                   # 0 = no end
REPLAY_SPEED_STEPS = [0, 0.25, 0.5, 1, 2, 5, 10]               # 0 = by rate
INJECT_STEPS = [10, 30, 60, 120, 300, 600, 1800, 3600]
DEFAULT_API = "127.0.0.1:8787"

# Protocol families on the Traffic tab (registry keys; anything else falls
# back to its category, plugin protocols to "Plugins").
FAMILIES = [
    ("OT/ICS", "Fieldbus / SCADA protocols: polling, identity, I/O, writes."),
    ("Substation/L2", "IEC 61850, PROFINET, PTP and ring redundancy — "
     "Layer-2 multicast that stays on one segment."),
    ("Building", "Building automation: BACnet, KNX."),
    ("Medical", "Clinical systems: DICOM imaging, HL7 messaging."),
    ("IT", "Business IT: web, TLS, directory, file sharing, EDR, MQTT."),
    ("Infra/Discovery", "Network plumbing a sensor sees everywhere: ARP, DHCP,"
     " DNS, NTP, SNMP, LLDP/CDP, syslog, multicast name discovery."),
    ("Remote access", "Interactive sessions into the plant: SSH, RDP, VNC, "
     "Telnet."),
    ("Vendor engineering", "Engineering-workstation traffic: program "
     "uploads/downloads, vendor protocols, firmware and file transfer."),
    ("Plugins", "Protocols registered by user plugins."),
]
_FAMILY_OF = {}
for _fam, _keys in (
        ("OT/ICS", "modbus dnp3 enip s7comm iec104 opcua enip-id s7-id "
                   "modbus-id enip-list enip-io dnp3-id modbus-write "
                   "dnp3-time iec104-time sparkplug enip-write"),
        ("Substation/L2", "pn-dcp pn-dcp-set pn-rt goose sv mms ptp ptp-l2 "
                          "mrp dlr sel-telnet"),
        ("Building", "bacnet bacnet-id bacnet-cov knxip"),
        ("Medical", "dicom hl7"),
        ("IT", "http https edr smb kerberos ldap smb-logon mqtt"),
        ("Infra/Discovery", "arp icmp dns dhcp netbios ntp snmp snmpv3 lldp "
                            "cdp syslog mdns ssdp llmnr nbns"),
        ("Remote access", "ssh rdp vnc telnet"),
        ("Vendor engineering", "s7-eng enip-eng s7plus fins slmp hart-ip srtp "
                               "codesys codesys-disc ftp tftp http-fw")):
    for _k in _keys.split():
        _FAMILY_OF[_k] = _fam


def proto_family(prof) -> str:
    """The Traffic-tab family of a registry protocol."""
    fam = _FAMILY_OF.get(prof.key)
    if fam:
        return fam
    from . import plugins
    if prof.key in plugins.OWNERS.get("protocol", {}):
        return "Plugins"
    return "OT/ICS" if prof.category == "OT" else "IT"

Value = Union[str, Tuple[str, int]]


# ── state ───────────────────────────────────────────────────────────────────
class UI:
    def __init__(self):
        self.sys = net.detect_env()          # cached: it reads /proc and PATH
        self.ifaces: Dict[str, dict] = {}
        self._if_poll = 0.0
        self._log_lock = threading.Lock()    # the engine thread logs too
        self.log: List[str] = []
        self.engine: Optional[Engine] = None
        self.api_server = None               # tgt.api.ControlServer
        self.refresh(force=True)
        pref = next((n for n in self.ifaces
                     if n.startswith("tgt") and not n.endswith("-mon")), None)
        self.send_iface: Optional[str] = pref
        self.extra_ifaces: List[str] = []    # fan-out: same frames to these
        self.sensor_label = "Zeek/Suricata"
        self.selected: List[str] = ["modbus", "s7comm"]
        self.scenario: Optional[str] = None
        self.env: Optional[str] = None       # modeled environment (overrides protos)
        self.span = "access"                 # env capture point: access | core
        self.incident: Optional[str] = None  # attack scenario (overrides protos)
        self.replay: Optional[str] = None    # pcap to replay (overrides all)
        self.campaign: Optional[str] = None  # campaign plan path (phased run)
        self.campaign_force = False          # skip the phase-length checks
        self.campaign_env_key: Optional[str] = None   # the plan's env key
        self.sprinkle_on = False             # mix malware into the base traffic
        self.sprinkle_variant = incidents.all_incidents()[0].key
        self.sprinkle_random = False         # random variant + jittered placement
        self.sprinkle_ratio = 0.0            # 0 = natural minority; else target fraction
        self.rate = 20.0
        self._cycle_rate = 20.0              # rate to restore when leaving timed
        self.messages = 5
        self.loop = True
        self.pcap: Optional[str] = None
        self.ep = Endpoints()
        # time model / reproducibility / ground truth / control
        self.schedule = "cycle"              # cycle | timed
        self.speed = 1.0                     # timed: time compression
        self.day_profile: Optional[str] = None   # None = the env's, else flat
        self.min_period = 0.0
        self.duration = 0.0                  # timed: simulated seconds (0 = no end)
        self.clock = "wall"                  # wall | synthetic
        self.start_time: Optional[str] = None    # synthetic clock start
        self.seed: Optional[int] = None      # None = a fresh random seed per run
        self.manifest: Optional[str] = None  # run manifest path
        self.api: Optional[str] = None       # control API [HOST:]PORT when on
        # replay extras
        self.replay_speed = 0.0              # 0 = paced by Rate
        self.replay_loop = 0                 # passes (0 = until stopped)
        self.replay_vlan: Optional[int] = None   # None keep, 0 untag, N retag
        self.remap: Dict[str, str] = {"ip": "", "subnet": "", "mac": ""}
        # live injection defaults
        self.inject_duration = 60.0
        self.phases = None                   # campaign phases of the last start
        self._plans: Dict[str, tuple] = {}   # plan path -> (plan, error)
        # Traffic tab
        self.fam_open: Dict[str, bool] = {}  # family -> folded open (override)
        self.proto_filter = ""

        self.focus = 0                 # index into PANELS
        self.row = 0                   # selected (visible) row within panel
        self.frame = 0                 # animation tick
        self.help_open = False
        self.quit_armed = False        # q pressed once while generating
        self._warned_restart = False
        self._load_service_config()

    # -- helpers -----------------------------------------------------------
    def add_log(self, msg: str):
        """Append a log line — safe from the engine / API threads."""
        line = f"{time.strftime('%H:%M:%S')} {msg}"
        with self._log_lock:
            self.log.append(line)
            del self.log[:-300]

    def log_lines(self) -> List[str]:
        """A snapshot of the log for drawing."""
        with self._log_lock:
            return list(self.log)

    def clear_log(self):
        with self._log_lock:
            self.log.clear()

    def running(self) -> bool:
        return bool(self.engine and self.engine.is_alive())

    def paused(self) -> bool:
        return self.running() and self.engine.control.paused

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
        if self.api_server is not None and not self.running():
            self.close_api()

    def close_api(self):
        if self.api_server is not None:
            self.api_server.close()
            self.api_server = None
            self.add_log("control API closed")

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

    def send_ifaces(self) -> List[str]:
        """Every interface a run sends on: the send interface, then the
        fan-out extras."""
        if not self.send_iface:
            return []
        return [self.send_iface] + [n for n in self.extra_ifaces
                                    if n != self.send_iface]

    def iface_spec(self) -> Optional[str]:
        """``--iface`` value: ``a`` or ``a,b,c`` (fan-out); None = pcap only."""
        return ",".join(self.send_ifaces()) or None

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
            names = [n for n in cfg["TGT_IFACE"].split(",") if n]
            if names:
                self.send_iface, self.extra_ifaces = names[0], names[1:]

    # -- mode --------------------------------------------------------------
    def mode(self) -> str:
        return ("replay" if self.replay else "campaign" if self.campaign else
                "incident" if self.incident else
                "env" if self.env else "scenario" if self.scenario else "custom")

    def timed(self) -> bool:
        """The timed scheduler runs (a timed schedule, or any campaign)."""
        m = self.mode()
        return m == "campaign" or (self.schedule == "timed" and m != "replay")

    def _clear_modes(self):
        if self.campaign and self.schedule == "cycle":
            self.rate = self._cycle_rate or 20.0   # leaving a campaign
        self.scenario = self.env = self.incident = self.replay = None
        self.campaign = None

    def plan(self, path: Optional[str] = None):
        """(Plan, error) for a campaign file (cached; error is a string)."""
        path = path or self.campaign
        if not path:
            return None, "no campaign"
        if path not in self._plans:
            from . import campaign as camp
            try:
                plan = camp.load(path)
                # the env must resolve too (an env_file is loaded once here)
                self._plans[path] = (plan, None, plan.base_env())
            except Exception as e:  # noqa: BLE001 - shown, never fatal
                self._plans[path] = (None, str(e), None)
        return self._plans[path][:2]

    def campaign_env(self):
        """The campaign plan's base environment (None when it fails)."""
        if not self.campaign:
            return None
        self.plan()
        return self._plans[self.campaign][2]

    def preset_protocols(self) -> Optional[List[str]]:
        """Registry protocols the current preset generates (None for a custom
        mix or a pcap replay, whose protocols are the selection / the file)."""
        if self.campaign:
            env = self.campaign_env()
            return env.protocols() if env is not None else None
        if self.scenario:
            return list(scenarios.get(self.scenario).profiles)
        if self.env:
            return enterprise.get(self.env).protocols()
        if self.incident:
            return incidents.get(self.incident).protocols()
        return None

    def preset_extras(self) -> List[str]:
        """Attack-only traffic an incident preset adds (no registry protocol)."""
        return incidents.get(self.incident).attack_only() if self.incident else []

    def _adopt_preset_protocols(self):
        """Show the preset's protocols on the Traffic tab — and start a custom
        mix from them if you toggle one."""
        protos = self.preset_protocols()
        if protos is not None:
            self.selected = protos

    def set_scenario(self, key: Optional[str]):
        self._clear_modes()
        self.scenario = key
        self._adopt_preset_protocols()

    def set_env(self, key: Optional[str]):
        self._clear_modes()
        self.env = key
        self._adopt_preset_protocols()

    def set_incident(self, key: Optional[str]):
        self._clear_modes()
        self.incident = key
        self._adopt_preset_protocols()

    def set_replay(self, path: str):
        self._clear_modes()
        self.replay = path

    def set_campaign(self, path: Optional[str]) -> bool:
        """Switch to campaign mode on a plan file (None = off). False (and
        a log line) when the plan does not load."""
        if not path:
            if self.campaign:
                env = self.campaign_env_key
                self._clear_modes()
                if env:
                    self.set_env(env)       # stay on the plan's environment
            return True
        plan, err = self.plan(path)
        if plan is None:
            self.add_log(f"campaign not loaded: {err}")
            return False
        self._clear_modes()
        if self.schedule == "cycle":      # timed: the rate becomes a cap
            self._cycle_rate, self.rate = self.rate, 0.0
        self.campaign = path
        self.campaign_env_key = plan.env_key
        self._adopt_preset_protocols()
        return True

    def set_schedule(self, sched: str):
        if sched == self.schedule:
            return
        if sched == "timed":            # the rate becomes a cap: none by default
            self._cycle_rate, self.rate = self.rate, 0.0
        else:
            self.rate = self._cycle_rate or 20.0
        self.schedule = sched

    def toggle_proto(self, key: str):
        if key in self.selected:
            self.selected.remove(key)
        else:
            self.selected.append(key)
        self._clear_modes()             # manual edit => custom protocols

    def family_open(self, fam: str) -> bool:
        if fam in self.fam_open:
            return self.fam_open[fam]
        return any(proto_family(protocols.get(k)) == fam
                   for k in self.selected if k in protocols.PROFILES)

    def sprinkle_list(self) -> List[str]:
        # random picks from all incidents (variant ignored); else the chosen one
        if self.sprinkle_on and not self.sprinkle_random:
            return [self.sprinkle_variant]
        return []

    def remap_list(self, kind: str) -> List[str]:
        v = self.remap.get(kind, "").strip()
        return [v] if v else []

    def build_config(self) -> RunConfig:
        """The run the current selection describes (campaign mode: as
        ``tgt campaign`` would run it; raises CampaignError / EnvFileError
        for a plan that does not load)."""
        if self.campaign:
            return self._campaign_config()
        timed = self.schedule == "timed" and not self.replay
        replay = bool(self.replay)
        return RunConfig(
            profiles=list(self.selected) or ["modbus"], env=self.env,
            span=self.span, incident=self.incident,
            sprinkle=self.sprinkle_list(),
            sprinkle_random=self.sprinkle_on and self.sprinkle_random,
            sprinkle_ratio=self.sprinkle_ratio if self.sprinkle_on else 0.0,
            replay_path=self.replay,
            iface=self.iface_spec(), pcap_path=self.pcap,
            rate=self.rate, messages=self.messages, loop=self.loop,
            duration=self.duration if timed else 0.0,
            endpoints=self.ep, seed=self.seed, manifest_path=self.manifest,
            clock=self.clock,
            start_time=self.start_time if self.clock == "synthetic" else None,
            schedule="timed" if timed else "cycle", speed=self.speed,
            day_profile=self.day_profile if timed else None,
            min_period=self.min_period if timed else 0.0,
            replay_speed=self.replay_speed if replay else 0.0,
            replay_loop=self.replay_loop if replay else 0,
            remap_ip=self.remap_list("ip") if replay else [],
            remap_subnet=self.remap_list("subnet") if replay else [],
            remap_mac=self.remap_list("mac") if replay else [],
            replay_vlan=self.replay_vlan if replay else None)

    def _campaign_config(self) -> RunConfig:
        """As cli.cmd_campaign: load + build the phases (handed to the
        engine via campaign.remember), the plan's env/span/day profile."""
        from . import campaign as camp
        from . import envfile
        plan = camp.load(self.campaign)
        base = plan.base_env()
        if plan.env_file:
            envfile.register(base)
        phases = camp.build(plan)
        camp.remember(self.campaign, phases)
        self.phases = phases
        seed = self.seed if self.seed is not None else plan.seed
        return RunConfig(
            env=base.key, span=plan.span, iface=self.iface_spec(),
            pcap_path=self.pcap, rate=self.rate, duration=0.0,
            sprinkle_messages=plan.sprinkle_messages, seed=seed,
            manifest_path=self.manifest, clock=self.clock,
            start_time=(self.start_time if self.clock == "synthetic" else
                        None) or plan.start_time,
            schedule="timed", speed=self.speed, day_profile=plan.day_profile,
            min_period=self.min_period, campaign=self.campaign,
            force=self.campaign_force)

    def service_command(self) -> str:
        """The tgt subcommand the service runs for this selection."""
        return "campaign" if self.campaign else "run"

    def run_args(self) -> str:
        """The same selection as `tgt run` (or, in campaign mode, `tgt
        campaign`) arguments for the service."""
        synthetic = self.clock == "synthetic"
        if self.campaign:
            return service.build_campaign_args(
                self.campaign, rate=self.rate, seed=self.seed,
                manifest=self.manifest, clock=self.clock,
                start_time=self.start_time if synthetic else None,
                speed=self.speed, min_period=self.min_period, pcap=self.pcap,
                api=self.api, force=self.campaign_force)
        timed = self.schedule == "timed" and not self.replay
        return service.build_run_args(
            self.scenario, self.selected, self.rate, self.messages,
            env=self.env, incident=self.incident, replay=self.replay,
            sprinkle=self.sprinkle_list() or None,
            sprinkle_random=self.sprinkle_on and self.sprinkle_random,
            sprinkle_ratio=self.sprinkle_ratio if self.sprinkle_on else 0.0,
            span=self.span, pcap=self.pcap, once=not self.loop and not timed,
            client_ip=self.ep.client_ip, server_ip=self.ep.server_ip,
            seed=self.seed, manifest=self.manifest,
            schedule="timed" if timed else "cycle", speed=self.speed,
            day_profile=self.day_profile, min_period=self.min_period,
            duration=self.duration if timed else 0.0, clock=self.clock,
            start_time=self.start_time if synthetic else None, api=self.api,
            replay_speed=self.replay_speed, replay_loop=self.replay_loop,
            remap_ip=self.remap_list("ip"),
            remap_subnet=self.remap_list("subnet"),
            remap_mac=self.remap_list("mac"), vlan=self.replay_vlan)

    def _check_start(self, cfg: RunConfig) -> Optional[str]:
        """Why ``cfg`` cannot start (None when it can) — the checks the CLI
        makes before running."""
        if cfg.start_time:
            from .manifest import parse_iso
            try:
                parse_iso(cfg.start_time)
            except ValueError:
                return (f"bad start time {cfg.start_time!r}: use ISO-8601, "
                        "e.g. 2026-11-05T14:00:00Z")
        if cfg.replay_path:
            from . import pcapread
            from .replay import rewriter_for
            from .rewrite import RewriteError
            try:
                pcapread.probe(cfg.replay_path)
            except (OSError, pcapread.PcapError) as e:
                return f"cannot replay {cfg.replay_path}: {e}"
            try:
                rewriter_for(cfg)
            except RewriteError as e:
                return str(e)
        if cfg.campaign and self.phases is not None:
            from . import campaign as camp
            problems = camp.validate(self.phases, cfg.min_period)
            if problems and not cfg.force:
                for p in problems:
                    self.add_log(f"campaign: {p}")
                return ("phases too short for fair learning: lengthen them, "
                        "raise Min period, or switch 'skip checks' on")
        return None

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
        try:
            cfg = self.build_config()
        except Exception as e:  # noqa: BLE001 - a bad plan / env file
            self.add_log(f"cannot start: {e}")
            return
        why = self._check_start(cfg)
        if why:
            self.add_log(f"cannot start: {why}")
            return
        self.add_log(f"start: {cfg.summary()}")
        self._warned_restart = False
        argv = ([self.service_command()] +
                (["--iface", cfg.iface] if cfg.iface else []) +
                shlex.split(self.run_args()))
        eng = Engine(cfg, on_log=self.add_log, argv=argv)
        if self.api:
            if not self._start_api(eng):
                return
        self.engine = eng
        eng.start()

    def _start_api(self, eng) -> bool:
        """Serve the control API for ``eng`` (``tgt ctl`` can then drive the
        TUI's run). Token from $TGT_API_TOKEN; loopback unless that is set."""
        from . import api
        self.close_api()
        token = os.environ.get("TGT_API_TOKEN") or None
        try:
            host, port = api.parse_bind(self.api)
            server = api.ControlServer(eng, host, port, token=token,
                                       allow_remote=bool(token))
        except api.ApiError as e:
            self.add_log(f"cannot start: API {e}")
            return False
        eng.record = True             # /manifest + injection records need it
        server.start()
        self.api_server = server
        self.add_log(f"control API on {server.url} — tgt ctl --api "
                     f"{host}:{server.port} status")
        return True

    def inject(self, key: str, duration: Optional[float] = None,
               ratio: Optional[float] = None) -> Tuple[bool, str]:
        """Inject incident ``key`` into the running engine for ``duration``
        seconds (tgt.control — as ``tgt ctl inject``). The share defaults to
        the sprinkle ratio when malware sprinkle is on, else 5%."""
        if not self.running():
            return False, "nothing running — start a run first (s)"
        duration = self.inject_duration if duration is None else duration
        if ratio is None and self.sprinkle_on and self.sprinkle_ratio > 0:
            ratio = self.sprinkle_ratio
        try:
            inj = self.engine.control.inject(key, duration, ratio, via="tui")
        except KeyError:
            return False, f"unknown incident {key}"
        except ValueError as e:
            return False, str(e)
        self.inject_duration = duration
        return True, (f"☣ injecting {key} for {duration:g}s "
                      f"({inj.id}, {inj.ratio:.0%} of frames)")

    def injections(self) -> List[dict]:
        """Pending/active injections of the current run (for the ENGINE box)."""
        if not self.engine:
            return []
        return [i for i in self.engine.control.status()
                if i["state"] in ("pending", "active")]

    def toggle_pause(self) -> str:
        if not self.running():
            return "nothing running"
        ctl = self.engine.control
        if ctl.paused:
            ctl.resume()
            return "resumed"
        ctl.pause()
        return "paused — p resumes"

    def campaign_progress(self) -> Optional[dict]:
        """Where a campaign run is: phase index/name, simulated time left in
        the phase (and wall time at the run's speed), change events so far."""
        phases = self.phases
        s = self.stats()
        if not phases or s is None or not self.engine.cfg.campaign:
            return None
        i = max(1, min(s.cycles or 1, len(phases))) - 1
        start = sum(p.duration for p in phases[:i])
        ph = phases[i]
        left = max(0.0, start + ph.duration - s.sim_time)
        cfg = self.engine.cfg
        wall = (left if cfg.clock == "synthetic" and not cfg.iface else
                left / (cfg.speed or 1.0))
        return {"index": i + 1, "count": len(phases), "id": ph.id,
                "name": ph.name, "left": left, "wall_left": wall,
                "events": sum(len(p.events) for p in phases[:i + 1]),
                "total": sum(p.duration for p in phases)}

    def export_inventory(self, base: str) -> List[str]:
        """Write ``tgt inventory`` ground truth for the selected environment
        as ``<base>.csv`` and ``<base>.json`` (with the sprinkled incident's
        assets when malware sprinkle is on). Returns the paths written."""
        from . import inventory
        key = self.env or self.campaign_env_key
        env = (self.campaign_env() if self.campaign else
               enterprise.get(key) if key else None)
        if env is None:
            raise ValueError("no environment selected")
        for ext in (".csv", ".json"):
            if base.endswith(ext):
                base = base[:-len(ext)]
        out = []
        sprinkle = self.sprinkle_list()
        d = os.path.dirname(base)
        if d:
            os.makedirs(d, exist_ok=True)
        for ext, write in ((".csv", inventory.write_csv),
                           (".json", inventory.write_json)):
            path = base + ext
            with open(path, "w", newline="", encoding="utf-8") as f:
                write(env, f, sprinkle)
            out.append(path)
        return out

    def findings(self) -> List[dict]:
        """Planted findings of the selected environment (ground truth a
        monitor should flag)."""
        if self.campaign:
            env = self.campaign_env()
        else:
            env = enterprise.get(self.env) if self.env else None
        return list(getattr(env, "findings", None) or []) if env else []

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
def _snap(d: dict) -> dict:
    """Copy a dict the engine thread may be growing (a resize mid-copy
    raises RuntimeError; retry)."""
    for _ in range(5):
        try:
            return dict(d)
        except RuntimeError:
            continue
    return {}


def _mix(ui: UI, slots: int) -> Tuple[List[Tuple[str, int]], int, int]:
    """(key, count) rows for the engine box, biggest first, plus the number
    hidden and the total. Malware rows are always kept on screen — a thin
    minority is exactly what you are testing for."""
    s = ui.stats()
    counts = _snap(s.per_profile) if s and s.per_profile else {}
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


def _span(sec: float) -> str:
    """Compact duration: 45s, 12m, 3h05m, 2d04h."""
    sec = int(max(0, sec))
    d, rem = divmod(sec, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    if d:
        return f"{d}d{h:02d}h" if h else f"{d}d"
    if h:
        return f"{h}h{m:02d}m" if m else f"{h}h"
    if m:
        return f"{m}m{s:02d}s" if s else f"{m}m"
    return f"{s}s"


def _engine_idle_lines(ui: UI) -> List[Tuple[str, int]]:
    """What the engine box says before anything has been generated."""
    m = ui.mode()
    if m == "campaign":
        plan, err = ui.plan()
        if plan is None:
            return [("plan error", C_RED)]
        env = ui.campaign_env()
        return [(f"env {env.key if env else '?'}", C_DIM),
                (f"{len(plan.phases)} phases", C_DIM),
                (f"{_span(plan.duration)} simulated", C_DIM)]
    if m == "env":
        e = enterprise.get(ui.env)
        out = [(f"{len(e.hosts)} hosts", C_DIM),
               (f"{len(e.segments)} VLANs", C_DIM),
               (f"{len(e.conversations)} flows", C_DIM),
               (f"{len(e.protocols())} protocols", C_DIM)]
        if e.findings:
            out.append((f"{len(e.findings)} planted findings", C_YELLOW))
        return out
    if m == "incident":
        return ([(k, C_DIM) for k in ui.preset_protocols()] +
                [(f"☣ {a}", C_RED) for a in ui.preset_extras()])
    if m == "replay":
        return [(_fit(os.path.basename(ui.replay), 30), C_DIM)]
    return [(k, C_DIM) for k in ui.selected] or [("no protocols", C_DIM)]


Line = Tuple[str, int]                     # (text, curses attribute)
Node = Tuple[int, str, str, List[Line]]    # (colour, title, short name, lines)
Link = Tuple[str, bool, bool]              # (label, dotted, animated)


def _engine_extra_lines(ui: UI) -> List[Line]:
    """Live state above the traffic mix: campaign phase progress, the
    simulated clock of a timed run, and active injections."""
    out: List[Line] = []
    s = ui.stats()
    prog = ui.campaign_progress()
    if prog:
        out.append((f"▸ {prog['index']}/{prog['count']} {prog['name']}",
                    _cattr(C_CYAN, curses.A_BOLD)))
        out.append((f"  {_span(prog['wall_left'])} left · "
                    f"{prog['events']} ev", _cattr(C_CYAN)))
    elif ui.running() and ui.engine.cfg.schedule == "timed":
        sp = ui.engine.cfg.speed or 1.0
        out.append((f"sim {_span(s.sim_time)}"
                    + (f" ×{sp:g}" if sp != 1 else ""), _cattr(C_CYAN)))
    for inj in ui.injections():
        left = (f" {_span(inj['remaining'])}" if "remaining" in inj
                else " queued")
        out.append((f"⚡{inj['incident']}{left}",
                    _cattr(C_RED, curses.A_BOLD)))
    return out


def _diagram_height(ui: UI, H: int, top: int, others: int) -> int:
    """Box height: just enough for the engine's content (header, live
    state, traffic mix or idle summary, status) and the tallest other box,
    capped by the terminal."""
    s = ui.stats()
    n = len(s.per_profile) if s and s.per_profile else \
        len(_engine_idle_lines(ui))
    headers = 1 + (ui.sprinkle_on and ui.mode() not in ("replay", "campaign"))
    headers += len(_engine_extra_lines(ui))
    want = max(6, headers + n + 1, others) + 2
    return max(7, min(want, 16, H - top - 15))


def _engine_lines(ui: UI, rows: int, inner: int) -> List[Line]:
    """Mode header, malware badge, live state (campaign phase, sim clock,
    injections), traffic mix (or idle summary); the status line is always
    the last row."""
    s = ui.stats()
    m = ui.mode()
    if m == "campaign":
        plan, _ = ui.plan()
        name = plan.name if plan else os.path.basename(ui.campaign)
    head = {"env": (f"env {ui.env}", C_GREEN),
            "incident": (f"☣ {ui.incident}", C_RED),
            "replay": ("⟳ replay", C_YELLOW),
            "campaign": (f"⧗ {name}" if m == "campaign" else "", C_CYAN),
            "scenario": (f"scenario {ui.scenario}", C_CYAN),
            "custom": (f"{len(ui.selected)} protocols", C_CYAN)}[m]
    out: List[Line] = [(head[0], _cattr(head[1], curses.A_BOLD))]
    if ui.sprinkle_on and m not in ("replay", "campaign"):
        v = "random" if ui.sprinkle_random else ui.sprinkle_variant
        out.append((f"☣ +{v}", _cattr(C_RED, curses.A_BOLD)))
    out += _engine_extra_lines(ui)
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
    if ui.paused():
        out.append((f"‖ paused  {_clock(s.elapsed)}",
                    _cattr(C_YELLOW, curses.A_BOLD)))
    elif ui.running():
        out.append((f"{s.recent_pps:6.1f} pps  {_clock(s.elapsed)}",
                    _cattr(C_GREEN, curses.A_BOLD)))
    else:
        out.append(("idle — press s" if s is None else "stopped",
                    _cattr(C_DIM)))
    return out


def _counter_lines(ui: UI) -> List[Line]:
    s = ui.stats()
    errs = s.errors if s else 0
    mbps = s.rolling()[1] if s and ui.running() else (s.mbps if s else 0)
    out = [(f"{s.packets if s else 0:,} pkts", _cattr(C_CYAN)),
           (f"{_human(s.bytes if s else 0)} {mbps:.2f}Mb/s",
            _cattr(C_DIM)),
           (f"errors {errs}", _cattr(C_RED if errs else C_DIM,
                                     curses.A_BOLD if errs else 0))]
    if s and s.cycle_frames:
        out.append((f"{s.cycle_frames:,} /cycle", _cattr(C_DIM)))
    return out


def _per_iface_lines(ui: UI) -> List[Line]:
    """Fan-out: one compact counter line per send interface."""
    s = ui.stats()
    counters = _snap(s.per_iface) if s and s.per_iface else {}
    out: List[Line] = []
    for name in ui.send_ifaces():
        c = counters.get(name) or {}
        errs = c.get("errors", 0)
        st = ui.iface_state(name)[0][:1] or "?"
        text = f"{st} {name}  {c.get('packets', 0):,}"
        if errs:
            text += f" ✕{errs}"
        out.append((text, _cattr(C_RED if errs else C_CYAN)))
    return out


def _tagging_lines(ui: UI) -> List[Line]:
    if ui.mode() == "env":
        e = enterprise.get(ui.env)
        out = [(f"SPAN {ui.span}", _cattr(C_YELLOW)),
               (f"{len(e.segments)} VLANs tagged", _cattr(C_DIM))]
        if ui.span == "core":
            out.append(("+ routed hops", _cattr(C_DIM)))
        return out
    if ui.mode() == "replay" and ui.replay_vlan is not None:
        return [("untagged" if ui.replay_vlan == 0 else
                 f"retag VLAN {ui.replay_vlan}", _cattr(C_YELLOW))]
    return [("untagged", _cattr(C_DIM))]


def _diagram_nodes(ui: UI) -> Tuple[List[Node], List[Link]]:
    """The boxes after the engine, and the links between all boxes, for how
    frames reach the sensor (see :meth:`UI.link_kind`):

    veth  ENGINE ─▶ SEND ─▶ MONITOR (peer) ─▶ SENSOR
    nic   ENGINE ─▶ SEND ┈▶ SENSOR    (a switch / vSwitch SPAN mirrors it)
    pcap  ENGINE ─▶ PCAP ┈▶ SENSOR    (imported offline — never animated)

    With fan-out (several send interfaces) the SEND box lists each one with
    its own counters; the rest of the path follows the first.
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
    fan = ui.send_ifaces()
    st, col = ui.iface_state(send)
    if len(fan) > 1:                     # fan-out: compact, one line each
        box = [(f"fan-out ×{len(fan)}", _cattr(C_CYAN, curses.A_BOLD))]
        box += _per_iface_lines(ui)
        if pcap:
            box.append(("+ " + pcap, _cattr(C_DIM)))
        counters = _counter_lines(ui)          # pkts, bytes, errors, …
        box += [counters[1]] + ([counters[2]] if ui.stats() and
                                ui.stats().errors else [])
        short = f"{send}+{len(fan) - 1}"
    else:
        box = [(send, _cattr(C_CYAN, curses.A_BOLD)),
               (f"{st} · {'veth' if kind == 'veth' else 'interface'}",
                _cattr(col))]
        if pcap:
            box.append(("+ " + pcap, _cattr(C_DIM)))
        box += _counter_lines(ui)
        short = send
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
        return ([(C_CYAN, "SEND", short, box),
                 (C_YELLOW, "MONITOR", peer or "peer", mon),
                 (C_MAGENTA, "SENSOR", ui.sensor_label, sensor)],
                [("emit", False, running), ("veth", False, running),
                 ("ingest", False, running and peer is not None)])
    # a real interface: something outside this host must mirror it
    up = ui.iface_state(send)[0].startswith("●")
    sensor = [label, ("gets a SPAN of", _cattr(C_DIM)),
              (send, _cattr(C_MAGENTA))] + _tagging_lines(ui)
    return ([(C_CYAN, "SEND", short, box),
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
    pps = s.recent_pps if s and ui.running() and not ui.paused() else 0.0
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


def _strip_info(ui: UI) -> str:
    """The narrow-terminal counters line."""
    s = ui.stats()
    if not s:
        return "idle — press s to start"
    info = (f"{s.packets:,} pkts · "
            f"{s.recent_pps if ui.running() else s.pps:.1f} pps · "
            f"{_human(s.bytes)} · errors {s.errors}")
    if ui.paused():
        info = "paused · " + info
    prog = ui.campaign_progress()
    if prog:
        info += f" · phase {prog['index']}/{prog['count']} {prog['name']}"
    inj = ui.injections()
    if inj:
        info += " · ⚡" + ",".join(i["incident"] for i in inj)
    return info


def _draw_strip(win, ui: UI, top: int, w: int, nodes: List[Node],
                links: List[Link]) -> int:
    """Narrow terminals: the same flow as one line plus a counters line."""
    x = 2
    parts = [("ENGINE", C_GREEN)]
    for (color, _title, short, _lines), (_l, dotted, _a) in zip(nodes, links):
        parts += [(" ┈▶ " if dotted else " ━▶ ", C_DIM), (short, color)]
    for text, col in parts:
        _put(win, top + 1, x, text, _cattr(col, curses.A_BOLD))
        x += len(text)
    _put(win, top + 2, 2, _fit(_strip_info(ui), w - 4),
         _cattr(C_GREEN if ui.running() else C_DIM))
    return top + 4


# ── panel model ─────────────────────────────────────────────────────────────
class Field:
    """One row of a panel: a label, a live value, what the keys do, help.

    ``ident`` keeps the cursor on the row when labels change (Traffic rows);
    ``path`` truncates the value from the left; ``long_help`` lets the help
    area grow (a list of findings)."""

    def __init__(self, label: str, value: Callable[[UI], Value],
                 act: Optional[Callable] = None, help: Union[str, Callable] = "",
                 show: Optional[Callable[[UI], bool]] = None,
                 toggle: bool = False, keys: str = "",
                 space: Optional[Callable] = None, ident: str = "",
                 path: bool = False, long_help: bool = False):
        self.label = label
        self.value = value
        self.act = act                  # act(stdscr, ui, step): step -1/+1/0
        self._help = help
        self.show = show or (lambda ui: True)
        self.toggle = toggle            # Space activates it
        self.space = space              # or does this instead
        self.keys = keys or ("Space toggle" if toggle else
                             "Enter run" if act else "")
        self.ident = ident or label
        self.path = path
        self.long_help = long_help

    def help(self, ui: UI) -> str:
        return self._help(ui) if callable(self._help) else self._help


def _cycle(seq: list, cur, step: int):
    try:
        i = seq.index(cur)
    except ValueError:
        i = -1 if step >= 0 else 0
    return seq[(i + (step or 1)) % len(seq)]


def _step(steps: list, cur: float, step: int) -> float:
    """The neighbour of ``cur`` in a sorted ladder (clamped at the ends)."""
    near = min(range(len(steps)), key=lambda i: abs(steps[i] - cur))
    return steps[max(0, min(len(steps) - 1, near + step))]


def _number(stdscr, ui: UI, label: str, cur: str, conv=float):
    """Prompt for a number (None when cancelled or not a number)."""
    v = _prompt(stdscr, label, cur)
    if v is None:
        return None
    try:
        return conv(v)
    except (TypeError, ValueError):
        ui.add_log(f"not a number: {v}")
        return None


def _seconds(stdscr, ui: UI, label: str, cur: float):
    """Prompt for a duration: 90, 30m, 4h, 7d (None when cancelled/bad)."""
    from .timing import parse_duration
    v = _prompt(stdscr, label, f"{cur:g}")
    if v is None:
        return None
    try:
        return parse_duration(v)
    except ValueError as e:
        ui.add_log(f"not a duration: {e}")
        return None


# -- Run panel ---------------------------------------------------------------
def _preset_value(ui: UI) -> Value:
    m = ui.mode()
    if m == "replay":
        return f"⟳ replay {os.path.basename(ui.replay)}", C_YELLOW
    if m == "campaign":
        env = ui.campaign_env()
        return (f"campaign env: {env.key if env else '?'}", C_CYAN)
    if m == "incident":
        return f"☣ incident: {ui.incident}", C_RED
    if m == "env":
        return f"env: {ui.env}", C_GREEN
    if m == "scenario":
        return f"scenario: {ui.scenario}", C_CYAN
    return f"custom mix ({len(ui.selected)} protocols)", 0


def _proto_summary(protos: List[str], extras: List[str] = ()) -> str:
    """'modbus, s7comm + port-scan' — registry protocols, then attack-only."""
    text = ", ".join(protos)
    if extras:
        text += (" + " if text else "") + ", ".join(extras)
    return text or "none"


def _findings_text(findings: List[dict], sep: str = " · ") -> str:
    """'[high] title (HOST1, HOST2) · …' for help / picker descriptions."""
    return sep.join(
        f"[{f.get('severity', '?')}] {f.get('title') or f.get('id')}"
        + (f" ({', '.join(f.get('hosts', [])[:3])})" if f.get("hosts") else "")
        for f in findings)


def env_group(env) -> str:
    """Preset-picker group of an environment: Built-in, Sites (packaged
    tgt/envs/sites), Files (TGT_ENV_PATH / ~/.config/tgt/envs) or
    Plugins."""
    from . import envfile, plugins
    if env.key in plugins.OWNERS.get("environment", {}):
        return "Environments · plugins"
    src = envfile.source_of(env)
    if not src:
        return "Environments · built-in"
    sites = os.path.realpath(envfile.SITES_DIR) + os.sep
    if os.path.realpath(src).startswith(sites):
        return "Environments · sites"
    return "Environments · files"


_ENV_GROUPS = ["Environments · built-in", "Environments · sites",
               "Environments · files", "Environments · plugins"]


def _env_item(e) -> tuple:
    desc = (f"Protocols ({len(e.protocols())}): "
            f"{_proto_summary(e.protocols())}\n{len(e.hosts)} hosts · "
            f"{len(e.segments)} VLANs · {len(e.conversations)} flows. "
            f"{e.desc}")
    if e.findings:
        desc += (f"\nPlanted findings ({len(e.findings)}): "
                 f"{_findings_text(e.findings)}")
    tag = f" · {len(e.findings)} findings" if e.findings else ""
    return (env_group(e), ("e", e.key), f"{e.key:20} {e.name}{tag}", desc)


def _preset_items(ui: UI) -> list:
    items = [("Custom", ("c", None), "custom protocol mix",
              f"Your own selection on the Traffic tab "
              f"({len(ui.selected)} selected).")]
    # descriptions: a "Protocols:" paragraph first, then the prose
    items += [("Scenarios", ("s", s.key), f"{s.key:16} {s.name}",
               f"Protocols: {_proto_summary(s.profiles)}\n{s.desc}")
              for s in scenarios.all_scenarios()]
    envs = [_env_item(e) for e in enterprise.all_environments()]
    for grp in _ENV_GROUPS:              # built-in, sites, files, plugins
        items += [it for it in envs if it[0] == grp]
    items += [("Incidents", ("i", x.key), f"{x.key:16} {x.name} ({x.year})",
               f"Protocols: {_proto_summary(x.protocols(), x.attack_only())}"
               f"\n{x.desc}  Signals: {'; '.join(x.indicators())}"
               f"  ATT&CK: {', '.join(techniques.for_incident(x.key))}")
              for x in incidents.all_incidents()]
    items += [("Replay", ("r", None), "replay a pcap file…",
               "Send the frames of an existing capture (pcap or pcapng) "
               "instead of generating traffic; optionally re-timed, "
               "re-addressed and re-tagged.")]
    return items


def _current_preset(ui: UI):
    m = ui.mode()
    return {"env": ("e", ui.env), "incident": ("i", ui.incident),
            "scenario": ("s", ui.scenario), "replay": ("r", None),
            "campaign": ("c", None), "custom": ("c", None)}[m]


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


# campaign
def _campaign_items(ui: UI) -> list:
    from . import campaign as camp
    items = [("Off", ("off", None), "off — a plain run",
              "Leave campaign mode (the plan's environment stays selected).")]
    for path in camp.packaged():
        plan, err = ui.plan(path)
        if plan is None:
            items.append(("Examples", ("p", path), os.path.basename(path),
                          f"invalid plan: {err}"))
            continue
        phases = ", ".join(f"{p.get('name') or i + 1} "
                           f"{_span(p['duration'])}"
                           for i, p in enumerate(plan.phases))
        items.append(("Examples", ("p", path),
                      f"{plan.name:24} {plan.env_key or 'env file'} · "
                      f"{len(plan.phases)} phases · {_span(plan.duration)}",
                      f"{plan.description}\nPhases: {phases}"))
    items.append(("Browse", ("b", None), "a plan file…",
                  "Type the path of a campaign plan (JSON, or TOML on "
                  "Python 3.11+); see tgt/campaign.py for the schema."))
    return items


def _act_campaign(stdscr, ui: UI, step: int):
    from . import campaign as camp
    if step:
        opts = [None] + camp.packaged()
        path = _cycle(opts, ui.campaign, step)
    else:
        choice = _pick(stdscr, "Campaign — phased run", _campaign_items(ui),
                       ("p", ui.campaign) if ui.campaign else ("off", None))
        if choice is None:
            return
        kind, path = choice
        if kind == "b":
            path = _prompt(stdscr, "Campaign plan path", ui.campaign or "")
            if not path:
                return
            if not os.path.exists(path):
                ui.add_log(f"campaign plan not found: {path}")
                return
    if ui.set_campaign(path) and path:
        plan, _ = ui.plan(path)
        ui.add_log(f"campaign {plan.name}: {len(plan.phases)} phases, "
                   f"{_span(plan.duration)} simulated")


def _campaign_value(ui: UI) -> Value:
    if not ui.campaign:
        return "off", C_DIM
    plan, err = ui.plan()
    if plan is None:
        return f"✕ {os.path.basename(ui.campaign)}", C_RED
    return (f"⧗ {plan.name} · {len(plan.phases)} phases · "
            f"{_span(plan.duration)}", C_CYAN)


def _campaign_help(ui: UI) -> str:
    base = ("A phased run on the timed scheduler: a learning baseline, then "
            "planned changes (new device, firmware, IP move, an intrusion "
            "window) with the change events recorded in the manifest. The "
            "ENGINE box shows the phase, time left and events so far.")
    if not ui.campaign:
        return base
    plan, err = ui.plan()
    if plan is None:
        return f"Plan error: {err}"
    phases = " → ".join(f"{p.get('name') or i + 1} ({_span(p['duration'])})"
                        for i, p in enumerate(plan.phases))
    return f"{plan.description or plan.name}  Phases: {phases}"


def _act_force(stdscr, ui: UI, step: int):
    ui.campaign_force = not ui.campaign_force


def _act_span(stdscr, ui: UI, step: int):
    ui.span = "core" if ui.span == "access" else "access"


def _act_sprinkle(stdscr, ui: UI, step: int):
    ui.sprinkle_on = not ui.sprinkle_on
    ui.add_log(f"malware sprinkle "
               f"{'ON: ' + ui.sprinkle_variant if ui.sprinkle_on else 'off'}")


def _variant_items() -> list:
    return [(x.category, x.key, f"{x.key:14} {x.name} ({x.year})",
             f"Protocols: {_proto_summary(x.protocols(), x.attack_only())}"
             f"\n{x.desc}  Signals: {'; '.join(x.indicators())}"
             f"  ATT&CK: {', '.join(techniques.for_incident(x.key))}")
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
        ui.sprinkle_ratio = _step(RATIO_STEPS, ui.sprinkle_ratio, step)
        return
    v = _number(stdscr, ui, "Malware fraction 0–0.9 (0 = natural minority)",
                f"{ui.sprinkle_ratio:g}")
    if v is not None:
        ui.sprinkle_ratio = min(0.9, max(0.0, v))


def _act_rate(stdscr, ui: UI, step: int):
    if step:
        steps = RATE_STEPS
        cur = 0 if ui.rate == 0 else min(steps[:-1],
                                         key=lambda r: abs(r - ui.rate))
        i = max(0, min(len(steps) - 1, steps.index(cur) + step))
        ui.rate = float(steps[i])
        return
    v = _number(stdscr, ui, "Packets per second (0 = as fast as possible)"
                if not ui.timed() else "Packet-rate cap (0 = none)",
                f"{ui.rate:g}")
    if v is not None:
        ui.rate = max(0.0, v)


def _rate_value(ui: UI) -> Value:
    if ui.timed():
        return (f"cap {ui.rate:g} pps", 0) if ui.rate else ("no cap", C_DIM)
    return f"{ui.rate:g} pps" if ui.rate else ("max", C_YELLOW)


def _rate_help(ui: UI) -> str:
    if ui.timed():
        return ("A cap only: the timed scheduler sends each conversation on "
                "its own period, so the rate follows the plant (0 = no cap).")
    return "Packets per second (0 = as fast as the system allows)."


def _act_msgs(stdscr, ui: UI, step: int):
    if step:
        ui.messages = max(1, ui.messages + step)
        return
    v = _number(stdscr, ui, "Protocol exchanges per flow per cycle",
                str(ui.messages), int)
    if v is not None:
        ui.messages = max(1, v)


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


# schedule / time model
def _act_schedule(stdscr, ui: UI, step: int):
    ui.set_schedule("cycle" if ui.schedule == "timed" else "timed")


def _act_speed(stdscr, ui: UI, step: int):
    if step:
        ui.speed = float(_step(SPEED_STEPS, ui.speed, step))
        return
    v = _number(stdscr, ui, "Speed: run X times faster than real time",
                f"{ui.speed:g}")
    if v is not None and v > 0:
        ui.speed = v


def _speed_value(ui: UI) -> Value:
    if ui.speed == 1:
        return "real time (×1)", C_DIM
    hour = 3600 / ui.speed
    per = (f"an hour per {hour:g}s" if hour < 60 else
           f"an hour per {hour / 60:g}m")
    return f"×{ui.speed:g} — {per}", C_CYAN


def _env_day_profile(ui: UI) -> Optional[str]:
    key = ui.env
    env = enterprise.get(key) if key else None
    return env.options.get("day_profile") if env is not None else None


def _act_day(stdscr, ui: UI, step: int):
    ui.day_profile = _cycle([None, "flat", "shift"], ui.day_profile, step)


def _day_value(ui: UI) -> Value:
    if ui.day_profile:
        return ui.day_profile, C_CYAN
    return f"env default ({_env_day_profile(ui) or 'flat'})", C_DIM


def _act_min_period(stdscr, ui: UI, step: int):
    if step:
        ui.min_period = float(_step(MIN_PERIOD_STEPS, ui.min_period, step))
        return
    v = _seconds(stdscr, ui, "Min period: no conversation recurs faster "
                 "(e.g. 5, 30s, 1m)", ui.min_period)
    if v is not None:
        ui.min_period = max(0.0, v)


def _act_duration(stdscr, ui: UI, step: int):
    if step:
        ui.duration = float(_step(DURATION_STEPS, ui.duration, step))
        return
    v = _seconds(stdscr, ui, "Simulated duration (0 = until stopped; e.g. "
                 "30m, 4h, 7d)", ui.duration)
    if v is not None:
        ui.duration = max(0.0, v)


def _act_clock(stdscr, ui: UI, step: int):
    ui.clock = "wall" if ui.clock == "synthetic" else "synthetic"


def _act_start(stdscr, ui: UI, step: int):
    from .manifest import parse_iso
    if step:                              # ±1 hour (from now when unset)
        try:
            base = parse_iso(ui.start_time) if ui.start_time else \
                float(int(time.time()) // 3600 * 3600)
        except ValueError:
            base = float(int(time.time()) // 3600 * 3600)
        ui.start_time = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                      time.gmtime(base + 3600 * step))
        return
    v = _prompt(stdscr, "Synthetic clock start, ISO-8601 (- = now)",
                ui.start_time or "")
    if not v or _cleared(v):
        ui.start_time = None if _cleared(v) else ui.start_time
        return
    try:
        parse_iso(v)
        ui.start_time = v
    except ValueError:
        ui.add_log(f"not an ISO-8601 time: {v} (e.g. 2026-11-05T14:00:00Z)")


def _act_start_clear(stdscr, ui: UI, step: int):
    ui.start_time = None


def _seed_value(ui: UI) -> Value:
    s = ui.stats()
    live = (f" · in use {s.seed}" if s is not None and s.seed is not None
            and (ui.running() or ui.seed is None) else "")
    if ui.seed is None:
        return f"random{live}", C_DIM
    return f"{ui.seed}{' (in use)' if live and ui.running() else ''}", C_CYAN


def _act_seed(stdscr, ui: UI, step: int):
    if step:
        if ui.seed is None:
            _act_seed_toggle(stdscr, ui, 0)
        else:
            ui.seed = max(0, ui.seed + step)
        return
    v = _prompt(stdscr, "Run seed (- = random each run)",
                "" if ui.seed is None else str(ui.seed))
    if not v or _cleared(v):
        ui.seed = None if _cleared(v) else ui.seed
        return
    try:
        ui.seed = max(0, int(v))
    except ValueError:
        ui.add_log(f"not a whole number: {v}")


def _act_seed_toggle(stdscr, ui: UI, step: int):
    """Space: random <-> fixed (keeps the last run's seed so you can redo
    exactly that run)."""
    if ui.seed is not None:
        ui.seed = None
        return
    s = ui.stats()
    if s is not None and s.seed is not None:
        ui.seed = s.seed
    else:
        from .engine import new_seed
        ui.seed = new_seed()


def default_manifest(ui: UI) -> str:
    """Where a manifest goes when switched on: next to the pcap, else
    ./tgt-manifest.json (absolute, so the service writes the same file)."""
    if ui.pcap:
        return os.path.abspath(os.path.splitext(ui.pcap)[0] + ".manifest.json")
    return os.path.abspath("tgt-manifest.json")


def _act_manifest(stdscr, ui: UI, step: int):
    if step:
        _act_manifest_toggle(stdscr, ui, 0)
        return
    v = _prompt(stdscr, "Write the run manifest (JSON ground truth) to "
                "(- = off)", ui.manifest or default_manifest(ui))
    if v:
        ui.manifest = None if _cleared(v) else v


def _act_manifest_toggle(stdscr, ui: UI, step: int):
    ui.manifest = None if ui.manifest else default_manifest(ui)


def _act_api(stdscr, ui: UI, step: int):
    if step:
        _act_api_toggle(stdscr, ui, 0)
        return
    from . import api
    v = _prompt(stdscr, "Control API [HOST:]PORT (- = off)",
                ui.api or DEFAULT_API)
    if not v or _cleared(v):
        ui.api = None if _cleared(v) else ui.api
        return
    try:
        api.parse_bind(v)
        ui.api = v
    except api.ApiError as e:
        ui.add_log(f"API: {e}")


def _act_api_toggle(stdscr, ui: UI, step: int):
    ui.api = None if ui.api else DEFAULT_API


def _api_value(ui: UI) -> Value:
    if not ui.api:
        return "off", C_DIM
    if ui.api_server is not None:
        return f"● {ui.api_server.url}", C_GREEN
    return ui.api, C_CYAN


def _api_help(ui: UI) -> str:
    where = ui.api_server.url if ui.api_server else (ui.api or DEFAULT_API)
    host = where.split("//")[-1]
    return (f"Serve the control API while running so scripts and `tgt ctl` "
            f"drive this run: tgt ctl --api {host} status | pause | inject "
            f"<incident> | stop. Loopback only; set TGT_API_TOKEN to require "
            f"a bearer token.")


# replay extras
def _act_replay_speed(stdscr, ui: UI, step: int):
    if step:
        ui.replay_speed = float(_step(REPLAY_SPEED_STEPS, ui.replay_speed,
                                      step))
        return
    v = _number(stdscr, ui, "Replay at capture timing ÷ X (0 = paced by Rate)",
                f"{ui.replay_speed:g}")
    if v is not None:
        ui.replay_speed = max(0.0, v)


def _act_replay_loop(stdscr, ui: UI, step: int):
    if step:
        ui.replay_loop = max(0, ui.replay_loop + step)
        return
    v = _number(stdscr, ui, "Passes over the capture (0 = until stopped)",
                str(ui.replay_loop), int)
    if v is not None:
        ui.replay_loop = max(0, v)


def _act_vlan(stdscr, ui: UI, step: int):
    if step:
        ui.replay_vlan = _cycle([None, 0] + ([ui.replay_vlan] if
                                ui.replay_vlan else []), ui.replay_vlan, step)
        return
    v = _prompt(stdscr, "Retag every frame with VLAN id (0 = strip the tag, "
                "- = keep)", "" if ui.replay_vlan is None
                else str(ui.replay_vlan))
    if not v or _cleared(v):
        ui.replay_vlan = None if _cleared(v) else ui.replay_vlan
        return
    try:
        n = int(v)
        if not 0 <= n <= 4094:
            raise ValueError
        ui.replay_vlan = n
    except ValueError:
        ui.add_log(f"not a VLAN id 0–4094: {v}")


def _vlan_value(ui: UI) -> Value:
    if ui.replay_vlan is None:
        return "keep tags", C_DIM
    return ("strip tags", C_YELLOW) if ui.replay_vlan == 0 else \
        (f"retag VLAN {ui.replay_vlan}", C_YELLOW)


_REMAP_HINT = {"ip": ("OLD=NEW[,OLD=NEW…]", "192.168.1.10=10.100.10.10"),
               "subnet": ("A/N=B/N[,…]", "192.168.1.0/24=10.100.10.0/24"),
               "mac": ("OLD=NEW[,…]", "00:1d:9c:00:00:01=02:00:00:00:00:01")}


def _remap_field(kind: str, label: str, what: str) -> Field:
    def act(stdscr, ui, step):
        if step:
            return
        fmt, example = _REMAP_HINT[kind]
        v = _prompt(stdscr, f"Remap {what} {fmt} (- = none)",
                    ui.remap[kind] or "")
        if v:
            ui.remap[kind] = "" if _cleared(v) else v.strip()

    def clear(stdscr, ui, step):
        ui.remap[kind] = ""

    fmt, example = _REMAP_HINT[kind]
    return Field(label, lambda ui: (ui.remap[kind], C_YELLOW) if ui.remap[kind]
                 else ("none", C_DIM), act,
                 f"Rewrite {what} in every replayed frame ({fmt}, e.g. "
                 f"{example}); checksums are recomputed.",
                 show=_is_replay, keys="Enter edit · Space clear", space=clear)


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


# ground truth
def _act_export(stdscr, ui: UI, step: int):
    if step:
        return
    key = ui.env or ui.campaign_env_key or "inventory"
    base = _prompt(stdscr, "Export inventory as <path>.csv + <path>.json",
                   os.path.abspath(f"{key}-inventory"))
    if not base:
        return
    try:
        paths = ui.export_inventory(base)
    except (OSError, ValueError) as e:
        ui.add_log(f"inventory export failed: {e}")
        return
    ui.add_log(f"saved inventory: {', '.join(paths)}")


def _findings_value(ui: UI) -> Value:
    f = ui.findings()
    sev = {}
    for x in f:
        sev[x.get("severity", "?")] = sev.get(x.get("severity", "?"), 0) + 1
    order = ["critical", "high", "medium", "low", "info", "?"]
    parts = [f"{sev[k]} {k}" for k in order if k in sev]
    return f"{len(f)} planted · {', '.join(parts)}", C_YELLOW


def _findings_help(ui: UI) -> str:
    return ("Planted issues a monitor should flag (ground truth in the "
            "inventory JSON):\n• "
            + _findings_text(ui.findings(), "\n• "))


def _manual(ui: UI) -> bool:
    return ui.mode() in ("custom", "scenario")


def _sprinkle_detail(ui: UI) -> bool:
    return ui.sprinkle_on and ui.mode() not in ("replay", "campaign")


def _is_replay(ui: UI) -> bool:
    return ui.mode() == "replay"


def _timed_plain(ui: UI) -> bool:
    """Timed rows a campaign plan sets itself (day profile, duration)."""
    return ui.timed() and ui.mode() != "campaign"


def _has_env(ui: UI) -> bool:
    return ui.mode() == "env" or (ui.mode() == "campaign" and
                                  ui.campaign_env() is not None)


RUN_FIELDS = [
    Field("Preset", _preset_value, _act_preset,
          "Base traffic: a protocol mix, a scenario, a modeled environment "
          "(built-in, packaged site, env file or plugin — hosts, VLANs, "
          "fingerprints), an incident, or a pcap replay.",
          keys="Enter pick · ←→ cycle"),
    Field("Campaign", _campaign_value, _act_campaign, _campaign_help,
          show=lambda ui: ui.mode() != "replay",
          keys="Enter pick · ←→ cycle"),
    Field("  skip checks", lambda ui: _onoff(ui.campaign_force, "on (force)"),
          _act_force,
          "Run even if a phase is shorter than 3× the slowest period its "
          "change involves (a monitor may not have learned the baseline).",
          show=lambda ui: ui.mode() == "campaign", toggle=True),
    Field("SPAN view",
          lambda ui: (f"‹ {ui.span} ›", C_CYAN), _act_span,
          "Where the sensor taps the environment: access = each frame once, on "
          "its sender's VLAN; core = also the router's copy on the receiver's "
          "VLAN (gateway MAC, TTL-1).",
          show=lambda ui: ui.mode() == "env", toggle=True,
          keys="←→/Space switch"),
    Field("Findings", _findings_value, None, _findings_help,
          show=lambda ui: _has_env(ui) and bool(ui.findings()),
          long_help=True),
    Field("Export inventory", lambda ui: ("CSV + JSON — press Enter", C_DIM),
          _act_export,
          "Write the environment's ground truth (`tgt inventory`: assets, "
          "identities, flows, findings; plus the sprinkled incident's hosts) "
          "as <path>.csv and <path>.json for scoring with `tgt score`.",
          show=_has_env),
    Field("Malware sprinkle",
          lambda ui: _onoff(ui.sprinkle_on, "☣ ON", "off"), _act_sprinkle,
          "Mix an attack into the base traffic as a thin minority. On an "
          "environment, its hosts are re-addressed onto real assets of the same "
          "role and vendor.",
          show=lambda ui: ui.mode() not in ("replay", "campaign"),
          toggle=True),
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
          "variant (a few percent). Also the share live injections (i) use.",
          show=_sprinkle_detail, keys="←→ step · Enter type"),
    Field("  replay speed",
          lambda ui: (f"capture timing ÷ {ui.replay_speed:g}", C_CYAN)
          if ui.replay_speed else ("paced by Rate", C_DIM),
          _act_replay_speed,
          "Keep the capture's own packet spacing divided by X (2 = twice as "
          "fast, 0.5 = half speed; long idle gaps are cut to 5 s), or 0 to "
          "send at the Rate below.",
          show=_is_replay, keys="←→ step · Enter type"),
    Field("  passes",
          lambda ui: (str(ui.replay_loop), 0) if ui.replay_loop
          else ("until stopped", C_DIM), _act_replay_loop,
          "Stop after N passes over the capture (0 = loop until stopped; "
          "Loop off = one pass).", show=_is_replay,
          keys="←→ ±1 · Enter type"),
    Field("  VLAN retag", _vlan_value, _act_vlan,
          "Retag every replayed frame onto one 802.1Q VLAN, strip the tags "
          "(0), or keep them as captured.", show=_is_replay,
          keys="←→ cycle · Enter type"),
    _remap_field("ip", "  remap IP", "IPv4 addresses (IP + ARP)"),
    _remap_field("subnet", "  remap subnet", "subnets, keeping host bits,"),
    _remap_field("mac", "  remap MAC", "MAC addresses (Ethernet + ARP)"),
    Field("Schedule",
          lambda ui: (f"‹ {ui.schedule} ›", C_CYAN if ui.schedule == "timed"
                      else 0), _act_schedule,
          "cycle = every conversation once per batch at the Rate; timed = "
          "each conversation on its own period with jitter, request/response "
          "RTT and persistent polling sessions, like a real plant.",
          show=lambda ui: ui.mode() not in ("replay", "campaign"),
          toggle=True, keys="←→/Space switch"),
    Field("  speed", _speed_value, _act_speed,
          "Run the timed schedule X times faster than real time (60 = an "
          "hour per minute) — wall clock; a synthetic-clock pcap-only run "
          "goes as fast as it can anyway.", show=lambda ui: ui.timed(),
          keys="←→ step · Enter type"),
    Field("  day profile", _day_value, _act_day,
          "Diurnal activity: shift = logons ~07:00, lunch dip, backups "
          "~02:00, quiet weekends, OT polling steady; flat = constant.",
          show=_timed_plain, keys="←→/Enter cycle"),
    Field("  min period",
          lambda ui: (f"{_span(ui.min_period)}" if ui.min_period
                      else ("none", C_DIM)), _act_min_period,
          "No conversation recurs faster than this — thins fast pollers and "
          "cyclic I/O for long captures.", show=lambda ui: ui.timed(),
          keys="←→ step · Enter type"),
    Field("  duration",
          lambda ui: (f"{_span(ui.duration)} simulated" if ui.duration
                      else ("until stopped", C_DIM)), _act_duration,
          "Stop after this much simulated time (30m, 4h, 7d); with speed ×60 "
          "a day takes 24 minutes.", show=_timed_plain,
          keys="←→ step · Enter type"),
    Field("Rate", _rate_value, _act_rate, _rate_help,
          keys="←→ step · Enter type"),
    Field("Messages / flow", lambda ui: str(ui.messages), _act_msgs,
          "Protocol exchanges in each flow per cycle. Larger = longer sessions "
          "and a bigger cycle.", keys="←→ ±1 · Enter type",
          show=lambda ui: ui.mode() not in ("replay", "campaign")),
    Field("Loop", lambda ui: _onoff(ui.loop, "repeat", "one cycle"), _act_loop,
          "Rebuild and resend continuously, or send one cycle and stop.",
          toggle=True, show=lambda ui: not ui.timed()),
    Field("Clock",
          lambda ui: (f"‹ {ui.clock} ›", C_CYAN if ui.clock == "synthetic"
                      else 0), _act_clock,
          "Timestamps in the pcap/manifest: wall = real send time; "
          "synthetic = simulated time from a start you choose (a pcap-only "
          "run then skips real-time pacing and finishes fast).",
          toggle=True, keys="←→/Space switch"),
    Field("  start time",
          lambda ui: (ui.start_time, C_CYAN) if ui.start_time
          else ("now", C_DIM), _act_start,
          "When the synthetic clock starts (ISO-8601 UTC, e.g. "
          "2026-11-05T14:00:00Z). ←→ move it by an hour.",
          show=lambda ui: ui.clock == "synthetic",
          keys="Enter type · ←→ ±1h · Space now", space=_act_start_clear),
    Field("Seed", _seed_value, _act_seed,
          "Same seed + same options = the same frames every cycle. Random "
          "picks a fresh one per run (shown here while running); Space keeps "
          "the last run's seed so you can redo it exactly.",
          show=lambda ui: ui.mode() != "replay",
          keys="Enter type · Space random/fixed · ←→ ±1",
          space=_act_seed_toggle),
    Field("Manifest",
          lambda ui: (ui.manifest, C_CYAN) if ui.manifest else ("off", C_DIM),
          _act_manifest,
          "Write the run manifest — JSON ground truth: seed, inventory, first/"
          "last seen per asset and flow, attack/injection/change events — "
          "every ~10 s and at the end, for `tgt score`.",
          keys="Enter path · Space on/off", space=_act_manifest_toggle,
          path=True),
    Field("API", _api_value, _act_api, _api_help,
          keys="Space on/off · Enter address", space=_act_api_toggle),
    Field("PCAP output",
          lambda ui: (ui.pcap, C_CYAN) if ui.pcap else ("off", C_DIM),
          _act_pcap,
          "Also (or only) write every frame to a pcap file — no root needed. "
          "Space switches it off.",
          keys="Enter path · Space on/off", space=_act_pcap_off, path=True),
    Field("Client IP", lambda ui: ui.ep.client_ip, _act_client,
          "Client address for a custom mix or scenario (environments and "
          "incidents bring their own hosts).", show=_manual, keys="Enter edit"),
    Field("Server IP", lambda ui: ui.ep.server_ip, _act_server,
          "Server address for a custom mix or scenario.", show=_manual,
          keys="Enter edit"),
]


# -- Traffic panel -----------------------------------------------------------
def _families(ui: UI) -> List[Tuple[str, str, list, list]]:
    """(family, description, all its protocols, those matching the filter)
    for families with at least one match, in FAMILIES order."""
    by: Dict[str, list] = {}
    for prof in protocols.all_profiles():
        by.setdefault(proto_family(prof), []).append(prof)
    q = ui.proto_filter.lower().strip()
    out = []
    for fam, desc in FAMILIES:
        profs = by.get(fam, [])
        shown = [p for p in profs if not q or q in
                 f"{p.key} {p.name} {p.desc} {p.port}/{p.transport} "
                 f"{fam}".lower()]
        if shown:
            out.append((fam, desc, profs, shown))
    return out


def _traffic_fields(ui: UI) -> List[Field]:
    s = ui.stats()
    counts = _snap(s.per_profile) if s and s.per_profile else {}
    fields = []
    for fam, desc, profs, shown in _families(ui):
        opened = bool(ui.proto_filter) or ui.family_open(fam)
        nsel = sum(p.key in ui.selected for p in profs)

        def fvalue(ui, nsel=nsel, profs=profs, fam=fam):
            sent = sum(counts.get(p.key, 0) for p in profs)
            text = f"{nsel}/{len(profs)} selected"
            if sent:
                text += f"  {sent:>9,}"
            return text, (C_GREEN if nsel else C_DIM)

        def fact(stdscr, ui, step, fam=fam, opened=opened):
            ui.fam_open[fam] = (not opened) if step == 0 else step > 0

        fields.append(Field(
            f"{'▾' if opened else '▸'} {fam}", fvalue, fact,
            lambda ui, desc=desc: f"{desc}  (Enter/Space fold · → open · "
            f"← close · / filter)", toggle=True,
            keys="Space/Enter fold · / filter", ident=f"family:{fam}"))
        if not opened:
            continue
        for prof in shown:
            def value(ui, prof=prof):
                cnt = counts.get(prof.key, 0)
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
            fields.append(Field(f"  {mark} {prof.key}", value, act, help_,
                                toggle=True, keys="Space/Enter toggle",
                                ident=f"proto:{prof.key}"))
    return fields


# -- Interfaces panel --------------------------------------------------------
def _send_candidates(ui: UI) -> List[str]:
    return [n for n in ui.ifaces if not n.endswith("-mon")]


def _act_send(stdscr, ui: UI, step: int):
    opts = [None] + _send_candidates(ui)
    ui.send_iface = _cycle(opts, ui.send_iface, step)
    ui.extra_ifaces = [n for n in ui.extra_ifaces if n != ui.send_iface]


def _act_fanout(stdscr, ui: UI, step: int):
    if step:
        return
    cands = [n for n in _send_candidates(ui) if n != ui.send_iface]
    if not cands:
        ui.add_log("no other interface to fan out to")
        return
    items = []
    for n in cands:
        info = ui.ifaces.get(n, {})
        st = ui.iface_state(n)[0]
        peer = f" → {info['peer']}" if info.get("peer") else ""
        items.append((n, f"{n:16} {st} · {info.get('kind', '?')}{peer}"))
    got = _pick_multi(stdscr, f"Also send on (same frames as "
                      f"{ui.send_iface})", items, ui.extra_ifaces)
    if got is not None:
        ui.extra_ifaces = [n for n in cands if n in got]
        ui.add_log("fan-out: " + (", ".join(ui.send_ifaces()) if
                                  ui.extra_ifaces else "off"))


def _act_fanout_clear(stdscr, ui: UI, step: int):
    ui.extra_ifaces = []


def _fanout_value(ui: UI) -> Value:
    if not ui.extra_ifaces:
        return "off", C_DIM
    bad = [n for n in ui.extra_ifaces if n not in ui.ifaces]
    return ("+ " + ", ".join(ui.extra_ifaces),
            C_RED if bad else C_CYAN)


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
        ui.extra_ifaces = []


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
    Field("Fan-out", _fanout_value, _act_fanout,
          "Send the same frames on more interfaces too (several sensors, or "
          "a veth plus a SPAN port), each with its own counters in the SEND "
          "box. A dead one is counted as errors, the others keep going.",
          show=lambda ui: bool(ui.send_iface) and (
              bool(ui.extra_ifaces) or len(_send_candidates(ui)) > 1),
          keys="Enter choose · Space off", space=_act_fanout_clear),
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
    cmd = ui.service_command()
    ok, msg = service.write_config(ui.iface_spec() or "tgt0", ui.run_args(),
                                   command=cmd)
    ui.add_log(("saved: " if ok else "error: ") + msg)
    if ok and cmd != "run" and not service.unit_runs_command():
        ui.add_log("the installed service unit predates campaigns — re-run "
                   "scripts/tgtctl.sh register so it runs `tgt campaign`")


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


def _would_run(ui: UI) -> str:
    return (f"tgt {ui.service_command()} -i {ui.iface_spec() or 'tgt0'} "
            f"{ui.run_args()}")


SERVICE_FIELDS = [
    Field("Status", _svc_value, None,
          "The background service runs `tgt run` (or `tgt campaign`) from "
          "the saved config, and survives logout/reboot."),
    Field("Would run", lambda ui: _would_run(ui)[4:], None, _would_run),
    Field("Config file", lambda ui: (service.CONF_PATH, C_DIM), None,
          lambda ui: service.CONF_PATH),
    Field("Save config", lambda ui: ("press Enter", C_DIM), _act_save,
          "Write the current Run/Traffic/Interfaces selection as the "
          "service's config (every option above, campaign included)."),
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
        m = ui.mode()
        if ui.proto_filter:
            n = sum(len(x[3]) for x in _families(ui))
            return (f"filter '{ui.proto_filter}': {n} match · / to change, "
                    f"Esc clears", C_YELLOW)
        if m == "custom":
            return (f"{len(ui.selected)} of {len(protocols.PROFILES)} "
                    f"selected · / filter", C_DIM)
        if m == "replay":
            return "replay: protocols come from the pcap", C_YELLOW
        if m == "campaign":
            plan, _ = ui.plan()
            name = plan.name if plan else ui.campaign
        key = {"env": ui.env, "incident": ui.incident,
               "scenario": ui.scenario,
               "campaign": name if m == "campaign" else None}[m]
        extras = ui.preset_extras()
        if not ui.selected:
            text = (f"{m} {key} uses none of these — only "
                    f"{', '.join(extras)}" if extras else
                    f"{m} {key} uses none of these")
        else:
            text = f"{m} {key} uses these {len(ui.selected)}" + (
                " + " + ", ".join(extras) if extras else "")
        return text, C_RED if m == "incident" else C_GREEN
    if PANELS[ui.focus] != "Run":
        return None
    m = ui.mode()
    if m == "campaign":
        plan, err = ui.plan()
        if plan is None:
            return f"campaign plan error: {err}", C_RED
        env = ui.campaign_env()
        return (f"campaign {plan.name} on {env.key if env else '?'} · "
                f"{len(plan.phases)} phases · {_span(plan.duration)} "
                f"simulated", C_CYAN)
    if m == "env":
        e = enterprise.get(ui.env)
        found = f" · {len(e.findings)} findings" if e.findings else ""
        return (f"{len(e.hosts)} hosts · {len(e.segments)} VLANs · "
                f"{len(e.conversations)} flows · {len(e.protocols())} protocols"
                f" · {len(e.legacy_hosts())} at-risk{found}", C_GREEN)
    if m == "incident":
        inc = incidents.get(ui.incident)
        return (f"{inc.name} ({inc.year}) · "
                f"{_proto_summary(inc.protocols(), inc.attack_only())}", C_RED)
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

    cur = fields[ui.row] if fields else None
    help_text = cur.help(ui) if cur else ""
    # rows first; help gets what's left (1-4 lines, ellipsis if cut short) —
    # a long-help row (findings) may take up to half the panel
    wrapped = [ln for para in help_text.split("\n")
               for ln in textwrap.wrap(para, max(10, w - 2),
                                       subsequent_indent="  " if
                                       para.startswith("• ") else "")]
    room = max(1, min(4, h - 3 - len(fields) - 1))
    if cur is not None and cur.long_help:
        room = max(room, min(10, (h - 3) // 2))
    help_lines = wrapped[:room]
    if len(wrapped) > room:
        help_lines[-1] = _fit(help_lines[-1] + " …", w - 2)
    avail = max(1, h - 3 - len(help_lines))
    shown_rows = min(len(fields), avail)
    start = max(0, ui.row - avail + 1)
    label_w = 20 if w >= 56 else 18
    for idx in range(start, min(len(fields), start + avail)):
        f = fields[idx]
        yy = top + (idx - start)
        sel = idx == ui.row
        val = f.value(ui)
        text, col = (val if isinstance(val, tuple) else (val, 0))
        shown = _fit(text, w - label_w - 3, left=f.path)
        label = _fit(f.label, label_w)
        if sel:
            _put(win, yy, x0, f"▸ {label:<{label_w}} {shown}".ljust(w),
                 _cattr(C_CYAN, curses.A_REVERSE))
        else:
            _put(win, yy, x0, f"  {label:<{label_w}}", curses.A_BOLD)
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
    for entry in ui.log_lines()[-(h * 2):]:
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
    """One-line text input; Enter on an empty line takes ``default``.
    Without a screen (tests) it is a cancel."""
    if stdscr is None:
        return None
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
    if stdscr is None:
        return None
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
        desc_lines = ([ln for para in shown[sel][3].split("\n")
                       for ln in textwrap.wrap(para, width - 4)][:5]
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


def _pick_multi(stdscr, title: str, items: list, checked) -> Optional[list]:
    """Modal checklist: items are (value, label). ↑↓ move, Space toggles,
    Enter accepts, Esc cancels. Returns the checked values or None."""
    if stdscr is None:
        return None
    on = set(checked or ())
    H, W = stdscr.getmaxyx()
    width = min(W - 4, 72)
    height = min(H - 2, len(items) + 4)
    win = curses.newwin(height, width, (H - height) // 2, (W - width) // 2)
    win.keypad(True)
    sel, first = 0, 0
    while True:
        list_h = height - 3
        first = max(0, min(first, sel), sel - list_h + 1)
        win.erase()
        win.attron(_cattr(C_CYAN))
        win.box()
        win.attroff(_cattr(C_CYAN))
        _put(win, 0, 2, _fit(f" {title} ", width - 4),
             _cattr(C_CYAN, curses.A_BOLD))
        for j, (val, label) in enumerate(items[first:first + list_h]):
            i = first + j
            mark = "◉" if val in on else "○"
            text = _fit(f"{'▸' if i == sel else ' '} {mark} {label}",
                        width - 4)
            _put(win, 1 + j, 2, text.ljust(width - 4) if i == sel else text,
                 _cattr(C_CYAN, curses.A_REVERSE) if i == sel else
                 _cattr(C_GREEN) if val in on else 0)
        _put(win, height - 1, 2, " ↑↓ move · Space toggle · Enter done · "
             "Esc cancel ", _cattr(C_CYAN))
        win.refresh()
        c = win.getch()
        if c == 27:
            return None
        if c in (curses.KEY_ENTER, 10, 13):
            return [v for v, _ in items if v in on]
        if c in (curses.KEY_UP, ord('k')):
            sel = (sel - 1) % max(1, len(items))
        elif c in (curses.KEY_DOWN, ord('j'), 9):
            sel = (sel + 1) % max(1, len(items))
        elif c == ord(' ') and items:
            on ^= {items[sel][0]}


def _cleared(v: Optional[str]) -> bool:
    """A prompt answer meaning 'off / none' ('-', 'off', 'none')."""
    return v is not None and v.strip().lower() in ("-", "off", "none")


def _draw_help(stdscr):
    H, W = stdscr.getmaxyx()
    lines = [
        ("Keys", None),
        ("Tab / Shift-Tab", "next / previous panel"),
        ("↑ ↓  (j k)", "move between rows"),
        ("← →", "change the value (cycle, step, switch; fold a family)"),
        ("Enter", "pick from a list, type a value, or run the action"),
        ("Space", "toggle on/off rows and protocols"),
        ("s", "start / stop generating"),
        ("i", "inject an incident into the running engine for a while"),
        ("p", "pause / resume the running engine"),
        ("/", "Traffic: filter protocols (Esc clears)"),
        ("c", "clear the log"),
        ("?", "this help"),
        ("q", "quit (asks first while generating)"),
        ("", ""),
        ("Panels", None),
        ("Run", "preset, campaign, schedule, malware, rate, clock, seed, "
                "manifest, API, pcap, ground truth"),
        ("Traffic", "the protocol mix, grouped by family"),
        ("Interfaces", "send interface(s) + fan-out, the -mon peer, sensor"),
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
    _changed(ui, f)


def _changed(ui: UI, f: Field):
    """After a row acted: note the restart, and keep the cursor on the same
    row if rows appeared/disappeared (or its label changed)."""
    if PANELS[ui.focus] in ("Run", "Traffic", "Interfaces") and \
            f.ident not in ("Create veth pair", "Delete veth pair",
                            "Sensor label", "Export inventory") and \
            not f.ident.startswith("family:"):
        ui.changed()
    for i, g in enumerate(_fields(ui)):
        if g.ident == f.ident:
            ui.row = i
            break


def _act_inject(stdscr, ui: UI):
    """Key i: pick an incident and a duration, inject it into the live run."""
    if not ui.running():
        ui.add_log("inject: nothing running — start a run first (s)")
        return
    key = _pick(stdscr, "Inject into the running engine", _variant_items(),
                ui.sprinkle_variant)
    if key is None:
        return
    from .timing import parse_duration
    v = _prompt(stdscr, f"Inject {key} for how long (e.g. 60, 5m)",
                f"{ui.inject_duration:g}")
    if v is None:
        return
    try:
        dur = parse_duration(v)
    except ValueError as e:
        ui.add_log(f"inject: not a duration: {e}")
        return
    ok, msg = ui.inject(key, dur)
    ui.add_log(msg if ok else f"inject failed: {msg}")


def _quit_hint(ui: UI) -> str:
    return "generating — press q again (or y) to stop and quit · any other " \
           "key cancels"


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
    if ui.paused():
        word, col = f"‖ PAUSED {_clock(s.elapsed)}", C_YELLOW
    elif ui.running():
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
    if ui.api_server is not None:
        sysline += f" · API {ui.api_server.url.split('//')[-1]}"
    _put(stdscr, 1, 2, sysline, _cattr(C_DIM))
    if ui.sprinkle_on and ui.mode() not in ("replay", "campaign"):
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

    # key bar: what the keys do on this row (or the quit question)
    if ui.quit_armed:
        _put(stdscr, h - 1, 0, (" " + _quit_hint(ui)).ljust(w)[:w - 1],
             _cattr(C_RED, curses.A_REVERSE | curses.A_BOLD))
    else:
        fields = _fields(ui)
        hint = fields[ui.row].keys if fields and ui.row < len(fields) else ""
        live = ("i inject · p " + ("resume" if ui.paused() else "pause")
                if ui.running() else "")
        keys = " · ".join(x for x in (
            "Tab panel", "↑↓ move", hint,
            f"s {'stop' if ui.running() else 'start'}", live, "? help",
            "q quit") if x)
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
    if ui.quit_armed:                       # answer to "stop and quit?"
        ui.quit_armed = False
        if c in (ord('q'), ord('y'), ord('Y')):
            return False
        ui.add_log("quit cancelled")
        return True
    fields = _fields(ui)
    traffic = PANELS[ui.focus] == "Traffic"
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
            _changed(ui, f)
        elif f.toggle:
            _activate(stdscr, ui, 0)
    elif c == ord('/') and traffic:
        v = _prompt(stdscr, "Filter protocols (key, name, port; - = all)",
                    ui.proto_filter)
        if v is not None:
            ui.proto_filter = "" if _cleared(v) else v.strip()
            ui.row = 0
    elif c == 27 and traffic and ui.proto_filter:      # Esc clears the filter
        ui.proto_filter = ""
        ui.row = 0
    elif c == ord('?'):
        ui.help_open = True
    elif c == ord('s'):
        ui.start_stop()
    elif c == ord('i'):
        _act_inject(stdscr, ui)
    elif c == ord('p'):
        ui.add_log(ui.toggle_pause())
    elif c == ord('c'):
        ui.clear_log()
    elif c == ord('q'):
        if ui.running():
            ui.quit_armed = True
            return True
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

    try:
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
                break
            stdscr.nodelay(True)
            stdscr.timeout(90)
    finally:
        if ui.running():
            ui.engine.stop()
            ui.engine.join(timeout=3)
        ui.close_api()


def run() -> int:
    curses.wrapper(_loop)
    return 0
