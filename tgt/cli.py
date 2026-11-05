"""Command-line interface for TGT.

    tgt                      launch the TUI
    tgt list                 list protocols and scenarios
    tgt env                  show detected environment (WSL/Podman/native)
    tgt iface ...            create / delete / list virtual interfaces
    tgt run ...              generate traffic (send and/or write pcap)
    tgt inventory -e ENV     export an environment's ground-truth asset list
    tgt env export ENV       write an environment as an env file (JSON)
    tgt campaign PLAN        phased run: baseline, then changes (timed)
    tgt ctl ...              control a running "tgt run --api" (status, inject…)
"""
from __future__ import annotations

import argparse
import os
import signal
import sys
import time

from . import __version__, net, protocols, scenarios
from .config import RunConfig
from .engine import Engine
from .packet import Endpoints
from . import enterprise

VERSION = __version__


# ---------------------------------------------------------------------------
def _columns(rows, mins) -> list:
    """``rows`` (tuples of str) formatted as aligned columns, each as wide as
    its longest value (at least ``mins``); the last column is left as is."""
    w = [max([m] + [len(r[i]) for r in rows]) for i, m in enumerate(mins)]
    return [" ".join(f"{v:{n}}" for v, n in zip(r, w)) +
            "".join(f" {v}" for v in r[len(w):]) for r in rows]


def cmd_list(args) -> int:
    print("Protocols:")
    for line in _columns([("key", "name", "cat", "port", "xport", "desc")] +
                         [(p.key, p.name, p.category, p.port, p.transport,
                           p.desc) for p in protocols.all_profiles()],
                         (10, 22, 4, 7, 6)):
        print(f"  {line}")
    print("\nScenarios (curated protocol mixes):")
    scen = scenarios.all_scenarios()
    lines = _columns([(s.key, s.name, f"[{', '.join(s.profiles)}]")
                      for s in scen], (14, 26))
    for s, line in zip(scen, lines):
        print(f"  {line}")
        print(f"    {s.desc}")
    print("\nEnvironments (modeled organizations — use with --env):")
    from . import envfile
    envs = enterprise.all_environments()
    lines = _columns([(e.key, e.name, f"[{e.category}]") for e in envs],
                     (18, 22))
    for e, line in zip(envs, lines):
        print(f"  {line}")
        if envfile.source_of(e):
            print(f"    file: {envfile.source_of(e)}")
        print(f"    {e.summary()}")
        print(f"    protocols: {', '.join(e.protocols())}")
        segs = ", ".join(f"{s.name} v{s.vlan} {s.subnet}" for s in e.segments)
        print(f"    segments: {segs}")
        if e.legacy_hosts():
            leg = ", ".join(f"{h.name} ({h.fp.label})" for h in e.legacy_hosts())
            print(f"    at-risk: {leg}")
    from . import incidents
    print("\nIncidents (famous attacks — detection-test traffic; use with "
          "--incident):")
    incs = incidents.all_incidents()
    lines = _columns([(i.key, i.name, f"[{i.category} · {i.year}]")
                      for i in incs], (14, 26))
    for inc, line in zip(incs, lines):
        print(f"  {line}")
        print(f"    {inc.desc}")
        protos, extra = ", ".join(inc.protocols()), ", ".join(inc.attack_only())
        print(f"    protocols: {protos}{' + ' if protos and extra else ''}{extra}")
        print(f"    signals: {'; '.join(inc.indicators())}")
    from . import plugins
    if plugins.LOADED or plugins.ERRORS:
        print("\nPlugins (TGT_PLUGIN_PATH, ~/.config/tgt/plugins):")
        for _, path in plugins.LOADED:
            mine = sorted(f"{kind} {k}" for kind, own in
                          plugins.OWNERS.items() for k, p in own.items()
                          if p == path)
            print(f"  {path}")
            if mine:
                print(f"    adds: {', '.join(mine)}")
        for path, msg in plugins.ERRORS:
            print(f"  {path}  NOT LOADED: {msg}")
    return 0


def _iface_line(i: dict) -> str:
    """One interface, marking veth pairs: a sensor on this host captures on
    the peer; a real interface needs a switch/vSwitch SPAN to reach one."""
    link = (f"  veth <-> {i['peer']}" if i.get("peer") else
            "  veth (peer in another namespace)" if i.get("kind") == "veth"
            else "")
    return (f"{i['name']:14} state={i['state']:8} mac={i['mac']:18} "
            f"mtu={i['mtu']}{link}")


def cmd_env(args) -> int:
    if getattr(args, "env_cmd", None) == "export":
        return cmd_env_export(args)
    e = net.detect_env()
    print(f"environment : {e.kind}  ({e.detail})")
    print(f"root/CAP_NET: {'yes' if e.is_root else 'no — sending needs sudo'}")
    print(f"iproute2 'ip': {'found' if e.has_ip else 'MISSING'}")
    print("\ninterfaces:")
    for i in net.list_interfaces():
        print(f"  {_iface_line(i)}")
    if e.kind in ("wsl", "podman", "container"):
        print(f"\nnote: on {e.kind}, run TGT and your sensor (Zeek/Suricata/tcpdump) "
              "inside the same\n      network namespace so both see the veth pair.")
    return 0


def cmd_env_export(args) -> int:
    from . import envfile
    if args.key not in enterprise.ENVIRONMENTS:
        print(f"unknown environment: {args.key}. Try 'tgt list'.",
              file=sys.stderr)
        return 2
    text = envfile.export(enterprise.get(args.key))
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"wrote environment {args.key} to {args.output}",
              file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


def _load_env_file(path: str):
    """Load + register ``--env-file``; returns its key or None (reported)."""
    from . import envfile
    try:
        return envfile.register(envfile.load(path)).key
    except envfile.EnvFileError as e:
        print(f"bad environment file: {e}", file=sys.stderr)
        return None


def cmd_iface(args) -> int:
    if args.iface_cmd == "list":
        for i in net.list_interfaces():
            print(_iface_line(i))
        return 0
    if args.iface_cmd == "create":
        if args.type == "veth":
            res = net.create_veth(args.name, args.peer, args.mtu,
                                  use_sudo=not args.no_sudo)
        else:
            res = net.create_dummy(args.name, args.mtu,
                                   use_sudo=not args.no_sudo)
        for line in res.log:
            print(line)
        if res.ok and args.type == "veth":
            peer = args.peer or f"{args.name}-mon"
            print(f"\nveth ready. Generate on '{args.name}', capture on '{peer}':")
            print(f"  tgt run --iface {args.name} --profile modbus")
            print(f"  # point your sensor (Zeek/Suricata/tcpdump, or Claroty CTD) at: {peer}")
        return 0 if res.ok else 1
    if args.iface_cmd == "delete":
        res = net.delete_interface(args.name, use_sudo=not args.no_sudo)
        for line in res.log:
            print(line)
        return 0 if res.ok else 1
    return 1


def _resolve_profiles(args) -> list[str]:
    keys: list[str] = []
    if args.scenario:
        keys.extend(scenarios.get(args.scenario).profiles)
    if args.profile:
        for p in args.profile:
            keys.extend(x.strip() for x in p.split(",") if x.strip())
    if not keys:
        keys = ["modbus"]
    # validate
    for k in keys:
        protocols.get(k)  # raises KeyError with a clear message below
    # de-dup, keep order
    seen, out = set(), []
    for k in keys:
        if k not in seen:
            seen.add(k)
            out.append(k)
    return out


def cmd_run(args) -> int:
    from . import incidents
    env = getattr(args, "env", None)
    if getattr(args, "env_file", None):
        key = _load_env_file(args.env_file)
        if key is None:
            return 2
        if env and env != key:
            print(f"--env {env} and --env-file (key {key}) disagree.",
                  file=sys.stderr)
            return 2
        env = key
    incident = getattr(args, "incident", None)
    replay = getattr(args, "replay", None)
    if env and env not in enterprise.ENVIRONMENTS:
        print(f"unknown environment: {env}. Try 'tgt list'.", file=sys.stderr)
        return 2
    span = getattr(args, "span", "access")
    if span != "access" and not env:
        print("--span core needs --env (segments come from the modeled "
              "environment).", file=sys.stderr)
        return 2
    if incident and incident not in incidents.INCIDENTS:
        print(f"unknown incident: {incident}. Try 'tgt list'.", file=sys.stderr)
        return 2
    if replay:
        import os
        if not os.path.exists(replay):
            print(f"replay file not found: {replay}", file=sys.stderr)
            return 2
        from . import pcapread
        try:
            pcapread.probe(replay)
        except (OSError, pcapread.PcapError) as e:
            print(f"cannot replay {replay}: {e}", file=sys.stderr)
            return 2
    remaps = [getattr(args, a, None) or [] for a in
              ("remap_ip", "remap_subnet", "remap_mac")]
    if any(remaps) and not replay:
        print("--remap-ip/--remap-subnet/--remap-mac rewrite a --replay "
              "capture.", file=sys.stderr)
        return 2
    tsresol = None
    if getattr(args, "replay_tsresol", None):
        tsresol = _parse_tsresol(args.replay_tsresol)
        if tsresol is None:
            print(f"bad --replay-tsresol {args.replay_tsresol!r}: use us, "
                  "ns, ms or ticks per second", file=sys.stderr)
            return 2
    sprinkle: list[str] = []
    for chunk in (getattr(args, "sprinkle", None) or []):
        sprinkle += [x.strip() for x in chunk.split(",") if x.strip()]
    for k in sprinkle:
        if k not in incidents.INCIDENTS:
            print(f"unknown malware variant: {k}. Try 'tgt list'.",
                  file=sys.stderr)
            return 2
    if env or incident or replay:
        profs = ["modbus"]   # unused (base comes from env/incident/replay)
    else:
        try:
            profs = _resolve_profiles(args)
        except KeyError as e:
            print(f"unknown protocol: {e}. Try 'tgt list'.", file=sys.stderr)
            return 2

    schedule = getattr(args, "schedule", "cycle") or "cycle"
    rate = args.rate
    if rate is None:            # timed: the schedule paces, no cap by default
        rate = 0.0 if schedule == "timed" else 20.0
    ep = Endpoints(
        client_mac=args.client_mac, client_ip=args.client_ip,
        server_mac=args.server_mac, server_ip=args.server_ip,
        vlan=args.vlan,
    )
    cfg = RunConfig(
        profiles=profs, env=env, span=span, incident=incident,
        sprinkle=sprinkle,
        sprinkle_ratio=max(0.0, getattr(args, "sprinkle_ratio", 0.0)),
        sprinkle_random=getattr(args, "sprinkle_random", False),
        replay_path=replay,
        replay_realtime=getattr(args, "replay_realtime", False),
        iface=args.iface, pcap_path=args.pcap,
        rate=rate, count=args.count, duration=args.duration,
        messages=args.messages, loop=not args.once, endpoints=ep,
        seed=getattr(args, "seed", None),
        manifest_path=getattr(args, "manifest", None),
        clock=getattr(args, "clock", "wall"),
        start_time=getattr(args, "start_time", None),
        schedule=schedule, speed=getattr(args, "speed", 1.0),
        day_profile=getattr(args, "day_profile", None),
        min_period=getattr(args, "min_period", 0.0),
        replay_speed=max(0.0, getattr(args, "replay_speed", 0.0) or 0.0),
        replay_loop=max(0, getattr(args, "replay_loop", 0) or 0),
        replay_tsresol=tsresol,
        remap_ip=remaps[0], remap_subnet=remaps[1], remap_mac=remaps[2],
        replay_vlan=args.vlan if replay else None,
    )
    if cfg.speed <= 0:
        print("--speed must be > 0.", file=sys.stderr)
        return 2
    if schedule == "timed" and replay:
        print("--schedule timed generates traffic; --replay keeps the "
              "capture's own timing (use --replay-realtime).",
              file=sys.stderr)
        return 2
    if replay:
        from .replay import rewriter_for
        from .rewrite import RewriteError
        try:
            rewriter_for(cfg)
        except RewriteError as e:
            print(str(e), file=sys.stderr)
            return 2
    return _run_engine(cfg, args)


def _run_engine(cfg: RunConfig, args) -> int:
    """Validate the output/clock options of ``cfg``, run the engine to the
    end (Ctrl-C / SIGTERM stop it cleanly) and print the summary."""
    if not cfg.iface and not cfg.pcap_path:
        print("nothing to do: specify --iface to send and/or --pcap to write a "
              "file.", file=sys.stderr)
        return 2
    if cfg.start_time:
        from .manifest import parse_iso
        try:
            parse_iso(cfg.start_time)
        except ValueError:
            print(f"bad --start-time {cfg.start_time!r}: use ISO-8601, e.g. "
                  "2026-11-05T14:00:00Z", file=sys.stderr)
            return 2
    if cfg.seed is None:                # chosen now so it is printed + logged
        from .engine import new_seed
        cfg.seed = new_seed()

    print(f"TGT run: {cfg.summary()}", flush=True)
    eng = Engine(cfg, on_log=lambda m: print(f"  [engine] {m}", flush=True),
                 argv=getattr(args, "argv", None))
    server = None
    if getattr(args, "api", None):
        server = _start_api(args, eng)
        if server is None:
            return 2
    # SIGTERM (systemctl/podman stop, timeout) and SIGHUP stop the engine like
    # Ctrl-C does, so the pcap is flushed + closed and the summary printed.
    caught: list[int] = []

    def _on_signal(signum, _frame):
        caught.append(signum)
        eng.stop()

    old_handlers = _install_signal_handlers(_on_signal)
    tty = sys.stdout.isatty()
    last_line = time.monotonic()
    eng.start()
    try:
        while eng.is_alive():
            time.sleep(0.25)
            s = eng.stats
            line = (f"sent={s.packets:<8} bytes={s.bytes:<10} "
                    f"pps={s.pps:7.1f} Mbps={s.mbps:6.2f} err={s.errors} "
                    f"t={s.elapsed:5.1f}s")
            if tty:                     # live, overwritten in place
                sys.stdout.write(f"\r  {line}")
                sys.stdout.flush()
            elif time.monotonic() - last_line >= STATS_INTERVAL:
                # logs/journald/pipes: a plain line every STATS_INTERVAL s
                last_line = time.monotonic()
                print(f"  {line}", flush=True)
            if caught:
                eng.join(timeout=3)
                break
    except KeyboardInterrupt:
        print("\n  stopping…")
        eng.stop()
        eng.join(timeout=3)
    finally:
        _restore_signal_handlers(old_handlers)
        if server is not None:
            server.close()
    if tty:
        print()
    if caught:
        print(f"  stopping on {signal.Signals(caught[0]).name}…")
    s = eng.stats
    print(f"summary: {s.packets} packets, {s.bytes} bytes, {s.errors} errors "
          f"in {s.elapsed:.1f}s")
    if cfg.schedule == "timed":
        print(f"  simulated {_fmt_span(s.sim_time)}"
              + (f" ({s.packets / s.elapsed:,.0f} frames/s)"
                 if s.elapsed > 0 else ""))
    if s.per_profile:
        for line in _columns([(k, str(v))
                              for k, v in s.per_profile.items()], (10,)):
            print(f"  {line}")
    iface_errors = 0
    if len(s.per_iface) > 1 or any(c["errors"] for c in s.per_iface.values()):
        for name, c in s.per_iface.items():
            iface_errors += c["errors"]
            err = f"  ({c['last_error']})" if c["errors"] else ""
            print(f"  iface {name:12} {c['packets']} packets, {c['bytes']} "
                  f"bytes, {c['errors']} errors{err}")
    for inj in eng.control.status():
        print(f"  injection {inj['id']} {inj['incident']}: {inj['packets']} "
              f"packets {inj['start'] or '-'} .. {inj['end'] or '-'}"
              + (f" [{inj['error']}]" if inj.get("error") else ""))
    if s.last_error:
        print(f"last error: {s.last_error}")
    return 0 if s.errors == 0 and iface_errors == 0 else 1


def _parse_tsresol(text: str):
    """--replay-tsresol: us | ns | ms | ticks per second -> float or None."""
    named = {"s": 1.0, "ms": 1e3, "us": 1e6, "ns": 1e9}
    t = str(text).strip().lower()
    if t in named:
        return named[t]
    try:
        v = float(t)
    except ValueError:
        return None
    return v if v > 0 else None


def _start_api(args, eng):
    """Start the --api control server for ``eng`` (None + message on error)."""
    import os
    from . import api
    token = getattr(args, "api_token", None) or \
        os.environ.get("TGT_API_TOKEN") or None
    try:
        host, port = api.parse_bind(args.api)
        server = api.ControlServer(eng, host, port, token=token,
                                   allow_remote=args.api_allow_remote)
    except api.ApiError as e:
        print(f"--api: {e}", file=sys.stderr)
        return None
    eng.record = True           # /manifest + injection records need it
    server.start()
    print(f"  [api] control API on {server.url} "
          f"({'token required' if token else 'no token'}) — "
          f"try: tgt ctl --api {host}:{server.port} status", flush=True)
    return server


def cmd_ctl(args) -> int:
    """tgt ctl: client for a run's --api control server."""
    import json
    import os
    from . import api
    token = args.token or os.environ.get("TGT_API_TOKEN") or None
    what = args.ctl_cmd
    if what == "status":
        method, path, params = "GET", "/status", None
    elif what == "manifest":
        method, path, params = "GET", "/manifest", None
    elif what == "rate":
        method, path, params = "POST", "/rate", {"pps": args.pps}
    elif what == "inject":
        method, path = "POST", "/inject"
        params = {"incident": args.incident, "duration": args.duration,
                  "ratio": args.ratio}
    else:                               # stop | pause | resume
        method, path, params = "POST", "/" + what, None
    try:
        code, doc = api.request(args.api, method, path, params, token)
    except api.ApiError as e:
        print(str(e), file=sys.stderr)
        return 2
    if what == "manifest" and code == 200 and args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1)
            f.write("\n")
        print(f"wrote manifest to {args.output}", file=sys.stderr)
    elif args.json or what == "manifest" or code >= 300:
        print(json.dumps(doc, indent=1))
    elif what == "status":
        _print_status(doc)
    elif what == "inject":
        i = doc.get("injection", {})
        print(f"injection {i.get('id')}: {i.get('incident')} for "
              f"{i.get('duration')}s at {i.get('ratio', 0):.0%} "
              f"({i.get('state')})")
    else:
        print(json.dumps(doc))
    return 0 if code < 300 else 1


def _print_status(d: dict) -> None:
    state = ("paused" if d.get("paused") else "running" if d.get("running")
             else "finished")
    print(f"{d.get('tool')}  {state}  up {d.get('uptime', 0):.1f}s  "
          f"seed {d.get('seed')}")
    print(f"  {d.get('summary')}")
    print(f"  sent={d.get('packets')} bytes={d.get('bytes')} "
          f"pps={d.get('pps')} errors={d.get('errors')} "
          f"cycles={d.get('cycles')} rate={d.get('rate')}")
    for name, c in (d.get("interfaces") or {}).items():
        print(f"  iface {name}: {c['packets']} packets, {c['errors']} errors"
              + (f" ({c['last_error']})" if c.get("last_error") else ""))
    for i in d.get("injections") or []:
        rem = f", {i['remaining']}s left" if "remaining" in i else ""
        print(f"  injection {i['id']} {i['incident']}: {i['state']}{rem}, "
              f"{i['packets']} packets, start {i['start'] or '-'}, "
              f"end {i['end'] or '-'}")


def _fmt_span(sec: float) -> str:
    d, rem = divmod(int(sec), 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    return (f"{d}d " if d else "") + f"{h:02d}:{m:02d}:{s:02d}"


def cmd_campaign(args) -> int:
    """Run a phased campaign plan (see tgt.campaign) on the timed scheduler."""
    from . import campaign, envfile
    if args.list or not args.plan:
        print("Example campaign plans (tgt/campaigns/):")
        for p in campaign.packaged():
            try:
                plan = campaign.load(p)
                print(f"  {os.path.basename(p):32} "
                      f"{plan.env_key or plan.env_file}  "
                      f"{len(plan.phases)} phases, "
                      f"{_fmt_span(plan.duration)}")
                if plan.description:
                    print(f"    {plan.description}")
            except campaign.CampaignError as e:
                print(f"  {os.path.basename(p):32} (invalid: {e})")
        return 0 if args.list else 2
    path = campaign.find(args.plan)
    try:
        plan = campaign.load(path)
        base = plan.base_env()
        if plan.env_file:
            envfile.register(base)
        phases = campaign.build(plan)
    except (campaign.CampaignError, envfile.EnvFileError) as e:
        print(f"bad campaign plan: {e}", file=sys.stderr)
        return 2
    problems = campaign.validate(phases, args.min_period)
    print(f"campaign {plan.name}: env {base.key}, {len(phases)} phases, "
          f"{_fmt_span(plan.duration)} simulated")
    for ph in phases:
        ch = ", ".join(f"{k}={len(v) if isinstance(v, list) else v}"
                       for k, v in ph.changes.items()) or "no changes"
        print(f"  {ph.id} {ph.name:24} {_fmt_span(ph.duration):>12}  "
              f"{ch}; {len(ph.events)} change events")
    if problems:
        for p in problems:
            print(f"  {'warning' if args.force else 'error'}: {p}",
                  file=sys.stderr)
        if not args.force:
            print("phases too short for fair learning; lengthen them or "
                  "pass --force.", file=sys.stderr)
            return 2
    if args.check:
        print("plan OK")
        return 0
    campaign.remember(path, phases)
    seed = args.seed if args.seed is not None else plan.seed
    if seed is None:
        from .engine import new_seed
        seed = new_seed()
    rate = args.rate if args.rate is not None else 0.0
    cfg = RunConfig(
        env=base.key, span=plan.span, iface=args.iface, pcap_path=args.pcap,
        rate=rate, count=args.count, duration=0.0,
        sprinkle_messages=plan.sprinkle_messages, seed=seed,
        manifest_path=args.manifest, clock=args.clock,
        start_time=args.start_time or plan.start_time, schedule="timed",
        speed=args.speed, day_profile=plan.day_profile,
        min_period=args.min_period, campaign=path, force=args.force)
    if cfg.speed <= 0:
        print("--speed must be > 0.", file=sys.stderr)
        return 2
    return _run_engine(cfg, args)


# Non-TTY stdout (service logs, pipes) gets one stats line this often.
STATS_INTERVAL = 10.0
_STOP_SIGNALS = ("SIGTERM", "SIGHUP")


def _install_signal_handlers(handler) -> dict:
    """Route SIGTERM/SIGHUP to ``handler``; returns the previous handlers.

    Installing a handler also makes the process stoppable as PID 1 in a
    container (the kernel drops default-action signals sent to PID 1).
    A signal that is already ignored (e.g. SIGHUP under ``nohup``) stays so.
    """
    old = {}
    for name in _STOP_SIGNALS:
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        try:
            if signal.getsignal(sig) == signal.SIG_IGN:
                continue
            old[sig] = signal.signal(sig, handler)
        except (ValueError, OSError):    # not the main thread / unsupported
            pass
    return old


def _restore_signal_handlers(old: dict) -> None:
    for sig, h in old.items():
        try:
            signal.signal(sig, h)
        except (ValueError, OSError, TypeError):
            pass


def cmd_inventory(args) -> int:
    from . import inventory
    if getattr(args, "env_file", None):
        args.env = _load_env_file(args.env_file)
        if args.env is None:
            return 2
    if args.env not in enterprise.ENVIRONMENTS:
        print(f"unknown environment: {args.env}. Try 'tgt list'.",
              file=sys.stderr)
        return 2
    env = enterprise.get(args.env)
    from . import incidents
    sprinkle = [x.strip() for chunk in (args.sprinkle or [])
                for x in chunk.split(",") if x.strip()]
    for k in sprinkle:
        if k not in incidents.INCIDENTS:
            print(f"unknown malware variant: {k}. Try 'tgt list'.",
                  file=sys.stderr)
            return 2
    write = inventory.write_json if args.format == "json" else inventory.write_csv
    if args.output:
        with open(args.output, "w", newline="", encoding="utf-8") as f:
            write(env, f, sprinkle)
        print(f"wrote {len(env.hosts)} hosts ({args.format}) to {args.output}",
              file=sys.stderr)
    else:
        write(env, sys.stdout, sprinkle)
    return 0


def cmd_score(args) -> int:
    from . import score
    return score.run(args)


def cmd_tui(args) -> int:
    from . import tui
    return tui.run()


# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tgt",
        description="Traffic Generation Toolkit — craft OT/ICS + IT test "
                    "traffic onto a virtual interface for SPAN-ingestion "
                    "testing with Zeek, Suricata, Security Onion, Malcolm, "
                    "Claroty CTD, Nozomi, etc.")
    p.add_argument("--version", action="version", version=f"tgt {VERSION}")
    sub = p.add_subparsers(dest="command")

    sub.add_parser("list", help="list protocols and scenarios")
    pe = sub.add_parser("env", help="show detected environment and "
                        "interfaces; 'env export' writes an env file")
    esub = pe.add_subparsers(dest="env_cmd")
    ee = esub.add_parser("export", help="write an environment (built-in or "
                         "loaded) in the env-file JSON format")
    ee.add_argument("key", help="environment key (see 'tgt list')")
    ee.add_argument("--output", "-o", metavar="FILE",
                    help="write here instead of stdout")
    sub.add_parser("tui", help="launch the text UI (default)")

    pv = sub.add_parser("inventory",
                        help="export an environment's ground-truth assets")
    pvg = pv.add_mutually_exclusive_group(required=True)
    pvg.add_argument("--env", "-e",
                     help="environment to export (see 'tgt list')")
    pvg.add_argument("--env-file", metavar="FILE",
                     help="environment defined in a JSON/TOML env file")
    pv.add_argument("--format", "-f", choices=["csv", "json"], default="csv",
                    help="csv = one row per host; json adds segments + flows")
    pv.add_argument("--output", "-o", metavar="FILE",
                    help="write here instead of stdout")
    pv.add_argument("--sprinkle", action="append", metavar="INCIDENT",
                    help="also list the hosts these sprinkled incidents add "
                         "as new assets (no compatible inventory host); "
                         "comma-separated, repeatable")

    from . import score
    score.add_arguments(sub.add_parser(
        "score", help="score a monitor's asset/alert export against TGT "
                      "ground truth (manifest or inventory JSON)"))

    pi = sub.add_parser("iface", help="manage virtual interfaces")
    isub = pi.add_subparsers(dest="iface_cmd", required=True)
    isub.add_parser("list", help="list interfaces")
    ic = isub.add_parser("create", help="create a veth pair or dummy iface")
    ic.add_argument("name", help="interface name, e.g. tgt0")
    ic.add_argument("--type", choices=["veth", "dummy"], default="veth")
    ic.add_argument("--peer", help="veth peer name (default: <name>-mon)")
    ic.add_argument("--mtu", type=int, default=1500)
    ic.add_argument("--no-sudo", action="store_true",
                    help="do not prefix ip commands with sudo")
    idl = isub.add_parser("delete", help="delete an interface")
    idl.add_argument("name")
    idl.add_argument("--no-sudo", action="store_true")

    r = sub.add_parser("run", help="generate traffic")
    r.add_argument("--profile", "-p", action="append",
                   help="protocol key(s), comma-separated; repeatable")
    r.add_argument("--scenario", "-s", help="named scenario (see 'tgt list')")
    r.add_argument("--env", "-e",
                   help="modeled environment: it-org | ot-plant | "
                        "enterprise-mixed | industrial-site (see 'tgt list')")
    r.add_argument("--env-file", metavar="FILE",
                   help="modeled environment from a JSON (or, on Python "
                        "3.11+, TOML) env file; see 'tgt env export'")
    r.add_argument("--span", choices=enterprise.SPAN_VIEWS, default="access",
                   help="--env capture point: access = each frame once on its "
                        "sender's VLAN; core = also the routed copy on the "
                        "receiver's VLAN (gateway MAC, TTL-1)")
    r.add_argument("--incident",
                   help="famous incident scenario, e.g. wannacry | stuxnet | "
                        "industroyer | triton (see 'tgt list')")
    r.add_argument("--sprinkle", action="append", metavar="INCIDENT",
                   help="mix malware traffic into the base (normal) traffic; "
                        "comma-separated, repeatable  (e.g. --sprinkle wannacry)")
    r.add_argument("--sprinkle-ratio", type=float, default=0.0, metavar="FRAC",
                   help="target malware fraction 0.0-0.9 regardless of base size "
                        "(e.g. 0.05 = 5%%); 0 = one natural minority cycle")
    r.add_argument("--sprinkle-random", action="store_true",
                   help="pick a random incident each cycle with jittered "
                        "placement (from --sprinkle list, or all if none given)")
    r.add_argument("--replay", metavar="FILE",
                   help="replay frames from a .pcap file instead of generating")
    r.add_argument("--replay-realtime", action="store_true",
                   help="honor the pcap's original inter-packet timing")
    r.add_argument("--replay-speed", type=float, default=0.0, metavar="X",
                   help="replay with the capture's timing divided by X "
                        "(2 = twice as fast, 0.5 = half speed); implies "
                        "--replay-realtime")
    r.add_argument("--replay-loop", type=int, default=0, metavar="N",
                   help="stop after N passes over the capture "
                        "(0 = loop until stopped; --once = one pass)")
    r.add_argument("--replay-tsresol", metavar="RES",
                   help="override the pcapng timestamp resolution: us, ns, "
                        "ms or ticks per second")
    r.add_argument("--remap-ip", action="append", metavar="OLD=NEW[,..]",
                   help="replay: rewrite IPv4 addresses (IP + ARP, "
                        "checksums recomputed); repeatable")
    r.add_argument("--remap-subnet", action="append", metavar="A/N=B/N[,..]",
                   help="replay: move a subnet, keeping host bits "
                        "(e.g. 192.168.1.0/24=10.100.10.0/24)")
    r.add_argument("--remap-mac", action="append", metavar="OLD=NEW[,..]",
                   help="replay: rewrite MAC addresses (Ethernet + ARP)")
    r.add_argument("--iface", "-i",
                   help="interface(s) to send on (needs root); a,b,c sends "
                        "the same frames to each (fan-out)")
    r.add_argument("--pcap", help="also/only write frames to this pcap file")
    r.add_argument("--rate", type=float, default=None,
                   help="packets per second (0 = as fast as possible; "
                        "default 20). With --schedule timed: a cap only "
                        "(default none)")
    r.add_argument("--count", type=int, default=0,
                   help="stop after N packets (0 = use --duration)")
    r.add_argument("--duration", type=_duration, default=0.0,
                   help="stop after this long: seconds or 30m / 4h / 7d (0 "
                        "with count=0 = run forever); simulated time with "
                        "--schedule timed")
    r.add_argument("--messages", type=int, default=5,
                   help="protocol exchanges per built flow cycle")
    r.add_argument("--once", action="store_true",
                   help="send one cycle then stop (do not loop)")
    r.add_argument("--client-mac", default="02:00:00:00:00:01")
    r.add_argument("--client-ip", default="10.10.10.10")
    r.add_argument("--server-mac", default="02:00:00:00:00:02")
    r.add_argument("--server-ip", default="10.10.10.20")
    r.add_argument("--vlan", type=int, default=None,
                   help="802.1Q VLAN id (with --replay: retag every frame, "
                        "0 = strip the tag)")
    r.add_argument("--seed", type=int, default=None,
                   help="run seed: same seed + options = identical frames "
                        "every cycle (default: random, printed)")
    r.add_argument("--manifest", metavar="FILE",
                   help="write the run manifest (JSON ground truth: seed, "
                        "inventory, first/last seen, flows, attack events); "
                        "rewritten every ~10 s and on exit")
    r.add_argument("--clock", choices=["wall", "synthetic"], default="wall",
                   help="pcap/manifest timestamps: wall = real send time; "
                        "synthetic = --start-time + n/--rate (pcap-only runs "
                        "then skip real-time pacing)")
    r.add_argument("--start-time", metavar="ISO",
                   help="synthetic clock start, e.g. 2026-11-05T14:00:00Z "
                        "(default: now)")
    r.add_argument("--schedule", choices=["cycle", "timed"], default="cycle",
                   help="cycle = every conversation once per batch at "
                        "--rate (default); timed = each conversation on its "
                        "own period with jitter, request/response RTT, "
                        "persistent polling sessions (see tgt/timing.py)")
    r.add_argument("--day-profile", choices=["flat", "shift"], default=None,
                   help="timed: diurnal activity - shift = logons ~07:00, "
                        "lunch dip, backups ~02:00, quiet weekends, OT "
                        "polling steady (default: the env's, else flat)")
    _timed_args(r)

    pc = sub.add_parser("campaign", help="run a phased campaign plan "
                        "(baseline, then changes) on the timed scheduler")
    pc.add_argument("plan", nargs="?",
                    help="plan file (JSON, or TOML on 3.11+) or the name of "
                         "an example in tgt/campaigns/")
    pc.add_argument("--list", action="store_true",
                    help="list the example plans")
    pc.add_argument("--check", action="store_true",
                    help="validate the plan and print its phases; send "
                         "nothing")
    pc.add_argument("--force", action="store_true",
                    help="run even if a phase is shorter than 3x the "
                         "slowest period its change involves")
    pc.add_argument("--iface", "-i", help="interface to send on (needs root)")
    pc.add_argument("--pcap", help="also/only write frames to this pcap")
    pc.add_argument("--manifest", metavar="FILE",
                    help="write the run manifest (phases, inventory diffs, "
                         "change events)")
    pc.add_argument("--clock", choices=["wall", "synthetic"], default="wall",
                    help="wall = real time (compress with --speed); "
                         "synthetic = simulated timestamps, as fast as "
                         "possible for a pcap-only run")
    pc.add_argument("--start-time", metavar="ISO",
                    help="synthetic clock start (default: the plan's, else "
                         "now)")
    pc.add_argument("--seed", type=int, default=None,
                    help="run seed (default: the plan's, else random)")
    pc.add_argument("--rate", type=float, default=None,
                    help="packet-rate cap (default: none)")
    pc.add_argument("--count", type=int, default=0,
                    help="stop after N packets")
    _timed_args(pc)
    r.add_argument("--api", metavar="[HOST:]PORT",
                   help="serve the control API (status/stop/pause/resume/"
                        "rate/inject/manifest) here, e.g. 127.0.0.1:8787; "
                        "see 'tgt ctl'")
    r.add_argument("--api-token", metavar="TOKEN",
                   help="require 'Authorization: Bearer TOKEN' (default: "
                        "$TGT_API_TOKEN)")
    r.add_argument("--api-allow-remote", action="store_true",
                   help="allow binding the API to a non-loopback address "
                        "(needs a token)")

    import os as _os
    c = sub.add_parser("ctl", help="control a running 'tgt run --api' "
                       "(status, stop, pause, resume, rate, inject)")
    c.add_argument("--api", default=_os.environ.get("TGT_API",
                                                     "127.0.0.1:8787"),
                   metavar="[HOST:]PORT|URL",
                   help="control API address (default $TGT_API or "
                        "127.0.0.1:8787)")
    c.add_argument("--token", help="bearer token (default $TGT_API_TOKEN)")
    c.add_argument("--json", action="store_true", help="print raw JSON")
    csub = c.add_subparsers(dest="ctl_cmd", required=True)
    csub.add_parser("status", help="run status and counters")
    csub.add_parser("stop", help="stop the run")
    csub.add_parser("pause", help="hold sending")
    csub.add_parser("resume", help="continue sending")
    cr = csub.add_parser("rate", help="change the send rate")
    cr.add_argument("pps", type=float, help="packets per second")
    ci = csub.add_parser("inject", help="sprinkle an incident for a while")
    ci.add_argument("incident", help="incident key (see 'tgt list')")
    ci.add_argument("--duration", "-d", type=float, default=60.0,
                    help="seconds to inject for (default 60)")
    ci.add_argument("--ratio", type=float, default=None,
                    help="injected share of frames (default: the run's "
                         "--sprinkle-ratio, else 0.05)")
    cm = csub.add_parser("manifest", help="fetch the live run manifest")
    cm.add_argument("--output", "-o", metavar="FILE")
    return p


def _duration(text: str) -> float:
    from .timing import parse_duration
    try:
        return parse_duration(text)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from None


def _timed_args(p) -> None:
    p.add_argument("--speed", type=float, default=1.0, metavar="X",
                   help="timed + wall clock: run X times faster than real "
                        "time (e.g. 60 = an hour per minute)")
    p.add_argument("--min-period", type=_duration, default=0.0,
                   metavar="SECONDS",
                   help="timed: no conversation recurs faster than this "
                        "(thins fast pollers / cyclic I/O for long "
                        "synthetic captures)")


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.argv = list(sys.argv[1:] if argv is None else argv)
    if args.command not in ("iface", "ctl"):
        # plugins (TGT_PLUGIN_PATH / ~/.config/tgt/plugins) first, so env
        # files may use plugin protocols; then env files in TGT_ENV_PATH /
        # ~/.config/tgt/envs join the built-ins
        from . import envfile, plugins
        plugins.load_plugins()
        envfile.load_user_envs()
    if args.command in (None, "tui"):
        # SIGTERM/SIGHUP exit cleanly (curses restores the terminal) — and
        # at all when running as PID 1 in a container
        def _exit(signum, _frame):
            raise SystemExit(128 + signum)
        _install_signal_handlers(_exit)
        return cmd_tui(args)
    return {
        "list": cmd_list, "env": cmd_env, "iface": cmd_iface, "run": cmd_run,
        "inventory": cmd_inventory,
        "score": cmd_score, "campaign": cmd_campaign, "ctl": cmd_ctl,
    }[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
