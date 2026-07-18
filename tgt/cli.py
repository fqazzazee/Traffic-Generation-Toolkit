"""Command-line interface for TGT.

    tgt                      launch the TUI
    tgt list                 list protocols and scenarios
    tgt env                  show detected environment (WSL/Podman/native)
    tgt iface ...            create / delete / list virtual interfaces
    tgt run ...              generate traffic (send and/or write pcap)
"""
from __future__ import annotations

import argparse
import sys
import time

from . import net, protocols, scenarios
from .config import RunConfig
from .engine import Engine
from .packet import Endpoints
from . import enterprise

VERSION = "1.4.0"


# ---------------------------------------------------------------------------
def cmd_list(args) -> int:
    print("Protocols:")
    print(f"  {'key':10} {'name':22} {'cat':4} {'port':7} {'xport':6} desc")
    for p in protocols.all_profiles():
        print(f"  {p.key:10} {p.name:22} {p.category:4} {p.port:7} "
              f"{p.transport:6} {p.desc}")
    print("\nScenarios (curated protocol mixes):")
    for s in scenarios.all_scenarios():
        print(f"  {s.key:14} {s.name:26} [{', '.join(s.profiles)}]")
        print(f"    {s.desc}")
    print("\nEnvironments (modeled organizations — use with --env):")
    for e in enterprise.all_environments():
        print(f"  {e.key:18} {e.name:22} [{e.category}]")
        print(f"    {e.summary()}")
        if e.legacy_hosts():
            leg = ", ".join(f"{h.name} ({h.fp.label})" for h in e.legacy_hosts())
            print(f"    at-risk: {leg}")
    from . import incidents
    print("\nIncidents (famous attacks — detection-test traffic; use with "
          "--incident):")
    for inc in incidents.all_incidents():
        print(f"  {inc.key:14} {inc.name:26} [{inc.category} · {inc.year}]")
        print(f"    {inc.desc}")
        print(f"    signals: {'; '.join(inc.indicators())}")
    return 0


def cmd_env(args) -> int:
    e = net.detect_env()
    print(f"environment : {e.kind}  ({e.detail})")
    print(f"root/CAP_NET: {'yes' if e.is_root else 'no — sending needs sudo'}")
    print(f"iproute2 'ip': {'found' if e.has_ip else 'MISSING'}")
    print("\ninterfaces:")
    for i in net.list_interfaces():
        print(f"  {i['name']:14} state={i['state']:8} mac={i['mac']:18} "
              f"mtu={i['mtu']}")
    if e.kind in ("wsl", "podman", "container"):
        print(f"\nnote: on {e.kind}, run TGT and your capture tool (CTD/tcpdump) "
              "inside the same\n      network namespace so both see the veth pair.")
    return 0


def cmd_iface(args) -> int:
    if args.iface_cmd == "list":
        for i in net.list_interfaces():
            print(f"{i['name']:14} state={i['state']:8} mac={i['mac']:18} "
                  f"mtu={i['mtu']}")
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
            print(f"  # point Claroty CTD / tcpdump at: {peer}")
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
    incident = getattr(args, "incident", None)
    replay = getattr(args, "replay", None)
    if env and env not in enterprise.ENVIRONMENTS:
        print(f"unknown environment: {env}. Try 'tgt list'.", file=sys.stderr)
        return 2
    if incident and incident not in incidents.INCIDENTS:
        print(f"unknown incident: {incident}. Try 'tgt list'.", file=sys.stderr)
        return 2
    if replay:
        import os
        if not os.path.exists(replay):
            print(f"replay file not found: {replay}", file=sys.stderr)
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

    ep = Endpoints(
        client_mac=args.client_mac, client_ip=args.client_ip,
        server_mac=args.server_mac, server_ip=args.server_ip,
        vlan=args.vlan,
    )
    cfg = RunConfig(
        profiles=profs, env=env, incident=incident, sprinkle=sprinkle,
        sprinkle_ratio=max(0.0, getattr(args, "sprinkle_ratio", 0.0)),
        sprinkle_random=getattr(args, "sprinkle_random", False),
        replay_path=replay,
        replay_realtime=getattr(args, "replay_realtime", False),
        iface=args.iface, pcap_path=args.pcap,
        rate=args.rate, count=args.count, duration=args.duration,
        messages=args.messages, loop=not args.once, endpoints=ep,
    )
    if not cfg.iface and not cfg.pcap_path:
        print("nothing to do: specify --iface to send and/or --pcap to write a "
              "file.", file=sys.stderr)
        return 2

    print(f"TGT run: {cfg.summary()}")
    eng = Engine(cfg, on_log=lambda m: print(f"  [engine] {m}"))
    eng.start()
    try:
        while eng.is_alive():
            time.sleep(0.25)
            s = eng.stats
            sys.stdout.write(
                f"\r  sent={s.packets:<8} bytes={s.bytes:<10} "
                f"pps={s.pps:7.1f} Mbps={s.mbps:6.2f} err={s.errors} "
                f"t={s.elapsed:5.1f}s")
            sys.stdout.flush()
    except KeyboardInterrupt:
        print("\n  stopping…")
        eng.stop()
        eng.join(timeout=3)
    print()
    s = eng.stats
    print(f"summary: {s.packets} packets, {s.bytes} bytes, {s.errors} errors "
          f"in {s.elapsed:.1f}s")
    if s.per_profile:
        for k, v in s.per_profile.items():
            print(f"  {k:10} {v}")
    if s.last_error:
        print(f"last error: {s.last_error}")
    return 0 if s.errors == 0 else 1


def cmd_tui(args) -> int:
    from . import tui
    return tui.run()


# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tgt",
        description="Traffic Generation Toolkit — craft OT/ICS + IT test "
                    "traffic onto a virtual interface for SPAN-ingestion "
                    "testing (e.g. Claroty CTD).")
    p.add_argument("--version", action="version", version=f"tgt {VERSION}")
    sub = p.add_subparsers(dest="command")

    sub.add_parser("list", help="list protocols and scenarios")
    sub.add_parser("env", help="show detected environment and interfaces")
    sub.add_parser("tui", help="launch the text UI (default)")

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
                        "enterprise-mixed (see 'tgt list')")
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
    r.add_argument("--iface", "-i", help="interface to send on (needs root)")
    r.add_argument("--pcap", help="also/only write frames to this pcap file")
    r.add_argument("--rate", type=float, default=20.0,
                   help="packets per second (0 = as fast as possible)")
    r.add_argument("--count", type=int, default=0,
                   help="stop after N packets (0 = use --duration)")
    r.add_argument("--duration", type=float, default=0.0,
                   help="stop after N seconds (0 with count=0 = run forever)")
    r.add_argument("--messages", type=int, default=5,
                   help="protocol exchanges per built flow cycle")
    r.add_argument("--once", action="store_true",
                   help="send one cycle then stop (do not loop)")
    r.add_argument("--client-mac", default="02:00:00:00:00:01")
    r.add_argument("--client-ip", default="10.10.10.10")
    r.add_argument("--server-mac", default="02:00:00:00:00:02")
    r.add_argument("--server-ip", default="10.10.10.20")
    r.add_argument("--vlan", type=int, default=None, help="802.1Q VLAN id")
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command in (None, "tui"):
        return cmd_tui(args)
    return {
        "list": cmd_list, "env": cmd_env, "iface": cmd_iface, "run": cmd_run,
    }[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
