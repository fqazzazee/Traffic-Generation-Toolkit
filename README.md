<div align="center">

# TGT — Traffic Generation Toolkit

**Generate realistic OT/ICS + IT test traffic onto a virtual interface, so a passive
sensor can capture and classify it exactly as it would a physical SPAN / mirror feed.**

Built for exercising **Claroty CTD SPAN ingestion** — and any other sensor
(Wireshark, Zeek, Suricata, Nozomi, tcpdump) — on a workstation, in **WSL**, or in a
**Podman / Docker** container.

`zero dependencies` · `pure Python stdlib` · `TUI + CLI` · `runs as a service`

</div>

---

## Highlights

- **Zero dependencies.** Pure Python standard library — no scapy, no pip packages to
  build. Runs anywhere Python 3.9+ runs.
- **Simple TUI.** A keyboard-driven terminal dashboard, plus a full CLI for scripting
  and CI.
- **Real protocol patterns.** Byte-accurate Modbus/TCP, DNP3, EtherNet/IP + CIP,
  S7comm, IEC 60870-5-104, BACnet/IP, OPC UA, plus ARP, ICMP, DNS, HTTP, NTP.
- **Two output modes.** Send live on an interface (root / `CAP_NET_RAW`), or write a
  `.pcap` (needs nothing) for offline replay with `tcpreplay`.
- **One-command setup + service.** `tgtctl.sh` installs system deps and
  registers/starts/stops/restarts TGT as a background service (systemd, with a
  PID-file fallback for WSL-without-systemd and containers).

---

## How the SPAN simulation works

A SPAN / mirror port delivers a copy of network traffic to a sensor. TGT reproduces
that on a single host — no real network required — with a **veth pair**: two
back-to-back virtual NICs. Frames written to one end appear on the other.

```
        TGT generates                     your sensor captures
        ┌───────────┐                     ┌────────────────────┐
        │  tgt run  │ ── frames ──▶ tgt0  │ tgt0-mon ── SPAN ──▶│ Claroty CTD
        └───────────┘              (veth pair, back-to-back)    │ / tcpdump / Zeek
                                                                └────────────────────┘
```

Generate on **`tgt0`**; point your capture tool at **`tgt0-mon`**.

---

## Quick start

### Option A — one-command install & service (recommended)

```bash
git clone <repo> TGT && cd TGT

sudo ./scripts/tgtctl.sh install     # system deps (python3, iproute2, tcpdump)
sudo ./scripts/tgtctl.sh register    # writes config + service, creates the veth
sudo ./scripts/tgtctl.sh start       # start generating in the background

sudo ./scripts/tgtctl.sh status      # check it
sudo ./scripts/tgtctl.sh logs        # follow output
```

Then point your sensor at the monitor interface:

```bash
sudo tcpdump -i tgt0-mon             # or point Claroty CTD at tgt0-mon
```

Tune what it generates by editing the config, then restart:

```bash
sudoedit /etc/tgt/tgt.conf           # set TGT_IFACE and TGT_RUN_ARGS
sudo ./scripts/tgtctl.sh restart
```

### Option B — run it directly (no service)

```bash
# Create the SPAN-simulation veth pair (once)
sudo python3 -m tgt iface create tgt0        # makes tgt0 <-> tgt0-mon

# Generate a steady OT baseline on tgt0
sudo python3 -m tgt run --scenario ot-baseline --iface tgt0 --rate 50
```

### Option C — no privileges, just a pcap

```bash
python3 -m tgt run --scenario ot-full --pcap ot.pcap --count 500
tcpreplay -i eth0 ot.pcap                     # replay later onto a real SPAN source
```

### Launch the TUI

```bash
python3 -m tgt        # or `tgt` after `pip install -e .`
```

---

## The service — `tgtctl.sh`

A single cross-distro control script. It uses **systemd** when present and falls back
to a **PID-file daemon** otherwise (so it also works on WSL without systemd and inside
plain containers).

| Command | Does |
|---|---|
| `install` | Install system deps via apt/dnf/apk/pacman/zypper; optionally the `tgt` command; run the self-test |
| `register` | Write `/etc/tgt/tgt.conf` + the service unit, create the veth, enable at boot |
| `start` / `stop` / `restart` | Manage the running service |
| `status` | Show service status and recent output |
| `logs` | Follow logs (`journalctl -u tgt` or the daemon logfile) |
| `unregister` | Stop, disable, remove the service and its veth (keeps config) |
| `config` | Print (and create) the config file path |

**Config — `/etc/tgt/tgt.conf`:**

```sh
# Virtual interface to generate on. A veth pair <IFACE> <-> <IFACE>-mon is created
# automatically; point your sensor (Claroty CTD / tcpdump) at the -mon end.
TGT_IFACE=tgt0

# Arguments passed to `tgt run`. The service loops until stopped.
TGT_RUN_ARGS="--scenario ot-baseline --rate 50"
```

The systemd unit runs with least privilege — only `CAP_NET_ADMIN` + `CAP_NET_RAW`,
not full root — and creates the veth in `ExecStartPre`.

---

## The TUI

```
 TGT · Traffic Generation Toolkit
 env: wsl · root · ip:yes
  Send interface    : tgt0                   ── Live ──
  PCAP output       : (disabled)             state   : RUNNING
  Protocols         : modbus, s7comm         packets : 1840
  Load scenario     : press Enter to pick…   pps     : 50.0
  Rate (pps)        : 50                      per-protocol:
  Loop              : yes                       modbus   920
  ▶ START / STOP    : running…                  s7comm   920
```

Keys: `↑/↓` move · `Enter` / `←/→` change a field · `Space` toggle a protocol ·
`s` start/stop · `c` clear log · `q` quit.

---

## Protocols

| key | protocol | cat | port / transport |
|---|---|---|---|
| `modbus` | Modbus/TCP | OT | 502 / tcp |
| `dnp3` | DNP3 | OT | 20000 / tcp |
| `enip` | EtherNet/IP + CIP | OT | 44818 / tcp |
| `s7comm` | S7comm (Siemens) | OT | 102 / tcp |
| `iec104` | IEC 60870-5-104 | OT | 2404 / tcp |
| `bacnet` | BACnet/IP | OT | 47808 / udp |
| `opcua` | OPC UA | OT | 4840 / tcp |
| `arp` | ARP | IT | — / l2 |
| `icmp` | ICMP echo | IT | — / ip |
| `dns` | DNS | IT | 53 / udp |
| `http` | HTTP | IT | 80 / tcp |
| `ntp` | NTP | IT | 123 / udp |

TCP protocols emit a coherent session (SYN / SYN-ACK / ACK → PSH data → FIN) so
stream-reassembling sensors see a real conversation, not orphaned segments. All IP,
TCP and UDP checksums are computed correctly (verified by the self-test).

### Scenarios (curated mixes)

`ot-baseline` · `ot-full` · `mixed-site` · `discovery` · `it-noise` — run `tgt list`
for the exact protocol set and intent of each.

---

## CLI reference

```
tgt                               launch the TUI (default)
tgt list                          list protocols and scenarios
tgt env                           detected environment + interfaces
tgt iface create tgt0             create a veth pair (tgt0 <-> tgt0-mon)
tgt iface create d0 --type dummy  create a single dummy interface
tgt iface delete tgt0             remove an interface
tgt iface list                    list interfaces

tgt run [options]
  -p, --profile KEY[,KEY]   protocol(s); repeatable  (e.g. -p modbus,s7comm)
  -s, --scenario NAME       load a named scenario
  -i, --iface NAME          send on this interface (needs root)
      --pcap PATH           write/also-write frames to a pcap file
      --rate PPS            packets per second (0 = as fast as possible)
      --count N             stop after N packets
      --duration SECS       stop after N seconds
      --messages N          protocol exchanges per build cycle (default 5)
      --once                one cycle then stop (default: loop)
      --client-ip/-mac      source endpoint (default 10.10.10.10)
      --server-ip/-mac      destination endpoint (default 10.10.10.20)
      --vlan ID             wrap frames in an 802.1Q VLAN tag
```

---

## Platform notes

### WSL

WSL 2 runs a real Linux kernel, so veth + `AF_PACKET` work normally. Run your
sensor/capture inside the **same** WSL distro so it shares the network namespace and
can see `tgt0-mon`. If systemd is disabled in your distro, `tgtctl.sh` automatically
uses its PID-file daemon mode — the same commands still work.

### Podman / Docker

Build and run privileged (raw sockets + `ip link` need `CAP_NET_ADMIN` +
`CAP_NET_RAW`):

```bash
podman build -t tgt -f Containerfile .
podman run --rm -it --cap-add=NET_ADMIN --cap-add=NET_RAW tgt \
    run -s ot-baseline -i tgt0 --rate 50     # entrypoint creates tgt0 first
```

Share a network namespace so TGT and your sensor container both see the veth:

```bash
podman run -d --name sensor --cap-add=NET_RAW <your-sensor-image>
podman run --rm -it --network container:sensor --cap-add=NET_ADMIN --cap-add=NET_RAW \
    tgt run -s ot-baseline -i tgt0-mon --rate 50
```

The unprivileged fallback always works: generate a pcap and hand it to the sensor
offline.

---

## Verify the install

```bash
python3 -m tests.selftest      # validates packet builders, checksums, sessions, pcap
make test                      # same, via the Makefile
```

---

## Authorized use only

TGT is a **test-traffic generator for lab and authorized assessment use.** It crafts
synthetic packets between endpoints you configure, on interfaces you create. It
performs no scanning, exploitation, or interaction with third-party systems. Only run
it on networks and interfaces you own or are explicitly authorized to test — and
prefer the isolated veth pair so generated frames never leave the host.

---

## Project layout

```
tgt/
  packet.py      raw Ethernet/IP/TCP/UDP/ARP builders + checksums
  protocols.py   per-protocol payload + flow builders, profile registry
  scenarios.py   curated multi-protocol mixes
  pcap.py        libpcap file writer
  sender.py      AF_PACKET raw send + rate limiter
  net.py         environment detection + veth/dummy management
  engine.py      build → send/write loop with live stats (threaded)
  config.py      run configuration
  cli.py         argparse command-line interface
  tui.py         curses text UI
scripts/
  tgtctl.sh      install deps + service lifecycle (systemd / daemon)
  setup-veth.sh  standalone veth-pair creator
tests/
  selftest.py    dependency-free verification suite
Containerfile · docker-entrypoint.sh · Makefile · pyproject.toml
```
