<div align="center">

# TGT — Traffic Generation Toolkit

**Generate realistic OT/ICS + IT test traffic onto a virtual interface, so a passive
network monitor can capture and classify it just like a physical SPAN / mirror feed.**

Works with any sensor — **Wireshark, Zeek, Suricata, Security Onion, Malcolm**
(all free/open-source), or a commercial OT platform like **Claroty CTD, Nozomi or
Dragos**. Runs on a workstation, in **WSL**, or in a **Podman / Docker** container.

`zero dependencies` · `pure Python stdlib` · `TUI + CLI` · `runs as a service`

[![Blog](https://img.shields.io/badge/📖%20Blog-Read%20the%20Write--up-FF6C37)](https://blog.safeqbit.com/traffic-generation-toolkit-tgt-make-network-traffic-on-one-machine/)

</div>

---

## Contents

- [What it does](#what-it-does) · [Quick start](#quick-start) · [The TUI](#the-tui)
- Traffic: [Protocols & scenarios](#protocols--scenarios) · [Modeled orgs](#modeled-organizations) · [Attack incidents](#attack-incidents) · [Replay pcaps](#replay-a-pcap)
- Running: [CLI](#cli-reference) · [Service](#run-as-a-service) · [WSL / Podman / Proxmox](#deployment)
- [Verify](#verify) · [Authorized use](#authorized-use) · [Layout](#project-layout)

---

## What it does

A SPAN / mirror port hands a copy of network traffic to a sensor. TGT reproduces that
on a single host — **no real network needed** — using a **veth pair**: two back-to-back
virtual NICs where frames sent on one end appear on the other.

> Generate on **`tgt0`** → point your sensor at **`tgt0-mon`**.

<img width="1024" height="559" alt="SPAN simulation diagram" src="https://github.com/user-attachments/assets/c666137f-5360-434d-b6c4-438a1f49ac10" />

**Highlights:** byte-accurate OT + IT protocols · modeled organizations with OS
fingerprints · famous attack scenarios you can sprinkle into normal traffic · pcap
replay · a live flow-diagram TUI · one-command install and background service · zero
dependencies (Python 3.9+ stdlib only).

---

## Quick start

```bash
git clone https://github.com/fqazzazee/Traffic-Generation-Toolkit.git
cd Traffic-Generation-Toolkit
```

**The interactive UI** — does everything from one screen:

```bash
sudo python3 -m tgt
```
```
 TGT · Traffic Generation Toolkit                                                                                          ● GENERATING
  env: native · root · ip:yes · service:not-installed                                                               ⚠ malware: stuxnet

  ╭─ TGT ENGINE ──────────╮        ╭─ SEND ────────────────╮        ╭─ MONITOR ─────────────╮        ╭─ SENSOR ──────────────╮
  │☣ +stuxnet             │        │ens19                  │        │(no peer)              │        │Zeek/Suricata          │
  │☣s7-con▇▇▇▇▇▇▇▇▇▇▇▇▇▇  │        │▶ out                  │        │capture pt             │        │ingest                 │
  │ modbus▇▇▇▇▇▇▇▇▇▇▇     │        │                       │        │                       │        │                       │
  │ s7comm▇▇▇▇▇▇▇▇▇▇▇     │        │2770                   │        │◀ SPAN                 │        │◀ in                   │
  │☣eterna▇▇▇▇▇▇▇▇▇       │        │packets                │        │                       │        │                       │
  │                       │─•──•──▶│                       │─•──•──▶│                       │─•──•──▶│                       │
  │                       │  emit  │                       │ mirror │                       │ ingest │                       │
  │                       │        │                       │        │                       │        │                       │
  │                       │        │                       │        │                       │        │                       │
  │  20.0 pps             │        │                       │        │                       │        │                       │
  ╰───────────────────────╯        ╰───────────────────────╯        ╰───────────────────────╯        ╰───────────────────────╯

   Map   Protocols   Settings   Service                     │ ─ Live log
                                                            │ 02:46:16 malware sprinkle ON: wannacry
  Preset               (custom protocols)                   │ 02:46:17 start: profiles=modbus,s7comm +malware[wannacry] iface=ens19 rat
  Replay pcap          (off — Enter to set)                 │ 02:46:17 raw socket bound to ens19
  Sprinkle malware     ON                                   │ 02:46:17 built 82 frames/cycle for [modbus, s7comm + malware:wannacry]
    variant            ⚠ stuxnet                            │ 02:46:23 stop requested
    random pick        no                                   │ 02:46:23 done: 128 pkts, 9455 bytes, 0 errors
    ratio              auto (natural)                       │ 02:46:28 start: profiles=modbus,s7comm +malware[wannacry] iface=ens19 rat
  Rate (pps)           20  (0 = max)                        │ 02:46:28 raw socket bound to ens19
  Msgs / cycle         5                                    │ 02:46:28 built 82 frames/cycle for [modbus, s7comm + malware:wannacry]
  Loop                 yes                                  │ 02:46:36 stop requested
  PCAP output          (off)                                │ 02:46:36 done: 172 pkts, 12722 bytes, 0 errors
  Client IP            10.10.10.10                          │ 02:46:40 start: profiles=modbus,s7comm +malware[stuxnet] iface=ens19 rate
  Server IP            10.10.10.20                          │ 02:46:40 raw socket bound to ens19
                                                            │ 02:46:40 built 66 frames/cycle for [modbus, s7comm + malware:stuxnet]
                                                            │ 02:46:46 stop requested
                                                            │ 02:46:46 done: 110 pkts, 7734 bytes, 0 errors
                                                            │ 02:47:29 start: profiles=modbus,s7comm +malware[stuxnet] iface=ens19 rate
                                                            │ 02:47:29 raw socket bound to ens19
                                                            │ 02:47:29 built 66 frames/cycle for [modbus, s7comm + malware:stuxnet]
Tab panel · ↑↓ move · ←→/Enter change · Space toggle · s start/stop · c clear · q quit
```

In the UI: **Map** → `Create veth pair`, then **Protocols** (`Space` to pick), then
press **`s`**. Point your sensor at `tgt0-mon`.

**Headless** — three commands:

```bash
sudo python3 -m tgt iface create tgt0                     # veth: tgt0 <-> tgt0-mon
sudo python3 -m tgt run -s ot-baseline -i tgt0 --rate 50  # generate
sudo tcpdump -i tgt0-mon                                  # capture (or point your sensor here)
```

**As a background service** — three commands:

```bash
sudo ./scripts/tgtctl.sh install     # deps: python3, iproute2, tcpdump
sudo ./scripts/tgtctl.sh register    # writes config + service, creates the veth
sudo ./scripts/tgtctl.sh start
```

**No root?** Just write a pcap (works anywhere; replay later with `tcpreplay`):

```bash
python3 -m tgt run -s ot-full --pcap ot.pcap --count 500
```

---

## The TUI

`python3 -m tgt` (or `tgt`) opens a **live SPAN flow diagram** — packets animate along
the veth path as it generates, and four tabbed panels do everything:

| Panel | What you do |
|---|---|
| **Map** | pick the send interface, see its `-mon` peer, name the sensor, create/delete the veth |
| **Protocols** | toggle any protocol; live per-protocol counters |
| **Settings** | preset (scenario/env/incident), rate, **malware sprinkle** (toggle/variant/random/ratio), pcap replay, endpoints |
| **Service** | service status; save config + start/stop/restart the background service |

The **TGT ENGINE** box lists the most-generated protocols (biggest first, with a
`+N more…` overflow) and shows a red **☣** badge whenever malware traffic is flowing.

**Keys:** `Tab` panel · `↑/↓` move · `Enter`/`←/→` change · `Space` toggle · `s`
start/stop · `c` clear log · `q` quit.

---

## Protocols & scenarios

Byte-accurate builders; TCP protocols emit full SYN→data→FIN sessions and every IP/TCP/
UDP checksum is correct (verified by the self-test).

**OT/ICS:** `modbus` · `dnp3` · `enip` (+`enip-id` Rockwell identity) · `s7comm`
(+`s7-id` Siemens identity) · `iec104` · `bacnet` · `opcua`
**IT:** `arp` · `icmp` · `dns` · `dhcp` · `netbios` · `http` · `https` · `smb`
(SMBv1/SMB2) · `kerberos` · `ldap` · `ntp`

**Scenarios** (curated mixes): `ot-baseline` · `ot-full` · `mixed-site` · `discovery` ·
`it-noise`. Run **`tgt list`** for every protocol, scenario, environment and incident
with descriptions.

```bash
tgt run -p modbus,s7comm -i tgt0        # specific protocols
tgt run -s ot-baseline   -i tgt0        # a scenario
```

---

## Modeled organizations

Generate a whole **modeled network** — named hosts with roles, IPs, vendor MAC OUIs and
**OS/device fingerprints** having realistic conversations — so a sensor has real assets
to discover and vulnerable systems to flag.

```bash
tgt run --env it-org           -i tgt0 --rate 100     # enterprise IT
tgt run --env ot-plant         -i tgt0 --rate 100     # industrial OT
tgt run --env enterprise-mixed -i tgt0 --rate 100     # both, converged
```

| env | models | at-risk fingerprints |
|---|---|---|
| `it-org` | 11 servers (DC×2, DNS, file, SQL, web, mail, proxy, backup) + 12 users; DHCP/DNS/Kerberos/LDAP/SMB/HTTP(S)/NetBIOS/NTP | **legacy Win2000 file server, Win7 + WinXP users** — SMBv1 → MS17-010 |
| `ot-plant` | Rockwell cell (EtherNet/IP) + Siemens cell (S7comm), HMIs, historian, engineering WS | vendor identity + **legacy WinXP/2000 HMIs** |
| `enterprise-mixed` | `it-org` + `ot-plant` together (34 hosts) | the full converged IT/OT mix |

Each host's OS profile shapes its traffic — TTL (128 Windows / 64 Linux / 30 Siemens),
HTTP `User-Agent`, SMB dialect, DHCP/NetBIOS fields, MAC OUI (Rockwell `00:1d:9c`,
Siemens `00:0e:8c`), and PLC identity strings (`1756-L71 LOGIX5571`, `6ES7 315-…`).

---

## Attack incidents

Replay the **network signatures of famous IT/OT incidents** to validate that your
sensor detects them — themed hostnames, the ports and protocol abuse, scan and
C2-beacon patterns, and public IOC domains.

```bash
tgt run --incident wannacry     -i tgt0     # SMBv1 EternalBlue + kill-switch DNS
tgt run --incident stuxnet      -i tgt0     # S7comm PLC STOP + program download
tgt run --incident industroyer  -i tgt0     # IEC-104 breaker command storm
```

| incident | year | reproduces |
|---|---|---|
| `wannacry` | 2017 | SMBv1 MS17-010/DOUBLEPULSAR, 445 scan, kill-switch domain |
| `conficker` | 2008 | MS08-067 SMB spread + DGA C2 domains |
| `mirai` | 2016 | Telnet (23) default-credential scan + C2 |
| `sunburst` | 2020 | SolarWinds `avsvmcloud.com` DGA + HTTP C2 beacon |
| `log4shell` | 2021 | `${jndi:ldap://…}` in HTTP headers |
| `stuxnet` | 2010 | Siemens S7comm PLC control + SMBv1 spread |
| `industroyer` | 2016 | IEC 60870-5-104 breaker commands |
| `triton` | 2017 | TriStation (UDP 1502) to a Triconex SIS |

> **Detection-test traffic only** — synthetic packets carrying the recognizable
> *indicators*, **not** working exploits, shellcode, or malware. For authorized
> detection engineering on your own isolated SPAN (like an IDS ruleset test pcap).

### Sprinkle malware into normal traffic

The most realistic test buries an attack in an otherwise-normal baseline. `--sprinkle`
mixes an incident, as a thin minority, into any base (scenario / environment / protocols):

```bash
tgt run --env it-org --sprinkle wannacry                        -i tgt0   # ~few % malware
tgt run --env it-org --sprinkle wannacry --sprinkle-ratio 0.1   -i tgt0   # exactly ~10%
tgt run --env ot-plant --sprinkle-random --sprinkle-ratio 0.05  -i tgt0   # random attack, 5%
```

- **`--sprinkle-ratio 0.0–0.9`** — fixed malware fraction regardless of base size.
- **`--sprinkle-random`** — random variant + jittered placement each cycle.

In the TUI: **Settings → Sprinkle malware** (toggle · variant · random · ratio); a red
`⚠ malware: <name>` banner shows while armed.

### Replay a pcap

Bring your own capture — a real threat sample, a lab recording — and put it on the wire:

```bash
tgt run --replay threat.pcap -i tgt0                      # at --rate
tgt run --replay threat.pcap -i tgt0 --replay-realtime    # keep original timing
tgt run --replay threat.pcap -i tgt0 --loop               # loop forever
```

Reads classic libpcap (both byte orders, µs/ns; Ethernet, raw-IP, Linux SLL). For
pcapng: `editcap -F pcap in.pcapng out.pcap` first. TUI: **Settings → Replay pcap**.

---

## CLI reference

```
tgt                      launch the TUI (default)
tgt list                 list protocols, scenarios, environments, incidents
tgt env                  detected environment + interfaces
tgt iface create tgt0    create a veth pair (tgt0 <-> tgt0-mon)   [--type dummy]
tgt iface delete|list    remove / list interfaces

tgt run [options]
  -p, --profile K[,K]    protocol(s), repeatable        -s, --scenario NAME
  -e, --env NAME         it-org | ot-plant | enterprise-mixed
      --incident NAME    wannacry | stuxnet | industroyer | triton | …
      --sprinkle N[,N]   mix incident(s) into the base traffic
      --sprinkle-ratio F   target malware fraction 0.0–0.9 (0 = natural)
      --sprinkle-random    random variant + jittered placement
      --replay FILE      replay a .pcap        --replay-realtime  keep its timing
  -i, --iface NAME       send on this interface (needs root)
      --pcap PATH        write frames to a pcap        --rate PPS   (0 = max)
      --count N | --duration SECS | --once        --messages N   (default 5)
      --client-ip/-mac · --server-ip/-mac · --vlan ID
```

---

## Run as a service

`tgtctl.sh` is one cross-distro control script — **systemd** when present, else a
**PID-file daemon** (so it also works on WSL-without-systemd and in containers).

| Command | Does |
|---|---|
| `install` | system deps (apt/dnf/apk/pacman/zypper) + optional `tgt` command + self-test |
| `register` | write `/etc/tgt/tgt.conf` + service unit, create the veth, enable at boot |
| `start` / `stop` / `restart` / `status` / `logs` | manage the running service |
| `unregister` | stop, disable, remove the service + veth (keeps config) |

Config — `/etc/tgt/tgt.conf` (also editable live from the TUI's Service panel):

```sh
TGT_IFACE=tgt0
TGT_RUN_ARGS="--scenario ot-baseline --rate 50"   # any `tgt run` args
```

The systemd unit runs least-privilege (`CAP_NET_ADMIN` + `CAP_NET_RAW` only) and
creates the veth in `ExecStartPre`.

---

## Deployment

### WSL

WSL 2 has a real Linux kernel, so veth + `AF_PACKET` work normally. Run your sensor in
the **same** distro to share the network namespace and see `tgt0-mon`. Without systemd,
`tgtctl.sh` uses daemon mode automatically — same commands.

### Podman / Docker

Run privileged (raw sockets + `ip link` need `CAP_NET_ADMIN` + `CAP_NET_RAW`):

```bash
podman build -t tgt -f Containerfile .
podman run --rm -it --cap-add=NET_ADMIN --cap-add=NET_RAW tgt \
    run -s ot-baseline -i tgt0 --rate 50          # entrypoint creates tgt0

# share a namespace so TGT + a sensor container both see the veth:
podman run -d --name sensor --cap-add=NET_RAW <sensor-image>
podman run --rm -it --network container:sensor --cap-add=NET_ADMIN --cap-add=NET_RAW \
    tgt run -s ot-baseline -i tgt0-mon --rate 50
```

### Proxmox — feed a Traffic Analyser VM (hub bridge)

Typical lab: **TGT in one VM, the analyser** (Zeek, Suricata, Security Onion, Malcolm,
Claroty CTD, …) **in another, on the same host.** Put both VMs on an isolated Linux
bridge run as a **hub** — no MAC learning, so every frame floods to the analyser, just
like a SPAN feed.

The `/etc/network/interfaces` file creates the bridge; the VM `tap` ports are created
dynamically at VM start, so a small hookscript sets the hub flag after each VM boots.

**1. Create the isolated bridge** (GUI: *node → System → Network → Create → Linux
Bridge*, or edit the file directly), then `ifreload -a`:

```
# /etc/network/interfaces
auto vmbrspan
iface vmbrspan inet manual
    bridge-ports none
    bridge-stp off
    bridge-fd 0
```

`bridge-ports none` keeps it isolated (no uplink → traffic never leaves the host);
`inet manual` gives it no IP — a pure L2 SPAN segment.

**2. Make it a hub** with a Proxmox hookscript. Create `/var/lib/vz/snippets/spanhub.sh`:

```bash
#!/bin/bash
# After a VM starts, make its SPAN bridge a hub (no learning => floods all ports).
[ "$2" = "post-start" ] || exit 0
for p in $(ls /sys/class/net/vmbrspan/brif 2>/dev/null); do
    bridge link set dev "$p" learning off flood on mcast_flood on
done
```

Make it executable and attach it to **both** VMs (whichever boots last re-flips every
port); it re-applies on every start, so it survives reboots:

```bash
chmod +x /var/lib/vz/snippets/spanhub.sh
qm set <TGT_VMID>      --hookscript local:snippets/spanhub.sh
qm set <ANALYSER_VMID> --hookscript local:snippets/spanhub.sh
```

**3. Attach both VMs' NICs** to `vmbrspan` (*VM → Hardware → Network Device*, **firewall
unchecked**). The analyser's NIC must be **promiscuous** (`ip link set eth0 up promisc
on`); most sensors set this themselves.

**4. Generate and verify** — point TGT at its bridge NIC (`TGT_IFACE=eth0` in
`/etc/tgt/tgt.conf`, or `-i eth0` on the CLI, or the TUI's **Map** panel), then confirm
on the analyser with `tcpdump -i <nic>` that the traffic arrives.

> Not using a hookscript? Just run the `for p in … bridge link set …` loop by hand
> once after starting the VMs. Verify with `bridge -d link show | grep -A1 vmbrspan` —
> each port should read `learning off flood on`.

---

## Verify

```bash
python3 -m tests.selftest      # packet builders, checksums, sessions, pcap, incidents
make test                      # same, via the Makefile
```

## Authorized use

TGT is a **test-traffic generator for lab and authorized assessment use.** It crafts
synthetic packets between endpoints you configure, on interfaces you create — no
scanning, exploitation, or interaction with third-party systems. Run it only on
networks you own or are authorized to test, and prefer the isolated veth pair so
frames never leave the host. The incident scenarios carry *detectable signatures*, not
functional exploits — for authorized detection engineering only.

## Project layout

```
tgt/  packet · protocols · scenarios · enterprise · incidents · pcap · pcapread
      sender · net · service · engine · config · cli · tui
scripts/  tgtctl.sh (install + service)   setup-veth.sh
tests/    selftest.py        Containerfile · docker-entrypoint.sh · Makefile · pyproject.toml
```

---

## License & security

- **License:** [MIT](LICENSE).
- **Security policy & vulnerability reporting:** [SECURITY.md](SECURITY.md).

> **Built with AI assistance.** Parts of this project were written with the help of an
> AI coding assistant. Review the code and test it in your own environment before
> relying on it — and use it only where you are authorized to (see [Authorized use](#authorized-use)).
