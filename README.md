<div align="center">

# TGT — Traffic Generation Toolkit

**Generate realistic OT/ICS + IT test traffic onto a virtual interface, so a passive
network monitor can capture and classify it just like a physical SPAN / mirror feed.**

Works with any sensor — **Wireshark, Zeek, Suricata, Security Onion, Malcolm**
(all free/open-source), or a commercial OT platform like **Claroty CTD, Nozomi or
Dragos**. Runs on a workstation, in **WSL**, or in a **Podman / Docker** container.

`zero dependencies` · `pure Python stdlib` · `TUI + CLI` · `runs as a service`

[![Blog](https://img.shields.io/badge/📖%20Blog-Read%20the%20Write--up-FF6C37)](https://blog.safeqbit.com/traffic-generation-toolkit-tgt-make-network-traffic-on-one-machine/)
[![Buy me a coffee](https://img.shields.io/badge/Buy%20me%20a%20coffee-FFDD00?logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/fqazzazee)

</div>

---

## Contents

- [What it does](#what-it-does) · [Quick start](#quick-start) · [The TUI](#the-tui)
- Traffic: [Protocols & scenarios](#protocols--scenarios) · [Modeled orgs](#modeled-organizations) · [Attack incidents](#attack-incidents) · [Replay pcaps](#replay-a-pcap)
- Running: [CLI](#cli-reference) · [Service](#run-as-a-service) · [WSL / Podman / Proxmox](#deployment) · [Sensor in another VM](#sensor-on-another-machine-or-vm)
- [Verify](#verify) · [Authorized use](#authorized-use) · [Layout](#project-layout)

---

## What it does

A SPAN / mirror port hands a copy of network traffic to a sensor. TGT reproduces that
on a single host — **no real network needed** — using a **veth pair**: two back-to-back
virtual NICs where frames sent on one end appear on the other.

> Generate on **`tgt0`** → point your sensor at **`tgt0-mon`**.

A veth only reaches a sensor that shares this host's kernel (the host itself, a
container, a network namespace). For a sensor in **another VM or on another machine**,
send on a real interface and let a switch or hypervisor mirror it; see
[Sensor on another machine or VM](#sensor-on-another-machine-or-vm).

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

## Demo

See Traffic Generation Toolkit in action:

https://github.com/user-attachments/assets/36108f6f-9ab7-4748-a387-1102560a0a3b



In the UI: **Interfaces** → `Create veth pair`, then **Run** → Preset (or **Traffic**,
`Space` to pick protocols), then press **`s`**. Point your sensor at `tgt0-mon`.

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

`python3 -m tgt` (or `tgt`) opens a **live SPAN flow diagram**, drawn for how frames
actually reach your sensor. TGT reads the send interface's type from the kernel:

```
veth pair        TGT ENGINE ──▶ SEND tgt0 ──veth──▶ MONITOR tgt0-mon ──▶ SENSOR
real interface   TGT ENGINE ──▶ SEND eth0 ┈┈SPAN┈┈▶ SENSOR     (a switch / vSwitch mirrors it)
pcap only        TGT ENGINE ──▶ PCAP file ┈import┈▶ SENSOR     (offline, not animated)
```

Packets animate along the path as it generates, and each box carries live data:

- **TGT ENGINE:** the preset, any sprinkled malware, the traffic mix (share of frames per
  protocol, biggest first; malware rows always stay on screen), pps and elapsed time.
- **SEND / PCAP:** interface, link state and type (or the pcap file), packets, bytes,
  Mb/s, errors, frames per cycle.
- **MONITOR** (veth only): the peer and its state, the SPAN view and VLAN tagging.
- **SENSOR:** your sensor's name and how it gets the traffic: the veth peer it listens on,
  the interface it gets a SPAN of, or the pcap it imports.

Four tabbed panels below drive it. Each shows only the rows that apply to the current
preset, explains the selected row underneath, and the key bar lists what the keys do there:

| Panel | What you do |
|---|---|
| **Run** | preset (pick from a filterable list: scenarios, environments, incidents, pcap replay), **SPAN view** (access/core, for an env), **malware sprinkle** (toggle/variant/random/ratio), rate, messages, loop, pcap output, endpoints |
| **Traffic** | toggle protocols for a custom mix; live per-protocol counters |
| **Interfaces** | pick the send interface and see how it reaches the sensor (veth pair or real interface that needs a SPAN), name the sensor, create/delete a veth pair (delete asks you to type the name and is never offered for a real interface) |
| **Service** | service status and the exact `tgt run` it would execute; save config + start/stop/restart |

Choosing a preset puts its protocols on the **Traffic** tab (an incident's attack-only
traffic, such as a port scan, is listed next to them), and toggling one there starts a
custom mix from them. `tgt list` shows each environment's and incident's protocols too.

Below 80 columns the diagram collapses to a one-line flow strip.

**Keys:** `Tab` panel · `↑/↓` move · `←/→` change · `Enter` pick/edit/run · `Space`
toggle · `s` start/stop · `c` clear log · `?` help · `q` quit.

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
tgt run --env industrial-site  -i tgt0 --rate 500     # large Purdue-model plant
```

| env | models | at-risk fingerprints |
|---|---|---|
| `it-org` | 11 servers (DC×2, DNS, file, SQL, web, mail, proxy, backup) + 12 users; DHCP/DNS/Kerberos/LDAP/SMB/HTTP(S)/NetBIOS/NTP | **legacy Win2000 file server, Win7 + WinXP users** — SMBv1 → MS17-010 |
| `ot-plant` | Rockwell cell (EtherNet/IP) + Siemens cell (S7comm), HMIs, historian, engineering WS | vendor identity + **legacy WinXP/2000 HMIs** |
| `enterprise-mixed` | `it-org` + `ot-plant` together (34 hosts) | the full converged IT/OT mix |
| `industrial-site` | 97 hosts on 9 VLANs: corporate IT, IT/OT DMZ, L3 operations, Rockwell packaging (Logix + PowerFlex), Siemens process, Schneider Modicon utilities + PM5560 meters, Johnson Controls/Tridium BACnet BMS, SEL RTAC + relays over DNP3, IEC-104 RTU | legacy Win7/XP HMIs and users, a Server 2012 R2 OT domain controller, and **an IT laptop polling a meter directly (L4 → L1)** |

Each host's OS profile shapes its traffic — TTL (128 Windows / 64 Linux / 30 Siemens),
HTTP `User-Agent`, SMB dialect, DHCP/NetBIOS fields, MAC OUI (Rockwell `00:1d:9c`,
Siemens `00:0e:8c`), and PLC identity strings (`1756-L71 LOGIX5571`, `6ES7 315-…`).

**Endpoint EDR (CrowdStrike Falcon).** Every Windows **and Linux** host that can run a
Falcon sensor (Win7 SP1+ / Server 2012+, Linux servers) keeps a TLS telemetry channel open
to the CrowdStrike Security Cloud, egressing via its gateway like any internet-bound flow —
so the sensor sees normal EDR traffic on each covered endpoint (protocol key `edr`). The
tell is the SNI: the **EU-1** cloud hosts `ts01-lanner-lion.cloudsink.net` (sensor channel),
`lfoup01-` / `lfodown01-lanner-lion.cloudsink.net` (telemetry / content) and
`api.eu-1.crowdstrike.com`. Each FQDN resolves to many AWS IPs, so the fleet's beacons are
spread across CrowdStrike's published **EU-1 (eu-central-1 / Frankfurt) egress IP set**
(`CROWDSTRIKE_CLOUD_IPS` in `tgt/enterprise.py`). The EOL **WinXP / Win2000** hosts and the
**embedded OT devices** (PLCs, RTUs, relays, drives, meters, BACnet/JACE firmware) stay
deliberately *uncovered* — a real gap an analyser should flag.

Hosts sit in **segments**, each with its own VLAN, subnet, zone and gateway, routed by a core L3
switch whose gateway MACs are HSRP virtual MACs (`00:00:0c:07:ac:<vlan>`):

| segment | VLAN | subnet | zone |
|---|---|---|---|
| `IT-SERVERS` | 10 | 10.20.10.0/24 | IT |
| `IT-USERS` | 20 | 10.20.20.0/24 | IT |
| `OT-SUPERVISORY` | 100 | 172.16.0.0/24 | OT-SUPERVISORY (Purdue L3) |
| `OT-CELL-RW` | 110 | 172.16.1.0/24 | OT-CELL (L1–2, Rockwell) |
| `OT-CELL-S7` | 120 | 172.16.2.0/24 | OT-CELL (L1–2, Siemens) |

`industrial-site` has its own segments: `CORP-SERVERS` (10) and `CORP-USERS` (20) in IT,
`IT-OT-DMZ` (50) as the DMZ, `OT-OPS` (100) at L3, and five L1–2 cells: `AREA-PACKAGING` (110),
`AREA-PROCESS` (120), `AREA-UTILITIES` (130), `BMS` (140) and `SUBSTATION` (150). IT segments
use `10.10.<n>.0/24` and OT segments use `10.100.<n>.0/24`. Run `tgt list` to see them all.

Every env frame carries its segment's 802.1Q tag. Same-segment flows are switched
peer to peer, and cross-segment flows are addressed to the sender's gateway MAC. `--span`
picks where the sensor sits:

```bash
tgt run --env it-org --span access -i tgt0   # default: each frame once, on the sender's VLAN
tgt run --env it-org --span core   -i tgt0   # + routed copy on the receiver's VLAN (gw MAC, TTL-1)
```

### Ground-truth inventory

`tgt inventory` exports what a sensor *should* discover from an environment, so you can diff it
against your analyser's asset list (Claroty CTD, Nozomi, Zeek `known_hosts`, …):

```bash
tgt inventory -e industrial-site                    > site.csv    # one row per host
tgt inventory -e industrial-site -f json -o site.json             # + segments and expected flows
```

Each host row has: name, IP, MAC, MAC vendor, device vendor and product, role, OS/firmware,
segment, VLAN, subnet, zone, gateway, legacy flag, risk note, services served
(`modbus 502/tcp`, …) and protocols used. The JSON `flows` list is the expected
communication baseline, including the planted contractor → meter violation in `industrial-site`.

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
| `notpetya` | 2017 | SMBv1 EternalBlue worm + 445 sweep (destructive) |
| `ryuk` | 2019 | HTTP C2 + 445/3389 scan + SMB lateral movement |
| `blackenergy` | 2015 | Ukraine-grid HTTP C2 + substation port recon |
| `emotet` | 2018 | HTTP C2 beacon + DNS tunneling / exfil |
| `colonial` | 2021 | DarkSide: TLS C2, RDP spray, SMB admin-share lateral |
| `havex` | 2014 | Dragonfly: HTTP C2 + OPC/ICS control-port scan |
| `ekans` | 2020 | ICS ransomware: SMB lateral + unauthorized Modbus writes |
| `pipedream` | 2022 | INCONTROLLER: ICS port scan + Modbus Write-Registers |
| `vpnfilter` | 2018 | Router botnet: HTTP C2 + Modbus manipulation |

Run `tgt list` for every incident with the exact protocols and signals each emits.
New attack signatures available to incidents: DNS tunneling, TLS/SNI C2 beaconing,
RDP (`mstshash`) password spray, SMB admin-share (`ADMIN$`/`IPC$`) lateral movement,
and unauthorized Modbus Write Multiple Registers — alongside the earlier SMBv1
EternalBlue, HTTP C2, DGA DNS, Telnet brute, Log4Shell JNDI, S7 control, IEC-104
commands and TriStation.

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

The incident's hosts are always re-addressed onto a **real inventory**, so the same
machines appear infected across cycles. On an `--env` base that inventory is the chosen
environment and the attack rides on its VLANs; on a scenario / protocol base (which has no
hosts of its own) the malware is mapped onto a representative full-Purdue plant so it still
looks like real assets. Each host maps onto one with the same role (or, failing that, a
related role: PLC / RTU / relay / drive / meter, or SCADA / HMI / historian), so Windows
malware lands on Windows hosts and a PLC attack on a PLC. An embedded device must also match
by vendor (MAC OUI): Industroyer's IEC-104 RTU lands on a Siemens RTU or PLC, never a
Rockwell one. The mapping runs **top-down through the Purdue model** — enterprise stages
first, plant floor last — so a multi-stage attack descends IT → supervisory → cell as a
coherent kill chain, with a cell's devices kept together. Only the *internal* hosts are
remapped — a C2 node or internet attacker keeps its own address, which is always a **public
IP** (RFC 5737 TEST-NET, or the campaign's real C2 IOC such as Industroyer's `195.16.88.6`),
so an infected inventory asset is seen beaconing *out to the internet*, never to some other
internal subnet the sensor doesn't monitor.

> **SPAN view matters for a sensor.** `--span core` emits *two copies* of every routed
> packet (ingress on the sender's VLAN, egress on the receiver's VLAN, TTL−1) — it models a
> capture taken at the core L3 switch. On a flat "TGT → one NIC → sensor" feed that just
> doubles traffic with gateway-MAC rewriting, which a stream reassembler reads as
> duplicates. For a single SPAN to one sensor, use the default **`--span access`** (each
> frame once, on its sender's VLAN).

In the TUI: **Run → Malware sprinkle** (toggle · variant · random · ratio); a red
`☣ malware: <name>` banner shows while armed.

### Replay a pcap

Bring your own capture — a real threat sample, a lab recording — and put it on the wire:

```bash
tgt run --replay threat.pcap -i tgt0                      # at --rate
tgt run --replay threat.pcap -i tgt0 --replay-realtime    # keep original timing
tgt run --replay threat.pcap -i tgt0 --loop               # loop forever
```

Reads classic libpcap (both byte orders, µs/ns; Ethernet, raw-IP, Linux SLL). For
pcapng: `editcap -F pcap in.pcapng out.pcap` first. TUI: **Run → Preset → replay a pcap file…**.

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
  -e, --env NAME         it-org | ot-plant | enterprise-mixed | industrial-site
      --span VIEW        access | core  (env capture point; core adds routed hops)
      --incident NAME    wannacry | stuxnet | industroyer | triton | …
      --sprinkle N[,N]   mix incident(s) into the base traffic
      --sprinkle-ratio F   target malware fraction 0.0–0.9 (0 = natural)
      --sprinkle-random    random variant + jittered placement
      --replay FILE      replay a .pcap        --replay-realtime  keep its timing
  -i, --iface NAME       send on this interface (needs root)
      --pcap PATH        write frames to a pcap        --rate PPS   (0 = max)
      --count N | --duration SECS | --once        --messages N   (default 5)
      --client-ip/-mac · --server-ip/-mac · --vlan ID

tgt inventory -e ENV     ground-truth asset list    [-f csv|json] [-o FILE]
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

### Sensor on another machine or VM

A veth pair lives inside one kernel, so a sensor in a separate VM or on another machine
can't open `tgt0-mon`. Send on a **real interface** instead (`-i eth0`, or pick it in the
TUI's Interfaces tab) and let something in between copy the traffic to the sensor:

| Setup | How the sensor gets the traffic |
|---|---|
| TGT and the sensor are VMs on one hypervisor | The hypervisor mirrors TGT's vNIC to the sensor's monitor vNIC: a Proxmox hub bridge (next section), or VMware / Nutanix / Xen port mirroring ([`SPAN Configuration/`](SPAN%20Configuration/README.md)). |
| TGT on a KVM/Proxmox host, sensor in a VM | Put the veth peer on the sensor's bridge and make it a hub: `ip link set tgt0-mon master vmbrspan` and `ip link set vmbrspan type bridge ageing_time 0`. Without hub mode the bridge learns that every TGT MAC sits behind `tgt0-mon` and stops flooding frames to the sensor. |
| Physical lab switch | Send from a host on a port or VLAN the switch mirrors (a SPAN **source**) to the sensor's monitor port. |
| No mirroring available | Write a pcap (`--pcap`) and import it into the sensor, if it supports offline analysis. |

Don't transmit out of the sensor's own capture NIC. The sensor may ignore its own
outgoing frames, and a switch port configured to accept ingress on a SPAN destination
would forward TGT's synthetic OT commands and attack traffic into the real network.
Mirror traffic only on isolated segments you're authorized to test.

### TGT VM — bring the send interface up (and promiscuous if needed)

On the TGT VM, the send interface must be **UP** before TGT can transmit — `AF_PACKET`
can't send on a down link. Bring it up (no IP is needed; it's a pure transmit port):

```bash
sudo ip link set eth0 up                 # the NIC TGT sends on (-i eth0 / TGT_IFACE)
ip link show eth0                         # expect: state UP ... (and PROMISC if set below)
```

TGT builds every frame with a **synthetic source MAC** — vendor OUIs, the HSRP gateway
MAC, the veth peer, not the vNIC's own address. A hypervisor vSwitch drops those by
default because the source MAC doesn't match the one it assigned the port, so the sensor
sees nothing. Two things fix it, and you usually need both:

- **On the TGT VM**, put the send NIC in **promiscuous** mode so the guest hands all
  crafted frames to the vNIC rather than only its own-MAC traffic:

  ```bash
  sudo ip link set eth0 promisc on         # PROMISC appears in `ip link show eth0`
  sudo ip link set eth0 promisc off        # revert
  ```

- **On the hypervisor**, allow forged source MACs on the port group feeding TGT's vNIC —
  on VMware that's **Promiscuous Mode + MAC Address Changes + Forged Transmits** set to
  *Accept* ([`SPAN Configuration/VMware.md`](SPAN%20Configuration/VMware.md)); other
  hypervisors have the equivalent. A plain Linux-bridge / Proxmox hub (below) floods
  regardless, so it needs no forged-transmit flag.

Both settings are runtime-only and reset on reboot. To make them durable, set the port
group / portgroup policy on the hypervisor, and persist the guest link state the usual
way — a systemd unit, a NetworkManager/`/etc/network/interfaces` stanza, or a `@reboot`
cron entry running the `ip link set … up promisc on` above. A **veth** send interface
(TGT's default, on the same host as the sensor) needs none of this: `iface create`
already brings both ends up, and synthetic MACs flood freely across a local veth/bridge.

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
`/etc/tgt/tgt.conf`, or `-i eth0` on the CLI, or the TUI's **Interfaces** panel), then confirm
on the analyser with `tcpdump -i <nic>` that the traffic arrives.

> Not using a hookscript? Just run the `for p in … bridge link set …` loop by hand
> once after starting the VMs. Verify with `bridge -d link show | grep -A1 vmbrspan` —
> each port should read `learning off flood on`.

> Full GUI-first walkthroughs (official docs + community tips + CLI fallbacks) for
> Proxmox, Nutanix AHV, and VMware vSphere are in
> [`SPAN Configuration/`](SPAN%20Configuration/).

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
tgt/  packet · protocols · scenarios · enterprise · inventory · incidents · pcap · pcapread
      sender · net · service · engine · config · cli · tui
scripts/  tgtctl.sh (install + service)   setup-veth.sh
tests/    selftest.py        Containerfile · docker-entrypoint.sh · Makefile · pyproject.toml
```

---

## Support

If it saved you building a test network for your sensor, you can [buy me a coffee ☕](https://buymeacoffee.com/fqazzazee).

---

## License & security

- **License:** [MIT](LICENSE).
- **Security policy & vulnerability reporting:** [SECURITY.md](SECURITY.md).

> **Built with AI assistance.** Parts of this project were written with the help of an
> AI coding assistant. Review the code and test it in your own environment before
> relying on it — and use it only where you are authorized to (see [Authorized use](#authorized-use)).
