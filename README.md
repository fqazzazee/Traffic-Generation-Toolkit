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
- **Live flow-diagram TUI.** A keyboard-driven SPAN diagram — map interfaces, toggle
  protocols, control the service, and watch packets animate along the veth path in
  real time. Plus a full CLI for scripting and CI.
- **Real protocol patterns.** Byte-accurate Modbus/TCP, DNP3, EtherNet/IP + CIP,
  S7comm, IEC 60870-5-104, BACnet/IP, OPC UA, plus DNS, DHCP, NetBIOS, HTTP, HTTPS,
  SMB, Kerberos, LDAP, ARP, ICMP, NTP.
- **Modeled organizations.** Generate a whole realistic network — 10+ servers, a
  dozen users, a DC/DNS/file server, Rockwell + Siemens OT cells, HMIs and **legacy
  Windows 2000/XP/7** — with OS/device fingerprints so an analyser can do asset
  discovery and flag vulnerable hosts.
- **Famous incident scenarios.** Detection-test traffic for WannaCry, Stuxnet,
  Industroyer, TRITON, SUNBURST, Log4Shell and more — themed hostnames and the
  network signatures each attack is known by. **Sprinkle** any of them as a thin
  minority into normal baseline traffic to test detection in a realistic haystack.
- **PCAP replay.** Feed any captured `.pcap` (e.g. a real threat sample) back onto
  the wire, at a fixed rate or with its original timing.
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

<img width="1024" height="559" alt="image" src="https://github.com/user-attachments/assets/c666137f-5360-434d-b6c4-438a1f49ac10" />

---

## Quick start

**Get it** (no dependencies to install — pure Python 3.9+):

```bash
git clone https://github.com/fqazzazee/Traffic-Generation-Toolkit.git
cd Traffic-Generation-Toolkit
```

**Easiest — the interactive UI.** One screen does everything: map the interface,
pick protocols, watch the traffic flow live.

```bash
sudo python3 -m tgt          # launches the TUI
```

```
 TGT · Traffic Generation Toolkit                              ● GENERATING

  ╭ TGT ENGINE ─╮      ╭ SEND ──────╮      ╭ MONITOR ───╮      ╭ SENSOR ────╮
  │ modbus ▇▇▇▇ │─emit▶│ tgt0       │mirror│ tgt0-mon   │ingest│ Claroty CTD│
  │ s7comm ▇▇   │ •••▶ │ ▶ out 12340│ •••▶ │ capture pt │ •••▶ │ ◀ ingest   │
  ╰─────────────╯      ╰────────────╯      ╰────────────╯      ╰────────────╯

  [ Map ]  Protocols   Settings   Service   │  ─ Live log
```

In the UI: **Map** → `Create veth pair` (Enter), switch to **Protocols** and
`Space` to pick some, then press **`s`** to start. Point your sensor at the
monitor end, **`tgt0-mon`**. Full keys: `Tab` panels · `↑/↓` move · `Space`
toggle · `s` start/stop · `q` quit.

**Headless — three commands:**

```bash
sudo python3 -m tgt iface create tgt0                        # veth: tgt0 <-> tgt0-mon
sudo python3 -m tgt run -s ot-baseline -i tgt0 --rate 50     # generate
sudo tcpdump -i tgt0-mon                                     # capture (or point CTD here)
```

**As an always-on service — three commands:**

```bash
sudo ./scripts/tgtctl.sh install     # system deps (python3, iproute2, tcpdump)
sudo ./scripts/tgtctl.sh register    # writes config + service, creates the veth
sudo ./scripts/tgtctl.sh start       # generate in the background
```

**No root? Just write a pcap** (works anywhere, replay later with `tcpreplay`):

```bash
python3 -m tgt run -s ot-full --pcap ot.pcap --count 500
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

Launch it with `python3 -m tgt` (or `tgt`). It's a **live SPAN flow diagram** you
navigate and drive — packets animate along the veth path in real time as it
generates, and four tabbed panels handle everything from one screen.

```
 TGT · Traffic Generation Toolkit                              ● GENERATING
 env: wsl · root · ip:yes · service:active

  ╭ TGT ENGINE ──╮        ╭ SEND ────────╮        ╭ MONITOR ─────╮        ╭ SENSOR ──────╮
  │ modbus ▇▇▇▇  │        │ tgt0         │        │ tgt0-mon     │        │ Claroty CTD  │
  │ s7comm ▇▇    │──────▶ │ ▶ out        │    ┈┈▶ │ capture pt   │    ──▶ │ ingest       │
  │              │  emit  │ 12,340       │ mirror │ ◀ SPAN       │ingest  │ ◀ in         │
  │ 50.0 pps     │        │ packets      │        │              │        │              │
  ╰──────────────╯        ╰──────────────╯        ╰──────────────╯        ╰──────────────╯
           •••▶ animated packet flow while generating •••▶

  [ Map ]  Protocols   Settings   Service      │  ─ Live log
  Send interface   : tgt0                       │  17:52:01 modbus → 502 read regs
  Monitor (peer)   : tgt0-mon                   │  17:52:01 s7comm job/ack
  Sensor label     : Claroty CTD                │  17:52:01 built 32 frames/cycle
  Create veth pair : press Enter                │  …
```

- **Map** — pick the send interface, see its veth monitor peer, name the sensor,
  and create/delete the veth pair right from the UI.
- **Protocols** — toggle any protocol on/off; live per-protocol counters.
- **Settings** — scenario, rate, messages, loop, pcap output, endpoints.
- **Service** — see service status and **save the current selection to
  `/etc/tgt/tgt.conf`**, then start/stop/restart the background service — the TUI
  is a full front-end for `tgtctl.sh`.

Keys: `Tab` switch panel · `↑/↓` move · `←/→` or `Enter` change · `Space` toggle a
protocol · `s` start/stop · `c` clear log · `q` quit.

---

## Protocols

| key | protocol | cat | port / transport |
|---|---|---|---|
| `modbus` | Modbus/TCP | OT | 502 / tcp |
| `dnp3` | DNP3 | OT | 20000 / tcp |
| `enip` | EtherNet/IP + CIP | OT | 44818 / tcp |
| `enip-id` | EtherNet/IP List Identity (Rockwell vendor/model) | OT | 44818 / tcp |
| `s7comm` | S7comm (Siemens) | OT | 102 / tcp |
| `s7-id` | S7 SZL identity (Siemens order no.) | OT | 102 / tcp |
| `iec104` | IEC 60870-5-104 | OT | 2404 / tcp |
| `bacnet` | BACnet/IP | OT | 47808 / udp |
| `opcua` | OPC UA | OT | 4840 / tcp |
| `arp` | ARP | IT | — / l2 |
| `icmp` | ICMP echo | IT | — / ip |
| `dns` | DNS | IT | 53 / udp |
| `dhcp` | DHCP (option 55 + vendor-class fingerprint) | IT | 67 / udp |
| `netbios` | NetBIOS-NS (host/OS announce) | IT | 137 / udp |
| `http` | HTTP (per-host User-Agent) | IT | 80 / tcp |
| `https` | HTTPS / TLS (ClientHello + SNI) | IT | 443 / tcp |
| `smb` | SMB / CIFS (SMBv1 legacy or SMB2) | IT | 445 / tcp |
| `kerberos` | Kerberos (AS-REQ/REP) | IT | 88 / tcp |
| `ldap` | LDAP / Active Directory | IT | 389 / tcp |
| `ntp` | NTP | IT | 123 / udp |

TCP protocols emit a coherent session (SYN / SYN-ACK / ACK → PSH data → FIN) so
stream-reassembling sensors see a real conversation, not orphaned segments. All IP,
TCP and UDP checksums are computed correctly (verified by the self-test).

### Scenarios (curated mixes)

`ot-baseline` · `ot-full` · `mixed-site` · `discovery` · `it-noise` — run `tgt list`
for the exact protocol set and intent of each.

---

## Modeled environments — realistic organizations

Beyond single-protocol traffic, TGT can generate a whole **modeled network**: named
hosts with roles, IPs, vendor MAC OUIs, and **OS/device fingerprints**, having
realistic conversations. This gives an analyser (Claroty CTD, Zeek, …) something to
do **asset discovery** and **vulnerability spotting** on — legacy hosts advertise
SMBv1 and old User-Agents so they're flagged as at-risk.

```bash
tgt run --env it-org           -i tgt0 --rate 100     # enterprise IT
tgt run --env ot-plant         -i tgt0 --rate 100     # industrial OT
tgt run --env enterprise-mixed -i tgt0 --rate 100     # both, converged
```

| env | models | fingerprints / vuln signals |
|---|---|---|
| `it-org` | 11 servers (DC×2, DNS, file, SQL, web, mail, proxy, backup) + 12 users, with DHCP, DNS, Kerberos, LDAP, SMB, HTTP/HTTPS, NetBIOS, NTP | Windows Server 2019 / Win10 / Linux; **legacy Win2000 file server, Win7 + WinXP users** (SMBv1 → MS17-010) |
| `ot-plant` | Rockwell cell (ControlLogix/CompactLogix over EtherNet/IP) + Siemens cell (S7-300/1500 over S7comm), HMIs, historian, engineering WS | Rockwell/Allen-Bradley + Siemens vendor & model identity; **legacy WinXP/2000 HMIs** |
| `enterprise-mixed` | the full converged site: `it-org` + `ot-plant` together (34 hosts) | everything above — the realistic IT/OT mix an industrial site presents |

**How the fingerprints work:** each host carries an OS profile that shapes its
traffic — TTL (128 Windows / 64 Linux / 30 Siemens), HTTP `User-Agent` (e.g.
`MSIE 6.0; Windows NT 5.1` for XP), SMB dialect (SMBv1 `NT LM 0.12` for legacy vs
SMB2), DHCP option-55 + vendor class, NetBIOS name, and vendor MAC OUI (Rockwell
`00:1d:9c`, Siemens `00:0e:8c`). OT PLCs answer identity queries with real product
strings (`1756-L71 LOGIX5571`, `6ES7 315-2EH14-0AB0`). `tgt list` prints each
environment's asset count and the hosts flagged at-risk.

Environments are selectable in the TUI (**Settings → Preset**) and the service
config, exactly like scenarios.

---

## Attack scenarios — famous incidents

TGT can replay the **network signatures of famous IT and OT incidents** so you can
validate that your analyser/IDS detects them. Each scenario uses **themed hostnames**
and the ports, protocol abuse, scan and C2-beacon patterns, and public IOC domains
the real attack is known by.

```bash
tgt run --incident wannacry     -i tgt0     # SMBv1 EternalBlue + kill-switch DNS
tgt run --incident stuxnet      -i tgt0     # S7comm PLC STOP + program download
tgt run --incident industroyer  -i tgt0     # IEC-104 breaker command storm
```

| incident | year | what it reproduces |
|---|---|---|
| `wannacry` | 2017 | SMBv1 MS17-010/DOUBLEPULSAR signature, 445 scan, kill-switch domain lookup |
| `conficker` | 2008 | MS08-067 SMB spread + DGA C2 domains |
| `mirai` | 2016 | Telnet (23) default-credential scanning + C2 report |
| `sunburst` | 2020 | SolarWinds `avsvmcloud.com` DGA + low-and-slow HTTP C2 beacon |
| `log4shell` | 2021 | `${jndi:ldap://…}` in HTTP headers (CVE-2021-44228) |
| `stuxnet` | 2010 | Siemens S7comm PLC STOP + program download, SMBv1 propagation |
| `industroyer` | 2016 | IEC 60870-5-104 breaker control-command storm |
| `triton` | 2017 | TriStation (UDP 1502) writes to a Schneider Triconex SIS |

`tgt list` prints each incident's detectable signals. In the TUI these are in the
**Settings → Preset** cycle (shown as `⚠ <name>`).

> **Detection-test traffic only.** These scenarios emit synthetic packets carrying the
> recognizable *indicators* of each attack — **not** working exploits, shellcode, or
> malware. Run them only on your own isolated test SPAN, for authorized detection
> engineering. This is the same idea as an IDS ruleset test pcap.

### Sprinkle malware on top of normal traffic

The most realistic detection test is an attack **buried in otherwise-normal traffic**.
`--sprinkle` mixes an incident's traffic, as a thin minority, into any base (a
scenario, an environment, or a protocol set) — so the malware rides on top of a
believable baseline instead of standing alone:

```bash
tgt run --env it-org        --sprinkle wannacry     -i tgt0   # IT org + EternalBlue
tgt run --env ot-plant      --sprinkle industroyer  -i tgt0   # OT plant + grid attack
tgt run --scenario mixed-site --sprinkle sunburst,mirai -i tgt0   # two variants
```

The sprinkled frames are spread through the base (typically a few percent of total),
so the analyser must pick the needle out of the haystack.

- **`--sprinkle-ratio FRAC`** sets a fixed malware fraction (0.0–0.9) *regardless of
  base size* — it scales the amount (growing the base if needed) to hit the target, so
  `--sprinkle-ratio 0.05` is 5% malware whether the base is tiny or huge. Default `0`
  keeps one natural minority cycle.
- **`--sprinkle-random`** picks a random incident each cycle (from your `--sprinkle`
  list, or all incidents if none given) and jitters where the frames land, so the
  attack and its timing vary over the run.

```bash
tgt run --env it-org --sprinkle wannacry --sprinkle-ratio 0.1  -i tgt0   # exactly ~10%
tgt run --env ot-plant --sprinkle-random --sprinkle-ratio 0.05 -i tgt0   # random attack, 5%
```

In the TUI it's **Settings → Sprinkle malware** (toggle), **variant**, **random pick**
and **ratio**; a red `⚠ malware: <name>` banner shows while it's armed. Same
detection-test-only caveat as above applies.

### Replay a pcap

Bring your own capture — a real threat sample, a lab recording, anything — and put it
back on the wire:

```bash
tgt run --replay threat.pcap -i tgt0                 # replay at --rate (default 20pps)
tgt run --replay threat.pcap -i tgt0 --replay-realtime   # keep original packet timing
tgt run --replay threat.pcap -i tgt0 --loop          # loop it continuously
```

Reads classic libpcap (both byte orders, µs/ns timestamps; Ethernet, raw-IP and Linux
SLL link types). For pcapng, convert first: `editcap -F pcap in.pcapng out.pcap`. In
the TUI, set **Settings → Replay pcap**.

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
  -e, --env NAME            modeled environment: it-org | ot-plant | enterprise-mixed
      --incident NAME       famous incident: wannacry | stuxnet | industroyer | …
      --sprinkle NAME[,NAME]  mix incident(s) into the base traffic; repeatable
      --sprinkle-ratio FRAC   target malware fraction 0.0-0.9 (0 = natural minority)
      --sprinkle-random       random variant + jittered placement each cycle
      --replay FILE         replay frames from a .pcap instead of generating
      --replay-realtime     honor the pcap's original inter-packet timing
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

### Proxmox — feed a Traffic Analyser VM (SPAN / RSPAN / ERSPAN)

The typical lab: **TGT runs in one VM, the analyser (Claroty CTD, Zeek, Suricata …)
runs in another.** Pick the mirroring method by where the analyser VM lives:

| Analyser location | Method | How the mirror is carried |
|---|---|---|
| Same Proxmox host | **SPAN** (local) | copied to the analyser's port on the host bridge |
| Another host, same L2 | **RSPAN** | tagged into a dedicated VLAN over the trunk |
| Another host across a router (L3) | **ERSPAN** | GRE-encapsulated to the analyser host's IP |

```
        Same host (SPAN)                     Remote host (RSPAN / ERSPAN)
 ┌──────── Proxmox A ────────┐        ┌─ Proxmox A ─┐        ┌─ Proxmox B ─┐
 │  TGT VM ─▶ vmbr1 ─mirror─▶ │       │ TGT VM ─▶ vmbr1 ─mirror─▶ VLAN 999 / │
 │           analyser VM      │       │            or ERSPAN GRE ─▶ analyser │
 └────────────────────────────┘       └─────────────┘        └─────────────┘
```

> **Note on the GUI:** Proxmox has no dedicated "SPAN" button. You build the
> *topology* in the GUI (bridges, VM NICs, VLAN tags); the *mirror session* itself is
> one command on the host shell. Open vSwitch (OVS) is what gives real
> SPAN/RSPAN/ERSPAN, so the methods below use an OVS bridge. A simpler no-OVS local
> option is at the end.

**GUI prep (once per host).** Install OVS on the host shell:
`apt install -y openvswitch-switch`. Then in the GUI: *node → System → Network →
Create → **OVS Bridge*** named `vmbr1` (add your physical NIC as its OVS port only if
the analyser is on another host), and *Apply Configuration*. Attach each VM's NIC in
*VM → Hardware → Network Device → Bridge `vmbr1`* (set the **VLAN Tag** field here for
RSPAN). Find a VM's host-side port name with `ovs-vsctl list-ports vmbr1` — it looks
like `tap<VMID>i0`.

**SPAN — analyser on the same host.** Mirror all bridge traffic to the analyser VM's
port (run on the host):

```bash
ovs-vsctl -- --id=@p get port tap<ANALYSER_VMID>i0 \
  -- --id=@m create mirror name=span0 select-all=true output-port=@p \
  -- set bridge vmbr1 mirrors=@m
```

**RSPAN — analyser on another host, same L2.** Mirror into a dedicated VLAN carried
over the trunk between the two hosts:

```bash
# on the TGT host:
ovs-vsctl -- --id=@m create mirror name=rspan0 select-all=true output-vlan=999 \
  -- set bridge vmbr1 mirrors=@m
```

Trunk VLAN 999 between the hosts (physical switch + the OVS uplink), keep it unused by
anything else, and on the analyser host set the analyser VM's NIC **VLAN Tag = 999**
in the GUI. It then receives the mirrored frames.

**ERSPAN — analyser across an L3 boundary.** GRE-encapsulate the mirror to the
analyser host's IP:

```bash
# on the TGT host: create the ERSPAN tunnel port, then mirror to it
ovs-vsctl add-port vmbr1 erspan0 -- set interface erspan0 type=erspan \
  options:remote_ip=<ANALYSER_HOST_IP> options:key=100 \
  options:erspan_ver=1 options:erspan_idx=1
ovs-vsctl -- --id=@p get port erspan0 \
  -- --id=@m create mirror name=erspan0 select-all=true output-port=@p \
  -- set bridge vmbr1 mirrors=@m
```

On the analyser host, terminate ERSPAN — either an OVS `type=erspan` port with the
reverse `remote_ip` feeding the analyser's bridge, or just capture GRE (IP proto 47),
which Wireshark and CTD decode as ERSPAN.

**Manage the mirror:**

```bash
ovs-vsctl list mirror                  # show active sessions
ovs-vsctl clear bridge vmbr1 mirrors   # remove all mirrors
```

Tips: the analyser's capture NIC must be **promiscuous** with the Proxmox **firewall
off**; `select-all=true` mirrors the whole bridge — to mirror only TGT, use
`select-src-port`/`select-dst-port` with the TGT tap's Port UUID; ERSPAN needs OVS
≥ 2.10 with kernel ERSPAN support; and TGT can pre-tag OT traffic with `--vlan <id>`.

#### Simpler local option (no OVS) — a persistent hub bridge

For same-host SPAN without OVS, put both VMs on an isolated Linux bridge and turn it
into a hub (no MAC learning ⇒ every frame floods to all ports, so the analyser sees
everything). The `/etc/network/interfaces` file can only create the *bridge* — the
hub flag has to be set on its *ports*, and on Proxmox the VM ports are `tap`
interfaces created dynamically at VM start, so they aren't present when the interfaces
file is applied at boot. You therefore need the bridge stanza **plus** a small
companion that flips the flag after the VMs are up.

**1. Create the isolated bridge** in `/etc/network/interfaces` (or GUI: *node → System
→ Network → Create → Linux Bridge*), then `ifreload -a`:

```
auto vmbrspan
iface vmbrspan inet manual
    bridge-ports none
    bridge-stp off
    bridge-fd 0
```

`bridge-ports none` keeps it isolated (no uplink); `inet manual` gives it no IP — a
pure L2 SPAN segment. Attach both VMs' NICs to `vmbrspan` (*VM → Hardware → Network
Device*, firewall unchecked).

**2. Turn it into a hub for the dynamic tap ports** with a Proxmox hookscript that runs
after each VM starts. Create `/var/lib/vz/snippets/spanhub.sh`:

```bash
#!/bin/bash
# After a VM starts, make its SPAN bridge a hub (no learning => floods all).
vmid="$1"; phase="$2"
[ "$phase" = "post-start" ] || exit 0
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

Prefer not to use a hookscript? Just run the loop by hand once after starting the VMs.
Verify with `bridge -d link show | grep -A1 vmbrspan` — each port should read
`learning off flood on`.

> If TGT runs **on the Proxmox host** rather than in a VM, its veth end is a static,
> host-side port you *can* configure straight in the interfaces file — no hook needed
> for that port (the analyser VM's tap still uses the hookscript):
> ```
>     post-up ip link add tgt0 type veth peer name tgt0-br || true
>     post-up ip link set tgt0-br master vmbrspan up && ip link set tgt0 up
>     post-up bridge link set dev tgt0-br learning off flood on mcast_flood on
> ```

**Then generate** (all methods): point TGT at its bridge NIC — set `TGT_IFACE=eth0`
in `/etc/tgt/tgt.conf` and `sudo ./scripts/tgtctl.sh restart`, run
`sudo python3 -m tgt run -i eth0 -s ot-baseline --rate 50`, or pick the interface in
the TUI's **Map** panel and press `s`. Verify on the analyser with
`tcpdump -i <nic>` that the Modbus/S7/DNP3 exchanges arrive, then confirm CTD
classifies them.

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

The **incident scenarios** emit synthetic traffic carrying the *detectable signatures*
of known attacks (for validating your monitoring) — not functional exploits, shellcode,
or malware. They are for authorized detection engineering on your own test SPAN, the
same as running an IDS ruleset test capture.

---

## Project layout

```
tgt/
  packet.py      raw Ethernet/IP/TCP/UDP/ARP builders + checksums
  protocols.py   per-protocol payload + flow builders, profile registry
  scenarios.py   curated multi-protocol mixes
  enterprise.py  modeled IT/OT organizations + host OS fingerprints
  incidents.py   famous IT/OT attack scenarios (detection-test traffic)
  pcap.py        libpcap file writer
  pcapread.py    libpcap file reader (for --replay)
  sender.py      AF_PACKET raw send + rate limiter
  net.py         environment detection + veth/dummy management
  service.py     read/write service config + start/stop/restart
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
