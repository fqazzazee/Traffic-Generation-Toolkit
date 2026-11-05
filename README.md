<div align="center">

# TGT — Traffic Generation Toolkit

**Generate realistic OT/ICS + IT test traffic onto a virtual interface, so a passive
network monitor can capture and classify it just like a physical SPAN / mirror feed.**

Works with any sensor — **Wireshark, Zeek, Suricata, Security Onion, Malcolm**
(all free/open-source), or any commercial OT / IT monitoring platform. Runs on a workstation, in **WSL**, or in a **Podman / Docker** container.

`zero dependencies` · `pure Python stdlib` · `TUI + CLI` · `runs as a service`

[![CI](https://github.com/fqazzazee/Traffic-Generation-Toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/fqazzazee/Traffic-Generation-Toolkit/actions/workflows/ci.yml)
[![Blog](https://img.shields.io/badge/📖%20Blog-Read%20the%20Write--up-FF6C37)](https://blog.safeqbit.com/traffic-generation-toolkit-tgt-make-network-traffic-on-one-machine/)
[![Buy me a coffee](https://img.shields.io/badge/Buy%20me%20a%20coffee-FFDD00?logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/fqazzazee)

</div>

---

## Contents

- [What it does](#what-it-does) · [Quick start](#quick-start) · [The TUI](#the-tui)
- Traffic: [Protocols](#protocols) · [Scenarios](#scenarios) · [Modeled networks](#modeled-networks) · [Your own environments](#your-own-environments) · [Realism & timing](#realism--timing)
- **[Evaluating a monitor](#evaluating-a-monitor)** — ground truth, baseline, change detection, scoring, [benchmark suites](#benchmark-suites-tgt-bench)
- Attacks: [Incidents](#attack-incidents) · [Sprinkle](#sprinkle-malware-into-normal-traffic) · [Live injection](#control-api-and-tgt-ctl)
- Running: [CLI](#cli-reference) · [Multiple interfaces](#send-on-several-interfaces) · [Control API](#control-api-and-tgt-ctl) · [Replay pcaps](#replay-a-pcap) · [Plugins](#plugins) · [Service](#run-as-a-service) · [WSL / Podman / Proxmox](#deployment) · [Sensor in another VM](#sensor-on-another-machine-or-vm)
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

**Highlights:**

- **85+ byte-accurate protocols** — OT/ICS, IEC 61850 substation and PROFINET L2, building
  automation, medical, IT, network infrastructure, remote access, vendor engineering
  (incl. CODESYS V3), **secured OT** (CIP Security, S7comm-plus over TLS, OPC UA
  SignAndEncrypt, IEC 104 / DNP3 over TLS, Modbus Security) and **serial gateways / IIoT**
  (Modbus RTU over TCP, terminal servers, BACnet/SC, LoRaWAN) — each device stating its real
  **vendor, model, firmware and serial** on the wire where the protocol carries it.
- **12 modeled networks** (4 built-in, 8 vertical sites: water, power, pipeline, auto,
  hospital, smart building, pharma, IIoT retrofit) with VLANs, NAT'd remote sites, devices
  behind serial and LoRa gateways, per-OS **TCP/IP and TLS (JA3/JA4) fingerprints** and
  **planted findings** — or describe your own in a JSON file.
- **A real time model** — every conversation on its own period, request/response RTTs,
  long-lived polling sessions, a working-day profile, and a synthetic clock that writes a
  **multi-day pcap in minutes**.
- **Ground truth and scoring** — `tgt inventory` says what a monitor *should* find, `--manifest`
  records what was actually sent, and `tgt score` grades the monitor's asset and alert export
  into an HTML report — with **MITRE ATT&CK for ICS** coverage per technique. `tgt bench`
  plays a fixed, seeded suite and turns the exports into one comparable **scorecard**.
- **17 famous attack scenarios** you can sprinkle into normal traffic, inject live, or run as
  phases of a change-detection **campaign**.
- pcap/pcapng replay with re-addressing · a live flow-diagram TUI · a control API · plugins ·
  one-command install and background service · zero dependencies (Python 3.9+ stdlib only).

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
python3 -m tgt run -e water-utility --pcap water.pcap --once --rate 0   # one cycle of a whole site
```

**Testing a commercial monitor?** Go straight to [Evaluating a monitor](#evaluating-a-monitor).

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

- **TGT ENGINE:** the preset, any sprinkled malware, live injections (`⚡industroyer 11s`
  left), the campaign phase and its countdown (`▸ 2/5 module-swap · 1s left`), simulated
  time and speed for a timed run, the traffic mix (share of frames per protocol, biggest
  first; malware rows always stay on screen), the rolling pps over the last ~5 s (so a
  stall shows at once) and elapsed time.
- **SEND / PCAP:** interface, link state and type (or the pcap file), packets, bytes,
  Mb/s, errors, frames per cycle; with several send interfaces, one counter line each.
- **MONITOR** (veth only): the peer and its state, the SPAN view and VLAN tagging.
- **SENSOR:** your sensor's name and how it gets the traffic: the veth peer it listens on,
  the interface it gets a SPAN of, or the pcap it imports.

Four tabbed panels below drive it. Each shows only the rows that apply to the current
preset, explains the selected row underneath, and the key bar lists what the keys do there:

| Panel | What you do |
|---|---|
| **Run** | pick a preset from a filterable list grouped Built-in / Sites / Files / Plugins (scenarios; environments, with each site's planted findings; incidents; pcap replay) or a **Campaign** plan, then set the options that apply: SPAN view, malware sprinkle, **Schedule** (cycle or timed, with speed, day profile, min period, duration), **Clock** and start time, **Seed**, **Manifest**, control **API**, rate, messages, loop, pcap output, endpoints; replay adds speed, loop count, IP/subnet/MAC remaps and VLAN retag. **Findings** lists what the env plants for a monitor to raise, and **Export inventory** writes its ground truth as CSV + JSON |
| **Traffic** | protocols grouped into folding families (OT, IT, infrastructure, …) with `/` to filter; toggle them for a custom mix; live per-protocol counters |
| **Interfaces** | pick the send interface and see how it reaches the sensor (veth pair or real interface that needs a SPAN), name the sensor, **Fan-out** to more interfaces (same frames to each, per-interface counters), create/delete a veth pair (delete asks you to type the name and is never offered for a real interface) |
| **Service** | service status and the exact `tgt run` (or `tgt campaign`) it would execute; save config + start/stop/restart |

Choosing a preset puts its protocols on the **Traffic** tab (an incident's attack-only
traffic, such as a port scan, is listed next to them), and toggling one there starts a
custom mix from them. `tgt list` shows each environment's and incident's protocols too.
Every option the TUI sets maps onto a [`tgt run`](#cli-reference) flag, and the Service
panel shows that command line, so a run you tune in the TUI can move to a script or the
service unchanged. Below 80 columns the diagram collapses to a one-line flow strip.

**Keys:** `Tab` panel · `↑/↓` move · `←/→` change · `Enter` pick/edit/run · `Space`
toggle · `s` start/stop · `i` inject an incident into the running engine for a while
(same as [`tgt ctl inject`](#control-api-and-tgt-ctl), recorded in the manifest) · `p`
pause/resume · `/` filter protocols on Traffic (`Esc` clears) · `c` clear log · `?` help ·
`q` quit (asks first while a run is live). In a text prompt, `-` clears the value. The key
bar at the bottom of each panel is the authoritative list.

---

## Protocols

Byte-accurate builders: TCP protocols emit full SYN→data→FIN sessions, every IP/TCP/UDP
checksum is correct, and every builder with a Wireshark dissector decodes with no expert
warnings (both checked by the self-test). Devices report their **own identity** in the
protocol they speak — so a passive monitor can inventory vendor, model, firmware and
serial without an active scan. `tgt list` prints every key with a one-line description.

**OT / ICS** — polling, identity and normal engineering operations

| keys | port | carries · identity exposed |
|---|---|---|
| `modbus` · `modbus-id` · `modbus-write` | 502/tcp | FC 3/4/1/2 polls + FC 6 setpoints, exception replies · **FC 43/14 Read Device ID**: vendor, product code, revision, model · HMI writes FC 16/5/15 |
| `dnp3` · `dnp3-id` · `dnp3-time` | 20000/tcp | class 0–3 polls + unsolicited events · **group 0 attributes**: manufacturer, model, software version, serial · delay measure + time write |
| `enip` · `enip-id` · `enip-list` · `enip-eng` · `enip-write` | 44818/tcp, udp | CIP Get_Attribute polls · **List Identity**: vendor ID, device type, product code/name, revision, serial (unicast and RSLinx-style broadcast browse) · controller mode/program/clock reads · Logix tag writes (recipe download) |
| `enip-io` | 2222/udp | Forward_Open + cyclic class-1 implicit I/O to adapters and drives |
| `s7comm` · `s7-id` · `s7-eng` | 102/tcp | COTP + Setup Communication + Read Var · **SZL 0x0011/0x001C**: order number, firmware, serial, module, CPU mode · block list, OB1 upload, planned DB download |
| `iec104` · `iec104-time` | 2404/tcp | STARTDT, general interrogation, time-tagged spontaneous points, TESTFR · clock sync |
| `opcua` | 4840/tcp | GetEndpoints (server **application + product URI**), Create/ActivateSession, Read, CloseSession |
| `mqtt` · `sparkplug` | 1883/tcp | CONNECT/SUBSCRIBE/PUBLISH QoS 0/1 · Sparkplug B NBIRTH/NDATA/NDEATH with protobuf metrics |

**Substation and industrial Layer 2** — link-local, kept inside one segment

| keys | port | carries · identity exposed |
|---|---|---|
| `goose` · `sv` | L2 (802.1Q prio 4) | IEC 61850 GOOSE trips with stNum/sqNum retransmission · 9-2LE sampled values (4 I + 4 V) · gocbRef, goID and APPID name the publishing IED |
| `mms` | 102/tcp | ISO association + Initiate, **Identify** (vendor, model, revision), GetNameList, MMXU reads |
| `ptp` · `ptp-l2` | 319/udp, L2 | IEEE 1588 grandmaster Announce (clock identity, class), Sync/Follow_Up, Delay_Req/Resp |
| `pn-dcp` · `pn-dcp-set` | L2 | PROFINET DCP Identify: **NameOfStation, Siemens vendor/device ID, role, IP** · Get/Set IP and NameOfStation |
| `pn-rt` | L2 (prio 6) | RT_CLASS_1 cyclic IO, cycle counter + data status |
| `mrp` · `dlr` | L2 | MRP ring-manager test frames (IEC 62439-2) · EtherNet/IP DLR supervisor beacons |
| `sel-telnet` | 23/tcp | SEL ASCII relay engineering: ACC/2AC login, **ID** (FID firmware, part number, serial), SHO, settings change |

**Building automation** · **Medical**

| keys | port | carries · identity exposed |
|---|---|---|
| `bacnet` · `bacnet-id` · `bacnet-cov` | 47808/udp | ReadProperty polls · **Who-Is/I-Am + Device object**: vendor, model, firmware · SubscribeCOV + COV notifications |
| `knxip` | 3671/udp | KNXnet/IP search + description (KNX address, serial, friendly name), routing group writes |
| `dicom` | 104/tcp | A-ASSOCIATE (AE titles, implementation UID/version), C-ECHO, C-STORE CT images with **modality manufacturer / model / serial / software** and placeholder PHI |
| `hl7` | 2575/tcp | HL7 v2 ADT^A01 / ORU^R01 over MLLP: sending/receiving application + facility, ACK replies (cleartext PHI) |

**IT**

| keys | port | carries · identity exposed |
|---|---|---|
| `arp` · `icmp` | L2, IP | who-has/is-at + gratuitous ARP · ping sweeps |
| `dhcp` | 67/udp | full **DORA** lease then renewals: host name, option 55 parameter list and vendor class (the DHCP OS fingerprint) |
| `dns` | 53/udp | each host resolves the names it actually talks to (`corp.local` FQDNs, cloud and EDR hosts) |
| `ntp` | 123/udp | client polls + stratum-2 replies with real timestamps |
| `http` · `https` · `edr` | 80, 443/tcp | per-host User-Agent · per-OS **TLS ClientHello (JA3/JA4)**, SNI, server certificate · CrowdStrike Falcon telemetry |
| `smb` · `smb-logon` | 445/tcp | Negotiate (SMBv1 legacy or SMB 3.0.2) · SMB2 NTLM session setup naming **domain\user + workstation**, tree connect |
| `kerberos` · `ldap` · `netbios` | 88, 389/tcp, 137/udp | AS-REQ to the DC · bind + rootDSE · name registration carrying host name and OS |

**Network infrastructure and discovery**

| keys | port | carries · identity exposed |
|---|---|---|
| `snmp` · `snmpv3` | 161/udp | v2c Get of the system group (**sysDescr, sysObjectID, sysName**), v1 trap + inform · USM engine discovery |
| `lldp` · `cdp` | L2 | chassis/port ID, system name + description, management address · CDPv2 device ID, IOS version, platform |
| `syslog` | 514/udp | RFC 3164 + 5424 messages from switches, RTACs and GxP servers |
| `mdns` · `ssdp` · `llmnr` · `nbns` | 5353, 1900, 5355, 137/udp | service browse, UPnP SERVER banners, name queries, NBSTAT name table + MAC |

**Remote access and file transfer** · **Vendor engineering**

| keys | port | carries · identity exposed |
|---|---|---|
| `ssh` | 22/tcp | banners, per-side KEXINIT (**HASSH**), ECDH kex, encrypted session |
| `rdp` · `vnc` · `telnet` | 3389, 5900, 23/tcp | X.224 `mstshash` + TLS/NLA · RFB auth + desktop name · cleartext login and commands |
| `ftp` · `tftp` · `http-fw` | 21/tcp, 69/udp, 80/tcp | cleartext FTP login, config backup + firmware upload · device TFTP image fetch · HTTP Basic firmware POST/PUT |
| `s7plus` | 102/tcp | S7CommPlus (S7-1200/1500) session with **order number + firmware**, variable polls |
| `fins` · `slmp` · `srtp` · `hart-ip` | 9600/udp, 5007, 18245, 5094/tcp | Omron controller data read (**model, version**) · Mitsubishi Read Type Name (**CPU model**) · GE SRTP register reads · HART-IP unique ID, long tag, PV |
| `codesys` · `codesys-disc` | 11740/tcp, 1740/udp | CODESYS V3 runtime (WAGO PFC, Schneider M241/M251, Eaton XC300): **DeviceInfo** (vendor, device, firmware, serial), channel open, device + application login, project info, monitoring reads · gateway network scan + replies. No stock Wireshark dissector: decodes as TCP/UDP data |

**Secured OT** — the same polls inside TLS / DTLS, so identity in the payload is no longer on
the wire (certificates still are on TLS ≤ 1.2)

| keys | port | carries · identity exposed |
|---|---|---|
| `enip-tls` · `enip-dtls` | 2221/tcp, 2221/udp | CIP Security: TLS 1.2 mutual auth around RegisterSession + CIP polls · Forward_Open over TLS, then class-1 I/O as DTLS 1.2 records · **client and server certificates** |
| `s7plus-tls` | 102/tcp | S7-1500 V2.9+: COTP + InitSsl in clear, then TLS 1.3 inside COTP DT (tshark: `--disable-heuristic ses_cotp`, on its own capture) |
| `opcua-sign-encrypt` | 4840/tcp | Basic256Sha256 OpenSecureChannel with **application certificate + thumbprint**, then encrypted MSG chunks |
| `iec104-tls` · `dnp3-tls` | 19998, 19999/tcp | IEC 62351-3: TLS 1.2 mutual auth, the plaintext polls as records |
| `modbus-sec` | 802/tcp | Modbus/TCP Security: TLS 1.2, client certificate carrying the **Modbus role** (tshark needs the role OID as a UAT entry) |

**Serial gateways and IIoT** — field devices reached through a gateway; behind it they have
no IP of their own (see `field_devices[]`)

| keys | port | carries · identity exposed |
|---|---|---|
| `modbus-rtu-tcp` · `dnp3-serial` | 4000+N/tcp | Modbus RTU frames (slave id + CRC-16) or DNP3 serial link frames sent raw to a device server's port N, slaves polled in turn (tshark: `-d tcp.port==4001,mbrtu`, `-d tcp.port==4003,dnp3`) |
| `realcom` · `realcom-cmd` · `moxa-discovery` | 950, 966/tcp, 4800/udp | Moxa RealCOM virtual COM port data + command channel (port setup, keep-alives) · NPort Administrator search broadcast + replies (**model**, MAC, IP) |
| `bacnet-sc` | 443/tcp | BACnet Secure Connect: TLS 1.3 + WebSocket to the hub, heartbeats (opaque on the wire) |
| `lorawan-udp` | 1700/udp | Semtech UDP packet forwarder: PUSH_DATA rxpk/stat JSON (**gateway EUI**, sensor DevAddr, frame counters), PULL_DATA, PULL_RESP + TX_ACK |

### TCP/IP stacks, TLS fingerprints and certificates

Each host's OS profile shapes every frame it sends, so passive OS fingerprinting has
something real to work with:

- **TCP/IP stack per OS family** (`tgt/stacks.py`) — the SYN option layout, initial window
  and scale, timestamps, IP ID pattern and DF bit of Windows 10/Server 2016–19, Server 2012 R2,
  Windows 7, XP, 2000, Linux, and embedded controllers (Rockwell, Siemens, Schneider, SEL,
  generic RTOS: MSS-only, small windows). TTL follows the OS (128 Windows, 64 Linux, 30
  Siemens, 255 Cisco IOS). Sessions split at the stack's MSS, use delayed ACKs, and some
  browser sessions end in a RST.
- **TLS** (`tgt/tls.py`) — ClientHellos reproduce real client families (SChannel on Windows
  10 / 7 / XP / 2000, Chrome, Firefox, OpenSSL/curl, the Falcon sensor), so hosts of
  different OSes carry different **JA3/JA4** hashes while each family stays stable. Servers
  answer with a consistent flight (TLS 1.3, or TLS 1.2 and older with an **X.509 server
  certificate** for the host's name, issued by the corporate CA or a DigiCert / Let's
  Encrypt-style public CA), or a fatal alert when the client and server cannot agree.
- **Vendor MAC OUIs** (Rockwell `00:1d:9c`, Siemens `00:0e:8c`, Cisco, Hirschmann, Moxa, …),
  HTTP `User-Agent`, SMB dialect, DHCP and NetBIOS fields all follow the host.

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

---

## Scenarios

Curated protocol mixes with no modeled hosts (a generic client and server per protocol):

| scenario | protocols | use it for |
|---|---|---|
| `ot-baseline` | modbus, s7comm, enip, dnp3 | steady industrial polling, the "normal day" |
| `ot-full` | modbus, dnp3, enip, s7comm, iec104, bacnet, opcua | widest classic OT classifier coverage |
| `mixed-site` | modbus, s7comm, http, dns, ntp, arp | control traffic + IT chatter |
| `discovery` | arp, icmp, dns, enip | asset-discovery and inventory features |
| `it-noise` | http, dns, ntp, icmp, arp | confirm IT is not misclassified as OT |
| `substation` | goose, sv, mms, ptp, iec104, dnp3 | IEC 61850 station + process bus, telecontrol |
| `profinet-cell` | pn-dcp, pn-dcp-set, pn-rt, s7comm, s7-id | PROFINET discovery, a DCP Set, cyclic IO, S7 access |
| `infra` | snmp, snmpv3, lldp, cdp, syslog, mdns, ssdp, llmnr, nbns | asset enrichment from management chatter |
| `iiot` | mqtt, sparkplug, opcua | IIoT / edge messaging |
| `remote-access` | ssh, rdp, vnc, telnet | remote-access inventory and insecure-protocol findings |
| `firmware-update` | ftp, tftp, http-fw | file-transfer and firmware-change events |
| `multi-vendor-ot` | s7plus, fins, slmp, hart-ip, srtp, enip, modbus | vendor coverage for classification and identity |

```bash
tgt run -p modbus,s7comm -i tgt0        # specific protocols
tgt run -s substation    -i tgt0        # a scenario
```

---

## Modeled networks

Generate a whole **modeled network** — named hosts with roles, IPs, vendor MAC OUIs,
catalog device models and OS fingerprints having realistic conversations — so a sensor has
real assets to discover and real problems to flag. Every environment starts each cycle with
ARP, has managed switches announcing LLDP/CDP and polled over SNMP by an NMS, and sends
syslog to it.

```bash
tgt run --env it-org           -i tgt0 --rate 100     # enterprise IT
tgt run --env ot-plant         -i tgt0 --rate 100     # industrial OT
tgt run --env enterprise-mixed -i tgt0 --rate 100     # both, converged, with a DMZ
tgt run --env industrial-site  -i tgt0 --rate 500     # large Purdue-model plant
```

### Built-in environments

| env | hosts · segments · conversations | models | at-risk |
|---|---|---|---|
| `it-org` | 26 · 2 · 122 | DCs, DNS, file, SQL, web, mail, proxy, backup, 12 users, 2 switches, NMS; DHCP/DNS/Kerberos/LDAP/SMB/HTTP(S)/NetBIOS/NTP | **Win2000 file server, Win7 + WinXP users** — SMBv1 |
| `ot-plant` | 15 · 3 · 35 | Rockwell cell (EtherNet/IP) + Siemens cell (S7comm), HMIs, SCADA, historian, engineering WS, switches, NMS | vendor identity + **WinXP/2000/7 HMIs** |
| `enterprise-mixed` | 45 · 6 · 174 | `it-org` + `ot-plant` joined through an **IT/OT DMZ** (jump host, patch server, historian replica) | the full converged mix |
| `industrial-site` | 108 · 9 · 496 | corporate IT, IT/OT DMZ, L3 operations, Rockwell packaging (Logix + PowerFlex), Siemens process, Schneider Modicon utilities + PM5560 meters, JCI/Tridium BACnet BMS, SEL RTAC + relays over DNP3, IEC 104 RTU | Win7/XP HMIs and users, a Server 2012 R2 OT DC, and **an IT laptop polling a meter directly (L4 → L1)** |

### Packaged sites

Eight vertical sites ship as env files in `tgt/envs/sites/` and load like built-ins
(`--env water-utility`). Each records its **planted findings** in the ground truth
(`tgt inventory -e SITE -f json` → `findings[]`), backed by traffic on the wire:

| site | hosts · segments | what's in it | planted findings |
|---|---|---|---|
| `water-utility` | 55 · 13 | AVEVA-style SCADA pair, Rockwell CompactLogix + PowerFlex, Modicon M580 + Danfoss VFDs, Hach analyzers; **8 lift stations behind cellular-modem NAT** (Sierra, Digi, Moxa), SCADAPack RTUs over DNP3/Modbus | unauthenticated VNC HMI · cleartext Telnet to a modem · default SNMP community · EOL WinXP HMI · EOL SCADAPack 334E |
| `electric-substation` | 24 · 5 | SEL-3530 RTAC polling SEL, ABB, GE and SIPROTEC IEDs over MMS/DNP3, GOOSE, 9-2LE merging units, PTP grandmaster; SCADA (DNP3 + IEC 104) across the WAN | GOOSE from an unexpected publisher · relay engineering from corporate · rogue PTP grandmaster · SEL factory passwords over Telnet |
| `oil-gas-pipeline` | 50 · 10 | gas-control centre, FortiGate VPN + vendor jump host, **5 compressor/meter stations over VSAT NAT** (~650 ms RTT): ControlLogix, M580, SICAM A8000 (IEC 104), ROC800 / Totalflow, SCADAPack | vendor remote access · metering config write from a corporate PC · flat station network · EOL Win7 HMI |
| `auto-assembly` | 94 · 6 | S7-1500R redundant pair, ET 200SP, KUKA robots on PROFINET + MRP; PLCnext, Beckhoff, WAGO; CompactLogix DLR rings, PowerFlex, FANUC; CODESYS V3 controllers (WAGO, Modicon M251, Eaton XC300) and their engineering laptop in the paint shop; IOT2050 edge gateway to a cloud MQTT broker | PROFINET DCP Set-IP from a laptop · duplicate NameOfStation · VNC on a Win7 robot controller · cleartext MQTT to the internet |
| `hospital-iomt` | 72 · 8 | EHR, HL7 engine, PACS/RIS/LIS; GE CT + Siemens MRI over DICOM, Mindray monitors → HL7, 20 BD Alaris pumps, nurse call, BACnet BMS | cleartext PHI (HL7/DICOM) · EOL XP Embedded CR reader · infusion pump talking to the internet · sanctioned MRI vendor remote service (info) |
| `smart-building-dc` | 84 · 6 | Niagara/JACE, Desigo, JCI FECs on BACnet (polls + COV), KNX IP router; APC/Raritan PDUs, UPS, CRAH, chillers, PM5560 meters; Axis/Hikvision cameras, Mercury access control, guest Wi-Fi | default SNMP communities · Hikvision P2P cloud phone-home · BMS reachable from guest Wi-Fi |
| `pharma-batch` | 43 · 5 | FactoryTalk Batch, PI historian, MES, DeltaV + ControlLogix 5580 PlantPAx units, POINT I/O, PowerFlex 755, GxP audit syslog; **CIP Security** (HMIs over TLS, PLC-to-PLC I/O over DTLS) and an OPC UA SignAndEncrypt historian link next to plaintext CIP | recipe write from a corporate host · shared service account · corporate → plant bypassing the DMZ · controllers accept plaintext CIP next to CIP Security |
| `iiot-retrofit` | 23 · 6 (+21 behind gateways) | Moxa NPort device servers (ABB drives as Modbus RTU over TCP, SEL relays over DNP3 serial), an MGate Modbus gateway to PM5330 meters, a boiler RTU through RealCOM; Kerlink / MultiTech LoRaWAN gateways with Milesight / Dragino sensors; BACnet/SC hub with Desigo and JACE controllers | EOL RTU reached through RealCOM from a Win7 HMI · unauthenticated raw-TCP serial tunnels carrying setpoint writes · LoRaWAN forwarded over unauthenticated Semtech UDP across zones |

**NAT'd remote sites.** In `water-utility` and `oil-gas-pipeline` the remote stations sit
behind their modem's or VSAT terminal's NAT, as a control-centre SPAN sees them: every
frame that leaves a station carries the router's outside address and MAC, station-internal
traffic is not on the HQ capture, and WAN links add their round-trip time. One pipeline
meter station (MS5) has a site-side sensor (`"nat": {"local": true}`), so its flat LAN is
visible too.

### Segments, VLANs and the SPAN view

Hosts sit in **segments**, each with its own VLAN, subnet, zone (IT · DMZ · OT-SUPERVISORY ·
OT-CELL) and gateway, routed by a core L3 switch whose gateway MACs are HSRP virtual MACs
(`00:00:0c:07:ac:<vlan>`). The built-ins use:

| segment | VLAN | subnet | zone |
|---|---|---|---|
| `IT-SERVERS` / `IT-USERS` | 10 / 20 | 10.20.10.0/24 / 10.20.20.0/24 | IT |
| `IT-OT-DMZ` (enterprise-mixed) | 50 | 10.20.50.0/24 | DMZ |
| `OT-SUPERVISORY` | 100 | 172.16.0.0/24 | OT-SUPERVISORY (Purdue L3) |
| `OT-CELL-RW` / `OT-CELL-S7` | 110 / 120 | 172.16.1.0/24 / 172.16.2.0/24 | OT-CELL (L1–2, Rockwell / Siemens) |

`industrial-site` has `CORP-SERVERS` (10) and `CORP-USERS` (20), `IT-OT-DMZ` (50), `OT-OPS`
(100) and five L1–2 cells: `AREA-PACKAGING` (110), `AREA-PROCESS` (120), `AREA-UTILITIES`
(130), `BMS` (140) and `SUBSTATION` (150), on `10.10.<n>.0/24` (IT) and `10.100.<n>.0/24`
(OT). `tgt list` prints every environment's segments.

Every env frame carries its segment's 802.1Q tag. Same-segment flows are switched peer to
peer, cross-segment flows are addressed to the sender's gateway MAC, and link-local
protocols (GOOSE, SV, PTP, DCP, LLDP, mDNS, …) never cross a segment. `--span` picks where
the sensor sits:

```bash
tgt run --env it-org --span access -i tgt0   # default: each frame once, on the sender's VLAN
tgt run --env it-org --span core   -i tgt0   # + routed copy on the receiver's VLAN (gw MAC, TTL-1)
```

### Device catalog

`tgt/devices.py` holds **85 device models** — PLCs, RTUs, relays, drives, robots, switches,
modems, firewalls, medical and building devices, Windows/Linux hosts — each with vendor and
MAC OUIs, device class and Purdue level, the firmware releases a unit may run, a serial
format, its rack modules, the identity it reports on each protocol (CIP product codes,
Siemens order numbers, BACnet vendor IDs, SNMP sysDescr/sysObjectID, banners), whether it
is embedded (no EDR), and **known CVEs that apply to every offered firmware**.

A host names its `model`; its firmware and serial are then picked deterministically from
its name, so the same host reports the same revision and serial on every run while two PLCs
of the same model differ. The same values feed the wire and the ground-truth inventory, so
a monitor can be scored field by field. Identity values are real where vendors publish them
(CIP and BACnet vendor IDs, order numbers, OUIs); product codes, serial formats and firmware
lists are representative.

### Ground-truth inventory

`tgt inventory` exports what a sensor *should* discover from an environment:

```bash
tgt inventory -e industrial-site                    > site.csv    # one row per host
tgt inventory -e water-utility -f json -o water.json              # + segments, flows, findings
tgt inventory -e it-org --sprinkle industroyer                    # + hosts an incident adds
```

Each host row has: name, IP, MAC, MAC vendor, device vendor and product, role, OS/firmware,
segment, VLAN, subnet, zone, gateway, legacy flag, risk note, services served
(`modbus 502/tcp`, …), protocols used, asset ID, catalog model, firmware, serial, Purdue
level and FQDN. The JSON adds:

| key | contents |
|---|---|
| `hosts[]` | the rows above + rack `modules`, `known_cves`, `embedded`, `edr`, `encrypted[]` (secured OT the host speaks, and whether its certificates are in clear), and per-field **`observability`**: whether a passive monitor can learn each field from the traffic this host actually sends, and from which protocol. Devices behind a gateway are rows with `behind` set and no IP or MAC: known assets that cannot be discovered as IP assets, so `tgt score` leaves them out of discovery |
| `segments[]` | VLAN, subnet, zone, gateway, NAT |
| `flows[]` | the expected communication baseline: client, server, protocol, port, period and jitter |
| `findings[]` | planted issues (packaged sites): id, title, severity, category, hosts, flows |
| `external[]` | internet endpoints (EDR cloud, cloud brokers, vendor portals) — not assets |
| `infrastructure[]` | on the wire but not an asset (HSRP gateway MACs) |
| `new_assets[]` | with `--sprinkle`: incident hosts with no compatible inventory host, which a monitor should report as new |

---

## Your own environments

Describe a site in a JSON file (or TOML on Python 3.11+) and use it anywhere an `--env`
goes. It is validated like a built-in; unknown keys are errors, so typos surface.

```bash
tgt env export ot-plant -o my-plant.json          # any environment, as an env file to edit
tgt run --env-file my-plant.json --pcap my.pcap --once --rate 0
tgt inventory --env-file my-plant.json -f json
```

Files in `$TGT_ENV_PATH` (colon-separated) and `~/.config/tgt/envs/` load at startup and
appear in `tgt list` by their `key`. `tgt/envs/` has exports of the built-ins,
[`example-site.json`](tgt/envs/example-site.json) and `example-cell.toml`. A condensed example:

```json
{
  "key": "my-plant", "name": "My Plant", "category": "OT",
  "segments": [
    {"name": "OPS", "vlan": 100, "subnet": "10.150.0.0/24", "zone": "OT-SUPERVISORY"},
    {"name": "AREA-PACKAGING", "vlan": 110, "subnet": "10.150.10.0/24", "zone": "OT-CELL"}
  ],
  "hosts": [
    {"name": "HIST01", "ip": "10.150.0.10", "role": "hist", "os": "win2019"},
    {"name": "HMI-PK{n}", "count": 2, "ip_start": "10.150.10.10", "role": "hmi", "os": "win10"},
    {"name": "PLC-PK{n:02}", "count": 4, "ip_start": "10.150.10.21", "model": "rockwell-1756-l71"}
  ],
  "flows": [
    {"from": "role:hmi@AREA-PACKAGING", "to": "role:plc@AREA-PACKAGING",
     "proto": "enip", "mode": "round-robin", "period": "1s±5%"},
    {"from": "HIST01", "to": "role:plc", "proto": "enip", "period": "5s", "jitter": "10%"},
    {"from": "role:hmi", "proto": "netbios"}
  ],
  "findings": [{"id": "hist-polls-plcs", "title": "Historian polls PLCs directly",
                "severity": "low", "hosts": ["HIST01"]}]
}
```

| section | keys |
|---|---|
| `hosts[]` | `name`, `ip`, `role`, `os` (fingerprint key: `win10`, `linux`, `rockwell`, `siemens`, `ios`, `rtos`, `linux-embedded`, …; the old `embedded` / `embedded-linux` still load) or a catalog `model` that fills them; optional `vendor`, `product`, `mac`, `firmware`, `serial`, `fqdn`, `meta`; `count` + `ip_start` repeat an entry (`name` is a `{n}` template) |
| `flows[]` | `client` + `server`, or selectors `from` [+ `to`]: a host name (globs ok), `role:`, `zone:`, `model:`, `*`, each optionally `@SEGMENT`; `mode` `all` or `round-robin`; `proto`; optional `period` / `jitter` for the timed scheduler; `"secure": true` picks the protocol's secured variant (`enip` → `enip-tls`, …; a host's `meta` `"secure": true` makes it the default, and a model or firmware that can't is an error). No `to` = a self-announcement |
| `field_devices[]` | devices with no IP behind a gateway host: `name`, `behind`, `via` (`modbus-rtu-tcp`, `dnp3-serial`, `realcom`, `modbus` gateway, `lorawan-udp`), `port`, `address`, optional `model`, `vendor`, `product`, `role`, `firmware`, `serial`, `count` |
| `segments[]` | `name`, `vlan`, `subnet`, `zone`, optional `gateway`, `gateway_mac`, `wan_rtt_ms`, `nat` (`outside_ip`, `outside_mac`, `local`) |
| `external[]` | internet endpoints (public IP, `fqdn`), named in flows like hosts |
| `findings[]` | `id`, `title`, `severity`, `category`, `hosts`, `flows`, `detail` — listed in the inventory |
| `options` | `arp`, `flat`, `dual_homed`, `snmp_community`, `default_snmp_community`, `day_profile`, `utc_offset` |

The full schema is in the docstring of [`tgt/envfile.py`](tgt/envfile.py).

---

## Realism & timing

**Every cycle differs, every run is reproducible.** Source ports, TCP sequence numbers,
IP IDs, transaction IDs, process values and TLS randoms change from cycle to cycle the way
real traffic does, so a monitor cannot fingerprint a loop. `--seed N` makes the whole run
reproducible (same seed + same options = the same frames); without it a random seed is
picked and printed, and recorded in the manifest.

### Timed schedule

The default `--schedule cycle` sends every conversation once per batch at `--rate`. That is
quick for smoke tests, but nothing like a plant. **`--schedule timed`** gives each
conversation its own clock (`tgt/timing.py`, a plain editable table):

- **per-flow periods with jitter** — HMI polling every 0.5–2 s at ±3 %, DNP3 2–10 s, CIP
  class-1 I/O every 20–100 ms, LLDP 30 s, SNMP 5 min, NetBIOS 12 min (B-node broadcasts
  with a browser host announcement, kept on the sender's VLAN), DHCP renewals every
  4 h, engineering reads every 20–60 min during the day shift, an IEC 104 general
  interrogation every 15 min on the open connection (N(S)/N(R) stay continuous); each conversation keeps one stable period,
  so a plant's pollers do not all tick together. Env-file `period` / `jitter` override it;
- **request → response RTT** by path (same segment, routed, WAN) plus device processing time;
- **persistent sessions** — HMI/SCADA/historian pollers keep one long-lived TCP connection
  (handshake once, every poll reuses it), as real masters do;
- **`--day-profile shift`** — logons around 07:00, a lunch dip, nightly backups around 02:00,
  quiet weekends, OT polling steady around the clock (an env file may set its own default);
- **`--speed X`** — compress wall-clock time (60 = an hour per minute);
- **`--min-period S`** — no conversation recurs faster than S seconds (thins cyclic I/O for
  long captures);
- **`--duration`** takes `30m`, `4h`, `7d` — in simulated time under `--schedule timed`.

```bash
tgt run -e industrial-site --schedule timed --day-profile shift -i tgt0             # real time
tgt run -e ot-plant --schedule timed --speed 60 --duration 8h -i tgt0               # 8 h in 8 min
```

### Multi-day pcaps in minutes

With `--clock synthetic` the pcap and manifest timestamps run from `--start-time` instead of
the wall clock, and a pcap-only run skips real-time pacing, so a week of traffic is written
as fast as the CPU allows:

```bash
tgt run -e ot-plant --schedule timed --clock synthetic --start-time 2026-11-02T00:00:00Z \
        --duration 7d --min-period 5 --seed 7 --pcap week.pcap --manifest week.json
```

Measured on a desktop CPU with `--min-period 5` (~45–50 k frames/s): a day of `ot-plant`
is 657 k frames (78 MB) in ~13 s and a week ~95 s; a day of `industrial-site` is 6.9 M frames
(1.4 GB) in ~2.5 min. Without `--min-period` the 20–100 ms CIP I/O streams multiply the
frame count. Import the pcap into a monitor that accepts offline captures, or `tcpreplay` it.

---

## Evaluating a monitor

The workflow TGT is built around: **know what's on the wire, let the monitor learn a
baseline, change things or attack, then grade what it reported.** Any passive monitor
fits — open source or commercial; only the export step differs.

**1. Pick an environment** like the one the product will face — a built-in, a [packaged
site](#packaged-sites) or [your own](#your-own-environments) — and wire up a veth or a
[mirrored NIC](#deployment).

**2. Export the ground truth** — the assets, fields, flows and planted findings a perfect
monitor would report:

```bash
tgt inventory -e water-utility -f json -o truth.json
tgt inventory -e water-utility -o truth.csv          # spreadsheet view
```

**3. Run a baseline with a manifest.** Use the timed scheduler so polling looks real, and
let it run through the monitor's learning (training / baselining) period before you change
anything. The manifest records the seed, the inventory, when each
asset first and last sent a frame, every flow seen, and every attack event; it is rewritten
every ~10 s and on exit, so a long or killed run still leaves a valid file.

```bash
sudo tgt run -e water-utility --schedule timed --day-profile shift \
             -i tgt0 --manifest baseline.json --api 127.0.0.1:8787
```

**4a. Change detection — run a campaign.** `tgt campaign` drives an environment through
phases on the timed scheduler: a quiet baseline, then a new device, a firmware change, an IP
change, a contractor laptop reaching across zones, a device going silent. Each change is an
event in the manifest. A campaign has its own baseline phase, so it stands in for step 3.
A plan refuses a phase shorter than 3× the slowest period its change touches (so the
baseline saw it) unless you pass `--force`.

```bash
tgt campaign --list                                      # example plans
tgt campaign baseline-then-change --check                # validate, print phases
sudo tgt campaign baseline-then-change -i tgt0 --speed 12 --manifest camp.json   # 12 h in 1 h
tgt campaign ot-plant-drift --clock synthetic --min-period 5 --pcap drift.pcap --manifest drift.json
```

| example plan | env | phases |
|---|---|---|
| `baseline-then-change` | industrial-site | 4 h baseline, new PLC, firmware change, contractor laptop across zones, PLC offline (12 h) |
| `incident-window` | industrial-site | 6 h baseline, 1 h Industroyer-style IEC 104 intrusion, 2 h recovery — for time-to-detect |
| `ot-plant-drift` | ot-plant | baseline, I/O module swap, PLC re-addressed, new engineering conversation, HMI decommissioned |

A plan is a short JSON file naming the env and its phases (`add_host`, `remove_host`,
`offline` / `online`, `set` firmware/IP/model/…, `add_flow` / `remove_flow`, `sprinkle`,
`rate`, `day_profile`). The schema is in [`tgt/campaign.py`](tgt/campaign.py), the
examples in `tgt/campaigns/`.

**4b. Detections — sprinkle or inject attacks** once the baseline is learned. Either start a
run with [`--sprinkle`](#sprinkle-malware-into-normal-traffic), or inject into the running
baseline through the [control API](#control-api-and-tgt-ctl) so the attack sits at a known
point in an otherwise-normal timeline:

```bash
tgt ctl inject industroyer --duration 300     # 5 min of IEC 104 commands + C2, recorded in the manifest
tgt ctl stop                                  # flushes the pcap and the final manifest
```

**5. Export from the monitor** its asset list (CSV or JSON) and its alerts (time,
source/destination, title); for Zeek, `known_hosts.log` and the log directory.

**6. Score it** against the manifest (or the inventory JSON, which scores discovery and
fields but not time or detections):

```bash
tgt score --manifest baseline.json --assets assets.csv --map generic \
          --alerts alerts.csv --alert-map alerts-generic --html report.html --json report.json
tgt score --truth truth.json --assets known_hosts.log --map zeek-known-hosts --zeek /opt/zeek/logs/current
```

| map | for |
|---|---|
| `generic` | an asset export in CSV (or JSON with `json_path`) whose headers are common names — `IP` / `IP Address`, `MAC`, `VLAN`, `Name` / `Hostname`, `Vendor`, `Model` / `Product`, `Firmware`, `Serial`, `OS`, `Protocols`, `First Seen`, … (case-insensitive); also reads `tgt inventory` CSV |
| `zeek-known-hosts` | Zeek `known_hosts.log` (IP + first seen: discovery, precision, time-to-discover) |
| `alerts-generic` | alert map: columns + regexes that map alert titles onto TGT's event categories (and, optionally, ATT&CK techniques) |

> **Check the map against your export.** Monitors name their export columns differently, and
> the same product differs between versions and views. Compare your export's header row with
> the candidate lists in `tgt/scoremaps/generic.json`; if a column isn't matched, copy the
> map, add your header names and pass it with `--map my-map.json`. Do the same with the
> regexes in `alerts-generic.json`, so your monitor's alert titles land on the right
> categories. The JSON report's `export.columns` says which fields were found in the export
> (a field with no matched column is not scored). `--map` and `--alert-map` take a bundled
> name or a path.

To check the scoring itself, `tgt score --manifest run.json --self-test-export perfect.csv`
writes the export a perfect monitor would produce (generic map: every asset that sent
traffic, identity fields only where observable). Scoring that file must give 100 %; it does
on every built-in env and packaged site.

**7. Read the report.** `report.html` is one self-contained page (light and dark) with
summary tiles, per-field accuracy, a per-asset table with each field marked correct, partial,
wrong or missing, missed and false-positive assets, baseline coverage and detections.

| metric | what it measures |
|---|---|
| **discovery recall** | assets the monitor reported / ground-truth assets that actually sent traffic (incident-added new assets included) |
| **discovery precision** | matched rows / (matched + duplicate + false-positive rows); gateway MACs and internet endpoints are counted apart, not as false positives |
| **field accuracy** | vendor, model, firmware, serial, OS — **scored only where the value is observable** from the traffic that host sent; correct guesses on unobservable fields are listed as "inferred", not credited |
| **protocols** | per-asset protocol precision and recall against the flows the asset took part in |
| **time to discover** | monitor first-seen minus the manifest's first frame for the asset |
| **baseline coverage** | (with `--zeek`) expected flows seen in `conn.log`, plus unexpected conversations |
| **detection rate** | manifest events (attack flows, campaign changes) matched by an alert in the right category, touching the event's hosts, inside the window (`--skew` before, `--tolerance` after) |
| **time to detect** | alert time minus event start, median overall and per category; plus false and unmapped alerts |
| **technique coverage** | per **MITRE ATT&CK for ICS** (and Enterprise, for IT stages) technique: events, detected, rate and median time to detect |

**ATT&CK techniques.** Every attack event in the manifest carries the technique IDs its
traffic shows (`T0846` Remote System Discovery for a scan, `T0855` Unauthorized Command
Message for IEC 104 or Modbus writes, `T0843` Program Download, `T1071.001` web C2, …);
`tgt list` shows them per incident and the table is [`tgt/attack_ics.json`](tgt/attack_ics.json).
Only techniques visible on the wire are tagged (no ransomware *impact*, for instance). An
alert map may tag alerts too — a `technique` column of IDs, or a `techniques` table of
`{title regex: ID}` — and `--strict-technique` then only lets an alert match an event that
shares a technique (a parent ID such as `T1071` matches its sub-techniques).

### Benchmark suites (`tgt bench`)

Running baseline → attacks → changes by hand is easy to get subtly different each time.
`tgt bench` plays a **packaged, seeded suite** so two monitors — or two versions of one —
see byte-identical traffic, then turns their exports into **one scorecard** you can compare:

```bash
tgt bench list                                                    # quick (1 h), standard (2 days)
sudo tgt bench run quick -i tgt0 --speed 30 --out bench-q         # ~2 min on the wire
tgt bench run standard --clock synthetic --pcap-dir pcaps --out bench-s   # offline import
tgt bench score bench-q --assets export.csv --map my-map.json \
                --alerts alerts.csv --alert-map my-alerts.json --label "monitor A" \
                --out a.json --html a.html
tgt bench compare a.json b.json --html a-vs-b.html
```

A suite (`tgt/benches/*.json`) is an ordered list of fixed-seed stages on one environment: a
**baseline** to learn, an **incidents** window with attacks injected at fixed offsets, and a
**campaign** of asset and conversation changes. `bench run` writes a bundle — a manifest per
stage, a merged `manifest.json`, optional pcaps and `bench.json` (suite, seeds, stage windows,
a fingerprint of the traffic). `bench score` scores the asset export once against the end
state of the whole bench, and detections per stage. The scorecard has discovery recall and
precision, field accuracy, change-detection and attack-detection rates with median times to
detect, technique coverage, false alerts, and the suite's pass / fail thresholds.
`bench compare` puts two scorecards side by side and warns when their traffic fingerprints
differ. `tgt bench score DIR --self-test-export OUT` writes perfect exports to check the
pipeline end to end.

### Tips for evaluating a monitor

- **Baseline before you attack.** Most OT monitors learn the network in a training or
  baselining mode, and baseline-deviation alerts (new asset, new conversation, changes) only mean something once
  it has left it. Run clean traffic through the learning period, then sprinkle, inject or let
  a campaign reach its change phases.
- **Enable the threat content.** Make sure the threat-detection, known-threat and
  unauthorized-write (or equivalent) policies are enabled; a fresh deployment may raise no
  malware alerts even when the traffic is plainly there.
- **Use `--span access`** (the default) for a single SPAN to one sensor; `--span core`
  doubles every routed packet.
- **Mind `--speed` during a baseline.** It compresses every period, so the monitor learns
  faster polling than the plant really has. Synthetic-clock pcaps are for offline import.

---

## Attack incidents

Replay the **network signatures of famous IT/OT incidents** to validate that your
sensor detects them — themed hostnames, the ports and protocol abuse, scan and
C2-beacon patterns, and public IOC domains.

```bash
tgt run --incident wannacry     -i tgt0     # SMBv1 EternalBlue + kill-switch DNS
tgt run --incident stuxnet      -i tgt0     # S7comm PLC STOP + SMBv1 indicator
tgt run --incident industroyer  -i tgt0     # IEC-104 breaker commands + outbound C2
```

| incident | year | reproduces |
|---|---|---|
| `wannacry` | 2017 | SMBv1 MS17-010/DOUBLEPULSAR, 445 scan, kill-switch domain |
| `conficker` | 2008 | 445/139 probe, DGA C2 domains, and the generic SMBv1 exploit-attempt indicator (no MS08-067 RPC is emitted) |
| `mirai` | 2016 | Telnet (23) default-credential scan + C2 |
| `sunburst` | 2020 | SolarWinds `avsvmcloud.com` DGA + HTTP C2, then TLS C2 |
| `log4shell` | 2021 | `${jndi:ldap://…}` in HTTP headers |
| `stuxnet` | 2010 | S7comm PLC STOP commands; its SMB spread is stood in for by the generic SMBv1 exploit-attempt indicator |
| `industroyer` | 2016 | IEC 60870-5-104 breaker commands, control-port recon, HTTP C2 beacon **out to** `195.16.88.6` |
| `triton` | 2017 | TriStation (UDP 1502) to a Triconex SIS |
| `notpetya` | 2017 | SMBv1 EternalBlue worm + 445 sweep (destructive) |
| `ryuk` | 2019 | HTTP C2 + 445/3389 scan + SMB spread |
| `blackenergy` | 2015 | Ukraine-grid HTTP C2 + substation port recon |
| `emotet` | 2018 | HTTP C2 beacon + DNS tunneling / exfil |
| `colonial` | 2021 | DarkSide: TLS C2, RDP spray, SMB admin-share lateral |
| `havex` | 2014 | Dragonfly: HTTP C2 + OPC/ICS control-port scan |
| `ekans` | 2020 | ICS ransomware: SMB lateral + unauthorized Modbus writes |
| `pipedream` | 2022 | INCONTROLLER: ICS port scan + Modbus Write-Registers |
| `vpnfilter` | 2018 | Router botnet: HTTP C2 + Modbus manipulation |

Run `tgt list` for every incident with the exact protocols and signals each emits. With a
`--manifest`, every attack flow becomes an event with a vendor-neutral category
(`exploit-attempt`, `plc-mode-change`, `ot-write`, `c2`, `scan`, `lateral-movement`, …) for
`tgt score`.

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

- **`--sprinkle-ratio 0.0–0.9`** — fixed malware fraction regardless of base size. Under
  `--schedule timed` the attack streams recur as often as needed to hold that share of
  wire frames (following day profiles and campaign phases); without it they keep their
  natural periods.
- **`--sprinkle-random`** — random variant + jittered placement each cycle.
- To add an attack *during* a run, use [`tgt ctl inject`](#control-api-and-tgt-ctl).

The incident's hosts are re-addressed onto a **real inventory**, so the same machines appear
infected across cycles. On an `--env` base that inventory is the chosen environment and the
attack rides on its VLANs; on a scenario / protocol base the malware is mapped onto a
representative full-Purdue plant. A host maps onto one that can **actually serve the
protocol the attack uses** — one the environment shows serving it, or whose product implies
it (an S7-315 never answers IEC 104, a Modicon never answers TriStation) — with the same
role or role family, and an embedded device must also match by vendor and product family.
The mapping runs **top-down through the Purdue model**, so a multi-stage attack descends
IT → supervisory → cell as a coherent kill chain, with a cell's devices kept together.

An incident host with **no compatible asset keeps its own identity** and appears on the wire
as a **new asset** — which a monitor should report. `tgt inventory -e ENV --sprinkle INCIDENT`
lists those hosts under `new_assets`, and `tgt score` counts them. A C2 node or internet
attacker is never remapped: it keeps a **public IP** (RFC 5737 TEST-NET, or the campaign's
real IOC such as Industroyer's `195.16.88.6`), so an infected asset is seen beaconing *out to
the internet*, never to an internal subnet the sensor doesn't monitor.

> **SPAN view matters for a sensor.** `--span core` emits *two copies* of every routed
> packet (ingress on the sender's VLAN, egress on the receiver's VLAN, TTL−1) — it models a
> capture taken at the core L3 switch. On a flat "TGT → one NIC → sensor" feed that just
> doubles traffic with gateway-MAC rewriting, which a stream reassembler reads as
> duplicates. For a single SPAN to one sensor, use the default **`--span access`** (each
> frame once, on its sender's VLAN).

In the TUI: **Run → Malware sprinkle** (toggle · variant · random · ratio); a red
`☣ malware: <name>` banner shows while armed.

---

## CLI reference

```
tgt                       launch the TUI (default)
tgt list                  protocols, scenarios, environments, incidents, plugins
tgt env                   detected environment + interfaces
tgt env export KEY [-o F] write an environment as an env file
tgt iface create tgt0     create a veth pair (tgt0 <-> tgt0-mon)   [--type dummy]
tgt iface delete|list     remove / list interfaces

tgt run [options]
 what to send
  -p, --profile K[,K]       protocol(s), repeatable        -s, --scenario NAME
  -e, --env NAME            built-in env or packaged site  --env-file FILE  JSON/TOML env
      --span access|core    env capture point (core adds routed copies)
      --incident NAME       wannacry | stuxnet | industroyer | triton | …
      --sprinkle N[,N]      mix incident(s) into the base traffic
      --sprinkle-ratio F    malware fraction 0.0–0.9      --sprinkle-random
      --replay FILE         replay a pcap/pcapng (see Replay a pcap)
      --remap-env ENV       replay onto an environment's hosts  --remap-report F
 where
  -i, --iface A[,B]         send on interface(s) (root); a,b = same frames to each
      --pcap PATH           write frames to a pcap
 how much / how fast
      --rate PPS            0 = max (default 20; a cap only with --schedule timed)
      --count N | --duration 30m|4h|7d | --once            --messages N
      --schedule cycle|timed   --day-profile flat|shift   --speed X   --min-period S
 ground truth
      --seed N              reproducible run            --manifest FILE  run manifest
      --clock wall|synthetic   --start-time ISO
 control
      --api [HOST:]PORT     control API   --api-token T   --api-allow-remote
      --client-ip/-mac · --server-ip/-mac · --vlan ID

tgt inventory (-e ENV | --env-file F) [-f csv|json] [-o FILE] [--sprinkle INCIDENT]
tgt campaign PLAN [--list | --check] [--force] [-i IFACE] [--pcap F] [--manifest F]
                  [--clock wall|synthetic] [--start-time ISO] [--seed N] [--speed X] [--min-period S]
                  [--api [HOST:]PORT --api-token T]
tgt score (--manifest RUN.json | --truth INV.json) --assets EXPORT --map MAP
          [--alerts F --alert-map MAP] [--zeek DIR] [--tolerance S] [--skew S] [--html F] [--json F]
          [--strict-technique] | --self-test-export OUT.csv
tgt bench list | run SUITE --out DIR [-i IFACE | --pcap-dir D] [--speed X] [--clock synthetic]
tgt bench score DIR --assets EXPORT --map MAP [--alerts F --alert-map MAP] [--label L] [--html F]
tgt bench compare A.json B.json [--html F]
tgt ctl [--api ADDR] [--token T] status|stop|pause|resume|rate PPS|inject INCIDENT|manifest
```

Every subcommand has `-h` with the full list.

---

## Send on several interfaces

`-i a,b,c` sends the same frames to each interface — one generator feeding two sensors
under test side by side, or a veth for a local Zeek plus a real NIC mirrored to an appliance.
The run summary, `tgt ctl status` and the manifest keep per-interface counters.

```bash
sudo tgt run -e industrial-site --schedule timed -i tgt0,eth1
```

---

## Control API and `tgt ctl`

`--api` serves a small HTTP control API from a running `tgt run`, and `tgt ctl` is its
client — for scripting a test, or injecting an attack into a baseline that is already
running.

```bash
sudo tgt run -e ot-plant --schedule timed -i tgt0 --manifest run.json --api 127.0.0.1:8787
tgt ctl status                                  # counters, seed, rate, per-interface stats
tgt ctl inject stuxnet --duration 120 --ratio 0.1
tgt ctl pause ; tgt ctl resume
tgt ctl rate 200
tgt ctl manifest > live.json
tgt ctl stop                                    # clean stop: pcap + manifest flushed
```

An injection sprinkles an existing incident (same host mapping as `--sprinkle`) for the
given time; the manifest records it with its exact first and last frame. `tgt ctl` reads the
address from `--api` or `$TGT_API` (default `127.0.0.1:8787`); `--json` prints raw replies.
The endpoints are `GET /status`, `/manifest`, `/injections` and `POST /stop`, `/pause`,
`/resume`, `/rate?pps=N`, `/inject?incident=KEY&duration=S&ratio=F`.

**Security.** The API binds to loopback only. Binding elsewhere needs `--api-allow-remote`
**and** a token (`--api-token` or `$TGT_API_TOKEN`; clients send `Authorization: Bearer …`,
`tgt ctl --token` or `$TGT_API_TOKEN`). Requests with a browser `Origin` header, or a `Host`
that is not the bound loopback address, are refused, so a web page cannot drive it. Treat a
remotely reachable API as a remote traffic-injection switch.

---

## Replay a pcap

Bring your own capture — a real threat sample, a lab recording, a customer capture — and put
it on the wire, optionally re-addressed onto your lab's subnets:

```bash
tgt run --replay threat.pcap -i tgt0                          # at --rate
tgt run --replay threat.pcapng -i tgt0 --replay-realtime      # keep original timing
tgt run --replay plant.pcap -i tgt0 --replay-speed 10         # 10x faster than captured
tgt run --replay plant.pcap -i tgt0 --replay-loop 3           # three passes (0 = forever)
tgt run --replay plant.pcap -i tgt0 \
        --remap-subnet 192.168.1.0/24=10.100.10.0/24 --remap-ip 192.168.1.5=10.100.0.5 --vlan 110
```

Reads classic libpcap (both byte orders, µs/ns) and **pcapng** (`--replay-tsresol` overrides
its timestamp resolution); Ethernet, raw-IP and Linux SLL. Files stream record by record, so
multi-gigabyte captures replay in constant memory. `--remap-ip` / `--remap-subnet` (host bits
kept) / `--remap-mac` rewrite IPv4 and **IPv6** addresses (mixed in one run), ARP and NDP, and
recompute checksums — IPv6 extension headers and fragments are walked, and `--remap-mac` also
rewrites EUI-64 addresses and NDP link-layer options; `--vlan N` retags every frame (`0` strips
the tag). Long idle gaps are shortened. TUI: **Run → Preset → replay a pcap file…**.

**Replay onto a modeled network.** `--remap-env ENV` profiles the capture's hosts (ports
served and used, OUI, TTL), gives each internal host a free host of a compatible role and
vendor in the environment — same IP, MAC and VLAN as that host — and keeps external hosts,
routers and anything without a match as they are. The mapping is printed (`--remap-report
F.json` writes it) and the run manifest records it, so `tgt score` grades against exactly
the hosts the replay became:

```bash
tgt run --replay plant.pcap --remap-env industrial-site --remap-report map.json \
        --manifest replay.json -i tgt0
```

---

## Plugins

Site-specific protocols, scenarios, environments, incidents, device models and score maps
can live outside the TGT tree. Every `*.py` file in each directory of `$TGT_PLUGIN_PATH`,
then `~/.config/tgt/plugins/`, is imported at startup by `tgt list`, `run`, `inventory`,
`score` and the TUI. A plugin that fails is reported in `tgt list` and skipped;
`TGT_NO_PLUGINS=1` turns loading off.

```bash
TGT_PLUGIN_PATH=examples/plugins tgt list                               # shows what it adds
TGT_PLUGIN_PATH=examples/plugins tgt run --env acme-plant --pcap acme.pcap --once --rate 0
python3 examples/plugins/acme_plant.py                                  # the plugin's self-test
```

A plugin calls `tgt.plugins` at import time: `register_protocol` (a flow builder plus its
Wireshark dissector name), `register_scenario`, `register_environment` / `register_env_file`,
`register_attack`, `register_incident`, `register_device_model` and `register_scoremap`.
[`examples/plugins/acme_plant.py`](examples/plugins/acme_plant.py) is a complete example: a
CoAP protocol, a scenario, a device model, an environment, an attack + incident and an alert
map. The API reference is the docstring of [`tgt/plugins.py`](tgt/plugins.py).

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
TGT_IFACE=tgt0                  # or tgt0,tgt1: every listed veth is created, same frames to each
TGT_CMD=run                     # or campaign: TGT_RUN_ARGS then starts with the plan name
TGT_RUN_ARGS="--env industrial-site --schedule timed --manifest '/var/tmp/tgt run.json'"
```

`TGT_RUN_ARGS` is a shell-quoted argument list, so a quoted path with spaces stays one argument.
Units registered before `TGT_CMD` existed always run `tgt run` and create only one veth: run
`tgtctl.sh register` again to use campaigns or fan-out (the TUI's Service panel warns).
The systemd unit runs least-privilege (`CAP_NET_ADMIN` + `CAP_NET_RAW` only), creates the veth
in `ExecStartPre`, and stops cleanly on `systemctl stop` (SIGTERM flushes the pcap and
manifest). It restarts on failure but gives up after 5 quick failures in 2 minutes; once the
cause is fixed: `systemctl reset-failed tgt.service && systemctl start tgt.service`.

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

TGT runs as PID 1 and handles SIGTERM itself, so `podman stop` / `docker stop` ends a run
cleanly with the pcap and manifest flushed. `--init` is optional (it adds a zombie-reaping
init in front).

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

Typical lab: **TGT in one VM, the analyser** (Zeek, Suricata, Security Onion, Malcolm, a
commercial OT monitor, …) **in another, on the same host.** Put both VMs on an isolated Linux
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
python3 tests/selftest.py      # 120+ groups: builders, checksums, sessions, envs, sites, timing, scoring, API
make test                      # same, via the Makefile
```

With `tshark` on `PATH` the self-test also checks that every builder and incident decodes
as the expected Wireshark protocol with no expert warnings; without it those groups are
skipped. The [CI workflow](.github/workflows/ci.yml) runs the suite with tshark on Python
3.9–3.14 for every push and pull request, plus shellcheck on the scripts.

## Authorized use

TGT is a **test-traffic generator for lab and authorized assessment use.** It crafts
synthetic packets between endpoints you configure, on interfaces you create — no
scanning, exploitation, or interaction with third-party systems. Run it only on
networks you own or are authorized to test, and prefer the isolated veth pair so
frames never leave the host. The incident scenarios carry *detectable signatures*, not
functional exploits — for authorized detection engineering only. Keep the control API on
loopback unless you need it elsewhere, and then behind a token.

## Project layout

```
tgt/
  cli · tui · engine · sender · net · config · service      run, UI, live send, veth, service glue
  packet · pcap · pcapread · replay · rewrite · remapenv    frames, pcap write, pcap/pcapng replay, v4/v6 remap, remap onto an env
  protocols                                                 registry + IT/classic OT builders
  protocols_ot · protocols_ind · protocols_infra            OT identity/ops · PROFINET/61850/PTP · SNMP/LLDP/MQTT…
  protocols_eng · protocols_site · protocols_util           remote access/vendor eng · ring/medical/building · SEL
  protocols_codesys · protocols_sec · protocols_iiot        CODESYS V3 · secured OT (TLS/DTLS) · serial gateways, BACnet/SC, LoRaWAN
  stacks · tls                                              per-OS TCP/IP stacks · TLS fingerprints + certificates
  enterprise · devices · envfile · inventory                environments · device catalog · env files · ground truth
  scenarios · incidents                                     protocol mixes · attack scenarios
  timing · schedule · campaign                              time model · timed scheduler · phased campaigns
  manifest · score · scoremaps/                             run manifest · tgt score · column/alert maps
  techniques · attack_ics.json · bench · benches/           ATT&CK tags · technique table · tgt bench · suites
  control · api · plugins                                   live control · HTTP API · plugin loader
  envs/ (built-in exports, examples, sites/) · campaigns/   data files
examples/plugins/   acme_plant.py (+ env file, alert map)
scripts/            tgtctl.sh (install + service) · setup-veth.sh
tests/              selftest.py · fixtures/
.github/workflows/  ci.yml        Containerfile · docker-entrypoint.sh · Makefile · pyproject.toml
```

---

## Support

If it saved you building a test network for your sensor, you can [buy me a coffee ☕](https://buymeacoffee.com/fqazzazee).

---

## License & security

TGT is source-available, not open source. You can use it under either of two
licenses, whichever fits you:

- **[PolyForm Noncommercial 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0)**
  covers personal, hobby and home-lab use with no commercial purpose, plus
  charities, schools, public research and government.
- **[PolyForm Internal Use 1.0.0](https://polyformproject.org/licenses/internal-use/1.0.0)**
  covers a company running TGT on its own networks to test its own monitoring,
  at no cost.

Using TGT to deliver work for someone else needs a commercial license. That
includes consulting, freelancing, contracting, assessments, audits, and managed
services, even if you work alone. Email fadi.qazzazee@gmail.com to arrange one.

Versions published before this change were released under the MIT License, and
copies of those versions stay under MIT. See [LICENSE](LICENSE) for the full
terms.

- **Contributing:** by sending a contribution, you license it to Fadi Qazzazee
  under the MIT License. That lets it ship under the licenses above, including
  commercial licenses.
- **Security policy & vulnerability reporting:** [SECURITY.md](SECURITY.md).

> **Built with AI assistance.** Parts of this project were written with the help of an
> AI coding assistant. Review the code and test it in your own environment before
> relying on it — and use it only where you are authorized to (see [Authorized use](#authorized-use)).
