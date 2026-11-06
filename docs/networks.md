# Networks and environments

Scenarios, the modeled networks and packaged sites, segments and VLANs, the device catalog, the ground-truth inventory, your own env files, and the time model.

[← back to the README](../README.md)

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

`tgt/devices.py` holds **99 device models** — PLCs, RTUs, relays, drives, robots, switches,
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
[`example-site.json`](../tgt/envs/example-site.json) and `example-cell.toml`. A condensed example:

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

The full schema is in the docstring of [`tgt/envfile.py`](../tgt/envfile.py).

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
