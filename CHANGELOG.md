# Changelog

## 2.0.0 — 2026-11-05

TGT 2.0 shifts from a traffic generator to a toolkit for evaluating a passive monitor. It
generates realistic, time-shaped traffic for a modeled site, records exactly what it sent,
and scores what the monitor reported against that record. Everything is still pure stdlib
on Python 3.9+. Issues #24–#62.

### Evaluating a monitor
- **Run manifest** (`--manifest`, schema `tgt-manifest/1`): the seed, every asset with when
  it first appeared, every conversation, and every attack, change and injection event with
  exact first and last frames. `--seed` reproduces a run byte for byte, and
  `--clock synthetic` writes pcaps with simulated timestamps. #24 #54
- **`tgt score`**: grades a monitor's asset and alert export against the manifest or the
  inventory. It reports discovery recall and precision, per-field accuracy (credited only
  where the value is observable on the wire), protocols, time to discover, baseline
  coverage from Zeek `conn.log`, and detection rate and time to detect, as a self-contained
  HTML/JSON report. Column maps are bring-your-own; `--self-test-export` writes the export
  a perfect monitor would produce. #55
- **`tgt campaign`**: phased plans to test baselining and change detection, covering new
  assets, firmware changes, new flows and devices going offline. #56
- **Ground truth**: firmware, serial, Purdue level and per-field observability, plus
  external and infrastructure lists in `tgt inventory`. #53

### Realism
- **Timed scheduler** (`--schedule timed`): each flow has its own period, jitter and
  request/response RTT. Masters keep persistent sessions. `--day-profile shift` shapes
  activity over the day, `--speed` compresses time and `--min-period` thins fast flows. #39
- **Per-cycle variation**: fresh ports, ISNs, transaction IDs and drifting process values
  on every cycle. #24
- **Fingerprints**: TCP/IP stacks per OS and TLS ClientHello families per client, giving
  distinct JA3/JA4, with X.509 server certificates. #40 #41
- **OT identity**: device identity on the wire for every OT protocol, and engineering
  operations in the baseline (uploads, downloads, mode changes, writes, clock sync). #44 #45
- **Device catalog**: 85+ models with firmware, serials, modules, banners and CVEs. #43
- **Topology**: ARP everywhere, a real DMZ, NAT'd remote sites, redundancy, and managed
  switches with LLDP/CDP, SNMP and syslog. #52

### Networks and protocols
- **Environment files** (`--env-file`, JSON or TOML on 3.11+) with findings and external
  endpoints. #50
- **Seven packaged sites**: water utility, electric substation, oil & gas pipeline,
  automotive assembly, hospital IoMT, smart building / data center, and pharma batch. #51
- **New protocols**:
  - Infrastructure: SNMP v2c/v3, LLDP, CDP, syslog, mDNS, SSDP, LLMNR, NBNS, MQTT, Sparkplug B
  - Industrial: PROFINET DCP/RT, IEC 61850 GOOSE/SV/MMS, PTP
  - File transfer and remote access: FTP/TFTP firmware transfer, SSH, RDP, VNC, Telnet
  - Vendor engineering: S7comm-plus, Omron FINS, MELSEC/SLMP, HART-IP, GE SRTP
  - Ring redundancy, healthcare and building: MRP, DLR, DICOM, HL7, KNXnet/IP

  #46 #47 #48 #49
- **Wire-level fixes**: UDP reply ports, SYN ack, BACnet invoke ID, IEC 104 sequence
  numbers, Industroyer C2 direction, Modbus FC6, and DHCP DORA, NTP and DNS content.
  #25–#29 #32 #42

### Attacks
- Sprinkled incidents now map onto hosts that can actually serve the attacked protocol, by
  vendor and product family. An attack flow never maps both ends onto one host. #30
- Incident descriptions now say what is actually emitted. #31 (era-specific exploit payloads
  are deliberately not included)

### Running it
- **Fan-out**: `--iface a,b` sends the same frames to several interfaces, with
  per-interface counters. A deleted interface is reopened when it comes back. #58
- **Control API** (`--api`) and `tgt ctl`: status, pause/resume, rate, timed incident
  injection and a live manifest. Injections build off the send loop and are recorded in
  the manifest. #59
- **Replay**: pcapng, streaming of large files, IP/subnet/MAC remap, VLAN retag, a speed
  factor and loops. #60
- **Plugins** for protocols, environments and incidents. #61
- **TUI**: toggles for every run option, live inject (`i`) and pause (`p`), protocol
  families with a filter, fan-out, a rolling pps and quit confirmation. #62
- **Ops**: clean SIGTERM with pcap and manifest flush, failed sends no longer counted as
  sent, accurate realtime replay timing, a quoted service config with a restart cap,
  campaigns and fan-out as a service (`TGT_CMD`, `TGT_IFACE=a,b`), and quiet non-TTY
  logs. #33–#38
- **CI**: Python 3.9–3.14, tshark dissection, golden pcaps and shellcheck. #57
