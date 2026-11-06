<div align="center">

# TGT — Traffic Generation Toolkit

### A whole industrial plant on a SPAN port, so you can prove what your OT monitor really sees.

PLCs, RTUs, relays, HMIs and historians speaking **87 protocols** with real vendor identities,<br>
well-known ICS attacks buried in normal traffic, and a scorecard that grades the monitor against ground truth.

`zero dependencies` · `pure Python 3.9+` · `TUI + CLI` · `Linux · WSL · containers`

[![CI](https://github.com/fqazzazee/Traffic-Generation-Toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/fqazzazee/Traffic-Generation-Toolkit/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/fqazzazee/Traffic-Generation-Toolkit)](https://github.com/fqazzazee/Traffic-Generation-Toolkit/releases/latest)
[![Blog](https://img.shields.io/badge/📖%20Blog-Read%20the%20Write--up-FF6C37)](https://blog.safeqbit.com/traffic-generation-toolkit-tgt-make-network-traffic-on-one-machine/)
[![Buy me a coffee](https://img.shields.io/badge/Buy%20me%20a%20coffee-FFDD00?logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/fqazzazee)

</div>

---

**Your OT monitor reports 212 assets. Should it have found 230?** Did it read the firmware
off that S7-1500, or guess? Would it catch IEC 104 breaker commands from an engineering
workstation that has never sent one, and how long would it take? A vendor demo can't
answer that, and you can't attack a live plant to find out.

TGT gives you a plant you control. It puts a modeled site on a virtual SPAN feed: a water
utility, a substation, a pipeline, a car plant, a hospital and more, each with Purdue-level
segments, VLANs, NAT'd remote stations and planted security findings. It plays known attacks
into that site at a known time, then scores the monitor's asset and alert exports against
what was actually on the wire.

It runs on one Linux box with no real network and no dependencies. Every passive monitor
works with it, open source or commercial.

## What you can test

| Question | How TGT answers it |
|---|---|
| **Asset discovery.** Does it find every device? | Every modeled host talks. `tgt inventory` is the answer key, and `tgt score` gives recall, precision and time to discover. |
| **Asset identity.** Vendor, model, firmware, serial? | 99 device models announce themselves the way real ones do (CIP List Identity, S7 SZL, Modbus FC 43, BACnet I-Am, DNP3 group 0, SNMP, …). A field only counts if the traffic actually carried it. |
| **Protocol coverage.** Does it decode it? | Byte-accurate Modbus, S7comm/S7CommPlus, EtherNet/IP + CIP I/O, DNP3, IEC 104, IEC 61850, PROFINET, BACnet, OPC UA, CODESYS, … and their **TLS/DTLS-secured** variants. All of it is Wireshark-clean. |
| **Threat detection.** Does it alert, and how fast? | 17 incident replays (Industroyer, Triton, Stuxnet, PIPEDREAM, EKANS, …) tagged with **MITRE ATT&CK for ICS**, mixed into normal traffic or injected live at a recorded time. |
| **Change detection.** Does it notice drift? | `tgt campaign` adds a PLC, changes firmware, re-addresses a device, sends a contractor laptop across zones, and takes an asset offline, each a timestamped event. |
| **Comparison.** Product A vs B, or v1 vs v2? | `tgt bench` plays a fixed, seeded suite (identical traffic every time) and produces one scorecard per monitor, plus a side-by-side diff. |

<img width="1024" height="559" alt="SPAN simulation diagram" src="https://github.com/user-attachments/assets/c666137f-5360-434d-b6c4-438a1f49ac10" />

## Quick start

```bash
git clone https://github.com/fqazzazee/Traffic-Generation-Toolkit.git
cd Traffic-Generation-Toolkit
sudo python3 -m tgt
```

That opens the TUI. Go to **Interfaces** and choose `Create veth pair`, pick a site under
**Run**, and press **`s`**. Then point your sensor at **`tgt0-mon`**.

https://github.com/user-attachments/assets/36108f6f-9ab7-4748-a387-1102560a0a3b

**Headless:**

```bash
sudo python3 -m tgt iface create tgt0                                    # veth pair: tgt0 <-> tgt0-mon
sudo python3 -m tgt run -e water-utility --schedule timed -i tgt0        # a utility, at real polling rates
```

**No root?** Write a pcap and import it into the monitor or `tcpreplay` it:

```bash
python3 -m tgt run -e electric-substation --pcap substation.pcap --once --rate 0
```

**Sensor in another VM or on another box?** Send on a real NIC and mirror it. See
[Deployment](docs/deployment.md) for Proxmox, VMware, Nutanix, Xen, WSL and containers.
To run TGT as a background service: `sudo ./scripts/tgtctl.sh install && sudo ./scripts/tgtctl.sh register && sudo ./scripts/tgtctl.sh start`.

## Grade a monitor in five steps

```bash
tgt inventory -e industrial-site -f json -o truth.json                 # 1. the answer key

sudo tgt run -e industrial-site --schedule timed --day-profile shift \
             -i tgt0 --manifest run.json --api 127.0.0.1:8787          # 2. baseline: let it learn

tgt ctl inject industroyer --duration 300                              # 3. attack at a known time
tgt ctl stop                                                           # 4. flush pcap + manifest

tgt score --manifest run.json --assets export.csv --map generic \
          --alerts alerts.csv --alert-map alerts-generic --html report.html   # 5. grade it
```

(`tgt` is `python3 -m tgt`. `tgtctl.sh install` can put a `tgt` command on your PATH.)

The report covers discovery recall and precision, per-field identity accuracy, protocol
coverage, detection rate, time to detect and per-technique ATT&CK coverage, all in one
self-contained HTML page. For a repeatable run, `tgt bench run quick` replaces steps 2–4.
The full workflow, the export maps and every metric are in
**[Evaluating a monitor](docs/evaluating.md)**.

## Plants in the box

| `--env` | What it is | Planted for the monitor to find |
|---|---|---|
| `water-utility` | SCADA pair, treatment PLCs and VFDs, 8 lift stations behind cellular NAT | unauthenticated VNC HMI, Telnet to a modem, EOL WinXP HMI |
| `electric-substation` | RTAC + SEL/ABB/GE/Siemens IEDs, GOOSE, sampled values, PTP, DNP3 + IEC 104 | GOOSE from an unexpected publisher, rogue PTP grandmaster |
| `oil-gas-pipeline` | gas control, 5 compressor/meter stations over VSAT NAT (~650 ms) | vendor remote access, metering write from corporate |
| `auto-assembly` | S7-1500R, KUKA on PROFINET + MRP, DLR rings, CODESYS controllers | DCP Set-IP from a laptop, duplicate NameOfStation |
| `pharma-batch` | batch, historian, PlantPAx units; CIP Security next to plaintext CIP | recipe write from corporate, DMZ bypass |
| `iiot-retrofit` | serial device servers, Modbus gateways, LoRaWAN, BACnet/SC | raw-TCP serial tunnels carrying setpoint writes |
| `hospital-iomt` | EHR, PACS, CT/MRI over DICOM, monitors over HL7, infusion pumps | cleartext PHI, a pump talking to the internet |
| `smart-building-dc` | BACnet BMS, KNX, PDUs, UPS, chillers, cameras, access control | default SNMP, camera P2P phone-home, BMS reachable from guest Wi-Fi |
| `industrial-site` | 108-host Purdue plant: Rockwell, Siemens, Schneider, BMS, substation | IT laptop polling a meter directly (L4 → L1) |
| `ot-plant` · `it-org` · `enterprise-mixed` | smaller OT, IT and converged networks | EOL Windows, SMBv1 |

Or describe your own site in a short JSON file. See **[Networks](docs/networks.md)**.

## Why a monitor can't tell it from a real plant

- **Real identities:** vendor MAC OUIs, order numbers, firmware and serials, with known
  CVEs for each firmware in the ground truth.
- **Real fingerprints:** a TCP/IP stack per OS (Windows 2000 through Server 2019, Linux,
  embedded RTOS), TLS ClientHellos with real **JA3/JA4** families, and SSH **HASSH**.
- **Real timing:** each conversation runs on its own period with jitter; HMIs keep
  long-lived polling sessions; request/response RTT follows the path; a shift-pattern day
  has logons at 07:00 and backups at 02:00.
- **Real topology:** 802.1Q segments, HSRP gateways, routed vs switched paths, NAT'd remote
  stations, devices behind serial and LoRa gateways.
- **Never the same loop twice:** ports, sequence numbers, transaction IDs and process values
  change every cycle, but `--seed` reproduces a run byte for byte. A synthetic clock writes
  **a week of plant traffic in minutes**.

## Protocols

- **OT / ICS:** Modbus/TCP, DNP3, EtherNet/IP + CIP class-1 I/O, S7comm, S7CommPlus, IEC 60870-5-104, OPC UA, MQTT + Sparkplug B
- **Substation & industrial L2:** IEC 61850 GOOSE / SV / MMS, PTP, PROFINET DCP + RT, MRP, DLR, SEL ASCII
- **Vendor engineering:** CODESYS V3, Omron FINS, MELSEC SLMP, GE SRTP, HART-IP
- **Secured OT:** CIP Security (TLS + DTLS), S7CommPlus over TLS, OPC UA SignAndEncrypt, IEC 104 / DNP3 over TLS, Modbus/TCP Security
- **Serial gateways & IIoT:** Modbus RTU over TCP, DNP3 serial, Moxa RealCOM + discovery, BACnet/SC, LoRaWAN
- **Building & medical:** BACnet, KNXnet/IP, DICOM, HL7
- **IT & infrastructure:** DHCP, DNS, NTP, SMB, Kerberos, LDAP, HTTP(S), SSH, RDP, VNC, Telnet, FTP/TFTP, SNMP, LLDP/CDP, syslog, mDNS/SSDP/LLMNR

What each one carries and which identity fields it exposes: **[Protocols](docs/protocols.md)**.

## Attacks

WannaCry · NotPetya · Conficker · Ryuk · Colonial (DarkSide) · Emotet · SUNBURST · Log4Shell ·
Mirai · VPNFilter · **Stuxnet · Industroyer · BlackEnergy · Triton · Havex · EKANS · PIPEDREAM**

Run one on its own (`--incident`), mix it into normal traffic at a fixed ratio
(`--sprinkle`), or inject it into a running baseline (`tgt ctl inject`). Attack hosts map
onto real assets that can serve the protocol, top-down through the Purdue levels, and C2
always beacons out to a public IP. See **[Attacks](docs/attacks.md)**.

> **Detection-test traffic only:** the network indicators of each incident, not working
> exploits, shellcode or malware.

## Documentation

| | |
|---|---|
| [Evaluating a monitor](docs/evaluating.md) | workflow, ground truth, campaigns, `tgt score`, metrics, ATT&CK, `tgt bench`, tips |
| [Networks](docs/networks.md) | scenarios, built-in networks, packaged sites, VLANs and SPAN view, device catalog, env files, timing |
| [Protocols](docs/protocols.md) | every protocol key, what it carries, identity exposed, TCP/IP + TLS fingerprints |
| [Attacks](docs/attacks.md) | the 17 incidents, sprinkling, host mapping |
| [Using TGT](docs/usage.md) | TUI, CLI reference, multiple interfaces, control API, pcap replay, plugins, self-test, layout |
| [Deployment](docs/deployment.md) | service, WSL, Podman/Docker, sensor in another VM, Proxmox hub bridge |
| [SPAN Configuration](SPAN%20Configuration/README.md) | hypervisor port mirroring: Proxmox, VMware, Nutanix, Xen |
| [CHANGELOG](CHANGELOG.md) | what changed in each release |

## Authorized use

TGT is a **test-traffic generator for labs and authorized assessments.** It crafts synthetic
packets between endpoints you configure, on interfaces you create. It does no scanning or
exploitation and never touches third-party systems. Run it only on networks you own or are
authorized to test, and prefer the isolated veth pair so frames never leave the host. Keep
the control API on loopback unless you need it elsewhere, and then behind a token.

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
