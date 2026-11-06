# Protocols

Every protocol TGT speaks, the identity each one exposes, and how hosts are fingerprinted. `tgt list` prints every key with a one-line description.

[← back to the README](../README.md)

---

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

## TCP/IP stacks, TLS fingerprints and certificates

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
