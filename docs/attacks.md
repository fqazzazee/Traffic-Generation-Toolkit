# Attack incidents

The 17 incident replays, how to bury them in normal traffic, and how they map onto an environment's hosts.

[← back to the README](../README.md)

---

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

## Sprinkle malware into normal traffic

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
- To add an attack *during* a run, use [`tgt ctl inject`](usage.md#control-api-and-tgt-ctl).

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
