# Using TGT

The TUI, the CLI, multiple interfaces, the control API, pcap replay, plugins, the self-test and the source layout.

[← back to the README](../README.md)

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
[`examples/plugins/acme_plant.py`](../examples/plugins/acme_plant.py) is a complete example: a
CoAP protocol, a scenario, a device model, an environment, an attack + incident and an alert
map. The API reference is the docstring of [`tgt/plugins.py`](../tgt/plugins.py).

---

## Verify

```bash
python3 tests/selftest.py      # 170+ groups: builders, checksums, sessions, envs, sites, timing, scoring, API
make test                      # same, via the Makefile
```

With `tshark` on `PATH` the self-test also checks that every builder and incident decodes
as the expected Wireshark protocol with no expert warnings; without it those groups are
skipped. The [CI workflow](../.github/workflows/ci.yml) runs the suite with tshark on Python
3.9–3.14 for every push and pull request, plus shellcheck on the scripts.

---

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
