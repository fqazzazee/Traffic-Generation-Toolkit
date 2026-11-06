# Evaluating a monitor

The baseline → change/attack → score workflow, the score maps and metrics, ATT&CK coverage and `tgt bench`.

[← back to the README](../README.md)

---

The workflow TGT is built around: **know what's on the wire, let the monitor learn a
baseline, change things or attack, then grade what it reported.** Any passive monitor
fits — open source or commercial; only the export step differs.

**1. Pick an environment** like the one the product will face — a built-in, a [packaged
site](networks.md#packaged-sites) or [your own](networks.md#your-own-environments) — and wire up a veth or a
[mirrored NIC](deployment.md).

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
`rate`, `day_profile`). The schema is in [`tgt/campaign.py`](../tgt/campaign.py), the
examples in `tgt/campaigns/`.

**4b. Detections — sprinkle or inject attacks** once the baseline is learned. Either start a
run with [`--sprinkle`](attacks.md#sprinkle-malware-into-normal-traffic), or inject into the running
baseline through the [control API](usage.md#control-api-and-tgt-ctl) so the attack sits at a known
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
`tgt list` shows them per incident and the table is [`tgt/attack_ics.json`](../tgt/attack_ics.json).
Only techniques visible on the wire are tagged (no ransomware *impact*, for instance). An
alert map may tag alerts too — a `technique` column of IDs, or a `techniques` table of
`{title regex: ID}` — and `--strict-technique` then only lets an alert match an event that
shares a technique (a parent ID such as `T1071` matches its sub-techniques).

## Benchmark suites (`tgt bench`)

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

## Tips for evaluating a monitor

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
