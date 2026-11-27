# EDR traffic

TGT can put an endpoint detection and response (EDR) agent's network behaviour on the wire,
with ground truth for what it sent. Use it to test whether a passive monitor recognises EDR
traffic, keeps it out of the asset list, and sees the real path through a proxy.

**This is simulated traffic.**

- Payloads are opaque seeded bytes. There is no sensor protocol content, customer ID, token,
  agent ID or credential in any frame.
- Frames are only crafted. TGT never opens a connection to a vendor service.
- **Only the CrowdStrike EU-1 addresses are a real published list. Every other region's
  addresses are RFC 5737 documentation placeholders**, which are not routable and belong to
  nobody.

## Default behaviour

With no EDR option set, an environment keeps its original traffic: every covered Windows and
Linux host beacons to the CrowdStrike EU-1 cloud. Set an option to choose a profile, a region,
a proxy, or to turn EDR off.

## Profiles and regions

`tgt edr list` prints this catalogue.

| Profile | Region | Sensor host | IP pool | IP provenance |
|---|---|---|---|---|
| `crowdstrike` | `us-1` | `ts01-b.cloudsink.net` | 192.0.2.64-71 | documentation |
| `crowdstrike` | `us-2` | `ts01-gyr-maverick.cloudsink.net` | 198.51.100.64-71 | documentation |
| `crowdstrike` | `eu-1` (default) | `ts01-lanner-lion.cloudsink.net` | 35 addresses | published |
| `crowdstrike` | `us-gov-1` | `ts01-laggar-gcw.cloudsink.net` | 203.0.113.64-71 | documentation |
| `generic` | `lab` (default) | `sensor.edr.example` | 192.0.2.128-135 | documentation |

Each CrowdStrike region also has `lfoup01-*` (upload) and `lfodown01-*` (download) hosts on
`cloudsink.net`, and an API host: `api.crowdstrike.com`, `api.us-2.crowdstrike.com`,
`api.eu-1.crowdstrike.com` or `api.laggar.gcw.crowdstrike.com`.

The `generic` profile is vendor-neutral. It uses RFC 2606 names under `edr.example`, its own
TLS client fingerprint (`edr-generic`) and a certificate issuer that names no real CA.

### Provenance

Each region records where its data came from, and the inventory repeats it.

| Field | Value | Meaning |
|---|---|---|
| IPs | `published` | the vendor's published list |
| IPs | `documentation` | RFC 5737 placeholders |
| Hostnames | `vendor-docs` | from the vendor's public documentation (all API hosts) |
| Hostnames | `mirrored-docs` | from public copies of the vendor's requirements (US-1, US-2, EU-1 sensor hosts) |
| Hostnames | `unverified` | not confirmed |

The US-GOV-1 sensor hostnames are `unverified` because public copies of the requirements
disagree on them. The `generic` names and every `custom` hostname are also `unverified`.

## Channels

| Channel | Who | Shape |
|---|---|---|
| `sensor` | every covered host, spread over the pool | long-lived TLS, low-rate heartbeat |
| `upload` | one anchor host | client-heavy telemetry |
| `download` | one anchor host | server-heavy content and policy |
| `api` | the same anchor host, never the sensors | short management session |

The anchor is the first historian, file server, domain controller or SCADA server that is
covered, otherwise the first covered host.

### Several clouds at once

A run can report to more than one cloud, for example every CrowdStrike region, or CrowdStrike
US-1 next to the `generic` profile. The covered fleet is split into contiguous groups, one per
cloud, in the order the clouds are listed, as a company with several tenants would be. Each
group gets its own anchor, so every cloud has all four channels. With fewer covered hosts
than clouds, some clouds get no host and send nothing. The proxy, when set, serves every cloud.

The inventory's `edr` summary then lists each cloud under `clouds`, with the hosts it covers,
and every `edr-cloud` external endpoint names its own profile and region.

## Configuration

### Command line

```bash
tgt edr list
tgt run -e ot-plant --edr crowdstrike:us-2 --once --rate 0 --pcap edr.pcap
tgt run -e enterprise-mixed --edr generic --edr-proxy PROXY01 --once --rate 0 --pcap proxy.pcap
tgt run -e ot-plant --edr off --once --rate 0 --pcap no-edr.pcap
tgt run -e enterprise-mixed --edr crowdstrike:all,generic --once --rate 0 --pcap clouds.pcap
tgt campaign PLAN --edr crowdstrike:eu-1 --pcap run.pcap --manifest run.json
```

- `--edr PROFILE[:REGION]` selects a profile, and its default region if none is named.
- `--edr off` removes EDR from the wire and from all ground truth.
- `--edr A,B,...` runs several clouds, and `--edr PROFILE:all` runs every region of a profile.
  A single cloud keeps the flat `profile`/`region` block.
- `--edr-proxy HOST` routes sensors through an environment host.
- `--edr custom` uses the custom profile in the environment file.

These options override the file's `edr` block for that run; a new profile keeps the block's
proxy. They need an environment and do not apply to `--replay`. An unknown profile, region or
proxy host exits with status 2.

An explicit setup owns every EDR path: flows an environment file declares with protocol `edr`
are not generated while it is active, and an external endpoint only they reach leaves the
ground truth. `tgt env export` still writes them back.

`tgt inventory` reads the environment file's block but has no `--edr` option. For a run with
a command-line override, take the ground truth from `--manifest`.

### Environment file

```json
"edr": {"enabled": true, "profile": "crowdstrike", "region": "us-2",
        "proxy": "PROXY01", "proxy_port": 8080}
```

All keys are optional. `profile` defaults to `crowdstrike`, `region` to the profile's default,
and `proxy_port` to 8080. `{"enabled": false}` turns EDR off. `tgt env export` writes the block
back, and omits it when unset.

For several clouds, list them in `clouds` instead of `profile` and `region`:

```json
"edr": {"clouds": ["crowdstrike:us-1", "crowdstrike:eu-1", "generic"]}
```

Each entry is `PROFILE[:REGION]`, or `PROFILE:all`. A `custom` entry, at most one, takes its
region from the entry (`custom:lab-a`) and its other keys from the block.

### Your own vendor

Use `"profile": "custom"`. No code change is needed.

```json
"edr": {
  "profile": "custom",
  "vendor": "Example Vendor",
  "region": "lab-a",
  "fqdns": {"sensor": "sensor.vendor.example", "upload": "up.vendor.example",
            "download": "down.vendor.example", "api": "api.vendor.example"},
  "ips": ["198.51.100.200", "198.51.100.201"]
}
```

`vendor`, all four `fqdns` and `ips` are required. `label` and `tls_client` (a TLS template key,
default `edr-generic`) are optional. Cloud addresses must be unicast, outside every segment, and
not used by a host, a NAT site or a built-in incident, so attack traffic never reads as EDR.
Custom IPs are reported as `documentation` when all are in RFC 5737, otherwise as `published`.

## On the wire

**DNS.** When a host has a DNS server it can use, it resolves the channel's name before each
new connection and the answer is the address it then connects to. It uses the server from its
own DNS flow, otherwise the nearest one in the site. With no DNS server in the environment,
hosts connect without a lookup.

**Proxy.** This is the usual OT/DMZ deployment. With a proxy set:

1. The sensor resolves the proxy's name and opens TCP to it.
2. It sends `CONNECT host:443`. The proxy resolves the cloud name and opens the upstream leg.
3. The proxy answers `200`, and TLS with the channel's SNI runs inside the tunnel.
4. The proxy relays the same TLS bytes on its upstream leg to the cloud.

Proxied hosts have no direct path to the cloud. The proxy host's own sensor, if it has one,
connects directly.

**Certificates.** The server presents a certificate for the requested FQDN, so it follows the
region. The signature is random bytes and would not validate.

## Ground truth

- **Inventory `external`:** cloud endpoints have `kind: "edr-cloud"`, the profile's `vendor`,
  and with an explicit setup also `profile`, `region`, `channels` and `ip_provenance`. `talkers`
  lists who really reaches each one, so under a proxy that is the proxy alone.
- **Inventory `edr`:** a summary of the active setup, present only with an explicit setup.
- **Inventory `flows`:** sensor-to-proxy legs and added DNS lookups, tagged by `path`.
- **Manifest `flows_seen`:** each observed leg, including proxy legs and DNS.
- **`tgt score`:** cloud addresses count as external even when they are RFC 5737 placeholders,
  so they are never scored as assets or false positives.

## Limits

- Payloads are opaque, so this exercises recognition by SNI, certificate, DNS, ports, timing and
  volume. It does not model sensor protocol behaviour.
- The TLS fingerprints are representative templates, not captures of a current sensor build.
- Vendor hostnames and addresses change. Check the provenance before relying on one.
- In timed mode the ordering across a tunnel's two legs is approximate at millisecond scale.
- The proxy is a plain CONNECT relay, with no authentication or TLS inspection.
