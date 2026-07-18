# Security Policy

## Scope and intent

TGT (Traffic Generation Toolkit) is a **defensive / testing** tool. It generates
synthetic test traffic onto virtual interfaces **you** create, so you can validate
passive network monitoring — SPAN/mirror ingestion, IDS/IPS, and asset-discovery
tooling (Wireshark, Zeek, Suricata, Security Onion, Malcolm, or commercial OT
platforms such as Claroty CTD, Nozomi, Dragos).

TGT does **not** scan, exploit, or interact with third-party systems. Its "incident"
scenarios reproduce the **detectable network signatures** of known attacks (ports,
protocol markers, scan/beacon patterns, public IOC strings) — they are **not** working
exploits, shellcode, or malware.

## Authorized use only

Run TGT only on networks and interfaces you own or are **explicitly authorized** to
test. Prefer the isolated veth pair so generated frames never leave the host. You are
responsible for complying with all applicable laws, contracts, and policies. The
software is provided "as is" (see [LICENSE](LICENSE)).

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue for a
vulnerability.

- **Preferred:** GitHub → the repository's **Security** tab → **Report a vulnerability**
  (private security advisory).
- Include: affected version (`tgt --version`), a description, reproduction steps, and
  the impact you observed.

We aim to acknowledge reports within a few business days and will coordinate a fix and
a disclosure timeline with you. Please give us reasonable time to remediate before any
public disclosure.

## Supported versions

Active development happens on `main`, and fixes land there — please reproduce against
the latest `main` before reporting. Tagged releases follow semantic versioning; only
the most recent minor release is supported with security fixes.

## Operational safety notes

- **Privileges.** Live sending needs `root` / `CAP_NET_RAW`. The systemd service runs
  least-privilege with only `CAP_NET_ADMIN` + `CAP_NET_RAW` (not full root).
- **Generated artifacts.** Frames, pcaps, and replayed captures may contain IOC strings
  and attack signatures **by design**. Treat output files as test artifacts, label them
  as such, and do not feed them into production detection pipelines unlabeled.
- **Isolation.** The recommended veth pair (or an isolated Proxmox hub bridge with no
  uplink) keeps generated traffic on the host. Do not attach TGT's send interface to a
  production network segment.
- **Dependencies.** TGT is pure Python standard library (no third-party packages), which
  keeps its supply-chain surface minimal.

## Verifying a build

```bash
python3 -m tests.selftest    # validates packet builders, checksums, sessions, pcap
```
