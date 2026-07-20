# Proxmox VE — SPAN / mirror feed setup

Goal: get every frame TGT sends visible to an analyser VM (Claroty CTD, Zeek,
Suricata, Security Onion, Malcolm, …) on Proxmox VE. Proxmox has **no built-in
port-mirroring GUI feature** — not for the default Linux bridge, and not for the
optional Open vSwitch bridge type either (the GUI lets you *create* an OVS bridge, but
not configure OVS mirrors on it). Everything below is built from the GUI-exposed
networking primitives, with CLI only where the GUI genuinely has no equivalent.

## Official documentation

- **Proxmox VE Administration Guide** (`pve.proxmox.com/pve-docs/`) — chapter
  **"Network Configuration"** covers Linux bridges, bonds, VLANs, and the OVS bridge
  types available in the GUI.
- Same guide, chapter on **"Hookscripts"** (`pvesh`/qm hookscript documentation) covers
  the hookscript mechanism used below.
- Proxmox VE **Bugzilla** and the official **Proxmox Community Forum**
  (`forum.proxmox.com`) are the right places to check current behavior/known issues —
  search "OVS mirror" or "SPAN bridge" before building on the CLI steps below, since
  bridge internals have shifted across PVE major versions.

## GUI steps — isolated bridge (works for a 2-VM PoC with no CLI at all)

1. **Datacenter → node → System → Network → Create → Linux Bridge.**
   Leave **Bridge ports** empty (don't attach a physical NIC) — this keeps the bridge
   host-local with no uplink, so traffic never leaves the host. Give it a name like
   `vmbrspan`. Apply the pending change (`Apply Configuration` in the Network view, or
   `ifreload -a` if you prefer confirming from a shell).
2. **Attach both VMs' NICs to `vmbrspan`:** VM → Hardware → Network Device → Edit →
   Bridge = `vmbrspan`. Leave the firewall checkbox **unticked** on both — the Proxmox
   firewall can drop the very traffic you're trying to mirror.
3. **Nothing else on this bridge.** With exactly two ports on the segment, any frame
   TGT sends to a synthetic/simulated destination MAC is "unknown unicast" — standard
   bridge behavior floods unknown-unicast to every other port, which is only the
   analyser's. This gets you SPAN-equivalent visibility without touching bridge
   internals at all, as long as you don't add a third, real, responding device to this
   bridge later.
4. **Set the analyser's NIC to promiscuous mode inside the guest OS** —
   `ip link set eth0 up promisc on` on Linux, or the sensor's own capture-interface
   setting. This is guest-level, not something the Proxmox GUI controls.
5. **Verify:** point TGT at its bridge NIC (`TGT_IFACE=eth0` in `/etc/tgt/tgt.conf`, or
   `-i eth0`, or the TUI's Map panel), then `tcpdump -i <nic>` on the analyser.

That's the whole setup for a controlled 2-VM PoC — no CLI, no hookscript.

## When the GUI isn't enough: guaranteed flooding (hub bridge) via CLI

The 2-port trick above breaks the moment a third device joins the bridge (a gateway, a
"victim" VM that actually responds — its MAC gets learned and traffic to it stops
flooding to the analyser). If your scenario needs more than TGT + analyser on the
segment, you need the bridge to genuinely behave as a hub (no MAC learning), and the
Proxmox GUI has no toggle for that — the VM `tap` interfaces are created dynamically at
boot, so the only way to flip their learning flag is a hookscript that runs after each
VM starts:

**1.** Create `/var/lib/vz/snippets/spanhub.sh`:

```bash
#!/bin/bash
# After a VM starts, make its SPAN bridge a hub (no learning => floods all ports).
[ "$2" = "post-start" ] || exit 0
for p in $(ls /sys/class/net/vmbrspan/brif 2>/dev/null); do
    bridge link set dev "$p" learning off flood on mcast_flood on
done
```

**2.** Make it executable and attach it to both VMs (whichever boots last re-flips
every port, and it reapplies on every start so it survives reboots):

```bash
chmod +x /var/lib/vz/snippets/spanhub.sh
qm set <TGT_VMID>      --hookscript local:snippets/spanhub.sh
qm set <ANALYSER_VMID> --hookscript local:snippets/spanhub.sh
```

Not using a hookscript? Run the `for p in … bridge link set …` loop by hand once after
starting the VMs. Verify with `bridge -d link show | grep -A1 vmbrspan` — each port
should read `learning off flood on`.

## Open vSwitch bridge type: real mirror sessions (CLI-only, no GUI path exists)

Proxmox's GUI lets you add an **OVS Bridge** / **OVS IntPort** / **OVS Bond** as
network device types (same Network view, `Create` dropdown) — but it stops there. OVS
natively supports proper SPAN/RSPAN/ERSPAN-style mirroring, and none of it is
GUI-configurable in Proxmox; it's `ovs-vsctl` only:

```bash
ovs-vsctl -- --id=@p get port <analyser-tap> \
  -- --id=@m create mirror name=m0 select-all=true output-port=@p \
  -- set bridge vmbrspan mirrors=@m
```

This mirrors *all* traffic on `vmbrspan` to the analyser's tap, regardless of how many
other devices are on the bridge — solving the "more than 2 ports" problem the Linux
hub-bridge hookscript also solves, just via OVS's actual mirror feature instead of
disabling learning. Trade-off: this config lives on the OVS bridge, not in
`/etc/network/interfaces`, so it does **not** survive `ifreload -a` or a host reboot
unless you also script it into a hookscript or a systemd unit that re-applies it at
boot. There is no supported, persistent, GUI-backed way to keep it — that's the
practical reason the project's default recommendation (above) is the plain Linux
hub-bridge, not OVS mirroring.

## Physical Cisco switch integration

If the analyser needs to see real inter-host or upstream traffic rather than just
TGT's synthetic frames on an isolated bridge, mirror at the physical switch instead and
land the feed on a normal Proxmox bridge/VLAN (same pattern as `Nutanix.md` and
`VMware.md`):

```
monitor session 1 source interface Gi1/0/1
monitor session 1 destination interface Gi1/0/24        ! local SPAN
monitor session 1 destination remote vlan 900           ! RSPAN
monitor session 1 destination ip address 10.10.10.50     ! ERSPAN
```

For SPAN/RSPAN, dedicate a physical NIC on the Proxmox host to a bridge with that
uplink attached and put the analyser's tap on it (promiscuous mode in-guest, as above).
For ERSPAN, no special bridge/VLAN is needed at all — it's just routed GRE traffic to
the analyser VM's ordinary IP; confirm your analyser (Claroty CTD, etc.) supports
ERSPAN ingestion natively before committing to this as the design.

## Community tips

Not Proxmox-official guidance — cross-check against current forum activity, but
reflects recurring practitioner experience:

- Proxmox Forum threads on isolated/"dummy" bridges repeatedly flag that leaving
  **Bridge ports** genuinely empty (not just unchecked) is what keeps the segment from
  leaking onto the LAN — a bridge with `bridge-ports none` still gets an `ifreload`
  warning in older PVE versions that people mistake for an error; it's expected.
- Multiple forum posts on IDS/sensor labs note the **firewall checkbox on the VM's
  network device** is the single most common reason mirrored traffic silently vanishes
  — the Proxmox firewall (if enabled cluster/datacenter-wide) applies per-tap even when
  you think you've left it off at the VM level; check Datacenter → Firewall too, not
  just the VM's NIC.
- Threads discussing OVS on Proxmox consistently recommend re-applying mirror config
  via a systemd unit (`After=pve-guests.service`) rather than relying on manual
  `ovs-vsctl` after every reboot — nobody has found a way to make it survive
  `ifreload -a` natively.

## Verify

```bash
tcpdump -i <nic> -n
```
on the analyser VM before pointing its detection engine at the interface.
