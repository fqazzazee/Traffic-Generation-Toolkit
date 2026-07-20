# SPAN Configuration

GUI-first walkthroughs for feeding TGT's simulated traffic to an analyser VM (Claroty
CTD, Zeek, Suricata, Security Onion, …) as a SPAN/mirror feed, per hypervisor. Each doc
references the vendor's official documentation, includes community-sourced tips, and
only reaches for CLI/scripting where the GUI has no equivalent.

- [Nutanix.md](Nutanix.md) — Prism Central has a native "Traffic Mirroring" GUI
  feature (Flow-licensed, confirmed via official doc titles) on current AOS/PC
  versions; isolated-VLAN flooding trick or ERSPAN via the physical switch if you're
  on an older version or without Flow.
- [VMware.md](VMware.md) — vSphere Distributed Switch has a real, native Port
  Mirroring GUI (including ERSPAN); standard-vSwitch promiscuous-mode fallback if you
  don't have a vDS license. Watch the confirmed vMotion caveat on the same-host-only
  session type.
- [Proxmox.md](Proxmox.md) — isolated Linux bridge (GUI-only, for a 2-VM PoC); hub-mode
  hookscript or `ovs-vsctl` mirrors (CLI) if you need more than two devices on the
  segment.
- [Xen.md](Xen.md) — XenServer/Citrix Hypervisor/XCP-ng (OVS-based; dom0 CLI is fully
  supported, but mirror/promiscuous config is *not* durable — VIF identifiers churn
  on every VM restart) and plain upstream Xen; isolated private network (GUI-only)
  plus a required 3-phase CLI procedure even for the 2-VM case.

See the main [README](../README.md#deployment) for how TGT itself attaches to whichever
bridge/subnet/port-group these docs set up.

## Ease-of-deployment comparison

How each hypervisor stacks up for getting TGT's traffic to an analyser VM, from a
clean PoC to a real physical-switch feed.

| | Native GUI mirror | Physical switch (SPAN/RSPAN/ERSPAN) | Single-host TGT + analyser PoC | Multi-host TGT + analyser | Config persistence |
|---|---|---|---|---|---|
| **VMware vSphere (vDS)** | Yes — full GUI, incl. built-in ERSPAN mode. Requires Enterprise Plus (or vSAN licensing) | Easiest: Remote Mirroring Source/Destination & ERSPAN are GUI dropdowns | Easiest: native mirror session or promiscuous port group, both pure GUI | Confirmed gotcha: plain Distributed Port Mirroring only works while source/dest stay on the *same* host — use Remote Mirroring/ERSPAN if VMs can vMotion | Fully persistent, vCenter-managed |
| **Nutanix AHV** | Yes on current AOS/Prism Central (confirmed via official doc titles) — ships under Flow Network Security/Virtual Networking, so it's licensing-gated like vDS. Isolated-subnet flood trick works on any version as a free fallback | Best done via ERSPAN (native switch-side encapsulation, lands on an ordinary routed subnet) if the native feature or Flow license isn't available | Easy either way: native GUI session, or the isolated-subnet flood trick (fully GUI, zero OVS CLI) | Native feature is centrally managed by Prism Central, plausibly more migration-safe than the old manual-OVS approach — confirm for your version. Flood trick has the same "nothing else on the segment" caveat as everywhere else | Manual `ovs-vsctl` mirror (the pre-native-feature workaround) is confirmed **unsupported, and lost on host reboot, VM restart, or migration** — don't rely on it now that the native feature exists |
| **Proxmox VE** | No | Manual: dedicate a physical NIC + switch-side `monitor session`, no native ERSPAN handling | Easy: isolated bridge is GUI-only for exactly 2 VMs | Needs a matching bridge/VLAN + physical trunk between hosts; `ovs-vsctl` mirror (CLI) if >2 devices | Hookscript (bridge hub trick) or OVS mirror both need manual re-apply on boot/VM restart — confirmed by multiple forum threads |
| **Xen (XenServer/XCP-ng)** | No | Straightforward: OVS mirror or ERSPAN via `ovs-vsctl`/switch config, PCI passthrough is mature | Needs a 3-phase CLI procedure (PIF + VIF promiscuous flags + unplug/replug) even for 2 VMs; network creation itself is GUI | Same CLI mirror approach extends cleanly; XO can overlay private networks across hosts | **Worst of the four, confirmed**: VIF backend names are destroyed and regenerated on every VM restart (not just host reboot), breaking any manually-keyed mirror — community tooling (MagicSPAN) exists specifically to work around this |

**Overall ease ranking: VMware ≈ Nutanix > Proxmox > Xen.** VMware and Nutanix are
now tied for best — both have a real native GUI mirroring feature, and both gate it
behind a paid licensing tier (Enterprise Plus/vSAN vs. Flow Network Security/Virtual
Networking). VMware edges ahead on maturity: it's been battle-tested far longer, and
its one confirmed gotcha (same-host-only Distributed Port Mirroring) has a
well-documented fix. Nutanix's native feature is newer and its exact docs sit behind
a support-portal login, so budget time to verify against your specific AOS/PC
version. Proxmox beats Xen because its 2-VM case needs zero CLI at all, while Xen
needs a multi-step `xe` procedure even for the trivial case — and Xen's mirror
persistence problem (VIF names churning on every VM restart, not just host reboot)
is confirmed to be the worst of the four, which is why a purpose-built community tool
(MagicSPAN) exists just to paper over it.
