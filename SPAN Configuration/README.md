# SPAN Configuration

GUI-first walkthroughs for feeding TGT's simulated traffic to an analyser VM (Claroty
CTD, Zeek, Suricata, Security Onion, …) as a SPAN/mirror feed, per hypervisor. Each doc
references the vendor's official documentation, includes community-sourced tips, and
only reaches for CLI/scripting where the GUI has no equivalent.

- [Nutanix.md](Nutanix.md) — AHV has no native port-mirror GUI; isolated-VLAN
  flooding trick for a 2-VM PoC, ERSPAN via the physical switch for the real thing.
- [VMware.md](VMware.md) — vSphere Distributed Switch has a real, native Port
  Mirroring GUI (including ERSPAN); standard-vSwitch promiscuous-mode fallback if you
  don't have a vDS license.
- [Proxmox.md](Proxmox.md) — isolated Linux bridge (GUI-only, for a 2-VM PoC); hub-mode
  hookscript or `ovs-vsctl` mirrors (CLI) if you need more than two devices on the
  segment.
- [Xen.md](Xen.md) — XenServer/Citrix Hypervisor/XCP-ng (OVS-based, dom0 CLI fully
  supported and persistent) and plain upstream Xen; isolated private network
  (GUI-only) plus one required CLI step (`xe vif-param-set ... promiscuous-mode`) even
  for the 2-VM case.

See the main [README](../README.md#deployment) for how TGT itself attaches to whichever
bridge/subnet/port-group these docs set up.

## Ease-of-deployment comparison

How each hypervisor stacks up for getting TGT's traffic to an analyser VM, from a
clean PoC to a real physical-switch feed.

| | Native GUI mirror | Physical switch (SPAN/RSPAN/ERSPAN) | Single-host TGT + analyser PoC | Multi-host TGT + analyser | Config persistence |
|---|---|---|---|---|---|
| **VMware vSphere (vDS)** | Yes — full GUI, incl. built-in ERSPAN mode | Easiest: Remote Mirroring Source/Destination & ERSPAN are GUI dropdowns | Easiest: native mirror session or promiscuous port group, both pure GUI | Easiest: a vDS is inherently cluster-wide, identical steps | Fully persistent, vCenter-managed |
| **Proxmox VE** | No | Manual: dedicate a physical NIC + switch-side `monitor session`, no native ERSPAN handling | Easy: isolated bridge is GUI-only for exactly 2 VMs | Needs a matching bridge/VLAN + physical trunk between hosts; `ovs-vsctl` mirror (CLI) if >2 devices | Hookscript/OVS mirror config needs manual re-apply on boot |
| **Xen (XenServer/XCP-ng)** | No | Straightforward: OVS mirror or ERSPAN via `ovs-vsctl`/switch config, PCI passthrough is mature | Needs one CLI step even for 2 VMs (VIF `promiscuous-mode`); network creation itself is GUI | Same CLI mirror approach extends cleanly; XO can overlay private networks across hosts | Persists across reboots — dom0 state isn't wiped like AHV |
| **Nutanix AHV** | No | Best done via ERSPAN (native switch-side encapsulation, lands on an ordinary routed subnet) — sidesteps AHV's OVS gap entirely | Easy for exactly TGT + 1 analyser (isolated-subnet flood trick), fully GUI | Fragile: depends on flood behavior holding across every host and the physical fabric between them, unless using ERSPAN | Manual OVS mirror config is explicitly **unsupported and non-persistent** — don't rely on it |

**Overall ease ranking: VMware > Proxmox > Xen > Nutanix.** VMware wins outright on
licensed vDS. Proxmox edges out Xen because its 2-VM case needs zero CLI at all, where
Xen needs one `xe` command even for the trivial case — but Xen edges out Nutanix
because that CLI step (and real OVS mirrors beyond it) is fully supported, persistent
host configuration, not something reverted on the next reboot or upgrade. Nutanix is
the hardest to get genuine SPAN behavior out of natively, which is why ERSPAN
offloaded to the physical switch is the recommended path there rather than fighting
AHV's OVS.
