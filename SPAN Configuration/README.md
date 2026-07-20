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

See the main [README](../README.md#deployment) for how TGT itself attaches to whichever
bridge/subnet/port-group these docs set up.
