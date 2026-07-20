# Xen-family hypervisors — SPAN / mirror feed setup

Covers **XenServer / Citrix Hypervisor and XCP-ng** (the managed, OVS-backed Xen
distributions with a real GUI stack — XenCenter or Xen Orchestra), and **plain
upstream Xen** (dom0 + `xl`, no vendor management layer at all).

**Read this first:** like Proxmox and Nutanix, none of the Xen-family management UIs
(XenCenter, Xen Orchestra) expose a native port-mirroring feature — there's no
dropdown that does what vSphere's vDS Port Mirroring does. But unlike Nutanix AHV,
**dom0/host CLI is the normal, fully supported way to administer XenServer/XCP-ng
networking.** The OVS database on a XenServer/XCP-ng host is persistent host state,
not something that gets reverted on the next reboot or upgrade the way manual AHV OVS
edits are — so the CLI steps below are legitimate, durable configuration, not a
workaround you're fighting the platform to keep.

## Official documentation

- **Citrix Hypervisor / XenServer Administrator's Guide** (`docs.xenserver.com`) —
  "Networking" chapter, section on Open vSwitch and `xe vif-param-set` /
  `xe network-param-set`.
- **XCP-ng documentation** (`docs.xcp-ng.org`) — Network configuration chapter.
- **Xen Orchestra documentation** (`docs.xen-orchestra.com`) — network creation
  (private networks, pool-wide networks) via the XO GUI.
- **Open vSwitch project documentation** (`docs.openvswitch.org`) — since
  XenServer/XCP-ng dom0 runs upstream OVS directly (not abstracted away the way
  Nutanix hides it), the vanilla `ovs-vsctl` mirror documentation applies as-is.
- **Xen Project wiki** (`wiki.xenproject.org`) — networking pages for `xl`/bridge or
  `xl`/OVS config, if you're on plain upstream Xen with no vendor stack.

## Single host — GUI + one CLI step

XenCenter and Xen Orchestra can both create an isolated, host-local network entirely
through the GUI:

1. **XenCenter:** select the host/pool → *Networking* tab → *Add Network* →
   **"Single-Server Private Network"** — this creates an internal-only network with no
   physical NIC attached, the Xen equivalent of Proxmox's `bridge-ports none` or
   Nutanix's non-trunked subnet.
   **Xen Orchestra:** *Network* → *New network*, leave the physical interface unset.
2. **Attach both VMs' virtual interfaces (VIFs) to this network** — GUI: VM →
   *Networking* tab → *Add Interface* → select the private network. Do this for TGT and
   the analyser VM.
3. **Nothing else on this network.** With only two VIFs on the segment, any frame TGT
   sends to a synthetic/simulated destination MAC is unknown-unicast to the OVS bridge
   and gets flooded to the only other port — same principle as the Proxmox and Nutanix
   docs in this folder.
4. **The one CLI step Xen needs that the others don't:** Citrix's OVS integration
   installs per-VIF flow rules that, by default, only deliver frames actually addressed
   to that VIF — setting promiscuous mode *inside the guest* alone is not sufficient
   here. You also need to tell the host to trust it:
   ```bash
   xe vif-param-set uuid=<analyser-vif-uuid> other-config:promiscuous-mode=true
   ```
   There's no XenCenter/Xen Orchestra GUI toggle for this — verify the exact parameter
   name against your XenServer/XCP-ng version's docs before relying on it, since it has
   moved between "other-config" keys across releases.
5. **Verify:** point TGT at its VIF's interface inside the guest, then `tcpdump` on the
   analyser.

## Multi-host (same pool)

1. Use a pool-wide network (not a single-server private network) so the same isolated
   VLAN/network exists identically on every host — XenCenter/Xen Orchestra will show
   this as one logical network spanning the pool.
2. **Physical requirement:** the ToR switch ports connecting the pool's hosts must
   trunk that VLAN, same as the Nutanix and Proxmox multi-host cases — the vswitch
   config alone doesn't get traffic across physical uplinks that don't allow it.
3. Xen Orchestra's more advanced editions also support **private networks encrypted/
   tunneled across hosts** (an SDN-style GRE overlay independent of the physical
   switch's VLAN trunking) — worth checking if you're on XO Premium and want to avoid
   touching physical trunk config at all, though verify current XO docs since this
   feature has been repositioned across releases.
4. The "only two real endpoints" flooding trick still requires nothing else live on
   that network anywhere in the pool — same caveat as everywhere else in this folder.

## Real mirror sessions (more than two devices, or you don't want to depend on flooding)

Because dom0 CLI is fully supported here, reach for actual OVS mirrors instead of the
flooding trick as soon as you have more than TGT + one analyser on the segment:

```bash
ovs-vsctl -- --id=@p get port <analyser-vif-tap> \
  -- --id=@m create mirror name=m0 select-all=true output-port=@p \
  -- set bridge xenbr0 mirrors=@m
```

Unlike the equivalent Proxmox OVS-mirror caveat, this **does persist** across host
reboots on XenServer/XCP-ng — it's written into the same OVS database dom0 already
manages as supported state, not a hand-run command that gets wiped.

## Physical switch integration

Same universal `monitor session` pattern as the Cisco/Aruba examples in
`Nutanix.md` and `VMware.md`:

```
monitor session 1 source interface Gi1/0/1
monitor session 1 destination interface Gi1/0/24        ! local SPAN
monitor session 1 destination remote vlan 900           ! RSPAN
monitor session 1 destination ip address 10.10.10.50     ! ERSPAN
```

For SPAN/RSPAN, dedicate a physical NIC on the Xen host to a network with that uplink
attached, and put the analyser's VIF on it. For ERSPAN, land the GRE stream on the
analyser's ordinary routed IP — no special VLAN or trunking needed. PCI passthrough is
also a mature, well-supported option on XenServer/XCP-ng (Xen pioneered PCI
passthrough for HVM guests) if you'd rather hand the analyser VM a dedicated physical
NIC cabled straight to a SPAN destination port.

## Community tips

Not Citrix/XCP-ng-official guidance — cross-check against current docs and forum
activity, but reflects recurring practitioner experience:

- XCP-ng forum (`xcp-ng.org/forum`) and Citrix discussion boards repeatedly flag the
  `other-config:promiscuous-mode` VIF parameter as the step people forget — guest-side
  promiscuous mode alone silently captures nothing until this is set.
- Several posts on deploying virtual IPS/IDS/NDR appliances on XenServer note that
  `xe vif-list` / `xe vif-param-list uuid=<uuid>` is the fastest way to confirm the
  parameter actually took, since there's no GUI surface showing it.
- XCP-ng community threads on Xen Orchestra's private-network/SDN features note the
  overlay tunnel mode adds encapsulation overhead worth measuring before assuming it's
  free — similar caveat to the ERSPAN overhead note in `VMware.md`.

## Verify

```bash
tcpdump -i <vif-interface> -n
```
on the analyser VM before pointing its detection engine at the interface.
