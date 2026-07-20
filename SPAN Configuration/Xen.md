# Xen-family hypervisors — SPAN / mirror feed setup

Covers **XenServer / Citrix Hypervisor and XCP-ng** (the managed, OVS-backed Xen
distributions with a real GUI stack — XenCenter or Xen Orchestra), and **plain
upstream Xen** (dom0 + `xl`, no vendor management layer at all).

**Read this first:** like Proxmox and Nutanix, none of the Xen-family management UIs
(XenCenter, Xen Orchestra) expose a native port-mirroring feature — there's no
dropdown that does what vSphere's vDS Port Mirroring does. Unlike Nutanix AHV,
**dom0/host CLI is the normal, fully supported way to administer XenServer/XCP-ng
networking** — you're not fighting an unsupported-customization boundary the way you
are on AHV. But that does **not** mean mirror sessions themselves survive
reboots/restarts for free (an earlier draft of this doc claimed they did — that was
wrong). The actual, confirmed problem: VIF backend names (`vifX.Y`) are keyed to the
VM's dynamically-assigned domU ID, which is **reassigned every time the VM boots**,
so any mirror you built by hand against a specific `vifX.Y` silently stops matching
the right port after the next reboot. See Option B/tips below for how people actually
solve this.

## Official documentation

- [XenServer Product Documentation](https://docs.xenserver.com/) — current official
  docs site (Cloud Software Group), covers Networking/OVS and `xe` CLI reference for
  XenServer 8.x/9.
- **XCP-ng documentation** (`docs.xcp-ng.org`) — Network configuration chapter.
- **Xen Orchestra documentation** (`docs.xen-orchestra.com`) — network creation
  (private networks, pool-wide networks) via the XO GUI.
- [Citrix Knowledge Center CTX121729 — "How to Configure a Promiscuous Virtual
  Machine in XenServer"](https://support.citrix.com/external/article/CTX121729/how-to-configure-a-promiscuous-virtual-m.html)
  — the official procedure Option A below is based on.
- **Open vSwitch project documentation** (`docs.openvswitch.org`) — since
  XenServer/XCP-ng dom0 runs upstream OVS directly (not abstracted away the way
  Nutanix hides it), the vanilla `ovs-vsctl` mirror documentation applies as-is.
- **Xen Project wiki** (`wiki.xenproject.org`) — networking pages for `xl`/bridge or
  `xl`/OVS config, if you're on plain upstream Xen with no vendor stack.

## Single host — GUI + CLI promiscuous setup

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
4. **The CLI steps Xen needs that the others don't:** Citrix's OVS integration
   installs per-VIF flow rules that, by default, only deliver frames actually addressed
   to that VIF — setting promiscuous mode *inside the guest* alone is not sufficient.
   The official procedure (Citrix KB CTX121729) is a three-phase process, and there's
   no XenCenter/Xen Orchestra GUI equivalent for any of it:
   ```bash
   # Phase 1: physical interface (PIF) the analyser's network rides on
   xe pif-list network-name-label=<name_of_network>
   xe pif-param-set uuid=<uuid_of_pif> other-config:promiscuous="true"

   # Phase 2: the analyser VM's virtual interface (VIF)
   xe vif-list vm-name-label=<analyser_vm_name>
   xe vif-param-set uuid=<uuid_of_vif> other-config:promiscuous="true"

   # Phase 3: activate — a plug cycle is required for either flag to take effect
   xe vif-unplug uuid=<uuid_of_vif>
   xe vif-plug uuid=<uuid_of_vif>
   ```
   `vif-unplug` briefly takes the VM's network offline until `vif-plug` restores it —
   expect a short interruption. Verify with
   `xe vif-param-list uuid=<uuid_of_vif>` (look for `promiscuous: true` under
   `other-config`).
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

If you have more than TGT + one analyser on the segment, the flooding trick above
doesn't apply and you need a real mirror. dom0 CLI is fully supported for this (no
Nutanix-style unsupported-customization problem) — but as the next paragraph covers,
"supported" doesn't mean "durable," so pair this with MagicSPAN or a hookscript:

```bash
ovs-vsctl -- set Bridge xenbr0 mirrors=@m \
  -- --id=@src get Port <tgt-vif-tap> \
  -- --id=@dst get Port <analyser-vif-tap> \
  -- --id=@m create Mirror name=m0 select-dst-port=@src select-src-port=@src \
     output-port=@dst
```

**This does not reliably persist, and it's worse than the Proxmox equivalent, not
better** — an earlier draft of this doc claimed otherwise, which was wrong. The
practical problem, confirmed independently by a XenServer engineer's blog and by
XCP-ng's own community forum: the `vifX.Y` port name is only valid until the VM that
owns it shuts down — "once the VM that owns the VIFs shuts down the VIFs are
destroyed, so the correct VIF numbers must be looked up every time" a VM (not just
the host) reboots. A host reboot makes it worse still. Options, in order of
preference:
- **[MagicSPAN](https://github.com/cdalamagkas/magicspan)** — a community script
  built specifically to solve this: it takes stable VM/network *names* instead of
  volatile `vifX.Y` labels and regenerates the correct `ovs-vsctl` mirror commands
  each time, so you re-run one script instead of manually re-deriving port names.
- A boot/VM-start hookscript equivalent to the Proxmox one in `Proxmox.md`, if you'd
  rather not add a third-party script.

## Physical switch integration

Same universal Cisco-style `monitor session` pattern documented in `Nutanix.md` and
`VMware.md`:

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
activity, but reflects real, confirmed practitioner experience:

- [XCP-ng Forum — "Promiscuous mode, how?"](https://xcp-ng.org/forum/topic/2466/promiscuous-mode-how):
  the official 4-step PIF/VIF/promiscuous/unplug-replug procedure (matching Option A
  above) **did not, by itself, solve the poster's actual problem** — what worked was
  a full OVS port-mirror setup instead. The thread also confirms the mirror needed
  reconfiguring after every VM reboot due to changing VIF identifiers, and notes an
  OpenFlow plugin for Xen Orchestra was floated as a future fix for exactly this
  class of problem — worth checking whether that's shipped by the time you read this.
- [blog.rootshell.be — "XenServer & Port Mirroring"](https://blog.rootshell.be/2013/09/09/xenserver-port-mirroring/):
  the source for the confirmed non-persistence behavior cited above — a commenter on
  this post is the one who pinned down that VIFs are destroyed and recreated on every
  VM shutdown, which is *why* manually-keyed mirrors break, not just an occasional
  glitch.
- [GitHub — cdalamagkas/magicspan](https://github.com/cdalamagkas/magicspan): built
  by a practitioner specifically to work around the VIF-naming persistence problem
  documented above — a good signal that this is a widely-hit issue, not an edge case.

## Verify

```bash
tcpdump -i <vif-interface> -n
```
on the analyser VM before pointing its detection engine at the interface.

## Sources

- [XenServer Product Documentation](https://docs.xenserver.com/)
- [Citrix Knowledge Center CTX121729 — How to Configure a Promiscuous Virtual Machine in XenServer](https://support.citrix.com/external/article/CTX121729/how-to-configure-a-promiscuous-virtual-m.html)
- [XCP-ng Forum — Promiscuous mode, how?](https://xcp-ng.org/forum/topic/2466/promiscuous-mode-how)
- [blog.rootshell.be — XenServer & Port Mirroring](https://blog.rootshell.be/2013/09/09/xenserver-port-mirroring/)
- [GitHub — cdalamagkas/magicspan](https://github.com/cdalamagkas/magicspan)
