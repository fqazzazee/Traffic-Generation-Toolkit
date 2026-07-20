# Nutanix AHV — SPAN / mirror feed setup

Goal: get every frame TGT sends visible to an analyser VM (Claroty CTD, Zeek,
Suricata, Security Onion, …) on Nutanix AHV, using supported tools wherever possible.

**Read this first:** unlike VMware's vSphere Distributed Switch, **AHV has no built-in
port-mirroring feature in Prism** (Prism Element or Prism Central). Nutanix's virtual
switch is Open vSwitch under the hood, and OVS itself supports mirroring — but Nutanix
does not expose it through any supported UI or CLI, and manually running `ovs-vsctl`
mirror commands over SSH on an AHV host is an **unsupported host customization**: it is
not persisted across host reboots, AHV upgrades, or LCM operations, and Nutanix's own
AHV networking guidance is that all network configuration should go through
Prism/`acli`, not direct host CLI. Design around that constraint rather than fighting it.

## Official documentation

- **Nutanix Support Portal** (`portal.nutanix.com`) → AOS / AHV documentation →
  "AHV Networking" / "Prism Central Guide → Network → Virtual Switch". Search the
  portal for "AHV Networking" and "Virtual Switch management" — these are the
  canonical references for subnets, VLANs, and uplink/bond configuration.
- Search the Support Portal / Nutanix KB base for "unsupported OVS configuration
  changes" to confirm the current wording on manual host-network customization before
  you rely on any CLI step below.

> The exact KB article numbers and doc URLs change between AOS releases and portal
> reorganizations — search by the terms above from the portal's own search box rather
> than trusting a deep link that may have moved.

## Single AHV host — GUI steps

1. **Prism Central/Element → Network & Security → Subnets → Create Subnet.**
   Type: VLAN. Give it a VLAN ID that is *not* trunked on any physical uplink (i.e.
   don't add it to your normal production trunk) — this keeps it host-local and
   isolated, the AHV equivalent of a Proxmox bridge with `bridge-ports none`.
2. **Attach both VMs' NICs to this subnet:** VM → *Update* → Network Adapters → add/edit
   NIC → select the new subnet. Do this for the TGT VM and the CTD (or other analyser)
   VM.
3. **Nothing else on this subnet.** With only two ports on the segment, any frame TGT
   sends to a simulated/synthetic destination MAC is "unknown unicast" to the switch —
   standard switch behavior floods unknown-unicast to every other port, which is only
   CTD's. This gets you SPAN-equivalent visibility with zero OVS customization. The
   moment you add a third VM (a real gateway, a responding host) its MAC gets learned
   and traffic addressed to it stops flooding to CTD.
4. **Set the analyser NIC to promiscuous mode inside the guest OS** — this is a
   guest-level setting, not a Prism one, e.g. `ip link set eth1 up promisc on` on Linux,
   or CTD's own capture-interface configuration. There's no GUI toggle for this in
   Prism because it isn't a hypervisor-level setting.
5. If **Nutanix Flow** (microsegmentation) is licensed and enabled on the cluster,
   exclude this subnet from policy enforcement — Flow policies can silently drop
   traffic independent of any mirroring config.

## Multi-host, VM-to-VM only (same cluster, no physical SPAN)

1. Create the same Subnet as above — it's a cluster-wide construct on the Virtual
   Switch (`vs0` by default since AOS 6.x), so it already exists identically on every
   host once created in Prism Central.
2. **Physical requirement, GUI won't save you here:** the ToR switch ports connecting
   each Nutanix node's uplinks must trunk (802.1Q) that VLAN. Nutanix's OVS will happily
   tag and pass it; if the physical switch between the two hosts doesn't allow the
   VLAN, inter-host traffic on it silently disappears. Verify with
   *Prism → Hardware → Diagram* for uplink status, and check the physical switch config
   directly (see the Proxmox/Cisco note in `Proxmox.md` and the VMware ERSPAN section
   in `VMware.md` for the switch-side commands).
3. The "only two real endpoints" flooding trick still holds, but now depends on every
   switch in the path (both hosts' OVS *and* the physical fabric between them) flooding
   unknown-unicast, and on nothing else living on that VLAN anywhere in the cluster.
   Fine for a controlled PoC; treat it as fragile beyond that.

## When the GUI/virtual-switch approach isn't enough: real mirroring via the physical switch

For a production-realistic PoC (the CTD deployment pattern actually used in the field),
don't try to make AHV's OVS do the mirroring at all — mirror at the physical switch and
land the feed on a normal Nutanix subnet or a passthrough NIC:

- **NIC passthrough:** dedicate a physical NIC on the AHV host running CTD to PCI
  passthrough into the CTD VM, and cable that NIC to the physical switch's SPAN
  destination port. Check the Nutanix Hardware Compatibility List for your AOS
  version/model before committing to this — passthrough support is narrower than GPU
  passthrough and varies by platform.
- **ERSPAN (recommended):** have the physical switch GRE-encapsulate the mirrored
  traffic and route it to the CTD VM's IP over a normal, ordinary Subnet — no passthrough,
  no special trunking between hosts required, since it's just routed IP traffic. Claroty
  CTD (like most OT/NDR sensors) supports ingesting ERSPAN natively; check your CTD
  version's supported ingestion methods in Claroty's own product documentation to
  confirm. See `VMware.md` and `Proxmox.md` for the switch-side `monitor session`
  commands — they're identical regardless of which hypervisor the destination VM runs on.

## Community tips

These are not Nutanix-official guidance — sanity-check them against current portal
docs before relying on them, but they reflect what practitioners have actually hit:

- Nutanix community forum (Nutanix NEXT / community.nutanix.com) threads on AHV
  networking repeatedly note that manual `allssh "ovs-vsctl ..."` mirror commands get
  reverted on the next AHV host reboot or one-click AOS/AHV upgrade — don't build a
  PoC around a config that disappears on the next patch cycle.
- Several posts recommend validating uplink/VLAN trunking with
  `manage_ovs show_uplinks` and `ovs-vsctl show` (read-only, safe to run over SSH) when
  traffic isn't arriving as expected, before assuming the Prism-side subnet config is
  wrong — the physical trunk is the most common miss.
- r/nutanix and community threads on deploying NDR/IDS sensors (Darktrace, Corelight,
  Claroty, Nozomi) on AHV consistently land on the same conclusion documented above:
  ERSPAN into a normal subnet is the path of least resistance, because it avoids
  depending on AHV's unsupported OVS mirroring entirely.

## Verify

From the CTD/analyser VM:

```bash
tcpdump -i <monitor-nic> -n
```

Confirm you see TGT's traffic (or the ERSPAN GRE stream decapsulating cleanly) before
pointing CTD's real detection engine at the interface.
