# Nutanix AHV — SPAN / mirror feed setup

Goal: get every frame TGT sends visible to an analyser VM (Claroty CTD, Zeek,
Suricata, Security Onion, …) on Nutanix AHV, using supported tools wherever possible.

**Correction from an earlier draft of this doc:** Nutanix *does* now ship a native,
GUI-driven **Traffic Mirroring** feature in Prism Central — this doc previously
claimed AHV had no port-mirroring feature at all, which was true for older AOS
releases but is outdated for current ones. Official docs confirm a "Creating a
Traffic Mirroring Session" / "Enabling a Traffic Mirroring Session" workflow exists
across Prism Central pc.7.3 through pc.2024.3.1, and an AHV Admin Guide "Traffic
Mirroring on AHV Hosts" chapter spanning versions v6.7 through v11.0. Nutanix's own
AOS 6.10 LTS announcement lists traffic mirroring as a capability delivered under
**Flow Network Security Next Gen / Flow Virtual Networking** — so treat it as a
Flow-licensed feature, not something guaranteed on a bare AHV cluster, and confirm
against the exact doc page for your Prism Central/AOS version (the portal requires a
support login, and content moves between releases — the links below are the doc
*titles* to search for, confirmed to exist, rather than guesses).

## Official documentation

- **Prism Central Guide → "Creating a Traffic Mirroring Session"** and
  **"Enabling a Traffic Mirroring Session"** — confirmed present for pc.7.3, pc.7.5,
  pc.2024.1, pc.2024.2, pc.2024.3, and pc.2024.3.1. Log into
  `portal.nutanix.com` and search the Prism Central Guide for your PC version.
- **AHV Admin Guide → "Traffic Mirroring on AHV Hosts"**, **"Configuring Traffic
  Mirroring on an AHV Host"**, **"Nutanix Recommendations for Traffic Mirroring"**,
  and **"Updating a Traffic Mirroring Session"** — confirmed present for AHV Admin
  Guide v6.7, v6.10, v10.0, v10.3, and v11.0.
- Nutanix blog: ["Elevate Your IT Infrastructure with Long-Term Support Release:
  Nutanix AOS 6.10"](https://www.nutanix.com/blog/elevate-your-it-infrastructure-with-long-term-support-release-nutanix-aos-6-10)
  — public, no login required; confirms traffic mirroring ships under Flow Network
  Security Next Gen / Flow Virtual Networking, and that Flow Network Security itself
  was introduced earlier (AOS 6.6, Prism Central Security Dashboard).
- All of the above require a Nutanix Support Portal login to read past the doc
  title — I could not verify the exact menu path/click sequence without one, so
  confirm the precise steps against the doc for your version before relying on the
  outline below.

## Option A — native Prism Central Traffic Mirroring (recommended if your version/license has it)

1. In **Prism Central**, find the **Traffic Mirroring** area (per the confirmed doc
   titles, this lives in the same part of Prism Central as Flow Network
   Security/Virtual Networking — check your version's nav, it has moved across
   releases) and **create a session**: select the TGT VM's NIC as the mirror source
   and the analyser (CTD) VM's NIC as the destination.
2. Sessions appear to be created and then separately **enabled** — the docs have a
   distinct "Enabling a Traffic Mirroring Session" page, the same create-then-enable
   pattern VMware's vDS uses (see `VMware.md`). Don't assume a newly created session
   is live; explicitly enable it.
3. Confirm your Prism Central edition/Flow licensing actually includes this — it's
   documented under the Flow Network Security Next Gen / Flow Virtual Networking
   umbrella, which are licensed add-ons on top of base AOS/AHV.
4. If this feature isn't available on your cluster (older AOS, Community Edition,
   no Flow license), fall back to Option B.

## Option B — isolated subnet, no native mirroring needed (works on any AOS version)

If Option A isn't available to you, you don't actually need switch-level mirroring
for a simple 2-VM PoC:

1. **Prism Central/Element → Network & Security → Subnets → Create Subnet.**
   Type: VLAN. Give it a VLAN ID that is *not* trunked on any physical uplink — this
   keeps it host-local and isolated, the AHV equivalent of a Proxmox bridge with
   `bridge-ports none`.
2. **Attach both VMs' NICs to this subnet:** VM → *Update* → Network Adapters →
   add/edit NIC → select the new subnet. Do this for TGT and the analyser VM.
3. **Nothing else on this subnet.** With only two ports on the segment, any frame TGT
   sends to a simulated/synthetic destination MAC is "unknown unicast" to the switch
   — standard switch behavior floods unknown-unicast to every other port, which is
   only the analyser's. This gets you SPAN-equivalent visibility with zero OVS
   customization. The moment you add a third VM (a real gateway, a responding host)
   its MAC gets learned and traffic addressed to it stops flooding to the analyser.
4. **Set the analyser NIC to promiscuous mode inside the guest OS** — a guest-level
   setting, e.g. `ip link set eth1 up promisc on` on Linux, or the sensor's own
   capture-interface configuration.
5. If Nutanix Flow (microsegmentation) is licensed and enabled on the cluster,
   exclude this subnet from policy enforcement — Flow security policies can silently
   drop traffic independent of any mirroring config.

## Option C — manual `ovs-vsctl` mirror (historical workaround, not recommended)

Before the native Traffic Mirroring feature existed, the community workaround was to
SSH into the AHV host and build an OVS mirror by hand. It still works mechanically,
but a Nutanix employee explicitly warned against it on the community forum, and it
has real, confirmed problems — only reach for this if Options A and B are both
unavailable:

```bash
ovs-vsctl add-br br0
ovs-vsctl add-port br0 eth0
ovs-vsctl add-port br0 tap0
ovs-vsctl add-port br0 tap1 -- --id=@p get port tap1 \
  -- --id=@m create mirror name=m0 select-all=true output-port=@p \
  -- set bridge br0 mirrors=@m
```

Confirmed problems, straight from a Nutanix employee's reply on the community forum
and independently corroborated by Mastering Nutanix's write-up:
- Not officially released or supported — "there is a feature request logged for
  this capability" was the 2018-era answer, before Option A shipped.
- **Lost after every host reboot.**
- **Disappears when the VM shuts down and restarts.**
- **Doesn't persist across live migration** — mirror config only applies on the host
  the VM happens to be running on at the time you created it.

## Multi-host, VM-to-VM only (same cluster, no physical SPAN)

1. If using Option A (Prism Central Traffic Mirroring), it's managed centrally rather
   than per-host OVS, so it's reasonable to expect it handles VMs on different hosts
   more gracefully than the manual OVS approach — but confirm this against the docs
   for your version, since I couldn't verify cross-host behavior specifically.
2. If using Option B (isolated subnet flood trick), it's a cluster-wide construct on
   the Virtual Switch (`vs0` by default since AOS 6.x), so the subnet already exists
   identically on every host once created in Prism Central. **Physical requirement,
   GUI won't save you here:** the ToR switch ports connecting each Nutanix node's
   uplinks must trunk (802.1Q) that VLAN, or inter-host traffic on it silently
   disappears. Verify with *Prism → Hardware → Diagram* for uplink status.
3. The "only two real endpoints" flooding trick (Option B) still holds multi-host,
   but now depends on every switch in the path (both hosts' OVS *and* the physical
   fabric between them) flooding unknown-unicast, and on nothing else living on that
   VLAN anywhere in the cluster. Fine for a controlled PoC; treat it as fragile beyond
   that.

## When you want the physical switch to do the mirroring instead

For a production-realistic PoC (the deployment pattern actually used for OT/NDR
sensors in the field, and a good fallback if none of the options above fit), mirror at
the physical switch and land the feed on a normal Nutanix subnet or a passthrough NIC:

- **NIC passthrough:** dedicate a physical NIC on the AHV host running the analyser
  to PCI passthrough, cabled to the physical switch's SPAN destination port. Check
  the Nutanix Hardware Compatibility List for your AOS version/model first —
  passthrough support is narrower than GPU passthrough and varies by platform.
- **ERSPAN:** have the physical switch GRE-encapsulate the mirrored traffic and route
  it to the analyser VM's IP over an ordinary Subnet — no passthrough, no special
  trunking required, since it's just routed IP traffic. Confirm your analyser's
  (e.g. Claroty CTD's) supported ingestion methods before committing to this. See
  `VMware.md` and `Proxmox.md` for the switch-side `monitor session` commands — the
  switch-side config is identical regardless of which hypervisor the destination VM
  runs on.

## Community tips

Not Nutanix-official guidance — cross-check against current docs, but reflects real
practitioner experience:

- [Mastering Nutanix — "How to configure mirror port (promiscuous mode) in Nutanix
  AHV"](https://masteringnutanix.com/2020/06/27/mirror-port-configuration-nutanix-ahv/)
  walks through the manual `ovs-vsctl` approach in Option C and states plainly:
  "Nutanix is not officially releasing Mirror Configuration, so it is not recommended
  in Nutanix AHV" — written before the native Traffic Mirroring feature existed, but
  the mechanical steps and caveats (host-only scope, no external physical-device
  sniffing) still apply if you ever fall back to it.
- [Nutanix Community — "single VM in promiscuous mode on AHV"](https://next.nutanix.com/installation-configuration-23/single-vm-in-promiscuous-mode-on-ahv-27096)
  is the actual employee reply confirming the "not officially supported... lost after
  host reboots... disappears when the VM shuts down and restarts... doesn't persist
  on migration" caveats cited in Option C above.
- Several threads recommend validating uplink/VLAN trunking with
  `manage_ovs show_uplinks` and `ovs-vsctl show` (read-only, safe to run over SSH)
  when traffic isn't arriving as expected, before assuming the Prism-side subnet
  config is wrong — the physical trunk is the most common miss.

## Verify

From the analyser VM:

```bash
tcpdump -i <monitor-nic> -n
```

Confirm you see TGT's traffic (or the ERSPAN GRE stream decapsulating cleanly) before
pointing the analyser's real detection engine at the interface.

## Sources

- [Nutanix blog — AOS 6.10 LTS release](https://www.nutanix.com/blog/elevate-your-it-infrastructure-with-long-term-support-release-nutanix-aos-6-10) — confirms traffic mirroring ships under Flow Network Security Next Gen / Flow Virtual Networking
- [Mastering Nutanix — Mirror port configuration in AHV](https://masteringnutanix.com/2020/06/27/mirror-port-configuration-nutanix-ahv/)
- [Nutanix Community — single VM in promiscuous mode on AHV](https://next.nutanix.com/installation-configuration-23/single-vm-in-promiscuous-mode-on-ahv-27096)
- [Nutanix Community — AHV network configuration via ovs-vsctl](https://next.nutanix.com/installation-configuration-23/ahv-network-configuration-ovs-vsctl-38219)
- Nutanix Support Portal doc titles confirmed to exist (login required to read): "Traffic Mirroring on AHV Hosts", "Configuring Traffic Mirroring on an AHV Host", "Nutanix Recommendations for Traffic Mirroring", "Updating a Traffic Mirroring Session" (AHV Admin Guide v6.7–v11.0); "Creating a Traffic Mirroring Session", "Enabling a Traffic Mirroring Session" (Prism Central Guide pc.7.3–pc.2024.3.1)
