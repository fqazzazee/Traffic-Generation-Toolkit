# VMware vSphere — SPAN / mirror feed setup

Goal: get every frame TGT sends visible to an analyser VM (Claroty CTD, Zeek,
Suricata, Security Onion, …) on ESXi/vSphere. vSphere has a real, native, GUI-driven
port-mirroring feature — but only on a **vSphere Distributed Switch (vDS)**, which
requires vCenter and an **Enterprise Plus** license (a vDS is also included free if
you're already licensed for vSAN, even without Enterprise Plus). If you're on a
standard vSwitch only, there's a well-documented, still fully GUI, fallback below.

## Official documentation

Since Broadcom's acquisition of VMware, vSphere docs live on `techdocs.broadcom.com`
rather than the legacy `docs.vmware.com`/`pubs.vmware.com` — old bookmarks redirect,
but search TechDocs directly if a link below has moved to a newer version:

- [Working With Port Mirroring (vSphere 8.0)](https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/8-0/vsphere-networking/monitoring-network-packets/working-with-port-mirroring.html)
- [Create a Port Mirroring Session](https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/8-0/vsphere-networking/monitoring-network-packets/working-with-port-mirroring/create-a-port-mirroring-session.html)
- **vSphere Security Guide** (search TechDocs for it) — section on virtual switch
  **Security policies** (Promiscuous Mode, MAC Address Changes, Forged Transmits)
  covers the standard-vSwitch fallback in Option B.

## Option A — vSphere Distributed Switch Port Mirroring (recommended, fully GUI)

This is a first-class, supported vSphere feature — no CLI needed at all. The vDS
itself inherently spans every host in the cluster, but that doesn't mean every
session type is multi-host-safe (see the Distributed Port Mirroring caveat below) —
for a layout where TGT and the analyser could land on different hosts, prefer Remote
Mirroring Source/Destination or ERSPAN over plain Distributed Port Mirroring.

1. **vSphere Client → Networking → select your Distributed Switch → Configure →
   Port Mirroring → New.**
2. Choose a **session type** (exact descriptions per VMware's own docs):
   - **Distributed Port Mirroring** — "Mirror packets from a number of distributed
     ports to other distributed ports **on the same host**." Use this for TGT → CTD
     when both VMs are pinned to the same ESXi host. **Important, confirmed gotcha:**
     this session type only works while source and destination stay on the same
     host — VMware's own troubleshooting KB documents it breaking the moment either
     VM vMotions to a different host, with the fix being to switch to Encapsulated
     Remote Mirroring (L3) Source instead. If DRS could ever move TGT or CTD, don't
     use this session type for anything you need to keep working.
   - **Remote Mirroring Source** — "Mirror packets from a number of distributed ports
     to specific uplink ports on the corresponding host." Sends mirrored traffic out
     a physical uplink, VLAN-tagged, to an upstream physical switch's RSPAN session.
     Use this if the analyser sits outside vSphere entirely.
   - **Encapsulated Remote Mirroring (L3) Source** — "Mirror packets from a number of
     distributed ports to the IP addresses of a remote agent." This **is ERSPAN**:
     vSphere GRE-encapsulates the mirrored traffic and routes it to a destination IP.
     Use this if the analyser VM (or a physical appliance) is reachable only over L3,
     you want to avoid VLAN-trunking between hosts/sites, or — per the gotcha above —
     you need mirroring that survives vMotion.
   - **Remote Mirroring Destination** — "Mirror packets from a number of VLANs to
     distributed ports." The inverse of Remote Mirroring Source: ingests a physical
     switch's SPAN/RSPAN feed into a vDS port group, if the mirroring is happening
     upstream on physical switch gear instead.
3. Set **source**: the TGT VM's vNIC port (or the whole port group), direction
   ingress/egress/both.
4. Set **destination**: the CTD VM's vNIC port (Distributed Port Mirroring), or a VLAN
   ID (Remote Mirroring Source), or the CTD VM's IP address (Encapsulated Remote
   Mirroring/ERSPAN).
5. Enable the session (sessions are created disabled by default) and save.

No promiscuous mode, no guest-side changes — the vDS explicitly duplicates frames to
the destination port, it isn't relying on flooding.

## Option B — Standard vSwitch, no vDS license: promiscuous-mode fallback (still GUI)

If you don't have Enterprise Plus/vDS, there's a widely used, still entirely
GUI-driven trick often called the "poor man's SPAN": put TGT and CTD on the same
port group and flip that port group's security policy to promiscuous.

1. **Host → Configure → Networking → Virtual switches** (or **Host Client** if
   managing a standalone ESXi host directly) → create a new **port group** on an
   internal-only vSwitch (no physical uplink attached, so traffic never leaves the
   host — same isolation intent as the Nutanix/Proxmox docs in this folder).
2. Attach both VMs' NICs to this port group.
3. **Edit the port group → Security** → set **Promiscuous mode** to **Accept** (leave
   MAC Address Changes / Forged Transmits at your normal policy unless TGT needs to
   send frames from spoofed source MACs, in which case set those to Accept too).
4. That's it — no CLI. Promiscuous mode makes ESXi forward every frame on that port
   group to the promiscuous port(s), regardless of destination MAC, functioning as a
   hub for that segment.

This works per-host; if TGT and CTD land on different ESXi hosts with no vDS tying
them together, you need identical port group names/VLANs on each host **and** the
physical switch trunking that VLAN between hosts — same requirement documented for
Nutanix multi-host in `Nutanix.md`.

## When CLI is actually needed

Neither vSphere option above requires CLI for a one-off setup. CLI/PowerCLI only
comes in if you want to **automate** the configuration (e.g. standing up the same
promiscuous port group across many hosts, or scripting vDS mirror sessions as part of
a repeatable PoC):

```powershell
# PowerCLI: set a standard-vSwitch port group to promiscuous accept
Get-VirtualPortGroup -Name "span-lab" | Get-SecurityPolicy | Set-SecurityPolicy -AllowPromiscuous $true
```

```bash
# esxcli equivalent, run on the ESXi shell/SSH if you prefer CLI over PowerCLI
esxcli network vswitch standard portgroup policy security set -p span-lab --allow-promiscuous true
```

Both are officially supported VMware tools (PowerCLI, esxcli) — this isn't an
unsupported hack the way manual OVS edits are on AHV; it's just automating a setting
that's otherwise a GUI checkbox.

## Physical Cisco switch integration (Remote Mirroring Source / ERSPAN)

If you chose **Remote Mirroring Source** or **Encapsulated Remote Mirroring (L3)
Source** above, the matching Cisco-side config is a standard `monitor session`:

```
! RSPAN-style, VLAN carried to the vSphere uplink
monitor session 1 source interface Gi1/0/1
monitor session 1 destination remote vlan 900

! ERSPAN, routed to the CTD VM's IP directly
monitor session 1 source interface Gi1/0/1 both
monitor session 1 destination ip address 10.10.10.50
```

Same commands as referenced in `Nutanix.md` and `Proxmox.md` — the switch-side
mirroring config is independent of which hypervisor the destination VM runs on.

## Community tips

Not VMware-official guidance — cross-check against current docs, but reflects real
field experience:

- Several community posts note ERSPAN sessions add real overhead (GRE encapsulation
  processed by the vDS on every mirrored frame) — for a high-rate TGT scenario, prefer
  Distributed Port Mirroring (same-host case) over ERSPAN unless you specifically need
  the L3 reach or vMotion-safety.
- The standard-vSwitch promiscuous trick is one of the most repeated tips across
  VMware forums for lab/PoC IDS deployments predating wide vDS licensing — but multiple
  threads warn it's a "security policy exception," not a monitoring feature, so audit
  tooling may flag the port group; document why it exists.

## Verify

```bash
tcpdump -i <monitor-nic> -n
```
on the CTD/analyser VM, confirm TGT's traffic (or the decapsulated ERSPAN stream)
arrives before pointing CTD's detection engine at the interface.

## Sources

- [Broadcom TechDocs — Types of Port Mirroring Session (vSphere 9.0)](https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/9-0/vsphere-networking/monitoring-network-packets/working-with-port-mirroring/create-a-port-mirroring-session/create-a-port-mirroring-session.html) — verbatim session-type descriptions used above
- [Broadcom TechDocs — Working With Port Mirroring (vSphere 7.0)](https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/7-0/vsphere-networking/monitoring-network-packets/working-with-port-mirroring.html)
- [Broadcom Knowledge Base 418402 — "Distributed Port Mirroring not working when session type 'Distributed Port Mirroring' is used"](https://knowledge.broadcom.com/external/article/418402/distributed-port-mirroring-not-working-w.html) — confirms the same-host-only limitation and the ERSPAN/Remote Mirroring fix for vMotion
- [NAKIVO — VMware Distributed Switch Configuration](https://www.nakivo.com/blog/vmware-distributed-switch-configuration/) — Enterprise Plus / vSAN licensing requirement for vDS
