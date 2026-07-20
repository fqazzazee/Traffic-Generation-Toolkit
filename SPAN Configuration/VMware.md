# VMware vSphere — SPAN / mirror feed setup

Goal: get every frame TGT sends visible to an analyser VM (Claroty CTD, Zeek,
Suricata, Security Onion, …) on ESXi/vSphere. Unlike Nutanix AHV, **vSphere has a
real, native, GUI-driven port-mirroring feature** — but only on a **vSphere
Distributed Switch (vDS)**, which requires vCenter and an Enterprise Plus (or
equivalent vSphere+/VCF) license. If you're on a standard vSwitch only, there's a
well-documented, still fully GUI, fallback below.

## Official documentation

- **VMware vSphere Networking Guide** (`docs.vmware.com` → vSphere product docs →
  "vSphere Networking") — chapter on **Distributed Switches → Port Mirroring** covers
  every session type referenced below.
- **vSphere Security Guide** — section on virtual switch **Security policies**
  (Promiscuous Mode, MAC Address Changes, Forged Transmits) covers the standard-vSwitch
  fallback.
- Search `docs.vmware.com` directly for "port mirroring vSphere" and "promiscuous mode
  virtual switch security policy" — VMware reorganizes doc URLs across releases, so use
  the docs site's own search rather than a guessed deep link.

## Option A — vSphere Distributed Switch Port Mirroring (recommended, fully GUI)

This is a first-class, supported vSphere feature — no CLI needed at all, and it
inherently spans every host attached to the vDS, so it works identically for
single-host and multi-host layouts.

1. **vSphere Client → Networking → select your Distributed Switch → Configure →
   Port Mirroring → New.**
2. Choose a **session type**:
   - **Distributed Port Mirroring** — mirrors traffic between ports on the *same* vDS
     to another port on that vDS. This is what you want for TGT VM → CTD VM, same
     cluster.
   - **Remote Mirroring Source** — mirrors a vDS port out a physical uplink, tagged
     with a VLAN, to an upstream physical switch's RSPAN session. Use this if CTD sits
     outside vSphere entirely.
   - **Encapsulated Remote Mirroring (L3) Source** — this **is ERSPAN**: vSphere
     GRE-encapsulates the mirrored traffic and routes it to a destination IP. Use this
     if CTD's VM (or a physical appliance) is reachable only over L3, or you want to
     avoid VLAN-trunking entirely between hosts/sites.
   - **Remote Mirroring Destination** — the inverse: ingests a physical switch's SPAN/
     RSPAN feed into a vDS port group, if the mirroring is happening upstream on Cisco
     gear instead.
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

Not VMware-official guidance — cross-check against current docs, but reflects common
field experience:

- r/vmware and VMware Technology Network (communities.vmware.com) threads on this
  topic consistently flag that **Distributed Port Mirroring sessions are silently
  disabled by default** when created — people forget to flip the "Enable this
  session" toggle and then wonder why CTD sees nothing.
- Several community posts note ERSPAN sessions add real overhead (GRE encapsulation
  processed by the vDS on every mirrored frame) — for a high-rate TGT scenario, prefer
  Distributed Port Mirroring (same-vDS case) over ERSPAN unless you specifically need
  the L3 reach.
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
