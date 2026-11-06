# Deployment

Running TGT as a service, in WSL or a container, and feeding a sensor in another VM or on another machine.

[← back to the README](../README.md)

---

## Run as a service

`tgtctl.sh` is one cross-distro control script — **systemd** when present, else a
**PID-file daemon** (so it also works on WSL-without-systemd and in containers).

| Command | Does |
|---|---|
| `install` | system deps (apt/dnf/apk/pacman/zypper) + optional `tgt` command + self-test |
| `register` | write `/etc/tgt/tgt.conf` + service unit, create the veth, enable at boot |
| `start` / `stop` / `restart` / `status` / `logs` | manage the running service |
| `unregister` | stop, disable, remove the service + veth (keeps config) |

Config — `/etc/tgt/tgt.conf` (also editable live from the TUI's Service panel):

```sh
TGT_IFACE=tgt0                  # or tgt0,tgt1: every listed veth is created, same frames to each
TGT_CMD=run                     # or campaign: TGT_RUN_ARGS then starts with the plan name
TGT_RUN_ARGS="--env industrial-site --schedule timed --manifest '/var/tmp/tgt run.json'"
```

`TGT_RUN_ARGS` is a shell-quoted argument list, so a quoted path with spaces stays one argument.
Units registered before `TGT_CMD` existed always run `tgt run` and create only one veth: run
`tgtctl.sh register` again to use campaigns or fan-out (the TUI's Service panel warns).
The systemd unit runs least-privilege (`CAP_NET_ADMIN` + `CAP_NET_RAW` only), creates the veth
in `ExecStartPre`, and stops cleanly on `systemctl stop` (SIGTERM flushes the pcap and
manifest). It restarts on failure but gives up after 5 quick failures in 2 minutes; once the
cause is fixed: `systemctl reset-failed tgt.service && systemctl start tgt.service`.

---

## Where to run it

### WSL

WSL 2 has a real Linux kernel, so veth + `AF_PACKET` work normally. Run your sensor in
the **same** distro to share the network namespace and see `tgt0-mon`. Without systemd,
`tgtctl.sh` uses daemon mode automatically — same commands.

### Podman / Docker

Run privileged (raw sockets + `ip link` need `CAP_NET_ADMIN` + `CAP_NET_RAW`):

```bash
podman build -t tgt -f Containerfile .
podman run --rm -it --cap-add=NET_ADMIN --cap-add=NET_RAW tgt \
    run -s ot-baseline -i tgt0 --rate 50          # entrypoint creates tgt0

# share a namespace so TGT + a sensor container both see the veth:
podman run -d --name sensor --cap-add=NET_RAW <sensor-image>
podman run --rm -it --network container:sensor --cap-add=NET_ADMIN --cap-add=NET_RAW \
    tgt run -s ot-baseline -i tgt0-mon --rate 50
```

TGT runs as PID 1 and handles SIGTERM itself, so `podman stop` / `docker stop` ends a run
cleanly with the pcap and manifest flushed. `--init` is optional (it adds a zombie-reaping
init in front).

### Sensor on another machine or VM

A veth pair lives inside one kernel, so a sensor in a separate VM or on another machine
can't open `tgt0-mon`. Send on a **real interface** instead (`-i eth0`, or pick it in the
TUI's Interfaces tab) and let something in between copy the traffic to the sensor:

| Setup | How the sensor gets the traffic |
|---|---|
| TGT and the sensor are VMs on one hypervisor | The hypervisor mirrors TGT's vNIC to the sensor's monitor vNIC: a Proxmox hub bridge (next section), or VMware / Nutanix / Xen port mirroring ([`SPAN Configuration/`](../SPAN%20Configuration/README.md)). |
| TGT on a KVM/Proxmox host, sensor in a VM | Put the veth peer on the sensor's bridge and make it a hub: `ip link set tgt0-mon master vmbrspan` and `ip link set vmbrspan type bridge ageing_time 0`. Without hub mode the bridge learns that every TGT MAC sits behind `tgt0-mon` and stops flooding frames to the sensor. |
| Physical lab switch | Send from a host on a port or VLAN the switch mirrors (a SPAN **source**) to the sensor's monitor port. |
| No mirroring available | Write a pcap (`--pcap`) and import it into the sensor, if it supports offline analysis. |

Don't transmit out of the sensor's own capture NIC. The sensor may ignore its own
outgoing frames, and a switch port configured to accept ingress on a SPAN destination
would forward TGT's synthetic OT commands and attack traffic into the real network.
Mirror traffic only on isolated segments you're authorized to test.

### TGT VM — bring the send interface up (and promiscuous if needed)

On the TGT VM, the send interface must be **UP** before TGT can transmit — `AF_PACKET`
can't send on a down link. Bring it up (no IP is needed; it's a pure transmit port):

```bash
sudo ip link set eth0 up                 # the NIC TGT sends on (-i eth0 / TGT_IFACE)
ip link show eth0                         # expect: state UP ... (and PROMISC if set below)
```

TGT builds every frame with a **synthetic source MAC** — vendor OUIs, the HSRP gateway
MAC, the veth peer, not the vNIC's own address. A hypervisor vSwitch drops those by
default because the source MAC doesn't match the one it assigned the port, so the sensor
sees nothing. Two things fix it, and you usually need both:

- **On the TGT VM**, put the send NIC in **promiscuous** mode so the guest hands all
  crafted frames to the vNIC rather than only its own-MAC traffic:

  ```bash
  sudo ip link set eth0 promisc on         # PROMISC appears in `ip link show eth0`
  sudo ip link set eth0 promisc off        # revert
  ```

- **On the hypervisor**, allow forged source MACs on the port group feeding TGT's vNIC —
  on VMware that's **Promiscuous Mode + MAC Address Changes + Forged Transmits** set to
  *Accept* ([`SPAN Configuration/VMware.md`](../SPAN%20Configuration/VMware.md)); other
  hypervisors have the equivalent. A plain Linux-bridge / Proxmox hub (below) floods
  regardless, so it needs no forged-transmit flag.

Both settings are runtime-only and reset on reboot. To make them durable, set the port
group / portgroup policy on the hypervisor, and persist the guest link state the usual
way — a systemd unit, a NetworkManager/`/etc/network/interfaces` stanza, or a `@reboot`
cron entry running the `ip link set … up promisc on` above. A **veth** send interface
(TGT's default, on the same host as the sensor) needs none of this: `iface create`
already brings both ends up, and synthetic MACs flood freely across a local veth/bridge.

### Proxmox — feed a Traffic Analyser VM (hub bridge)

Typical lab: **TGT in one VM, the analyser** (Zeek, Suricata, Security Onion, Malcolm, a
commercial OT monitor, …) **in another, on the same host.** Put both VMs on an isolated Linux
bridge run as a **hub** — no MAC learning, so every frame floods to the analyser, just
like a SPAN feed.

The `/etc/network/interfaces` file creates the bridge; the VM `tap` ports are created
dynamically at VM start, so a small hookscript sets the hub flag after each VM boots.

**1. Create the isolated bridge** (GUI: *node → System → Network → Create → Linux
Bridge*, or edit the file directly), then `ifreload -a`:

```
# /etc/network/interfaces
auto vmbrspan
iface vmbrspan inet manual
    bridge-ports none
    bridge-stp off
    bridge-fd 0
```

`bridge-ports none` keeps it isolated (no uplink → traffic never leaves the host);
`inet manual` gives it no IP — a pure L2 SPAN segment.

**2. Make it a hub** with a Proxmox hookscript. Create `/var/lib/vz/snippets/spanhub.sh`:

```bash
#!/bin/bash
# After a VM starts, make its SPAN bridge a hub (no learning => floods all ports).
[ "$2" = "post-start" ] || exit 0
for p in $(ls /sys/class/net/vmbrspan/brif 2>/dev/null); do
    bridge link set dev "$p" learning off flood on mcast_flood on
done
```

Make it executable and attach it to **both** VMs (whichever boots last re-flips every
port); it re-applies on every start, so it survives reboots:

```bash
chmod +x /var/lib/vz/snippets/spanhub.sh
qm set <TGT_VMID>      --hookscript local:snippets/spanhub.sh
qm set <ANALYSER_VMID> --hookscript local:snippets/spanhub.sh
```

**3. Attach both VMs' NICs** to `vmbrspan` (*VM → Hardware → Network Device*, **firewall
unchecked**). The analyser's NIC must be **promiscuous** (`ip link set eth0 up promisc
on`); most sensors set this themselves.

**4. Generate and verify** — point TGT at its bridge NIC (`TGT_IFACE=eth0` in
`/etc/tgt/tgt.conf`, or `-i eth0` on the CLI, or the TUI's **Interfaces** panel), then confirm
on the analyser with `tcpdump -i <nic>` that the traffic arrives.

> Not using a hookscript? Just run the `for p in … bridge link set …` loop by hand
> once after starting the VMs. Verify with `bridge -d link show | grep -A1 vmbrspan` —
> each port should read `learning off flood on`.

> Full GUI-first walkthroughs (official docs + community tips + CLI fallbacks) for
> Proxmox, Nutanix AHV, and VMware vSphere are in
> [`SPAN Configuration/`](../SPAN%20Configuration/).
