#!/bin/sh
# Create the SPAN-simulation veth pair for TGT.
#   sudo ./scripts/setup-veth.sh [iface]     # default: tgt0
# Generate traffic on <iface>; point your sensor/capture at <iface>-mon.
set -e

IFACE="${1:-tgt0}"
PEER="${IFACE}-mon"

if ! command -v ip >/dev/null 2>&1; then
    echo "error: 'ip' (iproute2) not found. Install it:  apt-get install -y iproute2" >&2
    exit 1
fi

if ip link show "$IFACE" >/dev/null 2>&1; then
    echo "$IFACE already exists — nothing to do."
    exit 0
fi

ip link add "$IFACE" type veth peer name "$PEER"
ip link set "$IFACE" up
ip link set "$PEER" up

echo "created veth pair:  $IFACE  <-->  $PEER"
echo
echo "  generate:  sudo python3 -m tgt run -s ot-baseline -i $IFACE --rate 50"
echo "  capture :  sudo tcpdump -i $PEER      (or point Claroty CTD at $PEER)"
echo "  cleanup :  sudo ip link del $IFACE"
