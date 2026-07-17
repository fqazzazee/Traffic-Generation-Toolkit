#!/bin/sh
# Auto-create the tgt0 <-> tgt0-mon veth pair when the container has the
# capabilities to do so, then hand off to the tgt CLI. Safe to run repeatedly.
set -e

IFACE="${TGT_IFACE:-tgt0}"

if command -v ip >/dev/null 2>&1; then
    if ! ip link show "$IFACE" >/dev/null 2>&1; then
        if ip link add "$IFACE" type veth peer name "${IFACE}-mon" 2>/dev/null; then
            ip link set "$IFACE" up
            ip link set "${IFACE}-mon" up
            echo "[entrypoint] created veth pair ${IFACE} <-> ${IFACE}-mon"
        else
            echo "[entrypoint] could not create ${IFACE} (need --cap-add=NET_ADMIN);"
            echo "[entrypoint] falling back to pcap-only usage."
        fi
    fi
fi

exec python3 -m tgt "$@"
