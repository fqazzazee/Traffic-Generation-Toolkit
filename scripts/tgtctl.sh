#!/bin/sh
# tgtctl — install dependencies and manage TGT as a background service.
#
#   ./scripts/tgtctl.sh install      install system deps (+ optional `tgt` cmd)
#   ./scripts/tgtctl.sh register     install & enable the service
#   ./scripts/tgtctl.sh start        start the service
#   ./scripts/tgtctl.sh stop         stop the service
#   ./scripts/tgtctl.sh restart      restart the service
#   ./scripts/tgtctl.sh status       show service status
#   ./scripts/tgtctl.sh logs         follow service logs
#   ./scripts/tgtctl.sh unregister   stop, disable and remove the service
#   ./scripts/tgtctl.sh config       print the config file path (+ create it)
#
# Uses systemd when available; otherwise falls back to a PID-file daemon
# (works on WSL without systemd and inside plain containers).
set -eu

# --- paths ------------------------------------------------------------------
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(dirname "$SCRIPT_DIR")
CONF_DIR="/etc/tgt"
CONF_FILE="${CONF_DIR}/tgt.conf"
UNIT_FILE="/etc/systemd/system/tgt.service"
# Fallback (no-systemd) runtime files:
PID_FILE="/run/tgt.pid"
LOG_FILE="/var/log/tgt.log"
[ -w /run ] 2>/dev/null || PID_FILE="/tmp/tgt.pid"
[ -w /var/log ] 2>/dev/null || LOG_FILE="/tmp/tgt.log"

PY=$(command -v python3 || command -v python || echo python3)

# --- pretty output ----------------------------------------------------------
if [ -t 1 ]; then B='\033[1m'; G='\033[32m'; Y='\033[33m'; R='\033[31m'; N='\033[0m'
else B=''; G=''; Y=''; R=''; N=''; fi
info() { printf "${B}»${N} %s\n" "$*"; }
ok()   { printf "${G}✓${N} %s\n" "$*"; }
warn() { printf "${Y}!${N} %s\n" "$*"; }
die()  { printf "${R}✗ %s${N}\n" "$*" >&2; exit 1; }

need_root() {
    if [ "$(id -u)" -ne 0 ]; then
        die "this command needs root — re-run with: sudo $0 $CMD"
    fi
}

have_systemd() {
    command -v systemctl >/dev/null 2>&1 && \
        [ -d /run/systemd/system ] 2>/dev/null
}

# Verify the tgt package is importable from REPO_ROOT before we register/start,
# so a wrong path or incomplete checkout fails loudly instead of crash-looping.
preflight_check() {
    if [ ! -f "$REPO_ROOT/tgt/__main__.py" ]; then
        die "tgt package not found at $REPO_ROOT/tgt — run tgtctl.sh from the cloned repo (…/Traffic-Generation-Toolkit/scripts/tgtctl.sh)"
    fi
    if ! PYTHONPATH="$REPO_ROOT" "$PY" -c "import tgt" >/dev/null 2>&1; then
        die "python at '$PY' cannot import tgt from $REPO_ROOT — check the Python version (needs 3.9+) and repo path"
    fi
}

# --- dependency install -----------------------------------------------------
detect_pm() {
    for pm in apt-get dnf yum apk pacman zypper; do
        command -v "$pm" >/dev/null 2>&1 && { echo "$pm"; return; }
    done
    echo ""
}

install_deps() {
    need_root
    pm=$(detect_pm)
    [ -n "$pm" ] || die "no supported package manager found (apt/dnf/apk/pacman/zypper)"
    info "installing dependencies with $pm ..."
    case "$pm" in
        apt-get) apt-get update -qq
                 apt-get install -y python3 iproute2 tcpdump ;;
        dnf|yum) "$pm" install -y python3 iproute tcpdump ;;
        apk)     apk add --no-cache python3 iproute2 tcpdump ;;
        pacman)  pacman -Sy --noconfirm python iproute2 tcpdump ;;
        zypper)  zypper install -y python3 iproute2 tcpdump ;;
    esac
    ok "system dependencies installed"

    # Optional: install the `tgt` command onto PATH (pure-stdlib, no build deps).
    if command -v pip3 >/dev/null 2>&1; then
        info "installing the 'tgt' command (pip install -e) ..."
        pip3 install -e "$REPO_ROOT" 2>/dev/null && ok "'tgt' command available" \
            || warn "pip install skipped — use '$PY -m tgt' instead"
    else
        warn "pip3 not found — run TGT with: $PY -m tgt"
    fi
    "$PY" -m tests.selftest >/dev/null 2>&1 \
        && ok "self-test passed — packet builders verified" \
        || warn "self-test could not run (check $PY and repo path)"
}

# --- config -----------------------------------------------------------------
write_default_config() {
    [ -f "$CONF_FILE" ] && return 0
    mkdir -p "$CONF_DIR"
    cat > "$CONF_FILE" <<'EOF'
# TGT service configuration — sourced by the systemd unit / daemon.
# Edit, then: sudo ./scripts/tgtctl.sh restart

# Virtual interface to generate on. A veth pair <IFACE> <-> <IFACE>-mon is
# created automatically; point your sensor (Zeek/Suricata/tcpdump, or Claroty CTD) at -mon.
TGT_IFACE=tgt0

# Arguments passed to `tgt run`. The service keeps looping until stopped.
# Examples:
#   --scenario ot-baseline --rate 50
#   --profile modbus,s7comm,enip --rate 100 --messages 10
TGT_RUN_ARGS="--scenario ot-baseline --rate 50"
EOF
    ok "wrote default config: $CONF_FILE"
}

# --- veth helper ------------------------------------------------------------
ensure_veth() {
    iface="$1"
    command -v ip >/dev/null 2>&1 || { warn "'ip' not found; skipping veth setup"; return 0; }
    if ip link show "$iface" >/dev/null 2>&1; then return 0; fi
    ip link add "$iface" type veth peer name "${iface}-mon"
    ip link set "$iface" up
    ip link set "${iface}-mon" up
    info "created veth pair: $iface <-> ${iface}-mon"
}

# --- systemd path -----------------------------------------------------------
write_unit() {
    cat > "$UNIT_FILE" <<EOF
[Unit]
Description=TGT — Traffic Generation Toolkit (SPAN test traffic)
Documentation=file://$REPO_ROOT/README.md
After=network.target

[Service]
Type=simple
EnvironmentFile=$CONF_FILE
Environment=PYTHONPATH=$REPO_ROOT
WorkingDirectory=$REPO_ROOT
# Create the veth pair before generating (idempotent).
ExecStartPre=/bin/sh -c 'ip link show "\$TGT_IFACE" >/dev/null 2>&1 || { ip link add "\$TGT_IFACE" type veth peer name "\$TGT_IFACE-mon" && ip link set "\$TGT_IFACE" up && ip link set "\$TGT_IFACE-mon" up; }'
# Self-contained: cd into the repo and set PYTHONPATH inline so the tgt package
# resolves even if the WorkingDirectory/Environment directives above are ignored.
ExecStart=/bin/sh -c 'cd "$REPO_ROOT" && PYTHONPATH="$REPO_ROOT" exec $PY -m tgt run --iface "\$TGT_IFACE" \$TGT_RUN_ARGS'
Restart=on-failure
RestartSec=3
# Least privilege: only the caps raw packet I/O actually needs.
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF
    ok "wrote systemd unit: $UNIT_FILE"
}

# --- daemon fallback (no systemd) ------------------------------------------
daemon_running() {
    [ -f "$PID_FILE" ] || return 1
    pid=$(cat "$PID_FILE" 2>/dev/null || echo "")
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

daemon_start() {
    daemon_running && { warn "already running (pid $(cat "$PID_FILE"))"; return 0; }
    preflight_check
    # shellcheck disable=SC1090
    . "$CONF_FILE"
    ensure_veth "${TGT_IFACE:-tgt0}"
    info "starting TGT daemon (logs: $LOG_FILE)"
    PYTHONPATH="$REPO_ROOT" nohup "$PY" -m tgt run \
        --iface "${TGT_IFACE:-tgt0}" ${TGT_RUN_ARGS:-} \
        >>"$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"
    sleep 1
    daemon_running && ok "started (pid $(cat "$PID_FILE"))" \
        || die "failed to start — see $LOG_FILE"
}

daemon_stop() {
    if daemon_running; then
        pid=$(cat "$PID_FILE")
        kill "$pid" 2>/dev/null || true
        for _ in 1 2 3 4 5; do daemon_running || break; sleep 0.5; done
        daemon_running && kill -9 "$pid" 2>/dev/null || true
        ok "stopped"
    else
        warn "not running"
    fi
    rm -f "$PID_FILE"
}

# --- commands ---------------------------------------------------------------
cmd_register() {
    need_root
    preflight_check
    write_default_config
    if have_systemd; then
        write_unit
        systemctl daemon-reload
        systemctl enable tgt.service >/dev/null 2>&1 || true
        ok "service registered — start it with: sudo $0 start"
    else
        warn "systemd not available — using PID-file daemon mode"
        ok "registered (daemon mode) — start it with: sudo $0 start"
    fi
    info "edit config at $CONF_FILE to change protocols/rate"
}

cmd_start() {
    need_root
    [ -f "$CONF_FILE" ] || cmd_register
    if have_systemd && [ -f "$UNIT_FILE" ]; then
        systemctl start tgt.service && ok "service started"
    else
        daemon_start
    fi
}

cmd_stop() {
    need_root
    if have_systemd && [ -f "$UNIT_FILE" ]; then
        systemctl stop tgt.service && ok "service stopped"
    else
        daemon_stop
    fi
}

cmd_restart() {
    need_root
    if have_systemd && [ -f "$UNIT_FILE" ]; then
        systemctl restart tgt.service && ok "service restarted"
    else
        daemon_stop; daemon_start
    fi
}

cmd_status() {
    if have_systemd && [ -f "$UNIT_FILE" ]; then
        systemctl status tgt.service --no-pager || true
    else
        if daemon_running; then
            ok "running (pid $(cat "$PID_FILE"))"
            [ -f "$LOG_FILE" ] && tail -n 5 "$LOG_FILE"
        else
            warn "not running"
        fi
    fi
}

cmd_logs() {
    if have_systemd && [ -f "$UNIT_FILE" ]; then
        journalctl -u tgt.service -f --no-pager
    else
        [ -f "$LOG_FILE" ] || die "no log file at $LOG_FILE"
        tail -n 50 -f "$LOG_FILE"
    fi
}

cmd_unregister() {
    need_root
    if have_systemd && [ -f "$UNIT_FILE" ]; then
        systemctl stop tgt.service 2>/dev/null || true
        systemctl disable tgt.service 2>/dev/null || true
        rm -f "$UNIT_FILE"
        systemctl daemon-reload
        ok "systemd service removed"
    else
        daemon_stop
        ok "daemon stopped"
    fi
    # shellcheck disable=SC1090
    [ -f "$CONF_FILE" ] && . "$CONF_FILE" 2>/dev/null || true
    iface="${TGT_IFACE:-tgt0}"
    if command -v ip >/dev/null 2>&1 && ip link show "$iface" >/dev/null 2>&1; then
        ip link del "$iface" 2>/dev/null && info "removed veth $iface" || true
    fi
    warn "config kept at $CONF_FILE (delete manually if desired)"
}

cmd_config() {
    need_root
    write_default_config
    echo "$CONF_FILE"
}

usage() {
    awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1 {exit}' "$0"
}

CMD="${1:-}"
case "$CMD" in
    install)    install_deps ;;
    register)   cmd_register ;;
    start)      cmd_start ;;
    stop)       cmd_stop ;;
    restart)    cmd_restart ;;
    status)     cmd_status ;;
    logs)       cmd_logs ;;
    unregister) cmd_unregister ;;
    config)     cmd_config ;;
    ""|-h|--help|help) usage ;;
    *) die "unknown command: $CMD  (try: $0 help)" ;;
esac
