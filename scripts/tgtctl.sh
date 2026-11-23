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

# The service is managed by systemd only once its unit exists. tgt/service.py
# (_use_systemd) makes the same check.
use_systemd() {
    have_systemd && [ -f "$UNIT_FILE" ]
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

# The unit runs as root with only CAP_NET_ADMIN and CAP_NET_RAW, so unlike this
# script it is bound by ordinary file permissions. Run a command the same way.
as_service() {
    setpriv --reuid=0 --regid=0 --clear-groups \
        --inh-caps=-all,+net_admin,+net_raw \
        --ambient-caps=-all,+net_admin,+net_raw \
        --bounding-set=-all,+net_admin,+net_raw "$@"
}

# Can the service do this? $1: r (read), x (enter a directory), e (execute).
# Uses real opens under setpriv, else the mode bits as root without DAC caps
# (the fallback cannot see ACLs).
service_can() {
    if [ "$SERVICE_PROBE" = setpriv ]; then
        # shellcheck disable=SC2016  # $1 expands in the inner shell
        case "$1" in
            r) as_service /bin/sh -c ': < "$1"' sh "$2" ;;
            x) as_service /bin/sh -c 'cd -- "$1"' sh "$2" ;;
            e) as_service "$2" -c '' ;;
        esac >/dev/null 2>&1
        return
    fi
    mode_info=$(stat -Lc '%u %g %a' "$2" 2>/dev/null) || return 1
    # shellcheck disable=SC2086
    set -- "$1" $mode_info
    case "$1" in r) want=4 ;; *) want=1 ;; esac
    if [ "$2" -eq 0 ]; then bits=6; elif [ "$3" -eq 0 ]; then bits=3; else bits=0; fi
    [ $(( (0$4 >> bits) & want )) -ne 0 ]
}

# Print the first component of path $2 the service cannot reach, if any.
service_blocked() {
    walked=""
    rest=${2#/}
    while [ "$rest" != "${rest#*/}" ]; do
        walked="$walked/${rest%%/*}"
        rest=${rest#*/}
        service_can x "$walked" || { printf '%s\n' "$walked"; return 0; }
    done
    service_can "$1" "$2" || printf '%s\n' "$2"
}

# Fail before systemd does when the service could not read the checkout $1,
# the config, or run the interpreter $2 (optional).
service_preflight() {
    if command -v setpriv >/dev/null 2>&1 && as_service /bin/sh -c : >/dev/null 2>&1; then
        SERVICE_PROBE=setpriv
    elif command -v stat >/dev/null 2>&1; then
        SERVICE_PROBE=stat
    else
        return 0
    fi
    blocked=$(service_blocked x "$1")
    [ -n "$blocked" ] || blocked=$(service_blocked r "$1")
    if [ -z "$blocked" ]; then
        real_root=$(readlink -f "$1" 2>/dev/null || printf '%s' "$1")
        blocked=$(service_blocked x "$real_root")
    fi
    if [ -z "$blocked" ]; then
        blocked=$(find "$1/tgt" -name __pycache__ -prune -o \
                \( -type d -o -name '*.py' -o -name '*.json' -o -name '*.toml' \) -print |
            while IFS= read -r f; do
                if [ -d "$f" ] && ! service_can x "$f"; then printf '%s\n' "$f"; break; fi
                if ! service_can r "$f"; then printf '%s\n' "$f"; break; fi
            done)
    fi
    if [ -z "$blocked" ] && [ -f "$CONF_FILE" ]; then
        blocked=$(service_blocked r "$CONF_FILE")
    fi
    if [ -z "$blocked" ] && [ -n "${2:-}" ]; then
        blocked=$(service_blocked e "$2")
    fi
    [ -z "$blocked" ] || die "the tgt service cannot access $blocked: it runs as root without CAP_DAC_OVERRIDE or CAP_DAC_READ_SEARCH, so normal file permissions apply. Move the checkout somewhere world-readable such as /opt/tgt, or grant access (a parent directory: chmod o+x; inside the checkout: chmod -R o+rX), then retry."
}

# The checkout an installed unit runs from, which may not be this one.
unit_repo_root() {
    unit_root=$(sed -n 's/^Environment=PYTHONPATH=//p' "$UNIT_FILE" | head -n 1)
    printf '%s\n' "${unit_root:-$REPO_ROOT}"
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
        if pip3 install -e "$REPO_ROOT" 2>/dev/null; then
            ok "'tgt' command available"
        else
            warn "pip install skipped — use '$PY -m tgt' instead"
        fi
    else
        warn "pip3 not found — run TGT with: $PY -m tgt"
    fi
    if "$PY" "$REPO_ROOT/tests/selftest.py" >/dev/null 2>&1; then
        ok "self-test passed — packet builders verified"
    else
        warn "self-test could not run (check $PY and repo path)"
    fi
}

# --- config -----------------------------------------------------------------
write_default_config() {
    [ -f "$CONF_FILE" ] && return 0
    mkdir -p "$CONF_DIR"
    cat > "$CONF_FILE" <<'EOF'
# TGT service configuration — sourced by the systemd unit / daemon.
# Edit, then: sudo ./scripts/tgtctl.sh restart

# Virtual interface to generate on. A veth pair <IFACE> <-> <IFACE>-mon is
# created automatically; point your sensor (Zeek/Suricata/tcpdump or your monitor) at -mon.
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

# True only for the pair ensure_veth creates: a veth whose peer is <name>-mon.
is_tgt_veth() {
    link=$(ip -o -d link show "$1" 2>/dev/null) || return 1
    case "$link" in *": $1@$1-mon:"*) ;; *) return 1 ;; esac
    case "$link" in *" veth "*) return 0 ;; *) return 1 ;; esac
}

# --- systemd path -----------------------------------------------------------
write_unit() {
    cat > "$UNIT_FILE" <<EOF
[Unit]
Description=TGT — Traffic Generation Toolkit (SPAN test traffic)
Documentation=file://$REPO_ROOT/README.md
After=network.target
# A persistent failure (e.g. the interface cannot be created) gives up after 5
# quick restarts instead of looping every few seconds forever; once fixed:
#   systemctl reset-failed tgt.service && systemctl start tgt.service
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=simple
EnvironmentFile=$CONF_FILE
Environment=PYTHONPATH=$REPO_ROOT
WorkingDirectory=$REPO_ROOT
# Create the veth pair(s) before generating (idempotent). TGT_IFACE may list
# several interfaces (a,b: the same frames to each).
ExecStartPre=/bin/sh -c '. "$CONF_FILE" && for i in \$\$(echo "\$\$TGT_IFACE" | tr , " "); do ip link show "\$\$i" >/dev/null 2>&1 || { ip link add "\$\$i" type veth peer name "\$\$i-mon" && ip link set "\$\$i" up && ip link set "\$\$i-mon" up; } || exit 1; done'
# Self-contained: cd into the repo and set PYTHONPATH inline so the tgt package
# resolves even if the WorkingDirectory/Environment directives above are ignored.
# The config is sourced by sh (its values are shell-quoted) and TGT_RUN_ARGS is
# a shell-quoted argument list, expanded with eval so quoted paths survive.
# TGT_CMD picks the subcommand: run (default) or campaign (a phased plan).
ExecStart=/bin/sh -c '. "$CONF_FILE" && cd "$REPO_ROOT" && eval "set -- \$\$TGT_RUN_ARGS" && PYTHONPATH="$REPO_ROOT" exec $PY -m tgt "\$\${TGT_CMD:-run}" --iface "\$\$TGT_IFACE" "\$\$@"'
Restart=on-failure
RestartSec=5
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
    [ -n "$pid" ] || return 1
    # EPERM means the process exists: a non-root status of a root daemon.
    kill_err=$(LC_ALL=C kill -0 "$pid" 2>&1) && return 0
    case "$kill_err" in *"not permitted"*) return 0 ;; *) return 1 ;; esac
}

# status and logs can run unprivileged, where the writability test at the top
# picks /tmp even though a root daemon used /run and /var/log. Search both.
find_daemon_files() {
    chosen=$PID_FILE
    for f in /run/tgt.pid /tmp/tgt.pid; do
        PID_FILE=$f
        if daemon_running; then chosen=$f; break; fi
    done
    PID_FILE=$chosen
    for f in /var/log/tgt.log /tmp/tgt.log; do
        [ -r "$f" ] || continue
        if [ ! -r "$LOG_FILE" ] || [ -n "$(find "$f" -newer "$LOG_FILE" 2>/dev/null)" ]; then
            LOG_FILE=$f
        fi
    done
}

daemon_start() {
    daemon_running && { warn "already running (pid $(cat "$PID_FILE"))"; return 0; }
    preflight_check
    # shellcheck disable=SC1090
    . "$CONF_FILE"
    for i in $(echo "${TGT_IFACE:-tgt0}" | tr , " "); do ensure_veth "$i"; done
    info "starting TGT daemon (logs: $LOG_FILE)"
    # TGT_RUN_ARGS is a shell-quoted argument list (the TUI writes it with
    # shlex); eval re-splits it so quoted paths with spaces stay one argument.
    eval "daemon_exec ${TGT_RUN_ARGS:-}"
    echo $! > "$PID_FILE"
    sleep 1
    if daemon_running; then
        ok "started (pid $(cat "$PID_FILE"))"
    else
        die "failed to start — see $LOG_FILE"
    fi
}

# Launch `tgt run` (or $TGT_CMD, e.g. campaign) in the background with the
# given extra arguments.
daemon_exec() {
    PYTHONPATH="$REPO_ROOT" nohup "$PY" -m tgt "${TGT_CMD:-run}" \
        --iface "${TGT_IFACE:-tgt0}" "$@" \
        >>"$LOG_FILE" 2>&1 &
}

daemon_stop() {
    if daemon_running; then
        pid=$(cat "$PID_FILE")
        kill "$pid" 2>/dev/null || true
        for _ in 1 2 3 4 5; do daemon_running || break; sleep 0.5; done
        if daemon_running; then kill -9 "$pid" 2>/dev/null || true; fi
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
        service_preflight "$REPO_ROOT" "$PY"
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
    if have_systemd && [ ! -f "$UNIT_FILE" ] && daemon_running; then
        warn "already running unmanaged (pid $(cat "$PID_FILE")); run '$0 stop', then start it under systemd"
        return 0
    fi
    if [ ! -f "$CONF_FILE" ] || { have_systemd && [ ! -f "$UNIT_FILE" ]; }; then
        cmd_register
    fi
    if use_systemd; then
        service_preflight "$(unit_repo_root)"
        systemctl start tgt.service && ok "service started"
    else
        daemon_start
    fi
}

cmd_stop() {
    need_root
    if use_systemd; then
        systemctl stop tgt.service && ok "service stopped"
    else
        daemon_stop
    fi
}

cmd_restart() {
    need_root
    if use_systemd; then
        service_preflight "$(unit_repo_root)"
        systemctl restart tgt.service && ok "service restarted"
    else
        daemon_stop; cmd_start
    fi
}

cmd_status() {
    if use_systemd; then
        systemctl status tgt.service --no-pager || true
    else
        find_daemon_files
        if daemon_running; then
            ok "running (pid $(cat "$PID_FILE"))"
            [ -f "$LOG_FILE" ] && tail -n 5 "$LOG_FILE"
        else
            warn "not running"
        fi
    fi
}

cmd_logs() {
    if use_systemd; then
        journalctl -u tgt.service -f --no-pager
    else
        find_daemon_files
        [ -f "$LOG_FILE" ] || die "no log file at $LOG_FILE"
        tail -n 50 -f "$LOG_FILE"
    fi
}

cmd_unregister() {
    need_root
    if use_systemd; then
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
    if [ -f "$CONF_FILE" ]; then . "$CONF_FILE" 2>/dev/null || true; fi
    for iface in $(echo "${TGT_IFACE:-tgt0}" | tr , " "); do
        if command -v ip >/dev/null 2>&1 && ip link show "$iface" >/dev/null 2>&1; then
            if ! is_tgt_veth "$iface"; then
                warn "leaving $iface: not a veth paired with ${iface}-mon"
            elif ip link del "$iface" 2>/dev/null; then
                info "removed veth $iface"
            fi
        fi
    done
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
