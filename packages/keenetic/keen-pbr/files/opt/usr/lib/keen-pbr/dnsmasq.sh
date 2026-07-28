#!/bin/sh

set -e

KEEN_PBR_BIN="${KEEN_PBR_BIN:-/opt/usr/bin/keen-pbr}"
CONFIG_PATH="${KEEN_PBR_CONFIG_PATH:-/opt/etc/keen-pbr/config.json}"
DNSMASQ_FALLBACK_FILE="${KEEN_PBR_DNSMASQ_FALLBACK_FILE:-/opt/etc/keen-pbr/dnsmasq-fallback.conf}"
STATE_DIR="${KEEN_PBR_STATE_DIR:-/tmp/keen-pbr}"
ACTIVE_FILE="${STATE_DIR}/active"
MANAGED_CONFIG_FILE="${STATE_DIR}/dnsmasq-managed.conf"
MANAGED_CONFIG_TMP="${MANAGED_CONFIG_FILE}.$$"
MANAGED_CANDIDATE_COMPLETE="N"

cleanup_managed_config_tmp() {
    rm -f "$MANAGED_CONFIG_TMP"
}

trap cleanup_managed_config_tmp EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

log_message() {
    local level="$1"
    local message="$2"

    logger -s -t "keen-pbr" -p "user.${level}" "$message" 2>/dev/null ||
        true
}

log_info() {
    log_message info "$1"
}

log_warn() {
    log_message warn "$1"
}

fallback_conf_line() {
    printf 'conf-file=%s\n' "$DNSMASQ_FALLBACK_FILE"
}

active_conf_line() {
    "$KEEN_PBR_BIN" --config "$CONFIG_PATH" generate-resolver-config dnsmasq
}

resolver_config_has_upstream() {
    local path="$1"

    [ -s "$path" ] || return 1
    grep -q '^[[:space:]]*server=' "$path" ||
        grep -q '^[[:space:]]*conf-file=' "$path"
}

resolver_config_is_active() {
    local path="$1"

    [ -s "$path" ] || return 1
    grep -q '^# keen-pbr resolver state: active$' "$path" &&
        grep -q '^txt-record=config-hash\.keen\.pbr,' "$path" &&
        grep -q '^txt-record=resolver-state\.keen\.pbr,.*|active|runtime_active$' "$path" &&
        resolver_config_has_upstream "$path"
}

resolver_config_is_fallback() {
    local path="$1"

    [ -s "$path" ] || return 1
    grep -q '^# keen-pbr resolver state: fallback reason=' "$path" &&
        grep -q '^txt-record=resolver-state\.keen\.pbr,' "$path" &&
        resolver_config_has_upstream "$path"
}

refresh_managed_config() {
    umask 077
    mkdir -p "$STATE_DIR" || return 1
    rm -f "$MANAGED_CONFIG_TMP"
    MANAGED_CANDIDATE_COMPLETE="N"

    if active_conf_line > "$MANAGED_CONFIG_TMP"; then
        MANAGED_CANDIDATE_COMPLETE="Y"
        if resolver_config_is_active "$MANAGED_CONFIG_TMP"; then
            mv -f "$MANAGED_CONFIG_TMP" "$MANAGED_CONFIG_FILE" || return 1
            return 0
        fi
    fi

    return 1
}

emit_active_config() {
    if refresh_managed_config; then
        cat "$MANAGED_CONFIG_FILE" || return 1
        log_info "Produced complete dnsmasq keen-pbr managed config"
        return 0
    fi

    if [ "$MANAGED_CANDIDATE_COMPLETE" = "Y" ] &&
        resolver_config_is_fallback "$MANAGED_CONFIG_TMP"; then
        cat "$MANAGED_CONFIG_TMP" || return 1
        log_warn "Resolver daemon supplied a complete fallback dnsmasq config"
        return 0
    fi

    if resolver_config_is_active "$MANAGED_CONFIG_FILE"; then
        cat "$MANAGED_CONFIG_FILE" || return 1
        log_warn "Resolver stream failed; reusing last complete dnsmasq config"
        return 0
    fi

    fallback_conf_line
    log_warn "Resolver stream failed without a last-known-good config; using dnsmasq fallback"
}

is_active() {
    [ -r "$ACTIVE_FILE" ] || return 1

    active_state="$(tr -d '[:space:]' < "$ACTIVE_FILE" 2>/dev/null || true)"
    [ "$active_state" = "Y" ]
}

set_active_state() {
    mkdir -p "$STATE_DIR"
    printf '%s\n' "$1" > "$ACTIVE_FILE"
}

emit_dnsmasq_config_entry() {
    # Store a bounded, tmpfs-backed DNS observation stream. The connections
    # page uses it to show best-effort domain names next to exact destination
    # IP addresses; no query history is written to persistent storage.
    printf 'log-queries=extra\n'
    printf 'log-facility=/tmp/dnsmasq-keen-pbr-queries.log\n'
    if is_active; then
        emit_active_config
    else
        fallback_conf_line
        log_info "Produced dnsmasq fallback config entry"
    fi
}

activate_dnsmasq() {
    set_active_state "Y"
    log_info "Marked keen-pbr dnsmasq state as active"
    restart_dnsmasq
}

deactivate_dnsmasq() {
    set_active_state "N"
    log_info "Marked keen-pbr dnsmasq state as inactive"
    restart_dnsmasq
}

# Returns the PID of the running dnsmasq, preferring the real process over the
# PID file: on Keenetic the file routinely goes stale, and then the init script
# reports "already running" while refusing to stop anything. dnsmasq only
# re-reads conf-script output on a genuine restart, so a restart that silently
# does nothing leaves keen-pbr's rules out of the resolver entirely.
dnsmasq_pid() {
    pid="$(pgrep -x dnsmasq 2>/dev/null | head -n 1)"
    if [ -n "$pid" ]; then
        printf '%s' "$pid"
        return 0
    fi
    for candidate in /opt/var/run/dnsmasq.pid /var/run/dnsmasq.pid; do
        [ -s "$candidate" ] || continue
        pid="$(tr -d '[:space:]' < "$candidate")"
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            printf '%s' "$pid"
            return 0
        fi
    done
    return 1
}

stop_dnsmasq() {
    pid="$(dnsmasq_pid)" || return 0

    kill "$pid" 2>/dev/null || true
    waited=0
    while [ "$waited" -lt 50 ]; do
        kill -0 "$pid" 2>/dev/null || return 0
        usleep 100000 2>/dev/null || sleep 1
        waited=$((waited + 1))
    done

    log_warn "dnsmasq did not stop within 5 s, forcing"
    kill -9 "$pid" 2>/dev/null || true
    sleep 1
    dnsmasq_pid >/dev/null 2>&1 && return 1
    return 0
}

restart_dnsmasq() {
    [ -x /opt/etc/init.d/S56dnsmasq ] || return 1

    if ! stop_dnsmasq; then
        log_warn "could not stop dnsmasq; configuration will stay stale"
        return 1
    fi

    # Stale PID files make the init script refuse to start, so clear them once
    # the process is confirmed gone.
    rm -f /opt/var/run/dnsmasq.pid /var/run/dnsmasq.pid 2>/dev/null || true

    /opt/etc/init.d/S56dnsmasq start >/dev/null 2>&1 || true

    waited=0
    while [ "$waited" -lt 30 ]; do
        if dnsmasq_pid >/dev/null 2>&1; then
            log_info "dnsmasq restarted"
            return 0
        fi
        usleep 100000 2>/dev/null || sleep 1
        waited=$((waited + 1))
    done

    log_warn "dnsmasq did not come back after restart"
    return 1
}

print_help() {
    cat <<EOF
Usage: $0 <command>

Commands:
  dnsmasq-config-entry   Print the dnsmasq config entry for the current active state.
  activate               Mark keen-pbr dnsmasq state active and restart dnsmasq.
  deactivate             Mark keen-pbr dnsmasq state inactive and restart dnsmasq.
  restart-dnsmasq        Restart dnsmasq without changing helper-managed config.
  reload                 Alias for restart-dnsmasq; used by the system resolver hook.
  help                   Show this help text.
EOF
}

case "$1" in
    dnsmasq-config-entry)
        emit_dnsmasq_config_entry
        ;;
    activate)
        activate_dnsmasq
        ;;
    deactivate)
        deactivate_dnsmasq
        ;;
    restart-dnsmasq)
        restart_dnsmasq
        ;;
    reload)
        restart_dnsmasq
        ;;
    help|-h|--help)
        print_help
        ;;
    *)
        print_help >&2
        exit 1
        ;;
esac
