#!/bin/sh

set -e

KEEN_PBR_BIN="${KEEN_PBR_BIN:-/opt/usr/bin/keen-pbr}"
CONFIG_PATH="${KEEN_PBR_CONFIG_PATH:-/opt/etc/keen-pbr/config.json}"
DNSMASQ_FALLBACK_FILE="${KEEN_PBR_DNSMASQ_FALLBACK_FILE:-/opt/etc/keen-pbr/dnsmasq-fallback.conf}"
FALLBACK_TMP="${DNSMASQ_FALLBACK_FILE}.$$"
STATE_DIR="${KEEN_PBR_STATE_DIR:-/tmp/keen-pbr}"
ACTIVE_FILE="${STATE_DIR}/active"
MANAGED_CONFIG_FILE="${STATE_DIR}/dnsmasq-managed.conf"
MANAGED_CONFIG_TMP="${MANAGED_CONFIG_FILE}.$$"
ATTEMPT_FILE="${STATE_DIR}/resolver-attempt-id"
ATTEMPT_TMP="${ATTEMPT_FILE}.$$"
ATTEMPT_ACCEPTED_FILE="${STATE_DIR}/resolver-attempt-accepted"
ATTEMPT_ACCEPTED_TMP="${ATTEMPT_ACCEPTED_FILE}.$$"
MANAGED_CANDIDATE_COMPLETE="N"
ACTIVE_ATTEMPT_ID=""

cleanup_managed_config_tmp() {
    rm -f "$MANAGED_CONFIG_TMP" "$ATTEMPT_TMP" "$ATTEMPT_ACCEPTED_TMP" "$FALLBACK_TMP"
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

fallback_is_automatic() {
    [ -e "$DNSMASQ_FALLBACK_FILE" ] || return 0
    # A custom conffile is never rewritten. Migrate only the exact previous
    # packaged default (CRLF is equivalent), or our explicitly marked output.
    local current first_line
    first_line="$(head -n 1 "$DNSMASQ_FALLBACK_FILE" | tr -d '\r')" || return 1
    [ "$first_line" = '# keen-pbr automatic direct DNS fallback v1' ] && return 0
    current="$(tr -d '\r' < "$DNSMASQ_FALLBACK_FILE")" || return 1
    [ "$current" = '# Fallback upstream DNS servers for dnsmasq.
# This file is used when keen-pbr is disabled, stopped, or otherwise not active.
# Configure the same fallback resolvers here that you want dnsmasq to use without keen-pbr.

server=8.8.8.8
server=8.8.4.4' ]
}

update_direct_fallback() {
    is_active || return 0
    fallback_is_automatic || return 0
    resolver_config_is_active "$MANAGED_CONFIG_FILE" || return 0
    grep -qx '# keen-pbr direct-fallback v1' "$MANAGED_CONFIG_FILE" || return 0
    # Run in the parent hook, after activation/receipt, not in dnsmasq's
    # conf-script child. Failure to save this small convenience snapshot must
    # not turn a successful active DNS configuration into a failed apply.
    {
        printf '%s\n' '# keen-pbr automatic direct DNS fallback v1' \
            '# Refreshed from the last complete resolver activation, without VPN detours.' \
            '# Remove the first line to keep your own fallback settings unchanged.'
        sed -n 's/^# keen-pbr direct-fallback \(server=.*\)$/\1/p' "$MANAGED_CONFIG_FILE"
    } > "$FALLBACK_TMP" || return 1
    if ! grep -q '^server=' "$FALLBACK_TMP"; then
        # Do not keep removed upstreams as an implicit permission to use them.
        printf '%s\n' '# keen-pbr direct-fallback unavailable' \
            '# No direct fallback DNS in this generation; configure a direct DNS or a manual fallback.' >> "$FALLBACK_TMP"
        log_warn "No direct fallback DNS is configured; VPN-only DNS cannot work while routing is stopped"
    fi
    if cmp -s "$FALLBACK_TMP" "$DNSMASQ_FALLBACK_FILE"; then
        rm -f "$FALLBACK_TMP"
        return 0
    fi
    chmod 644 "$FALLBACK_TMP" || return 1
    mv -f "$FALLBACK_TMP" "$DNSMASQ_FALLBACK_FILE"
}

resolver_attempt_is_valid() {
    [ "${#1}" -eq 32 ] || return 1
    case "$1" in *[!0-9a-f]*) return 1 ;; esac
}

active_conf_line() {
    attempt_id="$(tr -d '[:space:]' < "$ATTEMPT_FILE" 2>/dev/null || true)"
    if resolver_attempt_is_valid "$attempt_id"; then
        ACTIVE_ATTEMPT_ID="$attempt_id"
        KEEN_PBR_RESOLVER_ATTEMPT_ID="$attempt_id" \
            "$KEEN_PBR_BIN" --config "$CONFIG_PATH" generate-resolver-config dnsmasq
    else
        ACTIVE_ATTEMPT_ID=""
        "$KEEN_PBR_BIN" --config "$CONFIG_PATH" generate-resolver-config dnsmasq
    fi
}

publish_resolver_attempt() {
    attempt_id="${1:-}"
    [ -n "$attempt_id" ] || return 0
    resolver_attempt_is_valid "$attempt_id" || return 1
    umask 077
    mkdir -p "$STATE_DIR"
    rm -f "$ATTEMPT_ACCEPTED_FILE" "$ATTEMPT_ACCEPTED_TMP"
    printf '%s\n' "$attempt_id" > "$ATTEMPT_TMP"
    mv -f "$ATTEMPT_TMP" "$ATTEMPT_FILE"
}

accept_resolver_attempt() {
    attempt_id="${1:-}"
    [ -n "$attempt_id" ] || return 0
    resolver_attempt_is_valid "$attempt_id" || return 1
    printf '%s\n' "$attempt_id" > "$ATTEMPT_ACCEPTED_TMP"
    mv -f "$ATTEMPT_ACCEPTED_TMP" "$ATTEMPT_ACCEPTED_FILE"
}

wait_for_resolver_attempt_acceptance() {
    expected="${1:-}"
    [ -n "$expected" ] || return 0
    resolver_attempt_is_valid "$expected" || return 1
    if command -v usleep >/dev/null 2>&1; then
        wait_limit=30
        wait_delay=microseconds
    else
        # Keep the same three-second deadline on minimal BusyBox images that
        # do not install the optional usleep applet.
        wait_limit=3
        wait_delay=seconds
    fi
    waited=0
    while [ "$waited" -lt "$wait_limit" ]; do
        accepted="$(tr -d '[:space:]' < "$ATTEMPT_ACCEPTED_FILE" 2>/dev/null || true)"
        [ "$accepted" = "$expected" ] && return 0
        if [ "$wait_delay" = microseconds ]; then
            usleep 100000
        else
            sleep 1
        fi
        waited=$((waited + 1))
    done
    log_warn "dnsmasq did not accept the expected keen-pbr resolver generation"
    return 1
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
        { resolver_config_has_upstream "$path" ||
            grep -qx '# keen-pbr direct-fallback unavailable' "$path"; }
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
        accept_resolver_attempt "$ACTIVE_ATTEMPT_ID" || return 1
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
        # Count tenths of a second even when BusyBox has no usleep applet.
        if usleep 100000 2>/dev/null; then
            waited=$((waited + 1))
        else
            sleep 1
            waited=$((waited + 10))
        fi
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
        if usleep 100000 2>/dev/null; then
            waited=$((waited + 1))
        else
            sleep 1
            waited=$((waited + 10))
        fi
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
        attempt_id="${2:-}"
        publish_resolver_attempt "$attempt_id"
        activate_dnsmasq
        wait_for_resolver_attempt_acceptance "$attempt_id"
        update_direct_fallback || log_warn "Could not update the automatic DNS fallback; active DNS is unchanged"
        ;;
    deactivate)
        deactivate_dnsmasq
        ;;
    restart-dnsmasq)
        restart_dnsmasq
        update_direct_fallback || log_warn "Could not update the automatic DNS fallback; active DNS is unchanged"
        ;;
    reload)
        attempt_id="${2:-}"
        publish_resolver_attempt "$attempt_id"
        restart_dnsmasq
        wait_for_resolver_attempt_acceptance "$attempt_id"
        update_direct_fallback || log_warn "Could not update the automatic DNS fallback; active DNS is unchanged"
        ;;
    help|-h|--help)
        print_help
        ;;
    *)
        print_help >&2
        exit 1
        ;;
esac
