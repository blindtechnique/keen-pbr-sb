#!/bin/sh

set -eu

KEEN_PBR_BIN="${KEEN_PBR_BIN:-/usr/sbin/keen-pbr}"
CONFIG_PATH="${KEEN_PBR_CONFIG_PATH:-/etc/keen-pbr/config.json}"
DNSMASQ_FALLBACK_FILE="${KEEN_PBR_DNSMASQ_FALLBACK_FILE:-/etc/keen-pbr/dnsmasq-fallback.conf}"
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

log_warn() {
    log_message warn "$1"
}

log_info() {
    log_message info "$1"
}

log_error() {
    log_message err "$1"
}

ensure_xt_multiport_loaded() {
    if command -v nft >/dev/null 2>&1; then
        return 0
    fi

    if lsmod | grep -q '^xt_multiport[[:space:]]'; then
        return 0
    fi

    if command -v modprobe >/dev/null 2>&1 && modprobe xt_multiport 2>/dev/null; then
        return 0
    fi

    module_path="$(find "/lib/modules/$(uname -r)" -type f \
        -name 'xt_multiport.ko*' 2>/dev/null | head -n 1 || true)"

    if [ -n "$module_path" ]; then
        log_error "Failed to load xt_multiport from $module_path"
    else
        log_error "xt_multiport module not loaded and not found under /lib/modules/$(uname -r)"
    fi

    return 0
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
    if is_active; then
        emit_active_config
    else
        fallback_conf_line
        log_info "Produced dnsmasq fallback config entry"
    fi
}

activate_dnsmasq() {
    ensure_xt_multiport_loaded
    set_active_state "Y"
    log_info "Marked keen-pbr dnsmasq state as active"
    restart_dnsmasq
}

deactivate_dnsmasq() {
    set_active_state "N"
    log_info "Marked keen-pbr dnsmasq state as inactive"
    restart_dnsmasq
}

restart_dnsmasq() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart dnsmasq >/dev/null 2>&1
    elif command -v service >/dev/null 2>&1; then
        service dnsmasq restart >/dev/null 2>&1
    else
        log_warn "No supported dnsmasq service manager was found"
        return 1
    fi
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

case "${1:-}" in
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
