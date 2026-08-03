#!/bin/ash

set -e

KEEN_PBR_BIN="${KEEN_PBR_BIN:-/usr/sbin/keen-pbr}"
CONFIG_DIR="${KEEN_PBR_CONFIG_DIR:-/etc/keen-pbr}"
CONFIG_PATH="${KEEN_PBR_CONFIG_PATH:-/etc/keen-pbr/config.json}"
CACHE_DIR="${KEEN_PBR_CACHE_DIR:-/var/cache/keen-pbr}"
DNSMASQ_FALLBACK_FILE="${KEEN_PBR_DNSMASQ_FALLBACK_FILE:-/etc/keen-pbr/dnsmasq-fallback.conf}"
PACKAGE_NAME="keen-pbr"
CONFFILE="${PACKAGE_NAME}.conf"
UCI_HELPER="/usr/lib/keen-pbr/uci.sh"
DNSMASQ_HELPER="${KEEN_PBR_DNSMASQ_HELPER:-/usr/lib/keen-pbr/dnsmasq.sh}"
# OpenWrt dnsmasq runs inside a procd jail. /var/run/dnsmasq is its writable
# runtime mount, while generic /tmp paths are not guaranteed to be visible.
STATE_DIR="${KEEN_PBR_STATE_DIR:-/var/run/dnsmasq/keen-pbr}"
MANAGED_CONFIG_FILE="${STATE_DIR}/dnsmasq-managed.conf"
MANAGED_CONFIG_TMP="${MANAGED_CONFIG_FILE}.$$"
ATTEMPT_FILE="${STATE_DIR}/resolver-attempt-id"
ATTEMPT_TMP="${ATTEMPT_FILE}.$$"
ATTEMPT_ACCEPTED_FILE="${STATE_DIR}/resolver-attempt-accepted"
ATTEMPT_ACCEPTED_TMP="${ATTEMPT_ACCEPTED_FILE}.$$"
MANAGED_CANDIDATE_COMPLETE="N"
ACTIVE_ATTEMPT_ID=""

cleanup_managed_config_tmp() {
    rm -f "$MANAGED_CONFIG_TMP" "$ATTEMPT_TMP" "$ATTEMPT_ACCEPTED_TMP"
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

write_managed_conf() {
    local target="$1"
    local line="$2"
    local description="$3"
    local existing=""

    if [ -f "$target" ]; then
        existing="$(cat "$target")"
        if [ "$existing" = "$line" ]; then
            return 0
        fi
    fi

    printf '%s\n' "$line" > "$target"
    log_info "Created $target with $description configuration"
}

conf_script_line() {
    printf 'conf-script=%s dnsmasq-config-entry' "$DNSMASQ_HELPER"
}

fallback_conf_line() {
    printf 'conf-file=%s' "$DNSMASQ_FALLBACK_FILE"
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

    printf '%s\n' "$(fallback_conf_line)"
    log_warn "Resolver stream failed without a last-known-good config; using dnsmasq fallback"
}

dnsmasq_confdir() {
    "$UCI_HELPER" dnsmasq-confdir "$1"
}

dnsmasq_sections() {
    "$UCI_HELPER" dnsmasq-sections
}

write_temp_conf_for_section() {
    local section="$1"
    local confdir

    confdir="$(dnsmasq_confdir "$section")"
    mkdir -p "$confdir"
    write_managed_conf "${confdir}/${CONFFILE}" "$(conf_script_line)" "working"
}

write_fallback_conf_for_section() {
    local section="$1"
    local confdir

    confdir="$(dnsmasq_confdir "$section")"
    mkdir -p "$confdir"
    if [ -f "$DNSMASQ_FALLBACK_FILE" ]; then
        write_managed_conf "${confdir}/${CONFFILE}" "$(fallback_conf_line)" "fallback"
    else
        rm -f "${confdir}/${CONFFILE}"
        log_info "Removed ${confdir}/${CONFFILE}"
    fi
}

remove_temp_conf_for_section() {
    local section="$1"
    local confdir

    confdir="$(dnsmasq_confdir "$section")"
    rm -f "${confdir}/${CONFFILE}"
    log_info "Removed ${confdir}/${CONFFILE}"
}

remove_all_temp_confs() {
    local path

    for path in /tmp/dnsmasq.*.d/"${CONFFILE}" /tmp/dnsmasq.d/"${CONFFILE}"; do
        [ -e "$path" ] || continue
        rm -f "$path"
        log_info "Removed $path"
    done
}

install_persistent() {
    local section

    for section in $(dnsmasq_sections); do
        write_fallback_conf_for_section "$section" || true
    done

    "$UCI_HELPER" dnsmasq-install-persistent
}

ensure_runtime_prereqs() {
    "$UCI_HELPER" dnsmasq-ensure-runtime-prereqs
}

activate_dnsmasq() {
    local section

    ensure_runtime_prereqs

    for section in $(dnsmasq_sections); do
        write_temp_conf_for_section "$section" || true
    done

    restart_dnsmasq
}

deactivate_dnsmasq() {
    local section

    for section in $(dnsmasq_sections); do
        write_fallback_conf_for_section "$section" || true
    done

    restart_dnsmasq
}

uninstall_persistent() {
    local section

    for section in $(dnsmasq_sections); do
        remove_temp_conf_for_section "$section" || true
    done

    "$UCI_HELPER" dnsmasq-uninstall-persistent

    remove_all_temp_confs || true

    restart_dnsmasq
}

restart_dnsmasq() {
    /etc/init.d/dnsmasq restart 2>/dev/null
}

print_help() {
    cat <<EOF
Usage: $0 <command>

Commands:
  dnsmasq-config-entry   Print an atomic managed resolver config or a safe fallback.
  install-persistent     Seed fallback dnsmasq config and install persistent integration.
  activate               Switch dnsmasq to keen-pbr dynamic resolver config, and restart dnsmasq.
  deactivate             Switch dnsmasq to fallback resolver config and restart dnsmasq.
  uninstall-persistent   Remove persistent integration and helper-managed runtime config.
  restart-dnsmasq        Restart dnsmasq without changing helper-managed config.
  reload                 Alias for restart-dnsmasq; used by the system resolver hook.
  help                   Show this help text.
EOF
}

case "$1" in
    dnsmasq-config-entry)
        emit_active_config
        ;;
    install-persistent)
        install_persistent
        ;;
    activate)
        attempt_id="${2:-}"
        publish_resolver_attempt "$attempt_id"
        activate_dnsmasq
        wait_for_resolver_attempt_acceptance "$attempt_id"
        ;;
    deactivate)
        deactivate_dnsmasq
        ;;
    uninstall-persistent)
        uninstall_persistent
        ;;
    restart-dnsmasq)
        restart_dnsmasq
        ;;
    reload)
        attempt_id="${2:-}"
        publish_resolver_attempt "$attempt_id"
        restart_dnsmasq
        wait_for_resolver_attempt_acceptance "$attempt_id"
        ;;
    help|-h|--help)
        print_help
        ;;
    *)
        print_help >&2
        exit 1
        ;;
esac
