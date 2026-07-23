#!/bin/sh

set -u

RESCUE_DIR=/opt/var/lib/keen-pbr/rescue
RUN_FILE=/opt/var/run/keen-pbr-self-update.pid
LOG_FILE=/opt/var/log/keen-pbr-self-update.log
STATE_FILE=/opt/var/run/keen-pbr-self-update.json
CONFIG_DIR=/opt/etc/keen-pbr
CURRENT_IPK="$RESCUE_DIR/current.ipk"
PREVIOUS_IPK="$RESCUE_DIR/previous.ipk"
CANDIDATE_IPK="$RESCUE_DIR/candidate.ipk"
PRE_UPDATE_CONFIG="$RESCUE_DIR/pre-update-config"
PREVIOUS_CONFIG="$RESCUE_DIR/previous-config"

mkdir -p "$RESCUE_DIR" /opt/var/run /opt/var/log

write_state() {
    phase=$1
    percent=$2
    message=$3
    success=$4
    running=$5
    state_tmp="${STATE_FILE}.tmp.$$"
    printf '{"phase":"%s","percent":%s,"message":"%s","success":%s,"running":%s,"updated_at":%s}\n' \
        "$phase" "$percent" "$message" "$success" "$running" "$(date +%s)" \
        > "$state_tmp" &&
        mv -f "$state_tmp" "$STATE_FILE"
}

snapshot_config() {
    destination=$1
    temporary="${destination}.tmp.$$"
    rm -rf "$temporary"
    mkdir -p "$temporary"
    for name in config.json transports.json auth.json local.lst; do
        [ ! -f "$CONFIG_DIR/$name" ] ||
            cp -p "$CONFIG_DIR/$name" "$temporary/$name"
    done
    rm -rf "$destination"
    mv "$temporary" "$destination"
}

restore_config() {
    source_dir=$1
    [ -d "$source_dir" ] || return 0
    mkdir -p "$CONFIG_DIR"
    for source in "$source_dir"/*; do
        [ -f "$source" ] || continue
        cp -p "$source" "$CONFIG_DIR/$(basename "$source")"
    done
}

verify_runtime() {
    attempts=0
    stable=0
    listen=$(
        sed -n 's/.*"listen"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
            "$CONFIG_DIR/config.json" 2>/dev/null | head -n 1
    )
    api_port=${listen##*:}
    case "$api_port" in
        ''|*[!0-9]*) api_port=12121 ;;
    esac
    health_url="http://127.0.0.1:${api_port}/api/auth/status"
    while [ "$attempts" -lt 15 ]; do
        if /opt/etc/init.d/S80keen-pbr check >/dev/null 2>&1 &&
           /opt/etc/init.d/S79transport-manager check >/dev/null 2>&1; then
            http_code=""
            if [ -x /opt/bin/curl ]; then
                http_code=$(/opt/bin/curl -sS -o /dev/null \
                    -w '%{http_code}' --connect-timeout 2 \
                    "$health_url" 2>/dev/null || true)
            elif command -v curl >/dev/null 2>&1; then
                http_code=$(curl -sS -o /dev/null \
                    -w '%{http_code}' --connect-timeout 2 \
                    "$health_url" 2>/dev/null || true)
            elif [ -x /opt/bin/wget ]; then
                /opt/bin/wget -q -O /dev/null "$health_url" 2>/dev/null &&
                    http_code=200
            elif command -v wget >/dev/null 2>&1; then
                wget -q -O /dev/null "$health_url" 2>/dev/null &&
                    http_code=200
            fi
            if [ "$http_code" = "200" ]; then
                stable=$((stable + 1))
                [ "$stable" -lt 3 ] || return 0
            else
                stable=0
            fi
        else
            stable=0
        fi
        attempts=$((attempts + 1))
        sleep 2
    done
    return 1
}

install_archive() {
    archive=$1
    config_snapshot=$2

    [ -s "$archive" ] || return 2
    KEEN_PBR_REPLACE_DNSMASQ_DEFAULTS=N \
        /opt/bin/opkg --force-reinstall install "$archive" || true
    restore_config "$config_snapshot"
    /opt/etc/init.d/S79transport-manager restart >/dev/null 2>&1 || true
    /opt/etc/init.d/S80keen-pbr restart >/dev/null 2>&1 || true
    verify_runtime
}

stage_candidate() {
    source_ipk=$1
    [ -s "$source_ipk" ] || {
        echo "Candidate IPK is missing or empty: $source_ipk" >&2
        return 2
    }
    candidate_tmp="${CANDIDATE_IPK}.tmp.$$"
    cp -p "$source_ipk" "$candidate_tmp"
    mv -f "$candidate_tmp" "$CANDIDATE_IPK"
    snapshot_config "$PRE_UPDATE_CONFIG"
    sync
}

promote_candidate() {
    [ -s "$CANDIDATE_IPK" ] || return 2
    if [ -s "$CURRENT_IPK" ]; then
        previous_tmp="${PREVIOUS_IPK}.tmp.$$"
        cp -p "$CURRENT_IPK" "$previous_tmp"
        mv -f "$previous_tmp" "$PREVIOUS_IPK"
        if [ -d "$PRE_UPDATE_CONFIG" ]; then
            rm -rf "$PREVIOUS_CONFIG"
            mv "$PRE_UPDATE_CONFIG" "$PREVIOUS_CONFIG"
        fi
    else
        rm -rf "$PRE_UPDATE_CONFIG"
    fi
    mv -f "$CANDIDATE_IPK" "$CURRENT_IPK"
    sync
}

rollback_candidate() {
    [ -s "$CURRENT_IPK" ] || return 2
    install_archive "$CURRENT_IPK" "$PRE_UPDATE_CONFIG"
}

rollback_previous() {
    [ -s "$PREVIOUS_IPK" ] || return 2

    printf '%s\n' "$$" > "$RUN_FILE"
    trap 'rm -f "$RUN_FILE"' EXIT INT TERM
    : > "$LOG_FILE"
    exec >>"$LOG_FILE" 2>&1
    write_state rollback 10 "Восстанавливаю предыдущий пакет" null true
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting package rollback"

    redo_config="${RESCUE_DIR}/redo-config.tmp.$$"
    snapshot_config "$redo_config"
    redo_ipk="${RESCUE_DIR}/redo.ipk.tmp.$$"
    [ ! -s "$CURRENT_IPK" ] || cp -p "$CURRENT_IPK" "$redo_ipk"

    if ! install_archive "$PREVIOUS_IPK" "$PREVIOUS_CONFIG"; then
        write_state failed 100 "Откат пакета не выполнен" false false
        echo "Package rollback failed" >&2
        rm -rf "$redo_config"
        rm -f "$redo_ipk"
        return 1
    fi

    old_current="${RESCUE_DIR}/old-current.ipk.tmp.$$"
    [ ! -s "$CURRENT_IPK" ] || mv "$CURRENT_IPK" "$old_current"
    mv "$PREVIOUS_IPK" "$CURRENT_IPK"
    if [ -s "$redo_ipk" ]; then
        mv "$redo_ipk" "$PREVIOUS_IPK"
    elif [ -s "$old_current" ]; then
        mv "$old_current" "$PREVIOUS_IPK"
    fi
    rm -f "$old_current"

    rm -rf "$PREVIOUS_CONFIG"
    [ ! -d "$redo_config" ] || mv "$redo_config" "$PREVIOUS_CONFIG"
    sync
    write_state completed 100 "Предыдущий пакет восстановлен" true false
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Package rollback completed"
}

case "${1:-}" in
    stage)
        [ "$#" -eq 2 ] || exit 2
        stage_candidate "$2"
        ;;
    verify)
        verify_runtime
        ;;
    promote)
        promote_candidate
        ;;
    rollback-candidate)
        rollback_candidate
        ;;
    rollback-previous)
        rollback_previous
        ;;
    status)
        printf '{"ready":%s,"rollback_available":%s}\n' \
            "$([ -s "$CURRENT_IPK" ] && printf true || printf false)" \
            "$([ -s "$PREVIOUS_IPK" ] && printf true || printf false)"
        ;;
    *)
        echo "Usage: $0 {stage IPK|verify|promote|rollback-candidate|rollback-previous|status}" >&2
        exit 2
        ;;
esac
