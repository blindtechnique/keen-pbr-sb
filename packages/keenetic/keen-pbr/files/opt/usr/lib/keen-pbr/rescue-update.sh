#!/bin/sh

set -u
umask 077

ROOT=${KEEN_PBR_RESCUE_ROOT:-}
case "$ROOT" in
    ""|/*) ;;
    *)
        echo "KEEN_PBR_RESCUE_ROOT must be an absolute path" >&2
        exit 2
        ;;
esac

RESCUE_DIR="${ROOT}/opt/var/lib/keen-pbr/rescue"
RUN_FILE="${ROOT}/opt/var/run/keen-pbr-self-update.pid"
LOG_FILE="${ROOT}/opt/var/log/keen-pbr-self-update.log"
STATE_FILE="${ROOT}/opt/var/run/keen-pbr-self-update.json"
CONFIG_DIR="${ROOT}/opt/etc/keen-pbr"
OPKG="${ROOT}/opt/bin/opkg"
KEEN_PBR_INIT="${ROOT}/opt/etc/init.d/S80keen-pbr"
TRANSPORT_INIT="${ROOT}/opt/etc/init.d/S79transport-manager"
OPT_CURL="${ROOT}/opt/bin/curl"
OPT_WGET="${ROOT}/opt/bin/wget"
LOCK_HELPER="${KEEN_PBR_UPDATE_LOCK_HELPER:-${RESCUE_DIR}/update-lock.sh}"

CURRENT_IPK="$RESCUE_DIR/current.ipk"
PREVIOUS_IPK="$RESCUE_DIR/previous.ipk"
CANDIDATE_IPK="$RESCUE_DIR/candidate.ipk"
PRE_UPDATE_CONFIG="$RESCUE_DIR/pre-update-config"
PREVIOUS_CONFIG="$RESCUE_DIR/previous-config"
PENDING_FILE="$RESCUE_DIR/pending"
UNKNOWN_FILE="$RESCUE_DIR/UNKNOWN"
PENDING_BASELINE_IPK="$RESCUE_DIR/pending-baseline.ipk"
PENDING_BASELINE_CONFIG="$RESCUE_DIR/pending-baseline-config"
PENDING_TARGET_IPK="$RESCUE_DIR/pending-target.ipk"
PENDING_TARGET_CONFIG="$RESCUE_DIR/pending-target-config"
SNAPSHOT_MANIFEST=".snapshot-manifest"
SNAPSHOT_READY=".snapshot-ready"
STABLE_METADATA_HELPER="${RESCUE_DIR}/portable-stat.sh"
PACKAGE_METADATA_HELPER="${ROOT}/opt/usr/lib/keen-pbr/portable-stat.sh"

bootstrap_rescue_directory_is_private() {
    [ -d "$RESCUE_DIR" ] && [ ! -L "$RESCUE_DIR" ] || return 1
    if [ -x "${ROOT}/opt/bin/stat" ]; then
        bootstrap_output=$(
            LC_ALL=C "${ROOT}/opt/bin/stat" -t "$RESCUE_DIR" 2>/dev/null
        ) || return 1
    elif [ -x "${ROOT}/opt/bin/busybox" ]; then
        bootstrap_output=$(
            LC_ALL=C "${ROOT}/opt/bin/busybox" \
                stat -t "$RESCUE_DIR" 2>/dev/null
        ) || return 1
    elif command -v stat >/dev/null 2>&1; then
        bootstrap_output=$(
            LC_ALL=C stat -t "$RESCUE_DIR" 2>/dev/null
        ) || return 1
    elif command -v busybox >/dev/null 2>&1; then
        bootstrap_output=$(
            LC_ALL=C busybox stat -t "$RESCUE_DIR" 2>/dev/null
        ) || return 1
    else
        return 1
    fi
    case "$bootstrap_output" in
        "$RESCUE_DIR "*)
            bootstrap_fields=${bootstrap_output#"$RESCUE_DIR "}
            ;;
        *) return 1 ;;
    esac
    set -- $bootstrap_fields
    [ "$#" -ge 5 ] || return 1
    bootstrap_mode_hex=$3
    bootstrap_uid=$4
    case "$bootstrap_mode_hex" in
        ''|*[!0-9A-Fa-f]*) return 1 ;;
    esac
    [ "${#bootstrap_mode_hex}" -le 8 ] || return 1
    case "$bootstrap_uid" in
        ''|*[!0-9]*) return 1 ;;
    esac
    bootstrap_mode=$((0x$bootstrap_mode_hex & 4095))
    bootstrap_expected_uid=$(id -u 2>/dev/null) || return 1
    [ "$bootstrap_mode" -eq 448 ] 2>/dev/null &&
        [ "$bootstrap_uid" = "$bootstrap_expected_uid" ]
}

load_metadata_helper() {
    requested_helper=${KEEN_PBR_PORTABLE_STAT_HELPER:-}
    if [ -n "$requested_helper" ]; then
        metadata_helper=$requested_helper
    elif [ -f "$PACKAGE_METADATA_HELPER" ] &&
         [ ! -L "$PACKAGE_METADATA_HELPER" ]; then
        metadata_helper=$PACKAGE_METADATA_HELPER
    else
        bootstrap_rescue_directory_is_private || {
            echo "Refusing unsafe rescue metadata directory" >&2
            exit 2
        }
        metadata_helper=$STABLE_METADATA_HELPER
    fi
    [ -f "$metadata_helper" ] && [ ! -L "$metadata_helper" ] || {
        echo "Portable metadata helper is missing or unsafe" >&2
        exit 2
    }
    . "$metadata_helper" || exit 2
}

load_metadata_helper

[ ! -L "$RESCUE_DIR" ] &&
    { [ ! -e "$RESCUE_DIR" ] || [ -d "$RESCUE_DIR" ]; } || {
        echo "Refusing unsafe rescue directory: $RESCUE_DIR" >&2
        exit 1
    }
mkdir -p "$RESCUE_DIR" "${ROOT}/opt/var/run" "${ROOT}/opt/var/log" || exit 1
chmod 0700 "$RESCUE_DIR" || exit 1

write_state() {
    phase=$1
    percent=$2
    message=$3
    success=$4
    running=$5
    state_tmp="${STATE_FILE}.tmp.$$"
    if ! printf '{"phase":"%s","percent":%s,"message":"%s","success":%s,"running":%s,"updated_at":%s}\n' \
        "$phase" "$percent" "$message" "$success" "$running" "$(date +%s)" \
        > "$state_tmp"; then
        rm -f "$state_tmp"
        return 1
    fi
    chmod 0600 "$state_tmp" &&
        mv -f "$state_tmp" "$STATE_FILE"
}

managed_config_files() {
    # This is the single rescue inventory. Package rollback deliberately does
    # not include caches, generated *.json-opkg files, the downloadable backup
    # archive, or nfqws2's independently managed tree.
    printf '%s\n' \
        config.json \
        transports.json \
        auth.json \
        local.lst \
        defaults \
        dnsmasq-fallback.conf \
        hook.sh \
        catalog-source.json \
        logging.json \
        remote-access.json
}

managed_config_name() {
    candidate=${1:-}
    [ -n "$candidate" ] || return 1
    for managed_name in $(managed_config_files); do
        [ "$managed_name" != "$candidate" ] || return 0
    done
    return 1
}

valid_ipk_payload() {
    [ -f "$1" ] && [ -s "$1" ] && [ ! -L "$1" ] && [ -r "$1" ]
}

sha256_file() {
    target=$1
    if [ -x "${ROOT}/opt/bin/sha256sum" ]; then
        "${ROOT}/opt/bin/sha256sum" "$target"
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$target"
    else
        echo "sha256sum is required for rescue snapshots" >&2
        return 1
    fi
}

read_hash() {
    hash_line=$(sha256_file "$1") || return 1
    hash=${hash_line%%[[:space:]]*}
    [ "${#hash}" -eq 64 ] || return 1
    case "$hash" in
        *[!0-9a-f]*) return 1 ;;
    esac
    printf '%s\n' "$hash"
}

file_mode() {
    keen_pbr_stat_value '%a' "$1"
}

write_ipk_hash() {
    archive=$1
    valid_ipk_payload "$archive" || return 1
    digest=$(read_hash "$archive") || return 1
    sidecar="${archive}.sha256"
    sidecar_tmp="${sidecar}.tmp.$$"
    if ! printf '%s\n' "$digest" > "$sidecar_tmp" ||
       ! chmod 0600 "$sidecar_tmp" ||
       ! mv -f "$sidecar_tmp" "$sidecar"; then
        rm -f "$sidecar_tmp"
        return 1
    fi
}

valid_ipk_file() {
    archive=$1
    sidecar="${archive}.sha256"
    valid_ipk_payload "$archive" &&
        [ -f "$sidecar" ] && [ ! -L "$sidecar" ] ||
        return 1
    expected=""
    IFS= read -r expected < "$sidecar" || return 1
    [ "$(wc -l < "$sidecar" 2>/dev/null)" -eq 1 ] 2>/dev/null ||
        return 1
    [ "${#expected}" -eq 64 ] || return 1
    case "$expected" in
        *[!0-9a-f]*) return 1 ;;
    esac
    actual=$(read_hash "$archive") || return 1
    [ "$actual" = "$expected" ]
}

replace_directory() {
    prepared=$1
    destination=$2
    previous="${destination}.old.$$"
    rm -rf "$previous" || return 1
    if [ -e "$destination" ] || [ -L "$destination" ]; then
        [ -d "$destination" ] && [ ! -L "$destination" ] || return 1
        mv "$destination" "$previous" || return 1
    fi
    if mv "$prepared" "$destination"; then
        rm -rf "$previous" || return 1
        return 0
    fi
    [ ! -d "$previous" ] || mv "$previous" "$destination" 2>/dev/null || true
    return 1
}

validate_snapshot() {
    source_dir=$1
    [ -d "$source_dir" ] && [ ! -L "$source_dir" ] ||
        return 1
    manifest="$source_dir/$SNAPSHOT_MANIFEST"
    ready="$source_dir/$SNAPSHOT_READY"
    [ -f "$manifest" ] && [ ! -L "$manifest" ] &&
        [ -f "$ready" ] && [ ! -L "$ready" ] ||
        return 1

    expected_manifest_hash=""
    IFS= read -r expected_manifest_hash < "$ready" || return 1
    [ "$(wc -l < "$ready" 2>/dev/null)" -eq 1 ] 2>/dev/null || return 1
    [ "${#expected_manifest_hash}" -eq 64 ] || return 1
    case "$expected_manifest_hash" in
        *[!0-9a-f]*) return 1 ;;
    esac
    actual_manifest_hash=$(read_hash "$manifest") || return 1
    [ "$actual_manifest_hash" = "$expected_manifest_hash" ] || return 1

    seen="|"
    line_number=0
    while IFS=' ' read -r state name declared_mode file_hash extra; do
        line_number=$((line_number + 1))
        if [ "$line_number" -eq 1 ]; then
            [ "$state" = "keen-pbr-snapshot-v2" ] &&
                [ -z "${name:-}${declared_mode:-}${file_hash:-}${extra:-}" ] ||
                return 1
            continue
        fi
        [ -n "${state:-}" ] && [ -n "${name:-}" ] &&
            [ -n "${declared_mode:-}" ] && [ -n "${file_hash:-}" ] &&
            [ -z "${extra:-}" ] ||
            return 1
        managed_config_name "$name" || return 1
        case "$seen" in
            *"|$name|"*) return 1 ;;
        esac
        seen="${seen}${name}|"
        case "$state" in
            present)
                case "$declared_mode" in
                    [0-7][0-7][0-7]|[0-7][0-7][0-7][0-7]) ;;
                    *) return 1 ;;
                esac
                [ "${#file_hash}" -eq 64 ] || return 1
                case "$file_hash" in
                    *[!0-9a-f]*) return 1 ;;
                esac
                [ -f "$source_dir/$name" ] &&
                    [ ! -L "$source_dir/$name" ] ||
                    return 1
                actual_hash=$(read_hash "$source_dir/$name") || return 1
                [ "$actual_hash" = "$file_hash" ] || return 1
                actual_mode=$(file_mode "$source_dir/$name") || return 1
                [ "$actual_mode" = "$declared_mode" ] || return 1
                ;;
            absent)
                [ "$declared_mode" = "-" ] && [ "$file_hash" = "-" ] ||
                    return 1
                [ ! -e "$source_dir/$name" ] &&
                    [ ! -L "$source_dir/$name" ] ||
                    return 1
                ;;
            *)
                return 1
                ;;
        esac
    done < "$manifest"
    [ "$line_number" -gt 1 ] || return 1

    for name in $(managed_config_files); do
        case "$seen" in
            *"|$name|"*) ;;
            *) return 1 ;;
        esac
    done

    # The manifest is an exact inventory, not merely a list of files that
    # happened to be checked. Reject unmanifested sidecars or nested content.
    for entry in "$source_dir"/* "$source_dir"/.[!.]* "$source_dir"/..?*; do
        [ -e "$entry" ] || [ -L "$entry" ] || continue
        entry_name=${entry##*/}
        case "$entry_name" in
            "$SNAPSHOT_MANIFEST"|"$SNAPSHOT_READY") ;;
            *)
                managed_config_name "$entry_name" || return 1
                [ -f "$entry" ] && [ ! -L "$entry" ] || return 1
                ;;
        esac
    done
    return 0
}

snapshot_config() {
    destination=$1
    [ ! -L "$CONFIG_DIR" ] &&
        { [ ! -e "$CONFIG_DIR" ] || [ -d "$CONFIG_DIR" ]; } ||
        return 1
    temporary="${destination}.tmp.$$"
    rm -rf "$temporary" || return 1
    mkdir -p "$temporary" || return 1
    chmod 0700 "$temporary" || {
        rm -rf "$temporary"
        return 1
    }
    manifest="$temporary/$SNAPSHOT_MANIFEST"
    printf '%s\n' "keen-pbr-snapshot-v2" > "$manifest" || {
        rm -rf "$temporary"
        return 1
    }

    for name in $(managed_config_files); do
        source="$CONFIG_DIR/$name"
        if [ -L "$source" ]; then
            echo "Refusing to snapshot symlink: $source" >&2
            rm -rf "$temporary"
            return 1
        fi
        if [ -f "$source" ]; then
            cp -p "$source" "$temporary/$name" || {
                rm -rf "$temporary"
                return 1
            }
            file_hash=$(read_hash "$temporary/$name") || {
                rm -rf "$temporary"
                return 1
            }
            copied_mode=$(file_mode "$temporary/$name") || {
                rm -rf "$temporary"
                return 1
            }
            printf 'present %s %s %s\n' "$name" "$copied_mode" \
                "$file_hash" >> "$manifest" || {
                rm -rf "$temporary"
                return 1
            }
        elif [ -e "$source" ]; then
            echo "Refusing to snapshot non-regular file: $source" >&2
            rm -rf "$temporary"
            return 1
        else
            printf 'absent %s - -\n' "$name" >> "$manifest" || {
                rm -rf "$temporary"
                return 1
            }
        fi
    done

    manifest_hash=$(read_hash "$manifest") || {
        rm -rf "$temporary"
        return 1
    }
    printf '%s\n' "$manifest_hash" > "$temporary/$SNAPSHOT_READY" || {
        rm -rf "$temporary"
        return 1
    }
    chmod 0600 "$manifest" "$temporary/$SNAPSHOT_READY" || {
        rm -rf "$temporary"
        return 1
    }
    validate_snapshot "$temporary" || {
        rm -rf "$temporary"
        return 1
    }
    replace_directory "$temporary" "$destination"
}

copy_snapshot() {
    source_dir=$1
    destination=$2
    validate_snapshot "$source_dir" || return 1
    temporary="${destination}.tmp.$$"
    rm -rf "$temporary" || return 1
    mkdir -p "$temporary" || return 1
    chmod 0700 "$temporary" || {
        rm -rf "$temporary"
        return 1
    }
    cp -p "$source_dir/$SNAPSHOT_MANIFEST" \
        "$source_dir/$SNAPSHOT_READY" "$temporary/" || {
        rm -rf "$temporary"
        return 1
    }
    for name in $(managed_config_files); do
        [ ! -f "$source_dir/$name" ] ||
            cp -p "$source_dir/$name" "$temporary/$name" || {
                rm -rf "$temporary"
                return 1
            }
    done
    validate_snapshot "$temporary" || {
        rm -rf "$temporary"
        return 1
    }
    replace_directory "$temporary" "$destination"
}

restore_config() {
    source_dir=$1
    validate_snapshot "$source_dir" || return 1
    [ ! -L "$CONFIG_DIR" ] &&
        { [ ! -e "$CONFIG_DIR" ] || [ -d "$CONFIG_DIR" ]; } ||
        return 1
    mkdir -p "$CONFIG_DIR" || return 1
    staging="$CONFIG_DIR/.rescue-restore.tmp.$$"
    rm -rf "$staging" || return 1
    mkdir -p "$staging" || return 1
    chmod 0700 "$staging" || {
        rm -rf "$staging"
        return 1
    }

    for name in $(managed_config_files); do
        record=$(grep -E "^(present|absent) ${name} " \
            "$source_dir/$SNAPSHOT_MANIFEST") || {
                rm -rf "$staging"
                return 1
            }
        set -- $record
        if [ "$1" = "present" ]; then
            cp -p "$source_dir/$name" "$staging/$name" || {
                rm -rf "$staging"
                return 1
            }
        fi
    done

    for name in $(managed_config_files); do
        record=$(grep -E "^(present|absent) ${name} " \
            "$source_dir/$SNAPSHOT_MANIFEST") || {
                rm -rf "$staging"
                return 1
            }
        set -- $record
        if [ "$1" = "present" ]; then
            mv -f "$staging/$name" "$CONFIG_DIR/$name" || {
                rm -rf "$staging"
                return 1
            }
        else
            rm -f "$CONFIG_DIR/$name" || {
                rm -rf "$staging"
                return 1
            }
        fi
    done
    rmdir "$staging" || return 1

    # Verify the live files after the multi-file replacement. If an external
    # writer raced the update, fail closed and let the caller compensate.
    for name in $(managed_config_files); do
        record=$(grep -E "^(present|absent) ${name} " \
            "$source_dir/$SNAPSHOT_MANIFEST") || return 1
        set -- $record
        if [ "$1" = "present" ]; then
            [ -f "$CONFIG_DIR/$name" ] && [ ! -L "$CONFIG_DIR/$name" ] ||
                return 1
            restored_hash=$(read_hash "$CONFIG_DIR/$name") || return 1
            [ "$restored_hash" = "$4" ] || return 1
            restored_mode=$(file_mode "$CONFIG_DIR/$name") || return 1
            [ "$restored_mode" = "$3" ] || return 1
        else
            [ ! -e "$CONFIG_DIR/$name" ] &&
                [ ! -L "$CONFIG_DIR/$name" ] ||
                return 1
        fi
    done
    return 0
}

replace_file_from() {
    source=$1
    destination=$2
    valid_ipk_file "$source" || return 1
    temporary="${destination}.tmp.$$"
    temporary_hash="${temporary}.sha256"
    if ! cp -p "$source" "$temporary" ||
       ! cp -p "${source}.sha256" "$temporary_hash" ||
       ! valid_ipk_file "$temporary"; then
        rm -f "$temporary" "$temporary_hash"
        return 1
    fi
    if ! mv -f "$temporary" "$destination" ||
       ! mv -f "$temporary_hash" "${destination}.sha256"; then
        rm -f "$temporary" "$temporary_hash"
        return 1
    fi
}

import_file_from() {
    source=$1
    destination=$2
    valid_ipk_payload "$source" || return 1
    temporary="${destination}.tmp.$$"
    if ! cp -p "$source" "$temporary" ||
       ! write_ipk_hash "$temporary" ||
       ! valid_ipk_file "$temporary"; then
        rm -f "$temporary" "${temporary}.sha256"
        return 1
    fi
    if ! mv -f "$temporary" "$destination" ||
       ! mv -f "${temporary}.sha256" "${destination}.sha256"; then
        rm -f "$temporary" "${temporary}.sha256"
        return 1
    fi
}

pending_phase() {
    [ -f "$PENDING_FILE" ] && [ ! -L "$PENDING_FILE" ] || return 1
    phase=""
    IFS= read -r phase < "$PENDING_FILE" || return 1
    case "$phase" in
        candidate-staged|candidate-promoting|rollback-previous|rollback-swapping)
            printf '%s\n' "$phase"
            ;;
        *)
            return 1
            ;;
    esac
}

write_pending() {
    phase=$1
    pending_tmp="${PENDING_FILE}.tmp.$$"
    if ! printf '%s\n' "$phase" > "$pending_tmp" ||
       ! chmod 0600 "$pending_tmp"; then
        rm -f "$pending_tmp"
        return 1
    fi
    if ! mv -f "$pending_tmp" "$PENDING_FILE"; then
        rm -f "$pending_tmp"
        return 1
    fi

    # The rename above is the commit point. From here onward callers must
    # preserve every recovery artifact even if durability cannot be confirmed.
    # Returning a distinct code prevents a generic failure path from deleting
    # the payload referenced by the already-visible PENDING marker.
    if { [ -n "$ROOT" ] &&
         [ "${KEEN_PBR_RESCUE_TEST_FAIL_PENDING_AFTER_COMMIT:-0}" = "1" ]; } ||
       ! sync; then
        mark_unknown \
            "pending phase '${phase}' was committed but durability could not be confirmed" ||
            true
        return 74
    fi
    if [ -n "$ROOT" ] &&
       [ "${KEEN_PBR_RESCUE_TEST_STOP_AFTER_PHASE:-}" = "$phase" ]; then
        kill -9 "$$"
    fi
    return 0
}

mark_unknown() {
    reason=$1
    unknown_tmp="${UNKNOWN_FILE}.tmp.$$"
    if ! printf '%s\n' "$reason" > "$unknown_tmp" ||
       ! chmod 0600 "$unknown_tmp" ||
       ! mv -f "$unknown_tmp" "$UNKNOWN_FILE"; then
        rm -f "$unknown_tmp"
        return 1
    fi
    sync || return 1
    write_state unknown 100 \
        "Состояние пакета требует ручного восстановления" false false ||
        true
}

ensure_known_idle() {
    [ ! -e "$UNKNOWN_FILE" ] || {
        echo "Rescue state is UNKNOWN; recover it before another update" >&2
        return 1
    }
    [ ! -e "$PENDING_FILE" ] || {
        echo "An interrupted rescue transaction is pending; run recover-pending" >&2
        return 1
    }
}

cleanup_pending_artifacts() {
    if [ -n "$ROOT" ] &&
       [ "${KEEN_PBR_RESCUE_TEST_FAIL_CLEANUP:-0}" = "1" ]; then
        return 1
    fi
    cleanup_status=0
    rm -f "$CANDIDATE_IPK" "${CANDIDATE_IPK}.sha256" \
        "$PENDING_BASELINE_IPK" "${PENDING_BASELINE_IPK}.sha256" \
        "$PENDING_TARGET_IPK" "${PENDING_TARGET_IPK}.sha256" ||
        cleanup_status=1
    rm -rf "$PRE_UPDATE_CONFIG" "$PENDING_BASELINE_CONFIG" \
        "$PENDING_TARGET_CONFIG" || cleanup_status=1
    for artifact in \
        "$CANDIDATE_IPK" "${CANDIDATE_IPK}.sha256" \
        "$PENDING_BASELINE_IPK" "${PENDING_BASELINE_IPK}.sha256" \
        "$PENDING_TARGET_IPK" "${PENDING_TARGET_IPK}.sha256" \
        "$PRE_UPDATE_CONFIG" "$PENDING_BASELINE_CONFIG" \
        "$PENDING_TARGET_CONFIG"
    do
        [ ! -e "$artifact" ] && [ ! -L "$artifact" ] || cleanup_status=1
    done
    return "$cleanup_status"
}

clear_pending() {
    # Removing and durably syncing PENDING is the transaction commit point.
    # Recovery payloads must remain available until after that point; otherwise
    # a crash can leave PENDING behind without the bytes needed to recover.
    rm -f "$PENDING_FILE" || return 1
    if ! sync; then
        mark_unknown \
            "rescue transaction commit could not be made durable" ||
            true
        return 1
    fi

    # Everything below is post-commit garbage collection. Failure can waste
    # disk space, but must not turn a completed transaction back into PENDING
    # or UNKNOWN. The next stage operation starts with the same idempotent GC.
    if ! cleanup_pending_artifacts; then
        echo "WARNING: rescue transaction committed, but stale recovery artifacts could not be removed" >&2
        return 0
    fi
    if ! sync; then
        echo "WARNING: rescue transaction committed, but recovery artifact cleanup durability was not confirmed" >&2
    fi
    return 0
}

LOCK_OWNER_PID=${KEEN_PBR_UPDATE_LOCK_PID:-}
LOCK_TOKEN=${KEEN_PBR_UPDATE_LOCK_TOKEN:-}
LOCK_OWNED=0
RUN_FILE_OWNED=0

acquire_update_lock() {
    [ -x "$LOCK_HELPER" ] || {
        echo "Update lock helper is missing or not executable: $LOCK_HELPER" >&2
        return 1
    }
    if [ -n "$LOCK_OWNER_PID" ] || [ -n "$LOCK_TOKEN" ]; then
        [ -n "$LOCK_OWNER_PID" ] && [ -n "$LOCK_TOKEN" ] &&
            "$LOCK_HELPER" held "$LOCK_OWNER_PID" "$LOCK_TOKEN" ||
            return 1
        return 0
    fi
    LOCK_OWNER_PID=$$
    LOCK_TOKEN=$("$LOCK_HELPER" acquire "$LOCK_OWNER_PID") || return $?
    LOCK_OWNED=1
    export KEEN_PBR_UPDATE_LOCK_PID="$LOCK_OWNER_PID"
    export KEEN_PBR_UPDATE_LOCK_TOKEN="$LOCK_TOKEN"
}

release_update_lock() {
    [ "$LOCK_OWNED" -eq 1 ] || return 0
    "$LOCK_HELPER" release "$LOCK_OWNER_PID" "$LOCK_TOKEN" || return 1
    LOCK_OWNED=0
}

cleanup_process() {
    status=$?
    [ "$RUN_FILE_OWNED" -eq 0 ] || rm -f "$RUN_FILE"
    release_update_lock || true
    trap - EXIT INT TERM
    exit "$status"
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
        if "$KEEN_PBR_INIT" check >/dev/null 2>&1 &&
           "$TRANSPORT_INIT" check >/dev/null 2>&1; then
            http_code=""
            if [ -x "$OPT_CURL" ]; then
                http_code=$("$OPT_CURL" -sS -o /dev/null \
                    -w '%{http_code}' --connect-timeout 2 \
                    --max-time 4 \
                    "$health_url" 2>/dev/null || true)
            elif command -v curl >/dev/null 2>&1; then
                http_code=$(curl -sS -o /dev/null \
                    -w '%{http_code}' --connect-timeout 2 \
                    --max-time 4 \
                    "$health_url" 2>/dev/null || true)
            elif [ -x "$OPT_WGET" ]; then
                "$OPT_WGET" -q -T 4 -O /dev/null "$health_url" 2>/dev/null &&
                    http_code=200
            elif command -v wget >/dev/null 2>&1; then
                wget -q -T 4 -O /dev/null "$health_url" 2>/dev/null &&
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

stop_runtime() {
    [ -x "$KEEN_PBR_INIT" ] && [ -x "$TRANSPORT_INIT" ] || return 1
    stop_failed=0
    if ! "$KEEN_PBR_INIT" stop >/dev/null 2>&1; then
        "$KEEN_PBR_INIT" check >/dev/null 2>&1 && stop_failed=1
    fi
    if ! "$TRANSPORT_INIT" stop >/dev/null 2>&1; then
        "$TRANSPORT_INIT" check >/dev/null 2>&1 && stop_failed=1
    fi
    [ "$stop_failed" -eq 0 ]
}

restart_runtime() {
    "$TRANSPORT_INIT" restart >/dev/null 2>&1 || return 1
    "$KEEN_PBR_INIT" restart >/dev/null 2>&1 || return 1
}

opkg_install_archive() {
    archive=$1
    valid_ipk_file "$archive" || return 2
    PKG_UPGRADE=1 \
        KEEN_PBR_REPLACE_DNSMASQ_DEFAULTS=N \
        "$OPKG" --force-reinstall install "$archive"
}

INSTALL_COMPENSATED=0
install_archive() {
    archive=$1
    config_snapshot=$2
    compensation_archive=${3:-}
    compensation_snapshot=${4:-}
    INSTALL_COMPENSATED=0

    valid_ipk_file "$archive" || return 2
    validate_snapshot "$config_snapshot" || return 2
    if [ -n "$compensation_archive" ] || [ -n "$compensation_snapshot" ]; then
        valid_ipk_file "$compensation_archive" &&
            validate_snapshot "$compensation_snapshot" ||
            return 2
    fi

    # postinst starts both services while PENDING deliberately protects this
    # transaction. Let only descendants of this locked rescue operation bypass
    # the boot guard, otherwise postinst would recursively invoke recovery.
    export KEEN_PBR_RESCUE_TRANSACTION=1

    # The target snapshot must be live before opkg invokes the target package's
    # postinst. Otherwise an older daemon can be started with a newer schema.
    if stop_runtime &&
       restore_config "$config_snapshot" &&
       opkg_install_archive "$archive" &&
       restore_config "$config_snapshot" &&
       restart_runtime &&
       verify_runtime; then
        return 0
    fi

    echo "Target package did not become healthy; attempting compensation" >&2
    if [ -n "$compensation_archive" ]; then
        if stop_runtime &&
           restore_config "$compensation_snapshot" &&
           opkg_install_archive "$compensation_archive" &&
           restore_config "$compensation_snapshot" &&
           restart_runtime &&
           verify_runtime; then
            INSTALL_COMPENSATED=1
            return 1
        fi
    elif [ -n "$compensation_snapshot" ]; then
        restore_config "$compensation_snapshot" >/dev/null 2>&1 || true
        restart_runtime >/dev/null 2>&1 || true
    fi

    mark_unknown "package install or runtime verification failed and compensation was not verified"
    return 1
}

stage_candidate() {
    source_ipk=$1
    ensure_known_idle || return 3
    valid_ipk_payload "$source_ipk" || {
        echo "Candidate IPK is missing, empty, or a symlink: $source_ipk" >&2
        return 2
    }

    cleanup_pending_artifacts || return 1
    import_file_from "$source_ipk" "$CANDIDATE_IPK" || return 1
    snapshot_config "$PRE_UPDATE_CONFIG" || {
        rm -f "$CANDIDATE_IPK" "${CANDIDATE_IPK}.sha256"
        return 1
    }
    if valid_ipk_file "$CURRENT_IPK"; then
        replace_file_from "$CURRENT_IPK" "$PENDING_BASELINE_IPK" || {
            cleanup_pending_artifacts
            return 1
        }
    elif valid_ipk_payload "$CURRENT_IPK"; then
        # One-time migration from releases predating at-rest hash sidecars.
        import_file_from "$CURRENT_IPK" "$PENDING_BASELINE_IPK" || {
            cleanup_pending_artifacts
            return 1
        }
    elif [ -e "$CURRENT_IPK" ] || [ -L "$CURRENT_IPK" ] ||
         [ -e "${CURRENT_IPK}.sha256" ] ||
         [ -L "${CURRENT_IPK}.sha256" ]; then
        cleanup_pending_artifacts
        echo "Current rescue IPK is incomplete or corrupted" >&2
        return 2
    fi
    write_pending candidate-staged || {
        pending_status=$?
        [ "$pending_status" -eq 74 ] ||
            cleanup_pending_artifacts
        return 1
    }
    sync
}

promote_candidate() {
    phase=$(pending_phase) || return 2
    [ "$phase" = "candidate-staged" ] || return 2
    valid_ipk_file "$CANDIDATE_IPK" &&
        validate_snapshot "$PRE_UPDATE_CONFIG" ||
        return 2
    write_pending candidate-promoting || return 1

    if valid_ipk_file "$PENDING_BASELINE_IPK"; then
        replace_file_from "$PENDING_BASELINE_IPK" "$PREVIOUS_IPK" &&
            copy_snapshot "$PRE_UPDATE_CONFIG" "$PREVIOUS_CONFIG" ||
            return 1
    elif [ -e "$PENDING_BASELINE_IPK" ] ||
         [ -L "$PENDING_BASELINE_IPK" ] ||
         [ -e "${PENDING_BASELINE_IPK}.sha256" ] ||
         [ -L "${PENDING_BASELINE_IPK}.sha256" ]; then
        return 2
    else
        rm -f "$PREVIOUS_IPK" "${PREVIOUS_IPK}.sha256" || return 1
        rm -rf "$PREVIOUS_CONFIG" || return 1
    fi
    replace_file_from "$CANDIDATE_IPK" "$CURRENT_IPK" || return 1
    sync
    clear_pending
}

rollback_candidate() {
    phase=$(pending_phase) || return 2
    case "$phase" in
        candidate-staged|candidate-promoting) ;;
        *) return 2 ;;
    esac
    valid_ipk_file "$PENDING_BASELINE_IPK" &&
        validate_snapshot "$PRE_UPDATE_CONFIG" || {
            mark_unknown "candidate rollback has no verified baseline"
            return 2
        }

    if ! install_archive "$PENDING_BASELINE_IPK" "$PRE_UPDATE_CONFIG"; then
        return 1
    fi
    replace_file_from "$PENDING_BASELINE_IPK" "$CURRENT_IPK" || {
        mark_unknown "candidate rollback restored runtime but not package metadata"
        return 1
    }
    if [ "$phase" = "candidate-promoting" ]; then
        # Promotion may have replaced only one half of the previous pair.
        # Sacrifice the older history instead of advertising a mismatched pair.
        rm -f "$PREVIOUS_IPK" "${PREVIOUS_IPK}.sha256" || return 1
        rm -rf "$PREVIOUS_CONFIG" || return 1
    fi
    sync
    clear_pending
}

can_rollback_previous() {
    ensure_known_idle || return 3
    valid_ipk_file "$CURRENT_IPK" && valid_ipk_file "$PREVIOUS_IPK" ||
        return 2
    validate_snapshot "$PREVIOUS_CONFIG" || return 2
}

rollback_previous() {
    can_rollback_previous || return $?
    replace_file_from "$CURRENT_IPK" "$PENDING_BASELINE_IPK" || return 1
    snapshot_config "$PENDING_BASELINE_CONFIG" || {
        cleanup_pending_artifacts
        return 1
    }
    replace_file_from "$PREVIOUS_IPK" "$PENDING_TARGET_IPK" || {
        cleanup_pending_artifacts
        return 1
    }
    copy_snapshot "$PREVIOUS_CONFIG" "$PENDING_TARGET_CONFIG" || {
        cleanup_pending_artifacts
        return 1
    }
    write_pending rollback-previous || {
        pending_status=$?
        [ "$pending_status" -eq 74 ] ||
            cleanup_pending_artifacts
        return 1
    }
    sync

    printf '%s\n' "$$" > "$RUN_FILE" || return 1
    chmod 0600 "$RUN_FILE" || return 1
    RUN_FILE_OWNED=1
    : > "$LOG_FILE" || return 1
    chmod 0600 "$LOG_FILE" || return 1
    exec >>"$LOG_FILE" 2>&1
    write_state rollback 10 "Восстанавливаю предыдущий пакет" null true ||
        true
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting package rollback"
    # The lock and PID already exist, so the API can acknowledge the request
    # before this daemon is stopped by opkg.
    sleep 1

    if ! install_archive \
        "$PENDING_TARGET_IPK" "$PENDING_TARGET_CONFIG" \
        "$PENDING_BASELINE_IPK" "$PENDING_BASELINE_CONFIG"; then
        if [ "$INSTALL_COMPENSATED" -eq 1 ]; then
            clear_pending || true
            write_state failed 100 \
                "Откат не выполнен; текущий пакет восстановлен" false false ||
                true
        else
            write_state unknown 100 \
                "Откат не завершён; требуется ручное восстановление" false false ||
                true
        fi
        echo "Package rollback failed" >&2
        return 1
    fi

    write_pending rollback-swapping || {
        mark_unknown "runtime rollback succeeded but metadata swap could not start"
        return 1
    }
    replace_file_from "$PENDING_TARGET_IPK" "$CURRENT_IPK" &&
        replace_file_from "$PENDING_BASELINE_IPK" "$PREVIOUS_IPK" &&
        copy_snapshot "$PENDING_BASELINE_CONFIG" "$PREVIOUS_CONFIG" || {
            mark_unknown "runtime rollback succeeded but package metadata swap failed"
            return 1
        }
    sync
    clear_pending || {
        mark_unknown "package rollback completed but pending state could not be cleared"
        return 1
    }
    write_state completed 100 "Предыдущий пакет восстановлен" true false ||
        true
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Package rollback completed"
}

recover_pending() {
    phase=$(pending_phase) || return 2
    case "$phase" in
        candidate-staged|candidate-promoting)
            rollback_candidate
            ;;
        rollback-previous|rollback-swapping)
            valid_ipk_file "$PENDING_BASELINE_IPK" &&
                validate_snapshot "$PENDING_BASELINE_CONFIG" &&
                valid_ipk_file "$PENDING_TARGET_IPK" &&
                validate_snapshot "$PENDING_TARGET_CONFIG" || {
                    mark_unknown "interrupted package rollback has incomplete recovery artifacts"
                    return 2
                }
            if ! install_archive \
                "$PENDING_BASELINE_IPK" "$PENDING_BASELINE_CONFIG"; then
                return 1
            fi
            replace_file_from "$PENDING_BASELINE_IPK" "$CURRENT_IPK" &&
                replace_file_from "$PENDING_TARGET_IPK" "$PREVIOUS_IPK" &&
                copy_snapshot "$PENDING_TARGET_CONFIG" "$PREVIOUS_CONFIG" || {
                    mark_unknown "runtime recovered but rescue metadata could not be restored"
                    return 1
                }
            sync
            clear_pending
            ;;
        *)
            return 2
            ;;
    esac
}

recover_startup() {
    [ ! -e "$UNKNOWN_FILE" ] && [ ! -L "$UNKNOWN_FILE" ] || return 3
    if [ ! -e "$PENDING_FILE" ] && [ ! -L "$PENDING_FILE" ]; then
        return 0
    fi
    if ! recover_pending; then
        if [ ! -e "$UNKNOWN_FILE" ] && [ ! -L "$UNKNOWN_FILE" ]; then
            mark_unknown "automatic startup recovery failed" || true
        fi
        return 1
    fi
    ensure_known_idle
}

status_json() {
    pending=false
    unknown=false
    [ ! -e "$PENDING_FILE" ] || pending=true
    [ ! -e "$UNKNOWN_FILE" ] || unknown=true
    ready=false
    valid_ipk_file "$CURRENT_IPK" && [ "$unknown" = false ] &&
        [ "$pending" = false ] && ready=true
    rollback_available=false
    if [ "$unknown" = false ] && [ "$pending" = false ] &&
       valid_ipk_file "$PREVIOUS_IPK" &&
       validate_snapshot "$PREVIOUS_CONFIG"; then
        rollback_available=true
    fi
    printf '{"ready":%s,"rollback_available":%s,"pending":%s,"unknown":%s}\n' \
        "$ready" "$rollback_available" "$pending" "$unknown"
}

command=${1:-}
case "$command" in
    status|can-rollback-previous)
        if [ "$command" = status ]; then
            [ "$#" -eq 1 ] || exit 2
            status_json
        else
            [ "$#" -eq 1 ] || exit 2
            can_rollback_previous
        fi
        exit $?
        ;;
    *)
        acquire_update_lock || {
            echo "Another keen-pbr update or rollback is active" >&2
            exit 75
        }
        trap cleanup_process EXIT
        trap 'exit 130' INT TERM
        ;;
esac

case "$command" in
    stage)
        [ "$#" -eq 2 ] || exit 2
        stage_candidate "$2"
        ;;
    verify)
        [ "$#" -eq 1 ] || exit 2
        verify_runtime
        ;;
    promote)
        [ "$#" -eq 1 ] || exit 2
        promote_candidate
        ;;
    rollback-candidate)
        [ "$#" -eq 1 ] || exit 2
        rollback_candidate
        ;;
    rollback-previous)
        [ "$#" -eq 1 ] || exit 2
        rollback_previous
        ;;
    recover-startup)
        [ "$#" -eq 1 ] || exit 2
        recover_startup
        ;;
    recover-pending)
        [ "$#" -eq 1 ] || exit 2
        recover_pending
        ;;
    *)
        echo "Usage: $0 {stage IPK|verify|promote|rollback-candidate|rollback-previous|recover-startup|recover-pending|can-rollback-previous|status}" >&2
        exit 2
        ;;
esac
