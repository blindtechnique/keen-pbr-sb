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

LOCK_DIR="${ROOT}/opt/var/run/keen-pbr-update.lock"
CLEANUP_LOCK="${LOCK_DIR}.cleanup"
OWNER_FILE="$LOCK_DIR/owner"
PROVISIONAL_FILE="$LOCK_DIR/provisional"
GENERATION_DIR="${ROOT}/opt/var/lib/keen-pbr"
GENERATION_FILE="$GENERATION_DIR/maintenance-generation"
RESCUE_DIR="${ROOT}/opt/var/lib/keen-pbr/rescue"
CLEANUP_OWNED=0
GUARD_OWNER_PID=
GUARD_TOKEN=
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

valid_operation() {
    operation=${1:-}
    [ "${#operation}" -le 32 ] || return 1
    case "$operation" in
        ''|[!a-z]*|*[!a-z0-9-]*) return 1 ;;
    esac
}

operation_from_token() {
    token=${1:-}
    operation=${token%%.*}
    if valid_operation "$operation"; then
        printf '%s\n' "$operation"
    else
        # Tokens issued by protocol v2 started with a numeric PID. Keep them
        # identifiable as package maintenance while old releases are still
        # eligible for rescue rollback.
        printf '%s\n' "legacy-update"
    fi
}

valid_token() {
    checked_token=${1:-}
    [ "${#checked_token}" -ge 3 ] || return 1
    [ "${#checked_token}" -le 192 ] || return 1
    case "$checked_token" in
        ''|*[!A-Za-z0-9._-]*) return 1 ;;
    esac
}

canonical_unsigned() {
    case "${1:-}" in
        ''|*[!0-9]*) return 1 ;;
    esac
    case "$1" in
        0|[1-9]|[1-9][0-9]*) return 0 ;;
        *) return 1 ;;
    esac
}

valid_generation() {
    canonical_unsigned "${1:-}" || return 1
    [ "$1" -le 2147483646 ] 2>/dev/null
}

stat_value() {
    keen_pbr_stat_value "$1" "$2"
}

effective_uid() {
    if [ -x "${ROOT}/opt/bin/id" ]; then
        "${ROOT}/opt/bin/id" -u
    elif command -v id >/dev/null 2>&1; then
        id -u
    else
        return 1
    fi
}

path_owned_by_caller() {
    target_uid=$(stat_value '%u' "$1") || return 1
    caller_uid=$(effective_uid) || return 1
    [ "$target_uid" = "$caller_uid" ]
}

file_mode_is() {
    expected_mode=$1
    actual_mode=$(stat_value '%a' "$2") || return 1
    [ "$actual_mode" = "$expected_mode" ]
}

metadata_file_is_safe() {
    metadata_path=$1
    metadata_mode=${2:-600}
    [ -f "$metadata_path" ] && [ ! -L "$metadata_path" ] ||
        return 1
    path_owned_by_caller "$metadata_path" || return 1
    file_mode_is "$metadata_mode" "$metadata_path"
}

create_private_file_exclusive() {
    private_path=$1
    [ ! -e "$private_path" ] && [ ! -L "$private_path" ] ||
        return 1
    if ! (set -C; : > "$private_path") 2>/dev/null; then
        return 1
    fi
    chmod 0600 "$private_path" || {
        rm -f "$private_path" 2>/dev/null || true
        return 1
    }
    metadata_file_is_safe "$private_path" 600
}

# Read exactly one newline-terminated ASCII line. Merely using `read` would
# accept a valid first line followed by attacker-controlled trailing bytes.
read_exact_line() {
    exact_path=$1
    exact_line=
    IFS= read -r exact_line < "$exact_path" || return 1
    exact_bytes=$(wc -c < "$exact_path") || return 1
    [ "$exact_bytes" -eq $((${#exact_line} + 1)) ] 2>/dev/null
}

# Old bootstrap helpers wrote 0644 sidecars. They remain readable for rolling
# upgrades, but group/world-writable legacy metadata is never trusted.
legacy_metadata_file_is_safe() {
    legacy_path=$1
    [ -f "$legacy_path" ] && [ ! -L "$legacy_path" ] ||
        return 1
    path_owned_by_caller "$legacy_path" || return 1
    legacy_mode=$(stat_value '%a' "$legacy_path") || return 1
    [ "$legacy_mode" = "600" ] || [ "$legacy_mode" = "644" ]
}

directory_permissions_are_safe() {
    permissions=$(stat_value '%a' "$1") || return 1
    case "$permissions" in
        [0-7][0-7][0-7]) ;;
        *) return 1 ;;
    esac
    group_and_other=${permissions#?}
    case "$group_and_other" in
        *[2367]*) return 1 ;;
    esac
    return 0
}

lock_directory_is_safe() {
    [ -d "$LOCK_DIR" ] && [ ! -L "$LOCK_DIR" ] ||
        return 1
    path_owned_by_caller "$LOCK_DIR" || return 1
    file_mode_is 700 "$LOCK_DIR"
}

generation_directory_is_safe() {
    if [ -L "$GENERATION_DIR" ] ||
       { [ -e "$GENERATION_DIR" ] && [ ! -d "$GENERATION_DIR" ]; }; then
        return 1
    fi
    if [ -d "$GENERATION_DIR" ]; then
        path_owned_by_caller "$GENERATION_DIR" &&
            directory_permissions_are_safe "$GENERATION_DIR" ||
            return 1
    fi
    return 0
}

read_generation() {
    generation_directory_is_safe || return 1
    if [ -L "$GENERATION_FILE" ]; then
        return 1
    fi
    if [ ! -e "$GENERATION_FILE" ]; then
        printf '%s\n' "0"
        return 0
    fi
    [ -f "$GENERATION_FILE" ] || return 1
    metadata_file_is_safe "$GENERATION_FILE" 600 || return 1
    read_exact_line "$GENERATION_FILE" || return 1
    generation=$exact_line
    valid_generation "$generation" || return 1
    printf '%s\n' "$generation"
}

ensure_generation_directory() {
    generation_directory_is_safe || return 1
    if [ ! -d "$GENERATION_DIR" ]; then
        mkdir -p "$GENERATION_DIR" || return 1
        generation_directory_is_safe || return 1
        chmod 0700 "$GENERATION_DIR" || return 1
    fi
}

sync_generation() {
    command -v sync >/dev/null 2>&1 || return 1
    # BusyBox and coreutils both support a full sync. Newer variants support
    # sync -f, which avoids flushing unrelated storage on every rare config
    # mutation. Falling back to full sync keeps the rescue helper portable.
    if sync -f "$GENERATION_FILE" >/dev/null 2>&1 &&
       sync -f "$GENERATION_DIR" >/dev/null 2>&1; then
        return 0
    fi
    sync >/dev/null 2>&1
}

valid_pid() {
    canonical_unsigned "${1:-}" || return 1
    [ "$1" -gt 1 ] 2>/dev/null
}

process_state() {
    pid=${1:-}
    valid_pid "$pid" || return 1
    [ -r "/proc/$pid/stat" ] || return 1
    stat_line=$(cat "/proc/$pid/stat") || return 1
    stat_tail=${stat_line##*) }
    set -- $stat_tail
    [ "$#" -ge 20 ] || return 1
    case "${1:-}" in
        [A-Za-z]) printf '%s\n' "$1" ;;
        *) return 1 ;;
    esac
}

pid_is_alive() {
    valid_pid "${1:-}" && kill -0 "$1" 2>/dev/null || return 1
    state=$(process_state "$1") || return 1
    case "$state" in
        Z|X|x) return 1 ;;
    esac
    return 0
}

process_start_time() {
    pid=${1:-}
    valid_pid "$pid" || return 1
    [ -r "/proc/$pid/stat" ] || return 1
    stat_line=$(cat "/proc/$pid/stat") || return 1
    stat_tail=${stat_line##*) }
    set -- $stat_tail
    [ "$#" -ge 20 ] || return 1
    start_time=${20}
    canonical_unsigned "$start_time" || return 1
    printf '%s\n' "$start_time"
}

pid_identity_is_alive() {
    pid=${1:-}
    expected_start=${2:-}
    pid_is_alive "$pid" || return 1
    canonical_unsigned "$expected_start" || return 1
    actual_start=$(process_start_time "$pid") || return 1
    [ "$actual_start" = "$expected_start" ]
}

ready_marker_is_safe() {
    ready_path=$1
    legacy_metadata_file_is_safe "$ready_path" || return 1
    read_exact_line "$ready_path" || return 1
    [ "$exact_line" = "ready" ]
}

read_authoritative_owner() {
    metadata_file_is_safe "$OWNER_FILE" 600 || return 1
    read_exact_line "$OWNER_FILE" || return 1
    owner_pid=
    owner_start=
    owner_token=
    owner_extra=
    IFS=' ' read -r owner_pid owner_start owner_token owner_extra <<EOF
$exact_line
EOF
    [ -z "$owner_extra" ] || return 1
    valid_pid "$owner_pid" || return 1
    canonical_unsigned "$owner_start" || return 1
    valid_token "$owner_token" || return 1
    [ "$exact_line" = "$owner_pid $owner_start $owner_token" ]
}

read_legacy_owner() {
    # Compatibility with the lock published by the bootstrap installer just
    # before the protocol-2/3 helper is copied into place.
    legacy_metadata_file_is_safe "$LOCK_DIR/pid" &&
        legacy_metadata_file_is_safe "$LOCK_DIR/start" &&
        legacy_metadata_file_is_safe "$LOCK_DIR/token" ||
        return 1
    read_exact_line "$LOCK_DIR/pid" || return 1
    owner_pid=$exact_line
    read_exact_line "$LOCK_DIR/start" || return 1
    owner_start=$exact_line
    read_exact_line "$LOCK_DIR/token" || return 1
    owner_token=$exact_line
    valid_pid "$owner_pid" || return 1
    canonical_unsigned "$owner_start" || return 1
    valid_token "$owner_token"
}

load_owner_metadata() {
    if [ -e "$OWNER_FILE" ] || [ -L "$OWNER_FILE" ]; then
        read_authoritative_owner || return 1
        # Sidecars are not authoritative after protocol 2, so their values may
        # briefly lag an atomic owner transfer. Their filesystem identity must
        # still be safe because older installed readers may inspect them.
        legacy_metadata_file_is_safe "$LOCK_DIR/pid" &&
            legacy_metadata_file_is_safe "$LOCK_DIR/start" &&
            legacy_metadata_file_is_safe "$LOCK_DIR/token"
    else
        read_legacy_owner
    fi
}

read_owner_record() {
    lock_directory_is_safe || return 1
    if [ -e "$OWNER_FILE" ] || [ -L "$OWNER_FILE" ]; then
        metadata_file_is_safe "$LOCK_DIR/ready" 600 || return 1
        read_exact_line "$LOCK_DIR/ready" || return 1
        [ "$exact_line" = "ready" ] || return 1
    else
        ready_marker_is_safe "$LOCK_DIR/ready" || return 1
    fi
    load_owner_metadata
}

read_provisional_record() {
    metadata_file_is_safe "$PROVISIONAL_FILE" 600 || return 1
    read_exact_line "$PROVISIONAL_FILE" || return 1
    provisional_pid=
    provisional_start=
    provisional_extra=
    IFS=' ' read -r provisional_pid provisional_start provisional_extra <<EOF
$exact_line
EOF
    [ -z "$provisional_extra" ] || return 1
    valid_pid "$provisional_pid" || return 1
    canonical_unsigned "$provisional_start" || return 1
    [ "$exact_line" = "$provisional_pid $provisional_start" ]
}

# 0 = active, 1 = stale and safe to reap, 2 = unsafe/ambiguous.
lock_record_state() {
    lock_directory_is_safe || return 2
    if [ -e "$LOCK_DIR/ready" ] || [ -L "$LOCK_DIR/ready" ]; then
        read_owner_record || return 2
        if pid_identity_is_alive "$owner_pid" "$owner_start"; then
            return 0
        fi
        return 1
    fi

    # During publication, the helper identity is authoritative. It is written
    # immediately after mkdir and removed only after a complete owner record
    # exists. Missing or malformed provisional state is fail-closed: a live
    # publisher paused between filesystem operations must never lose its lock.
    if [ -e "$PROVISIONAL_FILE" ] || [ -L "$PROVISIONAL_FILE" ]; then
        read_provisional_record || return 2
        if pid_identity_is_alive "$provisional_pid" "$provisional_start"; then
            return 0
        fi
        return 1
    fi

    if load_owner_metadata 2>/dev/null; then
        if pid_identity_is_alive "$owner_pid" "$owner_start"; then
            return 0
        fi
        return 1
    fi
    return 2
}

read_owner_pid() {
    read_owner_record || return 1
    printf '%s\n' "$owner_pid"
}

owner_is_active() {
    read_owner_record || return 1
    pid_identity_is_alive "$owner_pid" "$owner_start"
}

release_cleanup_guard() {
    [ "$CLEANUP_OWNED" -eq 1 ] || return 0
    rm -f "$CLEANUP_LOCK/ready" "$CLEANUP_LOCK/pid" \
        "$CLEANUP_LOCK/start" "$CLEANUP_LOCK/provisional" \
        2>/dev/null || true
    rmdir "$CLEANUP_LOCK" 2>/dev/null || true
    CLEANUP_OWNED=0
}

cleanup_directory_is_safe() {
    [ -d "$CLEANUP_LOCK" ] && [ ! -L "$CLEANUP_LOCK" ] ||
        return 1
    path_owned_by_caller "$CLEANUP_LOCK" || return 1
    file_mode_is 700 "$CLEANUP_LOCK"
}

read_cleanup_identity() {
    cleanup_prefix=$1
    legacy_metadata_file_is_safe "$CLEANUP_LOCK/${cleanup_prefix}pid" &&
        legacy_metadata_file_is_safe "$CLEANUP_LOCK/${cleanup_prefix}start" ||
        return 1
    read_exact_line "$CLEANUP_LOCK/${cleanup_prefix}pid" || return 1
    cleanup_pid=$exact_line
    read_exact_line "$CLEANUP_LOCK/${cleanup_prefix}start" || return 1
    cleanup_start=$exact_line
    valid_pid "$cleanup_pid" || return 1
    canonical_unsigned "$cleanup_start"
}

# 0 = active, 1 = stale, 2 = unsafe.
cleanup_record_state() {
    cleanup_directory_is_safe || return 2
    if [ -e "$CLEANUP_LOCK/ready" ] || [ -L "$CLEANUP_LOCK/ready" ]; then
        ready_marker_is_safe "$CLEANUP_LOCK/ready" || return 2
        read_cleanup_identity "" || return 2
    elif [ -e "$CLEANUP_LOCK/provisional" ] ||
         [ -L "$CLEANUP_LOCK/provisional" ]; then
        metadata_file_is_safe "$CLEANUP_LOCK/provisional" 600 || return 2
        read_exact_line "$CLEANUP_LOCK/provisional" || return 2
        cleanup_pid=
        cleanup_start=
        cleanup_extra=
        IFS=' ' read -r cleanup_pid cleanup_start cleanup_extra <<EOF
$exact_line
EOF
        [ -z "$cleanup_extra" ] || return 2
        valid_pid "$cleanup_pid" || return 2
        canonical_unsigned "$cleanup_start" || return 2
        [ "$exact_line" = "$cleanup_pid $cleanup_start" ] || return 2
    else
        return 2
    fi
    if pid_identity_is_alive "$cleanup_pid" "$cleanup_start"; then
        return 0
    fi
    return 1
}

acquire_cleanup_guard() {
    attempts=0
    while [ "$attempts" -lt 2 ]; do
        if mkdir "$CLEANUP_LOCK" 2>/dev/null; then
            chmod 0700 "$CLEANUP_LOCK" || {
                rmdir "$CLEANUP_LOCK" 2>/dev/null || true
                return 1
            }
            cleanup_start=$(process_start_time "$$") || {
                rmdir "$CLEANUP_LOCK" 2>/dev/null || true
                return 1
            }
            if ! printf '%s %s\n' "$$" "$cleanup_start" \
                    > "$CLEANUP_LOCK/provisional" ||
               ! chmod 0600 "$CLEANUP_LOCK/provisional" ||
               ! printf '%s\n' "$$" > "$CLEANUP_LOCK/pid" ||
               ! printf '%s\n' "$cleanup_start" > "$CLEANUP_LOCK/start" ||
               ! chmod 0600 "$CLEANUP_LOCK/pid" "$CLEANUP_LOCK/start" \
                    "$CLEANUP_LOCK/provisional" ||
               ! rm -f "$CLEANUP_LOCK/provisional" ||
               ! printf 'ready\n' > "$CLEANUP_LOCK/ready" ||
               ! chmod 0600 "$CLEANUP_LOCK/ready"; then
                rm -f "$CLEANUP_LOCK/ready" "$CLEANUP_LOCK/pid" \
                    "$CLEANUP_LOCK/start" "$CLEANUP_LOCK/provisional"
                rmdir "$CLEANUP_LOCK" 2>/dev/null || true
                return 1
            fi
            CLEANUP_OWNED=1
            return 0
        fi

        cleanup_record_state
        cleanup_state=$?
        [ "$cleanup_state" -eq 1 ] || return 1
        rm -f "$CLEANUP_LOCK/ready" "$CLEANUP_LOCK/pid" \
            "$CLEANUP_LOCK/start" "$CLEANUP_LOCK/provisional" \
            2>/dev/null || true
        rmdir "$CLEANUP_LOCK" 2>/dev/null || return 1
        attempts=$((attempts + 1))
    done
    return 1
}

remove_stale_lock() {
    acquire_cleanup_guard || return 1

    lock_record_state
    record_state=$?
    if [ "$record_state" -ne 1 ]; then
        release_cleanup_guard
        return 1
    fi

    # Refuse recursive deletion. Only protocol-owned names are removed, and an
    # unknown entry deliberately leaves the directory non-empty/fail-closed.
    rm -f "$LOCK_DIR/ready" "$OWNER_FILE" "$PROVISIONAL_FILE" \
        "$LOCK_DIR/token" "$LOCK_DIR/pid" "$LOCK_DIR/start" \
        "$LOCK_DIR/owner.pending" "$LOCK_DIR/pid.pending" \
        "$LOCK_DIR/start.pending" "$LOCK_DIR/ready.pending" \
        2>/dev/null || true
    if ! rmdir "$LOCK_DIR" 2>/dev/null; then
        release_cleanup_guard
        return 1
    fi

    release_cleanup_guard
    return 0
}

acquire_lock() {
    requested_pid=${1:-}
    requested_operation=${2:-legacy-update}
    requested_token=${3:-}
    valid_pid "$requested_pid" || return 2
    valid_operation "$requested_operation" || return 2
    if [ -n "$requested_token" ]; then
        valid_token "$requested_token" || return 2
        [ "$(operation_from_token "$requested_token")" = \
            "$requested_operation" ] || return 2
    fi
    pid_is_alive "$requested_pid" || return 2
    requested_start=$(process_start_time "$requested_pid") || return 2
    mkdir -p "$(dirname "$LOCK_DIR")" || return 1

    attempts=0
    while [ "$attempts" -lt 2 ]; do
        if mkdir "$LOCK_DIR" 2>/dev/null; then
            chmod 0700 "$LOCK_DIR" || {
                rmdir "$LOCK_DIR" 2>/dev/null || true
                return 1
            }
            publisher_start=$(process_start_time "$$") || {
                rmdir "$LOCK_DIR" 2>/dev/null || true
                return 1
            }
            if ! printf '%s %s\n' "$$" "$publisher_start" \
                    > "$PROVISIONAL_FILE" ||
               ! chmod 0600 "$PROVISIONAL_FILE"; then
                rm -f "$PROVISIONAL_FILE" 2>/dev/null || true
                rmdir "$LOCK_DIR" 2>/dev/null || true
                return 1
            fi
            if [ -n "$ROOT" ] &&
               [ "${KEEN_PBR_UPDATE_LOCK_TEST_PAUSE_AFTER_PROVISIONAL:-0}" = "1" ]; then
                pause_marker="${LOCK_DIR}.test-publish-paused"
                : > "$pause_marker" || return 1
                chmod 0600 "$pause_marker" || return 1
                while [ -e "$pause_marker" ]; do
                    sleep 1
                done
            fi
            if [ -n "$requested_token" ]; then
                token=$requested_token
            else
                token="${requested_operation}.${requested_pid}.$$.$(date +%s)"
            fi
            owner_tmp="$LOCK_DIR/owner.pending"
            ready_tmp="$LOCK_DIR/ready.pending"
            if ! create_private_file_exclusive "$owner_tmp" ||
               ! create_private_file_exclusive "$ready_tmp"; then
                rm -f "$owner_tmp" "$ready_tmp" "$PROVISIONAL_FILE" \
                    "$LOCK_DIR/token" "$LOCK_DIR/pid" "$LOCK_DIR/start"
                rmdir "$LOCK_DIR" 2>/dev/null || true
                return 1
            fi
            if printf '%s\n' "$requested_pid" > "$LOCK_DIR/pid" &&
               printf '%s\n' "$requested_start" > "$LOCK_DIR/start" &&
               printf '%s\n' "$token" > "$LOCK_DIR/token" &&
               printf '%s %s %s\n' "$requested_pid" "$requested_start" \
                    "$token" > "$owner_tmp" &&
               chmod 0600 "$LOCK_DIR/pid" "$LOCK_DIR/start" \
                    "$LOCK_DIR/token" "$owner_tmp" &&
               mv -f "$owner_tmp" "$OWNER_FILE" &&
               rm -f "$PROVISIONAL_FILE" &&
               printf 'ready\n' > "$ready_tmp" &&
               chmod 0600 "$ready_tmp" &&
               mv -f "$ready_tmp" "$LOCK_DIR/ready"; then
                if ! read_owner_record; then
                    rm -f "$LOCK_DIR/ready" "$OWNER_FILE" \
                        "$LOCK_DIR/token" "$LOCK_DIR/pid" \
                        "$LOCK_DIR/start" "$PROVISIONAL_FILE" \
                        "$owner_tmp" "$ready_tmp"
                    rmdir "$LOCK_DIR" 2>/dev/null || true
                    return 1
                fi
                printf '%s\n' "$token"
                return 0
            fi
            rm -f "$LOCK_DIR/ready" "$OWNER_FILE" "$owner_tmp" "$ready_tmp" \
                "$PROVISIONAL_FILE" "$LOCK_DIR/token" "$LOCK_DIR/pid" \
                "$LOCK_DIR/start"
            rmdir "$LOCK_DIR" 2>/dev/null || true
            return 1
        fi

        lock_record_state
        record_state=$?
        if [ "$record_state" -eq 0 ]; then
            return 75
        fi
        [ "$record_state" -eq 1 ] || return 75
        remove_stale_lock || return 75
        attempts=$((attempts + 1))
    done
    return 75
}

lock_is_held_by() {
    requested_pid=${1:-}
    requested_token=${2:-}
    valid_pid "$requested_pid" || return 1
    [ -n "$requested_token" ] || return 1
    read_owner_record || return 1
    [ "$owner_pid" = "$requested_pid" ] || return 1
    [ "$owner_token" = "$requested_token" ] || return 1
    pid_identity_is_alive "$owner_pid" "$owner_start"
}

transfer_lock() {
    requested_pid=${1:-}
    requested_token=${2:-}
    replacement_pid=${3:-}
    lock_is_held_by "$requested_pid" "$requested_token" || return 1
    valid_pid "$replacement_pid" && pid_is_alive "$replacement_pid" ||
        return 1
    replacement_start=$(process_start_time "$replacement_pid") || return 1
    owner_tmp="$LOCK_DIR/owner.pending"
    pid_tmp="$LOCK_DIR/pid.pending"
    start_tmp="$LOCK_DIR/start.pending"
    if ! create_private_file_exclusive "$owner_tmp" ||
       ! create_private_file_exclusive "$pid_tmp" ||
       ! create_private_file_exclusive "$start_tmp"; then
        rm -f "$owner_tmp" "$pid_tmp" "$start_tmp" 2>/dev/null || true
        return 1
    fi
    if ! printf '%s %s %s\n' "$replacement_pid" "$replacement_start" \
            "$requested_token" > "$owner_tmp" ||
       ! printf '%s\n' "$replacement_pid" > "$pid_tmp" ||
       ! printf '%s\n' "$replacement_start" > "$start_tmp" ||
       ! chmod 0600 "$owner_tmp" "$pid_tmp" "$start_tmp" ||
       ! mv -f "$start_tmp" "$LOCK_DIR/start" ||
       ! mv -f "$pid_tmp" "$LOCK_DIR/pid"; then
        rm -f "$owner_tmp" "$pid_tmp" "$start_tmp"
        return 1
    fi
    # Tests can stop at the last pre-commit point only under an alternate
    # rescue root. Production never exposes a fault-injection switch.
    if [ -n "$ROOT" ] &&
       [ "${KEEN_PBR_UPDATE_LOCK_TEST_FAIL_BEFORE_COMMIT:-0}" = "1" ]; then
        rm -f "$owner_tmp"
        return 1
    fi
    # OWNER_FILE is the sole commit point. No fallible filesystem operation is
    # allowed after this rename: callers may now safely change their own view
    # of lock ownership.
    if ! mv -f "$owner_tmp" "$OWNER_FILE"; then
        rm -f "$owner_tmp"
        return 1
    fi
    printf '%s\n' "$requested_token"
    return 0
}

release_lock() {
    requested_pid=${1:-}
    requested_token=${2:-}
    lock_is_held_by "$requested_pid" "$requested_token" || return 1
    rm -f "$LOCK_DIR/ready" "$OWNER_FILE" "$LOCK_DIR/token" "$LOCK_DIR/pid" \
        "$LOCK_DIR/start" || return 1
    rmdir "$LOCK_DIR"
}

release_lock_and_cleanup_rescue() {
    requested_pid=${1:-}
    requested_token=${2:-}
    lock_is_held_by "$requested_pid" "$requested_token" || return 1
    [ "$(operation_from_token "$requested_token")" = "uninstall" ] || return 1

    # Remove canonical helper names while the uninstall lock is still held.
    # This script and the metadata functions are already loaded in the current
    # process, so unlinking them does not prevent the final lock release. A new
    # installer can only enter after rmdir(LOCK_DIR), at which point it sees no
    # stale helpers and uses its verified-IPK bootstrap/fallback path.
    rm -f \
        "${ROOT}/opt/etc/init.d/S00keen-pbr-rescue" \
        "$RESCUE_DIR/rescue-update.sh" \
        "$RESCUE_DIR/portable-stat.sh" \
        "$RESCUE_DIR/update-lock.sh" ||
        return 1
    release_lock "$requested_pid" "$requested_token"
}

reserve_generation() {
    requested_pid=${1:-}
    requested_token=${2:-}
    expected_generation=${3:-}
    lock_is_held_by "$requested_pid" "$requested_token" || return 1
    case "$expected_generation" in
        -) ;;
        *)
            valid_generation "$expected_generation" || return 2
            ;;
    esac

    current_generation=$(read_generation) || return 1
    if [ "$expected_generation" != "-" ] &&
       [ "$expected_generation" != "$current_generation" ]; then
        return 73
    fi
    [ "$current_generation" -lt 2147483646 ] 2>/dev/null || return 1
    next_generation=$((current_generation + 1))

    ensure_generation_directory || return 1
    if [ -L "$GENERATION_FILE" ] ||
       { [ -e "$GENERATION_FILE" ] && [ ! -f "$GENERATION_FILE" ]; }; then
        return 1
    fi
    generation_tmp="${GENERATION_FILE}.tmp.$$"
    rm -f "$generation_tmp" 2>/dev/null || return 1
    if ! (set -C; : > "$generation_tmp") 2>/dev/null ||
       [ ! -f "$generation_tmp" ] || [ -L "$generation_tmp" ]; then
        rm -f "$generation_tmp" 2>/dev/null || true
        return 1
    fi
    if ! printf '%s\n' "$next_generation" > "$generation_tmp" ||
       ! chmod 0600 "$generation_tmp"; then
        rm -f "$generation_tmp" 2>/dev/null || true
        return 1
    fi
    path_owned_by_caller "$generation_tmp" &&
        [ "$(stat_value '%a' "$generation_tmp")" = "600" ] || {
        rm -f "$generation_tmp" 2>/dev/null || true
        return 1
    }
    if [ -n "$ROOT" ] &&
       [ "${KEEN_PBR_UPDATE_LOCK_TEST_FAIL_GENERATION_BEFORE_COMMIT:-0}" = "1" ]; then
        rm -f "$generation_tmp" 2>/dev/null || true
        return 1
    fi
    if ! mv -f "$generation_tmp" "$GENERATION_FILE"; then
        rm -f "$generation_tmp" 2>/dev/null || true
        return 1
    fi
    # The rename is the commit point. Exit 74 means the caller must reconcile
    # with `generation`: reporting a plain failure here would make a committed
    # CAS indistinguishable from a pre-commit rejection.
    if { [ -n "$ROOT" ] &&
         [ "${KEEN_PBR_UPDATE_LOCK_TEST_FAIL_GENERATION_AFTER_COMMIT:-0}" = "1" ]; } ||
       ! sync_generation; then
        return 74
    fi
    printf '%s\n' "$next_generation"
}

synchronize_generation() {
    requested_pid=${1:-}
    requested_token=${2:-}
    expected_generation=${3:-}
    lock_is_held_by "$requested_pid" "$requested_token" || return 1
    valid_generation "$expected_generation" || return 2
    current_generation=$(read_generation) || return 1
    [ "$current_generation" = "$expected_generation" ] || return 73
    ensure_generation_directory || return 1

    # This command is the recovery path for a generation already visible
    # after reserve's rename commit. A failure is therefore reported as 74,
    # never as an ordinary pre-commit failure.
    if { [ -n "$ROOT" ] &&
         [ "${KEEN_PBR_UPDATE_LOCK_TEST_FAIL_SYNC_GENERATION:-0}" = "1" ]; } ||
       ! sync_generation; then
        return 74
    fi
    printf '%s\n' "$expected_generation"
}

guardian_release() {
    if [ -n "$GUARD_TOKEN" ]; then
        release_lock "$GUARD_OWNER_PID" "$GUARD_TOKEN" \
            >/dev/null 2>&1 || true
        GUARD_TOKEN=
    fi
}

guard_lock() {
    requested_operation=${1:-}
    valid_operation "$requested_operation" || return 2
    requested_owner_pid=${2:-}
    requested_token=${3:-}
    if [ -n "$requested_owner_pid" ] || [ -n "$requested_token" ]; then
        valid_pid "$requested_owner_pid" || return 2
        pid_is_alive "$requested_owner_pid" || return 2
        valid_token "$requested_token" || return 2
        [ "$(operation_from_token "$requested_token")" = \
            "$requested_operation" ] || return 2
        GUARD_OWNER_PID=$requested_owner_pid
    else
        # Compatibility for protocol-3 shell clients that predate parent-owned
        # leases. Their guardian remains the owner, as before.
        GUARD_OWNER_PID=$$
    fi
    GUARD_TOKEN=$(acquire_lock "$GUARD_OWNER_PID" "$requested_operation" \
        "$requested_token") ||
        return $?
    guard_generation=$(read_generation) || {
        release_lock "$GUARD_OWNER_PID" "$GUARD_TOKEN" \
            >/dev/null 2>&1 || true
        GUARD_TOKEN=
        return 1
    }

    # Signals and unexpected exits deliberately do not release a parent-owned
    # lease. The authoritative owner is still alive and must retain mutual
    # exclusion even if this observer is killed.
    trap 'exit 130' HUP INT TERM
    if ! printf '%s %s %s\n' "$GUARD_OWNER_PID" "$GUARD_TOKEN" \
            "$guard_generation"; then
        guardian_release
        return 1
    fi

    # EOF is the only guardian-owned normal release path. If the long-lived
    # owner crashes, the PID/start-time record becomes stale and the next
    # contender recovers it through the existing cleanup guard.
    while IFS= read -r _guardian_message; do
        :
    done
    guardian_release
}

trap release_cleanup_guard EXIT
trap 'release_cleanup_guard; exit 130' INT TERM

case "${1:-}" in
    version)
        [ "$#" -eq 1 ] || exit 2
        printf '%s\n' "2"
        ;;
    protocol)
        [ "$#" -eq 1 ] || exit 2
        printf '%s\n' "3"
        ;;
    acquire)
        [ "$#" -eq 2 ] || [ "$#" -eq 3 ] || exit 2
        acquire_lock "$2" "${3:-legacy-update}"
        ;;
    held)
        [ "$#" -eq 3 ] || exit 2
        lock_is_held_by "$2" "$3"
        ;;
    operation)
        [ "$#" -eq 3 ] || exit 2
        lock_is_held_by "$2" "$3" || exit 1
        operation_from_token "$3"
        ;;
    transfer)
        [ "$#" -eq 4 ] || exit 2
        transfer_lock "$2" "$3" "$4"
        ;;
    release)
        [ "$#" -eq 3 ] || exit 2
        release_lock "$2" "$3"
        ;;
    release-and-clean)
        [ "$#" -eq 3 ] || exit 2
        release_lock_and_cleanup_rescue "$2" "$3"
        ;;
    owner)
        [ "$#" -eq 1 ] || exit 2
        owner_pid=$(read_owner_pid) || exit 1
        owner_is_active || exit 1
        printf '%s\n' "$owner_pid"
        ;;
    generation)
        [ "$#" -eq 1 ] || exit 2
        read_generation
        ;;
    reserve)
        [ "$#" -eq 4 ] || exit 2
        reserve_generation "$2" "$3" "$4"
        ;;
    sync-generation)
        [ "$#" -eq 4 ] || exit 2
        synchronize_generation "$2" "$3" "$4"
        ;;
    guard)
        [ "$#" -eq 2 ] || [ "$#" -eq 4 ] || exit 2
        guard_lock "$2" "${3:-}" "${4:-}"
        ;;
    *)
        echo "Usage: $0 {version|protocol|acquire PID [OPERATION]|held PID TOKEN|operation PID TOKEN|transfer PID TOKEN NEW_PID|release PID TOKEN|release-and-clean PID TOKEN|owner|generation|reserve PID TOKEN EXPECTED|sync-generation PID TOKEN EXPECTED|guard OPERATION [OWNER_PID TOKEN]}" >&2
        exit 2
        ;;
esac
