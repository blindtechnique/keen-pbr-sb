#!/bin/sh

set -u

ROOT=${KEEN_PBR_RESCUE_ROOT:-}
case "$ROOT" in
    ""|/*) ;;
    *)
        echo "KEEN_PBR_RESCUE_ROOT must be an absolute path" >&2
        exit 2
        ;;
esac

RESCUE_DIR="${ROOT}/opt/var/lib/keen-pbr/rescue"
PENDING_FILE="$RESCUE_DIR/pending"
UNKNOWN_FILE="$RESCUE_DIR/UNKNOWN"
STABLE_HELPER="$RESCUE_DIR/rescue-update.sh"
PACKAGE_HELPER="${ROOT}/opt/usr/lib/keen-pbr/rescue-update.sh"
STABLE_METADATA_HELPER="$RESCUE_DIR/portable-stat.sh"
PACKAGE_METADATA_HELPER="${ROOT}/opt/usr/lib/keen-pbr/portable-stat.sh"
RECOVERY_DIR="${ROOT}/opt/var/lib/keen-pbr/recovery"
CONFIG_SAVE_DIR="$RECOVERY_DIR/config-save"
BACKUP_RESTORE_DIR="$RECOVERY_DIR/backup-restore"
CONFIG_SAVE_ACTIVE="$CONFIG_SAVE_DIR/active.json"
BACKUP_RESTORE_ACTIVE="$BACKUP_RESTORE_DIR/active.json"
RECOVERY_UNKNOWN="$RECOVERY_DIR/UNKNOWN"
CONFIG_SAVE_UNKNOWN="$CONFIG_SAVE_DIR/UNKNOWN"
BACKUP_RESTORE_UNKNOWN="$BACKUP_RESTORE_DIR/UNKNOWN"
KEEN_PBR_BINARY="${ROOT}/opt/usr/bin/keen-pbr"
STABLE_LOCK_HELPER="$RESCUE_DIR/update-lock.sh"
PACKAGE_LOCK_HELPER="${ROOT}/opt/usr/lib/keen-pbr/update-lock.sh"

# Only the two recovery invocations below take the update lock, not this whole
# script.
#
# This is a rescue component: its job is to look at a broken system and say
# what it found. Gating the inspection would add a way for it to refuse to
# report, which is the one thing it must never do. Gating the mutations is
# enough - what must not happen under someone else's transaction is changing
# state, not reading markers.
#
# Helper discovery mirrors the rescue helper above: the copy under the rescue
# directory wins, because it is the one that survives a half-installed package.
RECOVERY_LOCK_HELPER=
if [ -f "$STABLE_LOCK_HELPER" ] && [ ! -L "$STABLE_LOCK_HELPER" ] &&
   [ -x "$STABLE_LOCK_HELPER" ]; then
    RECOVERY_LOCK_HELPER=$STABLE_LOCK_HELPER
elif [ -f "$PACKAGE_LOCK_HELPER" ] && [ ! -L "$PACKAGE_LOCK_HELPER" ] &&
     [ -x "$PACKAGE_LOCK_HELPER" ]; then
    RECOVERY_LOCK_HELPER=$PACKAGE_LOCK_HELPER
fi

RECOVERY_LOCK_TOKEN=
RECOVERY_LOCK_OWNED=0

release_recovery_lock() {
    [ "$RECOVERY_LOCK_OWNED" = "1" ] || return 0
    "$RECOVERY_LOCK_HELPER" release $$ "$RECOVERY_LOCK_TOKEN" \
        >/dev/null 2>&1 || true
    RECOVERY_LOCK_OWNED=0
}

trap release_recovery_lock EXIT

enter_recovery_lock() {
    # No helper is not evidence of a competing update, and a rescue that
    # refuses because a lock script is missing helps nobody.
    [ -n "$RECOVERY_LOCK_HELPER" ] || return 0

    inherited_pid=${KEEN_PBR_UPDATE_LOCK_PID:-}
    inherited_token=${KEEN_PBR_UPDATE_LOCK_TOKEN:-}
    if [ -n "$inherited_pid" ] && [ -n "$inherited_token" ] &&
       "$RECOVERY_LOCK_HELPER" held "$inherited_pid" "$inherited_token" \
            >/dev/null 2>&1; then
        # Reached from S79, S80 or a postinst running under self-update. The
        # caller owns the exclusion; borrowing it is the whole point.
        return 0
    fi

    RECOVERY_LOCK_TOKEN=$(
        "$RECOVERY_LOCK_HELPER" acquire $$ recovery 2>/dev/null
    ) || return 1
    RECOVERY_LOCK_OWNED=1
    KEEN_PBR_UPDATE_LOCK_PID=$$
    KEEN_PBR_UPDATE_LOCK_TOKEN=$RECOVERY_LOCK_TOKEN
    export KEEN_PBR_UPDATE_LOCK_PID KEEN_PBR_UPDATE_LOCK_TOKEN
    return 0
}

fail() {
    message=$1
    if command -v logger >/dev/null 2>&1; then
        logger -s -t keen-pbr -p user.err "$message" 2>/dev/null || true
    fi
    printf '%s\n' "$message" >&2
    exit 1
}

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
        *)
            return 1
            ;;
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
    if [ -f "$PACKAGE_METADATA_HELPER" ] &&
       [ ! -L "$PACKAGE_METADATA_HELPER" ]; then
        metadata_helper=$PACKAGE_METADATA_HELPER
    else
        bootstrap_rescue_directory_is_private ||
            fail "keen-pbr cannot safely load rescue metadata support"
        [ -f "$STABLE_METADATA_HELPER" ] &&
            [ ! -L "$STABLE_METADATA_HELPER" ] ||
            fail "keen-pbr portable metadata helper is unavailable"
        metadata_helper=$STABLE_METADATA_HELPER
    fi
    . "$metadata_helper" ||
        fail "keen-pbr cannot load portable metadata support"
}

# Netfilter refreshes only signal the already running daemon and do not touch
# package rescue state. Running the persistent recovery guard recursively from
# an NDMS netfilter hook would instead risk delaying or re-entering recovery.
case "${1:-}" in
    start|restart|restartall|reload|reapply-dnsmasq-config) ;;
    *) exit 0 ;;
esac

load_metadata_helper

validate_private_directory() {
    directory=$1
    [ -e "$directory" ] || return 0
    if [ -L "$directory" ] || [ ! -d "$directory" ]; then
        fail "keen-pbr recovery state has an unsafe directory: $directory"
    fi

    metadata=$(keen_pbr_stat_value '%a:%u' "$directory") ||
        fail "keen-pbr cannot inspect recovery directory metadata: $directory"
    expected_uid=$(id -u 2>/dev/null) ||
        fail "keen-pbr cannot determine the recovery owner"
    if [ "$metadata" != "700:$expected_uid" ]; then
        fail "keen-pbr recovery directory is not private and owned: $directory"
    fi
}

validate_private_directory "$RESCUE_DIR"
if [ -e "$UNKNOWN_FILE" ] || [ -L "$UNKNOWN_FILE" ]; then
    fail "keen-pbr package recovery is UNKNOWN; refusing service startup"
fi
if [ -L "$PENDING_FILE" ] ||
   { [ -e "$PENDING_FILE" ] && [ ! -f "$PENDING_FILE" ]; }; then
    fail "keen-pbr package recovery marker has an unsafe type"
fi

# Package installation and the explicit package rescue transaction start
# services while a regular PENDING marker is intentionally present. UNKNOWN
# and unsafe metadata are never bypassed.
if [ -f "$PENDING_FILE" ] &&
   [ "${KEEN_PBR_RESCUE_TRANSACTION:-0}" != "1" ]; then
        # Calling opkg recursively from another package's postinst is unsafe.
        # An unmanaged package install with stale PENDING must stop and be
        # recovered separately.
        if [ "${KEEN_PBR_PACKAGE_POSTINST:-0}" = "1" ]; then
            fail "keen-pbr recovery is pending; refusing recursive recovery from postinst"
        fi

        HELPER=
        if [ -f "$STABLE_HELPER" ] && [ ! -L "$STABLE_HELPER" ] &&
           [ -x "$STABLE_HELPER" ]; then
            HELPER=$STABLE_HELPER
        elif [ -f "$PACKAGE_HELPER" ] && [ ! -L "$PACKAGE_HELPER" ] &&
             [ -x "$PACKAGE_HELPER" ]; then
            HELPER=$PACKAGE_HELPER
        else
            fail "keen-pbr recovery is pending but the rescue helper is unavailable"
        fi

        enter_recovery_lock ||
            fail "keen-pbr startup recovery is blocked by an in-flight update; services remain stopped"

        if ! "$HELPER" recover-startup; then
            fail "keen-pbr automatic startup recovery failed; services remain stopped"
        fi

        if [ -e "$PENDING_FILE" ] || [ -L "$PENDING_FILE" ] ||
           [ -e "$UNKNOWN_FILE" ] || [ -L "$UNKNOWN_FILE" ]; then
            fail "keen-pbr startup recovery did not reach a known state"
        fi
fi

validate_private_directory "$RECOVERY_DIR"
for operation_dir in "$CONFIG_SAVE_DIR" "$BACKUP_RESTORE_DIR"; do
    validate_private_directory "$operation_dir"
done

if [ -e "$RECOVERY_UNKNOWN" ] || [ -L "$RECOVERY_UNKNOWN" ] ||
   [ -e "$CONFIG_SAVE_UNKNOWN" ] || [ -L "$CONFIG_SAVE_UNKNOWN" ] ||
   [ -e "$BACKUP_RESTORE_UNKNOWN" ] || [ -L "$BACKUP_RESTORE_UNKNOWN" ]; then
    fail "keen-pbr persistent recovery is UNKNOWN; refusing service startup"
fi

persistent_recovery_count=0
for active_file in "$CONFIG_SAVE_ACTIVE" "$BACKUP_RESTORE_ACTIVE"; do
    if [ -L "$active_file" ] ||
       { [ -e "$active_file" ] && [ ! -f "$active_file" ]; }; then
        fail "keen-pbr persistent recovery marker has an unsafe type; refusing service startup"
    fi
    [ ! -f "$active_file" ] ||
        persistent_recovery_count=$((persistent_recovery_count + 1))
done

[ "$persistent_recovery_count" -gt 0 ] || exit 0
[ "$persistent_recovery_count" -eq 1 ] ||
    fail "keen-pbr has multiple active persistent transactions; refusing service startup"

# Recovery may stop/restart services. Never recurse into it from opkg postinst.
if [ "${KEEN_PBR_PACKAGE_POSTINST:-0}" = "1" ]; then
    fail "keen-pbr persistent recovery is pending; refusing recovery from postinst"
fi

# A transaction which has already captured its own durable WAL may restart
# dependencies without recursively invoking its offline recovery. Unlike the
# package-rescue bypass above, this skips only recovery of a valid active WAL;
# unsafe state and every UNKNOWN marker remain fail-closed.
[ "${KEEN_PBR_PERSISTENT_TRANSACTION:-0}" != "1" ] || exit 0

# Recovery changes persistent files and is deliberately offline. A config-save
# WAL may own both config.json and transports.json, while a backup restore may
# own those files plus nfqws data. The shell guard does not parse untrusted WAL
# effects before the C++ recovery coordinator verifies them, so both operations
# conservatively require the complete managed stack to be offline. This avoids
# restoring transports.json while transport-manager or a managed sing-box
# process can still mutate or consume the interrupted generation.
managed_processes="keen-pbr transport-manager nfqws2 nfqws sing-box"
for process_name in $managed_processes; do
    if [ -n "$(pidof "$process_name" 2>/dev/null || true)" ]; then
        fail "keen-pbr persistent recovery requires stopped services; $process_name is running"
    fi
done

if [ ! -f "$KEEN_PBR_BINARY" ] || [ -L "$KEEN_PBR_BINARY" ] ||
   [ ! -x "$KEEN_PBR_BINARY" ]; then
    fail "keen-pbr persistent recovery is pending but the keen-pbr binary is unsafe or unavailable"
fi

enter_recovery_lock ||
    fail "keen-pbr persistent recovery is blocked by an in-flight update; services remain stopped"

recovery_attempt=1
while :; do
    "$KEEN_PBR_BINARY" recover-persistent-state
    recovery_status=$?
    case "$recovery_status" in
        0)
            break
            ;;
        20)
            fail "keen-pbr persistent-state recovery is blocked; services remain stopped"
            ;;
        21)
            if [ "$recovery_attempt" -ge 3 ]; then
                fail "keen-pbr persistent-state recovery remained temporarily unavailable; services remain stopped"
            fi
            sleep "$recovery_attempt"
            recovery_attempt=$((recovery_attempt + 1))
            ;;
        *)
            fail "keen-pbr automatic persistent-state recovery failed with code $recovery_status; services remain stopped"
            ;;
    esac
done

if [ -e "$RECOVERY_UNKNOWN" ] || [ -L "$RECOVERY_UNKNOWN" ] ||
   [ -e "$CONFIG_SAVE_UNKNOWN" ] || [ -L "$CONFIG_SAVE_UNKNOWN" ] ||
   [ -e "$BACKUP_RESTORE_UNKNOWN" ] || [ -L "$BACKUP_RESTORE_UNKNOWN" ] ||
   [ -e "$CONFIG_SAVE_ACTIVE" ] || [ -L "$CONFIG_SAVE_ACTIVE" ] ||
   [ -e "$BACKUP_RESTORE_ACTIVE" ] || [ -L "$BACKUP_RESTORE_ACTIVE" ]; then
    fail "keen-pbr persistent-state recovery did not reach a known clean state"
fi

exit 0
