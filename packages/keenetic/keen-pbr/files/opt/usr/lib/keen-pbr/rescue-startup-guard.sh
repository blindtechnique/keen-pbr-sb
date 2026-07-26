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
RECOVERY_DIR="${ROOT}/opt/var/lib/keen-pbr/recovery"
CONFIG_SAVE_DIR="$RECOVERY_DIR/config-save"
BACKUP_RESTORE_DIR="$RECOVERY_DIR/backup-restore"
CONFIG_SAVE_ACTIVE="$CONFIG_SAVE_DIR/active.json"
BACKUP_RESTORE_ACTIVE="$BACKUP_RESTORE_DIR/active.json"
RECOVERY_UNKNOWN="$RECOVERY_DIR/UNKNOWN"
CONFIG_SAVE_UNKNOWN="$CONFIG_SAVE_DIR/UNKNOWN"
BACKUP_RESTORE_UNKNOWN="$BACKUP_RESTORE_DIR/UNKNOWN"
KEEN_PBR_BINARY="${ROOT}/opt/usr/bin/keen-pbr"

fail() {
    message=$1
    if command -v logger >/dev/null 2>&1; then
        logger -s -t keen-pbr -p user.err "$message" 2>/dev/null || true
    fi
    printf '%s\n' "$message" >&2
    exit 1
}

case "${1:-}" in
    start|restart|restartall|reload|reapply-firewall|reapply-dnsmasq-config) ;;
    *) exit 0 ;;
esac

validate_private_directory() {
    directory=$1
    [ -e "$directory" ] || return 0
    if [ -L "$directory" ] || [ ! -d "$directory" ]; then
        fail "keen-pbr recovery state has an unsafe directory: $directory"
    fi

    metadata=$(stat -c '%a:%u' "$directory" 2>/dev/null) ||
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
# WAL owns only config.json, so only the core writer must be stopped. A backup
# restore may own transports and nfqws data as well and therefore requires the
# complete managed stack to be offline.
managed_processes="keen-pbr"
if [ -f "$BACKUP_RESTORE_ACTIVE" ]; then
    managed_processes="keen-pbr transport-manager nfqws2 nfqws sing-box"
fi
for process_name in $managed_processes; do
    if [ -n "$(pidof "$process_name" 2>/dev/null || true)" ]; then
        fail "keen-pbr persistent recovery requires stopped services; $process_name is running"
    fi
done

if [ ! -f "$KEEN_PBR_BINARY" ] || [ -L "$KEEN_PBR_BINARY" ] ||
   [ ! -x "$KEEN_PBR_BINARY" ]; then
    fail "keen-pbr persistent recovery is pending but the keen-pbr binary is unsafe or unavailable"
fi

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
