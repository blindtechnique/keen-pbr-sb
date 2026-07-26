#!/bin/sh

set -eu

ask() {
    prompt="$1"
    default="$2"
    printf '%s ' "$prompt" >/dev/tty
    answer=""
    IFS= read -r answer </dev/tty || true
    [ -n "$answer" ] || answer="$default"
    printf '%s' "$answer"
}

is_yes() {
    case "$1" in y|Y|yes|YES|д|Д|да|ДА) return 0 ;; *) return 1 ;; esac
}

[ "$(id -u)" = "0" ] || { echo "Запустите деинсталлятор от пользователя root" >&2; exit 1; }

RESCUE_DIR=/opt/var/lib/keen-pbr/rescue
RECOVERY_DIR=/opt/var/lib/keen-pbr/recovery
LOCK_HELPER="$RESCUE_DIR/update-lock.sh"
LOCK_TOKEN=
LOCK_OWNED=0

cleanup() {
    status=$?
    if [ "$LOCK_OWNED" -eq 1 ] && [ -x "$LOCK_HELPER" ]; then
        "$LOCK_HELPER" release "$$" "$LOCK_TOKEN" >/dev/null 2>&1 || true
    fi
    trap - EXIT INT TERM
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

assert_recovery_state_is_clean() {
    for state_path in \
        "$RESCUE_DIR/pending" \
        "$RESCUE_DIR/UNKNOWN" \
        "$RECOVERY_DIR/UNKNOWN" \
        "$RECOVERY_DIR/config-save/UNKNOWN" \
        "$RECOVERY_DIR/backup-restore/UNKNOWN" \
        "$RECOVERY_DIR/config-save/active.json" \
        "$RECOVERY_DIR/backup-restore/active.json"; do
        if [ -e "$state_path" ] || [ -L "$state_path" ]; then
            echo "Удаление остановлено: обнаружена незавершённая операция восстановления." >&2
            echo "Сначала перезапустите keen-pbr-sb и завершите или откатите операцию." >&2
            return 1
        fi
    done
    for state_dir in \
        "$RESCUE_DIR" \
        "$RECOVERY_DIR" \
        "$RECOVERY_DIR/config-save" \
        "$RECOVERY_DIR/backup-restore"; do
        if [ -L "$state_dir" ] ||
           { [ -e "$state_dir" ] && [ ! -d "$state_dir" ]; }; then
            echo "Удаление остановлено: небезопасный тип каталога $state_dir" >&2
            return 1
        fi
    done
}

assert_recovery_state_is_clean

managed_sing_box=""
if [ -f /opt/etc/keen-pbr/sing-box-managed.path ]; then
    managed_sing_box=$(sed -n '1p' /opt/etc/keen-pbr/sing-box-managed.path)
fi

remove_data=$(ask "Удалить также конфигурацию, списки и кэш keen-pbr-sb? [y/N]:" "N")
remove_sing_box="N"
if [ -n "$managed_sing_box" ] && [ -x "$managed_sing_box" ]; then
    remove_sing_box=$(ask "Удалить sing-box, установленный keen-pbr-sb в $managed_sing_box? [y/N]:" "N")
fi
remove_nfqws="N"
if /opt/bin/opkg status nfqws2-keenetic 2>/dev/null | grep -q '^Status:.* installed'; then
    remove_nfqws=$(ask "Удалить отдельно установленный пакет nfqws2-keenetic? Его конфигурация будет сохранена. [y/N]:" "N")
fi
restore_dns=$(ask "Отключить Keenetic opkg dns-override и вернуть системный DNS-прокси? [y/N]:" "N")

[ -x "$LOCK_HELPER" ] || {
    echo "Удаление остановлено: отсутствует защищённый lock-helper." >&2
    echo "Сначала переустановите текущую версию keen-pbr-sb." >&2
    exit 1
}
if ! LOCK_TOKEN=$("$LOCK_HELPER" acquire "$$" uninstall); then
    echo "Удаление остановлено: обновление, восстановление или другая операция уже выполняется." >&2
    exit 1
fi
LOCK_OWNED=1

# The user may spend an arbitrary amount of time answering prompts. Recheck
# durable state after taking the shared lock so an update cannot race between
# the initial preflight and opkg removal.
assert_recovery_state_is_clean

/opt/etc/init.d/S79transport-manager stop >/dev/null 2>&1 || true
/opt/etc/init.d/S80keen-pbr stop >/dev/null 2>&1 || true

for package in keen-pbr keen-pbr-headless; do
    if /opt/bin/opkg status "$package" >/dev/null 2>&1; then
        # postrm deliberately preserves the durable guard for replacements.
        # The official uninstaller releases its lock and removes those helpers
        # itself only after every destructive step has completed.
        /opt/bin/opkg remove "$package"
    fi
done

if is_yes "$remove_sing_box"; then
    rm -f "$managed_sing_box"
    [ ! -f "${managed_sing_box}.real" ] || rm -f "${managed_sing_box}.real"
fi

if is_yes "$remove_nfqws"; then
    /opt/bin/opkg remove nfqws2-keenetic || true
fi

if is_yes "$remove_data"; then
    rm -rf /opt/etc/keen-pbr /opt/var/cache/keen-pbr /opt/var/run/keen-pbr
else
    echo "Конфигурация сохранена в /opt/etc/keen-pbr"
fi

if is_yes "$restore_dns"; then
    ndmc -c "no opkg dns-override" >/dev/null
    ndmc -c "system configuration save" >/dev/null
fi

# Do not delete the only recovery barrier if an uncoordinated actor created
# durable state while the package was being removed.
assert_recovery_state_is_clean
"$LOCK_HELPER" release-and-clean "$$" "$LOCK_TOKEN"
LOCK_OWNED=0

echo "keen-pbr-sb удалён. Сам Entware не изменён."
