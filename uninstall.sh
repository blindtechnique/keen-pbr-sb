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

/opt/etc/init.d/S79transport-manager stop >/dev/null 2>&1 || true
/opt/etc/init.d/S80keen-pbr stop >/dev/null 2>&1 || true

for package in keen-pbr keen-pbr-headless; do
    if /opt/bin/opkg status "$package" >/dev/null 2>&1; then
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

echo "keen-pbr-sb удалён. Сам Entware не изменён."
