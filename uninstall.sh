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
    case "$1" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

[ "$(id -u)" = "0" ] || { echo "Run this uninstaller as root" >&2; exit 1; }

managed_sing_box=""
if [ -f /opt/etc/keen-pbr/sing-box-managed.path ]; then
    managed_sing_box=$(sed -n '1p' /opt/etc/keen-pbr/sing-box-managed.path)
fi

remove_data=$(ask "Remove keen-pbr configuration, lists and cache too? [y/N]:" "N")
remove_sing_box="N"
if [ -n "$managed_sing_box" ] && [ -x "$managed_sing_box" ]; then
    remove_sing_box=$(ask "Remove sing-box installed by MyKeenPBR at $managed_sing_box? [y/N]:" "N")
fi
restore_dns=$(ask "Disable Keenetic opkg dns-override and restore the system DNS proxy? [y/N]:" "N")

/opt/etc/init.d/S79transport-manager stop >/dev/null 2>&1 || true
/opt/etc/init.d/S80keen-pbr stop >/dev/null 2>&1 || true

for package in keen-pbr keen-pbr-headless; do
    if /opt/bin/opkg status "$package" >/dev/null 2>&1; then
        /opt/bin/opkg remove "$package"
    fi
done

if is_yes "$remove_sing_box"; then
    rm -f "$managed_sing_box"
fi

if is_yes "$remove_data"; then
    rm -rf /opt/etc/keen-pbr /opt/var/cache/keen-pbr /opt/var/run/keen-pbr
else
    echo "Configuration was preserved in /opt/etc/keen-pbr"
fi

if is_yes "$restore_dns"; then
    ndmc -c "no opkg dns-override" >/dev/null
    ndmc -c "system configuration save" >/dev/null
fi

echo "MyKeenPBR has been removed. Entware itself was not modified."
