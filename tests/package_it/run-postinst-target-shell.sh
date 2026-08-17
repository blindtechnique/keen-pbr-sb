#!/bin/sh

set -eu

[ "${KEEN_PBR_PACKAGE_IT_CONTAINER:-0}" = "1" ] || {
    echo "This test must run inside its disposable package-test container" >&2
    exit 2
}

SOURCE_ROOT=${1:-/workspace}
VARIANT=${2:-full}
case "$VARIANT" in
    full) POSTINST="$SOURCE_ROOT/packages/keenetic/keen-pbr/files/postinst" ;;
    headless)
        POSTINST="$SOURCE_ROOT/packages/keenetic/keen-pbr/files/postinst-headless"
        ;;
    *) echo "Unknown package variant: $VARIANT" >&2; exit 2 ;;
esac

# Pin the exact router contract: the BusyBox stat applet is available, but
# there may be no standalone stat symlink after package replacement/removal.
mkdir -p /opt/bin
printf '%s\n' \
    '#!/bin/sh' \
    '[ "${1:-}" = stat ] || exit 127' \
    'shift' \
    'if [ "${1:-}" != -t ]; then' \
    '  printf "%s\n" "stat: invalid option -- ${1:-}" >&2' \
    '  exit 1' \
    'fi' \
    'exec /bin/stat "$@"' > /opt/bin/busybox
chmod 0755 /opt/bin/busybox
[ ! -e /opt/bin/stat ]
/opt/bin/busybox stat -t / >/dev/null
if /opt/bin/busybox stat -c '%u' / >/dev/null 2>&1; then
    echo "Target-shell test requires BusyBox stat without -c" >&2
    exit 2
fi

mkdir -p \
    /opt/etc/init.d \
    /opt/etc/keen-pbr \
    /opt/usr/lib/keen-pbr \
    /opt/var/lib/keen-pbr/rescue \
    /opt/var/run
chmod 0755 /opt/var/lib/keen-pbr/rescue

for helper in \
    portable-stat.sh \
    rescue-update.sh \
    rescue-startup-guard.sh \
    update-lock.sh; do
    cp "$SOURCE_ROOT/packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/$helper" \
        "/opt/usr/lib/keen-pbr/$helper"
    chmod 0755 "/opt/usr/lib/keen-pbr/$helper"
done

if [ "$VARIANT" = full ]; then
    mkdir -p /opt/usr/share/keen-pbr/nfqws-lua
    cp "$SOURCE_ROOT/packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/nfqws-lua/rotator-telemetry.lua" \
        /opt/usr/share/keen-pbr/nfqws-lua/rotator-telemetry.lua
fi

for service in S79transport-manager S80keen-pbr; do
    printf '%s\n' \
        '#!/bin/sh' \
        '[ "${1:-}" = start ] || exit 2' \
        'printf "%s\n" "$0 $1" >> /opt/var/run/package-it-services.log' \
        'exit 0' > "/opt/etc/init.d/$service"
    chmod 0755 "/opt/etc/init.d/$service"
done

KEEN_PBR_REPLACE_DNSMASQ_DEFAULTS=N /bin/sh "$POSTINST"

. /opt/var/lib/keen-pbr/rescue/portable-stat.sh
[ "$(keen_pbr_stat_value '%a:%u' /opt/var/lib/keen-pbr/rescue)" = \
    "700:$(id -u)" ]
[ -x /opt/etc/init.d/S00keen-pbr-rescue ]
[ -x /opt/var/lib/keen-pbr/rescue/portable-stat.sh ]
[ -x /opt/var/lib/keen-pbr/rescue/rescue-update.sh ]
[ -x /opt/var/lib/keen-pbr/rescue/update-lock.sh ]
[ ! -e /opt/var/lib/keen-pbr/rescue/pending ]
[ ! -e /opt/var/lib/keen-pbr/rescue/UNKNOWN ]

# During an interrupted package replacement the package copy can be absent.
# The early-boot guard must still validate and load its durable helper using
# only the BusyBox applet, without a standalone stat command.
rm -f /opt/usr/lib/keen-pbr/portable-stat.sh
/opt/etc/init.d/S00keen-pbr-rescue start

case "$VARIANT" in
    full)
        reporter_source="$SOURCE_ROOT/packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/nfqws-lua/rotator-telemetry.lua"
        reporter_live=/opt/var/lib/keen-pbr/nfqws-rotator-telemetry-v1.lua
        [ -f "$reporter_live" ]
        [ ! -L "$reporter_live" ]
        [ "$(keen_pbr_stat_value '%a:%u' "$reporter_live")" = \
            "644:$(id -u)" ]
        cmp "$reporter_source" "$reporter_live"
        rm -f /opt/usr/share/keen-pbr/nfqws-lua/rotator-telemetry.lua
        cmp "$reporter_source" "$reporter_live"
        [ "$(grep -c 'S79transport-manager start' \
            /opt/var/run/package-it-services.log)" -eq 1 ]
        [ "$(grep -c 'S80keen-pbr start' \
            /opt/var/run/package-it-services.log)" -eq 1 ]
        ;;
    headless)
        [ "$(grep -c 'S79transport-manager start' \
            /opt/var/run/package-it-services.log || true)" -eq 0 ]
        [ "$(grep -c 'S80keen-pbr start' \
            /opt/var/run/package-it-services.log)" -eq 1 ]
        ;;
esac
