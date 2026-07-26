#!/bin/sh

set -eu

[ "${KEEN_PBR_PACKAGE_IT_CONTAINER:-0}" = "1" ] || {
    echo "This test must run inside its disposable package-test container" >&2
    exit 2
}

IPK=${1:-}
[ -f "$IPK" ] || {
    echo "Built IPK is missing: $IPK" >&2
    exit 2
}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/outer" "$WORK/control"
tar -xzf "$IPK" -C "$WORK/outer"
[ "$(cat "$WORK/outer/debian-binary")" = "2.0" ]
tar -xzf "$WORK/outer/control.tar.gz" -C "$WORK/control"
tar -xzf "$WORK/outer/data.tar.gz" -C /

# Reproduce the minimal Keenetic/Entware contract. The stat applet is present
# through BusyBox, while a standalone /opt/bin/stat command is not guaranteed.
mkdir -p /opt/bin /opt/etc/init.d /opt/var/run
rm -f /opt/bin/stat
printf '%s\n' \
    '#!/bin/sh' \
    '[ "${1:-}" = stat ] || exit 127' \
    'shift' \
    '[ "${1:-}" = -t ] || exit 1' \
    'exec /bin/stat "$@"' > /opt/bin/busybox
chmod 0755 /opt/bin/busybox

for service in S79transport-manager S80keen-pbr; do
    printf '%s\n' \
        '#!/bin/sh' \
        'case "${1:-}" in' \
        '  start|stop|restart|check) exit 0 ;;' \
        '  *) exit 2 ;;' \
        'esac' > "/opt/etc/init.d/$service"
    chmod 0755 "/opt/etc/init.d/$service"
done

run_postinst() {
    KEEN_PBR_REPLACE_DNSMASQ_DEFAULTS=N \
        /bin/sh "$WORK/control/postinst"
    [ -x /opt/etc/init.d/S00keen-pbr-rescue ]
    [ -x /opt/var/lib/keen-pbr/rescue/portable-stat.sh ]
    [ -x /opt/var/lib/keen-pbr/rescue/rescue-update.sh ]
    [ -x /opt/var/lib/keen-pbr/rescue/update-lock.sh ]
    [ ! -e /opt/var/lib/keen-pbr/rescue/pending ]
    . /opt/var/lib/keen-pbr/rescue/portable-stat.sh
    [ "$(keen_pbr_stat_value '%a:%u' /opt/var/lib/keen-pbr/rescue)" = \
        "700:$(id -u)" ]
}

run_postinst

# A same-version replacement must not tear down the only early-boot guard.
/bin/sh "$WORK/control/postrm"
[ -x /opt/etc/init.d/S00keen-pbr-rescue ]
[ -x /opt/var/lib/keen-pbr/rescue/portable-stat.sh ]
run_postinst

# Explicit removal preserves forensic state, then cleans all durable helpers
# once recovery is known to be clean.
touch /opt/var/lib/keen-pbr/rescue/pending
KEEN_PBR_FINAL_REMOVE=1 /bin/sh "$WORK/control/postrm"
[ -x /opt/etc/init.d/S00keen-pbr-rescue ]
[ -x /opt/var/lib/keen-pbr/rescue/portable-stat.sh ]
rm -f /opt/var/lib/keen-pbr/rescue/pending
KEEN_PBR_FINAL_REMOVE=1 /bin/sh "$WORK/control/postrm"
[ ! -e /opt/etc/init.d/S00keen-pbr-rescue ]
[ ! -e /opt/var/lib/keen-pbr/rescue/portable-stat.sh ]
[ ! -e /opt/var/lib/keen-pbr/rescue/rescue-update.sh ]
[ ! -e /opt/var/lib/keen-pbr/rescue/update-lock.sh ]

# Even an early postinst failure must repair a guard removed by the previous
# package's legacy postrm.
rm -f /opt/usr/lib/keen-pbr/portable-stat.sh
if KEEN_PBR_REPLACE_DNSMASQ_DEFAULTS=N \
   /bin/sh "$WORK/control/postinst"; then
    echo "postinst unexpectedly succeeded without portable metadata support" >&2
    exit 1
fi
[ -x /opt/etc/init.d/S00keen-pbr-rescue ]
