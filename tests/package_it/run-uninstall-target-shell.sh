#!/bin/sh

set -eu

[ "${KEEN_PBR_PACKAGE_IT_CONTAINER:-0}" = "1" ] || {
    echo "This test must run inside its disposable package-test container" >&2
    exit 2
}

SOURCE_ROOT=${1:-}
[ -f "$SOURCE_ROOT/uninstall.sh" ] || {
    echo "Source root is missing uninstall.sh: $SOURCE_ROOT" >&2
    exit 2
}

RESCUE_DIR=/opt/var/lib/keen-pbr/rescue
mkdir -p "$RESCUE_DIR" /opt/bin /opt/etc/init.d /opt/etc/keen-pbr
chmod 0700 "$RESCUE_DIR"
cp "$SOURCE_ROOT/packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/portable-stat.sh" \
    "$RESCUE_DIR/portable-stat.sh"
cp "$SOURCE_ROOT/packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/update-lock.sh" \
    "$RESCUE_DIR/update-lock.sh"
chmod 0755 "$RESCUE_DIR/portable-stat.sh" "$RESCUE_DIR/update-lock.sh"
touch /opt/etc/init.d/S00keen-pbr-rescue
chmod 0755 /opt/etc/init.d/S00keen-pbr-rescue

for service in S79transport-manager S80keen-pbr; do
    cat > "/opt/etc/init.d/$service" <<'EOF'
#!/bin/sh
exit 0
EOF
    chmod 0755 "/opt/etc/init.d/$service"
done

cat > /opt/bin/opkg <<'EOF'
#!/bin/sh
case "${1:-} ${2:-}" in
    "status keen-pbr") exit 0 ;;
    "status keen-pbr-headless"|"status nfqws2-keenetic") exit 1 ;;
    "remove keen-pbr")
        /opt/var/lib/keen-pbr/rescue/update-lock.sh owner >/dev/null
        touch /tmp/opkg-remove-called
        exit 0
        ;;
    *) exit 2 ;;
esac
EOF
chmod 0755 /opt/bin/opkg

# `ask` intentionally reads from /dev/tty. BusyBox script supplies a real
# pseudo-terminal while the blank answers select every safe default.
printf '\n\n' |
    script -q -c "/bin/sh $SOURCE_ROOT/uninstall.sh" /tmp/uninstall.log

[ -e /tmp/opkg-remove-called ]
[ ! -e /opt/var/run/keen-pbr-update.lock ]
[ ! -e /opt/etc/init.d/S00keen-pbr-rescue ]
[ ! -e "$RESCUE_DIR/update-lock.sh" ]
[ ! -e "$RESCUE_DIR/portable-stat.sh" ]

# Recreate the helpers and inject recovery state while the user is answering.
# The mandatory second preflight must stop before opkg removal.
rm -f /tmp/opkg-remove-called
mkdir -p "$RESCUE_DIR"
chmod 0700 "$RESCUE_DIR"
cp "$SOURCE_ROOT/packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/portable-stat.sh" \
    "$RESCUE_DIR/portable-stat.sh"
cp "$SOURCE_ROOT/packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/update-lock.sh" \
    "$RESCUE_DIR/update-lock.sh"
chmod 0755 "$RESCUE_DIR/portable-stat.sh" "$RESCUE_DIR/update-lock.sh"
touch /opt/etc/init.d/S00keen-pbr-rescue
chmod 0755 /opt/etc/init.d/S00keen-pbr-rescue

cat > /opt/bin/opkg <<'EOF'
#!/bin/sh
case "${1:-} ${2:-}" in
    "status nfqws2-keenetic")
        touch /opt/var/lib/keen-pbr/rescue/pending
        exit 1
        ;;
    "status keen-pbr") exit 0 ;;
    "status keen-pbr-headless") exit 1 ;;
    "remove keen-pbr")
        touch /tmp/opkg-remove-called
        exit 0
        ;;
    *) exit 2 ;;
esac
EOF
chmod 0755 /opt/bin/opkg

printf '\n\n' |
    script -q -c "/bin/sh $SOURCE_ROOT/uninstall.sh" /tmp/uninstall-race.log
grep -q "Удаление остановлено" /tmp/uninstall-race.log
[ ! -e /tmp/opkg-remove-called ]
[ -x /opt/etc/init.d/S00keen-pbr-rescue ]
[ -x "$RESCUE_DIR/update-lock.sh" ]
