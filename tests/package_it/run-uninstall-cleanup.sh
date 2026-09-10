#!/bin/sh

# Mocked package lifecycle only. All writable paths, binaries, init actions and
# opkg calls live below one temporary root; no router /opt or real daemon.
set -eu
SOURCE_ROOT=${1:?source root required}
PACKAGE_FILES="$SOURCE_ROOT/packages/keenetic/keen-pbr/files"
work=$(mktemp -d /tmp/keen-pbr-uninstall.XXXXXX)
trap 'rm -rf "$work"' EXIT
export LC_ALL=C
SHELL_RUNNER=/bin/sh
if command -v busybox >/dev/null 2>&1; then
    SHELL_RUNNER="$work/busybox-sh"
    printf '#!/bin/sh\nexec "%s" sh "$@"\n' "$(command -v busybox)" > "$SHELL_RUNNER"
    chmod 0755 "$SHELL_RUNNER"
fi
export SHELL_RUNNER

setup_case() {
    ROOT="$work/$1"
    export ROOT KEEN_PBR_RESCUE_ROOT="$ROOT"
    mkdir -p "$ROOT/opt/bin" "$ROOT/opt/sbin" "$ROOT/opt/etc/init.d" \
        "$ROOT/opt/etc/keen-pbr" "$ROOT/opt/usr/lib/keen-pbr" \
        "$ROOT/opt/var/lib/keen-pbr/rescue/previous-config" \
        "$ROOT/opt/var/lib/keen-pbr/recovery/config-save" \
        "$ROOT/opt/var/lib/keen-pbr/recovery/backup-restore" \
        "$ROOT/opt/var/cache/keen-pbr" "$ROOT/opt/var/run/keen-pbr"
    chmod 0700 "$ROOT/opt/var/lib/keen-pbr/rescue"
    for helper in portable-stat.sh update-lock.sh lifecycle-lock.sh dnsmasq-package.sh; do
        cp "$PACKAGE_FILES/opt/usr/lib/keen-pbr/$helper" "$ROOT/opt/usr/lib/keen-pbr/$helper"
        chmod 0755 "$ROOT/opt/usr/lib/keen-pbr/$helper"
    done
    for helper in portable-stat.sh update-lock.sh; do
        cp "$ROOT/opt/usr/lib/keen-pbr/$helper" "$ROOT/opt/var/lib/keen-pbr/rescue/$helper"
    done
    touch "$ROOT/opt/etc/init.d/S00keen-pbr-rescue" \
        "$ROOT/opt/var/lib/keen-pbr/rescue/rescue-update.sh"
    cat > "$ROOT/opt/usr/lib/keen-pbr/dnsmasq.sh" <<'EOF'
#!/bin/sh
printf '%s\n' "dnsmasq:$1" >> "$ROOT/actions"
EOF
    chmod 0755 "$ROOT/opt/usr/lib/keen-pbr/dnsmasq.sh"
    for init in S80keen-pbr S79transport-manager; do
        cat > "$ROOT/opt/etc/init.d/$init" <<'EOF'
#!/bin/sh
. "$ROOT/opt/usr/lib/keen-pbr/lifecycle-lock.sh"
trap release_lifecycle_lock EXIT
enter_lifecycle_lock || exit 75
printf '%s\n' "${0##*/}:$1" >> "$ROOT/actions"
EOF
        chmod 0755 "$ROOT/opt/etc/init.d/$init"
    done
    cat > "$ROOT/opt/etc/init.d/S56dnsmasq" <<'EOF'
#!/bin/sh
echo "unexpected direct init call" >&2
exit 99
EOF
    chmod 0755 "$ROOT/opt/etc/init.d/S56dnsmasq"
    cat > "$ROOT/opt/sbin/dnsmasq" <<'EOF'
#!/bin/sh
[ "$1" = --test ] || exit 99
[ "${DNS_VALIDATION_FAIL:-0}" != 1 ]
EOF
    chmod 0755 "$ROOT/opt/sbin/dnsmasq"
    sed "s#/opt/#$ROOT/opt/#g" "$PACKAGE_FILES/prerm" > "$ROOT/prerm"
    cp "$PACKAGE_FILES/postrm" "$ROOT/postrm"
    cat > "$ROOT/opt/bin/opkg" <<'EOF'
#!/bin/sh
case "$1 $2" in
    'status keen-pbr') [ -f "$ROOT/installed" ] ;;
    'status keen-pbr-headless'|'status nfqws2-keenetic') exit 1 ;;
    'remove keen-pbr')
        "$SHELL_RUNNER" "$ROOT/prerm" || exit $?
        rm -f "$ROOT/installed" "$ROOT/opt/usr/lib/keen-pbr/dnsmasq.sh"
        "$SHELL_RUNNER" "$ROOT/postrm"
        ;;
    *) exit 99 ;;
esac
EOF
    chmod 0755 "$ROOT/opt/bin/opkg"
    touch "$ROOT/installed"
    printf 'server=9.9.9.10#5353\nstrict-order\n' > "$ROOT/opt/etc/keen-pbr/dnsmasq-fallback.conf"
    cat > "$ROOT/opt/etc/dnsmasq.conf" <<'EOF'
# Preserve this custom base and its unrelated DHCP setting.
dhcp-option=6,192.168.1.1
no-resolv
conf-script=/opt/usr/lib/keen-pbr/dnsmasq.sh dnsmasq-config-entry
server=/local.example/192.168.1.10
EOF
    chmod 0640 "$ROOT/opt/etc/dnsmasq.conf"
    cp "$ROOT/opt/etc/dnsmasq.conf" "$ROOT/original-dns"
    printf 'auth-secret\n' > "$ROOT/opt/var/lib/keen-pbr/rescue/previous-config/auth.json"
    printf 'transport-secret\n' > "$ROOT/opt/var/lib/keen-pbr/rescue/previous-config/transports.json"
    printf 'snapshot\n' > "$ROOT/opt/var/lib/keen-pbr/recovery/config-save/baseline"
    printf 'snapshot\n' > "$ROOT/opt/var/lib/keen-pbr/recovery/backup-restore/baseline"
    for archive in current.ipk previous.ipk; do
        printf 'ipk\n' > "$ROOT/opt/var/lib/keen-pbr/rescue/$archive"
        printf 'digest\n' > "$ROOT/opt/var/lib/keen-pbr/rescue/$archive.sha256"
    done
    printf 'keep nfqws boot dependency\n' > "$ROOT/opt/var/lib/keen-pbr/nfqws-rotator-telemetry-v1.lua"
    printf 'keep nfqws learned data\n' > "$ROOT/opt/var/lib/keen-pbr/nfqws-rotator-learned-v1.0"
    printf 'keep unrelated file\n' > "$ROOT/opt/var/lib/keen-pbr/foreign-data"
    # Only the generated entry point pretends to be root. Do not put id in
    # PATH: child lock helpers must observe the real owner of these temp files.
    awk -v root="$ROOT" '
        NR == 1 {
            print
            print "id() { if [ \"$#\" -eq 1 ] && [ \"$1\" = -u ]; then printf %s \"${TEST_UNINSTALL_UID:-0}\"; else command id \"$@\"; fi; }"
            next
        }
        /^ask\(\) \{/ {
            print "ask() { case \"$1\" in \"Удалить также\"*) printf %s \"$REMOVE_DATA\" ;; *) printf N ;; esac; }"
            skip=1; next
        }
        skip && /^}/ { skip=0; next }
        skip { next }
        { gsub("/opt/", root "/opt/"); print }
    ' "$SOURCE_ROOT/uninstall.sh" > "$ROOT/uninstall"
    for executable in "$ROOT/opt/usr/lib/keen-pbr/"*.sh \
        "$ROOT/opt/var/lib/keen-pbr/rescue/"*.sh \
        "$ROOT/opt/etc/init.d/S79transport-manager" \
        "$ROOT/opt/etc/init.d/S80keen-pbr" "$ROOT/opt/bin/opkg" \
        "$ROOT/opt/sbin/dnsmasq"; do
        [ -s "$executable" ] || continue
        sed -i "1c\\#!$SHELL_RUNNER" "$executable"
    done
    unset KEEN_PBR_UPDATE_LOCK_PID KEEN_PBR_UPDATE_LOCK_TOKEN
}

assert_standalone_dns() {
    grep -q '^# BEGIN keen-pbr standalone DNS fallback v1$' "$ROOT/opt/etc/dnsmasq.conf"
    grep -q '^server=9.9.9.10#5353$' "$ROOT/opt/etc/dnsmasq.conf"
    grep -q '^strict-order$' "$ROOT/opt/etc/dnsmasq.conf"
    grep -q '^dhcp-option=6,192.168.1.1$' "$ROOT/opt/etc/dnsmasq.conf"
    grep -q '^server=/local.example/192.168.1.10$' "$ROOT/opt/etc/dnsmasq.conf"
    ! grep -q '^conf-script=.*keen-pbr' "$ROOT/opt/etc/dnsmasq.conf"
    [ "$(stat -c %a "$ROOT/opt/etc/dnsmasq.conf")" = 640 ]
}

setup_case unprivileged_guard
if TEST_UNINSTALL_UID=1000 REMOVE_DATA=Y "$SHELL_RUNNER" "$ROOT/uninstall" > "$ROOT/output" 2>&1; then exit 1; fi
grep -q 'Запустите деинсталлятор от пользователя root' "$ROOT/output"
[ -f "$ROOT/installed" ]
[ -f "$ROOT/opt/var/lib/keen-pbr/rescue/previous-config/auth.json" ]
[ ! -e "$ROOT/actions" ]
[ ! -e "$ROOT/opt/var/run/keen-pbr-update.lock" ]
cmp "$ROOT/original-dns" "$ROOT/opt/etc/dnsmasq.conf"
echo 'PASS unprivileged uninstall is refused before any fixture mutation'

setup_case keep
REMOVE_DATA=N "$SHELL_RUNNER" "$ROOT/uninstall" > "$ROOT/output"
assert_standalone_dns
[ ! -e "$ROOT/installed" ]
[ ! -e "$ROOT/opt/var/run/keen-pbr-update.lock" ]
[ ! -e "$ROOT/opt/var/lib/keen-pbr/rescue/update-lock.sh" ]
[ -f "$ROOT/opt/var/lib/keen-pbr/rescue/previous-config/auth.json" ]
[ -f "$ROOT/opt/var/lib/keen-pbr/rescue/previous.ipk" ]
grep -q '^S80keen-pbr:stop$' "$ROOT/actions"
grep -q '^S79transport-manager:stop$' "$ROOT/actions"
echo 'PASS uninstall borrows its existing lock and preserves requested data'

setup_case purge
REMOVE_DATA=Y "$SHELL_RUNNER" "$ROOT/uninstall" > "$ROOT/output"
assert_standalone_dns
[ ! -e "$ROOT/opt/etc/keen-pbr" ]
[ ! -e "$ROOT/opt/var/lib/keen-pbr/rescue/previous-config" ]
[ ! -e "$ROOT/opt/var/lib/keen-pbr/recovery/config-save" ]
[ ! -e "$ROOT/opt/var/lib/keen-pbr/recovery/backup-restore" ]
[ ! -e "$ROOT/opt/var/lib/keen-pbr/rescue/current.ipk" ]
[ ! -e "$ROOT/opt/var/lib/keen-pbr/rescue/previous.ipk.sha256" ]
[ -f "$ROOT/opt/var/lib/keen-pbr/nfqws-rotator-telemetry-v1.lua" ]
[ -f "$ROOT/opt/var/lib/keen-pbr/nfqws-rotator-learned-v1.0" ]
[ -f "$ROOT/opt/var/lib/keen-pbr/foreign-data" ]
echo 'PASS purge removes completed owned backups, keeps standalone DNS and nfqws data'

setup_case pending
touch "$ROOT/opt/var/lib/keen-pbr/recovery/config-save/active.json"
if REMOVE_DATA=Y "$SHELL_RUNNER" "$ROOT/uninstall" > "$ROOT/output" 2>&1; then exit 1; fi
[ -f "$ROOT/installed" ]
[ -f "$ROOT/opt/var/lib/keen-pbr/rescue/previous-config/auth.json" ]
[ ! -e "$ROOT/actions" ]
echo 'PASS existing unfinished recovery is retained without package mutation'

setup_case bare_remove
"$ROOT/opt/bin/opkg" remove keen-pbr
assert_standalone_dns
[ ! -e "$ROOT/opt/usr/lib/keen-pbr/dnsmasq.sh" ]
echo 'PASS bare opkg removal has no dangling helper reference'

for upgrade in 1 0; do
    setup_case "reinstall_$upgrade"
    mkdir -p "$ROOT/opt/usr/bin"
    cat > "$ROOT/opt/usr/bin/transport-manager" <<'EOF'
#!/bin/sh
[ "$1" = -config ] && [ "$3" = -capture-upgrade-state ] || exit 99
printf '%s\n' 'transport:capture-upgrade-state' >> "$ROOT/actions"
printf '%s\n' '{"desired_up":{"stopped-vpn":false}}' > "$4"
EOF
    chmod 0755 "$ROOT/opt/usr/bin/transport-manager"
    PKG_UPGRADE=$upgrade "$SHELL_RUNNER" "$ROOT/prerm"
    if [ "$upgrade" = 1 ]; then
        awk '/transport:capture-upgrade-state/ { captured=1 }
             /S80keen-pbr:stop-for-upgrade/ { if (!captured) exit 1; checked=1 }
             END { if (!checked) exit 1 }' "$ROOT/actions"
    else
        ! grep -q 'transport:capture-upgrade-state' "$ROOT/actions"
    fi
    assert_standalone_dns
    "$ROOT/opt/usr/lib/keen-pbr/dnsmasq-package.sh" restore
    cmp "$ROOT/original-dns" "$ROOT/opt/etc/dnsmasq.conf"
    echo "PASS upgrade/reinstall PKG_UPGRADE=$upgrade restores only the owned integration"
done

setup_case foreign
printf 'server=192.0.2.53\n# custom DNS without keen-pbr\n' > "$ROOT/opt/etc/dnsmasq.conf"
cp -p "$ROOT/opt/etc/dnsmasq.conf" "$ROOT/foreign-original"
"$ROOT/opt/usr/lib/keen-pbr/dnsmasq-package.sh" detach
"$ROOT/opt/usr/lib/keen-pbr/dnsmasq-package.sh" restore
cmp "$ROOT/foreign-original" "$ROOT/opt/etc/dnsmasq.conf"
[ ! -e "$ROOT/actions" ]
echo 'PASS unrelated manual dnsmasq configuration is a complete no-op'

setup_case nested
mkdir "$ROOT/opt/etc/keen-pbr/dns"
cat >> "$ROOT/opt/etc/keen-pbr/dnsmasq-fallback.conf" <<'EOF'
conf-file=/opt/etc/keen-pbr/dns/one.conf
conf-dir="/opt/etc/keen-pbr/dns",*.conf
conf-file=/opt/etc/dnsmasq-external.conf
ipset=/example/kpbr4s_old
nftset=/example/4#inet#keen_pbr#old
EOF
cat > "$ROOT/opt/etc/keen-pbr/dns/one.conf" <<'EOF'
server=/one.example/192.0.2.1
conf-file=/opt/etc/keen-pbr/dnsmasq-fallback.conf
EOF
printf 'server=/two.example/192.0.2.2\n' > "$ROOT/opt/etc/keen-pbr/dns/two.conf"
printf 'must-not-copy\n' > "$ROOT/opt/etc/keen-pbr/dns/auth.json"
printf 'must-not-copy\n' > "$ROOT/opt/etc/keen-pbr/dns/backup.conf~"
"$ROOT/opt/usr/lib/keen-pbr/dnsmasq-package.sh" detach
assert_standalone_dns
grep -q '^server=/one.example/192.0.2.1$' "$ROOT/opt/etc/dnsmasq.conf"
grep -q '^server=/two.example/192.0.2.2$' "$ROOT/opt/etc/dnsmasq.conf"
grep -q '^conf-file=/opt/etc/dnsmasq-external.conf$' "$ROOT/opt/etc/dnsmasq.conf"
! grep -Eq '^(conf-file|conf-dir)=/opt/etc/keen-pbr|^(ipset|nftset)=|must-not-copy' "$ROOT/opt/etc/dnsmasq.conf"
cp "$ROOT/opt/etc/dnsmasq.conf" "$ROOT/detached-once"
"$ROOT/opt/usr/lib/keen-pbr/dnsmasq-package.sh" detach
cmp "$ROOT/detached-once" "$ROOT/opt/etc/dnsmasq.conf"
echo 'PASS local file/directory DNS includes are inlined once, external includes preserved'

setup_case validation_failure
if DNS_VALIDATION_FAIL=1 "$ROOT/opt/usr/lib/keen-pbr/dnsmasq-package.sh" detach; then exit 1; fi
cmp "$ROOT/original-dns" "$ROOT/opt/etc/dnsmasq.conf"
[ ! -e "$ROOT/actions" ]
echo 'PASS invalid standalone config does not replace the working base'

setup_case no_direct
printf '# No direct fallback\n' > "$ROOT/opt/etc/keen-pbr/dnsmasq-fallback.conf"
"$ROOT/opt/usr/lib/keen-pbr/dnsmasq-package.sh" detach
! grep -q '^server=[0-9]' "$ROOT/opt/etc/dnsmasq.conf"
echo 'PASS no direct DNS does not silently introduce a public upstream'

setup_case inactive_restore
mkdir "$ROOT/resolver-state"
printf 'N\n' > "$ROOT/resolver-state/active"
printf '#!/bin/sh\nexit 0\n' > "$ROOT/opt/bin/logger"
chmod 0755 "$ROOT/opt/bin/logger"
PATH="$ROOT/opt/bin:$PATH" KEEN_PBR_BIN=/bin/false \
    KEEN_PBR_STATE_DIR="$ROOT/resolver-state" \
    KEEN_PBR_DNSMASQ_FALLBACK_FILE="$ROOT/opt/etc/keen-pbr/dnsmasq-fallback.conf" \
    "$SHELL_RUNNER" "$PACKAGE_FILES/opt/usr/lib/keen-pbr/dnsmasq.sh" \
    dnsmasq-config-entry > "$ROOT/inactive-output"
grep -Fxq "conf-file=$ROOT/opt/etc/keen-pbr/dnsmasq-fallback.conf" "$ROOT/inactive-output"
! grep -Eq '^(ipset|nftset)=' "$ROOT/inactive-output"
echo 'PASS postinst conf-script validation uses inactive fallback without a live daemon'

# Both variants must restore before their first service startup.
for postinst in postinst postinst-headless; do
    awk '/dnsmasq-package.sh.*restore/ { restored=1 }
         /S(79transport-manager|80keen-pbr) start/ { if (!restored) exit 1; checked=1 }
         END { if (!checked) exit 1 }' "$PACKAGE_FILES/$postinst"
done
echo 'PASS full and headless postinst restore before service startup'
