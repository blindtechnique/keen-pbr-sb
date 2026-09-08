#!/bin/sh

set -eu

[ "$#" -eq 1 ] || {
    echo "usage: $0 <keenetic-dnsmasq-helper>" >&2
    exit 2
}

helper="$1"
workdir="$(mktemp -d /tmp/keen-pbr-dns-fallback.XXXXXX)"
trap 'rm -rf "$workdir"' EXIT HUP INT TERM
state_dir="$workdir/state"
fallback_file="$workdir/fallback.conf"
fake_bin="$workdir/keen-pbr"
test_helper="$workdir/helper.sh"
observed="$workdir/dnsmasq.out"
mkdir -p "$state_dir"

# Keep the production dispatch, stream/receipt and fallback publication paths.
# Replace only the real dnsmasq restart with a conf-script invocation; timeout
# polling is also instantaneous. The fixture never touches router paths or PIDs.
awk '
    /^set -e$/ {
        print
        print "usleep() { :; }"
        print "sleep() { :; }"
        next
    }
    /^restart_dnsmasq\(\) \{/ {
        print "restart_dnsmasq() {"
        print "    emit_dnsmasq_config_entry > \"$FAKE_DNSMASQ_OUTPUT\""
        print "}"
        skip = 1
        next
    }
    skip && /^}/ { skip = 0; next }
    !skip { print }
' "$helper" > "$test_helper"

cat > "$fake_bin" <<'EOF'
#!/bin/sh
set -eu
case "${FAKE_RESOLVER_MODE:-good}" in
    good|no-direct|partial)
        printf '%s\n' \
            '# keen-pbr resolver state: active' \
            'txt-record=config-hash.keen.pbr,1|0123456789abcdef0123456789abcdef' \
            '# keen-pbr direct-fallback v1'
        if [ "${FAKE_RESOLVER_MODE:-good}" != no-direct ]; then
            printf '# keen-pbr direct-fallback server=%s\n' "${FAKE_DIRECT_SERVER:-77.88.8.8}"
            printf '%s\n' '# keen-pbr direct-fallback server=127.0.0.1#40508'
        fi
        printf '%s\n' \
            'server=77.88.8.8' \
            'server=10.20.30.53' \
            'ipset=/vpn.example/kpbr4d_vpn'
        [ "${FAKE_RESOLVER_MODE:-good}" != partial ] || exit 1
        printf '%s\n' 'txt-record=resolver-state.keen.pbr,1|active|runtime_active'
        ;;
    fallback)
        printf '%s\n' \
            '# keen-pbr resolver state: fallback reason=socket_unavailable' \
            'txt-record=config-hash.keen.pbr,1|fedcba9876543210fedcba9876543210' \
            'txt-record=resolver-state.keen.pbr,1|fallback|socket_unavailable'
        cat "$KEEN_PBR_DNSMASQ_FALLBACK_FILE"
        ;;
    *) exit 9 ;;
esac
EOF
chmod 700 "$fake_bin"

fail() { printf '%s\n' "$*" >&2; exit 1; }
assert_has() { grep -q "$2" "$1" || fail "$1 is missing: $2"; }
assert_lacks() { if grep -q "$2" "$1"; then fail "$1 unexpectedly contains: $2"; fi; }
assert_same() { cmp -s "$1" "$2" || fail "$3"; }

run_hook() {
    if command -v busybox >/dev/null 2>&1; then
        set -- busybox sh "$test_helper" "$@"
    else
        set -- /bin/sh "$test_helper" "$@"
    fi
    env KEEN_PBR_BIN="$fake_bin" \
        KEEN_PBR_STATE_DIR="$state_dir" \
        KEEN_PBR_DNSMASQ_FALLBACK_FILE="$fallback_file" \
        FAKE_DNSMASQ_OUTPUT="$observed" \
        FAKE_RESOLVER_MODE="$mode" \
        FAKE_DIRECT_SERVER="${direct_server:-77.88.8.8}" \
        "$@"
}

write_old_default() {
    printf '%s\n' \
        '# Fallback upstream DNS servers for dnsmasq.' \
        '# This file is used when keen-pbr is disabled, stopped, or otherwise not active.' \
        '# Configure the same fallback resolvers here that you want dnsmasq to use without keen-pbr.' \
        '' 'server=8.8.8.8' 'server=8.8.4.4'
}

attempt=11111111111111111111111111111111
mode=good
printf '%s\n' '# keen-pbr automatic direct DNS fallback v1' \
    '# Bootstrap' 'server=9.9.9.9' > "$fallback_file"

# Complete activation persists only metadata-designated direct upstreams.
run_hook activate "$attempt"
assert_has "$fallback_file" '^server=77\.88\.8\.8$'
assert_has "$fallback_file" '^server=127\.0\.0\.1#40508$'
assert_lacks "$fallback_file" '^\(ipset\|nftset\|txt-record\)='
assert_lacks "$fallback_file" '^server=\(9\.9\.9\.9\|10\.20\.30\.53\)$'
assert_has "$state_dir/resolver-attempt-accepted" "^$attempt$"
cp "$fallback_file" "$workdir/saved.conf"

# A successful no-op reload must not replace or touch the persistent inode.
touch -t 200001010000 "$fallback_file"
before_metadata="$(stat -c '%i:%Y' "$fallback_file")"
run_hook reload "$attempt"
[ "$(stat -c '%i:%Y' "$fallback_file")" = "$before_metadata" ] ||
    fail 'unchanged fallback was rewritten'

# Inactive STOP selects the snapshot instead of the old package Google DNS.
run_hook deactivate
assert_has "$observed" "^conf-file=$fallback_file$"
assert_lacks "$observed" '^ipset='
assert_same "$fallback_file" "$workdir/saved.conf" 'STOP changed saved fallback'

# A complete fallback produced by the CLI must use that same saved snapshot.
printf 'Y\n' > "$state_dir/active"
mode=fallback
run_hook dnsmasq-config-entry > "$observed"
assert_has "$observed" '^# keen-pbr resolver state: fallback '
assert_has "$observed" '^server=77\.88\.8\.8$'
assert_lacks "$observed" '^ipset='

# A partial body, including different fallback metadata, cannot replace LKG
# or advance the persistent fallback. No receipt means parent reload fails.
mode=partial
direct_server=203.0.113.53
if run_hook reload 22222222222222222222222222222222; then
    fail 'partial stream falsely accepted a resolver attempt'
fi
assert_has "$observed" '^ipset=/vpn.example/kpbr4d_vpn$'
assert_lacks "$observed" '^# keen-pbr direct-fallback server=203\.0\.113\.53$'
assert_same "$fallback_file" "$workdir/saved.conf" 'partial stream changed fallback'
mode=good
direct_server=77.88.8.8

# User-owned bytes remain untouched, including comments and CRLF. An auto
# marker below the first line does not claim a custom file.
printf '# my manual resolver\r\n# keen-pbr automatic direct DNS fallback v1\r\nserver=192.0.2.53\r\n' > "$fallback_file"
cp "$fallback_file" "$workdir/manual.conf"
run_hook reload "$attempt"
assert_same "$fallback_file" "$workdir/manual.conf" 'manual fallback was overwritten'

# Only the exact previous packaged Google default migrates (LF and CRLF).
for ending in lf crlf; do
    if [ "$ending" = lf ]; then
        write_old_default > "$fallback_file"
    else
        write_old_default | sed 's/$/\r/' > "$fallback_file"
    fi
    run_hook reload "$attempt"
    assert_has "$fallback_file" '^# keen-pbr automatic direct DNS fallback v1$'
    assert_has "$fallback_file" '^server=77\.88\.8\.8$'
    assert_lacks "$fallback_file" '^server=8\.8\.'
done
printf 'server=8.8.8.8\nserver=8.8.4.4\n# customized\n' > "$fallback_file"
cp "$fallback_file" "$workdir/manual.conf"
run_hook reload "$attempt"
assert_same "$fallback_file" "$workdir/manual.conf" 'custom Google file was migrated'

# No direct upstream means no implicit reuse of a removed server. The complete
# fallback is still a complete generation, not a reason to resurrect active
# ipset/nftset directives from the managed LKG after routing was cleared.
cp "$workdir/saved.conf" "$fallback_file"
mode=no-direct
run_hook reload "$attempt"
assert_has "$fallback_file" '^# keen-pbr automatic direct DNS fallback v1$'
assert_lacks "$fallback_file" '^server='
mode=fallback
run_hook dnsmasq-config-entry > "$observed"
assert_has "$observed" '^# keen-pbr resolver state: fallback '
assert_lacks "$observed" '^\(server\|ipset\|nftset\)='

echo 'dnsmasq direct fallback: 10 scenarios passed'
