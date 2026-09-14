#!/bin/sh

set -eu

helper="$1"
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT HUP INT TERM

state_dir="$workdir/state"
fake_bin="$workdir/keen-pbr"
mkdir -p "$state_dir"
# Keenetic and Debian expose the config-script stream only while override is
# active. OpenWrt ignores this state file, so the same behavior test remains
# valid for all package helpers.
printf 'Y\n' > "$state_dir/active"

cat > "$fake_bin" <<'EOF'
#!/bin/sh
set -eu

case "${FAKE_RESOLVER_MODE:-valid}" in
    valid)
        [ "${KEEN_PBR_RESOLVER_ATTEMPT_ID:-}" = "${EXPECTED_ATTEMPT_ID:-}" ] || exit 8
        printf '%s\n' \
            '# keen-pbr resolver state: active' \
            'server=1.1.1.1' \
            'txt-record=config-hash.keen.pbr,test-hash' \
            'txt-record=resolver-state.keen.pbr,1|active|runtime_active'
        ;;
    invalid)
        printf '%s\n' '# incomplete resolver candidate'
        ;;
    *)
        exit 9
        ;;
esac
EOF
chmod +x "$fake_bin"

first_attempt='11111111111111111111111111111111'
printf '%s\n' "$first_attempt" > "$state_dir/resolver-attempt-id"
KEEN_PBR_BIN="$fake_bin" \
KEEN_PBR_STATE_DIR="$state_dir" \
EXPECTED_ATTEMPT_ID="$first_attempt" \
FAKE_RESOLVER_MODE=valid \
    /bin/sh "$helper" dnsmasq-config-entry > "$workdir/valid.out" 2>/dev/null

[ "$(tr -d '[:space:]' < "$state_dir/resolver-attempt-accepted")" = "$first_attempt" ]
grep -q '^# keen-pbr resolver state: active$' "$workdir/valid.out"

second_attempt='22222222222222222222222222222222'
printf '%s\n' "$second_attempt" > "$state_dir/resolver-attempt-id"
rm -f "$state_dir/resolver-attempt-accepted"
KEEN_PBR_BIN="$fake_bin" \
KEEN_PBR_STATE_DIR="$state_dir" \
EXPECTED_ATTEMPT_ID="$second_attempt" \
FAKE_RESOLVER_MODE=invalid \
    /bin/sh "$helper" dnsmasq-config-entry > "$workdir/invalid.out" 2>/dev/null

[ ! -e "$state_dir/resolver-attempt-accepted" ]
grep -q '^# keen-pbr resolver state: active$' "$workdir/invalid.out"
! grep -q '^# incomplete resolver candidate$' "$workdir/invalid.out"

rm -f "$state_dir/resolver-attempt-id" "$state_dir/resolver-attempt-accepted"
KEEN_PBR_BIN="$fake_bin" \
KEEN_PBR_STATE_DIR="$state_dir" \
EXPECTED_ATTEMPT_ID='' \
FAKE_RESOLVER_MODE=valid \
    /bin/sh "$helper" dnsmasq-config-entry > "$workdir/manual.out" 2>"$workdir/manual.err"

[ ! -e "$state_dir/resolver-attempt-accepted" ]
grep -q '^# keen-pbr resolver state: active$' "$workdir/manual.out"
[ ! -s "$workdir/manual.err" ] || {
    echo 'A normal start without an attempt ID emitted a shell error' >&2
    cat "$workdir/manual.err" >&2
    exit 1
}

# Missing/stale receipts are normal while waiting for dnsmasq. Exercise the
# shipped loop with instant fixture delays: only its final timeout warning is
# meaningful, never one file-open error on each poll. No real process is used.
eval "$(sed -n '/^resolver_attempt_is_valid() {/,/^}/p' "$helper")"
eval "$(sed -n '/^wait_for_resolver_attempt_acceptance() {/,/^}/p' "$helper")"
ATTEMPT_ACCEPTED_FILE="$state_dir/resolver-attempt-accepted"
sleep() { :; }
usleep() { :; }
log_warn() { printf '%s\n' "$1" >&2; }
for receipt in missing stale; do
    rm -f "$ATTEMPT_ACCEPTED_FILE"
    if [ "$receipt" = stale ]; then
        printf '%s\n' "$first_attempt" > "$ATTEMPT_ACCEPTED_FILE"
    fi
    if wait_for_resolver_attempt_acceptance "$second_attempt" 2>"$workdir/wait.err"; then
        echo 'An absent or stale receipt was accepted' >&2
        exit 1
    fi
    [ "$(cat "$workdir/wait.err")" = \
        'dnsmasq did not accept the expected keen-pbr resolver generation' ]
done
printf '%s\n' "$second_attempt" > "$ATTEMPT_ACCEPTED_FILE"
wait_for_resolver_attempt_acceptance "$second_attempt" 2>"$workdir/wait.err"
[ ! -s "$workdir/wait.err" ]
