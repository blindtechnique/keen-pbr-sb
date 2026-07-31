#!/bin/sh

set -eu

init_script=${1:-}
[ -f "$init_script" ] || {
    echo "usage: $0 <S80keen-pbr>" >&2
    exit 2
}

work=$(mktemp -d)
trap 'rm -rf "$work"' 0 HUP INT TERM

# Source only the production functions under test. The Keenetic rc.func
# dispatcher is deliberately not emulated here.
{
    sed -n '/^read_fastnat_value()/,/^signal_service()/p' "$init_script" |
        sed '$d'
    sed -n '/^stop_keen_pbr()/,/^prepare_start()/p' "$init_script" |
        sed '$d'
    sed -n '/^prepare_start()/,/^reapply_dnsmasq_config()/p' "$init_script" |
        sed '$d'
} > "$work/functions.sh"

calls="$work/sysctl.calls"
mkdir -p "$work/bin" "$work/proc/net/netfilter" "$work/state"
cat > "$work/bin/sysctl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$FASTNAT_TEST_CALLS"
case "$*" in
    *net.ipv4.netfilter.ip_conntrack_fastnat=*)
        [ "${FASTNAT_TEST_IPV4_ALIAS:-yes}" = yes ]
        ;;
    *net.netfilter.nf_conntrack_fastnat=*)
        [ "${FASTNAT_TEST_NET_ALIAS:-yes}" = yes ]
        ;;
    *) exit 1 ;;
esac
EOF
chmod +x "$work/bin/sysctl"

PATH="$work/bin:$PATH"
FASTNAT_TEST_CALLS=$calls
FASTNAT_PROC_ROOT="$work/proc"
FASTNAT_STATE_FILE="$work/state/value"
FASTNAT_UNSAFE_STOP_FILE="$work/state/unsafe"
export PATH FASTNAT_TEST_CALLS FASTNAT_PROC_ROOT
export FASTNAT_STATE_FILE FASTNAT_UNSAFE_STOP_FILE

log() { :; }
log_error() { :; }
. "$work/functions.sh"

assert_calls_contain() {
    pattern=$1
    grep -Fq -- "$pattern" "$calls" || {
        echo "missing sysctl call: $pattern" >&2
        cat "$calls" >&2
        exit 1
    }
}

printf '%s\n' 1 > "$FASTNAT_PROC_ROOT/net/netfilter/nf_conntrack_fastnat"
: > "$calls"
original_umask=$(umask)
disable_hwnat
[ "$(umask)" = "$original_umask" ]
[ "$(cat "$FASTNAT_STATE_FILE")" = 1 ]
assert_calls_contain 'net.ipv4.netfilter.ip_conntrack_fastnat=0'
assert_calls_contain 'net.netfilter.nf_conntrack_fastnat=0'

: > "$calls"
restore_hwnat_if_safe
assert_calls_contain 'net.ipv4.netfilter.ip_conntrack_fastnat=1'
assert_calls_contain 'net.netfilter.nf_conntrack_fastnat=1'
[ ! -e "$FASTNAT_STATE_FILE" ]

# An originally disabled system must stay disabled after a clean stop.
printf '%s\n' 0 > "$FASTNAT_PROC_ROOT/net/netfilter/nf_conntrack_fastnat"
: > "$calls"
disable_hwnat
restore_hwnat_if_safe
assert_calls_contain 'net.netfilter.nf_conntrack_fastnat=0'
[ ! -e "$FASTNAT_STATE_FILE" ]

# A forced/unclean stop must never re-enable FastNAT over stale routing state.
printf '%s\n' 1 > "$FASTNAT_STATE_FILE"
: > "$FASTNAT_UNSAFE_STOP_FILE"
: > "$calls"
restore_hwnat_if_safe
[ ! -s "$calls" ]
[ -e "$FASTNAT_STATE_FILE" ]
rm -f "$FASTNAT_UNSAFE_STOP_FILE"

# A damaged snapshot is rejected instead of being passed to sysctl.
printf '%s\n' unexpected > "$FASTNAT_STATE_FILE"
: > "$calls"
if restore_hwnat_if_safe; then
    echo "invalid FastNAT state was accepted" >&2
    exit 1
fi
[ ! -s "$calls" ]
rm -f "$FASTNAT_STATE_FILE"

# One available Keenetic sysctl alias is sufficient.
printf '%s\n' 1 > "$FASTNAT_PROC_ROOT/net/netfilter/nf_conntrack_fastnat"
FASTNAT_TEST_IPV4_ALIAS=no
FASTNAT_TEST_NET_ALIAS=yes
export FASTNAT_TEST_IPV4_ALIAS FASTNAT_TEST_NET_ALIAS
: > "$calls"
disable_hwnat
restore_hwnat_if_safe
assert_calls_contain 'net.netfilter.nf_conntrack_fastnat=1'

# Kernels without either FastNAT control remain supported.
rm -f "$FASTNAT_PROC_ROOT/net/netfilter/nf_conntrack_fastnat"
rm -f "$FASTNAT_STATE_FILE"
: > "$calls"
disable_hwnat
[ ! -e "$FASTNAT_STATE_FILE" ]
[ ! -s "$calls" ]

# Verify the control-flow contract separately from sysctl behavior.
order="$work/order"

# A failed TERM is not proof of graceful daemon shutdown, even when the
# process disappears before the next liveness probe. FastNAT must therefore
# stay disabled and its original-state snapshot must remain available.
FASTNAT_TEST_ALIVE="$work/alive"
PIDFILE="$work/keen-pbr.pid"
PROCS="keen-pbr-fastnat-test-$$"
DESC=keen-pbr
export FASTNAT_TEST_ALIVE PIDFILE PROCS DESC
: > "$FASTNAT_TEST_ALIVE"
printf '%s\n' 4242 > "$PIDFILE"
printf '%s\n' 1 > "$FASTNAT_STATE_FILE"
rm -f "$FASTNAT_UNSAFE_STOP_FILE"
pidof() {
    [ -e "$FASTNAT_TEST_ALIVE" ] && printf '%s\n' 4242
}
kill() {
    if [ "${1:-}" = -TERM ]; then
        rm -f "$FASTNAT_TEST_ALIVE"
        return 1
    fi
    return 0
}
sleep() { :; }
: > "$calls"
stop_keen_pbr stop
[ "$STOP_KEEN_PBR_SAFE" = no ]
[ -e "$FASTNAT_UNSAFE_STOP_FILE" ]
[ -e "$FASTNAT_STATE_FILE" ]
restore_hwnat_if_safe
[ ! -s "$calls" ]
rm -f "$FASTNAT_UNSAFE_STOP_FILE" "$FASTNAT_STATE_FILE"

prepare_stop() { printf '%s\n' prepare >> "$order"; }
stop_keen_pbr() {
    printf '%s\n' "stop:$1" >> "$order"
    STOP_KEEN_PBR_SAFE=yes
}
restore_hwnat_if_safe() { printf '%s\n' restore >> "$order"; }

FASTNAT_RESTORE_ON_START_FAILURE=no
: > "$order"
restore_fastnat_after_failed_start
[ ! -s "$order" ]

FASTNAT_RESTORE_ON_START_FAILURE=yes
restore_fastnat_after_failed_start
[ "$(cat "$order")" = restore ]

: > "$order"
stop_service_for_action stop no
[ "$(cat "$order")" = "prepare
stop:stop" ]

: > "$order"
stop_service_for_action stop yes
[ "$(cat "$order")" = "prepare
stop:stop
restore" ]

# After the dispatcher has attempted to spawn the daemon, failure is no
# longer provably clean. The production tail must mark the stop unsafe and
# must not restore FastNAT in that post-spawn branch.
dispatcher_tail=$(sed -n '/^\. \/opt\/etc\/init.d\/rc.func/,$p' "$init_script")
printf '%s\n' "$dispatcher_tail" |
    grep -Fq ': > "$FASTNAT_UNSAFE_STOP_FILE"'
if printf '%s\n' "$dispatcher_tail" |
    grep -Fq 'restore_fastnat_after_failed_start'; then
    echo "post-dispatch startup failure restores FastNAT unsafely" >&2
    exit 1
fi

/bin/sh -n "$init_script"
