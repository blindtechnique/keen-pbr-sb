#!/bin/sh

set -eu

init_script=${1:-}
prerm_script=${2:-}
[ -f "$init_script" ] || {
    echo "usage: $0 <S80keen-pbr> <prerm>" >&2
    exit 2
}
[ -f "$prerm_script" ] || {
    echo "usage: $0 <S80keen-pbr> <prerm>" >&2
    exit 2
}

work=$(mktemp -d)
trap 'rm -rf "$work"' 0 HUP INT TERM

# Source only the production functions under test. The Keenetic rc.func
# dispatcher is deliberately not emulated here.
{
    sed -n '/^read_fastnat_value()/,/^# Verify that a PID still belongs/p' "$init_script" |
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
assignment=${2:-}
value=${assignment#*=}
case "$assignment" in
    net.ipv4.netfilter.ip_conntrack_fastnat=*)
        [ "${FASTNAT_TEST_IPV4_ALIAS:-yes}" = yes ] || exit 1
        mkdir -p "$FASTNAT_PROC_ROOT/net/ipv4/netfilter"
        printf '%s\n' "$value" > \
            "$FASTNAT_PROC_ROOT/net/ipv4/netfilter/ip_conntrack_fastnat"
        ;;
    net.netfilter.nf_conntrack_fastnat=*)
        [ "${FASTNAT_TEST_NET_ALIAS:-yes}" = yes ] || exit 1
        mkdir -p "$FASTNAT_PROC_ROOT/net/netfilter"
        printf '%s\n' "$value" > \
            "$FASTNAT_PROC_ROOT/net/netfilter/nf_conntrack_fastnat"
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

# The FastNAT contract exercises lifecycle ordering, not the separate
# PID/startticks lease implementation. Model a uniquely owned stop admission
# without adding entries to the expected FastNAT action log.
acquire_control_lease() {
    STOPPING_CONTROL_OWNER_ROLE=stop
    return 0
}
release_control_lease() { return 0; }
control_lease_owned_by_self() { return 0; }
begin_stopping_marker() { return 0; }
mark_stopping_mutation_started() { return 0; }
discard_control_mailbox_after_successful_stop() { return 0; }
finish_stopping_marker() { return 0; }
drain_control_runtime() { return 0; }

assert_calls_contain() {
    pattern=$1
    grep -Fq -- "$pattern" "$calls" || {
        echo "missing sysctl call: $pattern" >&2
        cat "$calls" >&2
        exit 1
    }
}

assert_no_calls() {
    [ ! -s "$calls" ] || {
        echo "unexpected sysctl calls:" >&2
        cat "$calls" >&2
        exit 1
    }
}

# Real Keenetic sysctl pseudo-files can expose a valid value without a final
# newline. BusyBox read returns failure at EOF in that case even though it has
# assigned the value; startup must still snapshot and disable FastNAT.
printf '%s' 1 > "$FASTNAT_PROC_ROOT/net/netfilter/nf_conntrack_fastnat"
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

# A firmware netfilter rebuild may re-enable FastNAT while the daemon stays
# alive. The runtime guard must disable it without replacing the original
# snapshot that a graceful final stop will restore.
printf '%s\n' 1 > "$FASTNAT_STATE_FILE"
printf '%s\n' 1 > "$FASTNAT_PROC_ROOT/net/netfilter/nf_conntrack_fastnat"
: > "$calls"
ensure_fastnat_disabled
[ "$(cat "$FASTNAT_STATE_FILE")" = 1 ]
assert_calls_contain 'net.ipv4.netfilter.ip_conntrack_fastnat=0'
assert_calls_contain 'net.netfilter.nf_conntrack_fastnat=0'

# Healthy steady state is a true no-op: no repeated sysctl writes or logs.
printf '%s' 0 > "$FASTNAT_PROC_ROOT/net/netfilter/nf_conntrack_fastnat"
: > "$calls"
ensure_fastnat_disabled
assert_no_calls

# A missing runtime snapshot cannot be reconstructed from firmware-created
# drift. Record the fail-closed disabled value rather than later enabling a
# setting which may have been disabled before keen-pbr started.
rm -f "$FASTNAT_STATE_FILE"
printf '%s\n' 1 > "$FASTNAT_PROC_ROOT/net/netfilter/nf_conntrack_fastnat"
: > "$calls"
ensure_fastnat_disabled
[ "$(cat "$FASTNAT_STATE_FILE")" = 0 ]
assert_calls_contain 'net.netfilter.nf_conntrack_fastnat=0'
: > "$calls"
restore_hwnat_if_safe
assert_calls_contain 'net.netfilter.nf_conntrack_fastnat=0'
[ ! -e "$FASTNAT_STATE_FILE" ]

# If Keenetic exposes both aliases inconsistently, an enabled alias wins: the
# routing runtime cannot safely assume acceleration is disabled.
mkdir -p "$FASTNAT_PROC_ROOT/net/ipv4/netfilter"
printf '%s\n' 0 > "$FASTNAT_PROC_ROOT/net/netfilter/nf_conntrack_fastnat"
printf '%s\n' 1 > "$FASTNAT_PROC_ROOT/net/ipv4/netfilter/ip_conntrack_fastnat"
rm -f "$FASTNAT_STATE_FILE"
: > "$calls"
ensure_fastnat_disabled
[ "$(cat "$FASTNAT_STATE_FILE")" = 0 ]
assert_calls_contain 'net.netfilter.nf_conntrack_fastnat=0'
rm -f "$FASTNAT_PROC_ROOT/net/ipv4/netfilter/ip_conntrack_fastnat"
restore_hwnat_if_safe

# A successful write to one alias must not hide a second readable alias that
# remains enabled. The aggregate postcondition is authoritative.
printf '%s\n' 1 > "$FASTNAT_STATE_FILE"
printf '%s\n' 1 > "$FASTNAT_PROC_ROOT/net/netfilter/nf_conntrack_fastnat"
mkdir -p "$FASTNAT_PROC_ROOT/net/ipv4/netfilter"
printf '%s\n' 1 > \
    "$FASTNAT_PROC_ROOT/net/ipv4/netfilter/ip_conntrack_fastnat"
FASTNAT_TEST_IPV4_ALIAS=yes
FASTNAT_TEST_NET_ALIAS=no
export FASTNAT_TEST_IPV4_ALIAS FASTNAT_TEST_NET_ALIAS
: > "$calls"
if ensure_fastnat_disabled; then
    echo "runtime guard accepted a partial FastNAT write" >&2
    exit 1
fi
[ "$(cat "$FASTNAT_PROC_ROOT/net/netfilter/nf_conntrack_fastnat")" = 1 ]
[ "$(cat "$FASTNAT_PROC_ROOT/net/ipv4/netfilter/ip_conntrack_fastnat")" = 0 ]
rm -f "$FASTNAT_STATE_FILE"
FASTNAT_TEST_NET_ALIAS=yes
export FASTNAT_TEST_NET_ALIAS

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
rm -f "$FASTNAT_PROC_ROOT/net/ipv4/netfilter/ip_conntrack_fastnat"
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
rm -f "$FASTNAT_PROC_ROOT/net/ipv4/netfilter/ip_conntrack_fastnat"
rm -f "$FASTNAT_STATE_FILE"
: > "$calls"
ensure_fastnat_disabled
[ ! -e "$FASTNAT_STATE_FILE" ]
assert_no_calls

# A damaged snapshot fails closed and is never passed to sysctl by the
# runtime guard either.
printf '%s\n' unexpected > "$FASTNAT_STATE_FILE"
: > "$calls"
if ensure_fastnat_disabled; then
    echo "runtime guard accepted an invalid FastNAT snapshot" >&2
    exit 1
fi
assert_no_calls
rm -f "$FASTNAT_STATE_FILE"

# The mailbox wrapper is covered by run-netfilter-hook-signals.sh. Exercise its
# mutation primitive here: it proves that a daemon is live, restores the
# FastNAT invariant, and only then delivers the signal. A failed guard must
# never schedule a daemon refresh.
reapply_order="$work/reapply-order"
stopping_marker_authorizes_runtime_suppression() {
    return 1
}
validate_service_pid() {
    printf '%s\n' "validate:$1" >> "$reapply_order"
    [ "${FASTNAT_TEST_VALIDATE_OK:-yes}" = yes ]
}
ensure_fastnat_disabled() {
    printf '%s\n' guard >> "$reapply_order"
    [ "${FASTNAT_TEST_GUARD_OK:-yes}" = yes ]
}
signal_service() {
    printf '%s\n' "signal:$1" >> "$reapply_order"
    [ "${FASTNAT_TEST_SIGNAL_OK:-yes}" = yes ]
}

: > "$reapply_order"
FASTNAT_TEST_VALIDATE_OK=yes
FASTNAT_TEST_SIGNAL_OK=yes
FASTNAT_TEST_GUARD_OK=yes
reapply_netfilter_runtime_without_lease SIGUSR1
[ "$(cat "$reapply_order")" = "validate:SIGUSR1
guard
signal:SIGUSR1" ]

: > "$reapply_order"
FASTNAT_TEST_VALIDATE_OK=no
if reapply_netfilter_runtime_without_lease SIGUSR2; then
    echo "reapply accepted a failed daemon validation" >&2
    exit 1
fi
[ "$(cat "$reapply_order")" = "validate:SIGUSR2" ]

: > "$reapply_order"
FASTNAT_TEST_VALIDATE_OK=yes
FASTNAT_TEST_GUARD_OK=no
if reapply_netfilter_runtime_without_lease SIGUSR1; then
    echo "reapply ignored a failed FastNAT guard" >&2
    exit 1
fi
[ "$(cat "$reapply_order")" = "validate:SIGUSR1
guard" ]

: > "$reapply_order"
FASTNAT_TEST_GUARD_OK=yes
FASTNAT_TEST_SIGNAL_OK=no
if reapply_netfilter_runtime_without_lease SIGUSR2; then
    echo "reapply accepted a failed daemon signal" >&2
    exit 1
fi
[ "$(cat "$reapply_order")" = "validate:SIGUSR2
guard
signal:SIGUSR2" ]

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
cleanup_stale_tcp_rst_firewall() {
    printf '%s\n' cleanup-tcp-rst >> "$order"
}
cleanup_stale_meta_udp443_firewall() {
    printf '%s\n' cleanup-meta-udp443 >> "$order"
}

FASTNAT_RESTORE_ON_START_FAILURE=no
START_CONTROL_LEASE_HELD=no
STOPPING_CONTROL_LEASE_ROLE=""
: > "$order"
restore_fastnat_after_failed_start
[ ! -s "$order" ]

# A losing start/restart must not restore or remove the snapshot created by the
# exact start-lease winner after the loser inspected the old shared pathname.
printf '%s\n' 1 > "$FASTNAT_STATE_FILE"
FASTNAT_RESTORE_ON_START_FAILURE=yes
restore_fastnat_after_failed_start
[ ! -s "$order" ]
[ -f "$FASTNAT_STATE_FILE" ]

# Rollback authority is established only after exact start-lease ownership.
START_CONTROL_LEASE_HELD=yes
STOPPING_CONTROL_LEASE_ROLE=start
FASTNAT_RESTORE_ON_START_FAILURE=no
rm -f "$FASTNAT_STATE_FILE"
establish_fastnat_start_rollback_authority if-absent
[ "$FASTNAT_RESTORE_ON_START_FAILURE" = yes ]
printf '%s\n' 1 > "$FASTNAT_STATE_FILE"
restore_fastnat_after_failed_start
[ "$(cat "$order")" = restore ]
[ "$FASTNAT_RESTORE_ON_START_FAILURE" = no ]

: > "$order"
FASTNAT_RESTORE_ON_START_FAILURE=no
establish_fastnat_start_rollback_authority restart
[ "$FASTNAT_RESTORE_ON_START_FAILURE" = yes ]
restore_fastnat_after_failed_start
[ "$(cat "$order")" = restore ]

# Exact lease ownership still cannot roll back underneath a daemon that another
# completed start already launched before this action acquired the lease.
: > "$order"
: > "$FASTNAT_TEST_ALIVE"
printf '%s\n' 1 > "$FASTNAT_STATE_FILE"
FASTNAT_RESTORE_ON_START_FAILURE=yes
restore_fastnat_after_failed_start
[ ! -s "$order" ]
[ -f "$FASTNAT_STATE_FILE" ]
rm -f "$FASTNAT_TEST_ALIVE" "$FASTNAT_STATE_FILE"
START_CONTROL_LEASE_HELD=no
STOPPING_CONTROL_LEASE_ROLE=""

: > "$order"
stop_service_for_action stop no
[ "$(cat "$order")" = "prepare
stop:stop
cleanup-tcp-rst
cleanup-meta-udp443" ]

: > "$order"
stop_service_for_action stop yes
[ "$(cat "$order")" = "prepare
stop:stop
cleanup-tcp-rst
cleanup-meta-udp443
restore" ]

# Dispatcher authority is created after acquisition for both ordinary start
# and restart; neither pre-lease path may infer ownership from shared state.
start_case=$(sed -n '/^[[:space:]]*start)/,/^[[:space:]]*;;/p' "$init_script")
case "$start_case" in
    *'FASTNAT_RESTORE_ON_START_FAILURE=no'*'begin_start_control_lease'*'establish_fastnat_start_rollback_authority if-absent'*'prepare_start'*) ;;
    *) echo "start rollback authority is not ordered behind its lease" >&2; exit 1 ;;
esac
restart_case=$(sed -n \
    '/^[[:space:]]*restart|restartall)/,/^[[:space:]]*;;/p' "$init_script")
case "$restart_case" in
    *'FASTNAT_RESTORE_ON_START_FAILURE=no'*'begin_start_control_lease'*'establish_fastnat_start_rollback_authority restart'*'prepare_start'*) ;;
    *) echo "restart rollback authority is not ordered behind its lease" >&2; exit 1 ;;
esac

# Package replacement must not briefly restore FastNAT between the old and new
# daemon. A real final stop keeps the existing restore behavior.
upgrade_case=$(sed -n '/^[[:space:]]*stop-for-upgrade)/,/^[[:space:]]*;;/p' \
    "$init_script")
printf '%s\n' "$upgrade_case" |
    grep -Fq 'stop_service_for_action stop no'
if printf '%s\n' "$upgrade_case" | grep -Fq 'restore_hwnat_if_safe'; then
    echo "upgrade stop restores FastNAT between package versions" >&2
    exit 1
fi

# Only an attempted daemon start can make a failed rc.func result unsafe.
# Read-only actions such as status/check must never mutate lifecycle state.
dispatcher_tail=$(sed -n '/^\. \/opt\/etc\/init.d\/rc.func/,$p' "$init_script")
printf '%s\n' "$dispatcher_tail" |
    grep -Fq ': > "$FASTNAT_UNSAFE_STOP_FILE"'
printf '%s\n' "$dispatcher_tail" |
    grep -Fq '[ "$FASTNAT_DISPATCH_ACTION" = start ]'
if printf '%s\n' "$dispatcher_tail" |
    grep -Fq 'restore_fastnat_after_failed_start'; then
    echo "post-dispatch startup failure restores FastNAT unsafely" >&2
    exit 1
fi

grep -Fq 'reapply_netfilter_runtime SIGUSR1' "$init_script"
grep -Fq 'reapply_netfilter_runtime SIGUSR2' "$init_script"

# prerm may continue after cleanup failed only when the daemon is proven dead.
# This prevents an old lifecycle bug from stranding a half-removed package,
# while still refusing to replace a binary which is actually executing.
prerm_root="$work/prerm"
mkdir -p "$prerm_root/init.d" "$prerm_root/bin"
sed "s#/opt/etc/init.d#$prerm_root/init.d#g" "$prerm_script" > \
    "$prerm_root/prerm"
cat > "$prerm_root/init.d/S80keen-pbr" <<'EOF'
#!/bin/sh
printf 'keen-pbr:%s\n' "$1" >> "$PRERM_TEST_LOG"
exit "${PRERM_TEST_STOP_STATUS:-0}"
EOF
cat > "$prerm_root/init.d/S79transport-manager" <<'EOF'
#!/bin/sh
printf 'transport:%s\n' "$1" >> "$PRERM_TEST_LOG"
exit 0
EOF
cat > "$prerm_root/bin/pidof" <<'EOF'
#!/bin/sh
[ "${PRERM_TEST_PID_ALIVE:-no}" = yes ] || exit 1
printf '%s\n' 4242
EOF
chmod +x "$prerm_root/prerm" "$prerm_root/init.d/"* "$prerm_root/bin/pidof"

prerm_log="$prerm_root/actions"
: > "$prerm_log"
PATH="$prerm_root/bin:$PATH" PRERM_TEST_LOG="$prerm_log" \
    PKG_UPGRADE=1 /bin/sh "$prerm_root/prerm"
[ "$(sed -n '1p' "$prerm_log")" = 'keen-pbr:stop-for-upgrade' ]
[ "$(sed -n '2p' "$prerm_log")" = 'transport:stop' ]

: > "$prerm_log"
PATH="$prerm_root/bin:$PATH" PRERM_TEST_LOG="$prerm_log" \
    /bin/sh "$prerm_root/prerm"
[ "$(sed -n '1p' "$prerm_log")" = 'keen-pbr:stop' ]

: > "$prerm_log"
if PATH="$prerm_root/bin:$PATH" PRERM_TEST_LOG="$prerm_log" \
    PKG_UPGRADE=1 PRERM_TEST_STOP_STATUS=1 PRERM_TEST_PID_ALIVE=no \
    /bin/sh "$prerm_root/prerm"; then
    echo "upgrade prerm ignored failed lifecycle cleanup" >&2
    exit 1
fi
[ "$(wc -l < "$prerm_log" | tr -d ' ')" = 1 ]

: > "$prerm_log"
if PATH="$prerm_root/bin:$PATH" PRERM_TEST_LOG="$prerm_log" \
    PKG_UPGRADE=1 PRERM_TEST_STOP_STATUS=1 PRERM_TEST_PID_ALIVE=yes \
    /bin/sh "$prerm_root/prerm"; then
    echo "prerm replaced a running keen-pbr binary" >&2
    exit 1
fi
[ "$(wc -l < "$prerm_log" | tr -d ' ')" = 1 ]

: > "$prerm_log"
if PATH="$prerm_root/bin:$PATH" PRERM_TEST_LOG="$prerm_log" \
    PRERM_TEST_STOP_STATUS=1 PRERM_TEST_PID_ALIVE=no \
    /bin/sh "$prerm_root/prerm"; then
    echo "final uninstall ignored failed lifecycle cleanup" >&2
    exit 1
fi
[ "$(wc -l < "$prerm_log" | tr -d ' ')" = 1 ]

# Keenetic's firmware /bin/sh accepts scripts but does not expose the optional
# POSIX -n parser mode. Keep the syntax assertion where the shell supports it,
# while still allowing this lifecycle test to run on the actual target shell.
if /bin/sh -n -c ':' >/dev/null 2>&1; then
    /bin/sh -n "$init_script"
    /bin/sh -n "$prerm_script"
fi
