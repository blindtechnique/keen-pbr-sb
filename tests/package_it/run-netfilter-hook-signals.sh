#!/bin/sh

set -eu

if [ "$#" -ne 6 ]; then
    echo "usage: $0 <keenetic-hook> <keenetic-init> <rescue-guard> <openwrt-init> <openwrt-firewall> <openwrt-hotplug>" >&2
    exit 2
fi

keenetic_hook=$1
keenetic_init=$2
rescue_guard=$3
openwrt_init=$4
openwrt_firewall=$5
openwrt_hotplug=$6

work=$(mktemp -d)
trap 'rm -rf "$work"' 0 HUP INT TERM

calls="$work/calls"
fake_init="$work/fake-init"
stopping_runtime="$work/stopping-runtime"
stopping_marker="$stopping_runtime/stopping"
stopping_pidfile="$work/keenetic.pid"
mkdir "$stopping_runtime"
chmod 0700 "$stopping_runtime"

cat > "$fake_init" <<'EOF'
#!/bin/sh
printf '%s\n' "$1" >> "$KEEN_PBR_TEST_CALLS"
EOF
chmod +x "$fake_init"

cat > "$work/logger" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$work/logger"

run_hook() {
    hook_type=$1
    hook_table=$2
    expected=$3
    : > "$calls"

    env \
        PATH="$work:$PATH" \
        type="$hook_type" \
        table="$hook_table" \
        KEEN_PBR_INIT_SCRIPT="$fake_init" \
        KEEN_PBR_TEST_CALLS="$calls" \
        KEEN_PBR_STOPPING_RUNTIME_DIR="$stopping_runtime" \
        KEEN_PBR_STOPPING_MARKER="$stopping_marker" \
        KEEN_PBR_PIDFILE="$stopping_pidfile" \
        KEEN_PBR_PROC_ROOT=/proc \
        /bin/sh "$keenetic_hook"

    actual=$(cat "$calls")
    if [ "$actual" != "$expected" ]; then
        echo "unexpected hook action for type=$hook_type table=$hook_table: '$actual'" >&2
        exit 1
    fi
}

run_hook iptables mangle reapply-firewall
run_hook iptables nat reapply-nat
run_hook ip6tables mangle reapply-firewall
run_hook ip6tables nat reapply-nat
run_hook iptables filter ""
run_hook nftables nat ""

# Pre-mutation admission persists the event behind the stop lease. Only the
# atomic mutating phase suppresses teardown churn; it remains authoritative if
# the controller dies, while PID reuse/malformed ownership still fails open.
hook_pid=$$
hook_startticks=$(awk '{ print $22; exit }' "/proc/$hook_pid/stat")
printf '%s\n' "$hook_pid" > "$stopping_pidfile"
printf 'keen-pbr-stopping-v3 admitted %s %s %s %s\n' \
    "$hook_pid" "$hook_startticks" "$hook_pid" "$hook_startticks" \
    > "$stopping_marker"
chmod 0600 "$stopping_marker"
run_hook iptables mangle reapply-firewall

printf 'keen-pbr-stopping-v3 mutating %s %s %s %s\n' \
    "$hook_pid" "$hook_startticks" "$hook_pid" "$hook_startticks" \
    > "$stopping_marker"
chmod 0600 "$stopping_marker"
run_hook iptables mangle ""

# Post-mutation controller death remains fail-closed.
printf 'keen-pbr-stopping-v3 mutating %s %s 99999999 1\n' \
    "$hook_pid" "$hook_startticks" > "$stopping_marker"
chmod 0600 "$stopping_marker"
run_hook iptables mangle ""

# Pre-mutation controller death fails open and preserves the event.
printf 'keen-pbr-stopping-v3 admitted %s %s 99999999 1\n' \
    "$hook_pid" "$hook_startticks" > "$stopping_marker"
chmod 0600 "$stopping_marker"
run_hook iptables mangle reapply-firewall

printf 'keen-pbr-stopping-v3 mutating %s %s %s %s\n' \
    "$hook_pid" "$hook_startticks" "$hook_pid" "$hook_startticks" \
    > "$stopping_marker"
chmod 0600 "$stopping_marker"
printf '%s\n' "$((hook_pid + 1))" > "$stopping_pidfile"
run_hook iptables mangle reapply-firewall
printf '%s\n' "$hook_pid" > "$stopping_pidfile"

chmod 0755 "$stopping_runtime"
run_hook iptables nat reapply-nat
chmod 0700 "$stopping_runtime"

printf 'keen-pbr-stopping-v3 mutating %s %s1 %s %s\n' \
    "$hook_pid" "$hook_startticks" "$hook_pid" "$hook_startticks" \
    > "$stopping_marker"
run_hook iptables mangle reapply-firewall

printf '%s\n' 'not-a-keen-pbr-marker' > "$stopping_marker"
run_hook iptables nat reapply-nat

rm -f "$stopping_marker"
printf 'keen-pbr-stopping-v3 mutating %s %s %s %s\n' \
    "$hook_pid" "$hook_startticks" "$hook_pid" "$hook_startticks" \
    > "$work/symlink-target"
chmod 0600 "$work/symlink-target"
ln -s "$work/symlink-target" "$stopping_marker"
run_hook iptables mangle reapply-firewall
rm -f "$stopping_marker"

printf 'keen-pbr-stopping-v3 mutating %s %s %s %s\n' \
    "$hook_pid" "$hook_startticks" "$hook_pid" "$hook_startticks" \
    > "$stopping_marker"
chmod 0600 "$stopping_marker"
cat > "$work/stat" <<'EOF'
#!/bin/sh
exit 1
EOF
chmod +x "$work/stat"
run_hook iptables nat reapply-nat
rm -f "$work/stat" "$stopping_marker"

# Exercise the init-script ownership and lifecycle helpers without rc.func.
marker_functions="$work/stopping-marker-functions.sh"
stop_function="$work/stop-service-for-action.sh"
runtime_function="$work/control-runtime-drain.sh"
preserve_function="$work/preserve-control-work.sh"
delayed_action="$work/delayed-control-drain-action.sh"
sed -n \
    '/^# Netfilter stop admission marker/,/^# End netfilter stop admission marker/p' \
    "$keenetic_init" > "$marker_functions"
awk '
    /^stop_service_for_action\(\)/ { capture = 1 }
    capture { print }
    capture && /^}$/ { exit }
' "$keenetic_init" > "$stop_function"
awk '
    /^reapply_netfilter_runtime_without_lease\(\)/ { capture = 1 }
    /^reapply_dns_runtime\(\)/ { runtime = 1 }
    capture { print }
    capture && runtime && /^}$/ { exit }
' "$keenetic_init" > "$runtime_function"
awk '
    /^preserve_control_work_for_recovery\(\)/ { capture = 1 }
    capture { print }
    capture && /^}$/ { exit }
' "$keenetic_init" > "$preserve_function"
awk '
    /^    drain-pending-delayed\)/ { capture = 1; next }
    capture && /^        ;;/ { exit }
    capture {
        sub(/^        /, "")
        print
    }
' "$keenetic_init" > "$delayed_action"

(
    . "$marker_functions"
    STOPPING_RUNTIME_DIR="$work/init-stopping-runtime"
    STOPPING_MARKER="$STOPPING_RUNTIME_DIR/stopping"
    STOPPING_CONTROL_LEASE_DIR="$STOPPING_RUNTIME_DIR/control-lease"
    STOPPING_CONTROL_LEASE_OWNER="$STOPPING_CONTROL_LEASE_DIR/owner"
    STOPPING_CONTROL_RECOVERY_GATE_DIR="$STOPPING_RUNTIME_DIR/control-lease-recovery"
    STOPPING_CONTROL_RECOVERY_GATE_OWNER="$STOPPING_CONTROL_RECOVERY_GATE_DIR/owner"
    STOPPING_CONTROL_MAILBOX="$STOPPING_RUNTIME_DIR/control-pending"
    STOPPING_CONTROL_DRAIN_TOKEN="$STOPPING_RUNTIME_DIR/control-drain-token"
    STOPPING_PROC_ROOT=/proc
    STOPPING_MARKER_MAGIC=keen-pbr-stopping-v3
    STOPPING_CONTROL_LEASE_MAGIC=keen-pbr-control-lease-v1
    STOPPING_CONTROL_RECOVERY_GATE_MAGIC=keen-pbr-control-recovery-v1
    STOPPING_CONTROL_WORK_MAGIC=keen-pbr-control-work-v1
    STOPPING_ADMISSION_PID=""
    STOPPING_ADMISSION_STARTTICKS=""
    STOPPING_ADMISSION_PHASE=""
    STOPPING_ADMISSION_CONTROLLER_PID=""
    STOPPING_ADMISSION_CONTROLLER_STARTTICKS=""
    STOPPING_CONTROL_LEASE_PID=""
    STOPPING_CONTROL_LEASE_STARTTICKS=""
    STOPPING_CONTROL_LEASE_ROLE=""
    STOPPING_CONTROL_RECOVERY_GATE_PID=""
    STOPPING_CONTROL_RECOVERY_GATE_STARTTICKS=""
    STOPPING_CONTROL_ACQUIRE_RESULT=1
    STOPPING_TRAILING_SIGNAL=""
    STOPPING_TRAILING_DNS=no
    STOPPING_TRAILING_HUP=no
    STOPPING_RECOVERED_SIGNAL=""
    STOPPING_RECOVERED_DNS=no
    STOPPING_RECOVERED_HUP=no
    STOPPING_RECOVERY_CLOSING_DIRS=""
    STOPPING_CONTROL_WORK_PATH=""
    STOPPING_CONTROL_WORK_PID=""
    STOPPING_CONTROL_WORK_STARTTICKS=""
    STOPPING_CONTROL_WORK_SIGNAL=""
    STOPPING_CONTROL_WORK_DNS=no
    STOPPING_CONTROL_WORK_HUP=no
    PIDFILE="$work/init-keenetic.pid"
    PROCS=keen-pbr-test
    VALIDATED_SERVICE_PID=""
    log() { :; }
    log_error() { :; }
    pidof() { return 1; }
    validate_service_pid() { VALIDATED_SERVICE_PID=$hook_pid; }

    printf '%s\n' "$hook_pid" > "$PIDFILE"
    acquire_control_lease stop
    control_lease_owned_by_self
    begin_stopping_marker
    read_stopping_marker
    [ "$STOPPING_MARKER_PID" = "$hook_pid" ]
    [ "$STOPPING_MARKER_STARTTICKS" = "$hook_startticks" ]
    [ "$STOPPING_MARKER_PHASE" = admitted ]
    stopping_marker_is_live_admission
    if stopping_marker_authorizes_runtime_suppression; then
        echo "pre-mutation admission suppressed runtime work" >&2
        exit 1
    fi
    mark_stopping_mutation_started
    read_stopping_marker
    [ "$STOPPING_MARKER_PHASE" = mutating ]
    stopping_marker_authorizes_runtime_suppression
    finish_stopping_marker
    [ ! -e "$STOPPING_MARKER" ]
    release_control_lease
    [ ! -e "$STOPPING_CONTROL_LEASE_DIR" ]

    rm -f "$PIDFILE"
    ensure_stopping_runtime_dir
    printf '%s\n' 'keen-pbr-stopping-v3 mutating 99999999 1 99999998 1' > "$STOPPING_MARKER"
    chmod 0600 "$STOPPING_MARKER"
    if clear_stale_stopping_marker_for_start; then
        echo "startup cleared a dead post-mutation marker" >&2
        exit 1
    fi
    [ -f "$STOPPING_MARKER" ]
    acquire_control_lease stop
    begin_stopping_marker
    [ "$STOPPING_ADMISSION_PID" = 99999999 ]
    [ "$STOPPING_ADMISSION_STARTTICKS" = 1 ]
    [ "$STOPPING_ADMISSION_PHASE" = mutating ]
    read_stopping_marker
    [ "$STOPPING_MARKER_CONTROLLER_PID" = "$$" ]
    [ "$STOPPING_MARKER_CONTROLLER_STARTTICKS" = "$hook_startticks" ]
    if clear_stale_stopping_marker_for_start; then
        echo "startup cleared a dead marker while live stop cleanup owned the lease" >&2
        exit 1
    fi
    [ -f "$STOPPING_MARKER" ]
    finish_stopping_marker
    release_control_lease
    [ ! -e "$STOPPING_MARKER" ]
    printf '%s\n' "$hook_pid" > "$PIDFILE"

    ensure_stopping_runtime_dir
    printf 'keen-pbr-stopping-v3 admitted %s %s1 %s %s\n' \
        "$hook_pid" "$hook_startticks" "$hook_pid" "$hook_startticks" \
        > "$STOPPING_MARKER"
    chmod 0600 "$STOPPING_MARKER"
    clear_stale_stopping_marker_for_start
    [ ! -e "$STOPPING_MARKER" ]

    printf 'keen-pbr-stopping-v3 admitted %s %s %s %s\n' \
        "$hook_pid" "$hook_startticks" "$hook_pid" "$hook_startticks" \
        > "$STOPPING_MARKER"
    chmod 0600 "$STOPPING_MARKER"
    if clear_stale_stopping_marker_for_start; then
        echo "startup cleared a marker owned by a live daemon generation" >&2
        exit 1
    fi
    [ -f "$STOPPING_MARKER" ]
    rm -f "$STOPPING_MARKER"
    acquire_control_lease stop
    begin_stopping_marker
    [ "$STOPPING_ADMISSION_PID" = "$hook_pid" ]
    [ "$STOPPING_ADMISSION_STARTTICKS" = "$hook_startticks" ]
    finish_stopping_marker
    release_control_lease
    [ ! -e "$STOPPING_RUNTIME_DIR/.stopping.$$" ]

    printf 'keen-pbr-stopping-v3 admitted %s %s1 %s %s\n' \
        "$hook_pid" "$hook_startticks" "$hook_pid" "$hook_startticks" \
        > "$STOPPING_MARKER"
    chmod 0600 "$STOPPING_MARKER"
    acquire_control_lease stop
    begin_stopping_marker
    read_stopping_marker
    [ "$STOPPING_MARKER_PID" = "$hook_pid" ]
    [ "$STOPPING_MARKER_STARTTICKS" = "$hook_startticks" ]
    [ ! -e "$STOPPING_RUNTIME_DIR/.stopping.$$" ]
    [ ! -e "$STOPPING_RUNTIME_DIR/.stopping-mutating.$$" ]
    finish_stopping_marker
    release_control_lease

    printf '%s\n' malformed > "$STOPPING_MARKER"
    chmod 0600 "$STOPPING_MARKER"
    clear_stale_stopping_marker_for_start
    [ -f "$STOPPING_MARKER" ]
    rm -f "$STOPPING_MARKER"

    # Runtime recovery never adopts a dead/ambiguous sibling gate: only the
    # serialized startup boundary may clear it. This prevents a delayed
    # recoverer from moving a replacement fixed lease (ABA).
    mkdir "$STOPPING_CONTROL_RECOVERY_GATE_DIR"
    chmod 0700 "$STOPPING_CONTROL_RECOVERY_GATE_DIR"
    printf '%s\n' 'keen-pbr-control-recovery-v1 99999999 1' \
        > "$STOPPING_CONTROL_RECOVERY_GATE_OWNER"
    chmod 0600 "$STOPPING_CONTROL_RECOVERY_GATE_OWNER"
    if acquire_control_lease reapply-nat; then
        echo "runtime controller adopted a stale recovery gate" >&2
        exit 1
    fi
    [ ! -e "$STOPPING_CONTROL_LEASE_DIR" ]
    if clear_stale_control_recovery_gate_for_start; then
        echo "startup mutated a stale recovery gate without filesystem CAS" >&2
        exit 1
    fi
    [ -f "$STOPPING_CONTROL_RECOVERY_GATE_OWNER" ]
    # /var/run is tmpfs in production; removing this fixture models reboot,
    # the only safe recovery boundary for this millisecond-window crash.
    rm -f "$STOPPING_CONTROL_RECOVERY_GATE_OWNER"
    rmdir "$STOPPING_CONTROL_RECOVERY_GATE_DIR"

    mkdir "$STOPPING_CONTROL_RECOVERY_GATE_DIR"
    chmod 0700 "$STOPPING_CONTROL_RECOVERY_GATE_DIR"
    printf 'keen-pbr-control-recovery-v1 %s %s\n' \
        "$hook_pid" "$hook_startticks" \
        > "$STOPPING_CONTROL_RECOVERY_GATE_OWNER"
    chmod 0600 "$STOPPING_CONTROL_RECOVERY_GATE_OWNER"
    clear_stale_control_recovery_gate_for_start
    if acquire_control_lease reapply-nat; then
        echo "controller created a fixed lease before acquiring the live recovery gate" >&2
        exit 1
    fi
    [ ! -e "$STOPPING_CONTROL_LEASE_DIR" ]
    rm -f "$STOPPING_CONTROL_RECOVERY_GATE_OWNER"
    rmdir "$STOPPING_CONTROL_RECOVERY_GATE_DIR"

    # A live owner serializes controllers; a dead owner directory is renamed
    # out of the acquisition path and replaced by this caller's generation.
    mkdir "$STOPPING_CONTROL_LEASE_DIR"
    chmod 0700 "$STOPPING_CONTROL_LEASE_DIR"
    printf 'keen-pbr-control-lease-v1 stop %s %s\n' \
        "$hook_pid" "$hook_startticks" > "$STOPPING_CONTROL_LEASE_OWNER"
    chmod 0600 "$STOPPING_CONTROL_LEASE_OWNER"
    if acquire_control_lease reapply-nat; then
        echo "concurrent controller acquired a live lease" >&2
        exit 1
    else
        [ "$?" -eq 2 ]
    fi
    rm -f "$STOPPING_CONTROL_LEASE_OWNER"
    rmdir "$STOPPING_CONTROL_LEASE_DIR"

    # A stop requester that merely waits behind a live non-stop owner has not
    # admitted teardown yet. Recovered work is published into the actual
    # owner and survives even if the later stop wait times out or is killed.
    waiting_closing="$STOPPING_RUNTIME_DIR/.control-lease-closing.79000001"
    mkdir "$waiting_closing"
    chmod 0700 "$waiting_closing"
    printf '%s\n' 'keen-pbr-control-lease-v1 reapply-nat 99999999 1' \
        > "$waiting_closing/owner"
    chmod 0600 "$waiting_closing/owner"
    mkdir "$waiting_closing/pending-full"
    chmod 0700 "$waiting_closing/pending-full"
    mkdir "$STOPPING_CONTROL_LEASE_DIR"
    chmod 0700 "$STOPPING_CONTROL_LEASE_DIR"
    printf 'keen-pbr-control-lease-v1 reapply-nat %s %s\n' \
        "$hook_pid" "$hook_startticks" > "$STOPPING_CONTROL_LEASE_OWNER"
    chmod 0600 "$STOPPING_CONTROL_LEASE_OWNER"
    if acquire_control_lease stop; then
        echo "waiting stop unexpectedly acquired a live reapply lease" >&2
        exit 1
    else
        [ "$?" -eq 2 ]
    fi
    [ "$STOPPING_CONTROL_OWNER_ROLE" = reapply-nat ]
    read_control_work_file "$STOPPING_CONTROL_MAILBOX"
    [ "$CONTROL_WORK_SIGNAL" = SIGUSR1 ]
    [ ! -e "$waiting_closing" ]
    rm -f "$STOPPING_CONTROL_MAILBOX"
    rm -f "$STOPPING_CONTROL_LEASE_OWNER"
    rmdir "$STOPPING_CONTROL_LEASE_DIR"

    mkdir "$STOPPING_CONTROL_LEASE_DIR"
    chmod 0700 "$STOPPING_CONTROL_LEASE_DIR"
    printf '%s\n' 'keen-pbr-control-lease-v1 reapply-nat 99999999 1' \
        > "$STOPPING_CONTROL_LEASE_OWNER"
    chmod 0600 "$STOPPING_CONTROL_LEASE_OWNER"
    mkdir "$STOPPING_CONTROL_LEASE_DIR/pending-full"
    chmod 0700 "$STOPPING_CONTROL_LEASE_DIR/pending-full"
    if recover_stale_control_lease "$hook_startticks"; then
        echo "stale fixed lease was moved without the recovery gate" >&2
        exit 1
    fi
    [ -f "$STOPPING_CONTROL_LEASE_OWNER" ]
    acquire_control_lease reapply-nat
    control_lease_owned_by_self
    [ ! -e "$STOPPING_RUNTIME_DIR/.control-lease-closing.$$" ]
    release_control_lease
    [ "$STOPPING_TRAILING_SIGNAL" = SIGUSR1 ]
    [ ! -e "$STOPPING_CONTROL_RECOVERY_GATE_DIR" ]
    rm -f "$STOPPING_CONTROL_MAILBOX"

    # A malformed later entry cannot consume the valid earlier full intent.
    # The fixed generation is atomically quarantined in the same durable
    # closing namespace used after a recoverer crash, and remains intact.
    mkdir "$STOPPING_CONTROL_LEASE_DIR"
    chmod 0700 "$STOPPING_CONTROL_LEASE_DIR"
    printf '%s\n' 'keen-pbr-control-lease-v1 reapply-nat 99999999 1' \
        > "$STOPPING_CONTROL_LEASE_OWNER"
    chmod 0600 "$STOPPING_CONTROL_LEASE_OWNER"
    mkdir "$STOPPING_CONTROL_LEASE_DIR/pending-full"
    chmod 0700 "$STOPPING_CONTROL_LEASE_DIR/pending-full"
    mkdir "$STOPPING_CONTROL_LEASE_DIR/unexpected"
    chmod 0700 "$STOPPING_CONTROL_LEASE_DIR/unexpected"
    if acquire_control_lease start; then
        echo "malformed stale fixed lease unexpectedly admitted startup" >&2
        exit 1
    fi
    stale_closing="$STOPPING_RUNTIME_DIR/.control-lease-closing.$$"
    [ ! -e "$STOPPING_CONTROL_LEASE_DIR" ]
    [ -d "$stale_closing/pending-full" ]
    [ -d "$stale_closing/unexpected" ]
    [ -f "$stale_closing/owner" ]
    [ ! -e "$STOPPING_CONTROL_RECOVERY_GATE_DIR" ]
    rmdir "$stale_closing/unexpected"
    rmdir "$stale_closing/pending-full"
    rm -f "$stale_closing/owner"
    rmdir "$stale_closing"

    mkdir "$STOPPING_CONTROL_LEASE_DIR"
    chmod 0700 "$STOPPING_CONTROL_LEASE_DIR"
    acquire_control_lease reapply-nat
    control_lease_owned_by_self
    release_control_lease
    [ ! -e "$STOPPING_RUNTIME_DIR/.control-lease-owner.$$" ]

    # Full refresh dominates NAT in the atomic durable mailbox.
    acquire_control_lease reapply-nat
    queue_control_lease_intent SIGUSR2
    queue_control_lease_intent SIGUSR1
    release_control_lease
    [ "$STOPPING_TRAILING_SIGNAL" = SIGUSR1 ]
    read_control_work_file "$STOPPING_CONTROL_MAILBOX"
    [ "$CONTROL_WORK_SIGNAL" = SIGUSR1 ]
    rm -f "$STOPPING_CONTROL_MAILBOX"

    acquire_control_lease reapply-full
    queue_control_lease_intent SIGUSR2
    queue_control_lease_intent DNS
    release_control_lease
    [ "$STOPPING_TRAILING_SIGNAL" = SIGUSR2 ]
    [ "$STOPPING_TRAILING_DNS" = yes ]
    [ "$STOPPING_TRAILING_HUP" = no ]
    rm -f "$STOPPING_CONTROL_MAILBOX"

    acquire_control_lease start
    queue_control_lease_work SIGUSR1 yes yes
    release_control_lease
    [ "$STOPPING_TRAILING_SIGNAL" = SIGUSR1 ]
    [ "$STOPPING_TRAILING_DNS" = yes ]
    [ "$STOPPING_TRAILING_HUP" = yes ]
    rm -f "$STOPPING_CONTROL_MAILBOX"

    # A role=stop lease is not suppression authority before exact marker
    # admission. If admission later fails, all pre-marker work is still live.
    acquire_control_lease stop
    queue_control_lease_intent SIGUSR1
    queue_control_lease_intent SIGUSR2
    queue_control_lease_intent HUP
    release_control_lease
    [ "$STOPPING_TRAILING_SIGNAL" = SIGUSR1 ]
    [ "$STOPPING_TRAILING_DNS" = yes ]
    [ "$STOPPING_TRAILING_HUP" = yes ]
    rm -f "$STOPPING_CONTROL_MAILBOX"

    # Live pre-mutation admission queues rather than suppressing. The atomic
    # mutating phase suppresses only new churn and keeps the earlier mailbox
    # intact until verified teardown success.
    printf 'keen-pbr-stopping-v3 admitted %s %s %s %s\n' \
        "$hook_pid" "$hook_startticks" "$hook_pid" "$hook_startticks" \
        > "$STOPPING_MARKER"
    chmod 0600 "$STOPPING_MARKER"
    queue_control_lease_intent SIGUSR1
    read_control_work_file "$STOPPING_CONTROL_MAILBOX"
    [ "$CONTROL_WORK_SIGNAL" = SIGUSR1 ]
    [ "$CONTROL_WORK_DNS" = no ]
    printf 'keen-pbr-stopping-v3 mutating %s %s %s %s\n' \
        "$hook_pid" "$hook_startticks" "$hook_pid" "$hook_startticks" \
        > "$STOPPING_MARKER"
    chmod 0600 "$STOPPING_MARKER"
    queue_control_lease_intent HUP
    read_control_work_file "$STOPPING_CONTROL_MAILBOX"
    [ "$CONTROL_WORK_SIGNAL" = SIGUSR1 ]
    [ "$CONTROL_WORK_DNS" = no ]
    rm -f "$STOPPING_MARKER" "$STOPPING_CONTROL_MAILBOX"

    # A failed start never consumes its mailbox. A later verified start sees
    # the same atomic full+HUP bundle; no process-only closing handoff exists.
    acquire_control_lease start
    queue_control_lease_intent SIGUSR2
    queue_control_lease_intent SIGUSR1
    queue_control_lease_intent HUP
    release_control_lease yes
    [ "$STOPPING_TRAILING_SIGNAL" = SIGUSR1 ]
    [ "$STOPPING_TRAILING_DNS" = yes ]
    [ "$STOPPING_TRAILING_HUP" = yes ]
    [ ! -e "$STOPPING_CONTROL_LEASE_DIR" ]
    [ -f "$STOPPING_CONTROL_MAILBOX" ]
    acquire_control_lease start
    control_lease_owned_by_self
    release_control_lease
    [ "$STOPPING_TRAILING_SIGNAL" = SIGUSR1 ]
    [ "$STOPPING_TRAILING_DNS" = yes ]
    [ "$STOPPING_TRAILING_HUP" = yes ]
    [ ! -e "$STOPPING_CONTROL_LEASE_DIR" ]
    [ ! -e "$STOPPING_RUNTIME_DIR/.control-lease-closing.$$" ]
    rm -f "$STOPPING_CONTROL_MAILBOX"

    mkdir "$STOPPING_RUNTIME_DIR/.control-lease-closing.80000001"
    chmod 0700 "$STOPPING_RUNTIME_DIR/.control-lease-closing.80000001"
    acquire_control_lease start
    [ ! -e "$STOPPING_RUNTIME_DIR/.control-lease-closing.80000001" ]
    release_control_lease

    closing_index=1
    while [ "$closing_index" -le 32 ]; do
        closing_dir="$STOPPING_RUNTIME_DIR/.control-lease-closing.810000$closing_index"
        mkdir "$closing_dir"
        chmod 0700 \
            "$closing_dir"
        closing_index=$((closing_index + 1))
    done
    acquire_control_lease start
    release_control_lease
    [ ! -e "$STOPPING_CONTROL_RECOVERY_GATE_DIR" ]

    closing_index=1
    while [ "$closing_index" -le 33 ]; do
        closing_dir="$STOPPING_RUNTIME_DIR/.control-lease-closing.820000$closing_index"
        mkdir "$closing_dir"
        chmod 0700 \
            "$closing_dir"
        closing_index=$((closing_index + 1))
    done
    if acquire_control_lease start; then
        echo "unbounded orphan closing set unexpectedly admitted a controller" >&2
        exit 1
    fi
    [ ! -e "$STOPPING_CONTROL_LEASE_DIR" ]
    [ ! -e "$STOPPING_CONTROL_RECOVERY_GATE_DIR" ]
    [ -d "$STOPPING_RUNTIME_DIR/.control-lease-closing.8200001" ]
    for closing_dir in \
        "$STOPPING_RUNTIME_DIR"/.control-lease-closing.820000*; do
        [ ! -e "$closing_dir" ] || rmdir "$closing_dir"
    done

    # Preflight must reject a later malformed closing before mutating a valid
    # earlier generation or consuming its pending full-refresh authority.
    valid_closing="$STOPPING_RUNTIME_DIR/.control-lease-closing.83000001"
    malformed_closing="$STOPPING_RUNTIME_DIR/.control-lease-closing.83000002"
    mkdir "$valid_closing"
    chmod 0700 "$valid_closing"
    printf '%s\n' 'keen-pbr-control-lease-v1 reapply-nat 99999999 1' \
        > "$valid_closing/owner"
    chmod 0600 "$valid_closing/owner"
    mkdir "$valid_closing/pending-full"
    chmod 0700 "$valid_closing/pending-full"
    mkdir "$malformed_closing"
    chmod 0700 "$malformed_closing"
    printf '%s\n' malformed > "$malformed_closing/owner"
    chmod 0600 "$malformed_closing/owner"
    if acquire_control_lease start; then
        echo "malformed later closing unexpectedly admitted a controller" >&2
        exit 1
    fi
    [ -d "$valid_closing/pending-full" ]
    [ -f "$valid_closing/owner" ]
    [ ! -e "$STOPPING_CONTROL_LEASE_DIR" ]
    [ ! -e "$STOPPING_CONTROL_RECOVERY_GATE_DIR" ]
    rm -f "$malformed_closing/owner"
    rmdir "$malformed_closing"
    rmdir "$valid_closing/pending-full"
    rm -f "$valid_closing/owner"
    rmdir "$valid_closing"

    # Model a live releaser completing its ownerless-empty closing after the
    # recovery preflight has admitted that exact path but before phase two.
    # The vanished B path is benign; earlier A/full must still be published.
    valid_closing="$STOPPING_RUNTIME_DIR/.control-lease-closing.84000001"
    vanishing_closing="$STOPPING_RUNTIME_DIR/.control-lease-closing.84000002"
    vanish_flag="$work/ownerless-closing-vanished"
    mkdir "$valid_closing"
    chmod 0700 "$valid_closing"
    printf '%s\n' 'keen-pbr-control-lease-v1 reapply-nat 99999999 1' \
        > "$valid_closing/owner"
    chmod 0600 "$valid_closing/owner"
    mkdir "$valid_closing/pending-full"
    chmod 0700 "$valid_closing/pending-full"
    mkdir "$vanishing_closing"
    chmod 0700 "$vanishing_closing"
    stat() {
        stat_target=""
        for stat_arg in "$@"; do
            stat_target="$stat_arg"
        done
        command stat "$@"
        stat_status=$?
        if [ "$stat_target" = "$vanishing_closing" ] &&
           [ ! -e "$vanish_flag" ]; then
            rmdir "$vanishing_closing"
            : > "$vanish_flag"
        fi
        if [ -n "${publish_source_full:-}" ] &&
           [ "$stat_target" = "$publish_source_full" ] &&
           [ ! -e "${publish_fault_flag:-}" ]; then
            mkdir "$publish_source_full/late-cleanup-blocker"
            : > "$publish_fault_flag"
        fi
        return "$stat_status"
    }
    acquire_control_lease start
    [ -f "$vanish_flag" ]
    [ ! -e "$valid_closing" ]
    [ ! -e "$vanishing_closing" ]
    release_control_lease
    [ "$STOPPING_TRAILING_SIGNAL" = SIGUSR1 ]
    [ ! -e "$STOPPING_CONTROL_RECOVERY_GATE_DIR" ]
    rm -f "$STOPPING_CONTROL_MAILBOX"

    # Fault source cleanup only after its full bit passed preflight. Acquire
    # must fail, but publish-before-delete leaves the exact target pending bit
    # durable while the complete source closing also remains replayable.
    crash_closing="$STOPPING_RUNTIME_DIR/.control-lease-closing.85000001"
    publish_source_full="$crash_closing/pending-full"
    publish_fault_flag="$work/publish-before-delete-fault"
    mkdir "$crash_closing"
    chmod 0700 "$crash_closing"
    printf '%s\n' 'keen-pbr-control-lease-v1 reapply-nat 99999999 1' \
        > "$crash_closing/owner"
    chmod 0600 "$crash_closing/owner"
    mkdir "$publish_source_full"
    chmod 0700 "$publish_source_full"
    if acquire_control_lease start; then
        echo "source cleanup fault unexpectedly completed acquisition" >&2
        exit 1
    fi
    [ -f "$publish_fault_flag" ]
    read_control_work_file "$STOPPING_CONTROL_MAILBOX"
    [ "$CONTROL_WORK_SIGNAL" = SIGUSR1 ]
    [ -d "$publish_source_full/late-cleanup-blocker" ]
    [ -f "$crash_closing/owner" ]
    [ ! -e "$STOPPING_CONTROL_RECOVERY_GATE_DIR" ]
    [ ! -e "$STOPPING_CONTROL_LEASE_DIR" ]
    rm -f "$STOPPING_CONTROL_MAILBOX"
    rmdir "$publish_source_full/late-cleanup-blocker"
    rmdir "$publish_source_full"
    rm -f "$crash_closing/owner"
    rmdir "$crash_closing"
)


# The failed-start handoff is one atomic mailbox update, with no bounded owner
# retry loop and no process-only trailing state.
(
    . "$marker_functions"
    . "$preserve_function"
    STOPPING_RUNTIME_DIR="$work/preserve-runtime"
    STOPPING_MARKER="$STOPPING_RUNTIME_DIR/stopping"
    STOPPING_CONTROL_RECOVERY_GATE_DIR="$STOPPING_RUNTIME_DIR/control-lease-recovery"
    STOPPING_CONTROL_RECOVERY_GATE_OWNER="$STOPPING_CONTROL_RECOVERY_GATE_DIR/owner"
    STOPPING_CONTROL_MAILBOX="$STOPPING_RUNTIME_DIR/control-pending"
    STOPPING_PROC_ROOT=/proc
    STOPPING_MARKER_MAGIC=keen-pbr-stopping-v3
    STOPPING_CONTROL_RECOVERY_GATE_MAGIC=keen-pbr-control-recovery-v1
    STOPPING_CONTROL_WORK_MAGIC=keen-pbr-control-work-v1
    log() { :; }
    log_error() { :; }
    ensure_stopping_runtime_dir

    preserve_control_work_for_recovery SIGUSR1 yes yes
    read_control_work_file "$STOPPING_CONTROL_MAILBOX"
    [ "$CONTROL_WORK_SIGNAL" = SIGUSR1 ]
    [ "$CONTROL_WORK_DNS" = yes ]
    [ "$CONTROL_WORK_HUP" = yes ]
    preserve_control_work_for_recovery SIGUSR2 no no
    read_control_work_file "$STOPPING_CONTROL_MAILBOX"
    [ "$CONTROL_WORK_SIGNAL" = SIGUSR1 ]
    [ "$CONTROL_WORK_DNS" = yes ]
    [ "$CONTROL_WORK_HUP" = yes ]
)

(
    . "$marker_functions"
    . "$runtime_function"
    STOPPING_RUNTIME_DIR="$work/runtime-drain"
    STOPPING_MARKER="$STOPPING_RUNTIME_DIR/stopping"
    STOPPING_CONTROL_LEASE_DIR="$STOPPING_RUNTIME_DIR/control-lease"
    STOPPING_CONTROL_LEASE_OWNER="$STOPPING_CONTROL_LEASE_DIR/owner"
    STOPPING_CONTROL_RECOVERY_GATE_DIR="$STOPPING_RUNTIME_DIR/control-lease-recovery"
    STOPPING_CONTROL_RECOVERY_GATE_OWNER="$STOPPING_CONTROL_RECOVERY_GATE_DIR/owner"
    STOPPING_CONTROL_MAILBOX="$STOPPING_RUNTIME_DIR/control-pending"
    STOPPING_CONTROL_DRAIN_TOKEN="$STOPPING_RUNTIME_DIR/control-drain-token"
    STOPPING_PROC_ROOT=/proc
    STOPPING_MARKER_MAGIC=keen-pbr-stopping-v3
    STOPPING_CONTROL_LEASE_MAGIC=keen-pbr-control-lease-v1
    STOPPING_CONTROL_RECOVERY_GATE_MAGIC=keen-pbr-control-recovery-v1
    STOPPING_CONTROL_WORK_MAGIC=keen-pbr-control-work-v1
    STOPPING_CONTROL_LEASE_PID=""
    STOPPING_CONTROL_LEASE_STARTTICKS=""
    STOPPING_CONTROL_LEASE_ROLE=""
    STOPPING_CONTROL_WORK_PATH=""
    STOPPING_CONTROL_WORK_PID=""
    STOPPING_CONTROL_WORK_STARTTICKS=""
    STOPPING_CONTROL_WORK_SIGNAL=""
    STOPPING_CONTROL_WORK_DNS=no
    STOPPING_CONTROL_WORK_HUP=no
    STOPPING_CONTROL_LEASE_FAIL_OPEN=no
    PIDFILE="$work/runtime-drain.pid"
    printf '%s\n' 731 > "$PIDFILE"
    lifecycle="$work/runtime-lifecycle"
    : > "$lifecycle"
    validate_service_pid() { echo validate >> "$lifecycle"; return 0; }
    ensure_fastnat_disabled() { echo fastnat >> "$lifecycle"; return 0; }
    signal_service() { echo "signal-$1" >> "$lifecycle"; return 0; }
    reapply_dnsmasq_config() { echo dns >> "$lifecycle"; return 0; }
    pid_is_keen_pbr() { return 0; }
    delayed_calls=0
    schedule_delayed_control_mailbox_drain() {
        delayed_calls=$((delayed_calls + 1))
        CONTROL_MAILBOX_WATCHDOG_ARMED=yes
        return 0
    }
    log() { :; }
    log_error() { :; }
    ensure_stopping_runtime_dir

    reapply_netfilter_runtime SIGUSR1
    expected='validate
fastnat
signal-SIGUSR1'
    [ "$(cat "$lifecycle")" = "$expected" ]
    [ ! -e "$STOPPING_CONTROL_MAILBOX" ]
    [ ! -e "$STOPPING_CONTROL_LEASE_DIR" ]

    : > "$lifecycle"
    reapply_dns_runtime yes
    expected='validate
dns
signal-HUP'
    [ "$(cat "$lifecycle")" = "$expected" ]

    # A DNS/HUP bundle queued before stop promotion remains untouched when a
    # failed stop leaves an exact mutating marker and the daemon generation is
    # still live. The watchdog neither activates dnsmasq nor extends its chain.
    publish_control_mailbox_work "" yes yes
    runtime_pid=$$
    runtime_startticks=$(stopping_process_startticks "$runtime_pid")
    printf '%s\n' "$runtime_pid" > "$PIDFILE"
    printf 'keen-pbr-stopping-v3 mutating %s %s %s %s\n' \
        "$runtime_pid" "$runtime_startticks" \
        "$runtime_pid" "$runtime_startticks" > "$STOPPING_MARKER"
    chmod 0600 "$STOPPING_MARKER"
    : > "$lifecycle"
    delayed_calls=0
    drain_control_runtime "" no no
    [ ! -s "$lifecycle" ]
    [ "$delayed_calls" -eq 0 ]
    read_control_work_file "$STOPPING_CONTROL_MAILBOX"
    [ "$CONTROL_WORK_DNS" = yes ]
    [ "$CONTROL_WORK_HUP" = yes ]
    rm -f "$STOPPING_MARKER" "$STOPPING_CONTROL_MAILBOX"
    printf '%s\n' 731 > "$PIDFILE"

    # An orphan-only work file enters the bounded loop even without a fixed
    # mailbox, is atomically recovered, and is acknowledged in this pass.
    : > "$lifecycle"
    orphan_work="$STOPPING_RUNTIME_DIR/.control-work.99999999"
    write_control_work_candidate "$orphan_work" work 99999999 1 \
        SIGUSR2 no no
    drain_control_runtime "" no no
    expected='validate
fastnat
signal-SIGUSR2'
    [ "$(cat "$lifecycle")" = "$expected" ]
    [ ! -e "$orphan_work" ]

    # A failed claim may have completed mailbox->work rename but not the atomic
    # pending->work owner replacement. That validated pending-role residue is
    # both recoverable and watchdog-worthy before the delayed sole owner claims
    # it, so a later SIGKILL cannot strand the recovered generation.
    pending_residue="$STOPPING_RUNTIME_DIR/.control-work.99999997"
    write_control_work_candidate "$pending_residue" pending 0 1 \
        SIGUSR1 no no
    : > "$lifecycle"
    delayed_calls=0
    drain_control_runtime "" no no
    expected='validate
fastnat
signal-SIGUSR1'
    [ "$(cat "$lifecycle")" = "$expected" ]
    [ "$delayed_calls" -eq 1 ]
    [ ! -e "$pending_residue" ]

    # Failed work is retried for exactly the bounded passes, remains durable,
    # and hands liveness to one delayed drain.
    signal_calls=0
    delayed_calls=0
    signal_service() {
        signal_calls=$((signal_calls + 1))
        return 1
    }
    if reapply_netfilter_runtime SIGUSR1; then
        echo "failed netfilter work unexpectedly succeeded" >&2
        exit 1
    fi
    [ "$signal_calls" -eq 8 ]
    [ "$delayed_calls" -eq 1 ]
    read_control_work_file "$STOPPING_CONTROL_MAILBOX"
    [ "$CONTROL_WORK_SIGNAL" = SIGUSR1 ]
    rm -f "$STOPPING_CONTROL_MAILBOX"

    # Foreground delivery keeps its bounded fast attempts, but a delayed owner
    # performs only one attempt and advances the exact successor to 2 seconds.
    # The delay then caps at the 60-second maintenance cadence.
    signal_calls=0
    successor_delay=0
    control_drain_token_owned_by_self() { return 0; }
    arm_control_mailbox_watchdog() {
        successor_delay=$3
        CONTROL_MAILBOX_WATCHDOG_ARMED=yes
        return 0
    }
    KEEN_PBR_DELAYED_DRAIN=yes
    KEEN_PBR_WATCHDOG_DELAY_SECONDS=1
    if drain_control_runtime SIGUSR1 no no; then
        echo "persistent delayed failure unexpectedly succeeded" >&2
        exit 1
    fi
    [ "$signal_calls" -eq 1 ]
    [ "$successor_delay" -eq 2 ]
    read_control_work_file "$STOPPING_CONTROL_MAILBOX"
    [ "$CONTROL_WORK_SIGNAL" = SIGUSR1 ]
    rm -f "$STOPPING_CONTROL_MAILBOX"
    KEEN_PBR_WATCHDOG_DELAY_SECONDS=32
    arm_control_mailbox_watchdog_successor 731 42
    [ "$successor_delay" -eq 60 ]
    KEEN_PBR_WATCHDOG_DELAY_SECONDS=60
    arm_control_mailbox_watchdog_successor 731 42
    [ "$successor_delay" -eq 60 ]
    KEEN_PBR_DELAYED_DRAIN=no
    KEEN_PBR_WATCHDOG_DELAY_SECONDS=1

    # Exact pass-eight arrival: the event remains pending and transfers to the
    # delayed owner without recursion or process-only state.
    pass_calls=0
    delayed_calls=0
    execute_claimed_control_mailbox_work() {
        pass_calls=$((pass_calls + 1))
        publish_control_mailbox_work SIGUSR1 no no
        return 0
    }
    drain_control_runtime SIGUSR2 no no
    [ "$pass_calls" -eq 8 ]
    [ "$delayed_calls" -eq 1 ]
    read_control_work_file "$STOPPING_CONTROL_MAILBOX"
    [ "$CONTROL_WORK_SIGNAL" = SIGUSR1 ]
    rm -f "$STOPPING_CONTROL_MAILBOX"

    # Model a controller killed immediately after the fixed mailbox was
    # claimed: no new hook publishes work, yet the pre-armed delayed watchdog
    # wakes with an empty initial request, recovers the dead generation, and
    # acknowledges it. The arm must precede the first risky execution.
    killed_work="$STOPPING_RUNTIME_DIR/.control-work.99999998"
    write_control_work_candidate "$killed_work" work 99999998 1 \
        SIGUSR2 no no
    : > "$lifecycle"
    delayed_calls=0
    schedule_delayed_control_mailbox_drain() {
        echo watchdog >> "$lifecycle"
        delayed_calls=$((delayed_calls + 1))
        CONTROL_MAILBOX_WATCHDOG_ARMED=yes
        return 0
    }
    execute_claimed_control_mailbox_work() {
        echo execute >> "$lifecycle"
        return 0
    }
    drain_control_runtime "" no no
    expected='watchdog
execute'
    [ "$(cat "$lifecycle")" = "$expected" ]
    [ "$delayed_calls" -eq 1 ]
    [ ! -e "$killed_work" ]

    # The status=2 observation is a gate-fenced baton, not a later pathname
    # read. Even if the predecessor has already released the fixed token, the
    # exact successor still recognizes the captured generation and continues.
    KEEN_PBR_WATCHDOG_PREDECESSOR_PID=731
    KEEN_PBR_WATCHDOG_PREDECESSOR_STARTTICKS=42
    STOPPING_CONTROL_DRAIN_OBSERVED_PID=731
    STOPPING_CONTROL_DRAIN_OBSERVED_STARTTICKS=42
    rm -f "$STOPPING_CONTROL_DRAIN_TOKEN"
    control_drain_token_matches_expected_predecessor
    KEEN_PBR_WATCHDOG_PREDECESSOR_PID=""
    KEEN_PBR_WATCHDOG_PREDECESSOR_STARTTICKS=""
    STOPPING_CONTROL_DRAIN_OBSERVED_PID=""
    STOPPING_CONTROL_DRAIN_OBSERVED_STARTTICKS=""

    schedule_delayed_control_mailbox_drain() {
        delayed_calls=$((delayed_calls + 1))
        CONTROL_MAILBOX_WATCHDOG_ARMED=yes
        return 0
    }

    # An acknowledgement failure stops the immediate loop after one pass and
    # leaves the exact work file for one delayed recovery owner.
    delayed_calls=0
    ack_execute_calls=0
    execute_claimed_control_mailbox_work() {
        ack_execute_calls=$((ack_execute_calls + 1))
        return 0
    }
    finish_control_mailbox_work() { return 1; }
    if drain_control_runtime SIGUSR1 no no; then
        echo "failed acknowledgement unexpectedly completed" >&2
        exit 1
    fi
    [ "$ack_execute_calls" -eq 1 ]
    [ "$delayed_calls" -eq 1 ]
    [ -f "$STOPPING_CONTROL_WORK_PATH" ]
    rm -f "$STOPPING_CONTROL_WORK_PATH"
    STOPPING_CONTROL_WORK_PATH=""

    # If the live owner dies after a publisher observes it, the quiet stream
    # still has a delayed owner; the mailbox is not dependent on another hook.
    delayed_calls=0
    acquire_control_lease() {
        STOPPING_CONTROL_OWNER_ROLE=reapply-nat
        return 2
    }
    drain_control_runtime SIGUSR2 no no
    [ "$delayed_calls" -eq 1 ]
    read_control_work_file "$STOPPING_CONTROL_MAILBOX"
    [ "$CONTROL_WORK_SIGNAL" = SIGUSR2 ]
    rm -f "$STOPPING_CONTROL_MAILBOX"

    # A failed/not-yet-started daemon keeps work for the next verified start;
    # it performs no doomed pass and creates no one-second delayed chain.
    rm -f "$PIDFILE"
    delayed_calls=0
    ack_execute_calls=0
    drain_control_runtime SIGUSR1 no no
    [ "$ack_execute_calls" -eq 0 ]
    [ "$delayed_calls" -eq 0 ]
    read_control_work_file "$STOPPING_CONTROL_MAILBOX"
    [ "$CONTROL_WORK_SIGNAL" = SIGUSR1 ]
    rm -f "$STOPPING_CONTROL_MAILBOX"

)

# A delayed owner that failed before arming releases its token and schedules
# exactly one fallback when any durable work remains.
delayed_lifecycle="$work/delayed-pass-eight-lifecycle"
: > "$delayed_lifecycle"
(
    claim_control_drain_token() { echo claim >> "$delayed_lifecycle"; }
    drain_control_runtime() { echo pass8-arrival >> "$delayed_lifecycle"; }
    release_control_drain_token() { echo release >> "$delayed_lifecycle"; }
    control_runtime_has_any_durable_work() { return 0; }
    control_runtime_daemon_is_verified() { return 0; }
    stopping_marker_authorizes_runtime_suppression() { return 1; }
    CONTROL_MAILBOX_WATCHDOG_ARMED=no
    arm_control_mailbox_watchdog_successor() {
        echo "successor-$1-$2" >> "$delayed_lifecycle"
    }
    . "$delayed_action"
)
expected='claim
pass8-arrival
release
successor--'
[ "$(cat "$delayed_lifecycle")" = "$expected" ]

# A live daemon plus durable work is still not retry authority once a stop has
# entered the exact mutating phase. The current token exits without a successor.
: > "$delayed_lifecycle"
(
    claim_control_drain_token() { echo claim >> "$delayed_lifecycle"; }
    drain_control_runtime() {
        echo retained-mutating-work >> "$delayed_lifecycle"
        CONTROL_MAILBOX_WATCHDOG_ARMED=no
    }
    release_control_drain_token() { echo release >> "$delayed_lifecycle"; }
    control_runtime_has_any_durable_work() { return 0; }
    control_runtime_daemon_is_verified() { return 0; }
    stopping_marker_authorizes_runtime_suppression() { return 0; }
    arm_control_mailbox_watchdog_successor() {
        echo unexpected-successor >> "$delayed_lifecycle"
    }
    CONTROL_MAILBOX_WATCHDOG_ARMED=no
    . "$delayed_action"
)
expected='claim
retained-mutating-work
release'
[ "$(cat "$delayed_lifecycle")" = "$expected" ]

# A drain that already armed its exact successor does not fan out another one
# after token release.
: > "$delayed_lifecycle"
(
    claim_control_drain_token() { echo claim >> "$delayed_lifecycle"; }
    drain_control_runtime() {
        echo armed-drain >> "$delayed_lifecycle"
        CONTROL_MAILBOX_WATCHDOG_ARMED=yes
    }
    release_control_drain_token() { echo release >> "$delayed_lifecycle"; }
    control_runtime_has_any_durable_work() { return 0; }
    control_runtime_daemon_is_verified() { return 0; }
    stopping_marker_authorizes_runtime_suppression() { return 1; }
    arm_control_mailbox_watchdog_successor() { echo duplicate >> "$delayed_lifecycle"; }
    CONTROL_MAILBOX_WATCHDOG_ARMED=no
    . "$delayed_action"
)
expected='claim
armed-drain
release'
[ "$(cat "$delayed_lifecycle")" = "$expected" ]

# If the pre-armed successor wakes while its exact predecessor still owns the
# token, only that successor extends the capped backoff watch. It neither drains nor
# releases another owner's generation.
: > "$delayed_lifecycle"
(
    KEEN_PBR_WATCHDOG_PREDECESSOR_PID=731
    KEEN_PBR_WATCHDOG_PREDECESSOR_STARTTICKS=42
    claim_control_drain_token() { echo busy >> "$delayed_lifecycle"; return 2; }
    control_drain_token_matches_expected_predecessor() { return 0; }
    control_runtime_daemon_is_verified() { return 0; }
    stopping_marker_authorizes_runtime_suppression() { return 1; }
    control_runtime_has_any_durable_work() { return 0; }
    arm_control_mailbox_watchdog_successor() {
        echo "arm-$1-$2" >> "$delayed_lifecycle"
    }
    . "$delayed_action"
)
expected='busy
arm-731-42'
[ "$(cat "$delayed_lifecycle")" = "$expected" ]

# A verified daemon disappearance terminates even an exact predecessor chain;
# durable work stays quiet for the next successful start.
: > "$delayed_lifecycle"
(
    KEEN_PBR_WATCHDOG_PREDECESSOR_PID=731
    KEEN_PBR_WATCHDOG_PREDECESSOR_STARTTICKS=42
    claim_control_drain_token() { echo busy >> "$delayed_lifecycle"; return 2; }
    control_drain_token_matches_expected_predecessor() { return 0; }
    control_runtime_daemon_is_verified() { return 1; }
    arm_control_mailbox_watchdog_successor() {
        echo unexpected-arm >> "$delayed_lifecycle"
    }
    . "$delayed_action"
)
[ "$(cat "$delayed_lifecycle")" = busy ]

# A live predecessor token alone is not work. If its generation already
# acknowledged the mailbox but hangs before token release, do not spawn an
# empty shell chain forever.
: > "$delayed_lifecycle"
(
    KEEN_PBR_WATCHDOG_PREDECESSOR_PID=731
    KEEN_PBR_WATCHDOG_PREDECESSOR_STARTTICKS=42
    claim_control_drain_token() { echo busy >> "$delayed_lifecycle"; return 2; }
    control_drain_token_matches_expected_predecessor() { return 0; }
    control_runtime_daemon_is_verified() { return 0; }
    stopping_marker_authorizes_runtime_suppression() { return 1; }
    control_runtime_has_any_durable_work() { return 1; }
    arm_control_mailbox_watchdog_successor() {
        echo unexpected-arm >> "$delayed_lifecycle"
    }
    . "$delayed_action"
)
[ "$(cat "$delayed_lifecycle")" = busy ]

(
    . "$stop_function"
    lifecycle="$work/stop-lifecycle-v3"
    : > "$lifecycle"
    lease_ok=yes
    mark_mode=success
    STOPPING_ADMISSION_PID=""
    STOPPING_ADMISSION_PHASE=""
    STOPPING_CONTROL_OWNER_ROLE=""
    acquire_control_lease() { echo acquire >> "$lifecycle"; return 0; }
    release_control_lease() { echo release >> "$lifecycle"; return 0; }
    control_lease_owned_by_self() {
        echo lease-check >> "$lifecycle"
        [ "$lease_ok" = yes ]
    }
    begin_stopping_marker() {
        echo begin >> "$lifecycle"
        STOPPING_ADMISSION_PID=731
        STOPPING_ADMISSION_PHASE=admitted
    }
    mark_stopping_mutation_started() {
        echo mark-mutating >> "$lifecycle"
        control_lease_owned_by_self || return 1
        case "$mark_mode" in
            success) STOPPING_ADMISSION_PHASE=mutating; return 0 ;;
            fail-admitted) return 1 ;;
            fail-mutating) STOPPING_ADMISSION_PHASE=mutating; return 1 ;;
        esac
    }
    prepare_stop() { echo prepare >> "$lifecycle"; }
    stop_keen_pbr() {
        echo stop >> "$lifecycle"
        STOP_KEEN_PBR_SAFE=yes
    }
    cleanup_stale_tcp_rst_firewall() { echo tcp-cleanup >> "$lifecycle"; }
    cleanup_stale_meta_udp443_firewall() { echo meta-cleanup >> "$lifecycle"; }
    restore_hwnat_if_safe() { echo fastnat-restore >> "$lifecycle"; }
    discard_control_mailbox_after_successful_stop() { echo discard >> "$lifecycle"; }
    finish_stopping_marker() {
        echo finish >> "$lifecycle"
        STOPPING_ADMISSION_PID=""
        STOPPING_ADMISSION_PHASE=""
    }
    drain_control_runtime() { echo drain >> "$lifecycle"; }
    log_error() { :; }

    stop_service_for_action stop yes
    expected='acquire
begin
lease-check
mark-mutating
lease-check
prepare
stop
tcp-cleanup
meta-cleanup
fastnat-restore
discard
release
finish'
    [ "$(cat "$lifecycle")" = "$expected" ]

    # Post-mutation failure retains both marker and mailbox.
    : > "$lifecycle"
    stop_keen_pbr() { echo stop >> "$lifecycle"; return 1; }
    if stop_service_for_action stop yes; then
        echo "failed teardown unexpectedly released stop admission" >&2
        exit 1
    fi
    expected='acquire
begin
lease-check
mark-mutating
lease-check
prepare
stop
release'
    [ "$(cat "$lifecycle")" = "$expected" ]

    # Pre-mutation promotion failure clears admission and drains intact work.
    : > "$lifecycle"
    mark_mode=fail-admitted
    stop_keen_pbr() { echo stop >> "$lifecycle"; }
    if stop_service_for_action stop yes; then
        echo "failed pre-mutation promotion unexpectedly succeeded" >&2
        exit 1
    fi
    expected='acquire
begin
lease-check
mark-mutating
lease-check
finish
release
drain'
    [ "$(cat "$lifecycle")" = "$expected" ]

    # Once atomic promotion may have occurred, failure is conservative.
    : > "$lifecycle"
    mark_mode=fail-mutating
    if stop_service_for_action stop yes; then
        echo "uncertain mutating promotion unexpectedly succeeded" >&2
        exit 1
    fi
    expected='acquire
begin
lease-check
mark-mutating
lease-check
release'
    [ "$(cat "$lifecycle")" = "$expected" ]

    : > "$lifecycle"
    mark_mode=success
    lease_ok=no
    if stop_service_for_action stop yes; then
        echo "stop proceeded after losing its pre-mutation lease" >&2
        exit 1
    fi
    expected='acquire
begin
lease-check
finish
release
drain'
    [ "$(cat "$lifecycle")" = "$expected" ]

    : > "$lifecycle"
    acquire_control_lease() {
        echo acquire >> "$lifecycle"
        STOPPING_CONTROL_OWNER_ROLE=stop
        return 2
    }
    if stop_service_for_action stop yes; then
        echo "concurrent stop unexpectedly shared the control lease" >&2
        exit 1
    fi
    [ "$(cat "$lifecycle")" = acquire ]
)

/bin/sh -n "$keenetic_hook"
/bin/sh -n "$keenetic_init"
/bin/sh -n "$rescue_guard"
/bin/sh -n "$openwrt_init"
/bin/sh -n "$openwrt_firewall"
/bin/sh -n "$openwrt_hotplug"

grep -q 'reapply-nat)' "$keenetic_init"
grep -q 'reapply_netfilter_runtime SIGUSR1' "$keenetic_init"
grep -q 'reapply_netfilter_runtime SIGUSR2' "$keenetic_init"
grep -q 'reapply_dns_runtime yes' "$keenetic_init"
grep -q 'reapply_dns_runtime no' "$keenetic_init"
grep -q 'pid_is_keen_pbr "$pid"' "$keenetic_init"
grep -q 'acquire_control_lease start' "$keenetic_init"
grep -q 'wait_for_verified_service_start' "$keenetic_init"
grep -q 'finish_start_control_lease yes' "$keenetic_init"
grep -q 'release_control_lease yes' "$keenetic_init"
grep -q 'reapply_nat()' "$openwrt_init"
grep -q 'signal_service SIGUSR2' "$openwrt_init"

openwrt_pidfile="$work/openwrt.pid"
openwrt_proc="$work/proc"
openwrt_signals="$work/openwrt-signals"
mkdir -p "$openwrt_proc"

(
    # rc.common is not present in the package-test container. The init script
    # only needs this no-op declaration while it is sourced for function tests.
    extra_command() { :; }
    . "$openwrt_init"
    PIDFILE="$openwrt_pidfile"
    PROC_ROOT="$openwrt_proc"
    PROG=/usr/sbin/keen-pbr
    kill() {
        printf '%s %s\n' "$1" "$2" >> "$openwrt_signals"
    }

    : > "$openwrt_signals"
    printf '%s\n' not-a-pid > "$PIDFILE"
    if reapply_nat; then
        echo "OpenWrt accepted a non-numeric PID" >&2
        exit 1
    fi

    printf '%s\n' 731 > "$PIDFILE"
    mkdir -p "$PROC_ROOT/731"
    printf '/usr/sbin/not-keen-pbr\000service\000' \
        > "$PROC_ROOT/731/cmdline"
    if reapply_firewall; then
        echo "OpenWrt accepted a reused PID owned by another process" >&2
        exit 1
    fi

    printf '/usr/sbin/keen-pbr\000--config\000/etc/keen-pbr/config.json\000check\000' \
        > "$PROC_ROOT/731/cmdline"
    if reapply_firewall; then
        echo "OpenWrt accepted a non-service keen-pbr process" >&2
        exit 1
    fi

    printf '/usr/sbin/keen-pbr\000--config\000/etc/keen-pbr/config.json\000service\000' \
        > "$PROC_ROOT/731/cmdline"
    reapply_firewall
    reapply_nat
    reload_service
)

expected_signals='-SIGUSR1 731
-SIGUSR2 731
-HUP 731'
actual_signals=$(cat "$openwrt_signals")
if [ "$actual_signals" != "$expected_signals" ]; then
    echo "unexpected OpenWrt signal mapping: '$actual_signals'" >&2
    exit 1
fi

openwrt_firewall_calls="$work/openwrt-firewall-calls"
fake_openwrt_init="$work/fake-openwrt-init"
installed_openwrt_firewall="$work/firewall.sh"
cp "$openwrt_firewall" "$installed_openwrt_firewall"
chmod +x "$installed_openwrt_firewall"

cat > "$fake_openwrt_init" <<'EOF'
#!/bin/sh
case "$1" in
    enabled) exit 0 ;;
    *) printf '%s\n' "$1" >> "$KEEN_PBR_TEST_CALLS" ;;
esac
EOF
chmod +x "$fake_openwrt_init"

: > "$openwrt_firewall_calls"
env \
    PATH="$work:$PATH" \
    ACTION=includes \
    KEEN_PBR_INIT_SCRIPT="$fake_openwrt_init" \
    KEEN_PBR_TEST_CALLS="$openwrt_firewall_calls" \
    /bin/sh "$openwrt_firewall"
if [ -s "$openwrt_firewall_calls" ]; then
    echo "fw4 pre-ruleset include unexpectedly signalled keen-pbr" >&2
    exit 1
fi

env \
    PATH="$work:$PATH" \
    ACTION=reload \
    KEEN_PBR_FIREWALL_SCRIPT="$installed_openwrt_firewall" \
    KEEN_PBR_INIT_SCRIPT="$fake_openwrt_init" \
    KEEN_PBR_TEST_CALLS="$openwrt_firewall_calls" \
    /bin/sh "$openwrt_hotplug"
if [ "$(cat "$openwrt_firewall_calls")" != "reapply_firewall" ]; then
    echo "OpenWrt post-reload hotplug did not signal a full refresh" >&2
    exit 1
fi

echo "netfilter hook signal checks passed"
