#!/bin/sh

set -eu

init_script=${1:-}
[ -f "$init_script" ] || {
    echo "usage: $0 <S80keen-pbr>" >&2
    exit 2
}

work=$(mktemp -d)
trap 'rm -rf "$work"' 0 HUP INT TERM

# Source only the portable command watchdog, xtables/nft cleanup helpers, and
# the stop wrapper. Keenetic's rc.func dispatcher is intentionally not run.
{
    sed -n '/^run_bounded_command()/,/^is_module_loaded()/p' \
        "$init_script" | sed '$d'
    sed -n '/^stop_service_for_action()/,/^restore_fastnat_after_failed_start()/p' \
        "$init_script" | sed '$d'
} > "$work/functions.sh"
cat >> "$work/functions.sh" <<'EOF'
# These cases exercise exact Meta firewall cleanup. The stop lease itself has
# a dedicated contract suite, so model one uniquely owned lifecycle action.
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
EOF

mkdir -p "$work/bin" "$work/state"
cat > "$work/bin/iptables" <<'EOF'
#!/bin/sh

tool=${0##*/}
state_file="$META_TEST_STATE/$tool"
state=$(cat "$state_file")
printf '%s %s\n' "$tool" "$*" >> "$META_TEST_LOG"

# Model Keenetic 1.4.21 exactly: iptables accepts only bare -w while the paired
# restore binary rejects every -w form and accepts plain --noflush.
if [ "$*" = '-w 10 -S' ]; then
    echo "Bad argument \`10'" >&2
    exit 2
fi
if [ "$*" = '-w -S' ]; then
    if [ "$state" = unavailable ]; then
        echo "$tool: Table does not exist" >&2
        exit 3
    fi
    exit 0
fi
if [ "${1:-}" = -w ] && [ "${2:-}" != 10 ]; then
    shift
else
    echo "$tool inspection was not protected by bare xtables wait" >&2
    exit 90
fi

if [ "$*" = '-t filter -S' ]; then
    case "$state" in
        absent)
            exit 0
            ;;
        unavailable)
            echo "$tool: Table does not exist" >&2
            exit 3
            ;;
        fail-list)
            echo "$tool: Permission denied" >&2
            exit 3
            ;;
        stale|fail-restore|concurrent)
            cat <<'RULES'
-N KeenPbrMeta443
-N KeenPbrMeta443_A
-N KeenPbrMeta443_B
-A FORWARD -j KeenPbrMeta443
-A KeenPbrMeta443 -j KeenPbrMeta443_A
-A KeenPbrMeta443_A -j KeenPbrMeta443_B
-A KeenPbrMeta443_B -p udp --dport 443 -j REJECT
RULES
            exit 0
            ;;
        missing-extension)
            echo "iptables v1.4.21: Couldn't load match 'set': No such file or directory" >&2
            exit 3
            ;;
        foreign)
            cat <<'RULES'
-N KeenPbrMeta443
-N KeenPbrMeta443_A
-N KeenPbrMeta443_B
-A FORWARD -j KeenPbrMeta443
-A ForeignChain -j KeenPbrMeta443_A
RULES
            exit 0
            ;;
        tcp-stale|tcp-fail-restore|tcp-remains)
            cat <<'RULES'
-N KeenPbrTcpRst
-A FORWARD -j KeenPbrTcpRst
-A KeenPbrTcpRst -s 192.168.1.44/32 -d 31.13.72.53/32 -p tcp -m tcp --sport 51000 --dport 443 -m mark --mark 0x30000/0xffffffff -m tcp --tcp-flags ACK ACK -j REJECT --reject-with tcp-reset
RULES
            exit 0
            ;;
        tcp-duplicate)
            cat <<'RULES'
-N KeenPbrTcpRst
-A FORWARD -j KeenPbrTcpRst
-A FORWARD -j KeenPbrTcpRst
-A KeenPbrTcpRst -s 192.168.1.44/32 -d 31.13.72.53/32 -p tcp -m tcp --sport 51000 --dport 443 -m mark --mark 0x30000/0xffffffff -m tcp --tcp-flags ACK ACK -j REJECT --reject-with tcp-reset
RULES
            exit 0
            ;;
        tcp-foreign)
            cat <<'RULES'
-N KeenPbrTcpRst
-A FORWARD -j KeenPbrTcpRst
-A ForeignChain -j KeenPbrTcpRst
RULES
            exit 0
            ;;
    esac
fi

echo "unexpected $tool call: $*" >&2
exit 91
EOF
cp "$work/bin/iptables" "$work/bin/ip6tables"

cat > "$work/bin/iptables-restore" <<'EOF'
#!/bin/sh

restore=${0##*/}
tool=${restore%-restore}
state_file="$META_TEST_STATE/$tool"
state=$(cat "$state_file")
payload=$(cat)
printf '%s %s\n' "$restore" "$*" >> "$META_TEST_LOG"
printf '%s\n' "$payload" | sed "s/^/$restore stdin: /" >> "$META_TEST_LOG"

[ "$*" = '--noflush' ] || {
    echo "$restore received an unsupported option: $*" >&2
    exit 93
}

case "$state" in
    tcp-stale|tcp-fail-restore|tcp-remains)
        expected='*filter
-D FORWARD -j KeenPbrTcpRst
-F KeenPbrTcpRst
-X KeenPbrTcpRst
COMMIT'
        ;;
    tcp-duplicate)
        expected='*filter
-D FORWARD -j KeenPbrTcpRst
-D FORWARD -j KeenPbrTcpRst
-F KeenPbrTcpRst
-X KeenPbrTcpRst
COMMIT'
        ;;
    *) expected='*filter
-D FORWARD -j KeenPbrMeta443
-F KeenPbrMeta443
-X KeenPbrMeta443
-F KeenPbrMeta443_A
-X KeenPbrMeta443_A
-F KeenPbrMeta443_B
-X KeenPbrMeta443_B
COMMIT' ;;
esac
[ "$payload" = "$expected" ] || {
    echo "unexpected $restore transaction" >&2
    printf '%s\n' "$payload" >&2
    exit 94
}

case "$state" in
    stale)
        printf '%s\n' absent > "$state_file"
        exit 0
        ;;
    fail-restore)
        # A failed restore COMMIT is atomic: preserve the complete stale graph.
        exit 4
        ;;
    concurrent)
        # Model a foreign reference added after the checked snapshot. Kernel
        # validation rejects the transaction, leaving the owned graph intact.
        printf '%s\n' foreign > "$state_file"
        exit 4
        ;;
    tcp-stale|tcp-duplicate)
        printf '%s\n' absent > "$state_file"
        exit 0
        ;;
    tcp-fail-restore)
        exit 4
        ;;
    tcp-remains)
        # Model a restore that returned success without the requested state.
        exit 0
        ;;
esac

echo "unexpected $restore state: $state" >&2
exit 95
EOF
cp "$work/bin/iptables-restore" "$work/bin/ip6tables-restore"

cat > "$work/bin/nft" <<'EOF'
#!/bin/sh

state_file="$META_TEST_STATE/nft"
state=$(cat "$state_file")
printf 'nft %s\n' "$*" >> "$META_TEST_LOG"

case "$*" in
    'list chain inet KeenPbrTable meta_udp_443')
        case "$state" in
            absent)
                echo 'Error: No such file or directory' >&2
                echo 'list chain inet KeenPbrTable meta_udp_443' >&2
                exit 1
                ;;
            missing-library)
                echo 'nft: error while loading shared libraries: libnftables.so.1: cannot open shared object file: No such file or directory' >&2
                exit 127
                ;;
            fail-list)
                echo 'Error: Operation not permitted' >&2
                exit 1
                ;;
            stale|fail-delete)
                echo 'table inet KeenPbrTable { chain meta_udp_443 { } }'
                exit 0
                ;;
        esac
        ;;
    'delete chain inet KeenPbrTable meta_udp_443')
        [ "$state" != fail-delete ] || exit 1
        printf '%s\n' absent > "$state_file"
        exit 0
        ;;
esac

echo "unexpected nft call: $*" >&2
exit 92
EOF
chmod +x "$work/bin/iptables" "$work/bin/ip6tables" \
    "$work/bin/iptables-restore" "$work/bin/ip6tables-restore" \
    "$work/bin/nft"
mkdir -p "$work/bin-no-iptables" "$work/bin-no-ip6tables" \
    "$work/bin-no-nft" "$work/bin-ipv4-only"
cp "$work/bin/ip6tables" "$work/bin/ip6tables-restore" \
    "$work/bin/nft" "$work/bin-no-iptables/"
cp "$work/bin/iptables" "$work/bin/iptables-restore" \
    "$work/bin/nft" "$work/bin-no-ip6tables/"
cp "$work/bin/iptables" "$work/bin/iptables-restore" \
    "$work/bin-ipv4-only/"
cp "$work/bin/iptables" "$work/bin/iptables-restore" \
    "$work/bin/ip6tables" "$work/bin/ip6tables-restore" \
    "$work/bin-no-nft/"
META_XTABLES_RESTORE_FILE="$work/restore.input"
META_UDP443_OWNERSHIP_FILE="$work/ownership"
META_UDP443_OWNERSHIP_TMP="$work/ownership.tmp"
FASTNAT_UNSAFE_STOP_FILE="$work/unsafe"
IPTABLES_WAIT_MODE=""
IP6TABLES_WAIT_MODE=""
IPTABLES_BARE_WAIT_SECONDS=1
STOP_KEEN_PBR_SAFE=yes
PROCS="keen-pbr-meta-cleanup-test-$$"
META_TEST_DAEMON_LIVE=no

pidof() {
    [ "$1" = "$PROCS" ] || return 1
    [ "$META_TEST_DAEMON_LIVE" = yes ] || return 1
    printf '%s\n' 4242
}

reset_case() {
    printf '%s\n' "$1" > "$work/state/iptables"
    printf '%s\n' "$2" > "$work/state/ip6tables"
    printf '%s\n' "$3" > "$work/state/nft"
    : > "$work/calls"
    META_TEST_DAEMON_LIVE=no
    rm -f "$work/unsafe" "$work/restored" \
        "$META_UDP443_OWNERSHIP_FILE" "$META_UDP443_OWNERSHIP_TMP"
}

assert_state() {
    expected=$1
    object=$2
    actual=$(cat "$work/state/$object")
    [ "$actual" = "$expected" ] || {
        echo "$object state is $actual, expected $expected" >&2
        cat "$work/calls" >&2
        exit 1
    }
}

run_absent_noop_case() (
    # An installed ip6tables binary with no IPv6 filter table is also an
    # absent backend, not an operational cleanup failure.
    reset_case absent unavailable absent
    PATH="$work/bin:$PATH"
    META_TEST_STATE="$work/state"
    META_TEST_LOG="$work/calls"
    FASTNAT_UNSAFE_STOP_FILE="$work/unsafe"
    IPTABLES_WAIT_MODE=""
    IP6TABLES_WAIT_MODE=""
    IPTABLES_BARE_WAIT_SECONDS=1
    STOP_KEEN_PBR_SAFE=yes
    export PATH META_TEST_STATE META_TEST_LOG
    log_error() { printf 'error: %s\n' "$1" >&2; }
    . "$work/functions.sh"
    prepare_stop() { :; }
    stop_keen_pbr() { STOP_KEEN_PBR_SAFE=yes; return 0; }
    restore_hwnat_if_safe() { : > "$work/restored"; }

    stop_service_for_action stop yes
    [ ! -e "$FASTNAT_UNSAFE_STOP_FILE" ]
    [ -e "$work/restored" ]
    if grep -Eq -- 'tables-restore|nft delete chain' "$work/calls"; then
        echo "absent cleanup performed a mutation" >&2
        cat "$work/calls" >&2
        exit 1
    fi
)

run_crashed_stale_case() (
    reset_case stale stale stale
    printf '%s\n' iptables nftables > "$META_UDP443_OWNERSHIP_FILE"
    initial_umask=$(umask)
    PATH="$work/bin:$PATH"
    META_TEST_STATE="$work/state"
    META_TEST_LOG="$work/calls"
    FASTNAT_UNSAFE_STOP_FILE="$work/unsafe"
    IPTABLES_WAIT_MODE=""
    IP6TABLES_WAIT_MODE=""
    IPTABLES_BARE_WAIT_SECONDS=1
    STOP_KEEN_PBR_SAFE=no
    export PATH META_TEST_STATE META_TEST_LOG
    log_error() { printf 'error: %s\n' "$1" >&2; }
    . "$work/functions.sh"
    prepare_stop() { :; }
    stop_keen_pbr() { STOP_KEEN_PBR_SAFE=no; return 0; }
    restore_hwnat_if_safe() { : > "$work/restored"; }

    # Simulate an already-crashed daemon. The stop still succeeds only after
    # all three firewall backends have been verified clean.
    if ! stop_service_for_action stop yes; then
        echo "crashed-daemon cleanup failed" >&2
        cat "$work/calls" >&2
        exit 1
    fi
    [ "$(umask)" = "$initial_umask" ] || {
        echo "Meta cleanup changed the caller umask" >&2
        exit 1
    }
    assert_state absent iptables
    assert_state absent ip6tables
    assert_state absent nft
    [ ! -e "$META_UDP443_OWNERSHIP_FILE" ]
    [ ! -e "$work/restored" ]
    grep -F -x -q -- \
        'iptables-restore --noflush' "$work/calls"
    grep -F -x -q -- \
        'ip6tables-restore --noflush' "$work/calls"
    grep -F -x -q -- \
        'nft delete chain inet KeenPbrTable meta_udp_443' "$work/calls"
)

run_backend_marker_recording_case() (
    reset_case absent unavailable absent
    PATH="$work/bin:$PATH"
    META_TEST_STATE="$work/state"
    META_TEST_LOG="$work/calls"
    export PATH META_TEST_STATE META_TEST_LOG
    log_error() { printf 'error: %s\n' "$1" >&2; }
    . "$work/functions.sh"

    record_meta_udp443_possible_backends
    [ "$(cat "$META_UDP443_OWNERSHIP_FILE")" = "nftables
iptables
ip6tables" ] || {
        echo "possible backend marker was not recorded atomically" >&2
        exit 1
    }
)

run_missing_required_iptables_case() (
    reset_case absent unavailable absent
    printf '%s\n' iptables > "$META_UDP443_OWNERSHIP_FILE"
    PATH="$work/bin-no-iptables:/bin:/usr/bin"
    META_TEST_STATE="$work/state"
    META_TEST_LOG="$work/calls"
    FASTNAT_UNSAFE_STOP_FILE="$work/unsafe"
    IPTABLES_WAIT_MODE=""
    IP6TABLES_WAIT_MODE=""
    IPTABLES_BARE_WAIT_SECONDS=1
    STOP_KEEN_PBR_SAFE=yes
    export PATH META_TEST_STATE META_TEST_LOG
    log_error() { :; }
    . "$work/functions.sh"
    prepare_stop() { :; }
    stop_keen_pbr() { STOP_KEEN_PBR_SAFE=yes; return 0; }
    restore_hwnat_if_safe() { : > "$work/restored"; }

    if stop_service_for_action stop yes; then
        echo "missing previously-owned iptables backend was accepted" >&2
        exit 1
    fi
    [ -e "$FASTNAT_UNSAFE_STOP_FILE" ]
    [ "$STOP_KEEN_PBR_SAFE" = no ]
    [ ! -e "$work/restored" ]
    [ -e "$META_UDP443_OWNERSHIP_FILE" ]
)

run_missing_required_nft_case() (
    reset_case absent unavailable absent
    printf '%s\n' nftables > "$META_UDP443_OWNERSHIP_FILE"
    PATH="$work/bin-no-nft:/bin:/usr/bin"
    META_TEST_STATE="$work/state"
    META_TEST_LOG="$work/calls"
    FASTNAT_UNSAFE_STOP_FILE="$work/unsafe"
    IPTABLES_WAIT_MODE=""
    IP6TABLES_WAIT_MODE=""
    IPTABLES_BARE_WAIT_SECONDS=1
    STOP_KEEN_PBR_SAFE=yes
    export PATH META_TEST_STATE META_TEST_LOG
    log_error() { :; }
    . "$work/functions.sh"
    prepare_stop() { :; }
    stop_keen_pbr() { STOP_KEEN_PBR_SAFE=yes; return 0; }
    restore_hwnat_if_safe() { : > "$work/restored"; }

    if stop_service_for_action stop yes; then
        echo "missing previously-owned nft backend was accepted" >&2
        exit 1
    fi
    [ -e "$FASTNAT_UNSAFE_STOP_FILE" ]
    [ "$STOP_KEEN_PBR_SAFE" = no ]
    [ ! -e "$work/restored" ]
    [ -e "$META_UDP443_OWNERSHIP_FILE" ]
)

run_missing_required_ip6tables_case() (
    reset_case absent unavailable absent
    printf '%s\n' ip6tables > "$META_UDP443_OWNERSHIP_FILE"
    PATH="$work/bin-no-ip6tables:/bin:/usr/bin"
    META_TEST_STATE="$work/state"
    META_TEST_LOG="$work/calls"
    FASTNAT_UNSAFE_STOP_FILE="$work/unsafe"
    IPTABLES_WAIT_MODE=""
    IP6TABLES_WAIT_MODE=""
    IPTABLES_BARE_WAIT_SECONDS=1
    STOP_KEEN_PBR_SAFE=yes
    export PATH META_TEST_STATE META_TEST_LOG
    log_error() { :; }
    . "$work/functions.sh"
    prepare_stop() { :; }
    stop_keen_pbr() { STOP_KEEN_PBR_SAFE=yes; return 0; }
    restore_hwnat_if_safe() { : > "$work/restored"; }

    if stop_service_for_action stop yes; then
        echo "missing previously-owned ip6tables family was accepted" >&2
        exit 1
    fi
    [ -e "$FASTNAT_UNSAFE_STOP_FILE" ]
    [ "$STOP_KEEN_PBR_SAFE" = no ]
    [ ! -e "$work/restored" ]
    [ -e "$META_UDP443_OWNERSHIP_FILE" ]
)

run_restart_with_missing_prior_owner_case() (
    missing_backend=$1
    reset_case absent unavailable absent
    printf '%s\n' "$missing_backend" > "$META_UDP443_OWNERSHIP_FILE"
    case "$missing_backend" in
        iptables) PATH="$work/bin-no-iptables:/bin:/usr/bin" ;;
        nftables) PATH="$work/bin-no-nft:/bin:/usr/bin" ;;
        *) exit 2 ;;
    esac
    META_TEST_STATE="$work/state"
    META_TEST_LOG="$work/calls"
    FASTNAT_UNSAFE_STOP_FILE="$work/unsafe"
    STOP_KEEN_PBR_SAFE=yes
    export PATH META_TEST_STATE META_TEST_LOG
    log_error() { :; }
    . "$work/functions.sh"

    if guard_meta_udp443_start_ownership; then
        echo "start accepted missing prior $missing_backend owner" >&2
        exit 1
    fi
    [ -e "$FASTNAT_UNSAFE_STOP_FILE" ]
    [ "$STOP_KEEN_PBR_SAFE" = no ]
    [ "$(cat "$META_UDP443_OWNERSHIP_FILE")" = "$missing_backend" ]
)

run_ipv4_only_start_and_clean_stop_case() (
    reset_case absent unavailable absent
    PATH="$work/bin-ipv4-only:/bin:/usr/bin"
    META_TEST_STATE="$work/state"
    META_TEST_LOG="$work/calls"
    FASTNAT_UNSAFE_STOP_FILE="$work/unsafe"
    STOP_KEEN_PBR_SAFE=yes
    export PATH META_TEST_STATE META_TEST_LOG
    log_error() { :; }
    . "$work/functions.sh"

    if ! guard_meta_udp443_start_ownership; then
        echo "IPv4-only start could not record its available family" >&2
        exit 1
    fi
    [ "$(cat "$META_UDP443_OWNERSHIP_FILE")" = iptables ]
    prepare_stop() { :; }
    stop_keen_pbr() { STOP_KEEN_PBR_SAFE=yes; return 0; }
    restore_hwnat_if_safe() { : > "$work/restored"; }
    stop_service_for_action stop yes
    [ ! -e "$FASTNAT_UNSAFE_STOP_FILE" ]
    [ -e "$work/restored" ]
    [ ! -e "$META_UDP443_OWNERSHIP_FILE" ]
)

run_crash_reconciles_before_new_start_case() (
    reset_case tcp-stale unavailable stale
    printf '%s\n' nftables > "$META_UDP443_OWNERSHIP_FILE"
    PATH="$work/bin:$PATH"
    META_TEST_STATE="$work/state"
    META_TEST_LOG="$work/calls"
    FASTNAT_UNSAFE_STOP_FILE="$work/unsafe"
    IPTABLES_WAIT_MODE=""
    IP6TABLES_WAIT_MODE=""
    IPTABLES_BARE_WAIT_SECONDS=1
    STOP_KEEN_PBR_SAFE=no
    export PATH META_TEST_STATE META_TEST_LOG
    log_error() { printf 'error: %s\n' "$1" >&2; }
    . "$work/functions.sh"

    guard_meta_udp443_start_ownership
    assert_state absent iptables
    assert_state absent nft
    grep -F -x -q -- \
        'iptables-restore --noflush' "$work/calls"
    grep -F -x -q -- \
        'nft delete chain inet KeenPbrTable meta_udp_443' "$work/calls"
    [ "$(cat "$META_UDP443_OWNERSHIP_FILE")" = "nftables
iptables
ip6tables" ]
)

run_live_daemon_start_does_not_cleanup_case() (
    reset_case tcp-stale unavailable stale
    printf '%s\n' nftables > "$META_UDP443_OWNERSHIP_FILE"
    META_TEST_DAEMON_LIVE=yes
    PATH="$work/bin:$PATH"
    META_TEST_STATE="$work/state"
    META_TEST_LOG="$work/calls"
    FASTNAT_UNSAFE_STOP_FILE="$work/unsafe"
    STOP_KEEN_PBR_SAFE=yes
    export PATH META_TEST_STATE META_TEST_LOG
    log_error() { printf 'error: %s\n' "$1" >&2; }
    . "$work/functions.sh"

    guard_meta_udp443_start_ownership
    assert_state tcp-stale iptables
    assert_state stale nft
    if grep -Eq -- 'tables-restore|nft delete chain' "$work/calls"; then
        echo "already-running start mutated active Meta UDP/443 state" >&2
        cat "$work/calls" >&2
        exit 1
    fi
)

run_tcp_rst_duplicate_stop_cleanup_case() (
    reset_case tcp-duplicate unavailable absent
    PATH="$work/bin-ipv4-only:/bin:/usr/bin"
    META_TEST_STATE="$work/state"
    META_TEST_LOG="$work/calls"
    FASTNAT_UNSAFE_STOP_FILE="$work/unsafe"
    IPTABLES_WAIT_MODE=""
    STOP_KEEN_PBR_SAFE=yes
    export PATH META_TEST_STATE META_TEST_LOG
    log_error() { printf 'error: %s\n' "$1" >&2; }
    . "$work/functions.sh"
    prepare_stop() { :; }
    stop_keen_pbr() { STOP_KEEN_PBR_SAFE=yes; return 0; }
    restore_hwnat_if_safe() { : > "$work/restored"; }

    stop_service_for_action stop yes
    assert_state absent iptables
    [ -e "$work/restored" ]
    [ ! -e "$FASTNAT_UNSAFE_STOP_FILE" ]
    [ "$(grep -F -c -- \
        'iptables-restore stdin: -D FORWARD -j KeenPbrTcpRst' \
        "$work/calls")" -eq 2 ]
    grep -F -x -q -- \
        'iptables-restore stdin: -F KeenPbrTcpRst' "$work/calls"
    grep -F -x -q -- \
        'iptables-restore stdin: -X KeenPbrTcpRst' "$work/calls"
)

run_tcp_rst_foreign_reference_case() (
    reset_case tcp-foreign unavailable absent
    PATH="$work/bin-ipv4-only:/bin:/usr/bin"
    META_TEST_STATE="$work/state"
    META_TEST_LOG="$work/calls"
    FASTNAT_UNSAFE_STOP_FILE="$work/unsafe"
    IPTABLES_WAIT_MODE=""
    STOP_KEEN_PBR_SAFE=yes
    export PATH META_TEST_STATE META_TEST_LOG
    log_error() { :; }
    . "$work/functions.sh"

    if cleanup_stale_tcp_rst_firewall; then
        echo "TCP reset cleanup accepted a foreign chain reference" >&2
        exit 1
    fi
    [ -e "$FASTNAT_UNSAFE_STOP_FILE" ]
    [ "$STOP_KEEN_PBR_SAFE" = no ]
    assert_state tcp-foreign iptables
    if grep -F -q -- 'iptables-restore ' "$work/calls"; then
        echo "foreign TCP reset reference triggered a mutation" >&2
        cat "$work/calls" >&2
        exit 1
    fi
)

run_tcp_rst_post_cleanup_verification_case() (
    reset_case tcp-remains unavailable absent
    PATH="$work/bin-ipv4-only:/bin:/usr/bin"
    META_TEST_STATE="$work/state"
    META_TEST_LOG="$work/calls"
    FASTNAT_UNSAFE_STOP_FILE="$work/unsafe"
    IPTABLES_WAIT_MODE=""
    STOP_KEEN_PBR_SAFE=yes
    export PATH META_TEST_STATE META_TEST_LOG
    log_error() { :; }
    . "$work/functions.sh"

    if cleanup_stale_tcp_rst_firewall; then
        echo "TCP reset cleanup accepted stale post-restore state" >&2
        exit 1
    fi
    [ -e "$FASTNAT_UNSAFE_STOP_FILE" ]
    [ "$STOP_KEEN_PBR_SAFE" = no ]
    assert_state tcp-remains iptables
)

run_foreign_reference_case() (
    reset_case foreign absent absent
    PATH="$work/bin:$PATH"
    META_TEST_STATE="$work/state"
    META_TEST_LOG="$work/calls"
    FASTNAT_UNSAFE_STOP_FILE="$work/unsafe"
    IPTABLES_WAIT_MODE=""
    IP6TABLES_WAIT_MODE=""
    IPTABLES_BARE_WAIT_SECONDS=1
    STOP_KEEN_PBR_SAFE=yes
    export PATH META_TEST_STATE META_TEST_LOG
    log_error() { :; }
    . "$work/functions.sh"

    if cleanup_stale_meta_udp443_firewall; then
        echo "cleanup accepted a foreign chain reference" >&2
        exit 1
    fi
    [ -e "$FASTNAT_UNSAFE_STOP_FILE" ]
    [ "$STOP_KEEN_PBR_SAFE" = no ]
    assert_state foreign iptables
    if grep -F -q -- 'iptables-restore ' "$work/calls"; then
        echo "foreign-reference refusal mutated IPv4 state" >&2
        cat "$work/calls" >&2
        exit 1
    fi
)

run_failure_propagation_case() (
    reset_case fail-restore absent absent
    PATH="$work/bin:$PATH"
    META_TEST_STATE="$work/state"
    META_TEST_LOG="$work/calls"
    FASTNAT_UNSAFE_STOP_FILE="$work/unsafe"
    IPTABLES_WAIT_MODE=""
    IP6TABLES_WAIT_MODE=""
    IPTABLES_BARE_WAIT_SECONDS=1
    STOP_KEEN_PBR_SAFE=yes
    export PATH META_TEST_STATE META_TEST_LOG
    log_error() { :; }
    . "$work/functions.sh"
    prepare_stop() { :; }
    stop_keen_pbr() { STOP_KEEN_PBR_SAFE=yes; return 0; }
    restore_hwnat_if_safe() { : > "$work/restored"; }

    if stop_service_for_action stop yes; then
        echo "stop ignored a Meta UDP/443 cleanup failure" >&2
        exit 1
    fi
    [ -e "$FASTNAT_UNSAFE_STOP_FILE" ]
    [ "$STOP_KEEN_PBR_SAFE" = no ]
    [ ! -e "$work/restored" ]
    assert_state fail-restore iptables
    grep -F -x -q -- \
        'iptables-restore --noflush' "$work/calls"
)

run_concurrent_reference_case() (
    reset_case concurrent absent absent
    PATH="$work/bin:$PATH"
    META_TEST_STATE="$work/state"
    META_TEST_LOG="$work/calls"
    FASTNAT_UNSAFE_STOP_FILE="$work/unsafe"
    IPTABLES_WAIT_MODE=""
    IP6TABLES_WAIT_MODE=""
    IPTABLES_BARE_WAIT_SECONDS=1
    STOP_KEEN_PBR_SAFE=yes
    export PATH META_TEST_STATE META_TEST_LOG
    log_error() { :; }
    . "$work/functions.sh"

    if cleanup_stale_meta_udp443_firewall; then
        echo "cleanup ignored a reference added after its snapshot" >&2
        exit 1
    fi
    [ -e "$FASTNAT_UNSAFE_STOP_FILE" ]
    [ "$STOP_KEEN_PBR_SAFE" = no ]
    assert_state foreign iptables
)

run_inspection_failure_case() (
    reset_case absent fail-list absent
    PATH="$work/bin:$PATH"
    META_TEST_STATE="$work/state"
    META_TEST_LOG="$work/calls"
    FASTNAT_UNSAFE_STOP_FILE="$work/unsafe"
    IPTABLES_WAIT_MODE=""
    IP6TABLES_WAIT_MODE=""
    IPTABLES_BARE_WAIT_SECONDS=1
    STOP_KEEN_PBR_SAFE=yes
    export PATH META_TEST_STATE META_TEST_LOG
    log_error() { :; }
    . "$work/functions.sh"

    if cleanup_stale_meta_udp443_firewall; then
        echo "cleanup ignored an IPv6 inspection failure" >&2
        exit 1
    fi
    [ -e "$FASTNAT_UNSAFE_STOP_FILE" ]
    [ "$STOP_KEEN_PBR_SAFE" = no ]
)

run_missing_extension_failure_case() (
    reset_case missing-extension absent absent
    PATH="$work/bin:$PATH"
    META_TEST_STATE="$work/state"
    META_TEST_LOG="$work/calls"
    FASTNAT_UNSAFE_STOP_FILE="$work/unsafe"
    IPTABLES_WAIT_MODE=""
    IP6TABLES_WAIT_MODE=""
    IPTABLES_BARE_WAIT_SECONDS=1
    STOP_KEEN_PBR_SAFE=yes
    export PATH META_TEST_STATE META_TEST_LOG
    log_error() { :; }
    . "$work/functions.sh"
    prepare_stop() { :; }
    stop_keen_pbr() { STOP_KEEN_PBR_SAFE=yes; return 0; }
    restore_hwnat_if_safe() { : > "$work/restored"; }

    # A missing userspace match extension is an inspection failure, not proof
    # that the kernel filter table and its stale reject chains are absent.
    if stop_service_for_action stop yes; then
        echo "missing xtables extension was mistaken for an absent table" >&2
        exit 1
    fi
    [ -e "$FASTNAT_UNSAFE_STOP_FILE" ]
    [ "$STOP_KEEN_PBR_SAFE" = no ]
    [ ! -e "$work/restored" ]
    assert_state missing-extension iptables
    if grep -F -q -- 'iptables-restore ' "$work/calls"; then
        echo "inspection failure attempted an IPv4 mutation" >&2
        cat "$work/calls" >&2
        exit 1
    fi
)

run_missing_nft_library_failure_case() (
    reset_case absent absent missing-library
    PATH="$work/bin:$PATH"
    META_TEST_STATE="$work/state"
    META_TEST_LOG="$work/calls"
    FASTNAT_UNSAFE_STOP_FILE="$work/unsafe"
    IPTABLES_WAIT_MODE=""
    IP6TABLES_WAIT_MODE=""
    IPTABLES_BARE_WAIT_SECONDS=1
    STOP_KEEN_PBR_SAFE=yes
    export PATH META_TEST_STATE META_TEST_LOG
    log_error() { :; }
    . "$work/functions.sh"
    prepare_stop() { :; }
    stop_keen_pbr() { STOP_KEEN_PBR_SAFE=yes; return 0; }
    restore_hwnat_if_safe() { : > "$work/restored"; }

    # A present-but-unusable nft binary cannot prove that the kernel chain is
    # absent. Keep package removal and FastNAT restoration fail closed.
    if stop_service_for_action stop yes; then
        echo "missing nft library was mistaken for an absent chain" >&2
        exit 1
    fi
    [ -e "$FASTNAT_UNSAFE_STOP_FILE" ]
    [ "$STOP_KEEN_PBR_SAFE" = no ]
    [ ! -e "$work/restored" ]
    assert_state missing-library nft
    if grep -F -q -- \
        'nft delete chain inet KeenPbrTable meta_udp_443' "$work/calls"; then
        echo "nft inspection failure attempted a mutation" >&2
        cat "$work/calls" >&2
        exit 1
    fi
)

run_absent_noop_case
run_crashed_stale_case
run_backend_marker_recording_case
run_missing_required_iptables_case
run_missing_required_ip6tables_case
run_missing_required_nft_case
run_restart_with_missing_prior_owner_case iptables
run_restart_with_missing_prior_owner_case nftables
run_ipv4_only_start_and_clean_stop_case
run_crash_reconciles_before_new_start_case
run_live_daemon_start_does_not_cleanup_case
run_tcp_rst_duplicate_stop_cleanup_case
run_tcp_rst_foreign_reference_case
run_tcp_rst_post_cleanup_verification_case
run_foreign_reference_case
run_failure_propagation_case
run_concurrent_reference_case
run_inspection_failure_case
run_missing_extension_failure_case
run_missing_nft_library_failure_case

# Keenetic's firmware /bin/sh may omit the optional POSIX -n parser mode.
if /bin/sh -n -c ':' >/dev/null 2>&1; then
    /bin/sh -n "$init_script"
fi
