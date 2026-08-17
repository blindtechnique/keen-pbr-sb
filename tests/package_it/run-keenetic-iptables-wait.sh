#!/bin/sh

set -eu

init_script=${1:-}
[ -f "$init_script" ] || {
    echo "usage: $0 <S80keen-pbr>" >&2
    exit 2
}

work=$(mktemp -d)
trap 'rm -rf "$work"' 0 HUP INT TERM

# Source only the production probes under test; the Keenetic rc.func
# dispatcher and the rest of service startup are intentionally not emulated.
{
    sed -n '/^run_bounded_command()/,/^is_module_loaded()/p' \
        "$init_script" | sed '$d'
    sed -n '/^iptables_udp_peer_match_available()/,/^check_netfilter_addons_component()/p' \
        "$init_script" | sed '$d'
    sed -n '/^probe_raw_table()/,/^ensure_raw_table_available()/p' \
        "$init_script" | sed '$d'
} > "$work/functions.sh"

mkdir -p "$work/bin"
cat > "$work/bin/iptables" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$IPTABLES_TEST_LOG"

case "$*" in
    '-w 10 -S')
        case "$IPTABLES_TEST_MODE" in
            timeout) exit 0 ;;
            numeric_exit4) exit 4 ;;
            numeric_lock_message)
                echo "Another app is currently holding the xtables lock" >&2
                exit 1
                ;;
            numeric_option_none)
                echo "iptables: unrecognized option '-w'" >&2
                exit 2
                ;;
            numeric_getopt_none)
                echo "iptables: invalid option -- 'w'" >&2
                exit 2
                ;;
            flag|flag_lock|bare_exit4|bare_lock_message|bare_timeout|none|bare_getopt_none)
                echo "Bad argument \`10'" >&2
                exit 2
                ;;
            error)
                echo "iptables: Permission denied" >&2
                exit 3
                ;;
            wrong_argument)
                echo "Bad argument \`FORWARD'" >&2
                exit 2
                ;;
        esac
        ;;
    '-w -S')
        case "$IPTABLES_TEST_MODE" in
            timeout|flag|flag_lock) exit 0 ;;
            bare_exit4) exit 4 ;;
            bare_lock_message)
                echo "xtables lock is temporarily unavailable" >&2
                exit 1
                ;;
            bare_timeout)
                trap '' TERM
                while :; do sleep 1; done
                exit 1
                ;;
            none)
                echo "iptables: unrecognized option '-w'" >&2
                exit 2
                ;;
            bare_getopt_none)
                echo "iptables: invalid option -- 'w'" >&2
                exit 2
                ;;
        esac
        ;;
esac

case "$IPTABLES_TEST_MODE" in
    timeout|numeric_exit4|numeric_lock_message)
        [ "${1:-}" = -w ] && [ "${2:-}" = 10 ] || exit 42
        ;;
    flag|bare_exit4|bare_lock_message)
        [ "${1:-}" = -w ] || exit 42
        [ "${2:-}" != 10 ] || exit 42
        ;;
    flag_lock)
        [ "${1:-}" = -w ] || exit 42
        [ "${2:-}" != 10 ] || exit 42
        case "$*" in
            '-w -t mangle -A '*)
                trap '' TERM
                while :; do sleep 1; done
                exit 1
                ;;
        esac
        ;;
    none|numeric_option_none|numeric_getopt_none|bare_getopt_none)
        [ "${1:-}" != -w ] || exit 42
        ;;
    error|wrong_argument|bare_timeout) exit 44 ;;
    *) exit 43 ;;
esac
exit 0
EOF

cat > "$work/bin/ipset" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$work/bin/iptables" "$work/bin/ipset"
IPTABLES_BARE_WAIT_SECONDS=10

assert_line() {
    line=$1
    grep -F -x -q -- "$line" "$IPTABLES_TEST_LOG" || {
        echo "missing iptables call: $line" >&2
        cat "$IPTABLES_TEST_LOG" >&2
        exit 1
    }
}

assert_count() {
    expected=$1
    line=$2
    actual=$(grep -F -x -c -- "$line" "$IPTABLES_TEST_LOG" || true)
    [ "$actual" = "$expected" ] || {
        echo "unexpected iptables call count for '$line': $actual (expected $expected)" >&2
        cat "$IPTABLES_TEST_LOG" >&2
        exit 1
    }
}

run_case() (
    mode=$1
    expected_wait_mode=$2
    IPTABLES_TEST_MODE=$mode
    IPTABLES_TEST_LOG="$work/$mode.calls"
    PATH="$work/bin:$PATH"
    IPTABLES_WAIT_MODE=""
    IPSET_UDP_PEER_PROBE_SET="kpbr_probe_udp_peer_test"
    IPTABLES_UDP_PEER_PROBE_CHAIN="KpbrUdpProbeTest"
    export PATH IPTABLES_TEST_MODE IPTABLES_TEST_LOG
    : > "$IPTABLES_TEST_LOG"
    . "$work/functions.sh"

    iptables_udp_peer_match_available || {
        echo "UDP peer probe failed in $mode mode" >&2
        cat "$IPTABLES_TEST_LOG" >&2
        exit 1
    }
    probe_raw_table || {
        echo "raw-table probe failed in $mode mode" >&2
        cat "$IPTABLES_TEST_LOG" >&2
        exit 1
    }

    # Capability detection is cached: the later raw-table probe must reuse
    # the same syntax and must not rerun either read-only capability probe.
    assert_count 1 '-w 10 -S'
    assert_count 0 '-S'
    case "$expected_wait_mode" in
        timeout)
            assert_count 0 '-w -S'
            assert_line '-w 10 -t mangle -N KpbrUdpProbeTest'
            assert_line '-w 10 -t mangle -A KpbrUdpProbeTest -p udp -m set --match-set kpbr_probe_udp_peer_test src,dst,dst -j RETURN'
            assert_line '-w 10 -t mangle -F KpbrUdpProbeTest'
            assert_line '-w 10 -t mangle -X KpbrUdpProbeTest'
            assert_line '-w 10 -t raw -S'
            ;;
        flag)
            assert_count 1 '-w -S'
            assert_line '-w -t mangle -N KpbrUdpProbeTest'
            assert_line '-w -t mangle -A KpbrUdpProbeTest -p udp -m set --match-set kpbr_probe_udp_peer_test src,dst,dst -j RETURN'
            assert_line '-w -t mangle -F KpbrUdpProbeTest'
            assert_line '-w -t mangle -X KpbrUdpProbeTest'
            assert_line '-w -t raw -S'
            ;;
        none)
            case "$mode" in
                numeric_option_none|numeric_getopt_none) assert_count 0 '-w -S' ;;
                *) assert_count 1 '-w -S' ;;
            esac
            assert_line '-t mangle -N KpbrUdpProbeTest'
            assert_line '-t mangle -A KpbrUdpProbeTest -p udp -m set --match-set kpbr_probe_udp_peer_test src,dst,dst -j RETURN'
            assert_line '-t mangle -F KpbrUdpProbeTest'
            assert_line '-t mangle -X KpbrUdpProbeTest'
            assert_line '-t raw -S'
            ;;
    esac
)

run_error_case() (
    mode=$1
    IPTABLES_TEST_MODE=$mode
    IPTABLES_TEST_LOG="$work/$mode.calls"
    PATH="$work/bin:$PATH"
    IPTABLES_WAIT_MODE=""
    IPSET_UDP_PEER_PROBE_SET="kpbr_probe_udp_peer_test"
    IPTABLES_UDP_PEER_PROBE_CHAIN="KpbrUdpProbeTest"
    export PATH IPTABLES_TEST_MODE IPTABLES_TEST_LOG
    : > "$IPTABLES_TEST_LOG"
    . "$work/functions.sh"

    if iptables_udp_peer_match_available; then
        echo "UDP peer probe ignored an operational $mode failure" >&2
        exit 1
    fi
    if probe_raw_table; then
        echo "raw-table probe ignored an operational $mode failure" >&2
        exit 1
    fi
    assert_count 1 '-w 10 -S'
    assert_count 0 '-w -S'
    assert_count 0 '-S'
    if grep -F -q -- '-t mangle' "$IPTABLES_TEST_LOG" ||
       grep -F -q -- '-t raw' "$IPTABLES_TEST_LOG"; then
        echo "iptables mutation/probe ran after capability detection failed" >&2
        cat "$IPTABLES_TEST_LOG" >&2
        exit 1
    fi
)

run_bare_timeout_case() (
    IPTABLES_TEST_MODE=bare_timeout
    IPTABLES_TEST_LOG="$work/bare-timeout.calls"
    PATH="$work/bin:$PATH"
    IPTABLES_WAIT_MODE=""
    IPTABLES_BARE_WAIT_SECONDS=1
    export PATH IPTABLES_TEST_MODE IPTABLES_TEST_LOG
    : > "$IPTABLES_TEST_LOG"
    . "$work/functions.sh"

    started=$(date +%s)
    if probe_raw_table; then
        echo "raw-table probe accepted an ambiguous bare-wait timeout" >&2
        exit 1
    fi
    elapsed=$(($(date +%s) - started))
    [ "$elapsed" -le 4 ] || {
        echo "bare xtables capability probe was not bounded (${elapsed}s)" >&2
        exit 1
    }
    assert_count 1 '-w 10 -S'
    assert_count 1 '-w -S'
    assert_count 0 '-S'
    assert_count 0 '-t raw -S'
)

run_cleanup_lock_case() (
    IPTABLES_TEST_MODE=flag_lock
    IPTABLES_TEST_LOG="$work/cleanup-lock.calls"
    PATH="$work/bin:$PATH"
    IPTABLES_WAIT_MODE=""
    IPTABLES_BARE_WAIT_SECONDS=1
    IPSET_UDP_PEER_PROBE_SET="kpbr_probe_udp_peer_test"
    IPTABLES_UDP_PEER_PROBE_CHAIN="KpbrUdpProbeTest"
    export PATH IPTABLES_TEST_MODE IPTABLES_TEST_LOG
    : > "$IPTABLES_TEST_LOG"
    . "$work/functions.sh"

    started=$(date +%s)
    if iptables_udp_peer_match_available; then
        echo "UDP peer probe accepted a timed-out append" >&2
        exit 1
    fi
    elapsed=$(($(date +%s) - started))
    [ "$elapsed" -le 4 ] || {
        echo "bare xtables mutation was not bounded (${elapsed}s)" >&2
        exit 1
    }

    # The append can time out after the temporary chain was created. Cleanup
    # must still flush and delete that exact chain through the bounded helper.
    assert_line '-w -t mangle -N KpbrUdpProbeTest'
    assert_line '-w -t mangle -A KpbrUdpProbeTest -p udp -m set --match-set kpbr_probe_udp_peer_test src,dst,dst -j RETURN'
    assert_line '-w -t mangle -F KpbrUdpProbeTest'
    assert_line '-w -t mangle -X KpbrUdpProbeTest'
)

run_case timeout timeout
run_case numeric_exit4 timeout
run_case numeric_lock_message timeout
run_case flag flag
run_case bare_exit4 flag
run_case bare_lock_message flag
run_case none none
run_case numeric_option_none none
run_case numeric_getopt_none none
run_case bare_getopt_none none
run_error_case error
run_error_case wrong_argument
run_bare_timeout_case
run_cleanup_lock_case

# Keenetic's firmware /bin/sh does not expose the optional POSIX -n parser
# mode. Keep the syntax assertion on hosts where it exists; the cases above
# still run under BusyBox in package CI.
if /bin/sh -n -c ':' >/dev/null 2>&1; then
    /bin/sh -n "$init_script"
fi
