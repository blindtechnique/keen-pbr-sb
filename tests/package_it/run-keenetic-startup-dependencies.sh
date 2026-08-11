#!/bin/sh

set -eu

init_script=${1:-}
[ -f "$init_script" ] || {
    echo "usage: $0 <S80keen-pbr>" >&2
    exit 2
}

work=$(mktemp -d)
trap 'rm -rf "$work"' 0 HUP INT TERM

{
    sed -n '/^run_bounded_command()/,/^run_bounded_command_with_stdin()/p' \
        "$init_script" | sed '$d'
    sed -n '/^is_module_loaded()/,/^try_kernel_module_loaded()/p' \
        "$init_script" | sed '$d'
    sed -n '/^check_netfilter_addons_component()/,/^ensure_ipset_modules_loaded()/p' \
        "$init_script" | sed '$d'
    sed -n '/^ensure_xt_multiport_loaded()/,/^remove_daemon_arg()/p' \
        "$init_script" | sed '$d'
    sed -n '/^prepare_start()/,/^prepare_stop()/p' \
        "$init_script" | sed '$d'
} > "$work/functions.sh"

sed -n '/^IPTABLES_BARE_WAIT_SECONDS=/,/^log()/p' "$init_script" |
    sed '$d' > "$work/startup-limits.sh"

mkdir -p "$work/bin" "$work/modules"

cat > "$work/bin/wget" <<'EOF'
#!/bin/sh
count=0
[ ! -f "$RCI_TEST_COUNT" ] || count=$(cat "$RCI_TEST_COUNT")
count=$((count + 1))
printf '%s\n' "$count" > "$RCI_TEST_COUNT"
{
    printf '<%s>' "$@"
    printf '\n'
} >> "$RCI_TEST_ARGS"

case "$RCI_TEST_MODE" in
    success) exit 0 ;;
    retry) [ "$count" -ge 2 ] ;;
    component-present)
        printf '%s\n' 'opkg-kmod-netfilter-addons'
        exit 0
        ;;
    component-missing)
        printf '%s\n' 'some-other-component'
        exit 0
        ;;
    failure) exit 1 ;;
    hang)
        trap '' TERM
        while :; do /bin/sleep 1; done
        ;;
    *) exit 64 ;;
esac
EOF

cat > "$work/bin/lsmod" <<'EOF'
#!/bin/sh
[ "${MODULE_TEST_MODE:-}" != loaded ] ||
    printf '%s\n' 'xt_dscp 16384 0'
EOF

cat > "$work/bin/uname" <<'EOF'
#!/bin/sh
[ "${1:-}" = -r ] || exit 64
printf '%s\n' test-kernel
EOF

cat > "$work/bin/insmod" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$MODULE_TEST_CALLS"
[ "${MODULE_TEST_MODE:-}" != load-failure ]
EOF

chmod +x "$work/bin/wget" "$work/bin/lsmod" \
    "$work/bin/uname" "$work/bin/insmod"

assert_contains() {
    expected=$1
    file=$2
    grep -F -q -- "$expected" "$file" || {
        echo "missing '$expected' in $file" >&2
        cat "$file" >&2
        exit 1
    }
}

assert_not_contains() {
    unexpected=$1
    file=$2
    if grep -F -q -- "$unexpected" "$file"; then
        echo "unexpected '$unexpected' in $file" >&2
        cat "$file" >&2
        exit 1
    fi
}

assert_all_lines_equal() {
    expected=$1
    file=$2

    while IFS= read -r actual; do
        [ "$actual" = "$expected" ] || {
            echo "unexpected argv in $file: $actual" >&2
            cat "$file" >&2
            exit 1
        }
    done < "$file"
}

run_limit_case() (
    attempts=$1
    probe_seconds=$2
    expected_attempts=$3
    expected_probe_seconds=$4

    KEENETIC_RCI_STARTUP_ATTEMPTS=$attempts
    KEENETIC_RCI_PROBE_SECONDS=$probe_seconds
    . "$work/startup-limits.sh"

    [ "$KEENETIC_RCI_STARTUP_ATTEMPTS" = "$expected_attempts" ] || {
        echo "unexpected sanitized RCI attempts for '$attempts': $KEENETIC_RCI_STARTUP_ATTEMPTS" >&2
        exit 1
    }
    [ "$KEENETIC_RCI_PROBE_SECONDS" = "$expected_probe_seconds" ] || {
        echo "unexpected sanitized RCI probe seconds for '$probe_seconds': $KEENETIC_RCI_PROBE_SECONDS" >&2
        exit 1
    }
)

run_rci_case() (
    mode=$1
    attempts=$2
    expected_calls=$3
    RCI_TEST_MODE=$mode
    RCI_TEST_COUNT="$work/rci-$mode.count"
    RCI_TEST_ARGS="$work/rci-$mode.args"
    RCI_TEST_LOG="$work/rci-$mode.log"
    KEENETIC_RCI_STARTUP_ATTEMPTS=$attempts
    KEENETIC_RCI_PROBE_SECONDS=1
    PATH="$work/bin:$PATH"
    export PATH RCI_TEST_MODE RCI_TEST_COUNT RCI_TEST_ARGS
    printf '0\n' > "$RCI_TEST_COUNT"
    : > "$RCI_TEST_ARGS"
    : > "$RCI_TEST_LOG"
    . "$work/functions.sh"

    log() {
        printf 'info:%s\n' "$1" >> "$RCI_TEST_LOG"
    }
    log_error() {
        printf 'error:%s\n' "$1" >> "$RCI_TEST_LOG"
    }

    started=$(date +%s)
    wait_for_keenetic_rci
    elapsed=$(($(date +%s) - started))
    actual_calls=$(cat "$RCI_TEST_COUNT")
    [ "$actual_calls" = "$expected_calls" ] || {
        echo "unexpected RCI probe count for $mode: $actual_calls" >&2
        exit 1
    }
    assert_all_lines_equal \
        '<-q><-O></dev/null><http://127.0.0.1:79/rci/show/version>' \
        "$RCI_TEST_ARGS"

    case "$mode" in
        success)
            [ ! -s "$RCI_TEST_LOG" ] || {
                echo "immediate RCI readiness emitted a warning" >&2
                cat "$RCI_TEST_LOG" >&2
                exit 1
            }
            ;;
        retry)
            assert_contains \
                "Keenetic RCI became available after 2 attempts" \
                "$RCI_TEST_LOG"
            ;;
        failure|hang)
            assert_contains \
                "Keenetic RCI is still unavailable after $attempts attempts; continuing startup" \
                "$RCI_TEST_LOG"
            ;;
    esac

    if [ "$mode" = hang ] && [ "$elapsed" -gt 4 ]; then
        echo "RCI probe was not bounded (${elapsed}s)" >&2
        exit 1
    fi
)

run_component_case() (
    mode=$1
    RCI_TEST_MODE=$mode
    RCI_TEST_COUNT="$work/component-$mode.count"
    RCI_TEST_ARGS="$work/component-$mode.args"
    RCI_TEST_LOG="$work/component-$mode.log"
    KEENETIC_RCI_PROBE_SECONDS=1
    PATH="$work/bin:$PATH"
    export PATH RCI_TEST_MODE RCI_TEST_COUNT RCI_TEST_ARGS
    printf '0\n' > "$RCI_TEST_COUNT"
    : > "$RCI_TEST_ARGS"
    : > "$RCI_TEST_LOG"
    . "$work/functions.sh"

    log() {
        printf 'info:%s\n' "$1" >> "$RCI_TEST_LOG"
    }
    log_error() {
        printf 'error:%s\n' "$1" >> "$RCI_TEST_LOG"
    }

    started=$(date +%s)
    check_netfilter_addons_component
    elapsed=$(($(date +%s) - started))
    [ "$(cat "$RCI_TEST_COUNT")" = 1 ] || {
        echo "unexpected component probe count for $mode" >&2
        exit 1
    }
    assert_all_lines_equal \
        '<-q><-O><-><http://127.0.0.1:79/rci/show/version/ndw/components>' \
        "$RCI_TEST_ARGS"

    case "$mode" in
        component-present)
            [ ! -s "$RCI_TEST_LOG" ] || {
                echo "present component emitted a warning" >&2
                cat "$RCI_TEST_LOG" >&2
                exit 1
            }
            ;;
        component-missing)
            assert_contains \
                "Missing Keenetic component opkg-kmod-netfilter-addons" \
                "$RCI_TEST_LOG"
            assert_not_contains \
                "component status is unavailable" "$RCI_TEST_LOG"
            ;;
        failure|hang)
            assert_contains \
                "Failed to fetch installed Keenetic components; component status is unavailable" \
                "$RCI_TEST_LOG"
            assert_not_contains \
                "Missing Keenetic component" "$RCI_TEST_LOG"
            ;;
    esac

    if [ "$mode" = hang ] && [ "$elapsed" -gt 4 ]; then
        echo "component probe was not bounded (${elapsed}s)" >&2
        exit 1
    fi
)

run_module_case() (
    mode=$1
    MODULE_TEST_MODE=$mode
    MODULE_TEST_CALLS="$work/module-$mode.calls"
    MODULE_TEST_LOG="$work/module-$mode.log"
    MODULE_ROOT="$work/modules/$mode"
    PATH="$work/bin:$PATH"
    export PATH MODULE_TEST_MODE MODULE_TEST_CALLS
    rm -rf "$MODULE_ROOT"
    mkdir -p "$MODULE_ROOT"
    : > "$MODULE_TEST_CALLS"
    : > "$MODULE_TEST_LOG"
    case "$mode" in
        success|load-failure) : > "$MODULE_ROOT/xt_dscp.ko" ;;
    esac
    . "$work/functions.sh"

    log() {
        printf 'info:%s\n' "$1" >> "$MODULE_TEST_LOG"
    }
    log_error() {
        printf 'error:%s\n' "$1" >> "$MODULE_TEST_LOG"
    }
    module_path_for() {
        printf '%s/%s.ko\n' "$MODULE_ROOT" "$1"
    }

    ensure_xt_dscp_loaded || {
        echo "xt_dscp $mode case unexpectedly failed startup" >&2
        exit 1
    }

    case "$mode" in
        loaded)
            [ ! -s "$MODULE_TEST_CALLS" ] && [ ! -s "$MODULE_TEST_LOG" ]
            ;;
        missing)
            [ ! -s "$MODULE_TEST_CALLS" ]
            assert_contains \
                "xt_dscp module not loaded and not found at $MODULE_ROOT/xt_dscp.ko" \
                "$MODULE_TEST_LOG"
            ;;
        success)
            [ "$(cat "$MODULE_TEST_CALLS")" = \
                "$MODULE_ROOT/xt_dscp.ko" ]
            [ ! -s "$MODULE_TEST_LOG" ]
            ;;
        load-failure)
            [ "$(cat "$MODULE_TEST_CALLS")" = \
                "$MODULE_ROOT/xt_dscp.ko" ]
            assert_contains \
                "Failed to load xt_dscp from $MODULE_ROOT/xt_dscp.ko" \
                "$MODULE_TEST_LOG"
            ;;
    esac
)

run_dependency_order_case() (
    calls="$work/dependency-order.calls"
    : > "$calls"
    . "$work/functions.sh"
    check_netfilter_addons_component() { echo components >> "$calls"; }
    ensure_ipset_modules_loaded() { echo ipset >> "$calls"; }
    ensure_xt_multiport_loaded() { echo multiport >> "$calls"; }
    ensure_xt_dscp_loaded() { echo dscp >> "$calls"; }

    check_runtime_dependencies
    expected='components
ipset
multiport
dscp'
    actual=$(cat "$calls")
    [ "$actual" = "$expected" ] || {
        echo "unexpected dependency order: $actual" >&2
        exit 1
    }
)

run_prepare_start_order_case() (
    calls="$work/prepare-start-order.calls"
    : > "$calls"
    . "$work/functions.sh"
    wait_for_keenetic_rci() { echo rci >> "$calls"; }
    check_runtime_dependencies() { echo dependencies >> "$calls"; }
    configure_raw_prerouting() { echo raw >> "$calls"; }
    disable_hwnat() { echo fastnat >> "$calls"; }

    prepare_start
    expected='rci
dependencies
raw
fastnat'
    actual=$(cat "$calls")
    [ "$actual" = "$expected" ] || {
        echo "unexpected prepare_start order: $actual" >&2
        exit 1
    }
)

run_limit_case '' '' 15 1
run_limit_case 15 1 15 1
run_limit_case 7 2 7 2
run_limit_case invalid invalid 15 1
run_limit_case 0 0 15 1
run_limit_case 16 3 15 2
run_limit_case 99999999999999999999 99999999999999999999 15 1
run_rci_case success 3 1
run_rci_case retry 3 2
run_rci_case failure 2 2
run_rci_case hang 1 1
run_component_case component-present
run_component_case component-missing
run_component_case failure
run_component_case hang
run_module_case loaded
run_module_case missing
run_module_case success
run_module_case load-failure
run_dependency_order_case
run_prepare_start_order_case

if /bin/sh -n -c ':' >/dev/null 2>&1; then
    /bin/sh -n "$init_script"
    /bin/sh -n "$0"
fi

# Every action that mutates the running service must take the update lock, so
# a lifecycle step cannot run underneath an in-flight package update. This is a
# static check because the realistic regression is not a broken gate but a
# missing one: someone adds an action and does not think about the lock, and
# nothing at runtime says so.
#
# reapply-firewall and reapply-nat are deliberately absent: they only signal the
# already-running daemon to re-derive netfilter state and touch no package or
# persistent file.
for gated_action in reload reapply-dnsmasq-config start restart stop kill \
        stop-for-upgrade; do
    awk -v action="$gated_action" '
        $0 ~ "^    " action "\\)$" || $0 ~ "^    " action "\\|" { found = 1; next }
        found && /enter_lifecycle_lock/ { gated = 1; exit }
        found && /^    [a-z-]+\)/ { exit }
        END { exit(gated ? 0 : 1) }
    ' "$init_script" || {
        echo "S80 action '$gated_action' does not take the update lock" >&2
        exit 1
    }
done

echo "Keenetic startup dependency checks passed"
