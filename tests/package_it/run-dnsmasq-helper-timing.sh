#!/bin/sh

set -eu

[ "$#" -eq 1 ] || {
    echo "usage: $0 <keenetic-dnsmasq-helper>" >&2
    exit 2
}

# Exercise the shipped function bodies, not a second implementation of their
# retry loops. Only the fixed init-script I/O boundary is replaced. Everything
# below is in-process: no router paths, real signals, processes or sleeps.
helper="$1"
eval "$(sed -n '/^stop_dnsmasq() {/,/^}/p' "$helper")"
eval "$(sed -n '/^restart_dnsmasq() {/,/^}/p' "$helper" |
    sed -e 's@\[ -x /opt/etc/init.d/S56dnsmasq \] || return 1@:@' \
        -e 's|/opt/etc/init.d/S56dnsmasq start|mock_start_dnsmasq start|')"

fail() {
    printf '%s\n' "$*" >&2
    exit 1
}

assert_equal() {
    [ "$1" = "$2" ] || fail "$3: expected $2, got $1"
}

reset_fixture() {
    delay_mode="$1"
    elapsed_ms=0
    alive=0
    exits_on_term=0
    force_at_ms=-1
    start_after_ms=-1
    phase=initial
    start_calls=0
    pid_cleanup_calls=0
}

dnsmasq_pid() {
    if [ "$phase" = starting ]; then
        [ "$start_after_ms" -ge 0 ] &&
            [ "$elapsed_ms" -ge "$start_after_ms" ] || return 1
    else
        [ "$alive" -eq 1 ] || return 1
    fi
    printf '43210'
}

kill() {
    case "$1" in
        -0) [ "$alive" -eq 1 ] ;;
        -9) force_at_ms="$elapsed_ms"; alive=0 ;;
        *)
            if [ "$exits_on_term" -eq 1 ]; then alive=0; fi
            ;;
    esac
}

usleep() {
    # A missing applet and an installed but failing applet both take the
    # helper's ordinary sleep(1) fallback, with no synthetic wall-clock wait.
    [ "$delay_mode" = available ] || return 127
    assert_equal "$1" 100000 "usleep interval"
    elapsed_ms=$((elapsed_ms + 100))
}

sleep() { elapsed_ms=$((elapsed_ms + $1 * 1000)); }
log_warn() { :; }
log_info() { :; }
rm() { pid_cleanup_calls=$((pid_cleanup_calls + 1)); }
mock_start_dnsmasq() {
    assert_equal "$1" start "init action"
    start_calls=$((start_calls + 1))
    phase=starting
}

for mode in available missing; do
    reset_fixture "$mode"
    alive=1
    stop_dnsmasq || fail "$mode: forced stop failed"
    assert_equal "$force_at_ms" 5000 "$mode: TERM budget before SIGKILL"
    assert_equal "$elapsed_ms" 6000 "$mode: stop budget including existing kill grace"

    reset_fixture "$mode"
    alive=1
    exits_on_term=1
    stop_dnsmasq || fail "$mode: ordinary stop failed"
    assert_equal "$force_at_ms" -1 "$mode: ordinary stop must not force"
    assert_equal "$elapsed_ms" 0 "$mode: ordinary stop must not wait"

    reset_fixture "$mode"
    if restart_dnsmasq; then fail "$mode: missing process reported started"; fi
    assert_equal "$elapsed_ms" 3000 "$mode: start budget"
    assert_equal "$start_calls" 1 "$mode: single start attempt"
    assert_equal "$pid_cleanup_calls" 1 "$mode: existing PID cleanup"

    reset_fixture "$mode"
    start_after_ms=2000
    restart_dnsmasq || fail "$mode: delayed startup was not observed"
    assert_equal "$elapsed_ms" 2000 "$mode: delayed startup"

    reset_fixture "$mode"
    start_after_ms=0
    restart_dnsmasq || fail "$mode: immediate startup was not observed"
    assert_equal "$elapsed_ms" 0 "$mode: immediate startup must not wait"
done

echo "dnsmasq helper timing: 10 cases passed (usleep present/absent, no real waits)"
