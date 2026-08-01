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

/bin/sh -n "$keenetic_hook"
/bin/sh -n "$keenetic_init"
/bin/sh -n "$rescue_guard"
/bin/sh -n "$openwrt_init"
/bin/sh -n "$openwrt_firewall"
/bin/sh -n "$openwrt_hotplug"

grep -q 'reapply-nat)' "$keenetic_init"
grep -q 'reapply_netfilter_runtime SIGUSR1' "$keenetic_init"
grep -q 'reapply_netfilter_runtime SIGUSR2' "$keenetic_init"
grep -q 'pid_is_keen_pbr "$pid"' "$keenetic_init"
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
