#!/bin/sh
# Optional, event-driven TCP observation. No daemon, vendor-file edits,
# service control, policy/mark writes, conntrack flushes or global table restore.
# A missing/incompatible integration leaves normal nfqws2 and routing alone.
set -f
umask 077

window_root=${KEEN_PBR_NFQWS_WINDOW_ROOT:-}
window_lib=${KEEN_PBR_NFQWS_WINDOW_LIB:-/opt/usr/lib/keen-pbr}
window_run="$window_root/var/run/keen-pbr-nfqws-window"
window_mode=${1:-apply}
window_family=${2:-all}
case "$window_mode" in apply|remove|status) ;; *) exit 2 ;; esac
case "$window_family" in all|iptables|ip6tables) ;; *) exit 2 ;; esac
if [ -z "$window_root" ]; then
    PATH=/opt/sbin:/opt/bin:/opt/usr/sbin:/opt/usr/bin:/usr/sbin:/usr/bin:/sbin:/bin
fi

# Do not replace Entware's library or export LD_PRELOAD to the service, shell
# hooks or other commands. The adapter is built against libxtables.so.10 and
# is unnecessary on a future iptables ABI. Its init defers to native revision
# 1 support when an Entware update already provides it.
window_compat=
if [ -z "$window_root" ] && [ -f /opt/lib/libxtables.so.10 ] &&
    [ -f "$window_lib/libkeen-pbr-connndmmark.so" ] &&
    [ "$(iptables --version 2>/dev/null)" = 'iptables v1.4.21' ]; then
    window_compat="$window_lib/libkeen-pbr-connndmmark.so"
fi
window_xtables() {
    if [ -n "$window_compat" ]; then
        LD_PRELOAD="$window_compat${LD_PRELOAD:+:$LD_PRELOAD}" "$@"
    else
        "$@"
    fi
}

[ ! -L "$window_run" ] || exit 1
mkdir -p "$window_run" || exit 1
[ -d "$window_run" ] || exit 1
[ -r "$window_lib/portable-stat.sh" ] || exit 1
. "$window_lib/portable-stat.sh"
[ "$(keen_pbr_stat_value %u "$window_run")" = "$(id -u)" ] || exit 1
# This directory holds only this helper's short-lived lock and private input.
chmod 0700 "$window_run" || exit 1
window_work=$(mktemp -d "$window_run/event.XXXXXX") || exit 1
window_locked=0
window_cleanup() {
    if [ "$window_locked" = 1 ] && cmp -s "$window_work/owner" "$window_run/lock"; then
        rm -f "$window_run/lock"
    fi
    rm -f "$window_work/owner" "$window_work/argv" "$window_work/before" "$window_work/plan" "$window_work/after" "$window_work/restore-error"
    rmdir "$window_work" 2>/dev/null
}
trap window_cleanup EXIT
trap 'exit 1' HUP INT TERM
window_self_ticks=$(sed 's/^.*) //' "/proc/$$/stat" | awk '{print $20}')
printf '%s %s\n' "$$" "$window_self_ticks" > "$window_work/owner" || exit 1
# Hard-link publication has no empty PID-file crash window. This is a
# nonblocking lock for this helper only, not the routing lifecycle lease.
[ ! -L "$window_run/lock" ] || exit 1
if ! ln "$window_work/owner" "$window_run/lock" 2>/dev/null; then
    window_previous=$(cat "$window_run/lock" 2>/dev/null)
    read -r window_owner window_owner_ticks window_extra < "$window_run/lock" || exit 0
    case "$window_owner" in ''|0|*[!0-9]*) exit 0 ;; esac
    case "$window_owner_ticks" in ''|*[!0-9]*) exit 0 ;; esac
    [ -z "$window_extra" ] || exit 0
    window_actual_ticks=$(sed 's/^.*) //' "/proc/$window_owner/stat" 2>/dev/null | awk '{print $20}')
    [ "$window_actual_ticks" != "$window_owner_ticks" ] || exit 0
    [ "$(cat "$window_run/lock" 2>/dev/null)" = "$window_previous" ] || exit 0
    rm -f "$window_run/lock"
    ln "$window_work/owner" "$window_run/lock" 2>/dev/null || exit 0
fi
window_locked=1

window_queue=
window_reply=
window_pid=
window_identity=
window_runtime() {
    window_pid=$(cat "$window_root/opt/var/run/nfqws2.pid" 2>/dev/null)
    case "$window_pid" in ''|0|*[!0-9]*) return 1 ;; esac
    window_proc="$window_root/proc/$window_pid"
    [ "$(cat "$window_proc/comm" 2>/dev/null)" = nfqws2 ] || return 1
    window_identity=$(cat "$window_proc/stat" 2>/dev/null) || return 1
    [ -n "$window_identity" ] || return 1
    window_size=$(wc -c < "$window_proc/cmdline" 2>/dev/null) || return 1
    case "$window_size" in ''|*[!0-9]*) return 1 ;; esac
    [ "$window_size" -gt 0 ] && [ "$window_size" -le 262144 ] || return 1
    tr '\000' '\n' < "$window_proc/cmdline" > "$window_work/argv" || return 1
    # Capability is in the running argv, not a pending config edit. Stock
    # circular ignores the advisory kpbr argument; migration keeps it in args.
    grep -Eq '^--lua-desync=circular:.*:kpbr_tcp_window=96(:|$)' "$window_work/argv" || return 1
    grep -Fxq -- '--lua-init=@/opt/var/lib/keen-pbr/nfqws-rotator-telemetry-v1.lua' "$window_work/argv" || return 1
    if grep -Eq '^--lua-desync=circular:.*:kpbr_tcp_reply=postnat_v1(:|$)' "$window_work/argv"; then
        window_reply=postnat_v1
    fi
    window_queue=$(sed -n 's/^--qnum=\([0-9][0-9]*\)$/\1/p' "$window_work/argv")
    case "$window_queue" in ''|*[!0-9]*) return 1 ;; esac
    [ "$window_queue" -le 65535 ] || return 1
    awk -v q="$window_queue" '$1 == q { found=1 } END { exit !found }' \
        "$window_root/proc/net/netfilter/nfnetlink_queue" || return 1
    # Process stat contains changing CPU counters. Compare only starttime.
    window_identity=$(printf '%s\n' "$window_identity" | sed 's/^.*) //' | awk '{print $20}')
    [ -n "$window_identity" ] || return 1
}
window_same_process() {
    [ "$(cat "$window_root/opt/var/run/nfqws2.pid" 2>/dev/null)" = "$window_pid" ] || return 1
    [ "$(sed 's/^.*) //' "$window_root/proc/$window_pid/stat" 2>/dev/null | awk '{print $20}')" = "$window_identity" ]
}
if [ "$window_mode" = apply ] && ! window_runtime; then window_mode=remove; fi

window_result=0
for window_tables in iptables ip6tables; do
    [ "$window_family" = all ] || [ "$window_family" = "$window_tables" ] || continue
    command -v "$window_tables-save" >/dev/null 2>&1 || continue
    command -v "$window_tables-restore" >/dev/null 2>&1 || continue
    window_xtables "$window_tables-save" -t mangle > "$window_work/before" 2>/dev/null || continue
    [ "$(wc -c < "$window_work/before")" -le 1048576 ] || { window_result=1; continue; }
    if [ "$window_mode" = status ]; then
        grep -E 'keen-pbr-sb:nfqws:tcp-(window|reply):v1' "$window_work/before" || true
        continue
    fi
    if [ "$window_mode" = apply ] && ! window_same_process; then window_mode=remove; fi
    awk -v mode="$window_mode" -v queue="$window_queue" -v budget=96 -v reply="$window_reply" \
        -f "$window_lib/nfqws-tcp-window.awk" "$window_work/before" > "$window_work/plan" || { window_result=1; continue; }
    [ -s "$window_work/plan" ] || continue
    if [ "$window_mode" = apply ] && ! window_same_process; then
        # A new nfqws generation owns a possibly different firewall. Leave
        # that event to its own post-start callback rather than apply old rules.
        window_result=1
        continue
    fi
    # Some Keenetic builds ship xt_comment but have no modprobe/autoloader.
    # Load only that installed module for this kernel, only when adding our
    # tagged rules. Never download modules or unload one shared by others.
    if [ "$window_mode" = apply ] &&
        ! grep -qx comment "$window_root/proc/net/ip_tables_matches" 2>/dev/null; then
        window_comment_module="$window_root/lib/modules/$(uname -r)/xt_comment.ko"
        if [ -f "$window_comment_module" ] && command -v insmod >/dev/null 2>&1; then
            insmod "$window_comment_module" >/dev/null 2>&1 || true
        fi
    fi
    # --noflush preserves every vendor/user rule and counter not explicitly
    # named in this tiny transaction. Failure is confined to this extension.
    window_attempt=0
    while :; do
        if [ "$window_mode" = apply ] && ! window_same_process; then
            window_result=1
            break
        fi
        if window_xtables "$window_tables-restore" --noflush < "$window_work/plan" 2> "$window_work/restore-error"; then
            break
        else
            window_rc=$?
        fi
        window_attempt=$((window_attempt + 1))
        # Keenetic uses old xtables without a bounded --wait option. Retry
        # temporary lock/resource contention twice, never wait indefinitely.
        if [ "$window_rc" != 4 ] || [ "$window_attempt" -ge 3 ]; then
            head -c 4096 "$window_work/restore-error" >&2
            window_result=1
            break
        fi
        sleep 1
    done
done
exit "$window_result"
