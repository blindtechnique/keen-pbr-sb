#!/opt/bin/sh

case "$type" in
    iptables|ip6tables) ;;
    *) exit 0 ;;
esac

case "$table" in
    mangle)
        refresh_action=reapply-firewall
        ;;
    nat)
        refresh_action=reapply-nat
        ;;
    *)
        exit 0
        ;;
esac

stopping_runtime_dir=${KEEN_PBR_STOPPING_RUNTIME_DIR:-/var/run/keen-pbr}
stopping_marker=${KEEN_PBR_STOPPING_MARKER:-${stopping_runtime_dir}/stopping}
stopping_pidfile=${KEEN_PBR_PIDFILE:-/opt/var/run/keen-pbr.pid}
stopping_proc_root=${KEEN_PBR_PROC_ROOT:-/proc}

hook_process_startticks() {
    hook_pid=$1
    hook_process_ticks=
    case "$hook_pid" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ -r "$stopping_proc_root/$hook_pid/stat" ] || return 1
    hook_process_ticks=$(awk '{ print $22; exit }' \
        "$stopping_proc_root/$hook_pid/stat" 2>/dev/null) || return 1
    case "$hook_process_ticks" in
        ''|*[!0-9]*|0) return 1 ;;
    esac
    printf '%s\n' "$hook_process_ticks"
}

hook_stopping_marker_authorizes_suppression() {
    [ -d "$stopping_runtime_dir" ] || return 1
    [ ! -L "$stopping_runtime_dir" ] || return 1
    hook_metadata=$(stat -c '%u:%g:%a' \
        "$stopping_runtime_dir" 2>/dev/null) || return 1
    case "$hook_metadata" in
        0:0:700|0:0:750) ;;
        *) return 1 ;;
    esac

    [ -f "$stopping_marker" ] || return 1
    [ ! -L "$stopping_marker" ] || return 1
    hook_metadata=$(stat -c '%u:%g:%a' "$stopping_marker" 2>/dev/null) ||
        return 1
    [ "$hook_metadata" = "0:0:600" ] || return 1
    IFS=' ' read -r hook_magic hook_phase hook_pid hook_startticks \
        hook_controller_pid hook_controller_startticks hook_extra \
        < "$stopping_marker" || return 1
    [ "$hook_magic" = "keen-pbr-stopping-v3" ] || return 1
    [ "$hook_phase" = mutating ] || return 1
    [ -z "$hook_extra" ] || return 1
    case "$hook_pid" in
        ''|*[!0-9]*) return 1 ;;
    esac
    case "$hook_startticks" in
        ''|*[!0-9]*|0) return 1 ;;
    esac
    case "$hook_controller_pid" in
        ''|0|*[!0-9]*) return 1 ;;
    esac
    case "$hook_controller_startticks" in
        ''|0|*[!0-9]*) return 1 ;;
    esac

    # A mutating marker is fail-closed after controller death or daemon exit.
    # If the PID is live, however, its generation and PID-file identity must
    # still match so PID reuse cannot suppress a replacement daemon.
    hook_live_startticks=$(hook_process_startticks "$hook_pid" 2>/dev/null || true)
    if [ -n "$hook_live_startticks" ]; then
        [ "$hook_live_startticks" = "$hook_startticks" ] || return 1
        [ -s "$stopping_pidfile" ] || return 1
        read -r hook_pidfile_pid < "$stopping_pidfile" || return 1
        [ "$hook_pidfile_pid" = "$hook_pid" ] || return 1
    fi
    return 0
}

# Before mutation, the hook persists refresh work behind the stop lease. After
# the atomic mutating boundary, mangle/nat churn belongs to teardown and is
# suppressed even if the stop controller dies.
if hook_stopping_marker_authorizes_suppression; then
    logger -t "keen-pbr" \
        "Ignoring netfilter $table change while keen-pbr is stopping"
    exit 0
fi

init_script=${KEEN_PBR_INIT_SCRIPT:-/opt/etc/init.d/S80keen-pbr}
logger -t "keen-pbr" \
    "Scheduling $refresh_action after netfilter $table change"
"$init_script" "$refresh_action" >/dev/null 2>&1 || exit 0

if [ -f /opt/etc/keen-pbr/hook.sh ]; then
    keen_pbr_hook="netfilter"
    . /opt/etc/keen-pbr/hook.sh
fi

exit 0
