#!/bin/sh
# keen-pbr: make sure the Entware SSH listener survived boot ordering.
#
# Seen on a live reboot: the stock Keenetic dropbear (port 4122) came up before
# Entware did, and Entware's S51dropbear decided its own dropbear (port 222)
# was already running. Depending on the init script's vintage the check is by
# pidfile - /opt/var/run lives on the USB drive, survives a reboot, and the
# saved pid was alive because it now belonged to some other process - or by
# process name, which the stock daemon answers to. Either way the WAN forward
# to 127.0.0.1:222 pointed at nothing until the router could be reached some
# other way.
#
# This guard trusts neither a name nor a pidfile. It asks who owns the
# listening socket on the Entware port and compares that process's executable
# with the Entware binary. Only when the socket table was actually read and
# nobody owns the port does it clear a stale pidfile and start the Entware
# init script; when another program owns the port, or the pidfile names a
# live Entware daemon that merely listens elsewhere, it stops and says so. It
# never kills anything.
#
# Exit codes: 0 listener present (found or started), or nothing to guard;
# 1 start did not produce a listener; 2 configuration or socket table
# unusable (nothing touched); 3 the port, or the recorded daemon, belongs to
# something this guard must not fight.
set -u

ROOT=${KEEN_PBR_SSH_GUARD_ROOT:-}
case "$ROOT" in
    ""|/*) ;;
    *)
        echo "KEEN_PBR_SSH_GUARD_ROOT must be an absolute path" >&2
        exit 2
        ;;
esac
PROC=${KEEN_PBR_SSH_GUARD_PROC:-/proc}
PATH=${KEEN_PBR_SSH_GUARD_PATH:-/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin}
export PATH

INIT="${ROOT}/opt/etc/init.d/S51dropbear"
CONF="${ROOT}/opt/etc/config/dropbear.conf"
DROPBEAR="${ROOT}/opt/sbin/dropbear"
PIDFILE="${ROOT}/opt/var/run/dropbear.pid"
# How many times to start, and the first pause between starts (doubled each
# time). A listener that needs more than this is not a boot-ordering victim.
ATTEMPTS=${KEEN_PBR_SSH_GUARD_ATTEMPTS:-3}
BACKOFF=${KEEN_PBR_SSH_GUARD_BACKOFF:-2}
# Seconds to wait for a just-started daemon to bind before judging it.
BIND_WAIT=${KEEN_PBR_SSH_GUARD_BIND_WAIT:-5}
TAG=keen-pbr-ssh-guard

say() {
    echo "$TAG: $*"
    logger -t "$TAG" "$*" 2>/dev/null || true
}

if [ ! -x "$INIT" ] || [ ! -f "$CONF" ] || [ ! -x "$DROPBEAR" ]; then
    say "Entware dropbear is not installed; nothing to guard"
    exit 0
fi

# The conf is Entware's and S51dropbear sources it wholesale; this reads only
# the two values it needs, so a conf that does more than assign cannot make
# the guard do more than read.
PORT=$(sed -n 's/^[[:space:]]*PORT=["'"'"']\{0,1\}\([0-9]\{1,5\}\)["'"'"']\{0,1\}[[:space:]]*$/\1/p' "$CONF" | tail -n 1)
CONF_PIDFILE=$(sed -n 's/^[[:space:]]*PIDFILE=["'"'"']\{0,1\}\([^"'"'"'[:space:]]*\)["'"'"']\{0,1\}[[:space:]]*$/\1/p' "$CONF" | tail -n 1)
case "$PORT" in
    ''|*[!0-9]*)
        say "cannot read PORT from $CONF; nothing to guard"
        exit 2
        ;;
esac
if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
    say "PORT=$PORT in $CONF is not a TCP port"
    exit 2
fi
case "$CONF_PIDFILE" in
    /*) PIDFILE="${ROOT}${CONF_PIDFILE}" ;;
esac

# The socket table, read once per question. Emptiness is trusted only when
# the table was readable: BusyBox netstat that is missing, failing or
# printing nothing must never turn into "nobody listens", because the next
# step after that verdict removes a pidfile.
read_table() {
    TABLE=$(netstat -tlnp 2>/dev/null) || TABLE=
    case "$TABLE" in
        *tcp*|*Proto*) return 0 ;;
    esac
    return 1
}

# Who owns the LISTEN socket on the port, for either address family: the pid,
# or "?" when netstat could not attribute it ("-" in its PID column - the
# socket is real, its owner is unknown, and unknown is not "nobody").
listener_owner() {
    printf '%s\n' "$TABLE" | awk -v suffix=":$PORT" '
        $1 ~ /^tcp/ && $6 == "LISTEN" &&
        substr($4, length($4) - length(suffix) + 1) == suffix {
            split($7, owner, "/")
            if (owner[1] ~ /^[0-9]+$/) print owner[1]; else print "?"
            exit
        }'
}

# True when the pid owns any LISTEN socket at all.
pid_listens_somewhere() {
    printf '%s\n' "$TABLE" | awk -v pid="$1" '
        $1 ~ /^tcp/ && $6 == "LISTEN" && index($7, pid "/") == 1 { found = 1 }
        END { exit found ? 0 : 1 }'
}

pid_cmdline() {
    tr '\0' ' ' < "$PROC/$1/cmdline" 2>/dev/null
}

# True when the process image is the Entware binary. The executable link is
# the authority: it does not depend on how the daemon was invoked (rc.func
# starts it as a bare `dropbear` found on PATH) and survives the binary being
# replaced by an upgrade ("(deleted)"). The cmdline is only a fallback for a
# /proc that does not expose exe.
pid_is_entware_dropbear() {
    exe=$(readlink "$PROC/$1/exe" 2>/dev/null)
    if [ -n "$exe" ]; then
        case "$exe" in
            "$DROPBEAR"|"$DROPBEAR (deleted)") return 0 ;;
        esac
        return 1
    fi
    case "$(pid_cmdline "$1")" in
        "$DROPBEAR"|"$DROPBEAR "*) return 0 ;;
    esac
    return 1
}

# Wait up to BIND_WAIT seconds for an owner to appear; prints it.
await_owner() {
    waited=0
    while :; do
        read_table || return 2
        found=$(listener_owner)
        if [ -n "$found" ]; then
            echo "$found"
            return 0
        fi
        [ "$waited" -lt "$BIND_WAIT" ] || return 1
        sleep 1
        waited=$((waited + 1))
    done
}

describe() {
    if [ "$1" = "?" ]; then
        echo "an unattributed process"
    else
        echo "pid $1 ($(pid_cmdline "$1"))"
    fi
}

if ! read_table; then
    say "the socket table could not be read (netstat); nothing touched"
    exit 2
fi
owner=$(listener_owner)
if [ -n "$owner" ]; then
    if [ "$owner" != "?" ] && pid_is_entware_dropbear "$owner"; then
        say "Entware dropbear (pid $owner) is listening on :$PORT"
        exit 0
    fi
    say "port :$PORT is held by $(describe "$owner"), not by Entware dropbear; leaving it alone"
    exit 3
fi

if [ -f "$PIDFILE" ]; then
    saved=$(cat "$PIDFILE" 2>/dev/null)
    case "$saved" in
        ''|*[!0-9]*)
            say "removing unreadable pidfile $PIDFILE"
            rm -f "$PIDFILE"
            ;;
        *)
            if pid_is_entware_dropbear "$saved"; then
                # A live Entware daemon that does not own the port. Give it
                # the bind window; if it then listens somewhere else, it is
                # a daemon on another port and not this guard's to replace:
                # S51dropbear stops it through this very pidfile.
                owner=$(await_owner)
                waited_rc=$?
                if [ "$waited_rc" -eq 2 ]; then
                    say "the socket table became unreadable while waiting; nothing touched"
                    exit 2
                fi
                if [ "$waited_rc" -eq 0 ] && [ -n "$owner" ] &&
                   [ "$owner" != "?" ] && pid_is_entware_dropbear "$owner"; then
                    say "Entware dropbear (pid $owner) came up on :$PORT"
                    exit 0
                fi
                if pid_listens_somewhere "$saved"; then
                    say "pid $saved from $PIDFILE is an Entware dropbear listening on another port, not :$PORT; leaving it alone"
                    exit 3
                fi
                say "pid $saved from $PIDFILE is an Entware dropbear but listens nowhere; treating the pidfile as stale"
            else
                say "removing stale pidfile $PIDFILE: pid $saved is not Entware dropbear"
            fi
            rm -f "$PIDFILE"
            ;;
    esac
fi

attempt=1
while :; do
    say "starting Entware dropbear on :$PORT (attempt $attempt of $ATTEMPTS)"
    "$INIT" start >/dev/null 2>&1 || true
    owner=$(await_owner)
    waited_rc=$?
    if [ "$waited_rc" -eq 2 ]; then
        say "the socket table became unreadable after starting; cannot verify"
        exit 2
    fi
    if [ "$waited_rc" -eq 0 ] && [ -n "$owner" ]; then
        if [ "$owner" != "?" ] && pid_is_entware_dropbear "$owner"; then
            say "Entware dropbear (pid $owner) now listens on :$PORT"
            exit 0
        fi
        say "port :$PORT was taken by $(describe "$owner") while starting; leaving it alone"
        exit 3
    fi
    [ "$attempt" -lt "$ATTEMPTS" ] || break
    sleep "$BACKOFF"
    BACKOFF=$((BACKOFF * 2))
    attempt=$((attempt + 1))
done
say "Entware dropbear did not come up on :$PORT after $ATTEMPTS attempts"
exit 1
