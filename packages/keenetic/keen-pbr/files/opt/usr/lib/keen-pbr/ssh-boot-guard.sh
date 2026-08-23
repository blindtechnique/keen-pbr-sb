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
# listening socket on the Entware port and compares that process's cmdline
# with the Entware binary. Only when nobody owns the port does it clear the
# stale pidfile and start the Entware init script; when another program owns
# the port it stops and says so. It never touches the stock daemon and never
# kills anything.
#
# Exit codes: 0 listener present (found or started); 1 start did not produce a
# listener; 3 the port belongs to something that is not Entware dropbear;
# 2 configuration unusable. "Nothing to guard" (no Entware dropbear) is 0.
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

# The pid that owns a LISTEN socket on the port, for either address family.
# BusyBox netstat -p prints "pid/program" in the last column; only the pid is
# used, since the program name is exactly what this guard refuses to trust.
listener_pid() {
    netstat -tlnp 2>/dev/null | awk -v suffix=":$PORT" '
        $1 ~ /^tcp/ && $6 == "LISTEN" &&
        substr($4, length($4) - length(suffix) + 1) == suffix {
            split($7, owner, "/")
            if (owner[1] ~ /^[0-9]+$/) { print owner[1]; exit }
        }'
}

pid_cmdline() {
    tr '\0' ' ' < "$PROC/$1/cmdline" 2>/dev/null
}

# True when the process image is the Entware binary, whatever its arguments.
pid_is_entware_dropbear() {
    case "$(pid_cmdline "$1")" in
        "$DROPBEAR"|"$DROPBEAR "*) return 0 ;;
    esac
    return 1
}

# Wait up to BIND_WAIT seconds for a listener to appear; prints its pid.
await_listener() {
    waited=0
    while :; do
        found=$(listener_pid)
        if [ -n "$found" ]; then
            echo "$found"
            return 0
        fi
        [ "$waited" -lt "$BIND_WAIT" ] || return 1
        sleep 1
        waited=$((waited + 1))
    done
}

owner=$(listener_pid)
if [ -n "$owner" ]; then
    if pid_is_entware_dropbear "$owner"; then
        say "Entware dropbear (pid $owner) is listening on :$PORT"
        exit 0
    fi
    say "port :$PORT is held by pid $owner ($(pid_cmdline "$owner")), not by Entware dropbear; leaving it alone"
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
                # The recorded process is an Entware dropbear that is not
                # listening: most likely it is still starting. Give it the
                # bind window before deciding it is a leftover session child.
                if owner=$(await_listener) && [ -n "$owner" ] &&
                   pid_is_entware_dropbear "$owner"; then
                    say "Entware dropbear (pid $owner) came up on :$PORT"
                    exit 0
                fi
                say "pid $saved from $PIDFILE is an Entware dropbear but nothing listens on :$PORT; treating the pidfile as stale"
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
    if owner=$(await_listener) && [ -n "$owner" ]; then
        if pid_is_entware_dropbear "$owner"; then
            say "Entware dropbear (pid $owner) now listens on :$PORT"
            exit 0
        fi
        say "port :$PORT was taken by pid $owner ($(pid_cmdline "$owner")) while starting; leaving it alone"
        exit 3
    fi
    [ "$attempt" -lt "$ATTEMPTS" ] || break
    sleep "$BACKOFF"
    BACKOFF=$((BACKOFF * 2))
    attempt=$((attempt + 1))
done
say "Entware dropbear did not come up on :$PORT after $ATTEMPTS attempts"
exit 1
