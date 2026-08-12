#!/bin/sh
# Shared by S80keen-pbr and S79transport-manager. Sourced, not executed.
#
# Mutual exclusion between service lifecycle actions and package updates. An
# update holds the update lock across opkg, opkg runs prerm and postinst, and
# those stop and start the services. A service script acquiring normally there
# would wait on its own caller, so an inherited lease is honoured instead of
# contended.
#
# Lives in one file because S79 and S80 must not drift: two copies of an
# exclusion rule are two chances to fix only one of them.

LIFECYCLE_LOCK_HELPER="${KEEN_PBR_RESCUE_ROOT:-}/opt/usr/lib/keen-pbr/update-lock.sh"
LIFECYCLE_LOCK_TOKEN=
LIFECYCLE_LOCK_OWNED=0
LIFECYCLE_LOCK_BORROWED=0
LIFECYCLE_LOCK_PARENT_PID=

release_lifecycle_lock() {
    if [ "$LIFECYCLE_LOCK_BORROWED" = "1" ]; then
        # The child temporarily owns the durable record, so a crashed parent
        # cannot release exclusion while this lifecycle mutation is still
        # running. Hand ownership back only to the exact still-live parent;
        # otherwise release our own lease after the mutation has ended.
        if "$LIFECYCLE_LOCK_HELPER" transfer $$ \
                "$LIFECYCLE_LOCK_TOKEN" "$LIFECYCLE_LOCK_PARENT_PID" \
                >/dev/null 2>&1; then
            KEEN_PBR_UPDATE_LOCK_PID=$LIFECYCLE_LOCK_PARENT_PID
            export KEEN_PBR_UPDATE_LOCK_PID
        else
            "$LIFECYCLE_LOCK_HELPER" release $$ \
                "$LIFECYCLE_LOCK_TOKEN" >/dev/null 2>&1 || true
        fi
        LIFECYCLE_LOCK_BORROWED=0
        LIFECYCLE_LOCK_PARENT_PID=
        return 0
    fi
    [ "$LIFECYCLE_LOCK_OWNED" = "1" ] || return 0
    "$LIFECYCLE_LOCK_HELPER" release $$ "$LIFECYCLE_LOCK_TOKEN" \
        >/dev/null 2>&1 || true
    LIFECYCLE_LOCK_OWNED=0
}

enter_lifecycle_lock() {
    # A router without the helper keeps its previous behaviour rather than
    # refusing to start: an absent script is not evidence of a competing
    # update, and failing closed here would strand a boot on a missing file.
    [ -x "$LIFECYCLE_LOCK_HELPER" ] || return 0

    inherited_pid=${KEEN_PBR_UPDATE_LOCK_PID:-}
    inherited_token=${KEEN_PBR_UPDATE_LOCK_TOKEN:-}
    if [ -n "$inherited_pid" ] && [ -n "$inherited_token" ] &&
       "$LIFECYCLE_LOCK_HELPER" held "$inherited_pid" "$inherited_token" \
            >/dev/null 2>&1; then
        # Re-entrant call in the same shell: preserve the ownership mode that
        # the first admission established. Treating it as a new borrow would
        # hide LIFECYCLE_LOCK_OWNED from the EXIT release path.
        [ "$inherited_pid" = "$$" ] && return 0
        # Transfer ownership for the duration of this process. Merely checking
        # the parent's token is insufficient: if that parent crashes, its
        # guardian may release the lock while this script is still changing
        # service state. Nested init invocations repeat the same hand-off and
        # return it on EXIT.
        "$LIFECYCLE_LOCK_HELPER" transfer "$inherited_pid" \
            "$inherited_token" $$ >/dev/null 2>&1 || return 1
        LIFECYCLE_LOCK_TOKEN=$inherited_token
        LIFECYCLE_LOCK_BORROWED=1
        LIFECYCLE_LOCK_PARENT_PID=$inherited_pid
        KEEN_PBR_UPDATE_LOCK_PID=$$
        KEEN_PBR_UPDATE_LOCK_TOKEN=$LIFECYCLE_LOCK_TOKEN
        export KEEN_PBR_UPDATE_LOCK_PID KEEN_PBR_UPDATE_LOCK_TOKEN
        return 0
    fi

    LIFECYCLE_LOCK_TOKEN=$(
        "$LIFECYCLE_LOCK_HELPER" acquire $$ lifecycle 2>/dev/null
    ) || return 1
    LIFECYCLE_LOCK_OWNED=1

    # Published to children on purpose. S79's restart runs "$0" stop, and both
    # service scripts run the rescue guard, all while this lease is held. Those
    # must borrow it; without the export they would contend with their own
    # parent, which is the deadlock this whole mechanism exists to avoid.
    KEEN_PBR_UPDATE_LOCK_PID=$$
    KEEN_PBR_UPDATE_LOCK_TOKEN=$LIFECYCLE_LOCK_TOKEN
    export KEEN_PBR_UPDATE_LOCK_PID KEEN_PBR_UPDATE_LOCK_TOKEN
    return 0
}
