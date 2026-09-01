#!/bin/sh

set -eu

[ "${KEEN_PBR_PACKAGE_IT_CONTAINER:-0}" = "1" ] || {
    echo "This test must run inside its disposable package-test container" >&2
    exit 2
}

SOURCE_ROOT=${1:-/workspace}
FILES="$SOURCE_ROOT/packages/keenetic/keen-pbr/files"
GUARD="$FILES/opt/usr/lib/keen-pbr/rescue-startup-guard.sh"
LOCK="$FILES/opt/usr/lib/keen-pbr/update-lock.sh"
LIFECYCLE_LOCK="$FILES/opt/usr/lib/keen-pbr/lifecycle-lock.sh"

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

export KEEN_PBR_RESCUE_ROOT=/tmp/guard-root
rm -rf "$KEEN_PBR_RESCUE_ROOT"
RESCUE="$KEEN_PBR_RESCUE_ROOT/opt/var/lib/keen-pbr/rescue"
mkdir -p "$RESCUE" "$KEEN_PBR_RESCUE_ROOT/opt/var/run" \
    "$KEEN_PBR_RESCUE_ROOT/opt/usr/lib/keen-pbr" \
    "$KEEN_PBR_RESCUE_ROOT/opt/usr/bin"
chmod 700 "$RESCUE"
cp "$FILES/opt/usr/lib/keen-pbr/portable-stat.sh" \
    "$KEEN_PBR_RESCUE_ROOT/opt/usr/lib/keen-pbr/portable-stat.sh"
cp "$LOCK" "$KEEN_PBR_RESCUE_ROOT/opt/usr/lib/keen-pbr/update-lock.sh"
chmod 0755 "$KEEN_PBR_RESCUE_ROOT/opt/usr/lib/keen-pbr/update-lock.sh"
LOCK_UNDER_ROOT="$KEEN_PBR_RESCUE_ROOT/opt/usr/lib/keen-pbr/update-lock.sh"

# A pending package-recovery marker is what drives the guard into its
# recover-startup branch, which is one of the two mutating paths.
: > "$RESCUE/pending"
chmod 0600 "$RESCUE/pending"

# The rescue helper that branch would call. It must not run while a foreign
# transaction owns the lock, so this records whether it was reached.
RAN_MARKER="$KEEN_PBR_RESCUE_ROOT/recover-startup-ran"
cat > "$RESCUE/rescue-update.sh" <<'HELPER'
#!/bin/sh
: > "$KEEN_PBR_RESCUE_ROOT/recover-startup-ran"
rm -f "$KEEN_PBR_RESCUE_ROOT/opt/var/lib/keen-pbr/rescue/pending"
exit 0
HELPER
chmod 0755 "$RESCUE/rescue-update.sh"

# A live owner standing in for an update transaction. Ownership is verified
# against the PID's start time, so it has to actually exist.
sleep 300 &
OWNER_PID=$!
trap 'kill "$OWNER_PID" 2>/dev/null || true' EXIT

TOKEN=$("$LOCK_UNDER_ROOT" acquire "$OWNER_PID" update) ||
    fail "could not acquire the lock for the standing owner"

set +e
sh "$GUARD" start >/dev/null 2>&1
blocked_status=$?
set -e
[ "$blocked_status" -ne 0 ] ||
    fail "the guard ran recovery while another transaction held the lock"
[ ! -e "$RAN_MARKER" ] ||
    fail "recovery was executed under a foreign lock"
[ -f "$RESCUE/pending" ] ||
    fail "the pending marker was consumed under a foreign lock"

# Presented with the lease that is actually held, the guard must proceed: this
# is the S79/S80/postinst path, where the caller already owns the exclusion.
set +e
KEEN_PBR_UPDATE_LOCK_PID="$OWNER_PID" KEEN_PBR_UPDATE_LOCK_TOKEN="$TOKEN" \
    sh "$GUARD" start >/dev/null 2>&1
borrowed_status=$?
set -e
[ "$borrowed_status" -eq 0 ] ||
    fail "the guard refused to recover under an inherited lease: $borrowed_status"
[ -e "$RAN_MARKER" ] ||
    fail "recovery did not run under an inherited lease"

# Borrowing must not release: the transaction is still in flight.
"$LOCK_UNDER_ROOT" held "$OWNER_PID" "$TOKEN" ||
    fail "the owner lost its lease after the guard borrowed it"

# A generic rescue-transaction environment must not bypass package UNKNOWN.
# The explicit recover-pending capability is accepted only together with the
# exact inherited update-lock generation that issued it.
: > "$RESCUE/UNKNOWN"
chmod 0600 "$RESCUE/UNKNOWN"
set +e
KEEN_PBR_RESCUE_TRANSACTION=1 \
KEEN_PBR_PACKAGE_UNKNOWN_RECOVERY=recover-pending-v1 \
    sh "$GUARD" start >/dev/null 2>&1
unlocked_unknown_status=$?
set -e
[ "$unlocked_unknown_status" -ne 0 ] ||
    fail "package UNKNOWN bypassed startup without the locked recovery owner"
[ -f "$RESCUE/UNKNOWN" ] ||
    fail "an unauthorized UNKNOWN check consumed the marker"

KEEN_PBR_RESCUE_TRANSACTION=1 \
KEEN_PBR_PACKAGE_UNKNOWN_RECOVERY=recover-pending-v1 \
KEEN_PBR_UPDATE_LOCK_PID="$OWNER_PID" \
KEEN_PBR_UPDATE_LOCK_TOKEN="$TOKEN" \
    sh "$GUARD" start >/dev/null 2>&1 ||
    fail "locked explicit pending recovery could not cross package UNKNOWN"
[ -f "$RESCUE/UNKNOWN" ] ||
    fail "startup guard consumed package UNKNOWN before recovery completed"
rm -f "$RESCUE/UNKNOWN"

# A lifecycle child must become the authoritative owner while it mutates.
# Otherwise a daemon crash could make its guardian release exclusion while
# the already-forked S79/S80 child continues. The EXIT path hands ownership
# back to the still-live parent.
BORROW_READY="$KEEN_PBR_RESCUE_ROOT/borrow-ready"
BORROW_RELEASE="$KEEN_PBR_RESCUE_ROOT/borrow-release"
KEEN_PBR_UPDATE_LOCK_PID="$OWNER_PID" \
KEEN_PBR_UPDATE_LOCK_TOKEN="$TOKEN" \
    sh -c '
        set -eu
        . "$1"
        trap release_lifecycle_lock EXIT
        enter_lifecycle_lock
        printf "%s\n" "$$" > "$2"
        while [ ! -e "$3" ]; do sleep 1; done
    ' sh "$LIFECYCLE_LOCK" "$BORROW_READY" "$BORROW_RELEASE" &
BORROW_PID=$!
borrow_wait=0
while [ ! -s "$BORROW_READY" ] && [ "$borrow_wait" -lt 5 ]; do
    sleep 1
    borrow_wait=$((borrow_wait + 1))
done
[ -s "$BORROW_READY" ] || fail "lifecycle borrower did not publish readiness"
[ "$(cat "$BORROW_READY")" = "$BORROW_PID" ] ||
    fail "lifecycle borrower PID is not exact"
[ "$("$LOCK_UNDER_ROOT" owner)" = "$BORROW_PID" ] ||
    fail "lifecycle child did not take authoritative ownership"
: > "$BORROW_RELEASE"
wait "$BORROW_PID" || fail "lifecycle borrower failed"
"$LOCK_UNDER_ROOT" held "$OWNER_PID" "$TOKEN" ||
    fail "lifecycle child did not return ownership to its live parent"

"$LOCK_UNDER_ROOT" release "$OWNER_PID" "$TOKEN" ||
    fail "could not release the standing owner's lease"

# SIGKILL cannot run the borrower's EXIT hand-off. In that case the parent
# must not appear to own the token: its C++ caller is required to verify the
# lease before any rollback write, while a later controller may reap the
# exact dead-child record and acquire a new transaction.
sleep 300 &
KILLED_PARENT_PID=$!
KILLED_TOKEN=$(
    "$LOCK_UNDER_ROOT" acquire "$KILLED_PARENT_PID" update
) || fail "could not acquire the lock for killed-borrower coverage"
KILLED_READY="$KEEN_PBR_RESCUE_ROOT/killed-borrow-ready"
KEEN_PBR_UPDATE_LOCK_PID="$KILLED_PARENT_PID" \
KEEN_PBR_UPDATE_LOCK_TOKEN="$KILLED_TOKEN" \
    sh -c '
        set -eu
        . "$1"
        trap release_lifecycle_lock EXIT
        enter_lifecycle_lock
        printf "%s\n" "$$" > "$2"
        while :; do sleep 1; done
    ' sh "$LIFECYCLE_LOCK" "$KILLED_READY" &
KILLED_BORROW_PID=$!
killed_wait=0
while [ ! -s "$KILLED_READY" ] && [ "$killed_wait" -lt 5 ]; do
    sleep 1
    killed_wait=$((killed_wait + 1))
done
[ -s "$KILLED_READY" ] || fail "killed borrower did not publish readiness"
[ "$("$LOCK_UNDER_ROOT" owner)" = "$KILLED_BORROW_PID" ] ||
    fail "killed borrower did not take authoritative ownership"
kill -9 "$KILLED_BORROW_PID" 2>/dev/null || true
wait "$KILLED_BORROW_PID" 2>/dev/null || true
if "$LOCK_UNDER_ROOT" held "$KILLED_PARENT_PID" "$KILLED_TOKEN"; then
    fail "parent falsely regained a lease after borrower SIGKILL"
fi
sleep 300 &
RECLAIM_OWNER_PID=$!
RECLAIM_TOKEN=$(
    "$LOCK_UNDER_ROOT" acquire "$RECLAIM_OWNER_PID" update
) || fail "dead borrower record could not be reaped by a new controller"
"$LOCK_UNDER_ROOT" release "$RECLAIM_OWNER_PID" "$RECLAIM_TOKEN" ||
    fail "could not release the reclaimed lifecycle lease"
kill "$RECLAIM_OWNER_PID" "$KILLED_PARENT_PID" 2>/dev/null || true

# Inspection must stay available whatever the lock says. With nothing pending
# the guard has nothing to mutate and must simply agree that startup may
# proceed, even while a foreign transaction holds the lock.
rm -f "$RAN_MARKER"
sleep 300 &
SECOND_OWNER=$!
SECOND_TOKEN=$("$LOCK_UNDER_ROOT" acquire "$SECOND_OWNER" update) ||
    fail "could not acquire the lock for the second owner"
set +e
sh "$GUARD" start >/dev/null 2>&1
clean_status=$?
set -e
"$LOCK_UNDER_ROOT" release "$SECOND_OWNER" "$SECOND_TOKEN" || true
kill "$SECOND_OWNER" 2>/dev/null || true
[ "$clean_status" -eq 0 ] ||
    fail "the guard refused a clean system merely because a lock was held: $clean_status"

echo "rescue guard lock contract: OK"
