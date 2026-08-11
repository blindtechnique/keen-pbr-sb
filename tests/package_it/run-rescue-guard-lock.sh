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

"$LOCK_UNDER_ROOT" release "$OWNER_PID" "$TOKEN" ||
    fail "could not release the standing owner's lease"

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
