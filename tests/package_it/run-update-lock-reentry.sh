#!/bin/sh

set -eu

[ "${KEEN_PBR_PACKAGE_IT_CONTAINER:-0}" = "1" ] || {
    echo "This test must run inside its disposable package-test container" >&2
    exit 2
}

SOURCE_ROOT=${1:-/workspace}
LOCK="$SOURCE_ROOT/packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/update-lock.sh"

export KEEN_PBR_RESCUE_ROOT=/tmp/reentry-root
rm -rf "$KEEN_PBR_RESCUE_ROOT"
mkdir -p "$KEEN_PBR_RESCUE_ROOT/opt/var/run" \
    "$KEEN_PBR_RESCUE_ROOT/opt/var/lib/keen-pbr/rescue" \
    "$KEEN_PBR_RESCUE_ROOT/opt/usr/lib/keen-pbr"
chmod 700 "$KEEN_PBR_RESCUE_ROOT/opt/var/lib/keen-pbr/rescue"
cp "$SOURCE_ROOT/packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/portable-stat.sh" \
    "$KEEN_PBR_RESCUE_ROOT/opt/usr/lib/keen-pbr/portable-stat.sh"

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

# A long-lived owner, standing in for the update transaction that holds the
# lock across opkg. Its PID must stay alive: ownership is verified against the
# PID's start time, not merely its number.
sleep 300 &
OWNER_PID=$!
trap 'kill "$OWNER_PID" 2>/dev/null || true' EXIT

TOKEN=$("$LOCK" acquire "$OWNER_PID" update) ||
    fail "could not acquire the lock for the standing owner"

"$LOCK" held "$OWNER_PID" "$TOKEN" ||
    fail "the lock is not reported as held by the owner that took it"

# The defect this guards: acquire is not reentrant, so a lifecycle step running
# inside the transaction that already holds the lock is refused as a contender.
# Left that way, a service script started from postinst waits on its own caller.
set +e
"$LOCK" acquire "$OWNER_PID" update >/dev/null 2>&1
acquire_status=$?
set -e
[ "$acquire_status" -ne 0 ] ||
    fail "acquire unexpectedly succeeded while the lock was held"

# Re-entry with the lease actually held must succeed and say it borrowed.
entered=$(printf '' | "$LOCK" enter update "$OWNER_PID" "$TOKEN") ||
    fail "enter refused a lease that is genuinely held by the caller"
case "$entered" in
    "$OWNER_PID $TOKEN "*" borrowed") ;;
    *) fail "enter did not report a borrowed lease: $entered" ;;
esac

# Borrowing must not release. The transaction is still in flight, and a
# lifecycle step ending is not the transaction ending.
"$LOCK" held "$OWNER_PID" "$TOKEN" ||
    fail "the owner lost its lease after a borrowed entry returned"

# A token that is not the held one must not be able to borrow. Otherwise any
# caller could claim re-entry and walk straight through mutual exclusion.
set +e
printf '' | "$LOCK" enter update "$OWNER_PID" "update.999.999.1" >/dev/null 2>&1
forged_status=$?
set -e
[ "$forged_status" -ne 0 ] ||
    fail "enter accepted a token the lock does not hold"

# Same for a stranger presenting the real token under the wrong owner.
set +e
printf '' | "$LOCK" enter update 1 "$TOKEN" >/dev/null 2>&1
wrong_owner_status=$?
set -e
[ "$wrong_owner_status" -ne 0 ] ||
    fail "enter accepted the right token under the wrong owner"

"$LOCK" release "$OWNER_PID" "$TOKEN" ||
    fail "could not release the standing owner's lease"

# With nothing held, enter must take the lock itself and say it owns it, so a
# service started outside any transaction is still mutually excluded.
owned=$(printf '' | "$LOCK" enter lifecycle) ||
    fail "enter could not acquire an unheld lock"
case "$owned" in
    *" owned") ;;
    *) fail "enter did not report an owned lease: $owned" ;;
esac

# And that lease was released at EOF, or the next caller would be locked out
# by a guardian that has already exited.
owned_again=$(printf '' | "$LOCK" enter lifecycle) ||
    fail "enter did not release its own lease at EOF"
case "$owned_again" in
    *" owned") ;;
    *) fail "second enter did not report an owned lease: $owned_again" ;;
esac

# `guard` keeps its three-field output: existing callers parse it positionally
# and must not start seeing a fourth field.
guarded=$(printf '' | "$LOCK" guard lifecycle) ||
    fail "guard could not acquire an unheld lock"
set -- $guarded
[ "$#" -eq 3 ] ||
    fail "guard output gained a field, breaking its existing callers: $guarded"

echo "update-lock re-entry contract: OK"
