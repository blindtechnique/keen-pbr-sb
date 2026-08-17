// Why the backend says a byte-exact package rollback is impossible, mapped to
// the text an operator reads.
//
// This lives in its own module so the mapping can be checked against the
// backend enum by a test. A missing entry degrades silently - the panel simply
// stops explaining itself - and a silent degradation in the one place that
// tells an operator there is nothing to roll back to is worth a gate.

// Wire values of PackageRollbackState in src/update/rollback_availability.cpp.
// `available` is deliberately absent: it is not a reason for anything.
export const packageRollbackReasonKeys: Record<string, string> = {
  recovery_pending: "rollbackReasonRecoveryPending",
  recovery_unknown: "rollbackReasonRecoveryUnknown",
  helper_missing: "rollbackReasonHelperMissing",
  never_captured: "rollbackReasonNeverCaptured",
  package_unverified: "rollbackReasonPackageUnverified",
  snapshot_unverified: "rollbackReasonSnapshotUnverified",
}

// The i18n leaf for a state, or null when the page does not recognise it.
//
// Returning null rather than a guess matters: a page older than the backend it
// talks to must state only what it knows, never invent an explanation for a
// state it has never heard of.
export function packageRollbackReasonKey(state?: string): string | null {
  if (!state) return null
  return packageRollbackReasonKeys[state] ?? null
}
