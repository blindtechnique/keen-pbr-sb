import {
  NATIVE_MUTATION_LOCK_STORAGE_KEY,
  beginNativeMutationPending,
  clearNativeMutationPending,
  latchNativeMutationRecovery,
  latchNativeMutationUnknown,
  readNativeMutationLock,
  subscribeNativeMutationLock,
  type NativeMutationPendingToken,
} from "@/lib/native-mutation-lock"

export type NativeWireGuardImportLockReason =
  | "pending"
  | "recovery_required"
  | "unknown"

export type NativeWireGuardImportPendingToken = NativeMutationPendingToken

// Kept as a compatibility export for focused callers and tests. New code
// should use NATIVE_MUTATION_LOCK_STORAGE_KEY directly.
export const NATIVE_WIREGUARD_IMPORT_LOCK_STORAGE_KEY =
  NATIVE_MUTATION_LOCK_STORAGE_KEY

const importReason = (): NativeWireGuardImportLockReason | null => {
  const lock = readNativeMutationLock()
  if (!lock) return null
  if (lock.state === "pending") return "pending"
  if (lock.state === "recovery_required" && lock.recovery === "import") {
    return "recovery_required"
  }
  return "unknown"
}

/** Compatibility view over the global native-mutation journal. */
export function readNativeWireGuardImportLock(): NativeWireGuardImportLockReason | null {
  return importReason()
}

export function beginNativeWireGuardImportPending(): NativeWireGuardImportPendingToken | null {
  return beginNativeMutationPending("import")
}

export function clearNativeWireGuardImportPending(
  token: NativeWireGuardImportPendingToken
): boolean {
  return clearNativeMutationPending(token)
}

export function latchNativeWireGuardImportLock(
  reason: Exclude<NativeWireGuardImportLockReason, "pending">
): NativeWireGuardImportLockReason {
  if (reason === "recovery_required") {
    latchNativeMutationRecovery("import")
  } else {
    latchNativeMutationUnknown("import")
  }
  return reason
}

export function subscribeNativeWireGuardImportLock(
  listener: (reason: NativeWireGuardImportLockReason) => void
): () => void {
  return subscribeNativeMutationLock((lock) => {
    if (!lock) return
    listener(importReason() ?? "unknown")
  })
}
