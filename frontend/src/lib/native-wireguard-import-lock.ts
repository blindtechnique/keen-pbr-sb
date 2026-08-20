import {
  NATIVE_MUTATION_LOCK_STORAGE_KEY,
  readNativeMutationLock,
  subscribeNativeMutationLock,
  type NativeMutationLock,
} from "@/lib/native-mutation-lock"

export type NativeWireGuardImportLockReason =
  | "pending"
  | "recovery_required"
  | "unknown"

// Kept as a compatibility export for focused callers and tests. New code
// should use NATIVE_MUTATION_LOCK_STORAGE_KEY directly.
export const NATIVE_WIREGUARD_IMPORT_LOCK_STORAGE_KEY =
  NATIVE_MUTATION_LOCK_STORAGE_KEY

const importReason = (
  lock: NativeMutationLock | null
): NativeWireGuardImportLockReason | null => {
  if (!lock) return null
  if (lock.state === "pending") return "pending"
  if (lock.state === "recovery_required" && lock.recovery === "import") {
    return "recovery_required"
  }
  return "unknown"
}

/** Compatibility view over the global native-mutation journal. */
export function readNativeWireGuardImportLock(): NativeWireGuardImportLockReason | null {
  return importReason(readNativeMutationLock())
}

export function subscribeNativeWireGuardImportLock(
  listener: (reason: NativeWireGuardImportLockReason | null) => void
): () => void {
  return subscribeNativeMutationLock(
    (lock) => listener(importReason(lock)),
    // The importing component already owns its in-flight state and secret.
    // Do not make its own verified pending write look like an external crash.
    { suppressOwnedPending: true }
  )
}
