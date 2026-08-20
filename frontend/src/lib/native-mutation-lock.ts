import {
  safeStorageGet,
  safeStorageMatches,
  safeStorageSet,
} from "@/lib/safe-storage"

export type NativeMutationOperation =
  | "import"
  | "delete"
  | "import_recovery"
  | "delete_recovery"

export type NativeMutationRecoveryKind = "import" | "delete"

export type NativeMutationLock =
  | Readonly<{
      version: 1
      state: "pending"
      operation: NativeMutationOperation
      token: string
    }>
  | Readonly<{
      version: 1
      state: "recovery_required"
      recovery: NativeMutationRecoveryKind
    }>
  | Readonly<{
      version: 1
      state: "unknown"
      operation: NativeMutationOperation
    }>

declare const nativeMutationPendingTokenBrand: unique symbol
export type NativeMutationPendingToken = string & {
  readonly [nativeMutationPendingTokenBrand]: true
}

export const NATIVE_MUTATION_LOCK_STORAGE_KEY =
  "keen-pbr.native-mutation-lock.v1"
const LEGACY_IMPORT_LOCK_STORAGE_KEY = "keen-pbr.native-import-write-lock.v2"
const LEGACY_IMPORT_SESSION_KEY = "keen-pbr.native-import-write-lock.v1"

let volatileLock: NativeMutationLock | null = null
const activePendingTokens = new Set<string>()

const localStorageFactory = () => window.localStorage

const isOperation = (value: unknown): value is NativeMutationOperation =>
  value === "import" ||
  value === "delete" ||
  value === "import_recovery" ||
  value === "delete_recovery"

const isRecoveryKind = (value: unknown): value is NativeMutationRecoveryKind =>
  value === "import" || value === "delete"

const parseLock = (serialized: string | null): NativeMutationLock | null => {
  if (serialized === null) return null
  try {
    const value = JSON.parse(serialized) as Record<string, unknown>
    if (!value || Array.isArray(value) || value.version !== 1) return null
    if (
      value.state === "pending" &&
      isOperation(value.operation) &&
      typeof value.token === "string" &&
      /^[0-9a-f]{32}$/.test(value.token) &&
      Object.keys(value).every((key) =>
        ["version", "state", "operation", "token"].includes(key)
      )
    ) {
      return value as NativeMutationLock
    }
    if (
      value.state === "recovery_required" &&
      isRecoveryKind(value.recovery) &&
      Object.keys(value).every((key) =>
        ["version", "state", "recovery"].includes(key)
      )
    ) {
      return value as NativeMutationLock
    }
    if (
      value.state === "unknown" &&
      isOperation(value.operation) &&
      Object.keys(value).every((key) =>
        ["version", "state", "operation"].includes(key)
      )
    ) {
      return value as NativeMutationLock
    }
  } catch {
    // Corrupt durable state is converted to an opaque lock below.
  }
  return null
}

const serializeLock = (lock: NativeMutationLock): string => JSON.stringify(lock)

const persistLock = (lock: NativeMutationLock): boolean => {
  volatileLock = lock
  if (typeof window === "undefined") return false
  return safeStorageSet(
    localStorageFactory,
    NATIVE_MUTATION_LOCK_STORAGE_KEY,
    serializeLock(lock)
  )
}

const corruptLock = (): NativeMutationLock => ({
  version: 1,
  state: "unknown",
  operation: "import",
})

const migrateLegacyImportLock = (): NativeMutationLock | null => {
  if (typeof window === "undefined") return null
  const legacy =
    safeStorageGet(localStorageFactory, LEGACY_IMPORT_LOCK_STORAGE_KEY) ??
    safeStorageGet(() => window.sessionStorage, LEGACY_IMPORT_SESSION_KEY)
  if (legacy === null) return null

  const migrated: NativeMutationLock =
    legacy === "recovery_required"
      ? { version: 1, state: "recovery_required", recovery: "import" }
      : { version: 1, state: "unknown", operation: "import" }
  if (persistLock(migrated)) {
    try {
      window.localStorage.removeItem(LEGACY_IMPORT_LOCK_STORAGE_KEY)
      window.sessionStorage.removeItem(LEGACY_IMPORT_SESSION_KEY)
    } catch {
      // The new durable marker is already authoritative. A blocked legacy
      // cleanup must not weaken it or reopen the write path.
    }
  }
  return migrated
}

/** Reads only a redacted, bounded cross-tab mutation journal. */
export function readNativeMutationLock(): NativeMutationLock | null {
  if (typeof window === "undefined") return volatileLock

  const serialized = safeStorageGet(
    localStorageFactory,
    NATIVE_MUTATION_LOCK_STORAGE_KEY
  )
  if (serialized !== null) {
    const parsed = parseLock(serialized)
    if (parsed) {
      volatileLock = parsed
      return parsed
    }
    const locked = corruptLock()
    persistLock(locked)
    return locked
  }

  const migrated = migrateLegacyImportLock()
  if (migrated) return migrated

  // A mounted caller keeps its conservative process-local view if persistent
  // storage becomes unreadable. A fresh page starts from durable truth.
  return volatileLock
}

const newToken = (): NativeMutationPendingToken => {
  const bytes = new Uint8Array(16)
  try {
    globalThis.crypto.getRandomValues(bytes)
    return Array.from(bytes, (value) =>
      value.toString(16).padStart(2, "0")
    ).join("") as NativeMutationPendingToken
  } catch {
    return Array.from({ length: 32 }, () =>
      Math.floor(Math.random() * 16).toString(16)
    ).join("") as NativeMutationPendingToken
  } finally {
    bytes.fill(0)
  }
}

const recoveryForOperation = (
  operation: NativeMutationOperation
): NativeMutationRecoveryKind =>
  operation === "import" || operation === "import_recovery"
    ? "import"
    : "delete"

const mayReplaceForRecovery = (
  current: NativeMutationLock | null,
  operation: NativeMutationOperation
): boolean => {
  if (operation !== "import_recovery" && operation !== "delete_recovery") {
    return current === null
  }
  if (current === null) return true
  const recovery = recoveryForOperation(operation)
  if (current.state === "pending") {
    return (
      recoveryForOperation(current.operation) === recovery &&
      !activePendingTokens.has(current.token)
    )
  }
  if (current.state === "recovery_required")
    return current.recovery === recovery
  if (current.state === "unknown") {
    return recoveryForOperation(current.operation) === recovery
  }
  return false
}

/**
 * Persists the pending marker before the first request. Recovery operations
 * may replace only an uncertainty/recovery marker from their own journal.
 */
export function beginNativeMutationPending(
  operation: NativeMutationOperation
): NativeMutationPendingToken | null {
  if (!mayReplaceForRecovery(readNativeMutationLock(), operation)) return null
  const token = newToken()
  const pending: NativeMutationLock = {
    version: 1,
    state: "pending",
    operation,
    token,
  }
  if (!persistLock(pending)) {
    volatileLock = { version: 1, state: "unknown", operation }
    return null
  }

  // Detect a competing writer before returning authority to send. This is a
  // bounded best-effort CAS over localStorage; the server remains final and
  // independently serializes every native mutation.
  const observed = readNativeMutationLock()
  if (
    observed?.state !== "pending" ||
    observed.token !== token ||
    observed.operation !== operation
  ) {
    return null
  }
  activePendingTokens.add(token)
  return token
}

/** True only while this JavaScript process still owns the pending request. */
export function nativeMutationPendingIsActiveInThisProcess(
  lock: NativeMutationLock | null
): boolean {
  return lock?.state === "pending" && activePendingTokens.has(lock.token)
}

/** Clears only the exact pending request that received a trusted result. */
export function clearNativeMutationPending(
  token: NativeMutationPendingToken
): boolean {
  if (typeof window === "undefined") {
    if (volatileLock?.state !== "pending" || volatileLock.token !== token) {
      return false
    }
    activePendingTokens.delete(token)
    volatileLock = null
    return true
  }

  try {
    const current = parseLock(
      window.localStorage.getItem(NATIVE_MUTATION_LOCK_STORAGE_KEY)
    )
    if (current?.state !== "pending" || current.token !== token) return false
    window.localStorage.removeItem(NATIVE_MUTATION_LOCK_STORAGE_KEY)
    activePendingTokens.delete(token)
    if (volatileLock?.state === "pending" && volatileLock.token === token) {
      volatileLock = null
    }
    return true
  } catch {
    return false
  }
}

export function latchNativeMutationUnknown(
  operation: NativeMutationOperation
): NativeMutationLock {
  if (volatileLock?.state === "pending") {
    activePendingTokens.delete(volatileLock.token)
  }
  const lock: NativeMutationLock = { version: 1, state: "unknown", operation }
  persistLock(lock)
  return lock
}

export function latchNativeMutationRecovery(
  recovery: NativeMutationRecoveryKind
): NativeMutationLock {
  if (volatileLock?.state === "pending") {
    activePendingTokens.delete(volatileLock.token)
  }
  const lock: NativeMutationLock = {
    version: 1,
    state: "recovery_required",
    recovery,
  }
  persistLock(lock)
  return lock
}

/** Delivers both new locks and exact clears from another tab. */
export function subscribeNativeMutationLock(
  listener: (lock: NativeMutationLock | null) => void
): () => void {
  if (typeof window === "undefined") return () => undefined

  const onStorage = (event: StorageEvent) => {
    if (
      event.key !== NATIVE_MUTATION_LOCK_STORAGE_KEY ||
      !safeStorageMatches(localStorageFactory, event.storageArea)
    ) {
      return
    }
    if (event.newValue === null) {
      volatileLock = null
      listener(null)
      return
    }
    const lock = parseLock(event.newValue) ?? corruptLock()
    volatileLock = lock
    listener(lock)
  }
  window.addEventListener("storage", onStorage)
  return () => window.removeEventListener("storage", onStorage)
}
