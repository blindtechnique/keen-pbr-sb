import {
  safeStorageGet,
  safeStorageMatches,
  safeStorageSet,
} from "@/lib/safe-storage"

export type NativeWireGuardImportLockReason =
  | "pending"
  | "recovery_required"
  | "unknown"

declare const nativeWireGuardImportPendingTokenBrand: unique symbol
export type NativeWireGuardImportPendingToken = string & {
  readonly [nativeWireGuardImportPendingTokenBrand]: true
}

export const NATIVE_WIREGUARD_IMPORT_LOCK_STORAGE_KEY =
  "keen-pbr.native-import-write-lock.v2"
const LEGACY_SESSION_STORAGE_KEY = "keen-pbr.native-import-write-lock.v1"
const PENDING_PREFIX = "pending:"
let volatileValue: string | null = null

const durableReason = (
  value: string | null
): Exclude<NativeWireGuardImportLockReason, "pending"> | null =>
  value === "recovery_required" || value === "unknown" ? value : null

const pendingTokenFromValue = (
  value: string | null
): NativeWireGuardImportPendingToken | null =>
  value?.startsWith(PENDING_PREFIX) && value.length > PENDING_PREFIX.length
    ? (value.slice(PENDING_PREFIX.length) as NativeWireGuardImportPendingToken)
    : null

const reasonFromValue = (
  value: string | null
): NativeWireGuardImportLockReason | null =>
  durableReason(value) ?? (pendingTokenFromValue(value) ? "pending" : null)

const localStorageFactory = () => window.localStorage

const removeLocalValue = (expected: string): boolean => {
  if (typeof window === "undefined") return volatileValue === expected
  try {
    const stored = window.localStorage.getItem(
      NATIVE_WIREGUARD_IMPORT_LOCK_STORAGE_KEY
    )
    if (stored === null && volatileValue === expected) return true
    if (stored !== expected) return false
    window.localStorage.removeItem(NATIVE_WIREGUARD_IMPORT_LOCK_STORAGE_KEY)
    return true
  } catch {
    return volatileValue === expected
  }
}

const storeValue = (value: string): boolean => {
  volatileValue = value
  if (typeof window === "undefined") return false
  return safeStorageSet(
    localStorageFactory,
    NATIVE_WIREGUARD_IMPORT_LOCK_STORAGE_KEY,
    value
  )
}

const readValue = (): string | null => {
  if (typeof window === "undefined") return volatileValue

  const stored = safeStorageGet(
    localStorageFactory,
    NATIVE_WIREGUARD_IMPORT_LOCK_STORAGE_KEY
  )
  if (stored !== null) {
    if (reasonFromValue(stored)) {
      volatileValue = stored
      return stored
    }
    // A malformed durable marker must fail closed rather than silently
    // reopening a one-shot write after storage corruption or version skew.
    storeValue("unknown")
    return "unknown"
  }

  const legacy = safeStorageGet(
    () => window.sessionStorage,
    LEGACY_SESSION_STORAGE_KEY
  )
  const migrated = durableReason(legacy)
  if (migrated) {
    storeValue(migrated)
    return migrated
  }

  // If persistent storage became unavailable or another tab cleared its own
  // completed pending token, keep this mounted reader conservatively locked.
  // A fresh page load re-reads the durable source of truth.
  return volatileValue
}

const newPendingToken = (): NativeWireGuardImportPendingToken => {
  const bytes = new Uint8Array(16)
  try {
    globalThis.crypto.getRandomValues(bytes)
    return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join(
      ""
    ) as NativeWireGuardImportPendingToken
  } catch {
    return `${Date.now().toString(16)}-${Math.random().toString(16).slice(2)}` as NativeWireGuardImportPendingToken
  } finally {
    bytes.fill(0)
  }
}

/** Reads only a redacted cross-tab write-lock state. */
export function readNativeWireGuardImportLock(): NativeWireGuardImportLockReason | null {
  return reasonFromValue(readValue())
}

/**
 * Persists a redacted pending token before the one-shot secret leaves its
 * vault. A crash, reload, source-mode switch or component unmount therefore
 * fails closed before a result can be lost. The token contains no interface,
 * transaction or secret material.
 */
export function beginNativeWireGuardImportPending(): NativeWireGuardImportPendingToken | null {
  if (readNativeWireGuardImportLock() !== null) return null
  const token = newPendingToken()
  if (!storeValue(`${PENDING_PREFIX}${token}`)) {
    // A volatile marker cannot close the crash/reload window. Refuse to open
    // the one-shot vault and keep this page fail-closed instead.
    volatileValue = "unknown"
    return null
  }
  return token
}

/**
 * Clears only the exact pending operation that produced a strictly trusted
 * terminal result (or proved that takeOnce failed before fetch). Unknown and
 * recovery-required locks have no ordinary UI clear.
 */
export function clearNativeWireGuardImportPending(
  token: NativeWireGuardImportPendingToken
): boolean {
  const expected = `${PENDING_PREFIX}${token}`
  if (!removeLocalValue(expected)) return false
  if (volatileValue === expected) volatileValue = null
  return true
}

/** Promotes pending/empty state to a durable no-retry lock. */
export function latchNativeWireGuardImportLock(
  reason: Exclude<NativeWireGuardImportLockReason, "pending">
): NativeWireGuardImportLockReason {
  const current = readNativeWireGuardImportLock()
  if (current === "recovery_required") return current
  if (current === "unknown" && reason === "unknown") return current
  storeValue(reason)
  return reason
}

/** Delivers durable locks written by another tab. Null clears are ignored. */
export function subscribeNativeWireGuardImportLock(
  listener: (reason: NativeWireGuardImportLockReason) => void
): () => void {
  if (typeof window === "undefined") return () => undefined

  const onStorage = (event: StorageEvent) => {
    if (
      event.key !== NATIVE_WIREGUARD_IMPORT_LOCK_STORAGE_KEY ||
      !safeStorageMatches(localStorageFactory, event.storageArea)
    ) {
      return
    }
    if (event.newValue === null) return

    const reason = reasonFromValue(event.newValue) ?? "unknown"
    volatileValue = reason === "pending" ? event.newValue : reason
    listener(reason)
  }
  window.addEventListener("storage", onStorage)
  return () => window.removeEventListener("storage", onStorage)
}
