import { safeStorageMatches } from "@/lib/safe-storage"

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

export type NativeMutationLeaseDisposition =
  | Readonly<{ state: "not_started" }>
  | Readonly<{ state: "clear" }>
  | Readonly<{
      state: "recovery"
      recovery: NativeMutationRecoveryKind
    }>
  | Readonly<{ state: "unknown" }>

export type NativeMutationLeaseCompletion<T> = Readonly<{
  disposition: NativeMutationLeaseDisposition
  value: T
}>

export type NativeMutationLeaseRunResult<T> =
  | Readonly<{ status: "completed"; value: T }>
  | Readonly<{ status: "busy" }>
  | Readonly<{ status: "unavailable" }>
  | Readonly<{ status: "outcome_unknown" }>

export type NativeMutationLeaseContext = Readonly<{
  /**
   * Import alone defers its durable marker until the secret preflight is
   * admitted. A false result is a hard stop: no request may be dispatched.
   */
  beginPending: () => boolean
}>

export const NATIVE_MUTATION_LOCK_STORAGE_KEY =
  "keen-pbr.native-mutation-lock.v1"
export const NATIVE_MUTATION_WEB_LOCK_NAME = "keen-pbr.native-mutation.v1"

const LEGACY_IMPORT_LOCK_STORAGE_KEY = "keen-pbr.native-import-write-lock.v2"
const LEGACY_IMPORT_SESSION_KEY = "keen-pbr.native-import-write-lock.v1"

type AvailableSnapshot = Readonly<{
  status: "available"
  storage: Storage
  raw: string | null
  lock: NativeMutationLock | null
  corrupt: boolean
}>

type DurableSnapshot = AvailableSnapshot | Readonly<{ status: "unavailable" }>

type PendingAuthority = Readonly<{
  operation: NativeMutationOperation
  token: string
}>

type NativeMutationSubscriber = Readonly<{
  listener: (lock: NativeMutationLock | null) => void
  suppressOwnedPending: boolean
}>

let volatileLock: NativeMutationLock | null = null
const activePendingTokens = new Set<string>()
const sameDocumentSubscribers = new Set<NativeMutationSubscriber>()

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
    // The caller distinguishes corrupt durable state from an empty journal.
  }
  return null
}

const serializeLock = (lock: NativeMutationLock): string => JSON.stringify(lock)

const corruptLock = (): NativeMutationLock => ({
  version: 1,
  state: "unknown",
  operation: "import",
})

const notifySubscriber = (
  subscriber: NativeMutationSubscriber,
  lock: NativeMutationLock | null
) => {
  if (
    subscriber.suppressOwnedPending &&
    lock?.state === "pending" &&
    activePendingTokens.has(lock.token)
  ) {
    return
  }
  try {
    subscriber.listener(lock)
  } catch {
    // Notification is observational. A subscriber must never interrupt a
    // verified journal transition or strand its active in-process token.
  }
}

const notifySameDocument = (lock: NativeMutationLock | null) => {
  for (const subscriber of sameDocumentSubscribers) {
    notifySubscriber(subscriber, lock)
  }
}

const getStorage = (
  source: () => Storage
): Readonly<{ ok: true; storage: Storage }> | Readonly<{ ok: false }> => {
  try {
    const storage = source()
    if (!storage) return { ok: false }
    return { ok: true, storage }
  } catch {
    return { ok: false }
  }
}

const getItem = (
  storage: Storage,
  key: string
): Readonly<{ ok: true; value: string | null }> | Readonly<{ ok: false }> => {
  try {
    return { ok: true, value: storage.getItem(key) }
  } catch {
    return { ok: false }
  }
}

const migrateLegacyImportLock = (
  localStorage: Storage
): AvailableSnapshot | null | "unavailable" => {
  const legacyLocal = getItem(localStorage, LEGACY_IMPORT_LOCK_STORAGE_KEY)
  if (!legacyLocal.ok) return "unavailable"

  const session = getStorage(() => window.sessionStorage)
  if (!session.ok) return "unavailable"
  const legacySession = getItem(session.storage, LEGACY_IMPORT_SESSION_KEY)
  if (!legacySession.ok) return "unavailable"

  const legacy = legacyLocal.value ?? legacySession.value
  if (legacy === null) return null

  const migrated: NativeMutationLock =
    legacy === "recovery_required"
      ? { version: 1, state: "recovery_required", recovery: "import" }
      : { version: 1, state: "unknown", operation: "import" }
  const serialized = serializeLock(migrated)
  try {
    localStorage.setItem(NATIVE_MUTATION_LOCK_STORAGE_KEY, serialized)
  } catch {
    return "unavailable"
  }
  const verified = getItem(localStorage, NATIVE_MUTATION_LOCK_STORAGE_KEY)
  if (!verified.ok || verified.value !== serialized) return "unavailable"

  try {
    localStorage.removeItem(LEGACY_IMPORT_LOCK_STORAGE_KEY)
    session.storage.removeItem(LEGACY_IMPORT_SESSION_KEY)
  } catch {
    // The verified new marker remains authoritative. Legacy cleanup is best
    // effort and can never reopen the mutation path.
  }
  volatileLock = migrated
  return {
    status: "available",
    storage: localStorage,
    raw: serialized,
    lock: migrated,
    corrupt: false,
  }
}

const readDurableSnapshot = (): DurableSnapshot => {
  if (typeof window === "undefined") return { status: "unavailable" }

  const local = getStorage(() => window.localStorage)
  if (!local.ok) return { status: "unavailable" }
  const current = getItem(local.storage, NATIVE_MUTATION_LOCK_STORAGE_KEY)
  if (!current.ok) return { status: "unavailable" }

  if (current.value === null) {
    const migrated = migrateLegacyImportLock(local.storage)
    if (migrated === "unavailable") return { status: "unavailable" }
    if (migrated) return migrated
    return {
      status: "available",
      storage: local.storage,
      raw: null,
      lock: null,
      corrupt: false,
    }
  }

  const parsed = parseLock(current.value)
  return {
    status: "available",
    storage: local.storage,
    raw: current.value,
    lock: parsed,
    corrupt: parsed === null,
  }
}

const adoptSnapshot = (snapshot: DurableSnapshot) => {
  if (snapshot.status !== "available") return
  volatileLock = snapshot.corrupt ? corruptLock() : snapshot.lock
}

/** Reads only a redacted, bounded cross-tab mutation journal. */
export function readNativeMutationLock(): NativeMutationLock | null {
  const snapshot = readDurableSnapshot()
  if (snapshot.status === "unavailable") {
    if (volatileLock) return volatileLock
    volatileLock = corruptLock()
    return volatileLock
  }
  adoptSnapshot(snapshot)
  return volatileLock
}

const newToken = (): string | null => {
  const bytes = new Uint8Array(16)
  try {
    globalThis.crypto.getRandomValues(bytes)
    return Array.from(bytes, (value) =>
      value.toString(16).padStart(2, "0")
    ).join("")
  } catch {
    return null
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

const isFreshOperation = (operation: NativeMutationOperation): boolean =>
  operation === "import" || operation === "delete"

const operationEligible = (
  snapshot: AvailableSnapshot,
  operation: NativeMutationOperation
): boolean => {
  if (snapshot.corrupt) return false
  if (isFreshOperation(operation)) return snapshot.lock === null
  if (snapshot.lock === null) return true

  const recovery = recoveryForOperation(operation)
  if (snapshot.lock.state === "pending") {
    return recoveryForOperation(snapshot.lock.operation) === recovery
  }
  if (snapshot.lock.state === "recovery_required") {
    return snapshot.lock.recovery === recovery
  }
  return recoveryForOperation(snapshot.lock.operation) === recovery
}

const writePending = (
  baseline: AvailableSnapshot,
  operation: NativeMutationOperation
): PendingAuthority | null => {
  const token = newToken()
  if (!token) return null

  const current = readDurableSnapshot()
  if (
    current.status !== "available" ||
    current.storage !== baseline.storage ||
    current.raw !== baseline.raw ||
    current.corrupt
  ) {
    adoptSnapshot(current)
    return null
  }

  const pending: NativeMutationLock = {
    version: 1,
    state: "pending",
    operation,
    token,
  }
  const serialized = serializeLock(pending)
  try {
    current.storage.setItem(NATIVE_MUTATION_LOCK_STORAGE_KEY, serialized)
  } catch {
    return null
  }

  const verified = readDurableSnapshot()
  if (
    verified.status !== "available" ||
    verified.raw !== serialized ||
    verified.corrupt ||
    verified.lock?.state !== "pending" ||
    verified.lock.operation !== operation ||
    verified.lock.token !== token
  ) {
    adoptSnapshot(verified)
    return null
  }

  activePendingTokens.add(token)
  volatileLock = pending
  notifySameDocument(pending)

  // A same-document observer is not trusted with journal authority. It can
  // synchronously touch localStorage while being notified, so the pending
  // token must still be exact after every observer has returned.
  const stable = readDurableSnapshot()
  if (
    stable.status !== "available" ||
    stable.storage !== verified.storage ||
    stable.raw !== serialized ||
    stable.corrupt ||
    stable.lock?.state !== "pending" ||
    stable.lock.operation !== operation ||
    stable.lock.token !== token
  ) {
    activePendingTokens.delete(token)
    adoptSnapshot(stable)
    return null
  }
  return { operation, token }
}

const pendingMatches = (
  lock: NativeMutationLock | null,
  authority: PendingAuthority
): boolean =>
  lock?.state === "pending" &&
  lock.operation === authority.operation &&
  lock.token === authority.token

const writeTerminal = (
  authority: PendingAuthority,
  target: NativeMutationLock | null
): boolean => {
  const current = readDurableSnapshot()
  if (
    current.status !== "available" ||
    current.corrupt ||
    !pendingMatches(current.lock, authority)
  ) {
    adoptSnapshot(current)
    return false
  }

  let expectedRaw: string | null = null
  try {
    if (target === null) {
      current.storage.removeItem(NATIVE_MUTATION_LOCK_STORAGE_KEY)
    } else {
      expectedRaw = serializeLock(target)
      current.storage.setItem(NATIVE_MUTATION_LOCK_STORAGE_KEY, expectedRaw)
    }
  } catch {
    return false
  }

  const verified = readDurableSnapshot()
  if (
    verified.status !== "available" ||
    verified.corrupt ||
    verified.raw !== expectedRaw ||
    (target === null
      ? verified.lock !== null
      : serializeLock(verified.lock!) !== expectedRaw)
  ) {
    adoptSnapshot(verified)
    return false
  }

  activePendingTokens.delete(authority.token)
  volatileLock = target
  notifySameDocument(target)

  // Notification callbacks are untrusted synchronous code. Reconfirm the
  // exact terminal state after they run before reporting it as committed.
  const stable = readDurableSnapshot()
  if (
    stable.status !== "available" ||
    stable.storage !== verified.storage ||
    stable.corrupt ||
    stable.raw !== expectedRaw ||
    (target === null
      ? stable.lock !== null
      : serializeLock(stable.lock!) !== expectedRaw)
  ) {
    adoptSnapshot(stable)
    return false
  }
  return true
}

const getLockManager = (): LockManager | null => {
  if (typeof navigator === "undefined") return null
  try {
    const manager = navigator.locks
    return manager && typeof manager.request === "function" ? manager : null
  } catch {
    return null
  }
}

const isDisposition = (
  value: unknown
): value is NativeMutationLeaseDisposition => {
  if (!value || typeof value !== "object") return false
  const state = (value as { state?: unknown }).state
  if (state === "not_started" || state === "clear" || state === "unknown") {
    return true
  }
  return (
    state === "recovery" &&
    isRecoveryKind((value as { recovery?: unknown }).recovery)
  )
}

class CallbackBeforePendingError {
  readonly cause: unknown

  constructor(cause: unknown) {
    this.cause = cause
  }
}

const releasePendingAuthority = (authority: PendingAuthority | null) => {
  if (authority) activePendingTokens.delete(authority.token)
}

/**
 * Runs one native mutation under a browser-global exclusive lease. The
 * durable marker is created and terminally committed while the Web Lock is
 * still held. Storage is the crash journal; Web Locks fence live tabs.
 */
export async function runWithNativeMutationLease<T>(
  operation: NativeMutationOperation,
  callback: (
    context: NativeMutationLeaseContext
  ) => Promise<NativeMutationLeaseCompletion<T>>
): Promise<NativeMutationLeaseRunResult<T>> {
  const manager = getLockManager()
  if (!manager) return { status: "unavailable" }

  try {
    return await manager.request(
      NATIVE_MUTATION_WEB_LOCK_NAME,
      { mode: "exclusive", ifAvailable: true },
      async (lock) => {
        if (!lock) return { status: "busy" } as const

        const baseline = readDurableSnapshot()
        if (
          baseline.status !== "available" ||
          !operationEligible(baseline, operation)
        ) {
          adoptSnapshot(baseline)
          return { status: "unavailable" } as const
        }

        let authority: PendingAuthority | null = null
        let beginAttempted = false
        const beginPending = (): boolean => {
          if (beginAttempted) return false
          beginAttempted = true
          authority = writePending(baseline, operation)
          return authority !== null
        }

        if (operation !== "import" && !beginPending()) {
          return { status: "unavailable" } as const
        }

        try {
          let completion: NativeMutationLeaseCompletion<T>
          try {
            completion = await callback({ beginPending })
          } catch (error) {
            if (!authority) throw new CallbackBeforePendingError(error)
            writeTerminal(authority, {
              version: 1,
              state: "unknown",
              operation,
            })
            return { status: "outcome_unknown" } as const
          }

          if (
            !completion ||
            !isDisposition(completion.disposition) ||
            (beginAttempted && !authority)
          ) {
            return authority
              ? (writeTerminal(authority, {
                  version: 1,
                  state: "unknown",
                  operation,
                }),
                { status: "outcome_unknown" } as const)
              : ({ status: "unavailable" } as const)
          }

          if (!authority) {
            return completion.disposition.state === "not_started"
              ? ({ status: "completed", value: completion.value } as const)
              : ({ status: "outcome_unknown" } as const)
          }

          if (completion.disposition.state === "not_started") {
            writeTerminal(authority, {
              version: 1,
              state: "unknown",
              operation,
            })
            return { status: "outcome_unknown" } as const
          }

          if (completion.disposition.state === "unknown") {
            writeTerminal(authority, {
              version: 1,
              state: "unknown",
              operation,
            })
            return { status: "outcome_unknown" } as const
          }

          const target =
            completion.disposition.state === "clear"
              ? null
              : completion.disposition.recovery ===
                  recoveryForOperation(operation)
                ? ({
                    version: 1,
                    state: "recovery_required",
                    recovery: completion.disposition.recovery,
                  } as const)
                : ({
                    version: 1,
                    state: "unknown",
                    operation,
                  } as const)

          const coherentRecovery =
            completion.disposition.state !== "recovery" ||
            completion.disposition.recovery === recoveryForOperation(operation)
          if (!writeTerminal(authority, target) || !coherentRecovery) {
            return { status: "outcome_unknown" } as const
          }
          return { status: "completed", value: completion.value } as const
        } finally {
          releasePendingAuthority(authority)
        }
      }
    )
  } catch (error) {
    if (error instanceof CallbackBeforePendingError) throw error.cause
    return { status: "unavailable" }
  }
}

/**
 * Delivers authoritative storage-event rereads and verified same-document
 * transitions, including exact clears.
 */
export function subscribeNativeMutationLock(
  listener: (lock: NativeMutationLock | null) => void,
  options: Readonly<{ suppressOwnedPending?: boolean }> = {}
): () => void {
  if (typeof window === "undefined") return () => undefined

  const subscriber: NativeMutationSubscriber = {
    listener,
    suppressOwnedPending: options.suppressOwnedPending === true,
  }
  sameDocumentSubscribers.add(subscriber)
  const onStorage = (event: StorageEvent) => {
    if (
      event.key !== NATIVE_MUTATION_LOCK_STORAGE_KEY ||
      !safeStorageMatches(() => window.localStorage, event.storageArea)
    ) {
      return
    }
    // event.newValue can be stale relative to a later writer. The durable
    // journal is always reread before notifying the subscriber.
    notifySubscriber(subscriber, readNativeMutationLock())
  }
  window.addEventListener("storage", onStorage)
  return () => {
    sameDocumentSubscribers.delete(subscriber)
    window.removeEventListener("storage", onStorage)
  }
}
