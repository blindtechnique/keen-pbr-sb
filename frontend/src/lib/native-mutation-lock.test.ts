import {
  afterAll,
  afterEach,
  beforeEach,
  describe,
  expect,
  test,
} from "bun:test"

import type {
  NdmsNativeDeleteResult,
  NdmsNativeImportRecoveryResult,
} from "@/api/native-mutation"
import {
  nativeDeleteRecoveryDisposition,
  nativeImportRecoveryDisposition,
} from "@/components/transports/native-mutation-recovery-model"

import {
  NATIVE_MUTATION_LOCK_STORAGE_KEY,
  NATIVE_MUTATION_WEB_LOCK_NAME,
  readNativeMutationLock,
  runWithNativeMutationLease,
  subscribeNativeMutationLock,
  type NativeMutationLeaseCompletion,
  type NativeMutationLock,
  type NativeMutationOperation,
} from "./native-mutation-lock"

class ControlledStorage implements Storage {
  readonly values = new Map<string, string>()
  throwGet = false
  throwSet = false
  throwRemove = false
  afterGet: ((key: string, value: string | null) => void) | null = null
  afterSet: (() => void) | null = null

  get length() {
    return this.values.size
  }

  clear() {
    this.values.clear()
  }

  getItem(key: string) {
    if (this.throwGet) throw new DOMException("read unavailable")
    const value = this.values.get(key) ?? null
    this.afterGet?.(key, value)
    return value
  }

  key(index: number) {
    return [...this.values.keys()][index] ?? null
  }

  removeItem(key: string) {
    if (this.throwRemove) throw new DOMException("remove unavailable")
    this.values.delete(key)
  }

  setItem(key: string, value: string) {
    if (this.throwSet) throw new DOMException("write unavailable")
    this.values.set(key, value)
    this.afterSet?.()
  }
}

type LockRequestRecord = Readonly<{
  name: string
  mode: LockMode | undefined
  ifAvailable: boolean | undefined
}>

class FakeLockManager {
  held = false
  rejectRequests = false
  readonly requests: LockRequestRecord[] = []

  async request<T>(
    name: string,
    options: LockOptions,
    callback: (lock: Lock | null) => T | PromiseLike<T>
  ): Promise<T> {
    this.requests.push({
      name,
      mode: options.mode,
      ifAvailable: options.ifAvailable,
    })
    if (this.rejectRequests) throw new DOMException("locks unavailable")
    if (this.held) return await callback(null)

    this.held = true
    try {
      return await callback({ name, mode: "exclusive" } as Lock)
    } finally {
      this.held = false
    }
  }
}

const localStorage = new ControlledStorage()
const sessionStorage = new ControlledStorage()
let lockManager = new FakeLockManager()
const storageListeners = new Set<(event: StorageEvent) => void>()
const LEGACY_IMPORT_LOCK_STORAGE_KEY = "keen-pbr.native-import-write-lock.v2"
const LEGACY_IMPORT_SESSION_KEY = "keen-pbr.native-import-write-lock.v1"

const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window")
const originalNavigator = Object.getOwnPropertyDescriptor(
  globalThis,
  "navigator"
)

const installNavigator = (locks: FakeLockManager | null) => {
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: locks ? { locks: locks as unknown as LockManager } : {},
  })
}

const installWindow = () => {
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {
      localStorage,
      sessionStorage,
      addEventListener: (
        type: string,
        listener: (event: StorageEvent) => void
      ) => {
        if (type === "storage") storageListeners.add(listener)
      },
      removeEventListener: (
        type: string,
        listener: (event: StorageEvent) => void
      ) => {
        if (type === "storage") storageListeners.delete(listener)
      },
    },
  })
}

const marker = (lock: NativeMutationLock): string => JSON.stringify(lock)

const pending = (
  operation: NativeMutationOperation,
  digit = "a"
): NativeMutationLock => ({
  version: 1,
  state: "pending",
  operation,
  token: digit.repeat(32),
})

const complete = <T>(
  disposition: NativeMutationLeaseCompletion<T>["disposition"],
  value: T
): NativeMutationLeaseCompletion<T> => ({ disposition, value })

const importRecoveryResult = (
  status: NdmsNativeImportRecoveryResult["status"],
  stop: NdmsNativeImportRecoveryResult["stop"]
): NdmsNativeImportRecoveryResult => ({
  status,
  stop,
  ndms_import_request_dispatched: false,
  ndms_delete_dispatched: false,
  system_configuration_save_performed: false,
  external_ndms_writer_race_excluded: false,
  wal_may_require_recovery: status === "blocked",
  ownership_published: false,
  wal_removed: false,
})

const deleteRecoveryResult = (
  status: NdmsNativeDeleteResult["status"],
  stop: NdmsNativeDeleteResult["stop"]
): NdmsNativeDeleteResult => ({
  status,
  stop,
  external_writer_race_excluded: false,
  external_writer_race_accepted: false,
  global_save_scope_acknowledged: false,
  delete_perform_started: false,
  save_perform_started: false,
  request_may_have_been_dispatched: false,
  system_configuration_save_acknowledged: false,
  ownership_tombstone_durable: false,
  rollback_snapshot_retained: false,
})

const defer = () => {
  let resolve!: () => void
  const promise = new Promise<void>((done) => {
    resolve = done
  })
  return { promise, resolve }
}

const dispatchStorage = (newValue: string | null) => {
  for (const listener of storageListeners) {
    listener({
      key: NATIVE_MUTATION_LOCK_STORAGE_KEY,
      newValue,
      storageArea: localStorage,
    } as StorageEvent)
  }
}

beforeEach(() => {
  localStorage.clear()
  sessionStorage.clear()
  localStorage.throwGet = false
  localStorage.throwSet = false
  localStorage.throwRemove = false
  localStorage.afterGet = null
  localStorage.afterSet = null
  sessionStorage.throwGet = false
  sessionStorage.throwSet = false
  sessionStorage.throwRemove = false
  sessionStorage.afterGet = null
  sessionStorage.afterSet = null
  storageListeners.clear()
  lockManager = new FakeLockManager()
  installWindow()
  installNavigator(lockManager)
})

afterEach(() => {
  expect(lockManager.held).toBe(false)
})

afterAll(() => {
  if (originalWindow) {
    Object.defineProperty(globalThis, "window", originalWindow)
  } else {
    Reflect.deleteProperty(globalThis, "window")
  }
  if (originalNavigator) {
    Object.defineProperty(globalThis, "navigator", originalNavigator)
  } else {
    Reflect.deleteProperty(globalThis, "navigator")
  }
})

describe("native mutation browser-global lease", () => {
  test("1: a live import excludes another tab until its exact clear", async () => {
    const begun = defer()
    const release = defer()
    const importRun = runWithNativeMutationLease(
      "import",
      async ({ beginPending }) => {
        expect(beginPending()).toBe(true)
        begun.resolve()
        await release.promise
        return complete({ state: "clear" }, "imported")
      }
    )
    await begun.promise

    const durableWhileHeld = localStorage.getItem(
      NATIVE_MUTATION_LOCK_STORAGE_KEY
    )
    let recoveryCalls = 0
    const concurrent = await runWithNativeMutationLease(
      "import_recovery",
      async () => {
        recoveryCalls += 1
        return complete({ state: "clear" }, "unexpected")
      }
    )
    expect(concurrent).toEqual({ status: "busy" })
    expect(recoveryCalls).toBe(0)
    expect(localStorage.getItem(NATIVE_MUTATION_LOCK_STORAGE_KEY)).toBe(
      durableWhileHeld
    )

    release.resolve()
    expect(await importRun).toEqual({ status: "completed", value: "imported" })
    expect(localStorage.getItem(NATIVE_MUTATION_LOCK_STORAGE_KEY)).toBeNull()
    expect(lockManager.requests).toEqual([
      {
        name: NATIVE_MUTATION_WEB_LOCK_NAME,
        mode: "exclusive",
        ifAvailable: true,
      },
      {
        name: NATIVE_MUTATION_WEB_LOCK_NAME,
        mode: "exclusive",
        ifAvailable: true,
      },
    ])
    expect(NATIVE_MUTATION_WEB_LOCK_NAME).toBe("keen-pbr.native-mutation.v1")
  })

  test("2: only matching recovery replaces an orphan after lock grant", async () => {
    const orphan = pending("import")
    localStorage.setItem(NATIVE_MUTATION_LOCK_STORAGE_KEY, marker(orphan))

    let deleteCalls = 0
    const wrongFamily = await runWithNativeMutationLease(
      "delete_recovery",
      async () => {
        deleteCalls += 1
        return complete({ state: "clear" }, undefined)
      }
    )
    expect(wrongFamily).toEqual({ status: "unavailable" })
    expect(deleteCalls).toBe(0)
    expect(localStorage.getItem(NATIVE_MUTATION_LOCK_STORAGE_KEY)).toBe(
      marker(orphan)
    )

    let observedReplacement = false
    const matching = await runWithNativeMutationLease(
      "import_recovery",
      async () => {
        const observed = readNativeMutationLock()
        observedReplacement =
          observed?.state === "pending" &&
          observed.operation === "import_recovery" &&
          observed.token !== orphan.token
        return complete({ state: "clear" }, "recovered")
      }
    )
    expect(observedReplacement).toBe(true)
    expect(matching).toEqual({ status: "completed", value: "recovered" })
    expect(localStorage.getItem(NATIVE_MUTATION_LOCK_STORAGE_KEY)).toBeNull()
  })

  test("3: import writes only after admitted preflight and before raw request", async () => {
    let rawRequestCount = 0
    const denied = await runWithNativeMutationLease("import", async () => {
      expect(localStorage.getItem(NATIVE_MUTATION_LOCK_STORAGE_KEY)).toBeNull()
      return complete({ state: "not_started" }, "denied")
    })
    expect(denied).toEqual({ status: "completed", value: "denied" })
    expect(rawRequestCount).toBe(0)
    expect(localStorage.getItem(NATIVE_MUTATION_LOCK_STORAGE_KEY)).toBeNull()

    const admitted = await runWithNativeMutationLease(
      "import",
      async ({ beginPending }) => {
        expect(
          localStorage.getItem(NATIVE_MUTATION_LOCK_STORAGE_KEY)
        ).toBeNull()
        expect(beginPending()).toBe(true)
        expect(beginPending()).toBe(false)
        expect(readNativeMutationLock()?.state).toBe("pending")
        rawRequestCount += 1
        return complete({ state: "clear" }, "ok")
      }
    )
    expect(admitted).toEqual({ status: "completed", value: "ok" })
    expect(rawRequestCount).toBe(1)
    expect(localStorage.getItem(NATIVE_MUTATION_LOCK_STORAGE_KEY)).toBeNull()
  })

  test("4: missing locks and uncertain storage fail closed before dispatch", async () => {
    let callbackCount = 0
    installNavigator(null)
    expect(
      await runWithNativeMutationLease("delete", async () => {
        callbackCount += 1
        return complete({ state: "clear" }, undefined)
      })
    ).toEqual({ status: "unavailable" })
    expect(callbackCount).toBe(0)

    lockManager = new FakeLockManager()
    lockManager.rejectRequests = true
    installNavigator(lockManager)
    expect(
      await runWithNativeMutationLease("delete", async () => {
        callbackCount += 1
        return complete({ state: "clear" }, undefined)
      })
    ).toEqual({ status: "unavailable" })
    expect(callbackCount).toBe(0)

    lockManager = new FakeLockManager()
    installNavigator(lockManager)
    localStorage.throwGet = true
    expect(
      await runWithNativeMutationLease("delete", async () => {
        callbackCount += 1
        return complete({ state: "clear" }, undefined)
      })
    ).toEqual({ status: "unavailable" })
    expect(callbackCount).toBe(0)
    localStorage.throwGet = false

    localStorage.throwSet = true
    let rawRequestCount = 0
    expect(
      await runWithNativeMutationLease("import", async ({ beginPending }) => {
        expect(beginPending()).toBe(false)
        if (beginPending()) rawRequestCount += 1
        return complete({ state: "not_started" }, undefined)
      })
    ).toEqual({ status: "unavailable" })
    expect(rawRequestCount).toBe(0)
    localStorage.throwSet = false

    localStorage.afterSet = () => {
      localStorage.throwGet = true
    }
    expect(
      await runWithNativeMutationLease("import", async ({ beginPending }) => {
        expect(beginPending()).toBe(false)
        if (beginPending()) rawRequestCount += 1
        return complete({ state: "not_started" }, undefined)
      })
    ).toEqual({ status: "unavailable" })
    expect(rawRequestCount).toBe(0)
    localStorage.throwGet = false
    localStorage.afterSet = null
  })

  test("5: a post-begin exception latches unknown and releases for recovery", async () => {
    const failed = await runWithNativeMutationLease("delete", async () => {
      throw new Error()
    })
    expect(failed).toEqual({ status: "outcome_unknown" })
    expect(readNativeMutationLock()).toEqual({
      version: 1,
      state: "unknown",
      operation: "delete",
    })
    expect(lockManager.held).toBe(false)

    const recovered = await runWithNativeMutationLease(
      "delete_recovery",
      async () => complete({ state: "clear" }, "recovered")
    )
    expect(recovered).toEqual({ status: "completed", value: "recovered" })
    expect(readNativeMutationLock()).toBeNull()
  })

  test("6: a rogue token swap is preserved and makes clear outcome unknown", async () => {
    const rogue = pending("delete", "b")
    const result = await runWithNativeMutationLease("delete", async () => {
      localStorage.setItem(NATIVE_MUTATION_LOCK_STORAGE_KEY, marker(rogue))
      return complete({ state: "clear" }, "forged-terminal")
    })

    expect(result).toEqual({ status: "outcome_unknown" })
    expect(localStorage.getItem(NATIVE_MUTATION_LOCK_STORAGE_KEY)).toBe(
      marker(rogue)
    )
  })

  test("7: terminal states require exact verified persistence", async () => {
    expect(
      await runWithNativeMutationLease("delete", async () =>
        complete({ state: "clear" }, "cleared")
      )
    ).toEqual({ status: "completed", value: "cleared" })
    expect(readNativeMutationLock()).toBeNull()

    expect(
      await runWithNativeMutationLease("import_recovery", async () =>
        complete({ state: "recovery", recovery: "import" }, "blocked")
      )
    ).toEqual({ status: "completed", value: "blocked" })
    expect(readNativeMutationLock()).toEqual({
      version: 1,
      state: "recovery_required",
      recovery: "import",
    })

    expect(
      await runWithNativeMutationLease("import_recovery", async () =>
        complete({ state: "unknown" }, "ambiguous")
      )
    ).toEqual({ status: "outcome_unknown" })
    expect(readNativeMutationLock()).toEqual({
      version: 1,
      state: "unknown",
      operation: "import_recovery",
    })

    localStorage.clear()
    localStorage.throwRemove = true
    expect(
      await runWithNativeMutationLease("delete", async () =>
        complete({ state: "clear" }, undefined)
      )
    ).toEqual({ status: "outcome_unknown" })
    expect(lockManager.held).toBe(false)
    localStorage.throwRemove = false
    localStorage.clear()

    expect(
      await runWithNativeMutationLease("delete", async () => {
        localStorage.throwSet = true
        return complete({ state: "recovery", recovery: "delete" }, undefined)
      })
    ).toEqual({ status: "outcome_unknown" })
    expect(lockManager.held).toBe(false)
    localStorage.throwSet = false
    localStorage.clear()

    expect(
      await runWithNativeMutationLease("delete", async () => {
        localStorage.throwGet = true
        return complete({ state: "clear" }, undefined)
      })
    ).toEqual({ status: "outcome_unknown" })
    expect(lockManager.held).toBe(false)
    localStorage.throwGet = false
  })

  test("8: missing terminal disposition and post-begin not_started latch unknown", async () => {
    const missing = await runWithNativeMutationLease(
      "delete",
      async () => undefined as never
    )
    expect(missing).toEqual({ status: "outcome_unknown" })
    expect(readNativeMutationLock()).toEqual({
      version: 1,
      state: "unknown",
      operation: "delete",
    })

    localStorage.clear()
    const contradicted = await runWithNativeMutationLease("delete", async () =>
      complete({ state: "not_started" }, undefined)
    )
    expect(contradicted).toEqual({ status: "outcome_unknown" })
    expect(readNativeMutationLock()).toEqual({
      version: 1,
      state: "unknown",
      operation: "delete",
    })
  })

  test("9: storage events reread truth and same-document transitions notify once", async () => {
    const observed: Array<NativeMutationLock | null> = []
    const heldDuringNotification: boolean[] = []
    const unsubscribe = subscribeNativeMutationLock((lock) => {
      observed.push(lock)
      heldDuringNotification.push(lockManager.held)
    })
    const unsubscribeThrowing = subscribeNativeMutationLock(() => {
      throw new Error()
    })

    const newer = pending("delete", "c")
    localStorage.setItem(NATIVE_MUTATION_LOCK_STORAGE_KEY, marker(newer))
    dispatchStorage(null)
    expect(observed).toEqual([newer])

    observed.length = 0
    heldDuringNotification.length = 0
    localStorage.clear()
    expect(
      await runWithNativeMutationLease("delete", async () =>
        complete({ state: "clear" }, undefined)
      )
    ).toEqual({ status: "completed", value: undefined })
    expect(observed).toHaveLength(2)
    expect(observed[0]?.state).toBe("pending")
    expect(observed[1]).toBeNull()
    expect(heldDuringNotification).toEqual([true, true])
    expect(
      await runWithNativeMutationLease(
        "import_recovery",
        async ({ beginPending }) => {
          // Recovery already consumed the one-shot begin before its callback.
          expect(beginPending()).toBe(false)
          return complete({ state: "clear" }, "still-usable")
        }
      )
    ).toEqual({ status: "completed", value: "still-usable" })
    unsubscribeThrowing()
    unsubscribe()
  })

  test("10: fresh and recovery eligibility are exact and family-scoped", async () => {
    let calls = 0
    expect(
      await runWithNativeMutationLease("import", async () => {
        calls += 1
        return complete({ state: "not_started" }, "fresh")
      })
    ).toEqual({ status: "completed", value: "fresh" })

    localStorage.setItem(
      NATIVE_MUTATION_LOCK_STORAGE_KEY,
      marker({ version: 1, state: "unknown", operation: "import" })
    )
    expect(
      await runWithNativeMutationLease("delete", async () => {
        calls += 1
        return complete({ state: "clear" }, undefined)
      })
    ).toEqual({ status: "unavailable" })

    for (const accepted of [
      null,
      pending("import", "d"),
      { version: 1, state: "unknown", operation: "import" } as const,
      { version: 1, state: "recovery_required", recovery: "import" } as const,
    ]) {
      localStorage.clear()
      if (accepted) {
        localStorage.setItem(NATIVE_MUTATION_LOCK_STORAGE_KEY, marker(accepted))
      }
      const before = calls
      expect(
        await runWithNativeMutationLease("import_recovery", async () => {
          calls += 1
          return complete({ state: "clear" }, "ok")
        })
      ).toEqual({ status: "completed", value: "ok" })
      expect(calls).toBe(before + 1)
    }

    for (const rejected of [
      marker({ version: 1, state: "unknown", operation: "delete" }),
      marker({ version: 1, state: "recovery_required", recovery: "delete" }),
    ]) {
      localStorage.setItem(NATIVE_MUTATION_LOCK_STORAGE_KEY, rejected)
      const before = calls
      expect(
        await runWithNativeMutationLease("import_recovery", async () => {
          calls += 1
          return complete({ state: "clear" }, undefined)
        })
      ).toEqual({ status: "unavailable" })
      expect(calls).toBe(before)
    }

    expect(lockManager.requests.length).toBeGreaterThan(0)
    expect(
      lockManager.requests.every(
        (request) =>
          request.name === "keen-pbr.native-mutation.v1" &&
          request.mode === "exclusive" &&
          request.ifAvailable === true
      )
    ).toBe(true)
  })

  test("a mutating pending subscriber cannot authorize the raw request", async () => {
    const rogue = pending("import", "e")
    const unsubscribe = subscribeNativeMutationLock((lock) => {
      if (lock?.state === "pending" && lock.operation === "import") {
        localStorage.setItem(NATIVE_MUTATION_LOCK_STORAGE_KEY, marker(rogue))
      }
    })
    let rawRequestCount = 0

    const result = await runWithNativeMutationLease(
      "import",
      async ({ beginPending }) => {
        if (beginPending()) rawRequestCount += 1
        return complete({ state: "not_started" }, undefined)
      }
    )

    expect(result).toEqual({ status: "unavailable" })
    expect(rawRequestCount).toBe(0)
    expect(localStorage.getItem(NATIVE_MUTATION_LOCK_STORAGE_KEY)).toBe(
      marker(rogue)
    )
    unsubscribe()
  })

  test("a mutating terminal subscriber preserves its token and defeats success", async () => {
    const rogue = pending("delete", "f")
    const unsubscribe = subscribeNativeMutationLock((lock) => {
      if (lock === null) {
        localStorage.setItem(NATIVE_MUTATION_LOCK_STORAGE_KEY, marker(rogue))
      }
    })

    const result = await runWithNativeMutationLease("delete", async () =>
      complete({ state: "clear" }, "untrusted")
    )

    expect(result).toEqual({ status: "outcome_unknown" })
    expect(localStorage.getItem(NATIVE_MUTATION_LOCK_STORAGE_KEY)).toBe(
      marker(rogue)
    )
    unsubscribe()
  })

  test("11: an ordinary legacy observer cannot overwrite a live pending token", () => {
    localStorage.setItem(LEGACY_IMPORT_LOCK_STORAGE_KEY, "recovery_required")
    const live = pending("delete", "1")
    let interleaved = false
    localStorage.afterGet = (key, value) => {
      if (
        !interleaved &&
        key === NATIVE_MUTATION_LOCK_STORAGE_KEY &&
        value === null
      ) {
        interleaved = true
        // A different tab writes while this observer still holds its stale
        // null read. Direct map access models the other Storage object.
        localStorage.values.set(NATIVE_MUTATION_LOCK_STORAGE_KEY, marker(live))
      }
    }

    readNativeMutationLock()
    localStorage.afterGet = null

    expect(interleaved).toBe(true)
    expect(localStorage.getItem(NATIVE_MUTATION_LOCK_STORAGE_KEY)).toBe(
      marker(live)
    )
    expect(readNativeMutationLock()).toEqual(live)
    expect(localStorage.getItem(LEGACY_IMPORT_LOCK_STORAGE_KEY)).toBe(
      "recovery_required"
    )
  })

  test("12: legacy promotion is under-lease and participates in eligibility", async () => {
    localStorage.setItem(LEGACY_IMPORT_LOCK_STORAGE_KEY, "legacy-pending")

    expect(readNativeMutationLock()).toEqual({
      version: 1,
      state: "unknown",
      operation: "import",
    })
    expect(localStorage.getItem(NATIVE_MUTATION_LOCK_STORAGE_KEY)).toBeNull()
    expect(localStorage.getItem(LEGACY_IMPORT_LOCK_STORAGE_KEY)).toBe(
      "legacy-pending"
    )

    let freshCalls = 0
    expect(
      await runWithNativeMutationLease("delete", async () => {
        freshCalls += 1
        return complete({ state: "clear" }, undefined)
      })
    ).toEqual({ status: "unavailable" })
    expect(freshCalls).toBe(0)
    expect(readNativeMutationLock()).toEqual({
      version: 1,
      state: "unknown",
      operation: "import",
    })
    expect(localStorage.getItem(LEGACY_IMPORT_LOCK_STORAGE_KEY)).toBeNull()

    let observedReplacement = false
    expect(
      await runWithNativeMutationLease("import_recovery", async () => {
        const observed = readNativeMutationLock()
        observedReplacement =
          observed?.state === "pending" &&
          observed.operation === "import_recovery"
        return complete({ state: "clear" }, "recovered")
      })
    ).toEqual({ status: "completed", value: "recovered" })
    expect(observedReplacement).toBe(true)
    expect(readNativeMutationLock()).toBeNull()
  })

  test("13: failed legacy promotion and cleanup remain fail closed", async () => {
    sessionStorage.setItem(LEGACY_IMPORT_SESSION_KEY, "recovery_required")
    localStorage.throwSet = true
    let recoveryCalls = 0
    expect(
      await runWithNativeMutationLease("import_recovery", async () => {
        recoveryCalls += 1
        return complete({ state: "clear" }, undefined)
      })
    ).toEqual({ status: "unavailable" })
    expect(recoveryCalls).toBe(0)
    expect(localStorage.getItem(NATIVE_MUTATION_LOCK_STORAGE_KEY)).toBeNull()
    expect(readNativeMutationLock()).toEqual({
      version: 1,
      state: "recovery_required",
      recovery: "import",
    })

    localStorage.throwSet = false
    sessionStorage.throwRemove = true
    expect(
      await runWithNativeMutationLease("import_recovery", async () => {
        recoveryCalls += 1
        return complete({ state: "clear" }, undefined)
      })
    ).toEqual({ status: "outcome_unknown" })
    expect(recoveryCalls).toBe(1)
    expect(readNativeMutationLock()).toEqual({
      version: 1,
      state: "recovery_required",
      recovery: "import",
    })

    let freshCalls = 0
    expect(
      await runWithNativeMutationLease("import", async ({ beginPending }) => {
        freshCalls += 1
        if (beginPending()) freshCalls += 1
        return complete({ state: "clear" }, undefined)
      })
    ).toEqual({ status: "unavailable" })
    expect(freshCalls).toBe(0)
  })

  test("14: a failed legacy promotion roundtrip never enters the callback", async () => {
    localStorage.setItem(LEGACY_IMPORT_LOCK_STORAGE_KEY, "recovery_required")
    localStorage.afterSet = () => {
      localStorage.values.set(NATIVE_MUTATION_LOCK_STORAGE_KEY, "not-json")
    }
    let callbackCount = 0

    expect(
      await runWithNativeMutationLease("import_recovery", async () => {
        callbackCount += 1
        return complete({ state: "clear" }, undefined)
      })
    ).toEqual({ status: "unavailable" })
    expect(callbackCount).toBe(0)
    expect(localStorage.getItem(NATIVE_MUTATION_LOCK_STORAGE_KEY)).toBe(
      "not-json"
    )
    expect(readNativeMutationLock()?.state).toBe("unknown")
  })

  test("15: an exact redirect changes only an orphan recovery family", async () => {
    localStorage.setItem(NATIVE_MUTATION_LOCK_STORAGE_KEY, "not-json")
    let freshCalls = 0
    expect(
      await runWithNativeMutationLease("import", async () => {
        freshCalls += 1
        return complete({ state: "clear" }, "must-not-run")
      })
    ).toEqual({ status: "unavailable" })
    expect(freshCalls).toBe(0)
    expect(localStorage.getItem(NATIVE_MUTATION_LOCK_STORAGE_KEY)).toBe(
      "not-json"
    )

    const importOrphans: Array<() => void> = [
      () =>
        localStorage.setItem(
          NATIVE_MUTATION_LOCK_STORAGE_KEY,
          marker(pending("import", "2"))
        ),
      () =>
        localStorage.setItem(LEGACY_IMPORT_LOCK_STORAGE_KEY, "legacy-pending"),
      () => localStorage.setItem(NATIVE_MUTATION_LOCK_STORAGE_KEY, "not-json"),
      () =>
        localStorage.setItem(
          NATIVE_MUTATION_LOCK_STORAGE_KEY,
          JSON.stringify({ version: 1, state: "invalid-current-state" })
        ),
    ]

    for (const prepare of importOrphans) {
      localStorage.clear()
      sessionStorage.clear()
      prepare()
      expect(
        await runWithNativeMutationLease("import_recovery", async () =>
          complete(
            { state: "redirect_recovery", recovery: "delete" },
            "redirected"
          )
        )
      ).toEqual({ status: "completed", value: "redirected" })
      expect(readNativeMutationLock()).toEqual({
        version: 1,
        state: "recovery_required",
        recovery: "delete",
      })
    }

    const deleteOrphans: Array<() => void> = [
      () =>
        localStorage.setItem(
          NATIVE_MUTATION_LOCK_STORAGE_KEY,
          marker(pending("delete", "3"))
        ),
      () => localStorage.setItem(NATIVE_MUTATION_LOCK_STORAGE_KEY, "not-json"),
      () =>
        localStorage.setItem(
          NATIVE_MUTATION_LOCK_STORAGE_KEY,
          JSON.stringify({ version: 1, state: "invalid-current-state" })
        ),
    ]

    for (const prepare of deleteOrphans) {
      localStorage.clear()
      sessionStorage.clear()
      prepare()
      expect(
        await runWithNativeMutationLease("delete_recovery", async () =>
          complete(
            { state: "redirect_recovery", recovery: "import" },
            "redirected-back"
          )
        )
      ).toEqual({ status: "completed", value: "redirected-back" })
      expect(readNativeMutationLock()).toEqual({
        version: 1,
        state: "recovery_required",
        recovery: "import",
      })
    }
  })

  test("16: same-family and fresh-operation redirects stay outcome-unknown", async () => {
    localStorage.setItem(
      NATIVE_MUTATION_LOCK_STORAGE_KEY,
      marker(pending("import", "4"))
    )
    expect(
      await runWithNativeMutationLease("import_recovery", async () =>
        complete({ state: "redirect_recovery", recovery: "import" }, "invalid")
      )
    ).toEqual({ status: "outcome_unknown" })
    expect(readNativeMutationLock()).toEqual({
      version: 1,
      state: "unknown",
      operation: "import_recovery",
    })

    localStorage.clear()
    expect(
      await runWithNativeMutationLease("import", async ({ beginPending }) => {
        expect(beginPending()).toBe(true)
        return complete(
          { state: "redirect_recovery", recovery: "delete" },
          "invalid-fresh"
        )
      })
    ).toEqual({ status: "outcome_unknown" })
    expect(readNativeMutationLock()).toEqual({
      version: 1,
      state: "unknown",
      operation: "import",
    })
  })

  test("17: redirect persistence failures preserve exact journal authority", async () => {
    localStorage.setItem(
      NATIVE_MUTATION_LOCK_STORAGE_KEY,
      marker(pending("import", "5"))
    )
    const failedWrite = await runWithNativeMutationLease(
      "import_recovery",
      async () => {
        localStorage.throwSet = true
        return complete(
          { state: "redirect_recovery", recovery: "delete" },
          "uncommitted"
        )
      }
    )
    localStorage.throwSet = false
    expect(failedWrite).toEqual({ status: "outcome_unknown" })
    const retained = readNativeMutationLock()
    expect(retained?.state).toBe("pending")
    expect(retained?.state === "pending" && retained.operation).toBe(
      "import_recovery"
    )

    localStorage.setItem(
      NATIVE_MUTATION_LOCK_STORAGE_KEY,
      marker(pending("import", "6"))
    )
    const rogue = pending("import", "7")
    const unsubscribe = subscribeNativeMutationLock((lock) => {
      if (lock?.state === "recovery_required" && lock.recovery === "delete") {
        localStorage.setItem(NATIVE_MUTATION_LOCK_STORAGE_KEY, marker(rogue))
      }
    })
    expect(
      await runWithNativeMutationLease("import_recovery", async () =>
        complete({ state: "redirect_recovery", recovery: "delete" }, "tampered")
      )
    ).toEqual({ status: "outcome_unknown" })
    expect(readNativeMutationLock()).toEqual(rogue)
    unsubscribe()
  })

  test("18: an unsupported future lock version is never overwritten", async () => {
    const future = JSON.stringify({
      version: 2,
      state: "recovery_required",
      recovery: "delete",
    })
    localStorage.setItem(NATIVE_MUTATION_LOCK_STORAGE_KEY, future)
    let callbackCount = 0

    for (const operation of [
      "import",
      "delete",
      "import_recovery",
      "delete_recovery",
    ] as const) {
      expect(
        await runWithNativeMutationLease(operation, async () => {
          callbackCount += 1
          return complete(
            { state: "redirect_recovery", recovery: "delete" },
            undefined
          )
        })
      ).toEqual({ status: "unavailable" })
    }
    expect(callbackCount).toBe(0)
    expect(localStorage.getItem(NATIVE_MUTATION_LOCK_STORAGE_KEY)).toBe(future)
  })
})

describe("native mutation recovery dispositions", () => {
  test("only exact cross-WAL stops redirect the recovery family", () => {
    expect(
      nativeImportRecoveryDisposition(
        importRecoveryResult("blocked", "delete_wal_not_clean")
      )
    ).toEqual({ state: "redirect_recovery", recovery: "delete" })
    expect(
      nativeImportRecoveryDisposition(
        importRecoveryResult("blocked", "phase_not_forward_only")
      )
    ).toEqual({ state: "recovery", recovery: "import" })
    expect(
      nativeImportRecoveryDisposition(
        importRecoveryResult("blocked", "unexpected_failure")
      )
    ).toEqual({ state: "recovery", recovery: "import" })

    expect(
      nativeDeleteRecoveryDisposition(
        deleteRecoveryResult("blocked", "import_wal_not_authoritatively_clean")
      )
    ).toEqual({ state: "redirect_recovery", recovery: "import" })
    expect(
      nativeDeleteRecoveryDisposition(
        deleteRecoveryResult("blocked", "save_reconfirmation_required")
      )
    ).toEqual({ state: "recovery", recovery: "delete" })
    expect(
      nativeDeleteRecoveryDisposition(
        deleteRecoveryResult("blocked", "unexpected_failure")
      )
    ).toEqual({ state: "recovery", recovery: "delete" })
  })

  test("terminal no-work results still clear the browser journal", () => {
    expect(
      nativeImportRecoveryDisposition(importRecoveryResult("no_work", "none"))
    ).toEqual({ state: "clear" })
    expect(
      nativeImportRecoveryDisposition(importRecoveryResult("completed", "none"))
    ).toEqual({ state: "clear" })
    expect(
      nativeDeleteRecoveryDisposition(
        deleteRecoveryResult("blocked", "no_delete_transaction")
      )
    ).toEqual({ state: "clear" })
  })
})
