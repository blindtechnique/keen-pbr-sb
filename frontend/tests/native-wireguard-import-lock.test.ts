import { expect, test } from "bun:test"

import {
  NATIVE_MUTATION_LOCK_STORAGE_KEY,
  runWithNativeMutationLease,
} from "@/lib/native-mutation-lock"
import {
  readNativeWireGuardImportLock,
  subscribeNativeWireGuardImportLock,
  type NativeWireGuardImportLockReason,
} from "@/lib/native-wireguard-import-lock"

class MemoryStorage implements Storage {
  private readonly values = new Map<string, string>()
  get length() {
    return this.values.size
  }
  clear() {
    this.values.clear()
  }
  getItem(key: string) {
    return this.values.get(key) ?? null
  }
  key(index: number) {
    return [...this.values.keys()][index] ?? null
  }
  removeItem(key: string) {
    this.values.delete(key)
  }
  setItem(key: string, value: string) {
    this.values.set(key, value)
  }
}

test("native import compatibility view delivers authoritative clears", async () => {
  const localStorage = new MemoryStorage()
  const sessionStorage = new MemoryStorage()
  const listeners = new Set<(event: StorageEvent) => void>()
  let held = false
  const locks = {
    request: async <T>(
      name: string,
      options: LockOptions,
      callback: (lock: Lock | null) => T | PromiseLike<T>
    ): Promise<T> => {
      expect(name).toBe("keen-pbr.native-mutation.v1")
      expect(options).toMatchObject({ mode: "exclusive", ifAvailable: true })
      if (held) return await callback(null)
      held = true
      try {
        return await callback({ name, mode: "exclusive" } as Lock)
      } finally {
        held = false
      }
    },
  }
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window")
  const originalNavigator = Object.getOwnPropertyDescriptor(
    globalThis,
    "navigator"
  )
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {
      localStorage,
      sessionStorage,
      addEventListener: (
        type: string,
        listener: (event: StorageEvent) => void
      ) => {
        if (type === "storage") listeners.add(listener)
      },
      removeEventListener: (
        type: string,
        listener: (event: StorageEvent) => void
      ) => {
        if (type === "storage") listeners.delete(listener)
      },
    },
  })
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: { locks: locks as unknown as LockManager },
  })

  try {
    expect(readNativeWireGuardImportLock()).toBeNull()
    const observed: Array<NativeWireGuardImportLockReason | null> = []
    const unsubscribe = subscribeNativeWireGuardImportLock((reason) => {
      observed.push(reason)
    })

    expect(
      await runWithNativeMutationLease("import", async ({ beginPending }) => {
        expect(beginPending()).toBe(true)
        return {
          disposition: { state: "clear" },
          value: "ok",
        }
      })
    ).toEqual({ status: "completed", value: "ok" })
    // Its own pending notification is suppressed; the verified clear is not.
    expect(observed).toEqual([null])

    localStorage.setItem(
      NATIVE_MUTATION_LOCK_STORAGE_KEY,
      JSON.stringify({
        version: 1,
        state: "recovery_required",
        recovery: "import",
      })
    )
    for (const listener of listeners) {
      listener({
        key: NATIVE_MUTATION_LOCK_STORAGE_KEY,
        newValue: null,
        storageArea: localStorage,
      } as StorageEvent)
    }
    expect(observed.at(-1)).toBe("recovery_required")

    localStorage.removeItem(NATIVE_MUTATION_LOCK_STORAGE_KEY)
    for (const listener of listeners) {
      listener({
        key: NATIVE_MUTATION_LOCK_STORAGE_KEY,
        newValue: "stale-non-null-value",
        storageArea: localStorage,
      } as StorageEvent)
    }
    expect(observed.at(-1)).toBeNull()
    unsubscribe()
  } finally {
    expect(held).toBe(false)
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
  }
})
