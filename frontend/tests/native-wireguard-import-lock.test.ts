import { expect, test } from "bun:test"

import {
  NATIVE_WIREGUARD_IMPORT_LOCK_STORAGE_KEY,
  beginNativeWireGuardImportPending,
  clearNativeWireGuardImportPending,
  latchNativeWireGuardImportLock,
  readNativeWireGuardImportLock,
  subscribeNativeWireGuardImportLock,
  type NativeWireGuardImportPendingToken,
} from "@/lib/native-wireguard-import-lock"

test("native import pending and ambiguity remain serialized and fail closed", () => {
  let rejectWrites = false
  const makeStorage = (): Storage => {
    const values = new Map<string, string>()
    return {
      get length() {
        return values.size
      },
      clear: () => values.clear(),
      getItem: (key) => values.get(key) ?? null,
      key: (index) => [...values.keys()][index] ?? null,
      removeItem: (key) => void values.delete(key),
      setItem: (key, value) => {
        if (rejectWrites) throw new DOMException("storage unavailable")
        values.set(key, value)
      },
    }
  }
  const localStorage = makeStorage()
  const sessionStorage = makeStorage()
  const listeners = new Set<(event: StorageEvent) => void>()
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window")
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {
      localStorage,
      sessionStorage,
      addEventListener: (type: string, listener: (event: StorageEvent) => void) => {
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

  try {
    expect(readNativeWireGuardImportLock()).toBeNull()

    const pending = beginNativeWireGuardImportPending()
    expect(pending).not.toBeNull()
    expect(readNativeWireGuardImportLock()).toBe("pending")
    expect(
      localStorage.getItem(NATIVE_WIREGUARD_IMPORT_LOCK_STORAGE_KEY)
    ).toBe(`pending:${pending}`)
    expect(beginNativeWireGuardImportPending()).toBeNull()
    expect(
      clearNativeWireGuardImportPending(
        "another-operation" as NativeWireGuardImportPendingToken
      )
    ).toBe(false)
    expect(readNativeWireGuardImportLock()).toBe("pending")

    expect(clearNativeWireGuardImportPending(pending!)).toBe(true)
    expect(readNativeWireGuardImportLock()).toBeNull()

    rejectWrites = true
    expect(beginNativeWireGuardImportPending()).toBeNull()
    expect(readNativeWireGuardImportLock()).toBe("unknown")
    expect(
      localStorage.getItem(NATIVE_WIREGUARD_IMPORT_LOCK_STORAGE_KEY)
    ).toBeNull()
    rejectWrites = false

    let observed: string | null = null
    const unsubscribe = subscribeNativeWireGuardImportLock((reason) => {
      observed = reason
    })
    localStorage.setItem(NATIVE_WIREGUARD_IMPORT_LOCK_STORAGE_KEY, "unknown")
    for (const listener of listeners) {
      listener({
        key: NATIVE_WIREGUARD_IMPORT_LOCK_STORAGE_KEY,
        newValue: "unknown",
        storageArea: localStorage,
      } as StorageEvent)
    }
    expect(observed).toBe("unknown")
    expect(readNativeWireGuardImportLock()).toBe("unknown")
    expect(beginNativeWireGuardImportPending()).toBeNull()
    unsubscribe()

    latchNativeWireGuardImportLock("recovery_required")
    expect(readNativeWireGuardImportLock()).toBe("recovery_required")
    expect(beginNativeWireGuardImportPending()).toBeNull()
    expect(
      localStorage.getItem(NATIVE_WIREGUARD_IMPORT_LOCK_STORAGE_KEY)
    ).toBe("recovery_required")
  } finally {
    if (originalWindow) {
      Object.defineProperty(globalThis, "window", originalWindow)
    } else {
      Reflect.deleteProperty(globalThis, "window")
    }
  }
})
