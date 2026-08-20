import { afterEach, describe, expect, test } from "bun:test"

import {
  NATIVE_MUTATION_LOCK_STORAGE_KEY,
  beginNativeMutationPending,
  clearNativeMutationPending,
} from "./native-mutation-lock"

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

const localStorage = new MemoryStorage()
const sessionStorage = new MemoryStorage()

Object.defineProperty(globalThis, "window", {
  configurable: true,
  value: {
    addEventListener: () => undefined,
    localStorage,
    removeEventListener: () => undefined,
    sessionStorage,
  },
})

afterEach(() => {
  localStorage.clear()
  sessionStorage.clear()
})

describe("native mutation crash recovery lock", () => {
  test("matching recovery may replace an orphan pending marker, but not a live local request", () => {
    localStorage.setItem(
      NATIVE_MUTATION_LOCK_STORAGE_KEY,
      JSON.stringify({
        version: 1,
        state: "pending",
        operation: "import",
        token: "a".repeat(32),
      })
    )

    expect(beginNativeMutationPending("delete_recovery")).toBeNull()
    const recovered = beginNativeMutationPending("import_recovery")
    expect(recovered).not.toBeNull()
    expect(beginNativeMutationPending("import_recovery")).toBeNull()

    expect(clearNativeMutationPending(recovered!)).toBe(true)
    const liveImport = beginNativeMutationPending("import")
    expect(liveImport).not.toBeNull()
    expect(beginNativeMutationPending("import_recovery")).toBeNull()
    expect(clearNativeMutationPending(liveImport!)).toBe(true)
  })
})
