import { describe, expect, test } from "bun:test"

import {
  safeStorageGet,
  safeStorageMatches,
  safeStorageSet,
} from "../src/lib/safe-storage"

describe("safe browser storage", () => {
  test("reads and writes when storage is available", () => {
    const values = new Map<string, string>()
    const storage = {
      getItem: (key: string) => values.get(key) ?? null,
      setItem: (key: string, value: string) => values.set(key, value),
    }

    expect(safeStorageSet(() => storage, "theme", "dark")).toBe(true)
    expect(safeStorageGet(() => storage, "theme")).toBe("dark")
    expect(
      safeStorageMatches(() => storage as Storage, storage as Storage)
    ).toBe(true)
  })

  test("contains provider, read and quota errors", () => {
    const unavailable = () => {
      throw new DOMException("blocked", "SecurityError")
    }
    const broken = {
      getItem: () => {
        throw new DOMException("blocked", "SecurityError")
      },
      setItem: () => {
        throw new DOMException("quota", "QuotaExceededError")
      },
    }

    expect(safeStorageGet(unavailable, "theme")).toBeNull()
    expect(safeStorageGet(() => broken, "theme")).toBeNull()
    expect(safeStorageSet(() => broken, "theme", "dark")).toBe(false)
    expect(safeStorageMatches(unavailable, null)).toBe(false)
  })
})
