import { describe, expect, test } from "bun:test"

import { formatCatalogRefreshTimestamp } from "./catalog-refresh-timestamp"

describe("formatCatalogRefreshTimestamp", () => {
  test("formats the backend epoch with date, time and seconds", () => {
    const formatted = formatCatalogRefreshTimestamp(1785501296, {
      locale: "en-GB",
      timeZone: "UTC",
    })

    expect(formatted).toMatch(/^31\/07\/2026.*12:34:56$/)
  })

  test("does not invent a timestamp when the backend has none", () => {
    expect(formatCatalogRefreshTimestamp(undefined)).toBeNull()
    expect(formatCatalogRefreshTimestamp(0)).toBeNull()
    expect(formatCatalogRefreshTimestamp(Number.NaN)).toBeNull()
  })
})
