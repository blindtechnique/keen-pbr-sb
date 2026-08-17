import { describe, expect, test } from "bun:test"

import { compareTableValues, sortTableItems } from "@/hooks/use-table-sort"

describe("table sort", () => {
  test("compares numbers inside text, not the text itself", () => {
    // "Список 10" must land after "Список 2", not between "Список 1" and "2".
    expect(compareTableValues("Список 2", "Список 10")).toBeLessThan(0)
    expect(compareTableValues("Список 10", "Список 9")).toBeGreaterThan(0)
  })

  test("ignores case and puts Cyrillic in alphabetical order", () => {
    expect(compareTableValues("telegram", "Telegram")).toBe(0)
    expect(compareTableValues("Аналитика", "Реклама")).toBeLessThan(0)
  })

  test("sends empty values to the end in both directions", () => {
    const rows = [{ v: "b" }, { v: undefined }, { v: "a" }]
    const column = { index: 0, get: (row: (typeof rows)[number]) => row.v }

    expect(sortTableItems(rows, column, "asc").map((row) => row.v)).toEqual([
      "a",
      "b",
      undefined,
    ])
    // Descending must not open with a screen of blanks.
    expect(sortTableItems(rows, column, "desc").map((row) => row.v)).toEqual([
      "b",
      "a",
      undefined,
    ])
  })

  test("keeps the original order of equal values", () => {
    const rows = [
      { v: "a", id: 1 },
      { v: "a", id: 2 },
      { v: "a", id: 3 },
    ]
    const column = { index: 0, get: (row: (typeof rows)[number]) => row.v }

    expect(sortTableItems(rows, column, "asc").map((row) => row.id)).toEqual([
      1, 2, 3,
    ])
    expect(sortTableItems(rows, column, "desc").map((row) => row.id)).toEqual([
      1, 2, 3,
    ])
  })

  test("returns the input untouched when no column is active", () => {
    const rows = [{ v: "b" }, { v: "a" }]
    expect(sortTableItems(rows, undefined, "asc")).toBe(rows)
  })
})
