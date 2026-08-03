import { describe, expect, test } from "bun:test"

import {
  filterBySearchQuery,
  matchesSearchQuery,
  normalizeSearchQuery,
} from "@/lib/table-search"

describe("table search", () => {
  test("an empty query keeps every row", () => {
    expect(normalizeSearchQuery("   ")).toBe("")
    expect(matchesSearchQuery(["что угодно"], "  ")).toBe(true)
    expect(filterBySearchQuery([1, 2, 3], "", () => [])).toHaveLength(3)
  })

  test("matches case-insensitively, including Cyrillic", () => {
    expect(matchesSearchQuery(["Реклама и трекеры"], "РЕКЛАМА")).toBe(true)
    expect(matchesSearchQuery(["GitHub"], "github")).toBe(true)
  })

  test("every word must match, but the words may live in different fields", () => {
    // The point of splitting: "telegram awg" means "the telegram one that goes
    // through AWG", and those two words sit in different columns. A plain
    // substring search over the joined fields would find nothing.
    const fields = ["Telegram", "AWG bound", "raw.githubusercontent.com"]
    expect(matchesSearchQuery(fields, "telegram awg")).toBe(true)
    expect(matchesSearchQuery(fields, "telegram vless")).toBe(false)
  })

  test("ignores empty fields instead of matching on them", () => {
    expect(matchesSearchQuery([undefined, null, "", "Telegram"], "tele")).toBe(
      true
    )
    expect(matchesSearchQuery([undefined, null, ""], "tele")).toBe(false)
  })

  test("filters a list by the fields the caller exposes", () => {
    const rows = [
      { name: "Telegram", source: "inline" },
      { name: "GitHub", source: "raw.githubusercontent.com" },
    ]
    const byField = (row: (typeof rows)[number]) => [row.name, row.source]

    // "github" hits the GitHub row twice — its name and its source — but a row
    // must still appear once, and Telegram must not appear at all.
    expect(filterBySearchQuery(rows, "github", byField)).toEqual([rows[1]])
    expect(filterBySearchQuery(rows, "githubusercontent", byField)).toEqual([
      rows[1],
    ])
    expect(filterBySearchQuery(rows, "inline", byField)).toEqual([rows[0]])
  })

  test("carries the original index so filtering does not renumber rows", () => {
    // DNS rules derive their name and their edit link from the row index.
    // Filtering the array itself would renumber whatever survives, so the
    // index has to travel with the row.
    const rules = [{ id: "a" }, { id: "b" }, { id: "c" }]
    const indexed = rules.map((rule, index) => ({ rule, index }))

    const visible = filterBySearchQuery(indexed, "c", (entry) => [
      entry.rule.id,
    ])

    expect(visible).toEqual([{ rule: rules[2], index: 2 }])
  })
})
