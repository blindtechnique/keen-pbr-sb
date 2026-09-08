import { describe, expect, test } from "bun:test"
import { createElement } from "react"
import { renderToStaticMarkup } from "react-dom/server"

import { DataTable } from "../src/components/shared/data-table"
import {
  canVirtualizeDataTable,
  getVirtualRangeWithFocus,
  getVirtualRowsLayout,
} from "../src/hooks/virtual-rows-model"

const plainTable = {
  requested: true,
  count: 100,
  hasStableKeys: true,
  hasReorder: false,
  hasGroups: false,
  hasDetails: false,
}

describe("opt-in virtual rows", () => {
  test("small and non-opted-in tables retain their ordinary body", () => {
    expect(canVirtualizeDataTable(plainTable)).toBe(true)
    expect(canVirtualizeDataTable({ ...plainTable, count: 30 })).toBe(false)
    expect(canVirtualizeDataTable({ ...plainTable, count: 31 })).toBe(true)
    expect(canVirtualizeDataTable({ ...plainTable, requested: false })).toBe(
      false
    )
    expect(
      canVirtualizeDataTable({ ...plainTable, hasStableKeys: false })
    ).toBe(false)
  })

  test("dragging, groups and details keep their full existing DOM", () => {
    for (const option of ["hasReorder", "hasGroups", "hasDetails"] as const) {
      expect(canVirtualizeDataTable({ ...plainTable, [option]: true })).toBe(
        false
      )
    }
  })

  test("a distant focused row is pinned without rendering the intervening rows", () => {
    const keys = Array.from({ length: 1000 }, (_, index) => `list-${index}`)
    const range = {
      startIndex: 500,
      endIndex: 508,
      overscan: 4,
      count: keys.length,
    }
    const visible = getVirtualRangeWithFocus(range, keys, null)
    expect(visible).toEqual(
      Array.from({ length: 17 }, (_, index) => index + 496)
    )
    expect(getVirtualRangeWithFocus(range, keys, "list-3")).toEqual([
      2,
      3,
      4,
      ...visible,
    ])
    expect(getVirtualRangeWithFocus(range, keys, "list-999")).toEqual([
      ...visible,
      998,
      999,
    ])
  })

  test("focus follows a stable key through sorting and ignores keys outside the page", () => {
    const keys = Array.from(
      { length: 100 },
      (_, index) => `list-${index}`
    ).reverse()
    const range = {
      startIndex: 40,
      endIndex: 45,
      overscan: 1,
      count: keys.length,
    }
    const visible = getVirtualRangeWithFocus(range, keys, null)
    expect(getVirtualRangeWithFocus(range, keys, "list-3")).toEqual([
      ...visible,
      95,
      96,
      97,
    ])
    expect(getVirtualRangeWithFocus(range, keys, "removed-list")).toEqual(
      visible
    )
    expect(getVirtualRangeWithFocus(range, keys, "list-99")).toEqual([
      0,
      1,
      ...visible,
    ])
  })

  test("variable heights and the main scroll offset preserve every omitted gap", () => {
    const layout = getVirtualRowsLayout(
      [
        { index: 1, key: "short", start: 160, size: 70 },
        { index: 8, key: "tall", start: 700, size: 100 },
      ],
      1000,
      120
    )
    expect(
      layout.items.map(({ start, paddingBefore }) => ({ start, paddingBefore }))
    ).toEqual([
      { start: 40, paddingBefore: 40 },
      { start: 580, paddingBefore: 470 },
    ])
    expect(layout.paddingAfter).toBe(320)
    expect(
      layout.items.reduce(
        (size, row) => size + row.size + row.paddingBefore,
        layout.paddingAfter
      )
    ).toBe(1000)
  })

  test("a focused row above or below the viewport keeps the same total body height", () => {
    for (const indexes of [
      [1, 50, 51],
      [50, 51, 99],
    ]) {
      const layout = getVirtualRowsLayout(
        indexes.map((index) => ({
          index,
          key: String(index),
          start: 200 + index * 52.5,
          size: 52.5,
        })),
        5250,
        200
      )
      expect(
        layout.items.reduce(
          (size, row) => size + row.size + row.paddingBefore,
          layout.paddingAfter
        )
      ).toBe(5250)
      expect(layout.items.every((row) => row.paddingBefore >= 0)).toBe(true)
      expect(layout.paddingAfter).toBeGreaterThanOrEqual(0)
    }
  })

  test("empty and last-row ranges produce no negative spacer", () => {
    expect(getVirtualRowsLayout([], 0, 10)).toEqual({
      items: [],
      paddingAfter: 0,
    })
    expect(
      getVirtualRowsLayout(
        [{ index: 0, key: "only", start: 10, size: 50 }],
        50,
        10
      ).paddingAfter
    ).toBe(0)
  })

  test("the opt-in table mounts a bounded initial body without duplicate mobile cards", () => {
    const keys = Array.from({ length: 1000 }, (_, index) => `list-${index}`)
    const html = renderToStaticMarkup(
      createElement(DataTable, {
        headers: ["Name"],
        rows: keys.map((key) => [key]),
        virtualize: true,
        desktopOnly: true,
        selection: {
          rowIds: keys,
          selectedIds: new Set(keys),
          getRowLabel: (key) => `Select ${key}`,
          onToggle: () => undefined,
          onToggleAll: () => undefined,
        },
      })
    )
    expect([...html.matchAll(/data-sortable-table-row=/g)].length).toBeLessThan(
      30
    )
    expect(html).toContain('aria-rowcount="1001"')
    expect(html).toContain('aria-rowindex="2"')
    expect(html).not.toContain("divide-y border-y md:hidden")
    // The header still reflects all page keys, not just the mounted viewport.
    const headerCheckbox = html.match(
      /<span\b[^>]*aria-label="Select all visible rows"[^>]*>/
    )?.[0]
    expect(headerCheckbox).toContain('aria-checked="true"')
  })

  test("table details bypass windowing and existing mobile output remains the default", () => {
    const keys = Array.from({ length: 40 }, (_, index) => `list-${index}`)
    const html = renderToStaticMarkup(
      createElement(DataTable, {
        headers: ["Name"],
        rows: keys.map((key) => [key]),
        virtualize: true,
        rowDetails: { 39: "Last row details" },
        selection: {
          rowIds: keys,
          selectedIds: new Set<string>(),
          getRowLabel: (key) => `Select ${key}`,
          onToggle: () => undefined,
          onToggleAll: () => undefined,
        },
      })
    )
    expect([...html.matchAll(/data-sortable-table-row=/g)]).toHaveLength(40)
    expect([...html.matchAll(/Last row details/g)]).toHaveLength(2)
    expect(html).toContain("divide-y border-y md:hidden")
    expect(html).not.toContain("aria-rowcount=")
  })
})
