import { describe, expect, test } from "bun:test"

import { getDataTableMobileColumnLayout } from "../src/components/shared/data-table-mobile-layout"

describe("DataTable mobile column layout", () => {
  test("an explicitly labelled switch remains a control and the name is the title", () => {
    expect(
      getDataTableMobileColumnLayout(
        ["Enabled", "Name", "Criteria", "Server"],
        4,
        { titleColumn: 1, controlColumns: [0] }
      )
    ).toEqual({
      titleIndex: 1,
      controlIndices: [0],
      detailIndices: [2, 3],
    })
  })

  test("legacy tables still infer controls from empty headers", () => {
    expect(getDataTableMobileColumnLayout(["", "Name", "Status"], 3)).toEqual({
      titleIndex: 1,
      controlIndices: [0],
      detailIndices: [2],
    })
  })

  test("invalid explicit indexes cannot hide all row content", () => {
    expect(
      getDataTableMobileColumnLayout(["Name", "Status"], 2, {
        titleColumn: 9,
        controlColumns: [-1, 8],
      })
    ).toEqual({
      titleIndex: 0,
      controlIndices: [],
      detailIndices: [1],
    })
  })
})
