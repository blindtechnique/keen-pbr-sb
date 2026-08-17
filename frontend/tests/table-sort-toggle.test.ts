import { describe, expect, test } from "bun:test"

import { nextTableSortState } from "../src/hooks/use-table-sort"

describe("table sort toggle", () => {
  test("the first click on a column sorts it ascending", () => {
    expect(nextTableSortState({ activeColumn: null, direction: "asc" }, 2)).toEqual(
      { activeColumn: 2, direction: "asc" }
    )
  })

  test("the second click on the same column reverses the order", () => {
    expect(nextTableSortState({ activeColumn: 2, direction: "asc" }, 2)).toEqual(
      { activeColumn: 2, direction: "desc" }
    )
  })

  // В конфигураторе выбранная колонка остаётся выбранной до перезагрузки
  // страницы. Третий клик, снимавший сортировку, читался как сбой — значок
  // пропадал, а строки прыгали в порядок, которого никто не просил.
  test("the third click reverses again instead of clearing the sort", () => {
    expect(nextTableSortState({ activeColumn: 2, direction: "desc" }, 2)).toEqual(
      { activeColumn: 2, direction: "asc" }
    )
  })

  test("another column starts ascending again", () => {
    expect(nextTableSortState({ activeColumn: 2, direction: "desc" }, 5)).toEqual(
      { activeColumn: 5, direction: "asc" }
    )
  })
})
