import { describe, expect, test } from "bun:test"
import {
  buildListPageRequest,
  LIST_PAGE_SIZE,
} from "../src/pages/lists-pagination"
import {
  pruneSelectedIds,
  toggleSelectedId,
} from "../src/hooks/use-row-selection"
import { nextTableSortState } from "../src/hooks/use-table-sort"
import { buildListDeleteTargets } from "../src/pages/lists-utils"

describe("routing list pagination", () => {
  test("requests only a bounded page with global search and ordering", () => {
    expect(
      buildListPageRequest("  ТЕЛЕГРАМ AWG  ", 50, {
        activeColumn: 0,
        direction: "desc",
      })
    ).toEqual({
      search: "ТЕЛЕГРАМ AWG",
      offset: 50,
      limit: LIST_PAGE_SIZE,
      sort: "name",
      order: "desc",
    })
    expect(LIST_PAGE_SIZE).toBe(50)
    expect(
      buildListPageRequest(" ", 0, {
        activeColumn: null,
        direction: "asc",
      })
    ).toEqual({
      search: undefined,
      offset: 0,
      limit: 50,
      sort: "id",
      order: "asc",
    })
  })

  test("source header switches server ordering and keeps the two-state sort", () => {
    const next = nextTableSortState({ activeColumn: null, direction: "asc" }, 1)
    expect(buildListPageRequest("", 0, next).sort).toBe("source")
    expect(buildListPageRequest("", 0, nextTableSortState(next, 1)).order).toBe(
      "desc"
    )
  })

  test("selection and delete targets stay stable across pages, not row indexes", () => {
    const allIds = ["page1_list", "page2_list", "untouched"]
    const selected = toggleSelectedId(
      new Set(["page1_list"]),
      allIds,
      "page2_list"
    )
    expect([...pruneSelectedIds(selected, allIds)]).toEqual([
      "page1_list",
      "page2_list",
    ])
    expect(buildListDeleteTargets(selected)).toEqual([
      { list_id: "page1_list", replacement_list_id: undefined },
      { list_id: "page2_list", replacement_list_id: undefined },
    ])
    expect([
      ...pruneSelectedIds(selected, ["page2_list", "untouched"]),
    ]).toEqual(["page2_list"])
  })
})
