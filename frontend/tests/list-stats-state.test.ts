import { describe, expect, test } from "bun:test"

import { getListStatsState } from "../src/pages/lists-utils"

describe("list stats state", () => {
  test("a list stored in the configuration is counted, even when empty", () => {
    expect(
      getListStatsState({
        stats: { totalHosts: 0, ipv4Subnets: 0, ipv6Subnets: 0 },
      })
    ).toBe("counted")
  })

  test("a downloaded list reports that it arrived, not a count we do not have", () => {
    expect(getListStatsState({ lastUpdated: "2026-08-04T10:02:14Z" })).toBe(
      "loaded"
    )
  })

  // Это и есть та пара, которую раньше было не различить: оба показывались
  // прочерком, и пустой список выглядел так же, как ни разу не скачавшийся.
  test("a list that never downloaded is not the same as an empty one", () => {
    expect(getListStatsState({})).toBe("notLoaded")
    expect(getListStatsState({ lastUpdated: "" })).toBe("notLoaded")
  })
})
