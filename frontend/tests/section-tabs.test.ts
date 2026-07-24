import { describe, expect, test } from "bun:test"

import type { SectionTab } from "../src/components/shared/section-tabs"
import { getMobileTabPartition } from "../src/components/shared/section-tabs-utils"

type TabValue = "first" | "second" | "third" | "fourth"

const tabs: SectionTab<TabValue>[] = [
  { value: "first", label: "First" },
  { value: "second", label: "Second" },
  { value: "third", label: "Third" },
  { value: "fourth", label: "Fourth" },
]

describe("mobile section tabs", () => {
  test("keeps the leading tabs visible and puts the rest in overflow", () => {
    const result = getMobileTabPartition(tabs, "first")

    expect(result.visible.map((tab) => tab.value)).toEqual(["first", "second"])
    expect(result.overflow.map((tab) => tab.value)).toEqual(["third", "fourth"])
  })

  test("promotes a selected overflow tab without duplicating it", () => {
    const result = getMobileTabPartition(tabs, "fourth")

    expect(result.visible.map((tab) => tab.value)).toEqual(["first", "fourth"])
    expect(result.overflow.map((tab) => tab.value)).toEqual(["second", "third"])
  })
})
