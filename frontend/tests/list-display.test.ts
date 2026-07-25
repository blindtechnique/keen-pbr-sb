import { describe, expect, test } from "bun:test"

import {
  formatListReferenceLabels,
  getListDisplayName,
  getListReferenceLabel,
  getListSearchText,
  sortListIdsByDisplayName,
  withListDisplayName,
} from "../src/lib/list-display"

describe("list display helpers", () => {
  const lists = {
    ai_services: {
      domains: ["example.com"],
      display_name: "AI-сервисы",
    },
    privacy: {
      domains: ["privacy.example"],
    },
    second_ai: {
      domains: ["second.example"],
      display_name: "AI-сервисы",
    },
  }

  test("uses the human-readable name without changing the technical id", () => {
    expect(getListDisplayName("ai_services", lists)).toBe("AI-сервисы")
    expect(getListDisplayName("privacy", lists)).toBe("privacy")
  })

  test("searches by both the display name and the technical id", () => {
    expect(getListSearchText("ai_services", lists)).toContain("AI-сервисы")
    expect(getListSearchText("ai_services", lists)).toContain("ai_services")
    expect(getListSearchText("privacy", lists)).toBe("privacy")
  })

  test("formats references without changing their technical ids", () => {
    expect(getListReferenceLabel("ai_services", lists)).toBe(
      "AI-сервисы (ai_services)"
    )
    expect(getListReferenceLabel("privacy", lists)).toBe("privacy")
    expect(getListReferenceLabel("missing", lists)).toBe("missing")
    expect(
      formatListReferenceLabels(["ai_services", "privacy", "missing"], lists)
    ).toBe("AI-сервисы (ai_services), privacy, missing")
  })

  test("keeps duplicate display names distinguishable and deterministically sorted", () => {
    expect(
      sortListIdsByDisplayName(["privacy", "second_ai", "ai_services"], lists)
    ).toEqual(["ai_services", "second_ai", "privacy"])
  })

  test("stores a trimmed catalogue name as presentation metadata", () => {
    expect(
      withListDisplayName({ url: "https://example.test/list.srs" }, "  AI  ")
    ).toEqual({
      url: "https://example.test/list.srs",
      display_name: "AI",
    })
  })

  test("does not persist an empty display name", () => {
    expect(
      withListDisplayName(
        {
          display_name: "Old name",
          domains: ["example.com"],
        },
        "  "
      )
    ).toEqual({
      domains: ["example.com"],
    })
  })
})
