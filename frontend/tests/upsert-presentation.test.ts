import { describe, expect, test } from "bun:test"

import { buildAdvancedEditorHref } from "../src/lib/upsert-presentation"

describe("upsert presentation links", () => {
  test("opens the same entity in the full-page editor", () => {
    expect(buildAdvancedEditorHref("/lists/geosite_ai/edit", "")).toBe(
      "/lists/geosite_ai/edit?view=page"
    )
  })

  test("preserves unrelated deep-link parameters", () => {
    expect(
      buildAdvancedEditorHref(
        "/routing-rules/rule_ai/edit",
        "returnTo=%2Fcatalog&tab=rules"
      )
    ).toBe(
      "/routing-rules/rule_ai/edit?returnTo=%2Fcatalog&tab=rules&view=page"
    )
  })

  test("replaces an existing presentation without duplicating the query", () => {
    expect(
      buildAdvancedEditorHref(
        "/dns-servers/cloudflare/edit?view=dialog&tab=servers",
        "ignored=true"
      )
    ).toBe("/dns-servers/cloudflare/edit?view=page&tab=servers")
  })
})
