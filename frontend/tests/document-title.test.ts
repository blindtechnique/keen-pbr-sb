import { describe, expect, test } from "bun:test"

import { APP_NAME, documentTitleFor } from "@/hooks/use-document-title"

describe("browser tab title", () => {
  test("names the tab after the open section", () => {
    expect(documentTitleFor("Правила маршрутизации")).toBe(
      `Правила маршрутизации — ${APP_NAME}`
    )
  })

  test("falls back to the product name when the section is unknown", () => {
    // Screens without a plain-string heading pass nothing rather than an empty
    // section, and the tab must not read " — keen-pbr-sb".
    expect(documentTitleFor(undefined)).toBe(APP_NAME)
    expect(documentTitleFor("")).toBe(APP_NAME)
    expect(documentTitleFor("   ")).toBe(APP_NAME)
  })

  test("trims a section that carries stray whitespace", () => {
    expect(documentTitleFor("  Списки  ")).toBe(`Списки — ${APP_NAME}`)
  })
})
