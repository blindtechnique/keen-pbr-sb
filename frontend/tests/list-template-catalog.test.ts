import { describe, expect, test } from "bun:test"

import listTemplates from "@/data/list-templates.json"

describe("catalog-managed ready-made list templates", () => {
  test.each([
    ["meta", "meta"],
    ["telegram", "telegram"],
    ["whatsapp", "whatsapp"],
    ["kino_pub", "kinopub"],
  ])(
    "%s opens its managed catalog preset",
    (templateId, catalogPresetId) => {
      const template = listTemplates.find(
        (candidate) => candidate.id === templateId
      )

      expect(template).toBeDefined()
      expect(template?.catalogPresetId).toBe(catalogPresetId)
    }
  )
})
