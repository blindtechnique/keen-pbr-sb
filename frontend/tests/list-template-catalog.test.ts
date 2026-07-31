import { describe, expect, test } from "bun:test"

import listTemplates from "@/data/list-templates.json"

describe("catalog-managed ready-made list templates", () => {
  test.each(["meta", "telegram", "whatsapp"])(
    "%s opens the catalog so routing companions are not skipped",
    (id) => {
      const template = listTemplates.find((candidate) => candidate.id === id)

      expect(template).toBeDefined()
      expect(template?.catalogPresetId).toBe(id)
    }
  )
})
