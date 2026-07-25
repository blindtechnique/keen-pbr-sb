import { describe, expect, test } from "bun:test"

import type { ConfigObject } from "../src/api/generated/model/configObject"
import { semanticJsonEqual } from "../src/lib/semantic-json"
import {
  buildUpdatedConfigForListUpsert,
  getDraftFromMapEntry,
  getListConfigFromDraft,
  normalizeListDraftForComparison,
  type ListDraft,
} from "../src/pages/list-upsert-utils"

const baselineDraft: ListDraft = {
  displayName: "",
  name: "ai_services",
  ttlMs: "7200000",
  detour: "",
  domains: "",
  ipCidrs: "",
  url: "https://example.test/ai.srs",
  file: "",
}

describe("list aliases", () => {
  test("reads and persists a trimmed Unicode display name", () => {
    const draft = getDraftFromMapEntry("ai_services", {
      display_name: "Нейросети 🌐",
      url: "https://example.test/ai.srs",
    })

    expect(draft?.displayName).toBe("Нейросети 🌐")
    expect(
      getListConfigFromDraft({
        ...baselineDraft,
        displayName: "  Нейросети 🌐  ",
      })
    ).toMatchObject({
      display_name: "Нейросети 🌐",
      url: "https://example.test/ai.srs",
    })
  })

  test("normalizes a blank alias to an omitted API field", () => {
    const config = getListConfigFromDraft({
      ...baselineDraft,
      displayName: " \n ",
    })

    expect(config.display_name).toBeUndefined()
    expect(Object.hasOwn(config, "display_name")).toBe(false)
  })

  test("keeps the technical ID immutable while editing an alias", () => {
    const config: ConfigObject = {
      lists: {
        ai_services: {
          display_name: "Старое название",
          url: "https://example.test/ai.srs",
        },
      },
      route: {
        rules: [{ list: ["ai_services"], outbound: "proxy" }],
      },
      dns: {
        rules: [
          {
            list: ["ai_services"],
            server: "secure_dns",
            enabled: true,
            allow_domain_rebinding: false,
          },
        ],
      },
    }

    const updated = buildUpdatedConfigForListUpsert(
      config,
      "edit",
      {
        ...baselineDraft,
        displayName: "Новое название",
        name: "ignored_new_id",
      },
      "ai_services"
    )
    const list = updated.lists?.ai_services

    expect(updated.lists?.ignored_new_id).toBeUndefined()
    expect(list?.display_name).toBe("Новое название")
    expect(updated.route?.rules?.[0]?.list).toEqual(["ai_services"])
    expect(updated.dns?.rules?.[0]?.list).toEqual(["ai_services"])
  })

  test("treats whitespace-only aliases as unchanged and real edits as dirty", () => {
    const baseline = normalizeListDraftForComparison(baselineDraft)
    const whitespace = normalizeListDraftForComparison({
      ...baselineDraft,
      displayName: "   ",
    })
    const changed = normalizeListDraftForComparison({
      ...baselineDraft,
      displayName: "Нейросети",
    })
    const reverted = normalizeListDraftForComparison({
      ...baselineDraft,
      displayName: "",
    })

    expect(semanticJsonEqual(whitespace, baseline)).toBe(true)
    expect(semanticJsonEqual(changed, baseline)).toBe(false)
    expect(semanticJsonEqual(reverted, baseline)).toBe(true)
  })
})
