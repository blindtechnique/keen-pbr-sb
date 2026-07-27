import { describe, expect, test } from "bun:test"

import type { ConfigObject } from "../src/api/generated/model/configObject"
import { semanticJsonEqual } from "../src/lib/semantic-json"
import {
  buildUpdatedConfigForListUpsert,
  createListDraft,
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
  fallbackDetours: [],
  domains: "",
  ipCidrs: "",
  url: "https://example.test/ai.srs",
  file: "",
}

describe("list aliases", () => {
  test("derives a collision-safe technical ID from the readable name", () => {
    expect(createListDraft("Нейросети", ["neyroseti"]).name).toBe(
      "neyroseti_2"
    )
  })

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

  test("round-trips ordered fallback download routes", () => {
    const draft = getDraftFromMapEntry("ai_services", {
      url: "https://example.test/ai.srs",
      detour: "primary",
      fallback_detours: ["backup_a", "backup_b"],
    })

    expect(draft?.fallbackDetours).toEqual(["backup_a", "backup_b"])
    expect(
      getListConfigFromDraft({
        ...baselineDraft,
        detour: "primary",
        fallbackDetours: ["backup_a", "backup_b"],
      })
    ).toMatchObject({
      detour: "primary",
      fallback_detours: ["backup_a", "backup_b"],
    })
  })

  test("does not persist fallback routes without a primary route", () => {
    const config = getListConfigFromDraft({
      ...baselineDraft,
      detour: "",
      fallbackDetours: ["backup_a"],
    })

    expect(config.fallback_detours).toBeUndefined()
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

  test("quick setup gives the generated routing rule an alias and stable ID", () => {
    const updated = buildUpdatedConfigForListUpsert(
      { route: { rules: [] } },
      "create",
      {
        ...baselineDraft,
        displayName: "Нейросети",
      },
      undefined,
      {
        createRouteRule: true,
        routeOutbound: "proxy",
        createDnsRule: false,
        dnsServer: "",
      }
    )

    expect(updated.route?.rules?.[0]).toMatchObject({
      id: "neyroseti",
      display_name: "Нейросети",
      outbound: "proxy",
    })
  })

  test("quick setup gives the generated DNS rule an alias and stable ID", () => {
    const updated = buildUpdatedConfigForListUpsert(
      { dns: { rules: [] } },
      "create",
      {
        ...baselineDraft,
        displayName: "Нейросети",
      },
      undefined,
      {
        createRouteRule: false,
        routeOutbound: "",
        createDnsRule: true,
        dnsServer: "cloudflare",
      }
    )

    expect(updated.dns?.rules?.[0]).toMatchObject({
      id: "neyroseti",
      display_name: "Нейросети",
      server: "cloudflare",
    })
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
