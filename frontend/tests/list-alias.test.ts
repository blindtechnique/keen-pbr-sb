import { describe, expect, test } from "bun:test"

import type { ConfigObject } from "../src/api/generated/model/configObject"
import { semanticJsonEqual } from "../src/lib/semantic-json"
import {
  addRecommendedDnsServer,
  buildUpdatedConfigForListUpsert,
  createListDnsServerSelectItems,
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
  test("creates a compatible preset DNS server in the same candidate config", () => {
    const result = addRecommendedDnsServer(
      {
        dns: {
          servers: [
            {
              tag: "cloudflare_vpn",
              display_name: "Existing DNS",
              type: "static",
              address: "9.9.9.9",
              detour: "other_vpn",
            },
          ],
        },
      },
      {
        name: "Cloudflare",
        primaryAddress: "1.1.1.1",
        technicalSeed: "cloudflare",
      },
      "vpn",
      "Основной VPN"
    )

    expect(result?.serverTag).toBe("cloudflare_vpn_2")
    expect(result?.config.dns?.servers?.[1]).toEqual({
      tag: "cloudflare_vpn_2",
      display_name: "Cloudflare · Основной VPN",
      type: "static",
      address: "1.1.1.1",
      detour: "vpn",
    })
  })

  test("reuses an exact compatible DNS definition instead of duplicating it", () => {
    const config: ConfigObject = {
      dns: {
        servers: [
          {
            tag: "existing_cloudflare",
            type: "static",
            address: "1.1.1.1",
            detour: "vpn",
          },
        ],
      },
    }
    const result = addRecommendedDnsServer(
      config,
      {
        name: "Cloudflare",
        primaryAddress: "1.1.1.1",
        technicalSeed: "cloudflare",
      },
      "vpn",
      "VPN"
    )

    expect(result).toEqual({
      config,
      serverTag: "existing_cloudflare",
    })
    expect(result?.config.dns?.servers).toHaveLength(1)
  })

  test("renders the no-DNS sentinel as a localized label", () => {
    expect(createListDnsServerSelectItems([], "Не выбрано")).toEqual([
      { value: "__none__", label: "Не выбрано" },
    ])
  })

  test("uses DNS aliases without changing persisted server tags", () => {
    expect(
      createListDnsServerSelectItems(
        [{ tag: "cloudflare", display_name: "Cloudflare" }],
        "Не выбрано"
      )
    ).toEqual([
      { value: "__none__", label: "Не выбрано" },
      { value: "cloudflare", label: "Cloudflare" },
    ])
  })

  test("derives a collision-safe technical ID from the readable name", () => {
    expect(createListDraft("Нейросети", ["neyroseti"]).name).toBe("neyroseti_2")
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

  test("keeps catalogue provenance for metadata-only edits", () => {
    const catalogIdentity = "a".repeat(64)
    const config: ConfigObject = {
      lists: {
        ai_services: {
          catalog_identity: catalogIdentity,
          display_name: "Old alias",
          ttl_ms: 7200000,
          detour: "primary",
          fallback_detours: ["backup"],
          url: "https://example.test/ai.srs",
          domains: ["chatgpt.com", "oaistatic.com"],
          ip_cidrs: ["203.0.113.0/24"],
        },
      },
    }

    const updated = buildUpdatedConfigForListUpsert(
      config,
      "edit",
      {
        displayName: "New alias",
        name: "ignored",
        ttlMs: "3600000",
        detour: "other_primary",
        fallbackDetours: ["other_backup"],
        url: "https://example.test/ai.srs",
        file: "",
        domains: "oaistatic.com\nchatgpt.com",
        ipCidrs: "203.0.113.0/24",
      },
      "ai_services"
    )

    expect(updated.lists?.ai_services?.catalog_identity).toBe(catalogIdentity)
  })

  test("clears catalogue provenance when actual list source changes", () => {
    const catalogIdentity = "b".repeat(64)
    const baseline: ConfigObject = {
      lists: {
        ai_services: {
          catalog_identity: catalogIdentity,
          url: "https://example.test/ai.srs",
          domains: ["chatgpt.com"],
          ip_cidrs: ["203.0.113.0/24"],
        },
      },
    }
    const original = getDraftFromMapEntry(
      "ai_services",
      baseline.lists?.ai_services
    )
    expect(original).not.toBeNull()

    const changedUrl = buildUpdatedConfigForListUpsert(
      baseline,
      "edit",
      {
        ...original!,
        url: "https://example.test/ai-v2.srs",
      },
      "ai_services"
    )
    expect(changedUrl.lists?.ai_services?.catalog_identity).toBeUndefined()

    const changedInlineContent = buildUpdatedConfigForListUpsert(
      baseline,
      "edit",
      {
        ...original!,
        domains: "chatgpt.com\noaistatic.com",
      },
      "ai_services"
    )
    expect(
      changedInlineContent.lists?.ai_services?.catalog_identity
    ).toBeUndefined()
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
