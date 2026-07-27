import { describe, expect, test } from "bun:test"

import type { ConfigObject } from "../src/api/generated/model/configObject"
import {
  applyCatalogAddDraft,
  createCatalogAddDraft,
  type CatalogPreset,
} from "../src/pages/catalog-add"

const presets: CatalogPreset[] = [
  {
    id: "category-ai",
    name: "Нейросети",
    engines: {
      singbox: {
        ruleSets: [{ url: "https://example.test/category-ai.srs" }],
      },
    },
  },
]

describe("catalog aliases", () => {
  test("proposes catalogue names for the list and generated rules", () => {
    const config: ConfigObject = {
      outbounds: [{ tag: "proxy", type: "interface", interface: "tun0" }],
      dns: {
        servers: [
          {
            tag: "proxy_dns",
            display_name: "DNS через VPN",
            address: "1.1.1.1",
            detour: "proxy",
          },
        ],
        rules: [],
      },
      route: { rules: [] },
    }

    const draft = createCatalogAddDraft({
      config,
      destination: "proxy",
      directDestination: "__direct__",
      combinedDisplayName: "Каталог: 1 список",
      presets,
      selectedIds: new Set(["category-ai"]),
      sourceDetour: "proxy",
    })

    expect(draft).not.toBeNull()
    expect(draft?.lists[0]).toMatchObject({
      technicalId: "category_ai",
      displayName: "Нейросети",
    })
    expect(draft?.routeRule).toMatchObject({
      technicalId: "catalog_category_ai",
      displayName: "Нейросети",
      outbound: "proxy",
    })
    expect(draft?.dnsRule).toMatchObject({
      technicalId: "catalog_category_ai",
      displayName: "Нейросети",
      server: "proxy_dns",
    })
  })

  test("keeps technical IDs stable when the user edits accepted suggestions", () => {
    const draft = createCatalogAddDraft({
      config: {
        dns: {
          servers: [{ tag: "dns", address: "9.9.9.9", detour: "proxy" }],
          rules: [],
        },
        route: { rules: [] },
      },
      destination: "proxy",
      directDestination: "__direct__",
      combinedDisplayName: "Каталог",
      presets,
      selectedIds: new Set(["category-ai"]),
      sourceDetour: "",
    })
    if (!draft?.routeRule || !draft.dnsRule) {
      throw new Error("expected generated rule proposals")
    }

    draft.lists[0].displayName = "AI-сервисы"
    draft.routeRule.displayName = "AI через VPN"
    draft.dnsRule.displayName = "DNS для AI"

    const updated = applyCatalogAddDraft({}, draft)

    expect(updated.lists?.category_ai?.display_name).toBe("AI-сервисы")
    expect(updated.route?.rules?.[0]).toMatchObject({
      id: "catalog_category_ai",
      display_name: "AI через VPN",
      list: ["category_ai"],
    })
    expect(updated.dns?.rules?.[0]).toMatchObject({
      id: "catalog_category_ai",
      display_name: "DNS для AI",
      list: ["category_ai"],
    })
  })

  test("does not silently persist a cleared catalogue suggestion", () => {
    const draft = createCatalogAddDraft({
      config: { route: { rules: [] } },
      destination: "proxy",
      directDestination: "__direct__",
      combinedDisplayName: "Каталог",
      presets,
      selectedIds: new Set(["category-ai"]),
      sourceDetour: "",
    })
    if (!draft?.routeRule) {
      throw new Error("expected a generated routing rule proposal")
    }

    draft.lists[0].displayName = " "
    draft.routeRule.displayName = ""
    const updated = applyCatalogAddDraft({}, draft)

    expect(updated.lists?.category_ai?.display_name).toBeUndefined()
    expect(updated.route?.rules?.[0]?.display_name).toBeUndefined()
    expect(updated.route?.rules?.[0]?.id).toBe("catalog_category_ai")
  })
})
