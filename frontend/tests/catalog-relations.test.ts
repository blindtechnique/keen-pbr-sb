import { describe, expect, test } from "bun:test"

import {
  applyCatalogSelectionToggle,
  canSelectCatalogPreset,
  findNearestCatalogAncestor,
  getCatalogDescendantIds,
  getCatalogRoutingCompanionSourceSummaries,
  getCatalogPresetSourceSummary,
  matchesCatalogSearch,
  normalizeCatalogSelection,
  resolveCatalogInstallStates,
  resolveSelectedCatalogRoutingCompanions,
  type CatalogPreset,
} from "../src/pages/catalog-model"

const parentIdentity = "a".repeat(64)
const companionIdentity = "b".repeat(64)
const childIdentity = "c".repeat(64)

const catalog: CatalogPreset[] = [
  {
    id: "meta",
    name: "Meta",
    catalog_identity: parentIdentity,
    covers: ["instagram", "whatsapp"],
    routingCompanions: [
      {
        id: "meta_whatsapp_ip",
        name: "Meta / WhatsApp IP",
        catalog_identity: companionIdentity,
        include: "ip_cidrs",
        sourcePresetId: "whatsapp-ip-source",
      },
    ],
    engines: {
      singbox: {
        ruleSets: [
          { tag: "geosite-meta", url: "https://example.test/meta.srs" },
        ],
      },
    },
  },
  {
    id: "instagram",
    name: "Instagram",
    covers: ["instagram-cdn"],
    engines: {
      dns: { domains: ["instagram.com"] },
    },
  },
  {
    id: "instagram-cdn",
    name: "Instagram CDN",
    catalog_identity: childIdentity,
    engines: {
      dns: { domains: ["cdninstagram.com"] },
    },
  },
  {
    id: "whatsapp",
    name: "WhatsApp",
    routingCompanions: [
      {
        id: "whatsapp_ip",
        name: "WhatsApp IP",
        catalog_identity: companionIdentity,
        include: "ip_cidrs",
        sourcePresetId: "whatsapp-ip-source",
      },
    ],
    engines: {
      dns: { domains: ["whatsapp.com"] },
    },
  },
  {
    id: "telegram",
    name: "Telegram",
    routingCompanions: [
      {
        id: "telegram_ip",
        name: "Telegram IP",
        kind: "ip",
        url: "https://example.test/geoip-telegram.srs",
      },
    ],
    engines: {
      dns: { domains: ["telegram.org"] },
    },
  },
  {
    id: "whatsapp-ip-source",
    name: "WhatsApp IP source",
    hidden: true,
    engines: {
      dns: { subnets: ["31.13.64.0/18", "157.240.0.0/16"] },
    },
  },
]

describe("catalog relationships", () => {
  test("finds related KinoPub presets by stable ID and explanatory notice", () => {
    const presets: CatalogPreset[] = [
      {
        id: "kinopub",
        name: "Kino.pub",
        notice: "Полный сервис, включая CDN",
      },
      {
        id: "kinopub-core",
        name: "KinoPub без CDN",
        notice: "Сайт, API и управляющие зеркала",
      },
      { id: "netflix", name: "Netflix" },
    ]

    expect(
      presets.filter((preset) => matchesCatalogSearch(preset, "kinopub"))
    ).toHaveLength(2)
    expect(matchesCatalogSearch(presets[0], "полный сервис")).toBe(true)
    expect(matchesCatalogSearch(presets[2], "kinopub")).toBe(false)
  })

  test("resolves transitive descendants without looping on malformed cycles", () => {
    const withCycle: CatalogPreset[] = [
      ...catalog,
      { id: "cycle-a", name: "A", covers: ["cycle-b"] },
      { id: "cycle-b", name: "B", covers: ["cycle-a"] },
    ]

    expect([...getCatalogDescendantIds(catalog, "meta")].sort()).toEqual([
      "instagram",
      "instagram-cdn",
      "whatsapp",
    ])
    expect([...getCatalogDescendantIds(withCycle, "cycle-a")]).toEqual([
      "cycle-b",
    ])
  })

  test("selecting an aggregate removes children and blocks redundant toggles", () => {
    const parentSelected = applyCatalogSelectionToggle(
      catalog,
      new Set(["instagram", "instagram-cdn", "whatsapp"]),
      "meta"
    )
    expect([...parentSelected]).toEqual(["meta"])

    const blockedChild = applyCatalogSelectionToggle(
      catalog,
      parentSelected,
      "instagram-cdn"
    )
    expect([...blockedChild]).toEqual(["meta"])
    expect(
      findNearestCatalogAncestor(catalog, "instagram-cdn", parentSelected)?.id
    ).toBe("meta")
  })

  test("normalizes stale multi-selection regardless of insertion order", () => {
    expect([
      ...normalizeCatalogSelection(catalog, new Set(["instagram-cdn", "meta"])),
    ]).toEqual(["meta"])
  })

  test("chooses the nearest ancestor and uses stable IDs to break equal-depth ties", () => {
    const overlapping: CatalogPreset[] = [
      { id: "z-parent", name: "Z", covers: ["leaf"] },
      { id: "a-parent", name: "A", covers: ["leaf"] },
      { id: "root", name: "Root", covers: ["a-parent"] },
      { id: "leaf", name: "Leaf" },
    ]

    expect(
      findNearestCatalogAncestor(
        overlapping,
        "leaf",
        new Set(["root", "z-parent", "a-parent"])
      )?.id
    ).toBe("a-parent")
  })

  test("requires both the primary and every companion for full installation", () => {
    const partial = resolveCatalogInstallStates(catalog, {
      meta_primary: { catalog_identity: parentIdentity },
    })
    expect(partial.get("meta")).toMatchObject({
      kind: "partial",
      primaryListId: "meta_primary",
      missingCompanionIds: ["meta_whatsapp_ip"],
    })
    expect(partial.get("whatsapp")?.kind).toBe("missing")

    const installed = resolveCatalogInstallStates(catalog, {
      meta_primary: { catalog_identity: parentIdentity },
      meta_ips: { catalog_identity: companionIdentity },
    })
    expect(installed.get("meta")).toMatchObject({
      kind: "installed",
      primaryListId: "meta_primary",
      companionListIds: ["meta_ips"],
      missingCompanionIds: [],
    })
    expect(installed.get("instagram")?.kind).toBe("covered")
    expect(installed.get("instagram")?.coveredBy?.id).toBe("meta")
    expect(installed.get("instagram-cdn")?.kind).toBe("covered")
    expect(installed.get("instagram-cdn")?.coveredBy?.id).toBe("meta")
    expect(installed.get("whatsapp")?.kind).toBe("covered")
    expect(installed.get("whatsapp")?.coveredBy?.id).toBe("meta")
  })

  test("exact child installation wins over an installed aggregate", () => {
    const installed = resolveCatalogInstallStates(catalog, {
      meta_primary: { catalog_identity: parentIdentity },
      meta_ips: { catalog_identity: companionIdentity },
      instagram_cdn: { catalog_identity: childIdentity },
    })

    expect(installed.get("instagram-cdn")).toMatchObject({
      kind: "installed",
      primaryListId: "instagram_cdn",
    })
  })

  test("blocks covered entries while leaving exact and partial repair selectable", () => {
    const partial = resolveCatalogInstallStates(catalog, {
      meta_primary: { catalog_identity: parentIdentity },
    })
    expect(canSelectCatalogPreset(partial.get("meta"), undefined)).toBe(true)

    const installed = resolveCatalogInstallStates(catalog, {
      meta_primary: { catalog_identity: parentIdentity },
      meta_ips: { catalog_identity: companionIdentity },
    })
    expect(canSelectCatalogPreset(installed.get("meta"), undefined)).toBe(true)
    expect(canSelectCatalogPreset(installed.get("whatsapp"), undefined)).toBe(
      false
    )
    expect(
      canSelectCatalogPreset(
        { kind: "missing", companionListIds: [], missingCompanionIds: [] },
        catalog[0]
      )
    ).toBe(false)
  })

  test("describes the extra IP unit without hiding the primary source", () => {
    expect(getCatalogPresetSourceSummary(catalog[0])).toEqual({
      urlBacked: true,
      domainCount: 0,
      cidrCount: 0,
      companionCount: 1,
      hasIpCompanion: true,
    })

    expect(
      getCatalogRoutingCompanionSourceSummaries(catalog[0], catalog)
    ).toEqual([
      {
        id: "meta_whatsapp_ip",
        name: "Meta / WhatsApp IP",
        urlBacked: false,
        cidrCount: 2,
      },
    ])

    expect(
      getCatalogRoutingCompanionSourceSummaries(
        catalog.find((preset) => preset.id === "telegram")!,
        catalog
      )
    ).toEqual([
      {
        id: "telegram_ip",
        name: "Telegram IP",
        urlBacked: true,
        cidrCount: 0,
      },
    ])

    const selected = resolveSelectedCatalogRoutingCompanions(
      catalog,
      new Set(["meta", "telegram"])
    )
    expect([...selected.keys()]).toEqual(["meta_whatsapp_ip", "telegram_ip"])
  })
})
