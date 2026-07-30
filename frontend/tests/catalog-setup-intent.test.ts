import { describe, expect, test } from "bun:test"

import {
  findCatalogPresetInstalledListId,
  getCatalogPresetSourceSummary,
  getCatalogSelectionMode,
  isCatalogPresetInstalled,
  isCatalogRoutableOutboundType,
  type CatalogPreset,
} from "../src/pages/catalog-model"
import {
  createCatalogSetupIntent,
  resolveCatalogDestination,
  updateCatalogSetupRuleName,
  updateCatalogSetupSelectionName,
} from "../src/pages/catalog-setup-intent"

const presets: CatalogPreset[] = [
  { id: "instagram", name: "Instagram" },
  { id: "youtube", name: "YouTube" },
  {
    id: "ads",
    name: "Реклама",
    engines: { singbox: { action: "reject" } },
  },
]

describe("catalog setup intent", () => {
  test("offers only real egress paths as catalogue destinations", () => {
    expect(isCatalogRoutableOutboundType("interface")).toBe(true)
    expect(isCatalogRoutableOutboundType("table")).toBe(true)
    expect(isCatalogRoutableOutboundType("urltest")).toBe(true)
    expect(isCatalogRoutableOutboundType("ignore")).toBe(false)
    expect(isCatalogRoutableOutboundType("blackhole")).toBe(false)
  })

  test("contains only catalogue identities and friendly names", () => {
    expect(
      createCatalogSetupIntent({
        presets,
        selectedIds: new Set(["instagram"]),
        selectionMode: "route",
        destination: "vpn",
        directDestination: "__direct__",
        sourceDetour: " downloader ",
        combinedDisplayName: "Каталог",
      })
    ).toEqual({
      selections: [{ preset_id: "instagram", display_name: "Instagram" }],
      mode: "outbound",
      outbound_tag: "vpn",
      dns_mode: "automatic",
      source_detour_tag: "downloader",
      route_display_name: "Instagram",
      dns_display_name: "Instagram",
    })
  })

  test("direct selection adds lists without inventing route or DNS rules", () => {
    expect(
      createCatalogSetupIntent({
        presets,
        selectedIds: new Set(["instagram"]),
        selectionMode: "route",
        destination: "__direct__",
        directDestination: "__direct__",
        sourceDetour: "",
        combinedDisplayName: "Каталог",
      })
    ).toEqual({
      selections: [{ preset_id: "instagram", display_name: "Instagram" }],
      mode: "none",
      dns_mode: "none",
    })
  })

  test("blocking selection delegates blackhole creation and priority to backend", () => {
    expect(
      createCatalogSetupIntent({
        presets,
        selectedIds: new Set(["ads"]),
        selectionMode: "reject",
        destination: "vpn",
        directDestination: "__direct__",
        sourceDetour: "",
        combinedDisplayName: "Каталог",
      })
    ).toEqual({
      selections: [{ preset_id: "ads", display_name: "Реклама" }],
      mode: "block",
      dns_mode: "none",
      route_display_name: "Реклама",
    })
  })

  test("keeps edited aliases but never exposes technical IDs", () => {
    const initial = createCatalogSetupIntent({
      presets,
      selectedIds: new Set(["instagram", "youtube"]),
      selectionMode: "route",
      destination: "vpn",
      directDestination: "__direct__",
      sourceDetour: "",
      combinedDisplayName: "Два списка",
    })
    if (!initial) throw new Error("expected intent")

    const renamed = updateCatalogSetupRuleName(
      updateCatalogSetupSelectionName(initial, "instagram", " Meta "),
      "route_display_name",
      " Соцсети "
    )

    expect(renamed.selections).toEqual([
      { preset_id: "instagram", display_name: "Meta" },
      { preset_id: "youtube", display_name: "YouTube" },
    ])
    expect(renamed.route_display_name).toBe("Соцсети")
    expect(JSON.stringify(renamed)).not.toContain("technical")
  })

  test("rejects stale selections that are absent from the loaded catalogue", () => {
    expect(
      createCatalogSetupIntent({
        presets,
        selectedIds: new Set(["missing"]),
        selectionMode: "route",
        destination: "vpn",
        directDestination: "__direct__",
        sourceDetour: "",
        combinedDisplayName: "Каталог",
      })
    ).toBeNull()
  })

  test("falls back to list-only setup when no routable output exists", () => {
    expect(resolveCatalogDestination("", [], "__direct__")).toBe("__direct__")
  })

  test("recognises a live catalogue CIDR-only preset", () => {
    const cloudflareIps: CatalogPreset = {
      id: "cloudflare-ips",
      name: "Cloudflare IPs",
      engines: {
        dns: {
          subnets: ["1.1.1.0/24", "2606:4700::/32"],
        },
      },
    }

    expect(getCatalogPresetSourceSummary(cloudflareIps)).toEqual({
      urlBacked: false,
      domainCount: 0,
      cidrCount: 2,
    })
  })

  test("recognizes catalogue provenance and exact legacy sources", () => {
    const preset: CatalogPreset = {
      id: "github",
      name: "GitHub",
      catalog_identity: "a".repeat(64),
      engines: {
        dns: {
          subscriptionUrl: "https://example.test/github.srs",
        },
      },
    }

    expect(
      isCatalogPresetInstalled(preset, {
        renamed: {
          display_name: "Любое имя",
          catalog_identity: "a".repeat(64),
        },
      })
    ).toBe(true)
    expect(
      isCatalogPresetInstalled(preset, {
        legacy: {
          url: "https://example.test/github.srs",
        },
      })
    ).toBe(true)
    expect(
      isCatalogPresetInstalled(preset, {
        other: {
          url: "https://example.test/other.srs",
        },
      })
    ).toBe(false)
  })

  test("maps catalogue refresh state only through reliable provenance or exact legacy source", () => {
    const preset: CatalogPreset = {
      id: "github",
      name: "GitHub",
      catalog_identity: "a".repeat(64),
      engines: {
        dns: {
          subscriptionUrl: "https://example.test/github.srs",
        },
      },
    }

    expect(
      findCatalogPresetInstalledListId(preset, {
        renamed_by_user: {
          catalog_identity: "a".repeat(64),
          url: "https://mirror.test/github.srs",
        },
      })
    ).toBe("renamed_by_user")
    expect(
      findCatalogPresetInstalledListId(preset, {
        legacy_exact_source: {
          url: "https://example.test/github.srs",
        },
      })
    ).toBe("legacy_exact_source")
    expect(
      findCatalogPresetInstalledListId(preset, {
        different_catalog_item: {
          catalog_identity: "b".repeat(64),
          url: "https://example.test/github.srs",
        },
      })
    ).toBeUndefined()
    expect(
      findCatalogPresetInstalledListId(preset, {
        unrelated: {
          url: "https://example.test/other.srs",
        },
      })
    ).toBeUndefined()
    expect(
      findCatalogPresetInstalledListId(
        { id: "metadata-only", name: "Metadata only" },
        { unrelated_empty_list: {} }
      )
    ).toBeUndefined()
  })

  test("keeps routing and blocking selections as separate operations", () => {
    expect(
      getCatalogSelectionMode(presets, new Set(["instagram", "ads"]))
    ).toBe("mixed")
  })
})
