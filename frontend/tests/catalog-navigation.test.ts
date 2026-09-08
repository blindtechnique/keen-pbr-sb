import { describe, expect, test } from "bun:test"
import {
  catalogNavigationOptions,
  catalogReturnHref,
  catalogSelectionAfterCreate,
  readCatalogSelectionContext,
  type CatalogSelectionContext,
} from "../src/lib/catalog-navigation"

const selection: CatalogSelectionContext = {
  selectedIds: ["youtube", "instagram"],
  search: "видео & соцсети",
  category: "media",
  destination: "vpn",
  sourceDetour: "download_vpn",
}

describe("catalogue navigation without a persistent config draft", () => {
  test("round-trips selected lists, category, search and route choices", () => {
    const options = catalogNavigationOptions(selection)
    expect(readCatalogSelectionContext(options.state)).toEqual(selection)
    expect(options.state.catalogSelection.selectedIds).not.toBe(
      selection.selectedIds
    )
    const href = catalogReturnHref(selection)
    const url = new URL(href, "http://router.example")
    expect(url.pathname).toBe("/catalog")
    expect(url.searchParams.get("search")).toBe(selection.search)
    expect(url.hash).toBe("#media")
  })

  test("an explicitly created VPN becomes a suggestion, not an automatic write", () => {
    const next = catalogSelectionAfterCreate(selection, "new_vpn")
    expect(next).toEqual({ ...selection, destination: "new_vpn" })
    expect(selection.destination).toBe("vpn")
    expect(catalogSelectionAfterCreate(selection)).toEqual(selection)
    const fresh = catalogSelectionAfterCreate(null, "new_vpn")
    expect(fresh.selectedIds).toEqual([])
    expect(fresh.destination).toBe("new_vpn")
    expect(catalogReturnHref(fresh)).toBe("/catalog#all")
  })

  test("ignores unrelated history and retains only catalogue UI fields", () => {
    for (const state of [
      null,
      undefined,
      "text",
      {},
      { catalogSelection: null },
      { catalogSelection: { selectedIds: [1] } },
    ]) {
      expect(readCatalogSelectionContext(state)).toBeNull()
    }
    const restored = readCatalogSelectionContext({
      catalogSelection: {
        ...selection,
        subscription_url: "not-copied",
        config: { outbounds: [] },
      },
    })
    expect(restored).toEqual(selection)
    expect(JSON.stringify(restored)).not.toContain("subscription_url")
    expect(JSON.stringify(restored)).not.toContain("outbounds")
  })

  test("return targets cannot replace the catalogue path or inject another URL", () => {
    const href = catalogReturnHref({
      ...selection,
      category: "//elsewhere/?x=1#oops",
      search: "https://elsewhere/",
    })
    const url = new URL(href, "http://router.example")
    expect(url.origin).toBe("http://router.example")
    expect(url.pathname).toBe("/catalog")
    expect(url.searchParams.get("search")).toBe("https://elsewhere/")
  })
})
