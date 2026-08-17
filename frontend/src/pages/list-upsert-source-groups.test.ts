import { describe, expect, it } from "bun:test"

import {
  discardsDownloadRoute,
  getActiveSourceGroupsFromDraft,
  getDiscardedSourceGroups,
  isSourceGroupPopulated,
  narrowDraftToSourceGroups,
  type ListDraft,
} from "@/pages/list-upsert-utils"

function draft(overrides: Partial<ListDraft> = {}): ListDraft {
  return {
    displayName: "Example",
    name: "example",
    ttlMs: "7200000",
    refreshDetourMode: "inherit",
    detour: "",
    fallbackDetours: [],
    domains: "",
    ipCidrs: "",
    url: "",
    file: "",
    ...overrides,
  }
}

describe("source groups of a list draft", () => {
  it("reports every source a list actually carries", () => {
    // ListConfig says "at least one of url, domains, ip_cidrs, file", so a
    // list may legitimately arrive with several and the editor has to show
    // all of them rather than pick one.
    expect(
      getActiveSourceGroupsFromDraft(
        draft({ url: "https://example.test/a", domains: "example.com" })
      )
    ).toEqual(["url", "inline"])
    expect(
      getActiveSourceGroupsFromDraft(draft({ file: "./local.txt" }))
    ).toEqual(["file"])
  })

  it("falls back to url when a draft carries nothing yet", () => {
    expect(getActiveSourceGroupsFromDraft(draft())).toEqual(["url"])
  })

  it("counts inline entries by line, not by raw text", () => {
    expect(isSourceGroupPopulated("inline", draft({ domains: "  \n \n" }))).toBe(
      false
    )
    expect(isSourceGroupPopulated("inline", draft({ ipCidrs: "10.0.0.0/8" }))).toBe(
      true
    )
    expect(isSourceGroupPopulated("url", draft({ url: "   " }))).toBe(false)
  })
})

describe("narrowing a draft to the chosen sources", () => {
  it("keeps the chosen source and drops the others", () => {
    const wide = draft({
      url: "https://example.test/a",
      file: "./local.txt",
      domains: "example.com",
      ipCidrs: "10.0.0.0/8",
    })
    const narrowed = narrowDraftToSourceGroups(wide, ["inline"])

    expect(narrowed.domains).toBe("example.com")
    expect(narrowed.ipCidrs).toBe("10.0.0.0/8")
    expect(narrowed.url).toBe("")
    expect(narrowed.file).toBe("")
  })

  it("keeps several sources when several are chosen", () => {
    // The whole point of the set: a list that arrives with a URL and inline
    // entries must be savable with both, or the editor cannot round-trip a
    // configuration the backend accepts.
    const wide = draft({
      url: "https://example.test/a",
      file: "./local.txt",
      domains: "example.com",
    })
    const narrowed = narrowDraftToSourceGroups(wide, ["url", "inline"])

    expect(narrowed.url).toBe("https://example.test/a")
    expect(narrowed.domains).toBe("example.com")
    expect(narrowed.file).toBe("")
  })

  it("takes the download route with the url it belongs to", () => {
    // refreshDetourMode, detour and fallbackDetours describe how a URL is
    // fetched. Left behind without one they would be saved as configuration
    // for a download that cannot happen.
    const wide = draft({
      url: "https://example.test/a",
      domains: "example.com",
      refreshDetourMode: "override",
      detour: "vless_nl",
      fallbackDetours: ["wan"],
    })
    const narrowed = narrowDraftToSourceGroups(wide, ["inline"])

    expect(narrowed.refreshDetourMode).toBe("inherit")
    expect(narrowed.detour).toBe("")
    expect(narrowed.fallbackDetours).toEqual([])
  })

  it("leaves the download route alone when the url is kept", () => {
    const wide = draft({
      url: "https://example.test/a",
      refreshDetourMode: "override",
      detour: "vless_nl",
      fallbackDetours: ["wan"],
    })
    const narrowed = narrowDraftToSourceGroups(wide, ["url"])

    expect(narrowed.refreshDetourMode).toBe("override")
    expect(narrowed.detour).toBe("vless_nl")
    expect(narrowed.fallbackDetours).toEqual(["wan"])
  })

  it("does not mutate the draft it was given", () => {
    const wide = draft({ url: "https://example.test/a", domains: "example.com" })
    narrowDraftToSourceGroups(wide, ["inline"])

    expect(wide.url).toBe("https://example.test/a")
  })
})

describe("what saving would discard", () => {
  it("names only the sources that actually hold something", () => {
    const wide = draft({
      url: "https://example.test/a",
      file: "   ",
      domains: "example.com",
    })

    expect(getDiscardedSourceGroups(wide, ["url"])).toEqual(["inline"])
    expect(getDiscardedSourceGroups(wide, ["url", "inline"])).toEqual([])
  })

  it("names the download route separately from the source", () => {
    // The old prompt asked about "the currently filled fields" and never
    // mentioned this, so an operator agreed to lose a source and silently
    // lost their download route as well.
    const withRoute = draft({
      url: "https://example.test/a",
      domains: "example.com",
      refreshDetourMode: "override",
      detour: "vless_nl",
    })

    expect(discardsDownloadRoute(withRoute, ["inline"])).toBe(true)
    expect(discardsDownloadRoute(withRoute, ["url"])).toBe(false)
  })

  it("stays quiet when there is no download route to lose", () => {
    const plain = draft({ url: "https://example.test/a", domains: "a.test" })

    expect(discardsDownloadRoute(plain, ["inline"])).toBe(false)
  })

  it("notices a fallback chain even with no explicit detour", () => {
    const chained = draft({
      url: "https://example.test/a",
      fallbackDetours: ["wan"],
    })

    expect(discardsDownloadRoute(chained, ["file"])).toBe(true)
  })
})
