import { describe, expect, it } from "bun:test"

import type { SubscriptionPreviewCandidate } from "@/api/generated/model"

import {
  classifyPastedLink,
  looksLikeWireGuardConfig,
  buildSelections,
  effectiveTag,
  initialSelectedLines,
  isSelectable,
  isValidTag,
  requiresTagOverride,
  selectionProblems,
} from "./subscription-import-model"

function candidate(
  overrides: Partial<SubscriptionPreviewCandidate> & { line: number }
): SubscriptionPreviewCandidate {
  return {
    disposition: "importable",
    scheme: "vless",
    endpoint: "a.example:443",
    remark: "NL",
    suggested_tag: `tag_${overrides.line}`,
    ...overrides,
  }
}

describe("what may be selected", () => {
  it("offers importable entries and resolvable conflicts, nothing else", () => {
    expect(isSelectable(candidate({ line: 1 }))).toBe(true)
    expect(
      isSelectable(candidate({ line: 2, disposition: "tag_conflict" }))
    ).toBe(true)
    for (const disposition of [
      "duplicate_in_document",
      "already_configured",
      "scheme_not_supported",
      "malformed",
    ] as const) {
      // A duplicate or an unsupported scheme does not become sensible
      // because it has a checkbox.
      expect(isSelectable(candidate({ line: 3, disposition }))).toBe(false)
    }
  })

  it("preselects the importable and leaves conflicts to a decision", () => {
    const selected = initialSelectedLines([
      candidate({ line: 1 }),
      candidate({ line: 2, disposition: "tag_conflict" }),
      candidate({ line: 3, disposition: "already_configured" }),
      candidate({ line: 4 }),
    ])
    expect([...selected].sort()).toEqual([1, 4])
  })
})

describe("what blocks the apply button", () => {
  it("demands a rename for a selected conflict", () => {
    const candidates = [
      candidate({ line: 1, disposition: "tag_conflict" }),
    ]
    expect(
      selectionProblems(candidates, new Set([1]), new Map())
    ).toEqual([{ line: 1, kind: "tag_required" }])
    expect(
      selectionProblems(candidates, new Set([1]), new Map([[1, "fresh"]]))
    ).toEqual([])
    // An unselected conflict blocks nothing.
    expect(selectionProblems(candidates, new Set(), new Map())).toEqual([])
  })

  it("does not accept the flagged name itself as the resolution", () => {
    // Retyping the very tag the preview called taken would pass a bare
    // non-empty check and fail per-entry at the manager - the late failure
    // this validation exists to prevent.
    const candidates = [
      candidate({ line: 1, disposition: "tag_conflict", suggested_tag: "nl" }),
    ]
    expect(
      selectionProblems(candidates, new Set([1]), new Map([[1, "nl"]]))
    ).toEqual([{ line: 1, kind: "tag_required" }])
    expect(
      selectionProblems(candidates, new Set([1]), new Map([[1, "nl_2"]]))
    ).toEqual([])
  })

  it("refuses an override that is not a tag", () => {
    const candidates = [candidate({ line: 1 })]
    for (const bad of ["Bad", "1abc", "with-dash", "a".repeat(25)]) {
      expect(
        selectionProblems(candidates, new Set([1]), new Map([[1, bad]]))
      ).toEqual([{ line: 1, kind: "tag_invalid" }])
    }
  })

  it("catches two selections resolving to one tag", () => {
    // The operator's own edit can create the very collision the preview
    // named; it must surface before the request, not as one created entry
    // and one failed one.
    const candidates = [
      candidate({ line: 1, suggested_tag: "nl" }),
      candidate({ line: 2, suggested_tag: "de" }),
    ]
    const problems = selectionProblems(
      candidates,
      new Set([1, 2]),
      new Map([[2, "nl"]])
    )
    expect(problems).toEqual([{ line: 2, kind: "tag_duplicate" }])
  })
})

describe("what is sent", () => {
  it("sends only selected selectable lines, in document order", () => {
    const candidates = [
      candidate({ line: 1 }),
      candidate({ line: 2, disposition: "malformed" }),
      candidate({ line: 3 }),
    ]
    // Line 2 selected by a stale click on a row that later became
    // unselectable: it must not travel.
    const selections = buildSelections(
      candidates,
      new Set([1, 2, 3]),
      new Map()
    )
    expect(selections).toEqual([{ line: 1 }, { line: 3 }])
  })

  it("sends the tag only when the operator overrode it", () => {
    // The backend derives the same suggestion; sending it back would turn a
    // display default into an assertion.
    const candidates = [
      candidate({ line: 1, suggested_tag: "nl" }),
      candidate({ line: 2, suggested_tag: "de" }),
    ]
    const selections = buildSelections(
      candidates,
      new Set([1, 2]),
      new Map([
        [1, "renamed"],
        [2, "  "],
      ])
    )
    expect(selections).toEqual([{ line: 1, tag: "renamed" }, { line: 2 }])
  })
})

describe("tags and their fallback", () => {
  it("accepts exactly the transport tag pattern", () => {
    expect(isValidTag("nl_01")).toBe(true)
    expect(isValidTag("a")).toBe(true)
    expect(isValidTag("a".repeat(24))).toBe(true)
    expect(isValidTag("a".repeat(25))).toBe(false)
    expect(isValidTag("NL")).toBe(false)
    expect(isValidTag("")).toBe(false)
  })

  it("falls back from a blank override to the suggestion", () => {
    const entry = candidate({ line: 1, suggested_tag: "nl" })
    expect(effectiveTag(entry, new Map())).toBe("nl")
    expect(effectiveTag(entry, new Map([[1, "  "]]))).toBe("nl")
    expect(effectiveTag(entry, new Map([[1, "renamed"]]))).toBe("renamed")
  })

  it("requires an override exactly for conflicts", () => {
    expect(requiresTagOverride(candidate({ line: 1 }))).toBe(false)
    expect(
      requiresTagOverride(
        candidate({ line: 1, disposition: "tag_conflict" })
      )
    ).toBe(true)
  })
})

describe("what the operator pasted", () => {
  it("calls an ordinary web address a subscription", () => {
    // A share link carries its protocol in the scheme; a subscription is just
    // an address. No share-link scheme is http, so this is the whole rule.
    expect(classifyPastedLink("https://provider.example/sub")).toBe(
      "subscription"
    )
    expect(classifyPastedLink("  http://provider.example/sub  ")).toBe(
      "subscription"
    )
    expect(classifyPastedLink("HTTPS://provider.example/sub")).toBe(
      "subscription"
    )
  })

  it("calls everything else a share link", () => {
    // Deliberately not a list of known schemes: that list would need updating
    // for every new protocol, and the failure mode would be treating a new one
    // as a subscription address.
    for (const link of [
      "vless://u@a.example:443#One",
      "vmess://eyJ2IjoiMiJ9",
      "trojan://secret@c.example:8443",
      "ss://YWVzOnBhc3M@d.example:8388",
      "hy2://e.example:443",
      "tuic://f.example:443",
      "anytls://g.example:443",
      "socks://h.example:1080",
      "vpn://amnezia-payload",
      "wireguard://i.example",
    ]) {
      expect(classifyPastedLink(link), link).toBe("share-link")
    }
  })

  it("says nothing about an empty field", () => {
    expect(classifyPastedLink("")).toBe("empty")
    expect(classifyPastedLink("   ")).toBe("empty")
  })

  it("recognises a WireGuard configuration by its section header", () => {
    expect(looksLikeWireGuardConfig("[Interface]\nPrivateKey = x\n")).toBe(true)
    expect(looksLikeWireGuardConfig("\n  [Peer]\nPublicKey = y\n")).toBe(true)
    // A subscription file is not one, and must reach the planner that can name
    // what it actually is.
    expect(
      looksLikeWireGuardConfig("vless://u@a.example:443#One\nvmess://x\n")
    ).toBe(false)
    expect(looksLikeWireGuardConfig("dmxlc3M6Ly9hYmM=")).toBe(false)
    expect(looksLikeWireGuardConfig("")).toBe(false)
  })
})
