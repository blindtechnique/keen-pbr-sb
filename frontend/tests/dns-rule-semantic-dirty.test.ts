import { describe, expect, test } from "bun:test"

import { isSemanticallyDirty } from "../src/lib/semantic-dirty"
import { semanticJsonEqual } from "../src/lib/semantic-json"
import {
  getRuleDraft,
  normalizeDnsRuleDraft,
} from "../src/pages/dns-rules-utils"

describe("DNS rule semantic dirty state", () => {
  test("normalizes omitted defaults to the rule that is actually persisted", () => {
    const draft = getRuleDraft({
      server: "secure",
      list: ["privacy"],
    })

    expect(normalizeDnsRuleDraft(draft)).toEqual({
      enabled: true,
      server: "secure",
      list: ["privacy"],
      allow_domain_rebinding: false,
    })
  })

  test("becomes clean again after restoring the persisted rule", () => {
    const baseline = getRuleDraft({
      enabled: null,
      server: "secure",
      list: ["privacy"],
    })
    const dirty = {
      ...baseline,
      lists: ["privacy", "telemetry"],
    }
    const restored = {
      ...dirty,
      lists: ["privacy"],
    }
    const options = {
      equals: semanticJsonEqual,
      normalize: normalizeDnsRuleDraft,
    }

    expect(isSemanticallyDirty(dirty, baseline, options)).toBe(true)
    expect(isSemanticallyDirty(restored, baseline, options)).toBe(false)
  })

  test("ignores harmless whitespace, duplicates and list ordering", () => {
    const baseline = getRuleDraft({
      server: "secure",
      list: ["privacy", "telemetry"],
    })
    const equivalent = {
      ...baseline,
      server: " secure ",
      lists: ["telemetry", " privacy ", "privacy"],
    }

    expect(
      isSemanticallyDirty(equivalent, baseline, {
        equals: semanticJsonEqual,
        normalize: normalizeDnsRuleDraft,
      })
    ).toBe(false)
  })
})
