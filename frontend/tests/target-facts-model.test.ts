import { describe, expect, test } from "bun:test"

import {
  nfqwsVerdict,
  registryVerdict,
  summariseNfqwsCoverage,
  nfqwsProfileResult,
} from "../src/components/overview/target-facts-model"

const match = (role: string, includes: boolean, entry = "youtube.com"): never =>
  ({
    list: `/opt/etc/nfqws2/lists/${role}.list`,
    role,
    includes,
    entry,
    matched: "www.youtube.com",
    exact: false,
  }) as never

describe("nfqws coverage", () => {
  test("profile-only membership is retained and duplicate evidence is collapsed", () => {
    const include = match("hostlist", true)
    const exclude = match("hostlist_exclude", false)
    const coverage = summariseNfqwsCoverage({
      available: true,
      matches: [include],
      profiles: [{ index: 1, matches: [include, exclude] }],
    } as never)
    expect(coverage.covering).toHaveLength(1)
    expect(coverage.excluding).toHaveLength(1)
  })

  test("whitelist membership requires its own positive evidence", () => {
    expect(registryVerdict({ checked: true, blocked: false })).toBe(
      "not-listed"
    )
    expect(
      registryVerdict({ checked: true, blocked: false, whitelisted: true })
    ).toBe("whitelisted")
    expect(registryVerdict({ checked: false, whitelisted: true })).toBe(
      "not-checked"
    )
    expect(
      registryVerdict({ checked: true, blocked: true, whitelisted: true })
    ).toBe("listed")
  })
  test("an exclusion in another profile cannot prove a global bypass", () => {
    const coverage = summariseNfqwsCoverage({
      available: true,
      matches: [match("hostlist_exclude", false), match("ipset", true)],
      profiles: [
        { index: 1, list_result: "matched", matches: [match("ipset", true)] },
        {
          index: 2,
          list_result: "excluded",
          matches: [match("hostlist_exclude", false)],
        },
      ],
    } as never)
    expect(nfqwsVerdict(coverage)).toBe("mixed")
  })

  test("an unreadable nfqws config is unknown, not uncovered", () => {
    // "nfqws is not handling this" and "we could not tell" send someone to
    // different places, so they must not render the same.
    const coverage = summariseNfqwsCoverage({
      available: false,
      matches: [],
    } as never)
    expect(coverage.known).toBe(false)
    expect(nfqwsVerdict(coverage)).toBe("unknown")
  })

  test("a concurrent nfqws scan is busy, not unreadable", () => {
    const coverage = summariseNfqwsCoverage({
      available: false,
      reason: "busy",
      matches: [],
    } as never)
    expect(coverage.known).toBe(false)
    expect(coverage.reason).toBe("busy")
    expect(nfqwsVerdict(coverage)).toBe("busy")
  })

  test("covering and excluding lists are kept apart", () => {
    const coverage = summariseNfqwsCoverage({
      available: true,
      matches: [
        match("hostlist", true),
        match("hostlist_auto", true),
        match("hostlist_exclude", false),
        match("ipset", true),
        match("ipset_exclude", false),
      ],
    } as never)
    expect(coverage.covering).toHaveLength(3)
    expect(coverage.excluding).toHaveLength(2)
  })

  test("old flat evidence cannot establish global exclusion precedence", () => {
    const coverage = summariseNfqwsCoverage({
      available: true,
      matches: [match("hostlist", true), match("hostlist_exclude", false)],
    } as never)
    expect(nfqwsVerdict(coverage)).toBe("mixed")
  })

  test("unknown and IP-dependent profile results stay distinct", () => {
    for (const [result, verdict] of [
      ["unknown", "unknown"],
      ["future_result", "unknown"],
      ["mixed", "mixed"],
      ["matched", "covered"],
      ["excluded", "excluded"],
      ["hostname_required", "unknown"],
      ["ip_required", "unknown"],
      ["auto_pending", "uncovered"],
      ["unmatched", "uncovered"],
    ]) {
      const profile = { list_result: result, has_actions: true } as never
      const coverage = summariseNfqwsCoverage({
        available: true,
        matches: [],
        profiles: [profile],
      } as never)
      expect(nfqwsVerdict(coverage)).toBe(verdict)
    }
    expect(nfqwsProfileResult({ list_result: "future_result" } as never)).toBe(
      "unknown"
    )
  })

  test("no match at all is uncovered", () => {
    const coverage = summariseNfqwsCoverage({
      available: true,
      matches: [],
    } as never)
    expect(nfqwsVerdict(coverage)).toBe("uncovered")
  })
})

describe("registry verdict", () => {
  test("a lookup that did not run is never reported as not listed", () => {
    expect(registryVerdict({ checked: false })).toBe("not-checked")
    // The dangerous shape: no verdict at all, which a naive read of `blocked`
    // would turn into a clean bill of health.
    expect(registryVerdict({ checked: false, blocked: undefined })).toBe(
      "not-checked"
    )
  })

  test("listed, absent, and absent-but-behind-a-blocked-prefix differ", () => {
    expect(registryVerdict({ checked: true, blocked: true })).toBe("listed")
    expect(
      registryVerdict({ checked: true, blocked: false, blocked_subnets: [] })
    ).toBe("not-listed")
    // The case that explains an outage the domain's own status does not.
    expect(
      registryVerdict({
        checked: true,
        blocked: false,
        blocked_subnets: ["104.21.32.0/24"],
      })
    ).toBe("subnet-only")
  })
})
