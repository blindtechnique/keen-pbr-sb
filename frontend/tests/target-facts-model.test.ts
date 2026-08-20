import { describe, expect, test } from "bun:test"

import {
  nfqwsVerdict,
  registryVerdict,
  summariseNfqwsCoverage,
} from "../src/components/overview/target-facts-model"

const match = (
  role: string,
  includes: boolean,
  entry = "youtube.com"
): never =>
  ({
    list: `/opt/etc/nfqws2/lists/${role}.list`,
    role,
    includes,
    entry,
    matched: "www.youtube.com",
    exact: false,
  }) as never

describe("nfqws coverage", () => {
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

  test("an exclude match wins the summary over a covering one", () => {
    // This is what nfqws actually does: the exclude list is consulted and the
    // traffic is left alone. Saying "covered" would send someone debugging a
    // strategy that never runs on this domain.
    const coverage = summariseNfqwsCoverage({
      available: true,
      matches: [match("hostlist", true), match("hostlist_exclude", false)],
    } as never)
    expect(nfqwsVerdict(coverage)).toBe("excluded")
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
