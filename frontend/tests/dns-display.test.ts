import { describe, expect, test } from "bun:test"

import {
  createDnsServerDisplayNameMap,
  getDnsRuleDisplayName,
  getDnsRuleTechnicalId,
  getDnsServerDisplayName,
  getDnsServerSearchText,
} from "../src/lib/dns-display"

describe("DNS display identities", () => {
  test("uses aliases in presentation while keeping tags searchable", () => {
    const server = {
      tag: "dns_cf",
      display_name: "Cloudflare",
      address: "1.1.1.1",
    }

    expect(getDnsServerDisplayName(server)).toBe("Cloudflare")
    expect(createDnsServerDisplayNameMap([server]).get("dns_cf")).toBe(
      "Cloudflare"
    )
    expect(getDnsServerSearchText(server)).toContain("dns_cf")
  })

  test("uses stable rule ids for selection and aliases for labels", () => {
    const rule = {
      id: "dns_ai",
      display_name: "Нейросети",
    }

    expect(getDnsRuleTechnicalId(rule, 0)).toBe("id:dns_ai")
    expect(getDnsRuleDisplayName(rule, 0)).toBe("Нейросети")
  })

  test("keeps legacy rules usable without exposing an empty label", () => {
    expect(getDnsRuleTechnicalId(undefined, 2)).toBe("index:2")
    expect(getDnsRuleDisplayName(undefined, 2)).toBe("DNS 3")
  })

  test("keeps stable and legacy selection identities disjoint", () => {
    expect(getDnsRuleTechnicalId({ id: "legacy_dns_2" }, 0)).toBe(
      "id:legacy_dns_2"
    )
    expect(getDnsRuleTechnicalId(undefined, 1)).toBe("index:1")
  })
})
