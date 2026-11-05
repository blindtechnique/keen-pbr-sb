import { beforeAll, describe, expect, test } from "bun:test"
import { initI18n } from "../src/i18n"
import type { ConfigObject } from "../src/api/generated/model/configObject"
import {
  getDnsRuleServers,
  formatDnsRuleServers,
  withDnsRuleServers,
} from "../src/lib/dns-rule-servers"
import {
  getRuleDraft,
  normalizeDnsRuleDraft,
  validateRules,
} from "../src/pages/dns-rules-utils"
import {
  getDnsServerDeleteImpact,
  buildUpdatedConfigForDnsServersDelete,
} from "../src/pages/dns-servers-utils"
import { isSemanticallyDirty } from "../src/lib/semantic-dirty"
import { semanticJsonEqual } from "../src/lib/semantic-json"
import { getDnsServerDeleteImpactItems } from "../src/components/delete-impact/dns-server-items"

describe("multi-server DNS rules", () => {
  beforeAll(async () => {
    await initI18n()
  })
  const rule = {
    id: "ai_dns",
    list: ["ai"],
    servers: ["primary", "backup"],
    route_rule_ids: ["ai_route"],
  }
  const config: ConfigObject = {
    dns: {
      servers: [
        { tag: "primary", address: "1.1.1.1" },
        { tag: "backup", address: "9.9.9.9" },
      ],
      rules: [rule],
      fallback: ["primary", "backup"],
    },
  }

  test("legacy single server opens as a selection without mutating the input", () => {
    const old = { list: ["ai"], server: "primary" }
    expect(getRuleDraft(old).servers).toEqual(["primary"])
    expect(old).toEqual({ list: ["ai"], server: "primary" })
    expect(normalizeDnsRuleDraft(getRuleDraft(old)).servers).toEqual([
      "primary",
    ])
  })
  test("null optional fields from the API are absent, not a list or a server tag", () => {
    const legacy = { server: "primary", servers: null }
    expect(getDnsRuleServers(legacy)).toEqual(["primary"])
    expect(formatDnsRuleServers(legacy, new Map([["primary", "DNS"]]))).toBe(
      "DNS"
    )
    expect(getDnsRuleServers({ server: null, servers: null })).toEqual([])
    expect(getDnsRuleServers({ server: null })).toEqual([])
    const ordered = ["backup", "primary"]
    const result = getDnsRuleServers({ server: null, servers: ordered })
    expect(result).toEqual(ordered)
    expect(result).not.toBe(ordered)
  })
  test("an empty explicit array never restores the old server", () => {
    expect(getDnsRuleServers({ server: "primary", servers: [] })).toEqual([])
    expect(
      validateRules(
        [getRuleDraft({ list: ["ai"], servers: [] })],
        ["primary"],
        ["ai"]
      )[0].server
    ).toBeTruthy()
  })
  test("saved draft keeps every server, order, provenance and extensions", () => {
    const draft = getRuleDraft({
      ...rule,
      future_option: { preserve: true },
    } as typeof rule)
    const saved = normalizeDnsRuleDraft({ ...draft, displayName: "AI DNS" })
    expect(saved.servers).toEqual(["primary", "backup"])
    expect(saved.server).toBeUndefined()
    expect(saved.route_rule_ids).toEqual(["ai_route"])
    expect((saved as Record<string, unknown>).future_option).toEqual({
      preserve: true,
    })
    expect(draft.servers).not.toBe(rule.servers)
  })
  test("aliases are shown for every server", () => {
    expect(
      formatDnsRuleServers(
        rule,
        new Map([
          ["primary", "Cloudflare"],
          ["backup", "OpenDNS — резервный"],
        ])
      )
    ).toBe("Cloudflare, OpenDNS — резервный")
  })
  test("secondary references are validated", () => {
    expect(
      validateRules([getRuleDraft(rule)], ["primary"], ["ai"])[0].server
    ).toBeTruthy()
    expect(
      validateRules([getRuleDraft(rule)], ["primary", "backup"], ["ai"])
    ).toEqual({})
  })
  test("restoring the server order clears dirty state", () => {
    const baseline = getRuleDraft(rule)
    const changed = { ...baseline, servers: ["backup", "primary"] }
    const options = {
      normalize: normalizeDnsRuleDraft,
      equals: semanticJsonEqual,
    }
    expect(isSemanticallyDirty(changed, baseline, options)).toBe(true)
    expect(
      isSemanticallyDirty(
        { ...changed, servers: [...baseline.servers] },
        baseline,
        options
      )
    ).toBe(false)
  })
  test("deleting one server preserves its rule and other server", () => {
    expect(
      getDnsServerDeleteImpact(config, ["backup"]).matchingRuleIndexes
    ).toEqual([0])
    const next = buildUpdatedConfigForDnsServersDelete(config, ["backup"], true)
    expect(next.dns?.rules).toEqual([{ ...rule, servers: ["primary"] }])
    expect(next.dns?.fallback).toEqual(["primary"])
    expect(config.dns?.rules?.[0].servers).toEqual(["primary", "backup"])
  })
  test("deleting all selected servers removes the rule", () => {
    expect(
      buildUpdatedConfigForDnsServersDelete(config, ["primary", "backup"], true)
        .dns?.rules
    ).toEqual([])
  })
  test("confirmation distinguishes narrowing from deleting the DNS rule", () => {
    const t = (key: string) => key
    const narrow = getDnsServerDeleteImpactItems(
      config,
      ["backup"],
      getDnsServerDeleteImpact(config, ["backup"]),
      t
    )
    expect(narrow[1].label).toBe(
      "pages.dnsServers.deleteDialog.items.dnsRuleNarrowed"
    )
    const remove = getDnsServerDeleteImpactItems(
      config,
      ["primary", "backup"],
      getDnsServerDeleteImpact(config, ["primary", "backup"]),
      t
    )
    expect(remove[2].label).toBe("pages.dnsServers.deleteDialog.items.dnsRule")
  })
  test("cleanup is opt-in and unrelated legacy representations remain intact", () => {
    expect(
      buildUpdatedConfigForDnsServersDelete(config, ["backup"], false).dns
        ?.rules
    ).toEqual([rule])
    const legacy = { list: ["ai"], server: "primary" }
    expect(withDnsRuleServers(legacy, ["primary"])).toBe(legacy)
    expect(
      withDnsRuleServers({ ...legacy, servers: ["primary", "backup"] }, [
        "backup",
      ])
    ).toEqual({ list: ["ai"], servers: ["backup"] })
  })
  test("cleanup does not discard an unrelated incomplete draft", () => {
    const draft = { list: ["draft"], enabled: false, servers: [] }
    const withDraft = {
      ...config,
      dns: { ...config.dns, rules: [rule, draft] },
    }
    expect(
      buildUpdatedConfigForDnsServersDelete(withDraft, ["backup"], true).dns
        ?.rules?.[1]
    ).toBe(draft)
  })
})
