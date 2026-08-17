import { describe, expect, test } from "bun:test"

import type { ConfigObject } from "../src/api/generated/model/configObject"
import {
  emptyRouteRuleDraft,
  getRoutingRuleRowId,
  normalizeRouteRuleDraft,
  setRouteRuleEnabled,
  toRouteRuleDraft,
} from "../src/pages/routing-rules-utils"
import { type DnsRuleDraft } from "../src/pages/dns-rules-utils"

let dnsRuleUtilsPromise:
  | Promise<typeof import("../src/pages/dns-rules-utils")>
  | undefined

function loadDnsRuleUtils() {
  if (!globalThis.navigator) {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { language: "en-US", languages: ["en-US"] },
    })
  } else {
    Object.defineProperty(globalThis.navigator, "language", {
      configurable: true,
      value: "en-US",
    })
    Object.defineProperty(globalThis.navigator, "languages", {
      configurable: true,
      value: ["en-US"],
    })
  }

  dnsRuleUtilsPromise ??= import("../src/pages/dns-rules-utils")
  return dnsRuleUtilsPromise
}

describe("routing rule enabled helpers", () => {
  test("mobile and desktop selection use the same row id", () => {
    expect(getRoutingRuleRowId({ id: "video", outbound: "vpn" }, 0)).toBe(
      "id:video"
    )
    expect(getRoutingRuleRowId({ outbound: "vpn" }, 12)).toBe("index:12")
  })

  test("new route rule drafts default to enabled", () => {
    expect(emptyRouteRuleDraft.enabled).toBe(true)
    expect(normalizeRouteRuleDraft(emptyRouteRuleDraft).enabled).toBe(true)
  })

  test("route rule draft preserves disabled state and defaults missing state to enabled", () => {
    expect(
      toRouteRuleDraft({
        enabled: false,
        list: ["ads"],
        dscp: 46,
        outbound: "vpn",
      }).enabled
    ).toBe(false)

    expect(
      toRouteRuleDraft({
        list: ["ads"],
        outbound: "vpn",
      }).enabled
    ).toBe(true)
  })

  test("route rule draft preserves dscp", () => {
    const draft = toRouteRuleDraft({
      list: ["ads"],
      dscp: 46,
      outbound: "vpn",
    })

    expect(draft.dscp).toBe("46")
    expect(normalizeRouteRuleDraft(draft).dscp).toBe(46)
  })

  test("setRouteRuleEnabled updates only the targeted rule", () => {
    const rules = [
      { list: ["one"], outbound: "vpn" },
      { enabled: false, list: ["two"], outbound: "wan" },
    ]

    expect(setRouteRuleEnabled(rules, 1, true)).toEqual([
      { list: ["one"], outbound: "vpn" },
      { enabled: true, list: ["two"], outbound: "wan" },
    ])
  })
})

describe("dns rule enabled helpers", () => {
  test("dns rule drafts default to enabled and preserve disabled state", async () => {
    const { getRuleDraft } = await loadDnsRuleUtils()

    expect(getRuleDraft().enabled).toBe(true)
    expect(
      getRuleDraft({
        enabled: false,
        list: ["ads"],
        server: "vpn_dns",
      }).enabled
    ).toBe(false)
  })

  test("buildUpdatedConfigWithRules persists enabled into config payload", async () => {
    const { buildUpdatedConfigWithRules } = await loadDnsRuleUtils()

    const config: ConfigObject = {
      dns: {
        fallback: ["vpn_dns"],
        rules: [],
      },
    }

    expect(
      buildUpdatedConfigWithRules(
        config,
        ["vpn_dns"],
        [
          {
            id: "",
            displayName: "",
            enabled: false,
            server: "vpn_dns",
            lists: ["ads"],
            allowDomainRebinding: true,
          },
        ]
      )
    ).toEqual({
      dns: {
        fallback: ["vpn_dns"],
        rules: [
          {
            enabled: false,
            server: "vpn_dns",
            list: ["ads"],
            allow_domain_rebinding: true,
          },
        ],
      },
    })
  })

  test("setDnsRuleEnabled updates only the targeted draft rule", async () => {
    const { setDnsRuleEnabled } = await loadDnsRuleUtils()

    const rules: DnsRuleDraft[] = [
      {
        id: "dns_ads",
        displayName: "DNS for ads",
        enabled: true,
        server: "vpn_dns",
        lists: ["ads"],
        allowDomainRebinding: false,
      },
      {
        id: "dns_work",
        displayName: "DNS for work",
        enabled: false,
        server: "wan_dns",
        lists: ["work"],
        allowDomainRebinding: true,
      },
    ]

    expect(setDnsRuleEnabled(rules, 0, false)).toEqual([
      {
        id: "dns_ads",
        displayName: "DNS for ads",
        enabled: false,
        server: "vpn_dns",
        lists: ["ads"],
        allowDomainRebinding: false,
      },
      {
        id: "dns_work",
        displayName: "DNS for work",
        enabled: false,
        server: "wan_dns",
        lists: ["work"],
        allowDomainRebinding: true,
      },
    ])
  })

  test("validateRules ignores disabled rules", async () => {
    const { validateRules } = await loadDnsRuleUtils()

    expect(
      validateRules(
        [
          {
            id: "",
            displayName: "",
            enabled: false,
            server: "",
            lists: [],
            allowDomainRebinding: false,
          },
          {
            id: "dns_ads",
            displayName: "DNS for ads",
            enabled: true,
            server: "vpn_dns",
            lists: ["ads"],
            allowDomainRebinding: false,
          },
        ],
        ["vpn_dns"],
        ["ads"]
      )
    ).toEqual({})
  })

  test("DNS rule drafts preserve aliases and stable ids", async () => {
    const { getRuleDraft, normalizeDnsRuleDraft } = await loadDnsRuleUtils()
    const draft = getRuleDraft({
      id: "dns_video",
      display_name: "Видео через Cloudflare",
      enabled: true,
      list: ["video"],
      server: "cloudflare",
    })

    expect(draft.id).toBe("dns_video")
    expect(draft.displayName).toBe("Видео через Cloudflare")
    expect(normalizeDnsRuleDraft(draft)).toMatchObject({
      id: "dns_video",
      display_name: "Видео через Cloudflare",
    })
  })
})
