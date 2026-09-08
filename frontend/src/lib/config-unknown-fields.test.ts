import { describe, expect, it } from "bun:test"

import type { ConfigObject } from "@/api/generated/model/configObject"
import type { Outbound } from "@/api/generated/model/outbound"
import { configKnownFields } from "@/lib/config-known-fields.generated"
import { pickUnknownConfigProperties } from "@/lib/config-unknown-fields"
import { buildListRefreshConfig } from "@/lib/list-refresh-route"
import {
  buildUpdatedConfigForDnsServerUpsert,
  getDnsServerDraft,
  withSavedPlainDnsTemplate,
} from "@/pages/dns-server-upsert-utils"
import {
  buildUpdatedConfigWithRules,
  getRuleDraft,
  normalizeDnsRuleDraft,
} from "@/pages/dns-rules-utils"
import {
  buildUpdatedConfigForListUpsert,
  getDraftFromMapEntry,
} from "@/pages/list-upsert-utils"
import {
  mapOutboundToDraft,
  normalizeOutboundDraftForPersistence,
} from "@/pages/outbound-upsert-utils"
import {
  normalizeRouteRuleDraft,
  toRouteRuleDraft,
} from "@/pages/routing-rules-utils"

describe("config extension fields in ordinary forms", () => {
  it("copies unknown JSON values without retaining known optional fields", () => {
    const source = JSON.parse(
      '{"server":"dns","list":["a"],"display_name":"Old","future":{"enabled":false,"items":[null,2]},"__proto__":{"future":true}}'
    )
    const unknown = pickUnknownConfigProperties(
      source,
      configKnownFields.DnsRule
    )
    expect(Object.keys(unknown)).toEqual(["future", "__proto__"])
    expect(unknown.future).toEqual({ enabled: false, items: [null, 2] })
    expect(Object.getPrototypeOf(unknown)).toBe(Object.prototype)
    expect(Object.hasOwn(unknown, "__proto__")).toBe(true)
  })

  it("keeps legacy DNS rule extensions attached through reorder and deletion", () => {
    const first = {
      server: "dns",
      list: ["a"],
      display_name: "First",
      future: { id: 1 },
    }
    const second = { server: "dns", list: ["b"], future: { id: 2 } }
    const config: ConfigObject = {
      dns: { rules: [first, second], fallback: ["dns"] },
    }
    const drafts = [getRuleDraft(second), getRuleDraft(first)]
    drafts[0]!.enabled = false
    const reordered = buildUpdatedConfigWithRules(config, ["dns"], drafts)
    expect(reordered.dns?.rules).toMatchObject([
      { enabled: false, future: { id: 2 } },
      { future: { id: 1 } },
    ])
    drafts[1]!.displayName = ""
    const surviving = buildUpdatedConfigWithRules(config, [], [drafts[1]!])
    expect(surviving.dns?.rules).toMatchObject([{ future: { id: 1 } }])
    expect(surviving.dns?.rules?.[0]).not.toHaveProperty("display_name")
    expect(normalizeDnsRuleDraft(drafts[1]!)).not.toHaveProperty(
      "unknownFields"
    )
    expect(first.display_name).toBe("First")
  })

  it("does not restore cleared route criteria or fallback while preserving extensions", () => {
    const original = {
      id: "rule",
      outbound: "vpn",
      list: ["a"],
      proto: "tcp",
      failure_policy: "fallback" as const,
      fallback_outbound: "backup",
      future: { mode: "later" },
    }
    const draft = toRouteRuleDraft(original)
    draft.proto = ""
    draft.failurePolicy = "inherit"
    draft.fallbackOutbound = ""
    draft.outbound = "replacement"
    const next = normalizeRouteRuleDraft(draft)
    expect(next).toMatchObject({
      outbound: "replacement",
      future: { mode: "later" },
    })
    expect(next.proto).toBeUndefined()
    expect(next.failure_policy).toBeUndefined()
    expect(next.fallback_outbound).toBeUndefined()
  })

  it("carries each URLTEST group extension through reorder, edits and removal", () => {
    const original = {
      type: "urltest" as const,
      tag: "group",
      display_name: "Group",
      outbound_groups: [
        { outbounds: ["a"], weight: 1, future_group: { id: "a" } },
        { outbounds: ["b"], weight: 2, future_group: { id: "b" } },
      ],
      retry: { attempts: 3, future_retry: true },
      circuit_breaker: { timeout_ms: 3000, future_breaker: [1, 2] },
      future: { kind: "group" },
    }
    const draft = mapOutboundToDraft(original)
    draft.displayName = ""
    draft.retryAttempts = ""
    draft.circuitBreakerTimeout = ""
    draft.outboundGroups = [
      { ...draft.outboundGroups[1]!, outbounds: ["b", "c"], weight: "" },
      draft.outboundGroups[0]!,
    ]
    const next = normalizeOutboundDraftForPersistence(draft)
    expect(next).toMatchObject({
      future: { kind: "group" },
      retry: { future_retry: true },
      circuit_breaker: { future_breaker: [1, 2] },
      outbound_groups: [
        { outbounds: ["b", "c"], future_group: { id: "b" } },
        { future_group: { id: "a" } },
      ],
    })
    expect(next).not.toHaveProperty("display_name")
    expect(next.retry?.attempts).toBeUndefined()
    expect(next.circuit_breaker?.timeout_ms).toBeUndefined()
    expect(next.outbound_groups?.[0]?.weight).toBeUndefined()
    draft.outboundGroups = [
      draft.outboundGroups[0]!,
      { outbounds: ["fresh"], weight: "" },
    ]
    const removed = normalizeOutboundDraftForPersistence(draft)
    expect(removed.outbound_groups?.[1]).not.toHaveProperty("future_group")
    expect(original.outbound_groups[0]?.outbounds).toEqual(["a"])
  })

  it("does not restore fields belonging to an outbound type that was removed", () => {
    const original = {
      type: "urltest" as const,
      tag: "vpn",
      url: "https://example.test/",
      retry: { attempts: 2, future_retry: true },
      future: ["root"],
    }
    const draft = mapOutboundToDraft(original)
    draft.type = "interface"
    draft.interfaceName = "nwg1"
    const next: Outbound = normalizeOutboundDraftForPersistence(draft)
    expect(next).toMatchObject({
      type: "interface",
      interface: "nwg1",
      future: ["root"],
    })
    expect(next).not.toHaveProperty("retry")
    expect(next).not.toHaveProperty("url")
  })

  it("retains edited list and shrink-policy extensions without stale catalogue identity", () => {
    const original = {
      url: "https://example.test/old",
      catalog_identity: "a".repeat(64),
      detour: "vpn",
      refresh_detour_mode: "override" as const,
      shrink_policy: {
        min_previous_entries: 50,
        min_retained_fraction: 0.25,
        future_shrink: { mode: 1 },
      },
      future_list: ["kept"],
    }
    const config: ConfigObject = { lists: { sample: original } }
    const draft = getDraftFromMapEntry("sample", original)!
    draft.url = "https://example.test/new"
    draft.refreshDetourMode = "inherit"
    draft.detour = ""
    draft.shrinkMinPreviousEntries = ""
    draft.shrinkMinRetainedPercent = ""
    const next = buildUpdatedConfigForListUpsert(
      config,
      "edit",
      draft,
      "sample"
    )
    expect(next.lists?.sample).toMatchObject({
      future_list: ["kept"],
      shrink_policy: { future_shrink: { mode: 1 } },
    })
    expect(next.lists?.sample).not.toHaveProperty("catalog_identity")
    expect(next.lists?.sample).not.toHaveProperty("detour")
    expect(next.lists?.sample?.shrink_policy).not.toHaveProperty(
      "min_previous_entries"
    )
    expect(next.lists?.sample?.shrink_policy).not.toHaveProperty(
      "min_retained_fraction"
    )
  })

  it("retains exact DNS server extensions when renaming and clearing optional settings", () => {
    const original = {
      tag: "dns",
      display_name: "DNS",
      type: "static" as const,
      address: "1.1.1.1",
      detour: "vpn",
      domains: ["example.test"],
      future_server: null,
    }
    const sibling = {
      tag: "other",
      address: "9.9.9.9",
      future_other: { enabled: true },
    }
    const config: ConfigObject = { dns: { servers: [original, sibling] } }
    const draft = {
      ...getDnsServerDraft(original),
      tag: "renamed",
      domains: "",
      detour: "",
    }
    const next = buildUpdatedConfigForDnsServerUpsert(
      config,
      "edit",
      draft,
      "dns"
    )!
    expect(next.dns?.servers?.[0]).toMatchObject({
      tag: "renamed",
      future_server: null,
    })
    expect(next.dns?.servers?.[0]).not.toHaveProperty("detour")
    expect(next.dns?.servers?.[0]).not.toHaveProperty("domains")
    expect(next.dns?.servers?.[1]).toBe(sibling)
    expect(original.tag).toBe("dns")
  })

  it("drops obsolete static DNS settings on type change, not unknown extensions", () => {
    const original = {
      tag: "dns",
      display_name: "DNS",
      address: "1.1.1.1",
      detour: "vpn",
      future: true,
    }
    const next = buildUpdatedConfigForDnsServerUpsert(
      { dns: { servers: [original] } },
      "edit",
      { ...getDnsServerDraft(original), type: "keenetic" },
      "dns"
    )!
    expect(next.dns?.servers?.[0]).toMatchObject({
      type: "keenetic",
      future: true,
    })
    expect(next.dns?.servers?.[0]).not.toHaveProperty("address")
    expect(next.dns?.servers?.[0]).not.toHaveProperty("detour")
  })

  it("preserves a replaced DNS template extension while removing its secondary server", () => {
    const original = {
      name: "Example",
      primary_ipv4: "1.1.1.1",
      secondary_ipv4: "1.0.0.1",
      future: { value: 2 },
    }
    const config: ConfigObject = {
      ui_preferences: { plain_dns_templates: [original] },
    }
    const next = withSavedPlainDnsTemplate(config, {
      name: "example",
      primary_ipv4: "9.9.9.9",
    })!
    expect(next.ui_preferences?.plain_dns_templates?.[0]).toMatchObject({
      future: { value: 2 },
    })
    expect(next.ui_preferences?.plain_dns_templates?.[0]).not.toHaveProperty(
      "secondary_ipv4"
    )
  })

  it("preserves list-refresh extensions in direct mode without reviving a removed detour", () => {
    const original = {
      detour: "vpn",
      fallback_detours: ["backup"],
      future: { refresh: true },
    }
    expect(
      buildListRefreshConfig(original, { detour: "other", fallbackDetours: [] })
    ).toEqual({
      detour: "other",
      fallback_detours: [],
      future: { refresh: true },
    })
    expect(
      buildListRefreshConfig(original, {
        detour: "",
        fallbackDetours: ["backup"],
      })
    ).toEqual({ future: { refresh: true } })
    expect(
      buildListRefreshConfig(
        { detour: "vpn" },
        { detour: "", fallbackDetours: [] }
      )
    ).toBeUndefined()
  })
})
