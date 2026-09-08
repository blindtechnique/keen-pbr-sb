import { describe, expect, test } from "bun:test"
import { DnsServerType } from "../src/api/generated/model/dnsServerType"
import { normalizeDnsDomainBindings } from "../src/lib/dns-domain-bindings"
import {
  buildUpdatedConfigForDnsServerUpsert,
  getDnsServerDraft,
  getDnsServerPresetTransition,
  normalizeDnsServerDraftForComparison,
} from "../src/pages/dns-server-upsert-utils"
import { buildUpdatedConfigForDnsServersDelete } from "../src/pages/dns-servers-utils"

describe("direct DNS domain bindings", () => {
  const primary = {
    tag: "primary",
    display_name: "Primary DNS",
    address: "192.0.2.53",
    type: DnsServerType.static,
    domains: ["example.com"],
  }

  test("normalizes wildcards, case, separators and duplicates", () => {
    expect(
      normalizeDnsDomainBindings(
        " *.YouTube.com.\nYOUTUBE.com, googlevideo.com; youtube.com "
      )
    ).toEqual(["googlevideo.com", "youtube.com"])
    expect(normalizeDnsDomainBindings(" \n ")).toEqual([])
    expect(
      normalizeDnsDomainBindings("_sip._tcp.example.com xn--e1afmkfd.xn--p1ai")
    ).toEqual(["_sip._tcp.example.com", "xn--e1afmkfd.xn--p1ai"])
  })

  test("rejects malformed labels, URLs, IPs and directive syntax", () => {
    for (const input of [
      "https://example.com",
      "example.com/path",
      "/example.com/8.8.8.8",
      "8.8.8.8",
      "::1",
      ".example.com",
      "example.com..",
      "a..com",
      "-bad.com",
      "bad-.com",
      "x*.com",
      "пример.рф",
      `${"a".repeat(64)}.com`,
      `${"a.".repeat(127)}com`,
    ]) {
      expect(normalizeDnsDomainBindings(input)).toBeNull()
    }
  })

  test("round-trips pins and clears semantic dirty when restored", () => {
    const baseline = getDnsServerDraft(primary)
    const normalized = normalizeDnsServerDraftForComparison(baseline)
    expect(
      normalizeDnsServerDraftForComparison({
        ...baseline,
        domains: "*.EXAMPLE.com.\nexample.com",
      })
    ).toEqual(normalized)
    expect(
      normalizeDnsServerDraftForComparison({
        ...baseline,
        domains: "other.example",
      })
    ).not.toEqual(normalized)
    const config = {
      dns: { servers: [primary], fallback: ["primary"], rules: [] },
    }
    const updated = buildUpdatedConfigForDnsServerUpsert(
      config,
      "edit",
      { ...baseline, displayName: "Renamed" },
      "primary"
    )
    expect(updated?.dns?.servers?.[0].domains).toEqual(primary.domains)
    expect(updated?.dns?.fallback).toEqual(config.dns.fallback)
    expect(updated?.lists).toBeUndefined()
    expect(updated?.route).toBeUndefined()
    const removed = buildUpdatedConfigForDnsServerUpsert(
      config,
      "edit",
      { ...baseline, domains: "" },
      "primary"
    )
    expect(removed?.dns?.servers?.[0].domains).toBeUndefined()
    expect(config.dns.servers[0].domains).toEqual(["example.com"])
  })

  test("invalid pins cannot create a partial server", () => {
    const config = { dns: { servers: [] } }
    expect(
      buildUpdatedConfigForDnsServerUpsert(config, "create", {
        ...getDnsServerDraft(primary),
        domains: "https://example.com",
      })
    ).toBeNull()
    expect(config.dns.servers).toEqual([])
  })

  test("provider selection does not reset the domains the user entered", () => {
    const draft = getDnsServerDraft(primary)
    const transition = getDnsServerPresetTransition(
      "cloudflare",
      draft,
      [],
      []
    )!
    expect({ ...draft, ...transition.fields }.domains).toBe("example.com")
    const restored = getDnsServerPresetTransition("custom", draft, [], [])!
    expect({ ...draft, ...restored.fields }.domains).toBe("example.com")
  })

  test("primary and new backup receive the same normalized pins", () => {
    const updated = buildUpdatedConfigForDnsServerUpsert(
      { dns: { servers: [] } },
      "create",
      {
        ...getDnsServerDraft(primary),
        domains: "*.EXAMPLE.com.",
      },
      undefined,
      { tag: "backup", address: "192.0.2.54" }
    )
    expect(updated?.dns?.servers?.map((server) => server.domains)).toEqual([
      ["example.com"],
      ["example.com"],
    ])
  })

  test("reused backup retains existing pins and unrelated fields", () => {
    const backup = {
      ...primary,
      tag: "backup",
      address: "192.0.2.54",
      domains: ["other.example"],
    }
    const config = { dns: { servers: [backup] } }
    const updated = buildUpdatedConfigForDnsServerUpsert(
      config,
      "create",
      getDnsServerDraft(primary),
      undefined,
      { tag: "new_backup", address: backup.address }
    )
    expect(updated?.dns?.servers).toHaveLength(2)
    expect(updated?.dns?.servers?.[0]).toEqual({
      ...backup,
      domains: ["example.com", "other.example"],
    })
    expect(backup.domains).toEqual(["other.example"])
  })

  test("deleting a server removes only its domain bindings", () => {
    const backup = { ...primary, tag: "backup", address: "192.0.2.54" }
    const updated = buildUpdatedConfigForDnsServersDelete(
      { dns: { servers: [primary, backup], fallback: ["primary", "backup"] } },
      ["primary"],
      true
    )
    expect(updated.dns?.servers).toEqual([backup])
    expect(updated.dns?.fallback).toEqual(["backup"])
  })

  test("legacy configs remain valid and omit unused domain bindings", () => {
    const draft = {
      ...getDnsServerDraft(),
      displayName: "DNS",
      tag: "dns",
      address: "192.0.2.53",
    }
    const updated = buildUpdatedConfigForDnsServerUpsert({}, "create", draft)
    expect(updated?.dns?.servers?.[0].domains).toBeUndefined()
  })
})
