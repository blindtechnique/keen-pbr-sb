import { describe, expect, test } from "bun:test"

import type { ConfigObject } from "../src/api/generated/model/configObject"
import { isConfigMutationPending } from "../src/api/mutations"
import {
  pruneSelectedIds,
  selectVisibleIds,
  toggleSelectedId,
} from "../src/hooks/use-row-selection"
import {
  buildUpdatedConfigForDnsServersDelete,
  getDnsServerDeleteReferenceInfo,
} from "../src/pages/dns-servers-utils"
import {
  buildListDeleteTargets,
  buildUpdatedConfigForListsDelete,
  getListDeleteImpact,
  listDeletesAltersRoutingOrDnsRefs,
} from "../src/pages/lists-utils"
import {
  buildUpdatedConfigForOutboundsDelete,
  getOutboundDeleteImpact,
} from "../src/pages/outbounds-utils"

describe("row selection helpers", () => {
  test("prunes ids that are no longer visible", () => {
    expect([...pruneSelectedIds(["a", "missing", "b"], ["a", "b"])]).toEqual([
      "a",
      "b",
    ])
  })

  test("toggles one id after pruning stale ids", () => {
    expect([...toggleSelectedId(["a", "missing"], ["a", "b"], "b")]).toEqual([
      "a",
      "b",
    ])
    expect([...toggleSelectedId(["a", "missing"], ["a", "b"], "a")]).toEqual([])
  })

  test("selects and clears visible ids", () => {
    expect([...selectVisibleIds(["a", "b"], true)]).toEqual(["a", "b"])
    expect([...selectVisibleIds(["a", "b"], false)]).toEqual([])
  })
})

describe("config mutation pending helper", () => {
  test("is false with no mutations in flight", () => {
    expect(isConfigMutationPending(0, 0)).toBe(false)
  })

  test("is true with draft, apply, or discard mutations in flight", () => {
    expect(isConfigMutationPending(1, 0)).toBe(true)
    expect(isConfigMutationPending(0, 1)).toBe(true)
    expect(isConfigMutationPending(0, 0, 1)).toBe(true)
    expect(isConfigMutationPending(0, 0, 0, 1)).toBe(true)
    expect(isConfigMutationPending(0, 0, 0, 0, 1)).toBe(true)
    expect(isConfigMutationPending(0, 0, 0, 0, 0, 1)).toBe(true)
  })
})

describe("bulk DNS server delete helpers", () => {
  test("reports rule and fallback references", () => {
    const config: ConfigObject = {
      dns: {
        fallback: ["wan_dns"],
        servers: [{ tag: "wan_dns" }, { tag: "vpn_dns" }],
        rules: [
          { server: "wan_dns", list: ["ads"] },
          { server: "vpn_dns", list: ["work"] },
        ],
      },
    }

    expect(getDnsServerDeleteReferenceInfo(config, ["wan_dns"])).toEqual({
      matchingRuleIndexes: [0],
      matchingRulesCount: 1,
      usesFallback: true,
    })
  })

  test("deletes servers and cleans refs when requested", () => {
    const config: ConfigObject = {
      dns: {
        fallback: ["wan_dns", "vpn_dns"],
        servers: [{ tag: "wan_dns" }, { tag: "vpn_dns" }],
        rules: [
          { server: "wan_dns", list: ["ads"] },
          { server: "vpn_dns", list: ["work"] },
        ],
      },
    }

    expect(
      buildUpdatedConfigForDnsServersDelete(config, ["wan_dns"], true)
    ).toEqual({
      dns: {
        fallback: ["vpn_dns"],
        servers: [{ tag: "vpn_dns" }],
        rules: [{ server: "vpn_dns", list: ["work"] }],
      },
    })
  })
})

describe("bulk list delete helpers", () => {
  test("deletes lists and reports changed routing or DNS refs", () => {
    const config: ConfigObject = {
      lists: {
        ads: { domains: ["ads.example"] },
        work: { domains: ["work.example"] },
      },
      route: {
        rules: [
          { list: ["ads", "work"], outbound: "vpn" },
          { list: ["ads"], outbound: "wan" },
        ],
      },
      dns: {
        rules: [
          { server: "dns", list: ["ads"] },
          { server: "dns", list: ["work"] },
        ],
      },
    }

    const nextConfig = buildUpdatedConfigForListsDelete(config, ["ads"])

    expect(Object.keys(nextConfig.lists ?? {})).toEqual(["work"])
    expect(nextConfig.route?.rules).toEqual([
      { list: ["work"], outbound: "vpn" },
    ])
    expect(nextConfig.dns?.rules).toEqual([{ server: "dns", list: ["work"] }])
    expect(listDeletesAltersRoutingOrDnsRefs(config, nextConfig)).toBe(true)
  })

  test("preserves a route rule that still has non-list match conditions", () => {
    const config: ConfigObject = {
      lists: { ads: { domains: ["ads.example"] } },
      route: {
        rules: [
          {
            list: ["ads"],
            src_addr: "192.168.1.10",
            dest_port: "443",
            outbound: "vpn",
          },
        ],
      },
    }

    expect(
      buildUpdatedConfigForListsDelete(config, ["ads"]).route?.rules
    ).toEqual([
      {
        list: [],
        src_addr: "192.168.1.10",
        dest_port: "443",
        outbound: "vpn",
      },
    ])
  })

  test("does not treat protocol alone as a valid condition after list removal", () => {
    const config: ConfigObject = {
      lists: { meta: { domains: ["whatsapp.com"] } },
      route: {
        rules: [{ list: ["meta"], proto: "udp", outbound: "vpn" }],
      },
    }

    expect(getListDeleteImpact(config, ["meta"])).toMatchObject({
      routeRuleIndexes: [0],
      removedRouteRuleIndexes: [0],
    })
  })

  test("builds narrow delete or rebind intents for the backend planner", () => {
    expect(buildListDeleteTargets(["meta", "meta"], undefined)).toEqual([
      { list_id: "meta", replacement_list_id: undefined },
    ])
    expect(buildListDeleteTargets(["meta", "instagram"], "social")).toEqual([
      { list_id: "meta", replacement_list_id: "social" },
      { list_id: "instagram", replacement_list_id: "social" },
    ])
  })

  test("rebind preview keeps dependent rules and deduplicates the replacement", () => {
    const config: ConfigObject = {
      lists: {
        meta: { domains: ["whatsapp.com"] },
        social: { domains: ["example.com"] },
      },
      route: {
        rules: [
          {
            list: ["meta", "social"],
            proto: "udp",
            outbound: "vpn",
          },
        ],
      },
      dns: {
        rules: [{ list: ["meta"], server: "vpn_dns" }],
      },
    }

    expect(getListDeleteImpact(config, ["meta"], "social")).toEqual({
      dnsRuleIndexes: [0],
      routeRuleIndexes: [0],
      removedDnsRuleIndexes: [],
      removedRouteRuleIndexes: [],
    })
  })
})

describe("bulk outbound delete helpers", () => {
  test("clears a deleted primary list detour and its whole fallback chain", () => {
    const config: ConfigObject = {
      outbounds: [
        { tag: "primary", type: "interface", interface: "tun0" },
        { tag: "backup_a", type: "interface", interface: "tun1" },
        { tag: "backup_b", type: "interface", interface: "tun2" },
      ],
      lists: {
        remote: {
          url: "https://example.test/list.txt",
          detour: "primary",
          fallback_detours: ["backup_a", "backup_b"],
        },
      },
    }

    const impact = getOutboundDeleteImpact(config, ["primary"])
    expect(impact.listDownloadRoutes).toEqual([
      {
        listName: "remote",
        before: ["primary", "backup_a", "backup_b"],
        after: [],
      },
    ])
    expect(
      buildUpdatedConfigForOutboundsDelete(config, ["primary"]).lists
    ).toEqual({
      remote: {
        url: "https://example.test/list.txt",
      },
    })
  })

  test("removes only deleted fallback list detours and reports the transition", () => {
    const config: ConfigObject = {
      outbounds: [
        { tag: "primary", type: "interface", interface: "tun0" },
        { tag: "backup_a", type: "interface", interface: "tun1" },
        { tag: "backup_b", type: "interface", interface: "tun2" },
      ],
      lists: {
        remote: {
          url: "https://example.test/list.txt",
          detour: "primary",
          fallback_detours: ["backup_a", "backup_b"],
        },
      },
    }

    const impact = getOutboundDeleteImpact(config, ["backup_a"])
    expect(impact.listDownloadRoutes).toEqual([
      {
        listName: "remote",
        before: ["primary", "backup_a", "backup_b"],
        after: ["primary", "backup_b"],
      },
    ])
    expect(
      buildUpdatedConfigForOutboundsDelete(config, ["backup_a"]).lists
    ).toEqual({
      remote: {
        url: "https://example.test/list.txt",
        detour: "primary",
        fallback_detours: ["backup_b"],
      },
    })
  })

  test("uses cascaded urltest deletion when cleaning list detours", () => {
    const config: ConfigObject = {
      outbounds: [
        { tag: "leaf", type: "interface", interface: "tun0" },
        {
          tag: "automatic",
          type: "urltest",
          url: "https://example.test/ping",
          outbound_groups: [{ outbounds: ["leaf"] }],
        },
        { tag: "backup", type: "interface", interface: "tun1" },
      ],
      lists: {
        remote: {
          url: "https://example.test/list.txt",
          detour: "automatic",
          fallback_detours: ["backup"],
        },
      },
    }

    const impact = getOutboundDeleteImpact(config, ["leaf"])
    expect(impact.deletedOutboundTags).toEqual(["leaf", "automatic"])
    expect(impact.listDownloadRoutes).toEqual([
      {
        listName: "remote",
        before: ["automatic", "backup"],
        after: [],
      },
    ])
    expect(
      buildUpdatedConfigForOutboundsDelete(config, ["leaf"]).lists
    ).toEqual({
      remote: {
        url: "https://example.test/list.txt",
      },
    })
  })
})
