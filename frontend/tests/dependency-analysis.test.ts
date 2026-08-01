import { describe, expect, test } from "bun:test"

import type { ConfigObject } from "@/api/generated/model/configObject"
import type { DependencyReference } from "@/api/generated/model/dependencyReference"
import { mapDependencyReferences } from "@/hooks/use-config-dependencies"
import { findBrokenReferences } from "@/lib/dependencies"

describe("backend dependency mapping", () => {
  test("keeps backend ownership and only formats labels in the UI", () => {
    const config: ConfigObject = {
      route: {
        rules: [
          {
            list: ["ai"],
            outbound: "vpn",
          },
        ],
      },
    }
    const references: DependencyReference[] = [
      {
        target: { kind: "list", id: "ai", cascaded: false },
        dependent_kind: "routing_rule",
        dependent_id: "0",
        relation: "uses_list",
        consequence: "delete",
        path: "route.rules[0].list",
        href: "/routing-rules/0/edit",
      },
    ]

    expect(mapDependencyReferences(config, references)).toEqual(
      new Map([
        [
          "list:ai",
          [
            {
              kind: "routingRule",
              label: "#1 → vpn",
              href: "/routing-rules/0/edit",
            },
          ],
        ],
      ])
    )
  })

  test("uses a list alias for dependency labels without changing the target", () => {
    const config: ConfigObject = {
      lists: {
        ai: {
          display_name: "AI-сервисы",
          detour: "vpn",
        },
      },
    }
    const references: DependencyReference[] = [
      {
        target: { kind: "outbound", id: "vpn", cascaded: false },
        dependent_kind: "list",
        dependent_id: "ai",
        relation: "uses_outbound",
        consequence: "delete",
        path: "lists.ai.detour",
        href: "/lists/ai/edit",
      },
    ]

    expect(mapDependencyReferences(config, references)).toEqual(
      new Map([
        [
          "outbound:vpn",
          [
            {
              kind: "list",
              label: "AI-сервисы",
              href: "/lists/ai/edit",
            },
          ],
        ],
      ])
    )
  })

  test("rewrites rule dependency links to stable ids", () => {
    const config: ConfigObject = {
      route: {
        rules: [
          {
            id: "route_ai",
            display_name: "AI через VPN",
            list: ["ai"],
            outbound: "vpn",
          },
        ],
      },
      dns: {
        rules: [
          {
            id: "dns_ai",
            display_name: "DNS для AI",
            list: ["ai"],
            server: "secure_dns",
          },
        ],
      },
    }
    const references: DependencyReference[] = [
      {
        target: { kind: "list", id: "ai", cascaded: false },
        dependent_kind: "routing_rule",
        dependent_id: "0",
        relation: "uses_list",
        consequence: "delete",
        path: "route.rules[0].list",
        href: "/routing-rules/0/edit",
      },
      {
        target: { kind: "list", id: "ai", cascaded: false },
        dependent_kind: "dns_rule",
        dependent_id: "0",
        relation: "uses_list",
        consequence: "delete",
        path: "dns.rules[0].list",
        href: "/dns-rules/0/edit",
      },
    ]

    expect(mapDependencyReferences(config, references).get("list:ai")).toEqual([
      {
        kind: "routingRule",
        label: "AI через VPN → vpn",
        href: "/routing-rules/route_ai/edit",
      },
      {
        kind: "dnsRule",
        label: "DNS для AI → secure_dns",
        href: "/dns-rules/dns_ai/edit",
      },
    ])
  })

  test("maps the global URL list refresh dependency", () => {
    const config: ConfigObject = {
      outbounds: [{ type: "interface", tag: "vpn", display_name: "Основной" }],
      list_refresh: { detour: "vpn", fallback_detours: ["backup"] },
    }
    const references: DependencyReference[] = [
      {
        target: { kind: "outbound", id: "vpn", cascaded: false },
        dependent_kind: "list_refresh",
        dependent_id: "global",
        relation: "detours_via",
        consequence: "disconnect",
        path: "list_refresh.detour",
        href: "/general?tab=general",
      },
    ]

    expect(
      mapDependencyReferences(config, references).get("outbound:vpn")
    ).toEqual([
      {
        kind: "listRefresh",
        label: "Основной → backup",
        href: "/general?tab=general",
      },
    ])
  })

  test("finds broken per-list and global fallback routes", () => {
    const broken = findBrokenReferences({
      outbounds: [{ type: "interface", tag: "vpn" }],
      lists: {
        ai: {
          refresh_detour_mode: "override",
          detour: "vpn",
          fallback_detours: ["missing_list_backup"],
        },
      },
      list_refresh: {
        detour: "vpn",
        fallback_detours: ["missing_global_backup"],
      },
    })

    expect(broken.map((item) => item.id)).toEqual([
      "list:ai:fallback:0:missing_list_backup",
      "list-refresh:fallback:0:missing_global_backup",
    ])
  })
})
