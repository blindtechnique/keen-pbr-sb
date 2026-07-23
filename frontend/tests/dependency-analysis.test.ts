import { describe, expect, test } from "bun:test"

import type { ConfigObject } from "@/api/generated/model/configObject"
import type { DependencyReference } from "@/api/generated/model/dependencyReference"
import { mapDependencyReferences } from "@/hooks/use-config-dependencies"

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
})
