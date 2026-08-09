import { describe, expect, test } from "bun:test"

import type { RoutingTestRuleDiagnostic } from "../src/api/generated/model/routingTestRuleDiagnostic"
import {
  getRuleConditions,
  getVisibleRuleDiagnostics,
  isGrayRuleDiagnostic,
} from "../src/components/overview/routing-diagnostics-utils"

describe("routing diagnostics helpers", () => {
  test("hides fully gray rules by default", () => {
    const rules = [
      buildRuleDiagnostic(0, { inIpset: false }),
      buildRuleDiagnostic(1, { inIpset: null }),
    ]

    expect(getVisibleRuleDiagnostics(rules, false)).toEqual([])
  })

  test("keeps rule with target match", () => {
    const rule = buildRuleDiagnostic(0, {
      targetMatch: { list: "work", via: "example.com" },
    })

    expect(isGrayRuleDiagnostic(rule)).toBe(false)
    expect(getVisibleRuleDiagnostics([rule], false)).toEqual([rule])
  })

  test("keeps rule with stale ipset membership", () => {
    const rule = buildRuleDiagnostic(0, { inIpset: true })

    expect(isGrayRuleDiagnostic(rule)).toBe(false)
    expect(getVisibleRuleDiagnostics([rule], false)).toEqual([rule])
  })

  test("keeps per-IP list matches and packet-context unknowns visible", () => {
    const perIpMatch = buildRuleDiagnostic(0, {
      inLists: true,
      listMatch: { list: "work", via: "8.8.8.8" },
    })
    const insufficient = buildRuleDiagnostic(1, {
      evaluation: "insufficient_context",
      unknownConditions: ["source_address", "destination_port"],
    })

    expect(
      getVisibleRuleDiagnostics([perIpMatch, insufficient], false)
    ).toEqual([perIpMatch, insufficient])
  })

  test("keeps a list-free rule matched by destination semantics visible", () => {
    const matched = buildRuleDiagnostic(0, {
      evaluation: "matched",
    })
    matched.rule.list = undefined

    expect(isGrayRuleDiagnostic(matched)).toBe(false)
    expect(getVisibleRuleDiagnostics([matched], false)).toEqual([matched])
  })

  test("showAllRules keeps every rule", () => {
    const rules = [
      buildRuleDiagnostic(0, { inIpset: false }),
      buildRuleDiagnostic(1, { inIpset: true }),
    ]

    expect(getVisibleRuleDiagnostics(rules, true)).toEqual(rules)
  })

  test("formats only present rule conditions", () => {
    expect(
      getRuleConditions({
        list: ["work", "media"],
        outbound: "vpn",
        proto: "tcp",
        dest_port: "443",
        dscp: 10,
      })
    ).toEqual([
      { key: "lists", value: "work, media" },
      { key: "proto", value: "tcp" },
      { key: "destinationPort", value: "443" },
      { key: "dscp", value: "10" },
    ])
  })

  test("shows a list alias while preserving the technical reference in data", () => {
    expect(
      getRuleConditions(
        {
          list: ["work"],
          outbound: "vpn",
        },
        {
          work: {
            display_name: "Работа",
            domains: ["example.com"],
          },
        }
      )
    ).toEqual([{ key: "lists", value: "Работа" }])
  })
})

function buildRuleDiagnostic(
  ruleIndex: number,
  options: {
    inIpset?: boolean | null
    inLists?: boolean
    listMatch?: RoutingTestRuleDiagnostic["ip_rows"][number]["list_match"]
    evaluation?: RoutingTestRuleDiagnostic["ip_rows"][number]["evaluation"]
    unknownConditions?: RoutingTestRuleDiagnostic["ip_rows"][number]["unknown_conditions"]
    targetMatch?: RoutingTestRuleDiagnostic["target_match"]
  } = {}
): RoutingTestRuleDiagnostic {
  return {
    rule_index: ruleIndex,
    rule: {
      list: ["work"],
      outbound: "vpn",
    },
    outbound: "vpn",
    interface_name: "ppp0",
    target_in_lists: Boolean(options.targetMatch),
    target_match: options.targetMatch,
    ip_rows: [
      {
        ip: "8.8.8.8",
        in_lists: options.inLists ?? false,
        list_match: options.listMatch,
        in_ipset: options.inIpset,
        evaluation: options.evaluation ?? "not_matched",
        unknown_conditions: options.unknownConditions ?? [],
      },
    ],
  }
}
