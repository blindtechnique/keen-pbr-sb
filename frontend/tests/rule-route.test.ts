import { describe, expect, test } from "bun:test"

import {
  getRuleEditHref,
  resolveRuleRouteIndex,
} from "../src/lib/rule-route"

describe("stable rule edit routes", () => {
  const rules = [
    { id: "route_primary" },
    {},
    { id: "route_backup" },
  ]

  test("builds new links from stable ids and legacy links from indexes", () => {
    expect(getRuleEditHref("routing-rules", rules[0], 0)).toBe(
      "/routing-rules/route_primary/edit"
    )
    expect(getRuleEditHref("dns-rules", rules[1], 1)).toBe(
      "/dns-rules/1/edit"
    )
  })

  test("resolves stable ids after reordering", () => {
    const reordered = [rules[2], rules[0], rules[1]]
    expect(resolveRuleRouteIndex(reordered, "route_primary")).toBe(1)
    expect(resolveRuleRouteIndex(reordered, "route_backup")).toBe(0)
  })

  test("keeps old index URLs working for legacy bookmarks", () => {
    expect(resolveRuleRouteIndex(rules, "0")).toBe(0)
    expect(resolveRuleRouteIndex(rules, "1")).toBe(1)
    expect(resolveRuleRouteIndex(rules, "03")).toBe(-1)
    expect(resolveRuleRouteIndex(rules, "99")).toBe(-1)
  })
})
