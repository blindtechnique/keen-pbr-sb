import { describe, expect, test } from "bun:test"

import type { RouteRule } from "../src/api/generated/model/routeRule"
import { semanticJsonEqual } from "../src/lib/semantic-json"
import {
  areRouteRulesSemanticallyEqual,
  reorderRules,
  setRouteRuleEnabled,
} from "../src/pages/routing-rules-utils"

const directRule: RouteRule = {
  list: ["direct"],
  outbound: "direct",
}

const tunnelRule: RouteRule = {
  list: ["tunnel"],
  outbound: "vless",
}

describe("semantic JSON equality", () => {
  test("ignores object key order and undefined object fields", () => {
    expect(
      semanticJsonEqual(
        { enabled: true, nested: { name: "route", missing: undefined } },
        { nested: { name: "route" }, enabled: true }
      )
    ).toBe(true)
  })

  test("keeps array order significant", () => {
    expect(semanticJsonEqual(["direct", "vpn"], ["vpn", "direct"])).toBe(false)
  })
})

describe("routing rule semantic equality", () => {
  test("treats omitted defaults and their explicit values as equal", () => {
    expect(
      areRouteRulesSemanticallyEqual(
        [directRule],
        [{ ...directRule, enabled: true, list: ["direct"] }]
      )
    ).toBe(true)
    expect(
      areRouteRulesSemanticallyEqual(
        [{ outbound: "direct" }],
        [{ outbound: "direct", list: [], enabled: true }]
      )
    ).toBe(true)
  })

  test("detects a real enabled-state change", () => {
    expect(
      areRouteRulesSemanticallyEqual(
        [directRule],
        setRouteRuleEnabled([directRule], 0, false)
      )
    ).toBe(false)
  })

  test("becomes clean again after restoring the original order", () => {
    const baseline = [directRule, tunnelRule]
    const moved = reorderRules(baseline, 0, 1)
    const restored = reorderRules(moved, 1, 0)

    expect(areRouteRulesSemanticallyEqual(baseline, moved)).toBe(false)
    expect(areRouteRulesSemanticallyEqual(baseline, restored)).toBe(true)
  })
})
