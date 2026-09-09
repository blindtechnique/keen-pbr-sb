import { describe, expect, test } from "bun:test"

import {
  getRuleEditHref,
  resolveRuleEditTargetIndex,
  resolveRuleRouteIndex,
} from "../src/lib/rule-route"
import { semanticJsonEqual } from "../src/lib/semantic-json"
import { areRouteRulesSemanticallyEqual } from "../src/pages/routing-rules-utils"
import {
  getRuleDraft,
  normalizeDnsRuleDraft,
} from "../src/pages/dns-rules-utils"
import type { RouteRule } from "../src/api/generated/model/routeRule"
import type { DnsRule } from "../src/api/generated/model/dnsRule"

describe("stable rule edit routes", () => {
  const rules = [{ id: "route_primary" }, {}, { id: "route_backup" }]

  test("builds new links from stable ids and legacy links from indexes", () => {
    expect(getRuleEditHref("routing-rules", rules[0], 0)).toBe(
      "/routing-rules/route_primary/edit"
    )
    expect(getRuleEditHref("dns-rules", rules[1], 1)).toBe("/dns-rules/1/edit")
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

describe("open rule editor target", () => {
  const original: RouteRule = { outbound: "primary", list: ["one"] }
  const neighbor: RouteRule = { outbound: "backup", list: ["two"] }
  const routeEquals = (left: RouteRule, right: RouteRule) =>
    areRouteRulesSemanticallyEqual([left], [right])

  test("a legacy numeric entry captures one rule and follows a unique reorder", () => {
    const openedRules = [original, neighbor]
    const captured = openedRules[resolveRuleRouteIndex(openedRules, "0")]
    const currentRules = [neighbor, { ...original }]
    const index = resolveRuleEditTargetIndex(
      currentRules,
      captured,
      routeEquals
    )
    expect(index).toBe(1)

    const edited = { ...original, outbound: "updated" }
    expect(
      currentRules.map((rule, position) => (position === index ? edited : rule))
    ).toEqual([neighbor, edited])
    expect(
      currentRules.filter((_rule, position) => position !== index)
    ).toEqual([neighbor])
    expect(captured).toEqual(original)
  })

  test("deletion never retargets the next rule at the old numeric index", () => {
    expect(resolveRuleEditTargetIndex([neighbor], original, routeEquals)).toBe(
      -1
    )
    expect(resolveRuleEditTargetIndex([], original, routeEquals)).toBe(-1)
  })

  test("a changed legacy rule cannot be confused with the original draft", () => {
    expect(
      resolveRuleEditTargetIndex(
        [{ ...original, outbound: "changed" }, neighbor],
        original,
        routeEquals
      )
    ).toBe(-1)
  })

  test("ambiguous legacy copies never authorize save or delete", () => {
    expect(
      resolveRuleEditTargetIndex(
        [{ ...original }, neighbor, { ...original }],
        original,
        routeEquals
      )
    ).toBe(-1)
  })

  test("identical legacy rules remain editable within their captured snapshot", () => {
    const duplicate = { ...original }
    expect(
      resolveRuleEditTargetIndex([original, duplicate], original, routeEquals)
    ).toBe(0)
    expect(
      resolveRuleEditTargetIndex([duplicate, original], original, routeEquals)
    ).toBe(1)
    expect(
      resolveRuleEditTargetIndex([original, original], original, routeEquals)
    ).toBe(-1)
  })

  test("normal legacy editing survives equivalent default serialization", () => {
    expect(
      resolveRuleEditTargetIndex(
        [{ ...original, enabled: true }, neighbor],
        original,
        routeEquals
      )
    ).toBe(0)
  })

  test("stable ID selected through a numeric URL remains authoritative", () => {
    const stable = { ...original, id: "route_primary" }
    const openedRules = [stable, neighbor]
    const captured = openedRules[resolveRuleRouteIndex(openedRules, "0")]
    expect(
      resolveRuleEditTargetIndex(
        [neighbor, { ...stable, outbound: "changed" }],
        captured,
        routeEquals
      )
    ).toBe(1)
    expect(resolveRuleEditTargetIndex([neighbor], captured, routeEquals)).toBe(
      -1
    )
  })

  test("a missing numeric stable ID never falls back to an array index", () => {
    expect(
      resolveRuleEditTargetIndex(
        [neighbor],
        { ...original, id: "0" },
        routeEquals
      )
    ).toBe(-1)
  })

  test("duplicate stable IDs are ambiguous rather than first-match targets", () => {
    const stable = { ...original, id: "route_primary" }
    expect(
      resolveRuleEditTargetIndex([stable, { ...stable }], stable, routeEquals)
    ).toBe(-1)
  })

  test("missing initial targets do not adopt later records", () => {
    expect(resolveRuleEditTargetIndex([original], undefined, routeEquals)).toBe(
      -1
    )
  })

  test("DNS legacy targets use the editor's normalized semantic identity", () => {
    const dnsOriginal: DnsRule = { server: "primary", list: ["two", "one"] }
    const dnsNeighbor: DnsRule = { server: "backup", list: ["other"] }
    const dnsEquivalent: DnsRule = {
      server: "primary",
      list: ["one", "two"],
      enabled: true,
      allow_domain_rebinding: false,
    }
    const equals = (left: DnsRule, right: DnsRule) =>
      semanticJsonEqual(
        normalizeDnsRuleDraft(getRuleDraft(left)),
        normalizeDnsRuleDraft(getRuleDraft(right))
      )
    expect(
      resolveRuleEditTargetIndex(
        [dnsNeighbor, dnsEquivalent],
        dnsOriginal,
        equals
      )
    ).toBe(1)
    expect(resolveRuleEditTargetIndex([dnsNeighbor], dnsOriginal, equals)).toBe(
      -1
    )
    expect(
      resolveRuleEditTargetIndex(
        [{ ...dnsOriginal }, dnsEquivalent],
        dnsOriginal,
        equals
      )
    ).toBe(-1)
    expect(
      resolveRuleEditTargetIndex(
        [dnsOriginal, dnsNeighbor],
        dnsOriginal,
        equals
      )
    ).toBe(0)
  })
})
