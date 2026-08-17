import { describe, expect, test } from "bun:test"

import type { RouteRule } from "@/api/generated/model/routeRule"
import {
  getRouteRuleDerivedName,
  getRouteRuleDisplayName,
  isRouteRuleNameGenerated,
} from "@/pages/routing-rules-utils"

const rule = (displayName?: string, list?: string[]): RouteRule =>
  ({ outbound: "wan", display_name: displayName, list }) as RouteRule

const listNames: Record<string, string> = {
  google_tv: "google_tv",
  ads: "Реклама и трекеры",
  b2ip: "b2ip",
  porn: "Adult content (18+)",
}
const displayNameOf = (technicalId: string) =>
  listNames[technicalId] ?? technicalId

describe("routing rule without a name", () => {
  test("is reported as generated so the table can mute it", () => {
    expect(isRouteRuleNameGenerated(rule())).toBe(true)
    expect(isRouteRuleNameGenerated(rule(""))).toBe(true)
    // A name of spaces is not a name: the config writer trims it away too.
    expect(isRouteRuleNameGenerated(rule("   "))).toBe(true)
  })

  test("is not reported as generated once the user names it", () => {
    expect(isRouteRuleNameGenerated(rule("Telegram"))).toBe(false)
  })

  test("still resolves to the positional identifier for links and labels", () => {
    // Dependency labels, aria-labels and edit hrefs need a stable identifier,
    // so the fallback stays #N even though the table shows "Без названия".
    expect(getRouteRuleDisplayName(rule(), 2)).toBe("#3")
    expect(getRouteRuleDisplayName(rule("Telegram"), 2)).toBe("Telegram")
  })

  test("derives an honest name from the rule's lists", () => {
    expect(
      getRouteRuleDerivedName(rule(undefined, ["google_tv"]), displayNameOf)
    ).toBe("google_tv")
    expect(
      getRouteRuleDerivedName(rule(undefined, ["ads"]), displayNameOf)
    ).toBe("Реклама и трекеры")
    expect(
      getRouteRuleDerivedName(rule(undefined, ["b2ip", "porn"]), displayNameOf)
    ).toBe("b2ip +1")
  })

  test("uses the technical id when a list has no friendly name", () => {
    expect(
      getRouteRuleDerivedName(rule(undefined, ["unknown_list"]), displayNameOf)
    ).toBe("unknown_list")
  })

  test("keeps rules without lists honestly unnamed", () => {
    expect(getRouteRuleDerivedName(rule(), displayNameOf)).toBeUndefined()
    expect(
      getRouteRuleDerivedName(rule(undefined, ["  "]), displayNameOf)
    ).toBeUndefined()
  })
})
