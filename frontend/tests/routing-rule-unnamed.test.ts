import { describe, expect, test } from "bun:test"

import type { RouteRule } from "@/api/generated/model/routeRule"
import {
  getRouteRuleDisplayName,
  isRouteRuleNameGenerated,
} from "@/pages/routing-rules-utils"

const rule = (displayName?: string): RouteRule =>
  ({ outbound: "wan", display_name: displayName }) as RouteRule

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
})
