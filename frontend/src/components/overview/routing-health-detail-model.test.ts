import { describe, expect, test } from "bun:test"

import {
  localizeFirewallAction,
  localizeRouteType,
  localizeRoutingHealthDetail,
  localizeRoutingHealthStatus,
} from "./routing-health-detail-model"

const translations: Record<string, string> = {
  "overview.routing.statuses.degraded": "Есть проблемы",
  "overview.routing.statuses.missing": "Отсутствует",
  "overview.routing.actions.mark": "маркировка",
  "overview.routing.ipv4": "IPv4",
  "overview.routing.details.criteriaAny": "любое",
  "overview.routing.details.ruleNotFound":
    "Правило не найдено: {{backend}}/{{table}}/{{family}}/{{criteria}}",
}

function translate(key: string, options?: Record<string, unknown>) {
  let value = translations[key] ?? key
  Object.entries(options ?? {}).forEach(([name, replacement]) => {
    value = value.replace(`{{${name}}}`, String(replacement))
  })
  return value
}

describe("routing health localization", () => {
  test("localizes summary, row status and firewall action", () => {
    expect(localizeRoutingHealthStatus("degraded", translate)).toBe(
      "Есть проблемы"
    )
    expect(localizeRoutingHealthStatus("missing", translate)).toBe(
      "Отсутствует"
    )
    expect(localizeFirewallAction("mark", translate)).toBe("маркировка")
  })

  test("localizes a stable missing iptables rule detail", () => {
    expect(
      localizeRoutingHealthDetail(
        "rule not found in iptables raw table (family=ipv4 criteria=any)",
        translate
      )
    ).toBe("Правило не найдено: iptables/raw/IPv4/любое")
  })

  test("keeps an unknown technical detail intact", () => {
    expect(localizeRoutingHealthDetail("future diagnostic", translate)).toBe(
      "future diagnostic"
    )
  })

  test("labels unknown statuses, actions and route types without inventing a verdict", () => {
    expect(localizeRoutingHealthStatus("future_status", translate)).toBe(
      "overview.routing.statuses.unknown"
    )
    expect(localizeFirewallAction("future_action", translate)).toBe(
      "overview.routing.actions.unknown"
    )
    expect(localizeRouteType("future_route", translate)).toBe(
      "overview.routing.routeTypes.unknown"
    )
  })

  test.each(["unicast", "blackhole", "unreachable"])(
    "localizes the backend route type %s",
    (type) => {
      expect(localizeRouteType(type, translate)).toBe(
        `overview.routing.routeTypes.${type}`
      )
    }
  )

  test.each([
    ["unexpected route present in table", "unexpectedRoute"],
    [
      "rule not found in nftables prerouting chain (family=ipv6 criteria=any)",
      "nftRuleNotFound",
    ],
    ["fwmark mismatch: expected 0x10000 got 0x20000", "markMismatch"],
    [
      "fwmark mask mismatch: expected 0x10000/0xf0000 got 0x20000/0xfffff",
      "markMaskMismatch",
    ],
    ["expected MARK rule but found DROP rule", "actionMismatch"],
    [
      "route type mismatch: expected 'unicast', got 'blackhole'.",
      "routeTypeMismatch",
    ],
    ["metric mismatch: expected '10', got '20'.", "metricMismatch"],
    [
      "ip rule fwmark=0x10000/0xf0000 table=120 missing: IPv4 IPv6",
      "policyMissing",
    ],
  ])("localizes the exact backend diagnostic %s", (detail, key) => {
    expect(localizeRoutingHealthDetail(detail, translate)).toBe(
      `overview.routing.details.${key}`
    )
  })

  test("preserves every expected/actual parameter and does not match extended unknown errors", () => {
    const parameters = (_key: string, values?: Record<string, unknown>) =>
      JSON.stringify(values)
    expect(
      localizeRoutingHealthDetail(
        "fwmark mask mismatch: expected 0x10000/0xf0000 got 0x20000/0xfffff",
        parameters
      )
    ).toBe('{"expected":"0x10000/0xf0000","actual":"0x20000/0xfffff"}')
    const unexpected = "metric mismatch: expected '10', got '20'. extra cause"
    expect(localizeRoutingHealthDetail(unexpected, translate)).toBe(unexpected)
  })
})
