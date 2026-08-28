import { describe, expect, test } from "bun:test"

import {
  localizeFirewallAction,
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
})
