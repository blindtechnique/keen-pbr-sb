import { describe, expect, test } from "bun:test"

import { localizeRoutingHealthDetail } from "../src/components/overview/routing-health-detail-model"

const translate = (key: string) =>
  key === "overview.routing.details.disabledByConfiguration"
    ? "Отключено в настройках"
    : key

describe("routing health detail localization", () => {
  test("localizes a known backend detail", () => {
    expect(
      localizeRoutingHealthDetail("disabled by configuration", translate)
    ).toBe("Отключено в настройках")
  })

  test("matches a known detail independent of casing and outer whitespace", () => {
    expect(
      localizeRoutingHealthDetail("  Disabled by configuration  ", translate)
    ).toBe("Отключено в настройках")
  })

  test("preserves unknown diagnostic details verbatim", () => {
    expect(localizeRoutingHealthDetail("live rule mismatch", translate)).toBe(
      "live rule mismatch"
    )
  })

  test("hides empty and healthy details", () => {
    expect(localizeRoutingHealthDetail("ok", translate)).toBeNull()
    expect(localizeRoutingHealthDetail(undefined, translate)).toBeNull()
  })
})
