import { describe, expect, test } from "bun:test"

import {
  createOutboundDisplayNameMap,
  getOutboundDisplayName,
  getOutboundReferenceLabel,
  sortOutboundsByDisplayName,
} from "../src/lib/outbound-display"

describe("outbound display names", () => {
  const outbounds = [
    {
      type: "interface" as const,
      tag: "vpn_backup",
      display_name: "Резервный VPN",
    },
    {
      type: "interface" as const,
      tag: "vpn_primary",
      display_name: "Основной VPN",
    },
    {
      type: "ignore" as const,
      tag: "legacy",
    },
  ]

  test("shows aliases while keeping the technical tag available as context", () => {
    expect(getOutboundDisplayName(outbounds[0])).toBe("Резервный VPN")
    expect(getOutboundReferenceLabel(outbounds[0])).toBe(
      "Резервный VPN (vpn_backup)"
    )
    expect(getOutboundReferenceLabel(outbounds[2])).toBe("legacy")
  })

  test("builds reference maps and sorts by the visible name", () => {
    expect(createOutboundDisplayNameMap(outbounds).get("vpn_primary")).toBe(
      "Основной VPN"
    )
    expect(
      sortOutboundsByDisplayName(outbounds).map(getOutboundDisplayName)
    ).toEqual(["legacy", "Основной VPN", "Резервный VPN"])
  })
})
