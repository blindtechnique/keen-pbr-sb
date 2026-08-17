import { describe, expect, test } from "bun:test"

import {
  createOutboundDisplayNameMap,
  getOutboundDisplayName,
  getOutboundReferenceLabel,
  getOutboundSelectDisplayName,
  getOutboundSelectReferenceLabel,
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

  test("uses an invariant order instead of the browser locale", () => {
    expect(
      sortOutboundsByDisplayName([
        { type: "ignore", tag: "z", display_name: "ёж" },
        { type: "ignore", tag: "a", display_name: "Alpha" },
        { type: "ignore", tag: "b", display_name: "alpha" },
      ]).map((outbound) => outbound.tag)
    ).toEqual(["a", "b", "z"])
  })

  test("uses the NDMS label for a legacy interface route without an alias", () => {
    const outbound = {
      type: "interface" as const,
      tag: "legacy_nwg2",
      interface: "nwg2",
    }
    const labelFor = (interfaceName: string) =>
      interfaceName === "nwg2" ? "Домашний AWG" : interfaceName

    expect(getOutboundSelectDisplayName(outbound, labelFor)).toBe(
      "Домашний AWG"
    )
    expect(getOutboundSelectReferenceLabel(outbound, labelFor)).toBe(
      "Домашний AWG (legacy_nwg2)"
    )
  })

  test("keeps an explicit route alias ahead of the NDMS interface label", () => {
    const outbound = {
      type: "interface" as const,
      tag: "primary",
      display_name: "Основной маршрут",
      interface: "nwg2",
    }

    expect(getOutboundSelectDisplayName(outbound, () => "Домашний AWG")).toBe(
      "Основной маршрут"
    )
  })
})
