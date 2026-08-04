import { describe, expect, test } from "bun:test"

import {
  DNS_PRESETS,
  findDnsPresetByAddress,
  getDnsPreset,
} from "../src/data/dns-presets"
import {
  resolveDnsTemplateSelection,
  findSavedDnsTemplate,
  getSavedDnsTemplateSelection,
} from "../src/components/dns/dns-preset-selection"

describe("DNS presets", () => {
  test("resolves built-in and saved templates through the shared picker model", () => {
    expect(resolveDnsTemplateSelection("cloudflare", [])).toMatchObject({
      name: "Cloudflare",
      primaryAddress: "1.1.1.1",
      technicalSeed: "cloudflare",
    })

    expect(
      resolveDnsTemplateSelection(
        getSavedDnsTemplateSelection({ name: "Office DNS" }),
        [
          {
            name: "Office DNS",
            primary_ipv4: "192.0.2.53",
            secondary_ipv4: "192.0.2.54",
          },
        ]
      )
    ).toEqual({
      name: "Office DNS",
      primaryAddress: "192.0.2.53",
      secondaryAddress: "192.0.2.54",
      technicalSeed: "Office DNS",
    })
  })

  test("contains two distinct valid IPv4 addresses for every provider", () => {
    const ipv4Pattern =
      /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/

    expect(DNS_PRESETS).toHaveLength(5)
    for (const preset of DNS_PRESETS) {
      expect(preset.primaryAddress).toMatch(ipv4Pattern)
      expect(preset.secondaryAddress).toMatch(ipv4Pattern)
      expect(preset.secondaryAddress).not.toBe(preset.primaryAddress)
    }
  })

  test("finds providers by primary and secondary address", () => {
    expect(findDnsPresetByAddress(" 1.1.1.1 ")?.id).toBe("cloudflare")
    expect(findDnsPresetByAddress("149.112.112.112")?.id).toBe("quad9")
    expect(findDnsPresetByAddress("192.0.2.1")).toBeUndefined()
  })

  test("returns a preset by its typed id", () => {
    expect(getDnsPreset("google")?.secondaryAddress).toBe("8.8.4.4")
  })

  test("pins the canonical Yandex DNS endpoints", () => {
    expect(getDnsPreset("yandex")).toEqual({
      id: "yandex",
      name: "Yandex DNS",
      primaryAddress: "77.88.8.8",
      secondaryAddress: "77.88.8.1",
    })
  })

  test("keeps a saved template selected after templates are reordered", () => {
    const office = {
      name: "Office DNS",
      primary_ipv4: "192.0.2.53",
    }
    const selection = getSavedDnsTemplateSelection(office)
    const reordered = [
      { name: "Lab DNS", primary_ipv4: "198.51.100.53" },
      office,
    ]

    expect(findSavedDnsTemplate(selection, reordered)).toBe(office)
  })
})
