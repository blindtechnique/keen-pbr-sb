import { describe, expect, test } from "bun:test"

import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"
import {
  getMetaUdp443Policy,
  withMetaUdp443Policy,
} from "../src/lib/meta-udp-443-policy"

describe("Meta UDP/443 policy", () => {
  test("uses balanced mode for an omitted or unknown backend value", () => {
    expect(getMetaUdp443Policy(undefined)).toBe("balanced")
    expect(getMetaUdp443Policy({})).toBe("balanced")
    expect(getMetaUdp443Policy({ meta_udp443_policy: "future_mode" })).toBe(
      "balanced"
    )
    expect(getMetaUdp443Policy({ meta_udp443_policy: "messages_first" })).toBe(
      "messages_first"
    )
  })

  test("persists only the opt-in mode and preserves unrelated daemon fields", () => {
    expect(
      withMetaUdp443Policy({ ipv6_enabled: true }, "messages_first")
    ).toEqual({
      ipv6_enabled: true,
      meta_udp443_policy: "messages_first",
    })

    expect(
      withMetaUdp443Policy(
        {
          ipv6_enabled: true,
          meta_udp443_policy: "messages_first" as const,
        },
        "balanced"
      )
    ).toEqual({ ipv6_enabled: true })
  })

  test("explains the scoped UDP fallback and call trade-off in both locales", () => {
    for (const translation of [enTranslation, ruTranslation]) {
      const advanced = translation.pages.settings.advanced
      expect(Object.keys(advanced.metaUdp443PolicyOptions).sort()).toEqual([
        "balanced",
        "messagesFirst",
      ])
      expect(advanced.metaUdp443PolicyWarningDescription).toContain("UDP/443")
      expect(advanced.metaUdp443PolicyWarningDescription).toContain("TCP")
      expect(advanced.metaUdp443PolicyWarningDescription).toContain("10–20")
      expect(advanced.metaUdp443PolicyWarningDescription).toContain("Instagram")
      expect(advanced.metaUdp443PolicyWarningDescription).toContain("STUN")
      expect(advanced.metaUdp443PolicyWarningDescription).toContain("ICE")
      expect(advanced.metaUdp443PolicyWarningDescription).toContain("P2P")
    }
  })
})
