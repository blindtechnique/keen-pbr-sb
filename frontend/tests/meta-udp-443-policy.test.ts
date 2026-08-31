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
      expect(advanced.metaUdp443PolicyWarningDescription).toContain("UDP/3478")
      expect(advanced.metaUdp443PolicyWarningDescription).toContain("UDP/5349")
      expect(advanced.metaUdp443PolicyWarningDescription).toContain("P2P")
      expect(advanced.metaUdp443PolicyWarningDescription).toContain("IPv6")
      expect(advanced.metaUdp443AndroidBackgroundDescription).toContain(
        "WhatsApp"
      )
    }

    expect(
      enTranslation.pages.settings.advanced.metaUdp443PolicyWarningDescription
    ).toContain("rejects only UDP/443")
    expect(
      enTranslation.pages.settings.advanced.metaUdp443PolicyWarningDescription
    ).toContain("may then use TCP")
    expect(
      enTranslation.pages.settings.advanced.metaUdp443PolicyWarningDescription
    ).toContain("may improve initial")
    expect(
      enTranslation.pages.settings.advanced.metaUdp443PolicyWarningDescription
    ).toContain("sessions stalling")
    expect(
      enTranslation.pages.settings.advanced.metaUdp443PolicyWarningTitle
    ).toContain("Experimental")
    expect(
      enTranslation.pages.settings.advanced.metaUdp443PolicyWarningDescription
    ).toContain("disable IPv6 routing")
    expect(
      enTranslation.pages.settings.advanced
        .metaUdp443AndroidBackgroundDescription
    ).toContain("Unrestricted")
    expect(
      enTranslation.pages.settings.advanced
        .metaUdp443AndroidBackgroundDescription
      // Lower case on purpose. The hint used to name Samsung's own menu
      // items - "Sleeping and Deep sleeping apps" - which is the wording of
      // one manufacturer, not of Android. It still has to tell the reader
      // about sleeping-app lists; it no longer has to spell them the way one
      // vendor does.
    ).toContain("sleeping")
    expect(
      enTranslation.pages.settings.advanced
        .metaUdp443AndroidBackgroundDescription
    ).toContain("Balanced")

    expect(
      ruTranslation.pages.settings.advanced.metaUdp443PolicyWarningDescription
    ).toContain("отклоняет только UDP/443")
    expect(
      ruTranslation.pages.settings.advanced.metaUdp443PolicyWarningDescription
    ).toContain("может использовать TCP")
    expect(
      ruTranslation.pages.settings.advanced.metaUdp443PolicyWarningDescription
    ).toContain("может ускорить первую")
    expect(
      ruTranslation.pages.settings.advanced.metaUdp443PolicyWarningDescription
    ).toContain("последующее зависание")
    expect(
      ruTranslation.pages.settings.advanced.metaUdp443PolicyWarningTitle
    ).toContain("Экспериментальный")
    expect(
      ruTranslation.pages.settings.advanced.metaUdp443PolicyWarningDescription
    ).toContain("отключить IPv6-маршрутизацию")
    expect(
      ruTranslation.pages.settings.advanced
        .metaUdp443AndroidBackgroundDescription
    ).toContain("Без ограничений")
    expect(
      ruTranslation.pages.settings.advanced
        .metaUdp443AndroidBackgroundDescription
    ).toContain("спящих")
    expect(
      ruTranslation.pages.settings.advanced
        .metaUdp443AndroidBackgroundDescription
    ).toContain("Сбалансированный")
  })
})
