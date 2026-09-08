import { describe, expect, spyOn, test } from "bun:test"
import { createInstance } from "i18next"
import { renderToStaticMarkup } from "react-dom/server"
import { I18nextProvider } from "react-i18next"
import { Router } from "wouter"

import type { ConfigObject, Outbound } from "../src/api/generated/model"
import { FirstRunCard } from "../src/components/overview/first-run-card"
import { shouldOfferInitialSetup } from "../src/components/overview/first-run-state"
import i18n from "../src/i18n"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"
import {
  getOutboundDisplayName,
  getOutboundSelectDisplayName,
} from "../src/lib/outbound-display"

const defaults: Outbound[] = [
  { tag: "wan", type: "table", table: 254 },
  { tag: "block", type: "blackhole" },
]
const clean: ConfigObject = {
  outbounds: defaults,
  lists: {},
  route: { rules: [] },
}

describe("first-install invitation", () => {
  test.each(["full", "headless"])(
    "recognizes the actual Keenetic %s seed",
    async (variant) => {
      const config = await Bun.file(
        new URL(
          `../../packages/keenetic/keen-pbr/files/opt/etc/keen-pbr/config.${variant}.example.json`,
          import.meta.url
        )
      ).json()
      expect(shouldOfferInitialSetup({ config, transports: [] })).toBe(true)
    }
  )

  test("recognizes empty and stock-only installations, without requiring manual DNS", () => {
    expect(shouldOfferInitialSetup({ config: {}, transports: [] })).toBe(true)
    expect(shouldOfferInitialSetup({ config: clean, transports: [] })).toBe(
      true
    )
    expect(
      shouldOfferInitialSetup({
        config: { ...clean, dns: { servers: [] } },
        transports: [],
      })
    ).toBe(true)
  })

  test("never mistakes loading, errors, visible drafts or an unknown manager for first install", () => {
    expect(shouldOfferInitialSetup({ transports: [] })).toBe(false)
    expect(shouldOfferInitialSetup({ config: clean })).toBe(false)
    expect(
      shouldOfferInitialSetup({
        config: clean,
        transports: [],
        loadFailed: true,
      })
    ).toBe(false)
    expect(
      shouldOfferInitialSetup({ config: clean, transports: [], isDraft: true })
    ).toBe(false)
  })

  test("leaves existing lists, rules, transports and user routes alone", () => {
    expect(
      shouldOfferInitialSetup({ config: clean, transports: [{ tag: "vpn" }] })
    ).toBe(false)
    expect(
      shouldOfferInitialSetup({
        config: { ...clean, lists: { local_list: {} } },
        transports: [],
      })
    ).toBe(false)
    expect(
      shouldOfferInitialSetup({
        config: {
          ...clean,
          route: {
            rules: [{ list: "local_list", outbound: "block", enabled: false }],
          },
        },
        transports: [],
      })
    ).toBe(false)
    expect(
      shouldOfferInitialSetup({
        config: {
          ...clean,
          outbounds: [
            ...defaults,
            { tag: "vpn", type: "interface", interface: "nwg1" },
          ],
        },
        transports: [],
      })
    ).toBe(false)
    expect(
      shouldOfferInitialSetup({
        config: {
          ...clean,
          outbounds: [{ tag: "wan", type: "table", table: 100 }],
        },
        transports: [],
      })
    ).toBe(false)
  })

  test("automatically disappears after creating the linked route without mutating configuration", () => {
    const before = JSON.stringify(clean)
    expect(shouldOfferInitialSetup({ config: clean, transports: [] })).toBe(
      true
    )
    const configured: ConfigObject = {
      ...clean,
      outbounds: [
        ...defaults,
        { tag: "vpn", type: "interface", interface: "vless1" },
      ],
    }
    expect(
      shouldOfferInitialSetup({ config: configured, transports: [] })
    ).toBe(false)
    expect(JSON.stringify(clean)).toBe(before)
  })

  test.each(["ru", "en"] as const)(
    "renders existing setup/restore links and guidance in %s",
    async (language) => {
      const local = createInstance()
      const translation = language === "ru" ? ruTranslation : enTranslation
      await local.init({
        lng: language,
        resources: { [language]: { translation } },
      })
      const html = renderToStaticMarkup(
        <I18nextProvider i18n={local}>
          <Router ssrPath="/">
            <FirstRunCard />
          </Router>
        </I18nextProvider>
      )
      expect(html).toContain('href="/setup"')
      expect(html).toContain('href="/restore"')
      expect(html).toContain(translation.overview.firstRun.dns)
      expect(html).toContain(translation.overview.firstRun.check)
      expect(html).not.toContain("overview.firstRun.")
    }
  )
})

describe("localized stock route names", () => {
  test("uses translations only for the exact built-ins, never overwriting an alias", () => {
    const translate = spyOn(i18n, "t")
    try {
      translate.mockReturnValueOnce("Обычный интернет")
      expect(getOutboundDisplayName(defaults[0])).toBe("Обычный интернет")
      expect(translate).toHaveBeenLastCalledWith("common.systemOutbounds.wan", {
        defaultValue: "wan",
      })
      translate.mockReturnValueOnce("Block")
      expect(getOutboundSelectDisplayName(defaults[1])).toBe("Block")
      expect(translate).toHaveBeenLastCalledWith(
        "common.systemOutbounds.block",
        { defaultValue: "block" }
      )
      expect(
        getOutboundDisplayName({ ...defaults[0], display_name: "My ISP" })
      ).toBe("My ISP")
      expect(
        getOutboundDisplayName({ tag: "wan", type: "table", table: 100 })
      ).toBe("wan")
      expect(
        getOutboundDisplayName({
          tag: "block",
          type: "interface",
          interface: "nwg1",
        })
      ).toBe("block")
      expect(translate).toHaveBeenCalledTimes(2)
    } finally {
      translate.mockRestore()
    }
  })
})
