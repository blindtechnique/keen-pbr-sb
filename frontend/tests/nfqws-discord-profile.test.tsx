import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import { createInstance } from "i18next"
import { renderToStaticMarkup } from "react-dom/server"
import { I18nextProvider } from "react-i18next"

import { NfqwsProfileCards } from "../src/components/nfqws/profile-cards"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"
import {
  canonicalNfqwsProfileTier,
  NFQWS_PROFILE_ORDER,
  parseNfqwsStrategy,
} from "../src/pages/nfqws-strategy-model"

const names = ["01 safe", "02 balanced", "03 max"]
const profiles = names.map((name, index) => ({
  name,
  tier: NFQWS_PROFILE_ORDER[index]!,
  content: readFileSync(
    new URL(
      `../../packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/nfqws-strategies/${name}/nfqws2.conf`,
      import.meta.url
    ),
    "utf8"
  ),
  active: false,
  modified: false,
}))

describe("Discord experiment inside Max", () => {
  test("keeps the same three selectable profiles", () => {
    expect(NFQWS_PROFILE_ORDER).toEqual(["safe", "balanced", "max"])
    for (const profile of profiles) {
      expect(
        canonicalNfqwsProfileTier({
          ...profile,
          builtin: true,
          overridden: false,
        })
      ).toBe(profile.tier)
      if (profile.tier !== "max") {
        expect(profile.content).not.toContain("discord_tcp_exp")
      }
    }
  })

  test("shows two candidates in each new pool without hiding the existing pools", () => {
    const summary = parseNfqwsStrategy(profiles[2]!.content)
    expect(summary.status).toBe("complete")
    const experiments = summary.pools.filter((pool) =>
      pool.rotation?.stateKey?.endsWith("_exp")
    )
    expect(experiments.map((pool) => pool.rotation?.stateKey)).toEqual([
      "discord_tcp_exp",
      "discord_media_tcp_exp",
      "discord_udp_exp",
    ])
    expect(experiments.map((pool) => pool.rotation?.slots)).toEqual([2, 2, 2])
    expect(experiments[0]!.tcpPorts).toBe("443")
    expect(experiments[1]!.domains).toEqual(["discord.media"])
    expect(experiments[2]!.udpPorts).toBe("50000-50099,19294-19344")
    expect(
      summary.pools.some((pool) => pool.rotation?.stateKey === "gv_tcp")
    ).toBe(true)
    expect(
      summary.pools.some((pool) => pool.rotation?.stateKey === "discord_udp")
    ).toBe(true)
  })

  test.each(["ru", "en"])(
    "labels the experiment without adding a button in %s",
    async (language) => {
      const i18n = createInstance()
      await i18n.init({
        lng: language,
        resources: {
          ru: { translation: ruTranslation },
          en: { translation: enTranslation },
        },
        interpolation: { escapeValue: false },
      })
      let applied = 0
      const html = renderToStaticMarkup(
        <I18nextProvider i18n={i18n}>
          <NfqwsProfileCards
            profiles={profiles}
            onApply={() => applied++}
            onOpen={() => {}}
            onRestore={() => {}}
          />
        </I18nextProvider>
      )
      expect(html.match(/<li /g)).toHaveLength(3)
      expect(html.match(/<button /g)).toHaveLength(6)
      expect(html).toContain(
        language === "ru" ? "Экспериментальный" : "Experimental"
      )
      expect(html).toContain(
        language === "ru"
          ? "работа звонков не гарантируется"
          : "calls are not guaranteed to work"
      )
      expect(html).toContain(
        language === "ru" ? "прежнюю стратегию" : "previous strategy"
      )
      expect(applied).toBe(0)
    }
  )
})
