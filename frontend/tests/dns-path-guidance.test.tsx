import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import { createInstance } from "i18next"
import { I18nextProvider } from "react-i18next"
import { renderToStaticMarkup } from "react-dom/server"
import { Router } from "wouter"

import { DnsPathGuidance } from "../src/components/overview/dns-path-guidance"
import { ruTranslation } from "../src/i18n/ru"
import { enTranslation } from "../src/i18n/en"

async function renderGuidance(
  language: "ru" | "en",
  configuration: { enabled?: boolean; block_dot?: boolean } | undefined,
  configIsDraft = false
) {
  const i18n = createInstance()
  await i18n.init({
    lng: language,
    resources: {
      ru: { translation: ruTranslation },
      en: { translation: enTranslation },
    },
    interpolation: { escapeValue: false },
  })
  return renderToStaticMarkup(
    <I18nextProvider i18n={i18n}>
      <Router ssrPath="/">
        <DnsPathGuidance
          configuration={configuration}
          configIsDraft={configIsDraft}
        />
      </Router>
    </I18nextProvider>
  )
}

describe("DNS path guidance", () => {
  for (const language of ["ru", "en"] as const) {
    const copy = (language === "ru" ? ruTranslation : enTranslation).overview
      .dnsCheck.path
    test(`saved settings are not presented as live proof in ${language}`, async () => {
      const html = await renderGuidance(language, { enabled: true })
      expect(html).toContain(copy.enforcementOn)
      expect(html).toContain(copy.dotBlocked)
      expect(html).toContain(copy.enforcementScope)
      expect(html).not.toContain(copy.dotAllowed)
      expect(html).not.toContain("<details open")
      expect(html).toContain(copy.openSettings)
    })
    test(`missing settings do not look disabled in ${language}`, async () => {
      const html = await renderGuidance(language, undefined)
      expect(html).toContain(copy.configUnknown)
      expect(html).not.toContain(copy.enforcementOff)
      expect(html).not.toContain(copy.dotBlocked)
    })
    test(`draft settings are not reported as saved in ${language}`, async () => {
      for (const enabled of [true, false]) {
        const html = await renderGuidance(language, { enabled }, true)
        expect(html).toContain(copy.draft)
        expect(html).not.toContain(copy.enforcementOn)
        expect(html).not.toContain(copy.enforcementOff)
        expect(html).not.toContain(copy.dotBlocked)
      }
    })
    test(`DoT opt-out and disabled enforcement remain distinct in ${language}`, async () => {
      const allowed = await renderGuidance(language, {
        enabled: true,
        block_dot: false,
      })
      expect(allowed).toContain(copy.dotAllowed)
      expect(allowed).not.toContain(copy.dotBlocked)
      const disabled = await renderGuidance(language, { enabled: false })
      expect(disabled).toContain(copy.enforcementOff)
      expect(disabled).not.toContain(copy.dotBlocked)
      expect(disabled).not.toContain(copy.dotAllowed)
    })
    test(`device help is scoped and has official links in ${language}`, async () => {
      const html = await renderGuidance(language, { enabled: false })
      expect(html).toContain(copy.scope)
      expect(html).toContain(copy.encryptionTradeoff)
      expect(html).toContain(copy.androidTitle)
      expect(html).toContain(copy.browserTitle)
      expect(html).toContain(copy.appleTitle)
      expect(html).toContain(
        'href="https://support.google.com/pixelphone/answer/2819583"'
      )
      expect(html).toContain(
        'href="https://support.google.com/chrome/answer/10468685"'
      )
      expect(html).toContain('href="https://support.apple.com/en-us/102602"')
    })
  }

  test("settings action navigates to the existing checkbox without a mutation", () => {
    const guidance = readFileSync(
      new URL(
        "../src/components/overview/dns-path-guidance.tsx",
        import.meta.url
      ),
      "utf8"
    )
    const settings = readFileSync(
      new URL("../src/pages/general-config-page.tsx", import.meta.url),
      "utf8"
    )
    expect(guidance).toContain("/general?focus=client-dns-enforcement#general")
    expect(guidance).not.toMatch(/fetch\(|Mutation|\.mutate\(/)
    expect(settings).toContain(
      'document.getElementById("client-dns-enforcement")'
    )
    expect(settings).toContain("field?.focus({ preventScroll: true })")
  })
})
