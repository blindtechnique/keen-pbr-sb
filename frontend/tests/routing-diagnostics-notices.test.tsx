import { describe, expect, test } from "bun:test"
import { createInstance } from "i18next"
import { renderToStaticMarkup } from "react-dom/server"
import { I18nextProvider } from "react-i18next"

import type { RoutingTestResponse } from "../src/api/generated/model"
import { RoutingDiagnosticsResult } from "../src/components/overview/routing-diagnostics-result"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"

async function render(
  language: "ru" | "en",
  overrides: Partial<RoutingTestResponse> = {}
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
      <RoutingDiagnosticsResult
        diagnostics={{
          target: "youtube.com",
          is_domain: true,
          config_scope: "active",
          unapplied_draft: false,
          resolved_ips: ["203.0.113.1"],
          warnings: [],
          no_matching_rule: true,
          rule_diagnostics: [],
          results: [],
          ...overrides,
        }}
      />
    </I18nextProvider>
  )
}

describe("routing notices remain separate from nfqws lists", () => {
  test.each(["ru", "en"] as const)(
    "no separate PBR rule is neutral, not a warning in %s",
    async (language) => {
      const translation = (language === "ru" ? ruTranslation : enTranslation)
        .overview.routingDiagnostics
      const html = await render(language)
      expect(html).toContain(translation.noMatchingRule)
      expect(html).not.toContain('role="alert"')
      expect(html).not.toContain("border-amber-400/40")
      expect(html).not.toContain("overview.routingDiagnostics.")
    }
  )

  test("actual DNS errors remain warnings", async () => {
    const html = await render("en", { dns_error: "Diagnostic DNS failed" })
    expect(html).toContain('role="alert"')
    expect(html).toContain("Diagnostic DNS failed")
    expect(html).toContain(
      enTranslation.overview.routingDiagnostics.noMatchingRule
    )
  })

  test("an unapplied draft still has its own warning", async () => {
    const html = await render("ru", { unapplied_draft: true })
    expect(html).toContain('role="alert"')
    expect(html).toContain(
      ruTranslation.overview.routingDiagnostics.unappliedDraft
    )
  })
})
