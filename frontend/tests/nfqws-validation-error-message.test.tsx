import { describe, expect, spyOn, test } from "bun:test"
import { createInstance } from "i18next"
import { I18nextProvider } from "react-i18next"
import { renderToStaticMarkup } from "react-dom/server"

import { nfqwsAction } from "../src/api/nfqws"
import { NfqwsValidationErrorMessage } from "../src/components/nfqws/validation-error-message"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"

async function renderError(
  error: unknown,
  language: "ru" | "en",
  summary?: string
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
      <NfqwsValidationErrorMessage
        error={error}
        summary={summary}
        fallbackSummary="fallback summary"
      />
    </I18nextProvider>
  )
}

describe("nfqws candidate error rendering", () => {
  test.each(["ru", "en"] as const)(
    "a rejected apply keeps metadata through the actual API adapter in %s",
    async (language) => {
      const messages = language === "ru" ? ruTranslation : enTranslation
      const fetchSpy = spyOn(globalThis, "fetch").mockResolvedValue(
        new Response(
          JSON.stringify({
            error: "candidate rejected",
            code: "validation",
            validation_errors: [
              {
                path: "NFQWS_ARGS/--filter-tcp",
                message:
                  "Raw diagnostic with changed wording\nand another line",
                code: "nfqws.port.range",
              },
            ],
          }),
          { status: 400, headers: { "Content-Type": "application/json" } }
        )
      )
      try {
        const error = await nfqwsAction({ action: "apply_strategy" }).catch(
          (failure: unknown) => failure
        )
        const html = await renderError(error, language)
        expect(html.split("<details")[0]).toContain(
          messages.serverValidation.portNumber
        )
        expect(html.split("<details")[0]).not.toContain("Raw diagnostic")
        expect(html).toContain("Raw diagnostic with changed wording")
        expect(html).toContain("NFQWS_ARGS/--filter-tcp")
        expect(fetchSpy).toHaveBeenCalledTimes(1)
      } finally {
        fetchSpy.mockRestore()
      }
    }
  )

  test.each(["ru", "en"] as const)(
    "binary rejection is translated without replacing its exact details in %s",
    async (language) => {
      const messages = language === "ru" ? ruTranslation : enTranslation
      const html = await renderError(
        {
          details: {
            code: "validation",
            validation_errors: [
              {
                path: "NFQWS_ARGS",
                message: "nfqws2 --dry-run: Original binary diagnostic",
                code: "nfqws.binary.rejected",
              },
            ],
          },
        },
        language
      )
      expect(html.split("<details")[0]).toContain(
        messages.serverValidation.nfqwsBinaryRejected
      )
      expect(html.split("<details")[0]).not.toContain("Original binary")
      expect(html).toContain("nfqws2 --dry-run: Original binary diagnostic")
    }
  )

  test.each(["ru", "en"] as const)(
    "non-validation failures and an explicit partial-save summary keep their presentation in %s",
    async (language) => {
      const messages = language === "ru" ? ruTranslation : enTranslation
      const busy = await renderError(
        { message: "original runtime cause", details: { code: "busy" } },
        language
      )
      expect(busy).toContain(messages.operationErrors.busy)
      expect(busy.split("<details")[0]).not.toContain("original runtime cause")
      const partial = await renderError(
        {
          message: "restart failed",
          details: {
            code: "validation",
            validation_errors: [
              { path: "NFQWS_ARGS", message: "legacy detail" },
            ],
          },
        },
        language,
        messages.nfqws.connectivity.savedRestartFailed
      )
      expect(partial.split("<details")[0]).toContain(
        messages.nfqws.connectivity.savedRestartFailed
      )
      expect(partial).toContain("legacy detail")
    }
  )
})
