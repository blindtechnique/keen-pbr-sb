import { expect, test } from "bun:test"
import { createInstance } from "i18next"
import { I18nextProvider } from "react-i18next"
import { renderToStaticMarkup } from "react-dom/server"

import { parseUpdateTransport } from "@/components/settings/software-update-transport"
import { OperationErrorMessage } from "@/components/shared/operation-error-message"
import { enTranslation } from "@/i18n/en"
import { ruTranslation } from "@/i18n/ru"

test.each(["ru", "en"] as const)(
  "update transport protocol errors keep a localized summary in %s",
  async (language) => {
    const i18n = createInstance()
    await i18n.init({
      lng: language,
      resources: {
        ru: { translation: ruTranslation },
        en: { translation: enTranslation },
      },
    })
    let cause: unknown
    try {
      parseUpdateTransport(null)
    } catch (error) {
      cause = error
    }
    expect(cause).toBeInstanceOf(Error)
    const translation = language === "ru" ? ruTranslation : enTranslation
    const html = renderToStaticMarkup(
      <I18nextProvider i18n={i18n}>
        <OperationErrorMessage
          error={cause}
          fallbackSummary={
            translation.pages.settings.softwareUpdate.downloadPathFailed
          }
        />
      </I18nextProvider>
    )
    expect(html.split("<details")[0]).toContain(
      translation.pages.settings.softwareUpdate.downloadPathFailed
    )
    expect(html.split("<details")[0]).not.toContain(
      "Invalid update transport response"
    )
    expect(html).toContain("Invalid update transport response")
    expect(html).not.toContain("<details open")
  }
)

test("update transport control routes errors through the contextual presenter", async () => {
  const source = await Bun.file(
    new URL(
      "../src/components/settings/update-transport-control.tsx",
      import.meta.url
    )
  ).text()
  expect(source).toContain("<OperationErrorMessage")
  expect(source).toMatch(
    /fallbackSummary=\{t\(\s*"pages\.settings\.softwareUpdate\.downloadPathFailed"/
  )
  expect(source).not.toContain("error.message")
})
