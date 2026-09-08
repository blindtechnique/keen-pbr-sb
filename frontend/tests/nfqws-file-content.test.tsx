import { describe, expect, test } from "bun:test"
import { createInstance } from "i18next"
import type { ComponentProps } from "react"
import { renderToStaticMarkup } from "react-dom/server"
import { I18nextProvider } from "react-i18next"

import { NfqwsFileContent } from "../src/components/nfqws/file-content"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"

async function renderContent(
  props: Partial<ComponentProps<typeof NfqwsFileContent>>,
  language: "ru" | "en" = "en"
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
      <NfqwsFileContent
        error={null}
        loading={false}
        onChange={() => {}}
        onRetry={() => {}}
        readonly={true}
        {...props}
      />
    </I18nextProvider>
  )
}

describe("nfqws bounded file preview", () => {
  test.each(["ru", "en"] as const)(
    "marks a truncated log in %s and keeps it read-only",
    async (language) => {
      const html = await renderContent(
        { data: { content: "newest record", truncated: true } },
        language
      )
      const translation = language === "ru" ? ruTranslation : enTranslation
      expect(html).toContain(translation.nfqws.logTailShown)
      expect(html).toContain('role="status"')
      expect(html).toContain("newest record")
      expect(html).toContain("readOnly")
    }
  )

  test("does not label a small or legacy complete response as truncated", async () => {
    for (const data of [
      { content: "complete", truncated: false },
      { content: "complete" },
    ]) {
      const html = await renderContent({ data })
      expect(html).toContain("complete")
      expect(html).not.toContain(enTranslation.nfqws.logTailShown)
    }
  })

  test.each(["ru", "en"] as const)(
    "shows a file error and retry in %s instead of an empty editor",
    async (language) => {
      const html = await renderContent(
        { error: new Error("fixture read failed"), readonly: false },
        language
      )
      const translation = language === "ru" ? ruTranslation : enTranslation
      expect(html).toContain(translation.nfqws.fileLoadFailed)
      expect(html).toContain(translation.common.retry)
      expect(html).not.toContain("<textarea")
    }
  )

  test("does not silently present a stale cached log after a refresh error", async () => {
    const html = await renderContent({
      data: { content: "stale cache", truncated: true },
      error: new Error("fixture read failed"),
    })
    expect(html).toContain(enTranslation.nfqws.fileLoadFailed)
    expect(html).not.toContain("stale cache")
    expect(html).not.toContain("<textarea")
    expect(html).not.toContain(enTranslation.nfqws.logTailShown)
  })

  test("preserves an editable local draft when refreshing the saved file fails", async () => {
    const html = await renderContent({
      draftContent: "unsaved user entry",
      data: { content: "older saved entry" },
      error: new Error("fixture read failed"),
      readonly: false,
    })
    expect(html).toContain(enTranslation.nfqws.fileLoadFailed)
    expect(html).toContain("unsaved user entry")
    expect(html).toContain("<textarea")
    expect(html).not.toContain("older saved entry")
    expect(html).not.toContain("readOnly")
  })

  test("shows initial loading without creating a blank editor", async () => {
    const html = await renderContent({ loading: true, readonly: false })
    expect(html).not.toContain("<textarea")
    expect(html).not.toContain(enTranslation.nfqws.fileLoadFailed)
  })
})
