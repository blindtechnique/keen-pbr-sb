import { describe, expect, test } from "bun:test"
import { createInstance } from "i18next"
import { I18nextProvider } from "react-i18next"
import { renderToStaticMarkup } from "react-dom/server"
import { SoftwareUpdateActions } from "../src/components/settings/software-update-actions"
import { ruTranslation } from "../src/i18n/ru"
import { enTranslation } from "../src/i18n/en"

describe("software update pinned actions", () => {
  for (const language of ["ru", "en"] as const) {
    for (const confirmation of [null, "update", "rollback"] as const) {
      test(`${language}: ${confirmation ?? "availability"} actions stay in the footer`, async () => {
        const i18n = createInstance()
        await i18n.init({
          lng: language,
          resources: {
            ru: { translation: ruTranslation },
            en: { translation: enTranslation },
          },
          interpolation: { escapeValue: false },
        })
        const copy = (language === "ru" ? ruTranslation : enTranslation).pages
          .settings.softwareUpdate
        const html = renderToStaticMarkup(
          <I18nextProvider i18n={i18n}>
            <SoftwareUpdateActions
              confirmation={confirmation}
              busy={false}
              backupPending={false}
              updateDisabled={false}
              rollbackDisabled={false}
              onBackup={() => {}}
              onUpdate={() => {}}
              onRollback={() => {}}
              onCancel={() => {}}
            />
          </I18nextProvider>
        )
        expect(html).toContain('data-slot="dialog-footer"')
        expect(html).toContain("shrink-0")
        expect(html).toContain("safe-area-inset-bottom")
        expect(html).toContain(copy.downloadBackup)
        expect(html).toContain(
          confirmation === "rollback"
            ? copy.rollbackConfirmAction
            : copy.install
        )
        expect(html).toContain(confirmation ? copy.cancel : copy.rollbackButton)
        expect(html.match(/<button\b/g)?.length).toBe(3)
        expect(html).not.toContain("disabled=")
      })
    }
  }

  test("all mutations remain disabled during the accepted operation", async () => {
    const i18n = createInstance()
    await i18n.init({
      lng: "ru",
      resources: { ru: { translation: ruTranslation } },
    })
    const html = renderToStaticMarkup(
      <I18nextProvider i18n={i18n}>
        <SoftwareUpdateActions
          confirmation="update"
          busy
          backupPending={false}
          updateDisabled={false}
          rollbackDisabled={false}
          onBackup={() => {}}
          onUpdate={() => {}}
          onRollback={() => {}}
          onCancel={() => {}}
        />
      </I18nextProvider>
    )
    expect(html.match(/<button\b[^>]*\sdisabled=""/g)?.length).toBe(3)
  })
})
