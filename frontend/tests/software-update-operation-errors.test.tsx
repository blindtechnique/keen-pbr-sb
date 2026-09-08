import { describe, expect, test } from "bun:test"
import { createInstance } from "i18next"
import { I18nextProvider } from "react-i18next"
import { renderToStaticMarkup } from "react-dom/server"

import { softwareUpdateResponseError } from "../src/components/settings/software-update-view"
import { OperationErrorMessage } from "../src/components/shared/operation-error-message"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"
import { getOperationErrorPresentation } from "../src/lib/api-errors"

async function renderUpdateError(
  body: { error: string; code?: string; rolled_back?: boolean },
  language: "ru" | "en"
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
  const translation = language === "ru" ? ruTranslation : enTranslation
  return renderToStaticMarkup(
    <I18nextProvider i18n={i18n}>
      <OperationErrorMessage
        error={softwareUpdateResponseError(503, body)}
        fallbackSummary={
          translation.pages.settings.softwareUpdate.operationFailed
        }
      />
    </I18nextProvider>
  )
}

describe("software update error presentation", () => {
  test("retains the legacy Error message, status and diagnostic metadata", () => {
    const body = { error: "package worker unavailable", code: "busy" }
    const error = softwareUpdateResponseError(409, body)
    expect(error).toBeInstanceOf(Error)
    expect(error.message).toBe(body.error)
    expect(error.status).toBe(409)
    expect(error.details).toBe(body)
    expect(getOperationErrorPresentation(error)?.kind).toBe("busy")
    expect(softwareUpdateResponseError(502, {}).message).toBe("HTTP 502")
  })

  test.each(["ru", "en"] as const)(
    "unknown package failures stay contextual and collapsed in %s",
    async (language) => {
      const translation = language === "ru" ? ruTranslation : enTranslation
      const cause = "opkg failed after replacing the package <details>"
      const html = await renderUpdateError({ error: cause }, language)
      expect(html).toContain(
        translation.pages.settings.softwareUpdate.operationFailed
      )
      expect(html.split("<details")[0]).not.toContain("opkg failed")
      expect(html).toContain(
        "opkg failed after replacing the package &lt;details&gt;"
      )
      expect(html).not.toContain("<details open")
      expect(html).not.toContain(translation.operationErrors.rolled_back)
      expect(html).not.toContain(translation.operationErrors.apply_unchanged)
    }
  )

  test.each(["ru", "en"] as const)(
    "known auth and busy codes override the update fallback in %s",
    async (language) => {
      const translation = language === "ru" ? ruTranslation : enTranslation
      for (const code of ["busy", "reauthentication_required"] as const) {
        const html = await renderUpdateError(
          { error: "provider wording changed", code },
          language
        )
        expect(html).toContain(translation.operationErrors[code])
        expect(html).not.toContain(
          translation.pages.settings.softwareUpdate.operationFailed
        )
        expect(html).toContain(`code: ${code}`)
      }
    }
  )

  test("one package rollback flag cannot become a configuration rollback verdict", async () => {
    const html = await renderUpdateError(
      {
        error: "package rollback not proven",
        code: "rolled_back",
        rolled_back: true,
      },
      "ru"
    )
    expect(html).toContain(
      ruTranslation.pages.settings.softwareUpdate.operationFailed
    )
    expect(html).not.toContain(ruTranslation.operationErrors.rolled_back)
  })

  test("update polling and controls keep their existing request behavior", async () => {
    const source = await Bun.file(
      new URL(
        "../src/components/settings/maintenance-cards.tsx",
        import.meta.url
      )
    ).text()
    expect(source).toContain("if (!status?.running) return")
    expect(source).toContain(
      "window.setInterval(() => void refreshProgress(), 3000)"
    )
    expect(source).toContain(
      "window.setTimeout(() => void refreshProgress(), 1200)"
    )
    expect(source).toContain(
      "if (!nextOpen && (status?.running || starting)) return"
    )
    expect(source).toContain('fetch("/api/system/update", { method: "POST" })')
    expect(source).toContain('fetch("/api/system/update/rollback", {')
    expect(source).toContain(
      "throw softwareUpdateResponseError(response.status, body)"
    )
    expect(source).toContain("fallbackSummary={error.fallbackSummary}")
    expect(source).toContain(
      "open={status?.success !== false || status?.running === true}"
    )
    expect(source).toContain("if (status?.check_error) return null")
  })

  test("nfqws update and backup failures opt in without changing unrelated operations", async () => {
    const source = await Bun.file(
      new URL("../src/pages/nfqws-page.tsx", import.meta.url)
    ).text()
    expect(source).toContain('output: errorSummary ? "" : message')
    expect(source).toContain("...(errorSummary ? { error, errorSummary } : {})")
    expect(source).toContain("fallbackSummary={operation.errorSummary}")
    expect(source).toContain("if (!open && !operation.pending) onClose()")
    expect(source).toMatch(
      /action: "upgrade"[\s\S]*?t\("nfqws\.operationCompleted"\),\s*t\("nfqws\.operationFailed"\)/
    )
    expect(source).toMatch(
      /action: "install"[\s\S]*?t\("nfqws\.operationCompleted"\),\s*t\("nfqws\.operationFailed"\)/
    )
    expect(source).toMatch(
      /t\("nfqws\.backup\.restoreTitle"\),\s*execute,\s*t\("nfqws\.backup\.restored"\),\s*t\("nfqws\.operationFailed"\)/
    )
    expect(source).toContain("if (summary) {")
    expect(source).toContain("toast.error(summary, { richColors: true })")
  })

  test("sing-box keeps blockers and may-have-applied warnings outside diagnostics", async () => {
    const source = await Bun.file(
      new URL(
        "../src/components/transports/sing-box-install-button.tsx",
        import.meta.url
      )
    ).text()
    expect(source).toContain("summary={refusedSummary}")
    expect(source).toContain("singBoxInstallBlockerKey(blocker)")
    expect(source).toContain(
      "singBoxInstallMayHaveApplied(refused.length, lastOutcome)"
    )
    expect(source).toContain(
      '<p>{t("transports.singBoxInstall.mayHaveApplied")}</p>'
    )
    expect(source).toContain(
      "description: <OperationErrorMessage error={error} />"
    )
    expect(source).not.toContain("getApiErrorMessage")
    expect(source).toContain("report(data)")
    expect(source).toContain("singBoxInstallOutcomeKey(result.install_outcome)")
  })
})
