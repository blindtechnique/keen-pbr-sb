import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import { createInstance } from "i18next"
import { renderToStaticMarkup } from "react-dom/server"
import { I18nextProvider } from "react-i18next"

import { OperationErrorMessage } from "../src/components/shared/operation-error-message"
import { loadLogTail } from "../src/components/settings/log-diagnostics-tools-model"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"
import { CatalogWarningText } from "../src/pages/catalog-page"

const source = (path: string) =>
  readFileSync(new URL(`../src/${path}`, import.meta.url), "utf8")

describe("remaining user error literals", () => {
  test.each(["ru", "en"] as const)(
    "keeps exact local and server causes under details, not in the %s summary",
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
      const messages = language === "ru" ? ruTranslation : enTranslation
      for (const cause of [
        "Invalid log response",
        "Invalid log response: lines must be an array of strings",
        "Unexpected catalogue preview response",
        "Unexpected catalogue apply response",
      ]) {
        const html = renderToStaticMarkup(
          <I18nextProvider i18n={i18n}>
            <OperationErrorMessage error={new Error(cause)} />
          </I18nextProvider>
        )
        expect(html.split("<details")[0]).toContain(
          messages.operationErrors.unknown
        )
        expect(html.split("<details")[0]).not.toContain(cause)
        expect(html).toContain(cause)
        expect(html).toContain(messages.operationErrors.details)
        expect(html).not.toContain("<details open")
      }
      const html = renderToStaticMarkup(
        <I18nextProvider i18n={i18n}>
          <OperationErrorMessage
            error={{
              message: "original failure",
              details: {
                code: "busy",
                reason: "runtime-firewall-worker",
              },
            }}
            fallbackSummary={messages.transports.unavailable}
          />
        </I18nextProvider>
      )
      expect(html.split("<details")[0]).toContain(messages.operationErrors.busy)
      expect(html.split("<details")[0]).not.toContain("runtime-firewall-worker")
      expect(html).toContain("reason: runtime-firewall-worker")
      expect(html).toContain("original failure")
    }
  )

  test("log parsing retains exact diagnostic evidence", async () => {
    await expect(loadLogTail(async () => new Response("[]"))).rejects.toThrow(
      "Invalid log response"
    )
    await expect(
      loadLogTail(async () => new Response('{"lines":[1]}'))
    ).rejects.toThrow("Invalid log response: lines must be an array of strings")
    expect(
      await loadLogTail(async () => new Response('{"lines":["exact log"]}'))
    ).toMatchObject({ lines: ["exact log"] })
  })

  test.each(["ru", "en"] as const)(
    "catalogue risks keep known warnings and localize unknown ones in %s",
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
      const messages = language === "ru" ? ruTranslation : enTranslation
      const render = (code: string) =>
        renderToStaticMarkup(
          <I18nextProvider i18n={i18n}>
            <CatalogWarningText
              warning={{ code, message: "raw catalogue warning" }}
            />
          </I18nextProvider>
        )
      expect(render("broad_traffic_scope")).toContain(
        messages.pages.catalog.risks.broadTrafficScope
      )
      const unknown = render("future_warning_code")
      expect(unknown).toContain(messages.pages.catalog.risks.unknownSummary)
      expect(unknown).toContain(messages.operationErrors.details)
      expect(unknown).not.toContain("raw catalogue warning")
      expect(unknown).not.toContain("future_warning_code")
      expect(unknown).not.toContain("pages.catalog.")
    }
  )

  test("actual log, catalogue, wizard and VPN consumers retain error objects", () => {
    const logs = source("components/settings/log-diagnostics-tools.tsx")
    expect(logs).toContain("error={logError}")
    expect(logs).toContain("fallbackSummary={labels.logLoadFailed}")
    expect(logs).toContain("error={diagnosticsError}")
    expect(logs).toContain("fallbackSummary={labels.diagnosticsDownloadFailed}")
    expect(logs).not.toContain("{labels.logLoadFailed}: {logError}")
    expect(logs).not.toContain(
      "{labels.diagnosticsDownloadFailed}: {diagnosticsError}"
    )

    for (const path of [
      "pages/catalog-page.tsx",
      "pages/setup-wizard-page.tsx",
    ]) {
      const text = source(path)
      expect(text).toContain("<OperationErrorMessage error={error} />")
      expect(text).not.toContain("getApiErrorMessage")
      expect(text).not.toContain("toast.error(error.message")
    }

    const catalogue = source("pages/catalog-page.tsx")
    expect(catalogue).toContain('t("pages.catalog.refreshState.failed")')
    expect(catalogue).toContain("{state.last_error}")
    expect(catalogue).not.toContain("message: state.last_error")
    expect(catalogue).toContain("{warning.code}")
    expect(catalogue).toContain("warning.requiresAcceptance ?? false")
    expect(catalogue).toContain("<HelpHint")

    const transports = source("pages/transports-page.tsx")
    expect(transports).toContain("const error = query.error")
    expect(transports).toContain("<OperationErrorMessage error={error} />")
    expect(
      transports.match(/<OperationErrorMessage error=\{mutationError\} \/>/g)
        ?.length
    ).toBeGreaterThanOrEqual(8)
    expect(transports).not.toContain("getApiErrorMessage")
    expect(transports).not.toContain("transferError.message")
    expect(transports).not.toContain("exportError.message")
    expect(transports).toContain("error={transferError}")
    expect(transports).toContain("error={exportError}")
    expect(transports).toContain("error={body.log}")
    expect(transports).toContain(
      'fallbackSummary={t("transports.naiveComponent.failed")}'
    )
  })

  test("all restart error consumers preserve the readiness cause for details", () => {
    const services = source("components/overview/services-status-card.tsx")
    expect(
      services.match(/<ServiceRestartError error=\{error\} \/>/g)
    ).toHaveLength(3)
    const presentation = source("components/overview/service-restart-error.tsx")
    expect(presentation).toContain("OperationErrorMessage")
    expect(presentation).toContain("error={error}")
    const readiness = source("lib/runtime-readiness.ts")
    expect(readiness).toContain(
      "throw new Error(`Runtime did not become ready: ${lastReason}`)"
    )
  })

  test("auth and environment diagnostics have no raw user-facing consumer", () => {
    const auth = source("components/auth-gate.tsx")
    const refresh = auth.slice(
      auth.indexOf("const refresh = useCallback"),
      auth.indexOf("}, [revokeTrustedLocalConnection])")
    )
    expect(refresh).toContain('throw new Error("invalid auth status")')
    expect(refresh).toContain("} catch {")
    expect(refresh).not.toContain(".message")
    expect(refresh).toContain("setStatusUnavailable(true)")

    for (const path of [
      "pages/transports-page.tsx",
      "pages/transport-upsert-page.tsx",
    ]) {
      const text = source(path)
      expect(text).toContain(
        'throw new Error("transport environment unavailable")'
      )
      expect(text).not.toContain("environmentQuery.error")
    }
    const upsert = source("pages/transport-upsert-page.tsx")
    expect(upsert).toContain("environmentQuery.isError")
    expect(upsert).toContain('t("transports.form.loadErrorTitle")')
  })
})
