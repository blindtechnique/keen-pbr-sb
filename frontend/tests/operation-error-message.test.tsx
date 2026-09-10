import { describe, expect, spyOn, test } from "bun:test"
import { createInstance } from "i18next"
import { I18nextProvider } from "react-i18next"
import { renderToStaticMarkup } from "react-dom/server"

import { apiFetch } from "../src/api/client"
import { OperationErrorMessage } from "../src/components/shared/operation-error-message"
import { ConfigSaveErrorAlert } from "../src/components/shared/config-save-error-alert"
import { ResultsView } from "../src/components/transports/subscription-import-dialog"
import { getSubscriptionPreviewRefusalReason } from "../src/components/transports/subscription-import-model"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"
import { createDefaultBackupSelection, restoreBackup } from "../src/lib/backup"

async function renderError(
  error: unknown,
  language: "ru" | "en",
  alert = false,
  fallbackSummary?: string,
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
      {alert ? (
        <ConfigSaveErrorAlert error={error} />
      ) : (
        <OperationErrorMessage
          error={error}
          fallbackSummary={fallbackSummary}
          summary={summary}
        />
      )}
    </I18nextProvider>
  )
}

describe("operation error presentation", () => {
  test.each(["ru", "en"] as const)(
    "explains failed list routing apply in %s without claiming a rollback",
    async (language) => {
      const messages = language === "ru" ? ruTranslation : enTranslation
      const payload = {
        code: "list_refresh_apply_failed",
        error: "Routing apply failed: exact generation was not verified",
        params: {
          stage: "terminal",
          runtime_result: "unknown",
          url: "https://example.test/private-token",
        },
        refreshed_lists: ["work"],
        changed_lists: ["work"],
        failed_lists: [],
        reloaded: false,
      }
      for (const error of [
        { status: 503, message: payload.error, details: payload },
        { status: 503, data: payload },
      ]) {
        const html = await renderError(error, language)
        expect(html.split("<details")[0]).toContain(
          messages.operationErrors.list_refresh_apply_failed
        )
        expect(html).toContain(payload.error)
        expect(html).toContain("stage: terminal")
        expect(html).toContain("runtime_result: unknown")
        expect(html).not.toContain("private-token")
        expect(html).not.toContain(messages.operationErrors.rolled_back)
        expect(html).not.toContain(messages.operationErrors.apply_unchanged)
      }
    }
  )

  test.each(["ru", "en"] as const)(
    "explains required schema migration in %s without hiding recovery or raw details",
    async (language) => {
      const messages = language === "ru" ? ruTranslation : enTranslation
      const entry = {
        path: "schema_version",
        code: "config.schema_version.migration_required",
        params: { supported: "2", version: "private-input" },
        message: "Reworded migration cause\nprivate-input",
      }
      const error = {
        status: 400,
        message: "Config was rejected",
        details: { code: "validation", validation_errors: [entry] },
      }
      const html = await renderError(error, language)
      const summary = messages.serverValidation.schemaMigration.replace(
        "{{supported}}",
        "2"
      )
      expect(html.split("<details")[0]).toContain(summary)
      expect(html.split("<details")[0]).not.toContain("private-input")
      expect(html).toContain(entry.message)
      expect(html).toContain(entry.code)
      const recovery = await renderError(
        { ...error, details: { ...error.details, recovery_required: true } },
        language
      )
      expect(recovery.split("<details")[0]).toContain(
        messages.operationErrors.recovery_required
      )
      expect(recovery.split("<details")[0]).not.toContain(summary)
      const invalid = await renderError(
        {
          ...error,
          details: {
            ...error.details,
            validation_errors: [
              { ...entry, params: { supported: "<script>" } },
            ],
          },
        },
        language
      )
      expect(invalid.split("<details")[0]).toContain(
        messages.operationErrors.validation
      )
      expect(invalid.split("<details")[0]).not.toContain("<script>")
    }
  )

  test.each(["ru", "en"] as const)(
    "shows all finite JSON explanations in %s and preserves escaped raw details",
    async (language) => {
      const messages = language === "ru" ? ruTranslation : enTranslation
      for (const [code, key] of [
        ["config.json.syntax", "jsonSyntax"],
        ["config.json.number_overflow", "jsonNumberOverflow"],
        ["config.json.type", "jsonType"],
        ["config.json.missing_field", "jsonMissingField"],
        ["config.json.object", "jsonObject"],
        ["config.json.decode", "jsonDecode"],
      ]) {
        const raw =
          "Changed diagnostic\n<img src=x onerror=alert(1)> private-value"
        const error = {
          status: 400,
          message: "Config was rejected",
          details: {
            code: "validation",
            validation_errors: [{ path: "config", message: raw, code }],
          },
        }
        const before = JSON.stringify(error)
        for (const alert of [false, true]) {
          const html = await renderError(error, language, alert)
          const visible = html.split("<details")[0]
          expect(visible).toContain(
            (messages.serverValidation as Record<string, string>)[key]
          )
          expect(visible).not.toContain("private-value")
          expect(visible).not.toContain("Changed diagnostic")
          expect(html).toContain("Changed diagnostic\n&lt;img")
          expect(html).not.toContain("<img")
          expect(html).toContain("private-value")
          expect(html).toContain(`code: ${code}`)
          expect(html).not.toMatch(/<details[^>]*\bopen(?:=|\s|>)/)
          expect(JSON.stringify(error)).toBe(before)
        }
      }
    }
  )

  test.each(["ru", "en"] as const)(
    "JSON explanations do not change recovery, explicit summary, or other validation in %s",
    async (language) => {
      const messages = language === "ru" ? ruTranslation : enTranslation
      const error = {
        status: 400,
        message: "Config validation failed",
        details: {
          code: "validation",
          validation_errors: [
            {
              path: "config",
              message: "raw diagnostic",
              code: "config.json.type",
            },
          ],
        },
      }
      const recovery = await renderError(
        { ...error, details: { ...error.details, recovery_required: true } },
        language
      )
      expect(recovery.split("<details")[0]).toContain(
        messages.operationErrors.recovery_required
      )
      expect(recovery.split("<details")[0]).not.toContain(
        messages.serverValidation.jsonType
      )
      const explicit = await renderError(
        error,
        language,
        false,
        undefined,
        "Context summary"
      )
      expect(explicit.split("<details")[0]).toContain("Context summary")
      expect(explicit.split("<details")[0]).not.toContain(
        messages.serverValidation.jsonType
      )
      for (const code of [
        undefined,
        "config.json.future",
        "config.value.integer",
      ]) {
        const html = await renderError(
          {
            ...error,
            details: {
              ...error.details,
              validation_errors: [
                { path: "config", message: "Config must be an object", code },
              ],
            },
          },
          language
        )
        expect(html.split("<details")[0]).toContain(
          messages.operationErrors.validation
        )
        expect(html.split("<details")[0]).not.toContain(
          messages.serverValidation.jsonObject
        )
      }
    }
  )

  test("config and backup HTTP normalization retain JSON codes without replaying requests", async () => {
    const body = {
      error: "Config was rejected",
      code: "validation",
      validation_errors: [
        {
          path: "config",
          message: "Reworded JSON cause",
          code: "config.json.type",
        },
      ],
    }
    const fetchSpy = spyOn(globalThis, "fetch").mockResolvedValue(
      Response.json(body, { status: 400 })
    )
    try {
      const configError = await apiFetch("/api/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ daemon: { port: [] } }),
      }).catch((error: unknown) => error)
      fetchSpy.mockResolvedValue(Response.json(body, { status: 400 }))
      const backupError = await restoreBackup({
        format: "keen-pbr-sb-backup",
        schema: 1,
        created_at: 1,
        groups: { ...createDefaultBackupSelection(), nfqws: false },
        data: {},
      }).catch((error: unknown) => error)
      for (const error of [configError, backupError]) {
        expect(error).toMatchObject({ status: 400, details: body })
        for (const language of ["ru", "en"] as const) {
          const html = await renderError(error, language)
          const messages = language === "ru" ? ruTranslation : enTranslation
          expect(html.split("<details")[0]).toContain(
            messages.serverValidation.jsonType
          )
          expect(html).toContain(body.validation_errors[0].message)
          expect(html).toContain("code: config.json.type")
        }
      }
      expect(fetchSpy).toHaveBeenCalledTimes(2)
      expect(fetchSpy.mock.calls.map(([url]) => url)).toEqual([
        "/api/config",
        "/api/backup/restore",
      ])
    } finally {
      fetchSpy.mockRestore()
    }
  })

  test.each(["ru", "en"] as const)(
    "contextual fallback never hides a known cause in %s",
    async (language) => {
      const messages = language === "ru" ? ruTranslation : enTranslation
      const fallback = messages.pages.settings.softwareUpdate.operationFailed
      for (const code of [
        "busy",
        "reauthentication_required",
        "recovery_required",
      ] as const) {
        const html = await renderError(
          { message: "original cause", details: { code } },
          language,
          false,
          fallback
        )
        expect(html).toContain(messages.operationErrors[code])
        expect(html).not.toContain(fallback)
      }
      const html = await renderError(
        { message: "original cause", details: { code: "future_error" } },
        language,
        false,
        fallback
      )
      expect(html).toContain(fallback)
      expect(html.split("<details")[0]).not.toContain("original cause")
      expect(html).toContain("original cause")
      expect(html).toContain("code: future_error")
    }
  )

  test.each(["ru", "en"] as const)(
    "a subscription result retains its stable code and exact cause in %s",
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
      const html = renderToStaticMarkup(
        <I18nextProvider i18n={i18n}>
          <ResultsView
            results={{
              results: [
                { line: 1, outcome: "created" },
                {
                  line: 2,
                  outcome: "failed",
                  error: "The provider prose changed",
                  code: "name_in_use",
                },
              ],
            }}
          />
        </I18nextProvider>
      )
      const messages = language === "ru" ? ruTranslation : enTranslation
      expect(html).toContain(messages.operationErrors.name_in_use)
      expect(html).toContain("The provider prose changed")
      expect(html).toContain("code: name_in_use")
      expect(html.split("<details")[0]).not.toContain(
        "The provider prose changed"
      )
      expect(html).not.toContain(messages.operationErrors.unknown)
      expect(html).not.toContain("operationErrors.")
    }
  )

  test.each(["ru", "en"] as const)(
    "an unknown code keeps the generic localized summary in %s",
    async (language) => {
      const html = await renderError(
        {
          message: "A lifecycle operation is already active",
          details: { code: "future_code" },
        },
        language
      )
      const messages = language === "ru" ? ruTranslation : enTranslation
      expect(html).toContain(messages.operationErrors.unknown)
      expect(html).not.toContain(messages.operationErrors.busy)
      expect(html).toContain("A lifecycle operation is already active")
      expect(html).toContain("code: future_code")
    }
  )

  test.each(["ru", "en"] as const)(
    "localizes the summary in %s and keeps raw causes collapsed",
    async (language) => {
      const raw =
        "Another runtime mutation is already in progress: runtime-firewall-worker"
      const html = await renderError({ status: 409, message: raw }, language)
      const messages = language === "ru" ? ruTranslation : enTranslation
      expect(html).toContain(messages.operationErrors.busy)
      expect(html).toContain(messages.operationErrors.details)
      expect(html.split("<details")[0]).not.toContain(raw)
      expect(html).toContain(raw)
      expect(html).not.toMatch(/<details[^>]*\bopen(?:=|\s|>)/)
    }
  )

  test.each(["ru", "en"] as const)(
    "unknown responses use a localized fallback in %s",
    async (language) => {
      const html = await renderError(new Error("new server failure"), language)
      const messages = language === "ru" ? ruTranslation : enTranslation
      expect(html).toContain(messages.operationErrors.unknown)
      expect(html.split("<details")[0]).not.toContain("new server failure")
      expect(html).toContain("new server failure")
      expect(html).not.toContain("operationErrors.")
    }
  )

  test("a save alert retains both apply and recovery causes without claiming success", async () => {
    const html = await renderError(
      {
        status: 503,
        message:
          "Runtime rolled back, but exact persistent recovery could not be proven",
        details: {
          recovery_required: true,
          apply_error: "apply cause",
          recovery_error: "recovery cause",
          document: "DO_NOT_DISPLAY_CONFIG_BODY",
        },
      },
      "ru",
      true
    )
    expect(html).toContain('role="alert"')
    expect(html).toContain(ruTranslation.operationErrors.recovery_required)
    expect(html).toContain("apply cause")
    expect(html).toContain("recovery cause")
    expect(html).not.toContain("DO_NOT_DISPLAY_CONFIG_BODY")
    expect(html).not.toContain(ruTranslation.operationErrors.rolled_back)
  })

  test("renders no alert when there is no error", async () => {
    expect(await renderError(null, "ru", true)).toBe("")
  })

  test("renders diagnostic text as text, not server-supplied markup", async () => {
    const html = await renderError(
      new Error('<img src=x onerror="alert(1)">'),
      "ru"
    )
    expect(html).not.toContain("<img")
    expect(html).toContain("&lt;img")
  })
})

describe("subscription preview refusal reasons", () => {
  test.each([
    "scheme_not_allowed",
    "credentials_in_url",
    "destination_not_permitted",
    "malformed",
  ])("accepts known reason %s", (reason) => {
    expect(getSubscriptionPreviewRefusalReason({ details: { reason } })).toBe(
      reason
    )
  })

  test.each([
    null,
    {},
    { details: null },
    { details: { reason: 4 } },
    { details: { reason: "new_provider_reason" } },
  ])("unknown reason cannot become an untranslated key", (error) => {
    expect(getSubscriptionPreviewRefusalReason(error)).toBeNull()
  })
})
