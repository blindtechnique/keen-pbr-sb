import { readFileSync } from "node:fs"

import { describe, expect, spyOn, test } from "bun:test"
import { createInstance } from "i18next"
import { renderToStaticMarkup } from "react-dom/server"
import { I18nextProvider } from "react-i18next"

import { OperationErrorMessage } from "../src/components/shared/operation-error-message"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"
import {
  createBackup,
  createDefaultBackupSelection,
  getRollbackAvailability,
  InvalidBackupBundleError,
  readBackupFile,
  restoreBackup,
  rollbackBackup,
  type BackupBundle,
} from "../src/lib/backup"

const bundle: BackupBundle = {
  format: "keen-pbr-sb-backup",
  schema: 1,
  created_at: 1,
  groups: { ...createDefaultBackupSelection(), nfqws: true },
  data: {},
}

const dialogSource = readFileSync(
  new URL("../src/components/settings/backup-dialogs.tsx", import.meta.url),
  "utf8"
)

async function renderBackupError(error: unknown, language: "ru" | "en") {
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
  return renderToStaticMarkup(
    <I18nextProvider i18n={i18n}>
      <OperationErrorMessage
        error={error}
        fallbackSummary={messages.pages.settings.backup.actionFailed}
      />
    </I18nextProvider>
  )
}

describe("backup API error presentation", () => {
  test("structured future-version reason renders uint64 exactly after restore HTTP normalization", async () => {
    const params = { version: "18446744073709551615", supported: "2" }
    const raw = {
      path: "schema_version",
      message: "Changed diagnostic\nНовая формулировка",
      code: "config.schema_version.unsupported",
      params,
    }
    const fetchSpy = spyOn(globalThis, "fetch").mockResolvedValue(
      Response.json(
        {
          code: "validation",
          error: "Config was rejected",
          validation_errors: [raw],
        },
        { status: 400 }
      )
    )
    try {
      const error = await restoreBackup(bundle).catch(
        (failure: unknown) => failure
      )
      for (const language of ["ru", "en"] as const) {
        const html = await renderBackupError(error, language)
        const translation = language === "ru" ? ruTranslation : enTranslation
        expect(html).toContain(
          translation.serverValidation.futureSchemaVersion
            .replace("{{version}}", params.version)
            .replace("{{supported}}", params.supported)
        )
        expect(html.split("<details")[0]).not.toContain(raw.message)
        expect(html).toContain(raw.message)
        expect(html).toContain(`code: ${raw.code}`)
      }
      expect(fetchSpy).toHaveBeenCalledTimes(1)
    } finally {
      fetchSpy.mockRestore()
    }
  })
  test.each(["ru", "en"] as const)(
    "explains a newer config format during restore in %s",
    async (language) => {
      const raw =
        "Configuration schema version 3 is newer than supported version 2. Update keen-pbr-sb before loading this configuration."
      const body = {
        error: "restored configuration is invalid",
        code: "validation",
        validation_errors: [{ path: "schema_version", message: raw }],
      }
      const fetchSpy = spyOn(globalThis, "fetch").mockResolvedValue(
        Response.json(body, { status: 400 })
      )
      try {
        const error = await restoreBackup(bundle).catch(
          (failure: unknown) => failure
        )
        const html = await renderBackupError(error, language)
        const messages = language === "ru" ? ruTranslation : enTranslation
        expect(html).toContain(
          messages.serverValidation.futureSchemaVersion
            .replace("{{version}}", "3")
            .replace("{{supported}}", "2")
        )
        expect(html.split("<details")[0]).not.toContain(raw)
        expect(html).toContain(raw)
        expect(html).not.toContain(messages.pages.settings.backup.actionFailed)
        expect(fetchSpy).toHaveBeenCalledTimes(1)
      } finally {
        fetchSpy.mockRestore()
      }
    }
  )
  test.each([
    [
      "export",
      () => createBackup(createDefaultBackupSelection()),
      "/api/backup",
      "POST",
    ],
    ["restore", () => restoreBackup(bundle), "/api/backup/restore", "POST"],
    ["rollback", rollbackBackup, "/api/backup/rollback", "POST"],
    [
      "availability",
      getRollbackAvailability,
      "/api/backup/rollback",
      undefined,
    ],
  ] as const)(
    "%s preserves the original error body without replaying the request",
    async (_name, operation, url, method) => {
      const body = {
        error: "The server diagnostic wording changed",
        code: "busy",
        apply_error: "original apply cause",
        validation_errors: [{ path: "dns.servers", message: "invalid value" }],
      }
      const fetchSpy = spyOn(globalThis, "fetch").mockResolvedValue(
        Response.json(body, { status: 409 })
      )
      try {
        let failure: unknown
        try {
          await operation()
        } catch (error) {
          failure = error
        }
        expect(failure).toBeInstanceOf(Error)
        expect(failure).toMatchObject({
          message: body.error,
          status: 409,
          details: body,
        })
        expect(fetchSpy).toHaveBeenCalledTimes(1)
        expect(fetchSpy.mock.calls[0]?.[0]).toBe(url)
        expect(fetchSpy.mock.calls[0]?.[1]?.method).toBe(method)
      } finally {
        fetchSpy.mockRestore()
      }
    }
  )

  test.each(["ru", "en"] as const)(
    "a failed restore keeps recovery evidence and a localized summary in %s",
    async (language) => {
      const body = {
        error: "Restore did not finish",
        code: "busy",
        recovery_required: true,
        apply_error: "original apply cause",
        recovery_error: "original recovery cause",
        data: { private_key: "DO_NOT_RENDER_ARCHIVE_DATA" },
      }
      const fetchSpy = spyOn(globalThis, "fetch").mockResolvedValue(
        Response.json(body, { status: 503 })
      )
      try {
        const failure = await restoreBackup(bundle).catch(
          (error: unknown) => error
        )
        const html = await renderBackupError(failure, language)
        const messages = language === "ru" ? ruTranslation : enTranslation
        expect(html).toContain(messages.operationErrors.recovery_required)
        expect(html).not.toContain(messages.operationErrors.busy)
        expect(html).not.toContain(messages.pages.settings.backup.actionFailed)
        expect(html).toContain("original apply cause")
        expect(html).toContain("original recovery cause")
        expect(html.split("<details")[0]).not.toContain(body.error)
        expect(html).not.toMatch(/<details[^>]*\bopen(?:=|\s|>)/)
        expect(html).not.toContain("DO_NOT_RENDER_ARCHIVE_DATA")
        expect(html).not.toContain("operationErrors.")
        expect(fetchSpy).toHaveBeenCalledTimes(1)
      } finally {
        fetchSpy.mockRestore()
      }
    }
  )

  test.each(["ru", "en"] as const)(
    "an unfamiliar backup error keeps the action-specific fallback in %s",
    async (language) => {
      const html = await renderBackupError(
        Object.assign(new Error("unfamiliar server diagnostic"), {
          status: 500,
          details: { code: "future_backup_error" },
        }),
        language
      )
      const messages = language === "ru" ? ruTranslation : enTranslation
      expect(html).toContain(messages.pages.settings.backup.actionFailed)
      expect(html).toContain("unfamiliar server diagnostic")
      expect(html).toContain("code: future_backup_error")
      expect(html.split("<details")[0]).not.toContain(
        "unfamiliar server diagnostic"
      )
    }
  )

  test("a non-JSON server error retains its HTTP cause", async () => {
    const fetchSpy = spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("gateway unavailable", { status: 502 })
    )
    try {
      await expect(getRollbackAvailability()).rejects.toMatchObject({
        message: "HTTP 502",
        status: 502,
        details: {},
      })
      expect(fetchSpy).toHaveBeenCalledTimes(1)
    } finally {
      fetchSpy.mockRestore()
    }
  })

  test("a valid availability response still reports absence without an error", async () => {
    const fetchSpy = spyOn(globalThis, "fetch").mockResolvedValue(
      Response.json({ available: false })
    )
    try {
      expect(await getRollbackAvailability()).toBe(false)
      expect(fetchSpy).toHaveBeenCalledTimes(1)
    } finally {
      fetchSpy.mockRestore()
    }
  })

  test("invalid local files retain their existing parse errors", async () => {
    await expect(
      readBackupFile(new File(["{}"], "not-backup.json"))
    ).rejects.toBeInstanceOf(InvalidBackupBundleError)
    await expect(
      readBackupFile(new File(["{"], "invalid.json"))
    ).rejects.toBeInstanceOf(SyntaxError)
  })

  test("backup dialogs opt in all four error paths without losing availability errors", () => {
    expect(dialogSource.match(/<OperationErrorMessage\b/g)).toHaveLength(4)
    expect(dialogSource).not.toContain("? error.message")
    expect(dialogSource).toContain("setRollbackError(error)")
    expect(dialogSource).toContain("setRollbackError(null)")
    expect(dialogSource).toContain('role="alert"')
    expect(dialogSource).toContain("pages.settings.backup.rollbackCheckFailed")
    expect(dialogSource).toContain("disabled={pending || !rollbackAvailable}")
    expect(dialogSource).toContain("if (!nextOpen && busy) return")
  })
})
