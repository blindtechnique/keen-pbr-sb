import { describe, expect, test } from "bun:test"
import { createInstance } from "i18next"
import { renderToStaticMarkup } from "react-dom/server"
import { I18nextProvider } from "react-i18next"

import type { ApiError } from "../src/api/client"
import { DnsServerOperationError } from "../src/pages/dns-servers-upsert-page"
import { splitFormApiErrors } from "../src/lib/form-api-errors"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"

async function render(error: ApiError | null, language: "ru" | "en") {
  const local = createInstance()
  await local.init({
    lng: language,
    resources: {
      ru: { translation: ruTranslation },
      en: { translation: enTranslation },
    },
    interpolation: { escapeValue: false },
  })
  return renderToStaticMarkup(
    <I18nextProvider i18n={local}>
      <DnsServerOperationError error={error} />
    </I18nextProvider>
  )
}

describe("DNS server operation error localization", () => {
  test.each(["ru", "en"] as const)(
    "unknown server text remains in collapsed details, not the primary message in %s",
    async (language) => {
      const html = await render(
        {
          status: 500,
          message: "Unexpected owner failure <script>unsafe()</script>",
          details: {
            code: "future_owner_failure",
            apply_error: "exact apply cause",
          },
        },
        language
      )
      const copy = (language === "ru" ? ruTranslation : enTranslation)
        .operationErrors
      expect(html).toContain(copy.unknown)
      expect(html).toContain(copy.details)
      expect(html.split("<details")[0]).not.toContain(
        "Unexpected owner failure"
      )
      expect(html).toContain("Unexpected owner failure &lt;script&gt;")
      expect(html).toContain("code: future_owner_failure")
      expect(html).toContain("apply_error: exact apply cause")
      expect(html).not.toContain("<details open")
      expect(html).not.toContain("<script>")
    }
  )

  test.each(["ru", "en"] as const)(
    "keeps structured authorization and recovery outcomes in %s",
    async (language) => {
      const copy = (language === "ru" ? ruTranslation : enTranslation)
        .operationErrors
      for (const code of [
        "busy",
        "unauthenticated",
        "reauthentication_required",
        "forbidden",
      ] as const) {
        const html = await render(
          {
            status: 403,
            message: "Original service wording",
            details: { code },
          },
          language
        )
        expect(html).toContain(copy[code])
        expect(html).not.toContain(copy.unknown)
      }
      const html = await render(
        {
          status: 500,
          message: "Restore did not finish",
          details: {
            code: "busy",
            recovery_required: true,
            recovery_error: "exact recovery cause",
            rollback_error: "exact rollback cause",
          },
        },
        language
      )
      expect(html).toContain(copy.recovery_required)
      expect(html).not.toContain(copy.busy)
      expect(html).not.toContain(copy.rolled_back)
      expect(html).toContain("recovery_error: exact recovery cause")
      expect(html).toContain("rollback_error: exact rollback cause")
    }
  )

  test("reports restored configuration only for the existing confirmed rollback tuple", async () => {
    const details = {
      saved: false,
      applied: false,
      rolled_back: true,
      runtime_unchanged: false,
      file_rolled_back: true,
      recovery_required: false,
      apply_error: "DNS config preparation failed",
    }
    const confirmed = await render(
      { status: 500, message: "Apply failed", details },
      "ru"
    )
    expect(confirmed).toContain(ruTranslation.operationErrors.rolled_back)
    expect(confirmed).toContain("apply_error: DNS config preparation failed")
    const incomplete = await render(
      { status: 500, message: "Apply failed", details: { rolled_back: true } },
      "ru"
    )
    expect(incomplete).not.toContain(ruTranslation.operationErrors.rolled_back)
    expect(incomplete).toContain(ruTranslation.operationErrors.unknown)
  })

  test("has no banner without an operation failure", async () => {
    expect(await render(null, "ru")).toBe("")
  })

  test("retains field validation and the original error rather than a reconstructed string", async () => {
    const split = splitFormApiErrors({
      error: {
        status: 400,
        message: "Config validation failed",
        details: {
          validation_errors: [
            {
              path: "dns.servers.main.address",
              message: "Invalid server address",
            },
            { path: "dns.unmapped", message: "Original unmapped validation" },
          ],
        },
      },
      fieldNames: ["address"],
      resolvePath: (path) =>
        path === "dns.servers.main.address" ? "address" : undefined,
    })
    expect(split.formError).toBeNull()
    expect(split.fieldErrors).toEqual({
      address: {
        kind: "server-validation",
        entries: [
          {
            path: "dns.servers.main.address",
            message: "Invalid server address",
          },
        ],
      },
    })
    expect(split.unmappedErrors).toEqual([
      { path: "dns.unmapped", message: "Original unmapped validation" },
    ])
    const source = await Bun.file(
      new URL("../src/pages/dns-servers-upsert-page.tsx", import.meta.url)
    ).text()
    expect(source).toContain("const formMessage = applyFormApiErrors({")
    expect(source).toContain(
      "setOperationError(formMessage ? (error as ApiError) : null)"
    )
    expect(source).toContain(
      "<DnsServerOperationError error={operationError} />"
    )
    expect(source).toContain(
      "<ServerValidationAlert errors={unmappedServerErrors} />"
    )
    expect(source).not.toContain(
      "setApiErrorMessage(\n          applyFormApiErrors"
    )
  })
})
