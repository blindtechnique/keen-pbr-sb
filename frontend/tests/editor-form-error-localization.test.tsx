import { describe, expect, test } from "bun:test"
import { FormApi } from "@tanstack/react-form"
import { createInstance } from "i18next"
import { renderToStaticMarkup } from "react-dom/server"
import { I18nextProvider } from "react-i18next"
import { readFileSync } from "node:fs"

import type { ApiError } from "../src/api/client"
import { getFormErrorMessage } from "../src/lib/form-field-error"
import {
  clearFormServerErrors,
  getUnmappedFormErrors,
  setFormServerErrors,
  splitFormApiErrors,
} from "../src/lib/form-api-errors"
import { ServerValidationAlert } from "../src/components/shared/server-validation-alert"
import { ruTranslation } from "../src/i18n/ru"
import { enTranslation } from "../src/i18n/en"

async function renderStoredError(error: ApiError, language: "ru" | "en") {
  const local = createInstance()
  await local.init({
    lng: language,
    resources: {
      ru: { translation: ruTranslation },
      en: { translation: enTranslation },
    },
  })
  const form = new FormApi({ defaultValues: { name: "unchanged" } })
  const unmount = form.mount()
  const split = splitFormApiErrors({ error, resolvePath: () => undefined })
  setFormServerErrors(form, {
    form: split.formError ?? undefined,
    fields: split.fieldErrors,
    unmapped: split.unmappedErrors,
  })
  const render = () => {
    const html = renderToStaticMarkup(
      <I18nextProvider i18n={local}>
        <ServerValidationAlert
          message={getFormErrorMessage(form.state.errorMap.onServer)}
          errors={getUnmappedFormErrors(form.state.errorMap.onServer)}
        />
      </I18nextProvider>
    )
    return { html, primary: html.replace(/<details[\s\S]*?<\/details>/g, "") }
  }
  return { form, unmount, local, render }
}

describe("editor general errors through the real form store", () => {
  test.each(["ru", "en"] as const)(
    "unknown server codes stay neutral in %s without discarding their cause",
    async (language) => {
      const error: ApiError = {
        status: 401,
        message: "Internal worker interrupted",
        details: {
          code: "future_failure",
          apply_error: "Exact apply cause",
          configuration: { private_key: "do-not-render" },
        },
      }
      const { render, unmount, form } = await renderStoredError(error, language)
      try {
        const copy = language === "ru" ? ruTranslation : enTranslation
        const { primary, html } = render()
        expect(primary).toContain(copy.operationErrors.unknown)
        expect(primary).not.toContain(copy.operationErrors.unauthenticated)
        expect(primary).not.toContain(error.message)
        expect(html).toContain(error.message)
        expect(html).toContain("Exact apply cause")
        expect(html).not.toContain("do-not-render")
        expect(html).not.toMatch(/<details[^>]*\bopen/)
        expect(form.state.values).toEqual({ name: "unchanged" })
      } finally {
        unmount()
      }
    }
  )

  test.each(["ru", "en"] as const)(
    "known busy/authorization codes survive normalization in %s",
    async (language) => {
      for (const code of [
        "busy",
        "unauthenticated",
        "reauthentication_required",
      ] as const) {
        const { render, unmount } = await renderStoredError(
          { status: 409, message: "Exact server reason", details: { code } },
          language
        )
        try {
          expect(render().primary).toContain(
            (language === "ru" ? ruTranslation : enTranslation).operationErrors[
              code
            ]
          )
          expect(render().html).toContain("Exact server reason")
        } finally {
          unmount()
        }
      }
    }
  )

  test("a stored error switches language without splitting or saving again", async () => {
    const { render, unmount, local } = await renderStoredError(
      { status: 409, message: "Worker busy", details: { code: "busy" } },
      "ru"
    )
    try {
      expect(render().primary).toContain(ruTranslation.operationErrors.busy)
      await local.changeLanguage("en")
      expect(render().primary).toContain(enTranslation.operationErrors.busy)
    } finally {
      unmount()
    }
  })

  test("restoration is claimed only with the existing complete terminal facts", async () => {
    for (const confirmed of [false, true]) {
      const details = confirmed
        ? {
            saved: false,
            applied: false,
            rolled_back: true,
            runtime_unchanged: false,
            file_rolled_back: true,
            recovery_required: false,
          }
        : { rolled_back: true }
      const { render, unmount } = await renderStoredError(
        { status: 500, message: "Apply failed", details },
        "ru"
      )
      try {
        expect(render().primary).toContain(
          confirmed
            ? ruTranslation.operationErrors.rolled_back
            : ruTranslation.operationErrors.unknown
        )
      } finally {
        unmount()
      }
    }
  })

  test("network exceptions retain their cause without requiring an HTTP response", async () => {
    const error = new TypeError("Failed to fetch")
    const { render, unmount } = await renderStoredError(
      error as unknown as ApiError,
      "ru"
    )
    try {
      expect(render().primary).toContain(ruTranslation.operationErrors.network)
      expect(render().html).toContain(error.message)
    } finally {
      unmount()
    }
  })

  test("unmapped validation remains visible after library normalization and clears normally", async () => {
    const entry = { path: "future.parameter", message: "Future constraint" }
    const { form, render, unmount } = await renderStoredError(
      {
        status: 400,
        message: "Config validation failed",
        details: { validation_errors: [entry] },
      },
      "ru"
    )
    try {
      expect(render().primary).toContain(ruTranslation.serverValidation.unknown)
      expect(render().primary).not.toContain(entry.message)
      expect(render().html).toContain("future.parameter: Future constraint")
      clearFormServerErrors(form)
      expect(render().html).toBe("")
    } finally {
      unmount()
    }
  })

  test("local general messages stay strings and replace prior server explanations", async () => {
    const { form, render, unmount } = await renderStoredError(
      { status: 500, message: "Previous server error" },
      "ru"
    )
    try {
      const message = "Добавьте хотя бы одно условие правила."
      setFormServerErrors(form, { form: message })
      expect(getFormErrorMessage(form.state.errorMap.onServer)).toBe(message)
      expect(render().primary).toContain(message)
      expect(render().html).not.toContain("Previous server error")
      expect(render().html).not.toContain("<details")
      clearFormServerErrors(form)
      expect(getFormErrorMessage(form.state.errorMap.onServer)).toBeNull()
    } finally {
      unmount()
    }
  })

  test("inline and toast consumers render original errors without changing the special list-delete refresh branch", () => {
    const source = (name: string) =>
      readFileSync(new URL(`../src/pages/${name}.tsx`, import.meta.url), "utf8")
    for (const name of ["list-upsert-page", "outbound-upsert-page"]) {
      const page = source(name)
      expect(page).toContain("getFormErrorMessage(serverFormError)")
      expect(page).toContain("(state) => state.errorMap.onServer")
      expect(page).not.toContain("as { form?: string }")
    }
    const list = source("list-upsert-page")
    expect(list).toContain("<OperationErrorMessage error={apiError} />")
    expect(list).toContain("<OperationErrorMessage error={error} />")
    expect(list).not.toContain("toast.error(result.formError")
    expect(list).toMatch(
      /if \(error.status === 409\) \{[\s\S]*?toast.warning\(t\("pages.lists.deleteDialog.revisionChanged"\)[\s\S]*?invalidateQueries[\s\S]*?deleteStageMutation.reset\(\)[\s\S]*?return/
    )
    const routing = source("routing-rule-upsert-page")
    expect(routing).toContain("isServerOperationError(onSubmitError)")
    expect(routing).toContain("isServerOperationError(firstError)")
    expect(routing).toContain("getFormErrorMessage(submitError)")
    expect(routing).toContain(
      'form: t("pages.routingRuleUpsert.validation.atLeastOneCondition")'
    )
  })
})
