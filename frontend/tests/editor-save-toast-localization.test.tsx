import { describe, expect, test } from "bun:test"

const editors = [
  {
    page: "general-config-page",
    fields: "SETTINGS_FIELD_NAMES",
    resolver: "resolveSettingsFieldPath",
  },
  {
    page: "dns-rule-upsert-page",
    fields: "DNS_RULE_FIELD_NAMES",
    resolver: "resolveDnsRuleFieldPath",
  },
] as const

describe("settings and DNS rule save error presentation", () => {
  for (const { page, fields, resolver } of editors) {
    test(`${page} renders the original save error only for a form-level failure`, async () => {
      const source = await Bun.file(
        new URL(`../src/pages/${page}.tsx`, import.meta.url)
      ).text()

      expect(source).toContain(
        'import { OperationErrorMessage } from "@/components/shared/operation-error-message"'
      )
      expect(source).toMatch(
        /if \(result\.formError\) \{\s*toast\.error\(<OperationErrorMessage error=\{error\} \/>, \{\s*richColors: true,\s*\}\)/
      )
      expect(source).not.toContain("toast.error(result.formError")
      expect(source).not.toContain(
        "<OperationErrorMessage error={result.formError}"
      )
    })

    test(`${page} preserves field mapping and form validation results`, async () => {
      const source = await Bun.file(
        new URL(`../src/pages/${page}.tsx`, import.meta.url)
      ).text()

      expect(source).toMatch(
        new RegExp(
          `splitFormApiErrors\\(\\{\\s*error: error as ApiError,\\s*fieldNames: Object\\.values\\(${fields}\\),\\s*resolvePath: ${resolver},`
        )
      )
      expect(source).toMatch(
        /setFormServerErrors\(form, \{\s*form: result\.formError \?\? undefined,\s*fields: result\.fieldErrors,\s*unmapped: result\.unmappedErrors,/
      )
      expect(source).toMatch(
        /return \{\s*form: result\.formError \?\? undefined,\s*fields: result\.fieldErrors,\s*\}/
      )
      expect(source).toContain("clearFormServerErrors(form)")
      expect(source).toContain("getUnmappedFormErrors(state.errorMap.onServer)")
      const validationAlert = source.match(
        /<ServerValidationAlert\b[\s\S]*?\/>/
      )?.[0]
      expect(validationAlert).toBeDefined()
      expect(validationAlert).toMatch(
        /\berrors\s*=\s*\{\s*unmappedServerErrors\s*\}/
      )
      if (page === "dns-rule-upsert-page") {
        expect(validationAlert).toMatch(
          /\bmessage\s*=\s*\{\s*targetUnavailable\s*\?\s*t\("common\.ruleEditTargetChanged"\)\s*:\s*undefined\s*\}/
        )
      }
    })
  }
})
