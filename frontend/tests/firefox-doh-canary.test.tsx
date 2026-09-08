import { describe, expect, mock, test } from "bun:test"
import { readFileSync } from "node:fs"
import { FieldApi, FormApi } from "@tanstack/react-form"
import { createInstance } from "i18next"
import { renderToStaticMarkup } from "react-dom/server"
import { I18nextProvider } from "react-i18next"

import type { DnsConfig } from "../src/api/generated/model/dnsConfig"
import { FirefoxDohCanaryField } from "../src/components/settings/firefox-doh-canary-field"
import { configKnownFields } from "../src/lib/config-known-fields.generated"
import { pickUnknownConfigProperties } from "../src/lib/config-unknown-fields"
import {
  getFirefoxDohCanaryEnabled,
  withFirefoxDohCanary,
} from "../src/lib/firefox-doh-canary"
import { getGeneralConfigActionState } from "../src/pages/general-config-form-state"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"

describe("Firefox automatic DoH canary local settings", () => {
  test("missing and null retain the enabled legacy baseline; explicit false stays off", () => {
    expect(getFirefoxDohCanaryEnabled(undefined)).toBe(true)
    for (const value of [undefined, null, true, false]) {
      const dns = value === undefined ? {} : { firefox_doh_canary: value }
      expect(getFirefoxDohCanaryEnabled(dns)).toBe(value !== false)
      expect(withFirefoxDohCanary(dns, value !== false)).toEqual(dns)
    }
  })

  test("a changed toggle preserves other DNS fields and extensions without mutating the source", () => {
    const dns = {
      servers: [{ tag: "primary", address: "192.0.2.53" }],
      rules: [{ list: ["sites"], server: "primary" }],
      fallback: ["primary"],
      client_dns_enforcement: { enabled: false, block_dot: false },
      firefox_doh_canary: null,
      future_dns: { value: [null, "kept"] },
    }
    const before = structuredClone(dns)
    const disabled = withFirefoxDohCanary(dns, false)
    expect(disabled).toEqual({ ...before, firefox_doh_canary: false })
    expect(dns).toEqual(before)
    expect(withFirefoxDohCanary(disabled, true)).toEqual({
      ...before,
      firefox_doh_canary: true,
    })
    expect(withFirefoxDohCanary(undefined, false)).toEqual({
      firefox_doh_canary: false,
    })
    expect(withFirefoxDohCanary(undefined, true)).toEqual({})
  })

  test("toggle and revert use semantic form state; only explicit submit builds the saved DNS value", async () => {
    for (const value of [undefined, null, false, true]) {
      const dns: DnsConfig =
        value === undefined ? {} : { firefox_doh_canary: value }
      const save = mock((savedDns: DnsConfig) => savedDns)
      const form = new FormApi({
        defaultValues: { firefoxDohCanary: getFirefoxDohCanaryEnabled(dns) },
        onSubmit: ({ value: draft }) => {
          save(withFirefoxDohCanary(dns, draft.firefoxDohCanary))
        },
      })
      const field = new FieldApi({ form, name: "firefoxDohCanary" })
      const unmountForm = form.mount()
      const unmountField = field.mount()
      const action = () =>
        getGeneralConfigActionState({
          canSubmit: form.state.canSubmit,
          deferredDirty: false,
          deferredValid: true,
          isDefaultValue: form.state.isDefaultValue,
          isPending: false,
        })
      try {
        const baseline = form.state.values.firefoxDohCanary
        expect(action().saveDisabled).toBe(true)
        form.setFieldValue("firefoxDohCanary", !baseline)
        expect(action().hasChanges).toBe(true)
        expect(save).not.toHaveBeenCalled()
        form.setFieldValue("firefoxDohCanary", baseline)
        expect(action().hasChanges).toBe(false)
        expect(action().saveDisabled).toBe(true)
        form.setFieldValue("firefoxDohCanary", !baseline)
        await form.handleSubmit()
        expect(save).toHaveBeenCalledTimes(1)
        expect(save.mock.calls[0][0]).toEqual({ firefox_doh_canary: !baseline })
        form.reset({
          firefoxDohCanary: getFirefoxDohCanaryEnabled(save.mock.calls[0][0]),
        })
        expect(action().hasChanges).toBe(false)
      } finally {
        unmountField()
        unmountForm()
      }
    }
  })

  test("the schema knows the toggle while future DNS fields remain preservable", () => {
    expect(configKnownFields.DnsConfig).toContain("firefox_doh_canary")
    expect(
      pickUnknownConfigProperties(
        { firefox_doh_canary: false, future_dns: "kept" },
        configKnownFields.DnsConfig
      )
    ).toEqual({ future_dns: "kept" })
  })

  test("the existing general settings form owns default, edit, build and server-error mapping", () => {
    const page = readFileSync(
      new URL("../src/pages/general-config-page.tsx", import.meta.url),
      "utf8"
    )
    expect(page).toContain(
      "firefoxDohCanary: getFirefoxDohCanaryEnabled(config.dns)"
    )
    expect(page).toContain(
      "...withFirefoxDohCanary(config.dns, draft.firefoxDohCanary)"
    )
    expect(page).toContain(
      "<form.Field name={SETTINGS_FIELD_NAMES.firefoxDohCanary}>"
    )
    expect(page).toContain(
      "onChange={(enabled) => field.handleChange(enabled)}"
    )
    expect(page).toContain('case "dns.firefox_doh_canary":')
    expect(page).toContain("return SETTINGS_FIELD_NAMES.firefoxDohCanary")
  })

  for (const language of ["ru", "en"] as const) {
    test(
      "the checkbox and quiet scope details are explicit and localized in " +
        language,
      async () => {
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
          .settings.general
        const change = mock(() => {})
        for (const enabled of [false, true]) {
          const html = renderToStaticMarkup(
            <I18nextProvider i18n={i18n}>
              <FirefoxDohCanaryField value={enabled} onChange={change} />
            </I18nextProvider>
          )
          expect(html).toContain('id="firefox-doh-canary"')
          expect(html).toContain('for="firefox-doh-canary"')
          expect(html).toContain('aria-describedby="firefox-doh-canary-hint"')
          expect(html).toContain('aria-checked="' + String(enabled) + '"')
          expect(html).toContain(copy.firefoxDohCanaryLabel)
          expect(html).toContain(copy.firefoxDohCanaryHint)
          expect(html).toContain(copy.firefoxDohCanaryScope)
          expect(html).not.toMatch(/<details[^>]*\sopen(?:=|>)/)
          expect(html).not.toContain('role="alert"')
        }
        expect(change).not.toHaveBeenCalled()
      }
    )
  }
})
