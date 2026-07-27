import { describe, expect, test } from "bun:test"

import {
  authEndpointModeLabelKey,
  parseAuthStatus,
} from "../src/lib/auth-status"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"

describe("authentication status contract", () => {
  test("accepts only the explicit boolean contract", () => {
    expect(
      parseAuthStatus({ enabled: true, authenticated: false })
    ).toEqual({ enabled: true, authenticated: false })
    expect(
      parseAuthStatus({ enabled: false, authenticated: true })
    ).toEqual({ enabled: false, authenticated: true })
  })

  test("rejects malformed and truthy lookalike responses", () => {
    expect(parseAuthStatus(null)).toBeNull()
    expect(parseAuthStatus({})).toBeNull()
    expect(
      parseAuthStatus({ enabled: "false", authenticated: 1 })
    ).toBeNull()
  })

  test("maps Keenetic endpoint modes to localized labels", () => {
    expect(authEndpointModeLabelKey("auto")).toBe(
      "pages.settings.auth.endpointModeAuto"
    )
    expect(authEndpointModeLabelKey("manual")).toBe(
      "pages.settings.auth.endpointModeManual"
    )
    expect(ruTranslation.pages.settings.auth.endpointModeAuto).toBe(
      "Автоматически через NDMS"
    )
    expect(ruTranslation.pages.settings.auth.endpointModeManual).toBe(
      "Вручную"
    )
    expect(enTranslation.pages.settings.auth.endpointModeAuto).toBe(
      "Automatically via NDMS"
    )
    expect(enTranslation.pages.settings.auth.endpointModeManual).toBe(
      "Manually"
    )
  })
})
