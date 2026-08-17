import { describe, expect, test } from "bun:test"

import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"

// Ровно те пять значений, которые может прислать бэкенд в поле `kind`.
const KINDS = ["l2tp", "ikev1", "ikev2", "sstp", "openconnect"] as const

const ru = ruTranslation.pages.settings.general
  .internalVpnServiceNames as Record<string, string>
const en = enTranslation.pages.settings.general
  .internalVpnServiceNames as Record<string, string>

describe("internal VPN service names", () => {
  test("every kind the backend can send has a name in both locales", () => {
    for (const kind of KINDS) {
      expect(ru[kind]).toBeTruthy()
      expect(en[kind]).toBeTruthy()
    }
    expect(Object.keys(ru).sort()).toEqual([...KINDS].sort())
    expect(Object.keys(en).sort()).toEqual([...KINDS].sort())
  })

  // Имена задавались списком по-русски и сначала лежали прямо в коде — в
  // английской панели показывались русские подписи, а `i18n:check` этого не
  // видел, потому что строки не проходили через `t()`.
  test("the English panel does not show the Russian names", () => {
    for (const kind of KINDS) {
      expect(en[kind]).not.toBe(ru[kind])
      expect(en[kind]).not.toMatch(/[А-Яа-яЁё]/)
    }
  })

  test("the name says which protocol it is", () => {
    expect(ru.l2tp).toContain("L2TP")
    expect(ru.ikev2).toContain("IKEv2")
    expect(en.openconnect).toContain("OpenConnect")
  })
})
