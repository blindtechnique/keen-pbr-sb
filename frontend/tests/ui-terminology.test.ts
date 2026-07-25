import { describe, expect, test } from "bun:test"

import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"

describe("public routing terminology", () => {
  test("uses the renamed Russian sections in their primary actions", () => {
    expect(ruTranslation.pages.outbounds.title).toBe(
      "Маршруты и резервирование"
    )
    expect(ruTranslation.pages.outbounds.actions.new).toBe(
      "Добавить маршрут или резервирование"
    )
    expect(ruTranslation.transports.title).toBe("Туннели и прокси")
    expect(ruTranslation.transports.form.createTitle).toBe(
      "Добавить туннель или прокси"
    )
  })

  test("uses matching English terminology", () => {
    expect(enTranslation.pages.outbounds.title).toBe("Routes and failover")
    expect(enTranslation.pages.outbounds.actions.new).toBe(
      "Add route or failover target"
    )
    expect(enTranslation.transports.title).toBe("Tunnels and proxies")
    expect(enTranslation.transports.form.createTitle).toBe(
      "Add tunnel or proxy"
    )
  })
})
