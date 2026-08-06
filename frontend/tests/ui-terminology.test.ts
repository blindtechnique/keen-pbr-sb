import { describe, expect, test } from "bun:test"

import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"

// Терминология переименована по решению владельца: «резервирование» → «группы»,
// затем раздел стал «VPN, прокси, группы», а туннели — «VPN и прокси». Тест
// закрепляет новую терминологию в главных местах, чтобы случайная правка не
// вернула старые слова.
describe("public routing terminology", () => {
  test("uses the renamed Russian sections in their primary actions", () => {
    expect(ruTranslation.pages.outbounds.title).toBe("Маршруты и группы")
    expect(ruTranslation.pages.outbounds.actions.new).toBe(
      "Добавить маршрут или группу"
    )
    expect(ruTranslation.transports.title).toBe("VPN и прокси")
    expect(ruTranslation.transports.add).toBe("Добавить VPN или прокси")
    expect(ruTranslation.transports.form.createTitle).toBe(
      "Добавить VPN или прокси"
    )
    expect(ruTranslation.nav.items.routesAndTunnels).toBe("VPN, прокси, группы")
    expect(ruTranslation.pages.routesAndTunnels.title).toBe(
      "VPN, прокси, группы"
    )
    expect(ruTranslation.pages.routesAndTunnels.tabs.tunnels).toBe(
      "VPN и прокси"
    )
    // Ступени внутри группы не называются «группами»: «группа внутри группы»
    // читалась бы как ошибка.
    expect(ruTranslation.pages.outboundUpsert.urltest.groupTitle).toBe(
      "Ступень {{index}}"
    )
  })

  test("uses matching English terminology", () => {
    expect(enTranslation.pages.outbounds.title).toBe("Routes and groups")
    expect(enTranslation.pages.outbounds.actions.new).toBe("Add route or group")
    expect(enTranslation.transports.title).toBe("VPN and proxies")
    expect(enTranslation.transports.add).toBe("Add VPN or proxy")
    expect(enTranslation.transports.form.createTitle).toBe("Add VPN or proxy")
    expect(enTranslation.nav.items.routesAndTunnels).toBe(
      "VPN, proxies, groups"
    )
    expect(enTranslation.pages.routesAndTunnels.title).toBe(
      "VPN, proxies, groups"
    )
    expect(enTranslation.pages.routesAndTunnels.tabs.tunnels).toBe(
      "VPN and proxies"
    )
    expect(enTranslation.pages.outboundUpsert.urltest.groupTitle).toBe(
      "Tier {{index}}"
    )
  })
})
