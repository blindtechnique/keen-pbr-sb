import { describe, expect, test } from "bun:test"

import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"

// «Резервирование» переименовано в «группы» по решению владельца: по старому
// названию не было понятно назначение. Тест закрепляет новую терминологию в
// главных местах, чтобы случайная правка не вернула старое слово.
describe("public routing terminology", () => {
  test("uses the renamed Russian sections in their primary actions", () => {
    expect(ruTranslation.pages.outbounds.title).toBe("Маршруты и группы")
    expect(ruTranslation.pages.outbounds.actions.new).toBe(
      "Добавить маршрут или группу"
    )
    expect(ruTranslation.transports.title).toBe("Туннели и прокси")
    expect(ruTranslation.transports.form.createTitle).toBe(
      "Добавить туннель или прокси"
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
    expect(enTranslation.transports.title).toBe("Tunnels and proxies")
    expect(enTranslation.transports.form.createTitle).toBe(
      "Add tunnel or proxy"
    )
    expect(enTranslation.pages.outboundUpsert.urltest.groupTitle).toBe(
      "Tier {{index}}"
    )
  })
})
