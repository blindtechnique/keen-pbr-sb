import { describe, expect, test } from "bun:test"

import { outboundManagementHref } from "@/components/overview/outbound-state-model"
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

/**
 * Раздел переименовали, а ссылки на него — нет: диагностика сломанного
 * туннеля на дашборде звала «Открыть маршруты и группы» и вела на
 * `/outbounds#interfaces`. Пункта с таким названием в меню давно нет, и
 * человек, которому предложили «открыть» его, искать его будет глазами по
 * меню. Тест закрепляет обе половины: подпись называет раздел так же, как
 * меню, а ссылка ведёт на нынешний адрес.
 */
describe("cross-references to the renamed section", () => {
  test("the dashboard link names the section exactly as the menu does", () => {
    expect(ruTranslation.overview.outbounds.issue.open).toContain(
      ruTranslation.nav.items.routesAndTunnels
    )
    expect(enTranslation.overview.outbounds.issue.open).toContain(
      enTranslation.nav.items.routesAndTunnels
    )
  })

  test("the dashboard link points at the current section address", () => {
    const hrefs = [
      outboundManagementHref({ type: "interface" }),
      outboundManagementHref({ type: "urltest" }),
      outboundManagementHref({ type: "table" }),
      outboundManagementHref({ type: "blackhole" }),
    ]
    for (const href of hrefs) {
      expect(href.startsWith("/transports#")).toBe(true)
    }
    // Вкладка сохраняется: группа открывается на группах, туннель — на туннелях.
    expect(outboundManagementHref({ type: "urltest" })).toBe(
      "/transports#failover"
    )
    expect(outboundManagementHref({ type: "interface" })).toBe(
      "/transports#tunnels"
    )
    expect(outboundManagementHref({ type: "blackhole" })).toBe(
      "/transports#system"
    )
  })
})
