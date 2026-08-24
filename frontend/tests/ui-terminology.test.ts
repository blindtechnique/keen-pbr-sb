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
    expect(ruTranslation.transports.add).toBe(
      "Добавить прокси или подключить VPN"
    )
    expect(ruTranslation.transports.form.createTitle).toBe(
      "Добавить прокси или подключить VPN"
    )
    expect(ruTranslation.transports.form.singBox).toBe(
      "Подключение sing-box/Amnezia/WireGuard"
    )
    expect(ruTranslation.transports.form.shareLink).toBe("Ссылка подключения")
    expect(ruTranslation.transports.form.importFile).toBe("Импорт файла")
    expect(ruTranslation.transports.form.outboundJson).toBe(
      "JSON подключения sing-box"
    )
    // Subscriptions were folded into this one field, so the sentence that
    // explains it names them first - an operator pasting a subscription
    // address needs to know it belongs here before they look for another way.
    expect(ruTranslation.transports.form.shareLinkHint).toContain(
      "Поддерживаются подписки и ссылки VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS, SOCKS и HTTP-прокси"
    )
    expect(ruTranslation.transports.form.shareLinkHint).toContain("vpn://")
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
    expect(enTranslation.transports.add).toBe("Add proxy or connect VPN")
    expect(enTranslation.transports.form.createTitle).toBe(
      "Add proxy or connect VPN"
    )
    expect(enTranslation.transports.form.singBox).toBe(
      "sing-box/Amnezia/WireGuard connection"
    )
    expect(enTranslation.transports.form.shareLink).toBe("Connection link")
    expect(enTranslation.transports.form.importFile).toBe("Import file")
    expect(enTranslation.transports.form.outboundJson).toBe(
      "sing-box connection JSON"
    )
    expect(enTranslation.transports.form.shareLinkHint).toContain("vpn://")
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

describe("nfqws updater truthfulness", () => {
  test("does not claim the configured opkg source or target package is official", () => {
    const russian = `${ruTranslation.nfqws.serviceHelp.upgrade} ${ruTranslation.nfqws.upgradeConfirmDescription}`
    const english = `${enTranslation.nfqws.serviceHelp.upgrade} ${enTranslation.nfqws.upgradeConfirmDescription}`

    expect(russian).not.toContain("официального репозитория")
    expect(english.toLowerCase()).not.toContain("official repository")
    // What installs comes from the configured sources, which need not be the
    // GitHub release the panel displays as "latest".
    expect(russian).toContain("настроенн")
    expect(english).toContain("configured Entware")
    // The panel does now pin and check the package - against that same
    // repository's index, which is self-referential. The disclosure that
    // survives is about the repository's own authenticity, not about the
    // absence of any verification, which is why the older "does not pin"
    // wording was retired rather than kept.
    expect(russian).toContain("подлинность")
    expect(english).toContain("does not independently confirm")
  })

  test("does not promise a stale one-click rollback after the request", () => {
    expect(ruTranslation.nfqws.automaticBackupDescription).toContain(
      "отката в один клик нет"
    )
    expect(enTranslation.nfqws.automaticBackupDescription).toContain(
      "no attributable one-click rollback"
    )
  })

  test("does not describe normal guarded-opkg limitations as the unavailable reason", () => {
    for (const text of [
      ruTranslation.nfqws.upgradeUnavailableDescription,
      enTranslation.nfqws.upgradeUnavailableDescription,
    ]) {
      expect(text).not.toContain("IPK")
      expect(text.toLowerCase()).not.toContain("pin")
      expect(text.toLowerCase()).not.toContain("reboot")
      expect(text.toLowerCase()).not.toContain("перезагруз")
    }
    expect(ruTranslation.nfqws.upgradeMetadataUnverifiedDescription).toContain(
      "opkg по SSH"
    )
    expect(enTranslation.nfqws.upgradeMetadataUnverifiedDescription).toContain(
      "opkg over SSH"
    )
  })

  test("discloses before file restore that web updates require manual package repair", () => {
    const russian = `${ruTranslation.nfqws.restoreComponentConfirmDescription} ${ruTranslation.nfqws.restoreComponentLimitDescription}`
    const english = `${enTranslation.nfqws.restoreComponentConfirmDescription} ${enTranslation.nfqws.restoreComponentLimitDescription}`

    expect(russian).toContain("будут заблокированы")
    expect(russian).toContain("вручную")
    expect(russian).toContain("opkg по SSH")
    expect(english).toContain("stay blocked")
    expect(english).toContain("manually")
    expect(english).toContain("opkg over SSH")
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
