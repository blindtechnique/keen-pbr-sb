import { describe, expect, test } from "bun:test"

import {
  NdmsManagementBlocker,
  NdmsNativeImportReadinessBlockersItem,
} from "@/api/generated/model"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"

describe("native Keenetic interface wording", () => {
  test("says that the current create flow only links an existing interface", () => {
    expect(ruTranslation.transports.form.native).toContain("существующий")
    expect(ruTranslation.transports.form.nativeInterfaceHint).toContain(
      "не создаёт и не изменяет"
    )
    expect(ruTranslation.transports.nativeManagedExternally).toContain(
      "уже существующий"
    )
    expect(ruTranslation.transports.routeOffer.question).toContain(
      "только маршрут"
    )
    expect(ruTranslation.transports.configMessages.nativeLinked).toContain(
      "сам интерфейс не изменён"
    )

    expect(enTranslation.transports.form.native).toContain("existing")
    expect(enTranslation.transports.form.nativeInterfaceHint).toContain(
      "does not create or edit"
    )
    expect(enTranslation.transports.nativeManagedExternally).toContain(
      "existing"
    )
    expect(enTranslation.transports.routeOffer.question).toContain(
      "Create only a route"
    )
    expect(enTranslation.transports.configMessages.nativeLinked).toContain(
      "interface itself was not changed"
    )
  })

  test("has visible copy for every typed management blocker", () => {
    for (const blocker of Object.values(NdmsManagementBlocker)) {
      expect(
        ruTranslation.transports.nativeInterface.managementBlockers[blocker]
      ).toBeTruthy()
      expect(
        enTranslation.transports.nativeInterface.managementBlockers[blocker]
      ).toBeTruthy()
    }
    expect(
      ruTranslation.transports.nativeInterface.managementReadOnlyDescription
    ).toContain("отключены")
    expect(
      enTranslation.transports.nativeInterface.managementReadOnlyDescription
    ).toContain("disabled")
  })

  test("previews locally and sends once only after protected explicit consent", () => {
    expect(ruTranslation.transports.nativeImport.description).toContain(
      "превью строится локально"
    )
    expect(ruTranslation.transports.nativeImport.description).toContain(
      "один раз отправляет"
    )
    expect(ruTranslation.transports.nativeImport.description).toContain(
      "автоматические повторы"
    )
    expect(ruTranslation.transports.nativeImport.description).toContain(
      "подтверждённое роутером"
    )
    expect(
      ruTranslation.transports.nativeImport.transportBlockedDescription
    ).toContain("HTTPS-домену Keenetic")
    expect(
      ruTranslation.transports.nativeImport.transportBlockedDescription
    ).toContain("HTTP заблокирован")
    expect(ruTranslation.transports.nativeImport.redactedNotice).toContain(
      "локальное структурное превью"
    )
    expect(ruTranslation.transports.nativeImport.redactedNotice).not.toContain(
      "backend"
    )

    expect(enTranslation.transports.nativeImport.description).toContain(
      "structural preview is local"
    )
    expect(enTranslation.transports.nativeImport.description).toContain(
      "send the source once"
    )
    expect(enTranslation.transports.nativeImport.description).toContain(
      "automatic retries"
    )
    expect(enTranslation.transports.nativeImport.description).toContain(
      "verified by the router"
    )
    expect(
      enTranslation.transports.nativeImport.transportBlockedDescription
    ).toContain("Keenetic HTTPS domain")
    expect(
      enTranslation.transports.nativeImport.transportBlockedDescription
    ).toContain("HTTP is blocked")
    expect(enTranslation.transports.nativeImport.redactedNotice).toContain(
      "local structural preview"
    )
    expect(enTranslation.transports.nativeImport.redactedNotice).not.toContain(
      "backend"
    )
  })

  test("describes every typed readiness blocker and the live owner boundary", () => {
    for (const blocker of Object.values(
      NdmsNativeImportReadinessBlockersItem
    )) {
      expect(ruTranslation.transports.nativeImport.blockers[blocker]).toBeTruthy()
      expect(enTranslation.transports.nativeImport.blockers[blocker]).toBeTruthy()
    }

    expect(ruTranslation.transports.nativeImport.ownerRiskConsent).toContain(
      "другим инструментом"
    )
    expect(enTranslation.transports.nativeImport.ownerRiskConsent).toContain(
      "another tool"
    )
    expect(ruTranslation.transports.nativeImport.results.runningOnly).toContain(
      "system configuration save"
    )
    expect(enTranslation.transports.nativeImport.results.runningOnly).toContain(
      "system configuration save"
    )
  })
})
