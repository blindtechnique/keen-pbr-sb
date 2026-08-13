import { describe, expect, test } from "bun:test"

import { NdmsManagementBlocker } from "@/api/generated/model"
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

  test("keeps secret-bearing import local until a protected channel exists", () => {
    expect(ruTranslation.transports.nativeImport.description).toContain(
      "только в этом браузере"
    )
    expect(ruTranslation.transports.nativeImport.description).toContain(
      "приложение не отправляет"
    )
    expect(ruTranslation.transports.nativeImport.description).toContain(
      "подтверждённое роутером"
    )
    expect(
      ruTranslation.transports.nativeImport.transportBlockedDescription
    ).toContain("подтверждения роутером")
    expect(ruTranslation.transports.nativeImport.redactedNotice).toContain(
      "предварительное"
    )
    expect(ruTranslation.transports.nativeImport.redactedNotice).not.toContain(
      "backend"
    )

    expect(enTranslation.transports.nativeImport.description).toContain(
      "only in this browser"
    )
    expect(enTranslation.transports.nativeImport.description).toContain(
      "application does not send"
    )
    expect(enTranslation.transports.nativeImport.description).toContain(
      "verified by the router"
    )
    expect(
      enTranslation.transports.nativeImport.transportBlockedDescription
    ).toContain("router verifies")
    expect(enTranslation.transports.nativeImport.redactedNotice).toContain(
      "preliminary"
    )
    expect(enTranslation.transports.nativeImport.redactedNotice).not.toContain(
      "backend"
    )
  })
})
