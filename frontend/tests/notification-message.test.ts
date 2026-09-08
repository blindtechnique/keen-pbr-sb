import { describe, expect, test } from "bun:test"
import { createInstance } from "i18next"

import {
  presentNotificationMessage,
  type NotificationMessageLevel,
} from "../src/components/layout/notification-message"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"

const liveIncidents = [
  [
    "Urltest 'hysteria2_bound' candidate was rejected; the previous selection remains verified: exact runtime routing transaction did not commit",
    "groupSwitchRejected",
  ],
  [
    "Urltest 'hysteria2_bound' candidate and exact rollback were not verified: URLTEST rollback was not verified",
    "groupSwitchUnverified",
  ],
  [
    "Config apply failed: staged configuration changed before candidate admission; rolled_back=false; runtime_unchanged=true",
    "configDraftChanged",
  ],
  [
    "Cannot quiesce routing after unsafe config save: Runtime STOP was not admitted by the firewall owner",
    "routingStopFailed",
  ],
  [
    "Config save recovery required: Runtime rolled back, but exact persistent recovery could not be proven; apply: staged configuration changed before candidate admission; recovery: Persistent rollback runtime reconciliation was interrupted: transport manager restart failed",
    "configRecoveryVpnRestartFailed",
  ],
  [
    "Delayed runtime firewall refresh failed: candidate rule has no owned route anchor or external table authority. The last verified daemon snapshot remains active while a bounded retry resnapshots the backend.",
    "routingAnchorMissing",
  ],
  [
    "control response failed: control socket write failed: Broken pipe",
    "controlResponseInterrupted",
  ],
] as const

async function present(
  raw: string,
  level: NotificationMessageLevel = "error",
  language: "ru" | "en" = "ru"
) {
  const i18n = createInstance()
  await i18n.init({
    lng: language,
    resources: {
      [language]: {
        translation: language === "ru" ? ruTranslation : enTranslation,
      },
    },
    interpolation: { escapeValue: false },
  })
  return presentNotificationMessage(raw, level, i18n.getFixedT(language))
}

describe("notification message presentation", () => {
  test.each(liveIncidents)("localizes live incident %s", async (raw, key) => {
    const translated = await present(raw)
    const expected = ruTranslation.notifications.messages[key].replace(
      "{{name}}",
      "hysteria2_bound"
    )
    expect(translated.text).toBe(expected)
    expect(translated.text).not.toBe(raw)
    expect(translated.details).toBe(raw)
  })

  test("keeps the selected language and the original technical detail", async () => {
    const raw = liveIncidents[1][0]
    const result = await present(raw, "error", "en")
    expect(result.text).toContain("Neither switching group")
    expect(result.text).toContain("hysteria2_bound")
    expect(result.text).not.toMatch(/[А-Яа-яЁё]/)
    expect(result.details).toBe(raw)
  })

  test("does not claim rollback or unchanged runtime for an unproven outcome", async () => {
    const raw =
      "Config apply failed: firewall failed; rolled_back=false; runtime_unchanged=false"
    const result = await present(raw)
    expect(result.text).toBe(
      ruTranslation.notifications.messages.configApplyFailed
    )
    expect(result.text).not.toContain("был сохранён")
    expect(result.text).not.toContain("маршрутизация не менялась")
    expect(result.details).toBe(raw)
  })

  test("does not report a historical busy condition as current service state", async () => {
    const result = await present(
      "Another runtime mutation is already in progress: runtime-firewall-worker"
    )
    expect(result.text).toContain("в это время")
    expect(result.text).not.toContain("ещё выполняет")
    expect(result.text).not.toContain("runtime-firewall-worker")
  })

  test.each(["error", "warning", "info"] as const)(
    "unknown %s messages have a localized primary and exact details",
    async (level) => {
      const raw =
        "Unexpected new worker failure; internal_code=73; a rollback might have happened"
      const result = await present(raw, level)
      expect(result.text).toMatch(/[А-Яа-яЁё]/)
      expect(result.text).not.toContain("Unexpected")
      expect(result.text).not.toContain("rollback")
      expect(result.details).toBe(raw)
    }
  )

  test("does not reinterpret nested familiar errors or fabricate empty details", async () => {
    const result = await present(
      "Unrecognized operation failed: Another runtime mutation is already in progress: worker"
    )
    expect(result.text).toBe(ruTranslation.notifications.messages.unknownError)
    expect((await present(" \n ", "warning")).details).toBeUndefined()
  })
})

describe("specific list and routing causes", () => {
  test("subscription auto-refresh failure is localized without claiming a VPN rollback", async () => {
    const raw = "Subscription auto-refresh failed"
    for (const language of ["ru", "en"] as const) {
      const result = await present(raw, "warning", language)
      const dictionary = language === "ru" ? ruTranslation : enTranslation
      expect(result.text).toBe(
        dictionary.notifications.messages.subscriptionRefreshFailed
      )
      expect(result.details).toBe(raw)
      expect(result.text).not.toContain("rollback")
      expect(result.text).not.toContain("откат")
    }
    const different = await present(`${raw}: unknown private detail`, "warning")
    expect(different.text).toBe(
      ruTranslation.notifications.messages.unknownWarning
    )
  })
  test("preserves list names and source hosts without putting URL credentials or tokens in the primary", async () => {
    const raw =
      "List 'Рабочие сайты': failed to refresh https://user:password@lists.example.test:8443/private?token=secret: Could not resolve host: lists.example.test"
    const result = await present(raw, "warning")
    expect(result.text).toContain("Рабочие сайты")
    expect(result.text).toContain("lists.example.test:8443")
    expect(result.text).toContain("DNS")
    expect(result.text).not.toContain("password")
    expect(result.text).not.toContain("token=secret")
    expect(result.details).toBe(raw)
  })

  test.each([
    ["Operation timed out after 15000 milliseconds", "listTimedOut"],
    [
      "Failed to connect to example.test port 443 after 1 ms: Could not connect to server",
      "listConnectionFailed",
    ],
    ["HTTP error 503", "listHttpFailed"],
    [
      "HTTP 304 received without a matching local cache validator",
      "listNotModifiedWithoutCache",
    ],
    [
      "SRS contains no safely representable domain, domain suffix or IP/CIDR entries",
      "listSrsUnsupported",
    ],
    [
      "no configured download outbound has a routing mark",
      "listDownloadRouteUnavailable",
    ],
  ] as const)("maps the exact list cause %s", (reason, key) => {
    const result = presentNotificationMessage(
      `List 'work': failed to refresh https://example.test/list: ${reason}`,
      "warning",
      (value) => value
    )
    expect(result.text).toBe(`notifications.messages.${key}`)
  })

  test("explains both reduced and empty candidates with the recorded counts", async () => {
    const reduced = await present(
      "List 'work': failed to refresh https://example.test/list: the update decoded 120 entries against 1000 cached, keeping 12% - below the 50% this source is allowed to lose; keeping the cached list",
      "warning"
    )
    expect(reduced.text).toContain("с 1000 до 120 записей")
    expect(reduced.text).toContain("была сохранена")
    expect(reduced.text).toContain("принятия сокращения")
    const empty = await present(
      "List 'work': failed to refresh https://example.test/list: the update decoded no entries at all while the cached list has 90; keeping the cached list",
      "warning"
    )
    expect(empty.text).toContain("не содержало записей")
    expect(empty.text).toContain("из 90 записей была сохранена")
    expect(empty.text).not.toContain("принятия сокращения")
  })

  test("does not mistake missing error metadata for a resolved list failure", async () => {
    const raw =
      "List 'work': could not persist refresh failure status: disk full"
    const result = await present(raw, "warning")
    expect(result.text).toContain("закончилось место")
    expect(result.text).not.toContain("обновился")
    expect(result.details).toBe(raw)
  })

  test("partially skipped SRS rules differ from harmless domain mapping", async () => {
    const result = await present(
      "List 'work': SRS import is lossy: skipped 3 rule(s), including 1 inverted rule(s)",
      "warning"
    )
    expect(result.text).toContain("Часть условий")
    const mapping = await present(
      "List 'work': SRS import is lossy: mapped 30 exact domain(s) to keen-pbr root-and-subdomain semantics",
      "warning"
    )
    expect(mapping.text).not.toContain("Часть условий")
  })

  test("routes known Meta/PPE incidents to current diagnostics without claiming current failure", async () => {
    const meta = await present(
      "Meta/WhatsApp UDP/443 policy state is degraded: publication unverified"
    )
    expect(meta.text).toContain("Не удалось подтвердить")
    expect(meta.text).toContain("текущее состояние")
    expect(meta.text).not.toContain("degraded")
    const ppe = await present(
      "PPE de-offload reconciliation degraded: could not inspect the IPv4 PPE de-offload graph",
      "warning"
    )
    expect(ppe.text).toContain("аппаратном ускорении")
    expect(ppe.text).not.toContain("PPE")
  })
})
