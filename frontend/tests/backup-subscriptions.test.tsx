import { describe, expect, spyOn, test } from "bun:test"
import { createInstance } from "i18next"
import type { ReactNode } from "react"
import { renderToStaticMarkup } from "react-dom/server"
import { I18nextProvider } from "react-i18next"

import {
  BackupPanel,
  RestoreSubscriptionsSummary,
} from "../src/components/settings/backup-dialogs"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"
import {
  BACKUP_GROUPS,
  createBackup,
  createDefaultBackupSelection,
  InvalidBackupBundleError,
  parseBackupBundle,
  readBackupFile,
  restoreBackup,
  toBackupWireSelection,
  type BackupBundle,
} from "../src/lib/backup"

const source = {
  id: "subscription-fixture",
  name: "DO_NOT_RENDER_SOURCE_NAME",
  url: "https://provider.invalid/DO_NOT_RENDER_SOURCE_TOKEN",
  refresh_interval_seconds: 3600,
  _bindings: { server: { transport_id: "vpn-fixture" } },
  _inventory: [{ private_key: "DO_NOT_RENDER_PRIVATE_KEY" }],
  future_metadata: { retained: true },
}

function backup(data: BackupBundle["data"] = {}): BackupBundle {
  return {
    format: "keen-pbr-sb-backup",
    schema: 1,
    created_at: 1,
    groups: toBackupWireSelection(createDefaultBackupSelection()),
    data,
  }
}

async function renderLocalized(node: ReactNode, language: "ru" | "en") {
  const i18n = createInstance()
  await i18n.init({
    lng: language,
    resources: {
      ru: { translation: ruTranslation },
      en: { translation: enTranslation },
    },
    interpolation: { escapeValue: false },
  })
  return renderToStaticMarkup(
    <I18nextProvider i18n={i18n}>{node}</I18nextProvider>
  )
}

describe("subscription backup compatibility", () => {
  test("keeps opaque source records and legacy absence distinct from an empty store", async () => {
    const data = { subscriptions: [source] }
    const parsed = parseBackupBundle(backup(data))
    expect(parsed.data).toBe(data)
    expect(parsed.data.subscriptions).toEqual([source])

    const loaded = await readBackupFile(
      new File([JSON.stringify(backup(data))], "backup.json")
    )
    expect(loaded.data.subscriptions).toEqual([source])
    expect(
      parseBackupBundle(backup({ subscriptions: [] })).data.subscriptions
    ).toEqual([])
    expect(
      Object.hasOwn(parseBackupBundle(backup()).data, "subscriptions")
    ).toBe(false)
  })

  test("accepts source metadata without a transport file or a new checkbox group", () => {
    const bundle = backup({ subscriptions: [source] })
    bundle.groups.transports = false
    expect(parseBackupBundle(bundle).data.subscriptions).toEqual([source])
    expect(BACKUP_GROUPS).not.toContain("subscriptions")
  })

  test.each([
    ["wrapper", { version: 1, subscriptions: [] }],
    ["null", null],
    ["string", "not-an-array"],
    ["non-object record", [null]],
    ["nested array record", [[]]],
    ["too many records", Array.from({ length: 65 }, () => source)],
  ])("rejects an invalid subscription section: %s", (_name, subscriptions) => {
    expect(() =>
      parseBackupBundle({ ...backup(), data: { subscriptions } })
    ).toThrow(InvalidBackupBundleError)
  })

  test("enforces the section byte limit rather than a JavaScript character count", () => {
    const subscriptions = [{ ...source, payload: "я".repeat(2 * 1024 * 1024) }]
    expect(() => parseBackupBundle(backup({ subscriptions }))).toThrow(
      InvalidBackupBundleError
    )
    expect(
      parseBackupBundle(
        backup({ subscriptions: Array.from({ length: 64 }, () => source) })
      ).data.subscriptions
    ).toHaveLength(64)
  })

  test("export and restore retain source URLs, schedules, bindings and unknown metadata", async () => {
    const bundle = backup({ subscriptions: [source] })
    const selection = createDefaultBackupSelection()
    const fetchSpy = spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(Response.json(bundle))
      .mockResolvedValueOnce(Response.json({}))
    try {
      const exported = await createBackup(selection)
      expect(exported.data.subscriptions).toEqual([source])
      await restoreBackup(exported)
      expect(fetchSpy).toHaveBeenCalledTimes(2)
      expect(JSON.parse(String(fetchSpy.mock.calls[0]?.[1]?.body))).toEqual({
        groups: toBackupWireSelection(selection),
      })
      expect(JSON.parse(String(fetchSpy.mock.calls[1]?.[1]?.body))).toEqual(
        bundle
      )
    } finally {
      fetchSpy.mockRestore()
    }
  })
})

describe.each(["ru", "en"] as const)(
  "subscription backup UI in %s",
  (language) => {
    const messages = (language === "ru" ? ruTranslation : enTranslation).pages
      .settings.backup

    test("explains subscriptions within the existing VPN choice and secrets notice", async () => {
      const html = await renderLocalized(<BackupPanel />, language)
      expect(html).toContain(messages.choices.vpn)
      expect(html).toContain(messages.vpnHint)
      expect(html).toContain(messages.secretsWarning)
      expect(html.match(/role="checkbox"/g)).toHaveLength(5)
    })

    test("shows only the source count and restore behavior, never archive values", async () => {
      const html = await renderLocalized(
        <RestoreSubscriptionsSummary
          bundle={backup({ subscriptions: [source, source] })}
        />,
        language
      )
      expect(html).toContain(
        messages.restoreSubscriptions.replace("{{count}}", "2")
      )
      expect(html).not.toContain("DO_NOT_RENDER")
      expect(html).not.toContain("provider.invalid")
      expect(html).not.toContain("subscription-fixture")
      expect(html).not.toContain("vpn-fixture")
      expect(html).not.toContain("pages.settings.backup.")
    })

    test("distinguishes an empty source store from a legacy VPN backup", async () => {
      const empty = await renderLocalized(
        <RestoreSubscriptionsSummary bundle={backup({ subscriptions: [] })} />,
        language
      )
      expect(empty).toContain(messages.restoreSubscriptionsEmpty)
      expect(empty).not.toContain(messages.restoreSubscriptionsLegacy)

      const legacy = await renderLocalized(
        <RestoreSubscriptionsSummary bundle={backup({ transports: {} })} />,
        language
      )
      expect(legacy).toContain(messages.restoreSubscriptionsLegacy)
      expect(legacy).not.toContain(messages.restoreSubscriptionsEmpty)
    })

    test("does not add a subscription summary to an unrelated partial backup", async () => {
      const html = await renderLocalized(
        <RestoreSubscriptionsSummary bundle={backup({ dns: {} })} />,
        language
      )
      expect(html).toBe("")
    })
  }
)
