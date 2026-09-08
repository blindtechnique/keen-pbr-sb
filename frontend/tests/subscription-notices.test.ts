import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import { createInstance } from "i18next"
import { QueryClient } from "@tanstack/react-query"
import { invalidateSubscriptionQueries } from "@/api/subscription-events"
import { queryKeys } from "@/api/query-keys"

import {
  SubscriptionNoticeKind,
  type SubscriptionNotice,
} from "@/api/generated/model"
import { collectNotices } from "@/components/layout/notifications"
import {
  notificationUpdateIds,
  presentSubscriptionNotice,
} from "@/components/layout/subscription-notices"
import { readSubscriptionDeepLink } from "@/components/transports/subscription-settings-model"
import { enTranslation } from "@/i18n/en"
import { ruTranslation } from "@/i18n/ru"

const base: SubscriptionNotice = {
  id: "subscription:source:new:revision1",
  subscription_id: "source / #&?",
  name: "Home plan",
  kind: "new_servers",
  count: 3,
}
const key = (key: string) => key

describe("subscription bell notices", () => {
  test("localizes every backend notice kind and links to the exact source without importing", async () => {
    for (const language of ["ru", "en"] as const) {
      const i18n = createInstance()
      await i18n.init({
        lng: language,
        resources: {
          ru: { translation: ruTranslation },
          en: { translation: enTranslation },
        },
        interpolation: { escapeValue: false },
      })
      for (const kind of Object.values(SubscriptionNoticeKind)) {
        const notice = presentSubscriptionNotice(
          { ...base, kind, days: 2, remaining_percent: 8 },
          i18n.t
        )
        expect(notice).toBeDefined()
        expect(notice!.text).toContain("Home plan")
        expect(notice!.text).not.toContain("notifications.")
        expect(notice!.text).not.toContain("undefined")
        expect(notice!.actionLabel).not.toContain("notifications.")
        if (language === "ru") expect(notice!.text).toMatch(/[А-Яа-я]/)
        const href = new URL(notice!.href!, "http://router")
        expect(href.pathname).toBe("/transports")
        expect(readSubscriptionDeepLink(href.search)).toEqual({
          open: true,
          id: base.subscription_id,
        })
      }
    }
    expect(presentSubscriptionNotice(base, key)?.actionLabel).toBe(
      "notifications.subscriptions.chooseServers"
    )
  })

  test("missing provider counters or dates are not guessed as zero", () => {
    expect(
      presentSubscriptionNotice({ ...base, count: undefined }, key)?.text
    ).toBe("notifications.subscriptions.newServers")
    expect(
      presentSubscriptionNotice({ ...base, kind: "traffic_low" }, key)?.text
    ).toBe("notifications.subscriptions.trafficLow")
    expect(
      presentSubscriptionNotice({ ...base, kind: "expires_soon" }, key)?.text
    ).toBe("notifications.subscriptions.expiresSoon")
  })

  test("shared exact dismissal hides the read pending set but not its later revision", () => {
    const next = { ...base, id: "subscription:source:new:revision2", count: 4 }
    const result = collectNotices(
      [],
      undefined,
      undefined,
      undefined,
      [],
      new Set([base.id]),
      key,
      undefined,
      [base, next]
    )
    expect(result.map((notice) => notice.id)).toEqual([next.id])
  })

  test("clear includes all loaded subscription notices beyond twenty visible rows", () => {
    const batch = Array.from({ length: 30 }, (_, index) => ({
      ...base,
      id: `subscription:source:${index}`,
    }))
    const visible = collectNotices(
      [],
      { available: true, latest: "3.3.0" },
      undefined,
      undefined,
      [],
      new Set(),
      key,
      undefined,
      batch
    )
    expect(visible).toHaveLength(20)
    const ids = notificationUpdateIds(visible, batch)
    expect(ids).toHaveLength(31)
    expect(new Set(ids).size).toBe(31)
    expect(ids).toContain("system-update-3.3.0")
    expect(ids).toContain(batch[29].id)
    expect(ids).not.toContain("subscription:source:31")
    expect(
      notificationUpdateIds(
        [
          {
            id: "log:one",
            level: "warning",
            text: "history",
            timestamp: "yesterday",
          },
        ],
        []
      )
    ).toEqual([])
  })

  test("the bell wires current notices, full-batch clear and a closing navigation link", () => {
    const bell = readFileSync(
      new URL(
        "../src/components/layout/notifications-bell.tsx",
        import.meta.url
      ),
      "utf8"
    )
    expect(bell).toContain("logsQuery.data?.subscription_notices")
    expect(bell).toContain("notificationUpdateIds(")
    expect(bell).toMatch(
      /<Link[\s\S]*?href=\{notice.href\}[\s\S]*?onClick=\{\(\) => setOpen\(false\)\}/
    )
    expect(bell).toContain('t("notifications.subscriptions.loadFailed")')
    expect(bell).not.toContain("postSubscriptionApply")
  })

  test("confirmed subscription import invalidates linked routing rules and notices", () => {
    const source = readFileSync(
      new URL("../src/api/mutations.ts", import.meta.url),
      "utf8"
    )
    const hook = source.slice(
      source.indexOf("export const usePostSubscriptionApplyMutation"),
      source.indexOf("export const usePostTransportActionMutation")
    )
    expect(hook).toContain("invalidateSubscriptionQueries(queryClient)")
    const client = new QueryClient()
    try {
      const keys = [queryKeys.config(), ["logs", "notifications"]]
      for (const queryKey of keys)
        client.setQueryData(queryKey, { existing: true })
      invalidateSubscriptionQueries(client)
      for (const queryKey of keys)
        expect(client.getQueryState(queryKey)?.isInvalidated).toBe(true)
    } finally {
      client.clear()
    }
  })
})
