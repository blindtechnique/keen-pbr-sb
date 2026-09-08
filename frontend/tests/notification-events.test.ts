import { describe, expect, test } from "bun:test"
import { QueryClient } from "@tanstack/react-query"

import {
  applyNotificationState,
  applyNotificationStatusEvent,
  NOTIFICATION_STATE_QUERY_KEY,
} from "@/api/notification-events"
import { collectNotices } from "@/components/layout/notifications"
import type { NotificationDismissalState } from "@/api/generated/model"

const event = (data: NotificationDismissalState) =>
  JSON.stringify({ type: "notification_state", data })
const read = (client: QueryClient) =>
  client.getQueryData<NotificationDismissalState>(NOTIFICATION_STATE_QUERY_KEY)!

describe("shared notification dismissal", () => {
  test("phone clear reaches PC and a newly opened browser via the same state", () => {
    const phone = new QueryClient()
    const pc = new QueryClient()
    const initial = { revision: 0, log_ids: [], update_ids: [] }
    applyNotificationState(phone, initial)
    applyNotificationState(pc, initial)
    const cleared = {
      revision: 1,
      log_ids: ["log:old"],
      update_ids: ["system-update-3.3.0"],
    }
    applyNotificationState(phone, cleared)
    expect(applyNotificationStatusEvent(pc, event(cleared))).toBe(true)
    const reopened = new QueryClient()
    expect(applyNotificationStatusEvent(reopened, event(cleared))).toBe(true)
    expect(read(pc)).toEqual(read(phone))
    expect(read(reopened)).toEqual(cleared)

    for (const client of [phone, pc, reopened]) {
      const state = read(client)
      const notices = collectNotices(
        [
          "2026-09-05 12:00:00.000 [W] Previous warning",
          "2026-09-05 12:00:01.000 [E] Concurrent new error",
        ],
        { available: true, latest: "3.3.0" },
        undefined,
        undefined,
        ["log:old", "log:new"],
        new Set([...state.log_ids, ...state.update_ids]),
        (key) => key
      )
      expect(notices.map((notice) => notice.id)).toEqual(["log:new"])
    }
  })

  test("late GET, duplicate response and older SSE cannot undo a newer clear", () => {
    const client = new QueryClient()
    const current = { revision: 3, log_ids: ["log:a", "log:b"], update_ids: [] }
    applyNotificationState(client, current)
    applyNotificationState(client, { revision: 1, log_ids: [], update_ids: [] })
    applyNotificationStatusEvent(
      client,
      event({ revision: 2, log_ids: ["log:a"], update_ids: [] })
    )
    applyNotificationStatusEvent(client, event(current))
    expect(read(client)).toEqual(current)
  })

  test("ignores unrelated or malformed events without changing visible state", () => {
    const client = new QueryClient()
    for (const raw of [
      "not json",
      "null",
      "[]",
      JSON.stringify({ type: "service", data: {} }),
      JSON.stringify({
        type: "notification_state",
        data: { revision: -1, log_ids: [], update_ids: [] },
      }),
      JSON.stringify({
        type: "notification_state",
        data: { revision: 1, log_ids: [null], update_ids: [] },
      }),
    ]) {
      expect(applyNotificationStatusEvent(client, raw)).toBe(false)
    }
    expect(read(client)).toBeUndefined()
  })
})
