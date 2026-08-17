import { describe, expect, test } from "bun:test"

import {
  applyListRefreshStatusEvent,
  subscribeListRefreshEvents,
} from "../src/api/list-refresh-events"

describe("list refresh events on the shared status stream", () => {
  test("dispatches an opaque task snapshot to subscribers", () => {
    const received: unknown[] = []
    const unsubscribe = subscribeListRefreshEvents((snapshot) => {
      received.push(snapshot)
    })

    expect(
      applyListRefreshStatusEvent(
        JSON.stringify({
          type: "list_refresh",
          data: {
            task_id: "list-refresh-11",
            state: "running",
            completed: 2,
            future_backend_field: { remains: "opaque" },
          },
        })
      )
    ).toBe(true)
    expect(received).toEqual([
      {
        task_id: "list-refresh-11",
        state: "running",
        completed: 2,
        future_backend_field: { remains: "opaque" },
      },
    ])

    unsubscribe()
  })

  test("rejects malformed and unrelated envelopes without dispatching", () => {
    const received: unknown[] = []
    const unsubscribe = subscribeListRefreshEvents((snapshot) => {
      received.push(snapshot)
    })

    expect(applyListRefreshStatusEvent("not-json")).toBe(false)
    expect(
      applyListRefreshStatusEvent(
        JSON.stringify({ type: "service", data: { status: "running" } })
      )
    ).toBe(false)
    expect(
      applyListRefreshStatusEvent(JSON.stringify({ type: "list_refresh" }))
    ).toBe(false)
    expect(received).toEqual([])

    unsubscribe()
  })

  test("unsubscribe stops later dispatches", () => {
    let calls = 0
    const unsubscribe = subscribeListRefreshEvents(() => {
      calls += 1
    })
    unsubscribe()

    expect(
      applyListRefreshStatusEvent(
        JSON.stringify({ type: "list_refresh", data: null })
      )
    ).toBe(true)
    expect(calls).toBe(0)
  })
})
