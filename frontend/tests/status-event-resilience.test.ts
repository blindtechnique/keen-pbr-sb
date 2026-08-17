import { describe, expect, test } from "bun:test"
import { QueryClient } from "@tanstack/react-query"

import { getGetRuntimeOutboundsQueryKey } from "../src/api/generated/keen-api"
import { createStatusQueryResilience } from "../src/api/status-event-resilience"

function runtimeResponse(status: "healthy" | "unknown") {
  return {
    data: {
      outbounds: [
        {
          tag: "techcorner_awg",
          type: "interface",
          status,
          interfaces: [],
        },
      ],
    },
    status: 200,
    headers: new Headers(),
  }
}

describe("status event REST fallback", () => {
  test("replaces an initial UNKNOWN snapshot while SSE is unavailable", () => {
    const client = new QueryClient()
    const key = getGetRuntimeOutboundsQueryKey()
    client.setQueryData(key, runtimeResponse("unknown"))

    let scheduled = 0
    const resilience = createStatusQueryResilience({
      refresh: () => {
        client.setQueryData(key, runtimeResponse("healthy"))
      },
      schedule: () => {
        scheduled += 1
        return scheduled
      },
      cancel: () => undefined,
    })

    resilience.transition("connecting")
    expect(scheduled).toBe(1)
    expect(client.getQueryData(key)).toMatchObject({
      data: { outbounds: [{ status: "unknown" }] },
    })

    resilience.transition("disconnected")
    expect(client.getQueryData(key)).toMatchObject({
      data: { outbounds: [{ status: "healthy" }] },
    })
    resilience.transition("disconnected")
    expect(scheduled).toBe(1)
    resilience.dispose()
  })

  test("cancels fallback polling and performs one reconciliation on connect", () => {
    let refreshes = 0
    let schedules = 0
    const cancelled: number[] = []
    const resilience = createStatusQueryResilience({
      refresh: () => {
        refreshes += 1
      },
      schedule: () => {
        schedules += 1
        return schedules
      },
      cancel: (handle) => cancelled.push(handle),
    })

    resilience.transition("connecting")
    expect(schedules).toBe(1)
    expect(refreshes).toBe(0)

    resilience.transition("connected")
    expect(cancelled).toEqual([1])
    expect(refreshes).toBe(1)

    // Repeated browser error/open callbacks in the same state cannot turn the
    // fallback into an unbounded request loop.
    resilience.transition("connected")
    expect(refreshes).toBe(1)

    // A connected stream stays event-driven; no replacement interval starts.
    expect(schedules).toBe(1)
    resilience.dispose()
  })
})
