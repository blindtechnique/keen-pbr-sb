import { describe, expect, test } from "bun:test"

import { selectVisibleLatency } from "@/components/transports/transport-latency-model"

describe("transport latency presentation", () => {
  test("prefers the SSE runtime value over a stale probe-details response", () => {
    expect(
      selectVisibleLatency(
        { success: true, latency_ms: 95, age_seconds: 18 },
        31
      )
    ).toEqual({ milliseconds: 31, ageSeconds: undefined })
  })

  test("keeps measurement age when both caches describe the same result", () => {
    expect(
      selectVisibleLatency(
        { success: true, latency_ms: 31, age_seconds: 4.9 },
        31
      )
    ).toEqual({ milliseconds: 31, ageSeconds: 4 })
  })

  test("falls back to probe details and rejects invalid figures", () => {
    expect(
      selectVisibleLatency(
        { success: true, latency_ms: 72, age_seconds: 2 },
        undefined
      )
    ).toEqual({ milliseconds: 72, ageSeconds: 2 })
    expect(
      selectVisibleLatency(
        { success: true, latency_ms: Number.NaN, age_seconds: 2 },
        undefined
      )
    ).toBeUndefined()
  })
})
