import { describe, expect, test } from "bun:test"

import {
  collectProbeByInterface,
  collectRuntimeLatencyByInterface,
  selectVisibleLatency,
} from "@/components/transports/transport-latency-model"

describe("transport latency presentation", () => {
  test("prefers the SSE runtime value over a stale probe-details response", () => {
    expect(
      selectVisibleLatency(
        { success: true, attributed: true, latency_ms: 95, age_seconds: 18 },
        31
      )
    ).toEqual({ milliseconds: 31, ageSeconds: undefined })
  })

  test("keeps measurement age when both caches describe the same result", () => {
    expect(
      selectVisibleLatency(
        { success: true, attributed: true, latency_ms: 31, age_seconds: 4.9 },
        31
      )
    ).toEqual({ milliseconds: 31, ageSeconds: 4 })
  })

  test("falls back to probe details and rejects invalid figures", () => {
    expect(
      selectVisibleLatency(
        { success: true, attributed: true, latency_ms: 72, age_seconds: 2 },
        undefined
      )
    ).toEqual({ milliseconds: 72, ageSeconds: 2 })
    expect(
      selectVisibleLatency(
        {
          success: true,
          attributed: true,
          latency_ms: Number.NaN,
          age_seconds: 2,
        },
        undefined
      )
    ).toBeUndefined()
    expect(
      selectVisibleLatency(
        { success: false, attributed: true, latency_ms: 0, age_seconds: 2 },
        0
      )
    ).toBeUndefined()
  })

  // A probe that was not pinned to the outbound's device followed whatever the
  // mark selected. When the outbound's table holds no usable default that is
  // the WAN, so the figure describes the router and must not be shown against
  // a transport whose server is gone.
  test("discards an unattributed probe success instead of showing WAN latency", () => {
    expect(
      selectVisibleLatency(
        { success: true, attributed: false, latency_ms: 163, age_seconds: 2 },
        undefined
      )
    ).toBeUndefined()
  })

  test("treats a daemon that omits attribution as unattributed", () => {
    expect(
      selectVisibleLatency(
        { success: true, latency_ms: 163, age_seconds: 2 },
        undefined
      )
    ).toBeUndefined()
  })

  test("does not annotate a runtime figure with an unattributed measurement age", () => {
    expect(
      selectVisibleLatency(
        { success: true, attributed: false, latency_ms: 31, age_seconds: 5 },
        31
      )
    ).toEqual({ milliseconds: 31, ageSeconds: undefined })
  })

  test("keeps the successful standalone latency when a group reports failed zero", () => {
    const result = collectRuntimeLatencyByInterface(
      [
        {
          tag: "vless_primary",
          type: "interface",
          status: "healthy",
          interfaces: [
            {
              outbound_tag: "vless_primary",
              interface_name: "vless0",
              status: "active",
              latency_ms: 84,
            },
          ],
        },
        {
          tag: "vless_failover",
          type: "urltest",
          status: "degraded",
          interfaces: [
            {
              outbound_tag: "vless_primary",
              interface_name: "vless0",
              status: "unavailable",
              latency_ms: 0,
            },
          ],
        },
      ],
      new Map([["vless0", "vless_primary"]])
    )

    expect(result.get("vless0")).toBe(84)
  })

  test("keeps a successful standalone detailed probe over a failed group entry", () => {
    const result = collectProbeByInterface(
      {
        vless_primary: {
          success: true,
          attributed: true,
          latency_ms: 84,
          age_seconds: 2,
          interface: "vless0",
        },
        vless_failover: {
          success: false,
          attributed: true,
          latency_ms: 0,
          age_seconds: 1,
          interface: "vless0",
        },
      },
      new Map([["vless0", "vless_primary"]])
    )

    expect(result.get("vless0")).toMatchObject({
      success: true,
      latency_ms: 84,
    })
  })

  test("drops an unattributed probe rather than keying it to an interface", () => {
    const result = collectProbeByInterface(
      {
        dead_tunnel: {
          success: true,
          attributed: false,
          latency_ms: 163,
          age_seconds: 2,
          interface: "hy1",
        },
      },
      new Map([["hy1", "dead_tunnel"]])
    )

    expect(result.has("hy1")).toBe(false)
  })
})
