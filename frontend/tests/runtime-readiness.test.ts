import { describe, expect, test } from "bun:test"

import {
  describeRuntimeNotReady,
  waitForRuntimeReadiness,
  type RuntimeReadinessHealth,
} from "../src/lib/runtime-readiness"

const readyHealth: RuntimeReadinessHealth = {
  status: "running",
  runtime_state: "running",
  resolver_config_hash: "0123456789abcdef0123456789abcdef",
  resolver_live_status: "healthy",
  resolver_config_sync_state: "converged",
}

describe("dashboard runtime restart readiness", () => {
  test("does not report success while dnsmasq is still converging", () => {
    expect(
      describeRuntimeNotReady(
        {
          ...readyHealth,
          resolver_config_sync_state: "converging",
        },
        { overall: "ok" },
        [],
        []
      )
    ).toContain("converging")
  })

  test("does not report success while a restarted transport is degraded", () => {
    expect(
      describeRuntimeNotReady(
        readyHealth,
        { overall: "ok" },
        [
          {
            tag: "proxy",
            state: "degraded",
            error: "TUN interface is missing",
          },
        ],
        ["proxy"]
      )
    ).toBe("TUN interface is missing")
  })

  test("waits for routing, resolver and transports to converge", async () => {
    let ready = false
    let sleeps = 0

    await waitForRuntimeReadiness(
      {
        health: async () =>
          ready
            ? readyHealth
            : {
                ...readyHealth,
                resolver_config_sync_state: "converging",
              },
        routing: async () => ({ overall: ready ? "ok" : "degraded" }),
        transports: async () => [
          { tag: "proxy", state: ready ? "up" : "starting" },
        ],
      },
      {
        expectedTransportTags: ["proxy"],
        intervalMs: 1,
        timeoutMs: 1_000,
        sleep: async () => {
          sleeps += 1
          ready = true
        },
      }
    )

    expect(sleeps).toBe(1)
  })

  test("returns a concrete failure instead of a false success", async () => {
    await expect(
      waitForRuntimeReadiness(
        {
          health: async () => ({
            ...readyHealth,
            runtime_state: "broken",
            runtime_state_reason: "resolver activation failed",
          }),
          routing: async () => ({ overall: "degraded" }),
        },
        { timeoutMs: 0 }
      )
    ).rejects.toThrow("resolver activation failed")
  })
})
