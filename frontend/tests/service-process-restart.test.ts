import { describe, expect, it } from "bun:test"
import { waitForServiceProcessRestart } from "../src/components/overview/service-process-restart"

const healthy = {
  status: "running" as const,
  runtime_state: "running" as const,
  resolver_live_status: "healthy" as const,
}

describe("waitForServiceProcessRestart", () => {
  it("waits for the new daemon and manager, not the old healthy response", async () => {
    let now = 0
    let calls = 0
    let managerCalls = 0
    await waitForServiceProcessRestart(
      {
        health: async () => {
          calls += 1
          if (calls === 2) throw new Error("disconnected")
          return { ...healthy, daemon_pid: calls === 1 ? 10 : 20 }
        },
        routing: async () => ({ overall: "ok" }),
        transports: async () => {
          managerCalls += 1
          return []
        },
      },
      10,
      {
        now: () => now,
        sleep: async (duration) => {
          now += duration
        },
      }
    )
    expect(now).toBe(2000)
    expect(calls).toBeGreaterThanOrEqual(4)
    expect(managerCalls).toBeGreaterThanOrEqual(1)
  })

  it("does not call an unchanged daemon a completed restart", async () => {
    let now = 0
    let managerCalls = 0
    await expect(
      waitForServiceProcessRestart(
        {
          health: async () => ({ ...healthy, daemon_pid: 10 }),
          routing: async () => ({ overall: "ok" }),
          transports: async () => {
            managerCalls += 1
            return []
          },
        },
        10,
        {
          timeoutMs: 2000,
          now: () => now,
          sleep: async (duration) => {
            now += duration
          },
        }
      )
    ).rejects.toThrow("service_process_restart_timeout")
    expect(managerCalls).toBe(0)
  })

  it("requires the manager to return even when there are no VPNs", async () => {
    let now = 0
    await expect(
      waitForServiceProcessRestart(
        {
          health: async () => ({ ...healthy, daemon_pid: 20 }),
          routing: async () => ({ overall: "ok" }),
          transports: async () => {
            throw new Error("manager unavailable")
          },
        },
        10,
        {
          timeoutMs: 2000,
          now: () => now,
          sleep: async (duration) => {
            now += duration
          },
        }
      )
    ).rejects.toThrow("service_process_restart_timeout")
  })
})
