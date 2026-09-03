import { describe, expect, test } from "bun:test"

import { selectRoutingRecoveryAction } from "../src/components/overview/service-routing-recovery"

describe("dashboard routing recovery action", () => {
  test("starts an inactive runtime after a broken cold boot", () => {
    expect(
      selectRoutingRecoveryAction({
        status: "stopped",
        runtime_state: "broken",
      })
    ).toBe("start")
  })

  test("starts a deliberately stopped runtime", () => {
    expect(
      selectRoutingRecoveryAction({
        status: "stopped",
        runtime_state: "stopped",
      })
    ).toBe("start")
  })

  test("restarts a running runtime", () => {
    expect(
      selectRoutingRecoveryAction({
        status: "running",
        runtime_state: "running",
      })
    ).toBe("restart")
  })

  test("uses active status for a runtime that requires restart", () => {
    expect(
      selectRoutingRecoveryAction({
        status: "running",
        runtime_state: "restart_required",
      })
    ).toBe("restart")
  })
})
