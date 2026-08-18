import { describe, expect, test } from "bun:test"

import { exitCheckSummary } from "@/components/transports/exit-check-model"
import type { TransportExitCheckResponse } from "@/api/generated/model"

const probe = (address: string, attributed: boolean, ok = true) => ({
  ok,
  attributed,
  address,
  latency_ms: 120,
  error: "",
})

const result = (
  patch: Partial<TransportExitCheckResponse>
): TransportExitCheckResponse =>
  ({
    outbound: "moooawg",
    verdict: "working",
    exit_address: "changed",
    through: probe("203.0.113.7", true),
    direct: probe("198.51.100.9", false),
    ...patch,
  }) as TransportExitCheckResponse

describe("exit check summary", () => {
  test("a different address through the tunnel is the one green answer", () => {
    const summary = exitCheckSummary(result({}))
    expect(summary?.tone).toBe("success")
    expect(summary?.titleKey).toBe("transports.exitCheck.changed")
    expect(summary?.through).toBe("203.0.113.7")
    expect(summary?.direct).toBe("198.51.100.9")
  })

  test("an unattributed answer is never rendered as success or failure", () => {
    // It carries an address, and that is exactly the trap: the address belongs
    // to whatever route the mark happened to select.
    const summary = exitCheckSummary(
      result({ verdict: "unattributed", exit_address: "changed" })
    )
    expect(summary?.tone).toBe("info")
    expect(summary?.titleKey).toBe("transports.exitCheck.unattributed")
  })

  test("the same address on both sides is a warning, not a tick", () => {
    const summary = exitCheckSummary(
      result({
        exit_address: "same",
        through: probe("198.51.100.9", true),
      })
    )
    expect(summary?.tone).toBe("warning")
    expect(summary?.titleKey).toBe("transports.exitCheck.same")
  })

  test("a missing control claims only what the run measured", () => {
    const summary = exitCheckSummary(
      result({ exit_address: "unknown", direct: probe("", false, false) })
    )
    expect(summary?.tone).toBe("info")
    expect(summary?.titleKey).toBe("transports.exitCheck.noControl")
    expect(summary?.through).toBe("203.0.113.7")
    expect(summary?.direct).toBeUndefined()
  })

  test("an unreachable pinned probe is the failure", () => {
    const summary = exitCheckSummary(result({ verdict: "unreachable" }))
    expect(summary?.tone).toBe("danger")
    expect(summary?.titleKey).toBe("transports.exitCheck.unreachable")
  })

  test("nothing is claimed before a result exists", () => {
    expect(exitCheckSummary(undefined)).toBeNull()
  })
})
