import { describe, expect, test } from "bun:test"

import type { PpeDeoffloadHealth } from "../src/api/generated/model"
import {
  formatPpePorts,
  getPpeDeoffloadPresentation,
} from "../src/components/overview/ppe-deoffload-status-model"

function health(state: PpeDeoffloadHealth["state"]): PpeDeoffloadHealth {
  return {
    mode: "auto",
    capability: "supported",
    state,
    tcp: { active: false, desired_ports: ["80", "443"], applied_ports: [] },
    quic: { active: false, desired_ports: [], applied_ports: [] },
  }
}

describe("PPE de-offload status presentation", () => {
  test("never presents admissibility as verified active", () => {
    expect(getPpeDeoffloadPresentation(health("admissible"))).toEqual({
      kind: "admissibleOnly",
      badgeVariant: "warning",
    })
  })

  test("uses success only for the semantically verified active state", () => {
    expect(getPpeDeoffloadPresentation(health("active"))).toEqual({
      kind: "verifiedActive",
      badgeVariant: "success",
    })
    expect(getPpeDeoffloadPresentation(health("inactive")).badgeVariant).toBe(
      "outline"
    )
    expect(getPpeDeoffloadPresentation(health("degraded")).badgeVariant).toBe(
      "destructive"
    )
  })

  test("ports are displayed as exact backend values without inventing ranges", () => {
    expect(formatPpePorts(["80", "443", "1984", "5222"])).toBe(
      "80, 443, 1984, 5222"
    )
    expect(formatPpePorts([])).toBeNull()
  })
})
