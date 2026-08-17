import { describe, expect, test } from "bun:test"

import type {
  RuntimeOutboundState,
  TransportStatus,
} from "@/api/generated/model"
import { transportOperationalState } from "@/components/transports/transport-operational-state"

const runningTransport = {
  desired_up: true,
  interface: "kpbr-vless1",
  state: "up",
} satisfies Pick<TransportStatus, "desired_up" | "interface" | "state">

function runtime(
  status: RuntimeOutboundState["status"],
  detail?: string
): RuntimeOutboundState {
  return {
    tag: "vless1",
    type: "interface",
    status,
    detail,
    interfaces: [],
  }
}

describe("transport operational state", () => {
  test("never lets a stale healthy route override a stopped supervisor", () => {
    expect(
      transportOperationalState(
        { desired_up: false, interface: "kpbr-vless1", state: "up" },
        runtime("healthy"),
        true
      )
    ).toEqual({ key: "down", healthy: false })
  })

  test("describes an unbound running transport as a process only", () => {
    expect(
      transportOperationalState(runningTransport, undefined, false)
    ).toEqual({ key: "processRunning", healthy: false })
  })

  test("does not claim success while a bound route awaits verification", () => {
    expect(
      transportOperationalState(runningTransport, undefined, true)
    ).toEqual({ key: "verificationPending", healthy: false })
  })

  test("shows success only for a healthy bound runtime", () => {
    expect(
      transportOperationalState(runningTransport, runtime("healthy"), true)
    ).toEqual({ key: "healthy", healthy: true })
  })

  test("propagates the same degraded and unavailable verdicts as dashboard", () => {
    expect(
      transportOperationalState(
        runningTransport,
        runtime("degraded", "probe timed out"),
        true
      )
    ).toEqual({
      key: "runtimeDegraded",
      healthy: false,
      detail: "probe timed out",
    })
    expect(
      transportOperationalState(
        runningTransport,
        runtime("unavailable", "no usable route"),
        true
      )
    ).toEqual({
      key: "runtimeUnavailable",
      healthy: false,
      detail: "no usable route",
    })
  })

  test("keeps supervisor degradation ahead of a stale runtime success", () => {
    expect(
      transportOperationalState(
        {
          desired_up: true,
          interface: "kpbr-vless1",
          state: "degraded",
        },
        runtime("healthy"),
        true
      )
    ).toEqual({ key: "supervisorDegraded", healthy: false })
  })

  test("keeps a starting supervisor non-healthy despite stale success", () => {
    expect(
      transportOperationalState(
        {
          desired_up: true,
          interface: "kpbr-vless1",
          state: "starting",
        },
        runtime("healthy"),
        true
      )
    ).toEqual({ key: "starting", healthy: false })
  })

  test("shows unknown runtime as non-healthy", () => {
    expect(
      transportOperationalState(
        runningTransport,
        runtime("unknown", "probe evidence is stale"),
        true
      )
    ).toEqual({
      key: "runtimeUnknown",
      healthy: false,
      detail: "probe evidence is stale",
    })
  })

  test("uses the matching interface detail when the outbound detail is empty", () => {
    const state = runtime("unavailable")
    state.interfaces = [
      {
        outbound_tag: "vless1",
        interface_name: "kpbr-vless1",
        status: "unavailable",
        detail: "interface probe timed out",
      },
    ]

    expect(transportOperationalState(runningTransport, state, true)).toEqual({
      key: "runtimeUnavailable",
      healthy: false,
      detail: "interface probe timed out",
    })
  })
})
