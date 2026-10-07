import { describe, expect, test } from "bun:test"
import type { RuntimeOutboundState } from "@/api/generated/model"
import { nativeInterfaceConnectionState } from "@/lib/native-interfaces"

const enabled = { live: true, connected: true, link: true }
const runtime = (
  status: RuntimeOutboundState["status"]
): RuntimeOutboundState => ({
  tag: "awg",
  type: "interface",
  status,
  interfaces: [],
})

describe("native VPN connection state", () => {
  test("enabled kernel interface is not a connected VPN when its peer is disconnected", () => {
    expect(
      nativeInterfaceConnectionState(
        { ...enabled, connected: false },
        runtime("healthy"),
        true
      )
    ).toBe("unavailable")
  })
  test("keeps connected peers distinct from an unsuccessful routing check", () => {
    expect(
      nativeInterfaceConnectionState(enabled, runtime("degraded"), true)
    ).toBe("connectedUnverified")
    expect(
      nativeInterfaceConnectionState(enabled, runtime("unavailable"), true)
    ).toBe("connectedUnverified")
    expect(
      nativeInterfaceConnectionState(enabled, runtime("healthy"), true)
    ).toBe("up")
  })
  test("a missing probe is unknown, not failed, and does not need a latency value", () => {
    expect(nativeInterfaceConnectionState(enabled, undefined, true)).toBe(
      "connectedPending"
    )
    expect(
      nativeInterfaceConnectionState(enabled, runtime("healthy"), true)
    ).toBe("up")
  })
  test("never manufactures a connected peer from missing NDMS data", () => {
    expect(
      nativeInterfaceConnectionState(
        { live: true },
        runtime("unavailable"),
        true
      )
    ).toBe("unavailable")
    expect(
      nativeInterfaceConnectionState({ live: true }, runtime("degraded"), true)
    ).toBe("degraded")
    expect(
      nativeInterfaceConnectionState({ live: true }, undefined, true)
    ).toBe("unknown")
    expect(
      nativeInterfaceConnectionState(
        { ...enabled, link: false },
        runtime("healthy"),
        true
      )
    ).toBe("unavailable")
  })
  test("keeps the administrative off state separate and respects disconnected unbound interfaces", () => {
    expect(
      nativeInterfaceConnectionState(
        { ...enabled, live: false },
        runtime("healthy"),
        true
      )
    ).toBe("down")
    expect(
      nativeInterfaceConnectionState(
        { ...enabled, connected: false },
        undefined,
        false
      )
    ).toBe("unavailable")
    expect(
      nativeInterfaceConnectionState({ live: true }, undefined, false)
    ).toBe("unknown")
  })
})
