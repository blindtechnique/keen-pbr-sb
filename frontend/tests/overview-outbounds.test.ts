import { describe, expect, test } from "bun:test"

import type { RuntimeOutboundState } from "@/api/generated/model"
import {
  activeOutboundMember,
  outboundRuntimeIssue,
  outboundRuntimeIssues,
  outboundTrafficBucket,
} from "@/components/overview/outbound-state-model"

describe("dashboard outbound traffic classification", () => {
  test("does not call a tunnel-backed routing table direct", () => {
    expect(outboundTrafficBucket({ type: "table" }, "AWG")).toBe("tunnels")
    expect(outboundTrafficBucket({ type: "table" }, "")).toBe("direct")
  })

  test("classifies interface routes by proven protocol", () => {
    expect(outboundTrafficBucket({ type: "interface" }, "VLESS")).toBe(
      "tunnels"
    )
    expect(outboundTrafficBucket({ type: "interface" }, "")).toBe("direct")
  })

  test("keeps blackhole separate from route transport", () => {
    expect(outboundTrafficBucket({ type: "blackhole" }, "VLESS")).toBe(
      "blocked"
    )
  })

  test("selects the live failover member from runtime state", () => {
    const runtime: RuntimeOutboundState = {
      tag: "vpn",
      type: "urltest",
      status: "healthy",
      interfaces: [
        { outbound_tag: "primary", status: "backup" },
        { outbound_tag: "secondary", status: "active" },
      ],
    }

    expect(activeOutboundMember(runtime)?.outbound_tag).toBe("secondary")
  })

  test("maps known runtime details to human-facing issue codes", () => {
    expect(
      outboundRuntimeIssue({
        tag: "vpn",
        type: "urltest",
        status: "degraded",
        detail: "live route selection differs from urltest manager selection",
        interfaces: [],
      })
    ).toEqual({ code: "selectionMismatch" })

    expect(
      outboundRuntimeIssue({
        tag: "vpn",
        type: "interface",
        status: "unavailable",
        interfaces: [
          {
            outbound_tag: "vpn",
            status: "unavailable",
            detail: "interface is not reachable from the main routing table",
          },
        ],
      })
    ).toEqual({ code: "interfaceUnreachable", memberTag: "vpn" })
  })

  test("does not expose arbitrary backend probe text on the dashboard", () => {
    expect(
      outboundRuntimeIssue({
        tag: "vpn",
        type: "interface",
        status: "degraded",
        interfaces: [
          {
            outbound_tag: "vpn",
            status: "degraded",
            detail: "probe timed out",
          },
        ],
      })
    ).toEqual({
      code: "probeTimeout",
      memberTag: "vpn",
    })

    expect(
      outboundRuntimeIssue({
        tag: "vpn",
        type: "interface",
        status: "healthy",
        interfaces: [],
      })
    ).toBeUndefined()
  })

  test("reports the group and every failed member separately", () => {
    expect(
      outboundRuntimeIssues({
        tag: "vpn",
        type: "urltest",
        status: "degraded",
        detail: "live route selection differs from urltest manager selection",
        interfaces: [
          {
            outbound_tag: "primary",
            status: "unavailable",
            detail: "connection refused",
          },
          {
            outbound_tag: "backup",
            status: "degraded",
            detail: "opaque probe implementation text",
          },
        ],
      })
    ).toEqual([
      { code: "selectionMismatch" },
      { code: "connectionRefused", memberTag: "primary" },
      { code: "degraded", memberTag: "backup" },
    ])
  })
})
