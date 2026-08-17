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
    ).toEqual({ code: "selectionMismatch", tone: "error" })

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
    ).toEqual({
      code: "interfaceUnreachable",
      memberTag: "vpn",
      tone: "error",
    })
  })

  // Older daemons used the same detail for a probe that had not run, a stale
  // result and a genuinely unbound result. Do not turn that ambiguity into a
  // red tunnel failure or claim that binding itself failed.
  test("surfaces legacy unknown probe state as a non-destructive pending check", () => {
    expect(
      outboundRuntimeIssue({
        tag: "dead_tunnel",
        type: "interface",
        status: "unknown",
        interfaces: [
          {
            outbound_tag: "dead_tunnel",
            status: "unknown",
            detail:
              "cannot verify: no attributable probe result for this outbound",
          },
        ],
      })
    ).toEqual({
      code: "verificationPending",
      memberTag: "dead_tunnel",
      tone: "warning",
    })
  })

  // The daemon reports UNKNOWN for shapes it never probes at all: a table
  // outbound whose externally managed table holds no default, or a group with
  // no resolvable members. Announcing "not checked yet" there would be
  // permanently false, because nothing will ever check them.
  test("stays silent on an unknown outbound that was never a probe target", () => {
    expect(
      outboundRuntimeIssues({
        tag: "wan",
        type: "table",
        status: "unknown",
        interfaces: [],
      })
    ).toEqual([])

    expect(
      outboundRuntimeIssues({
        tag: "empty_group",
        type: "urltest",
        status: "unknown",
        interfaces: [],
      })
    ).toEqual([])
  })

  test("still reports an unknown member the daemon could not verify", () => {
    expect(
      outboundRuntimeIssue({
        tag: "dead_tunnel",
        type: "interface",
        status: "unknown",
        interfaces: [
          {
            outbound_tag: "dead_tunnel",
            status: "unknown",
            detail: "some detail the UI vocabulary does not recognise",
          },
        ],
      })
    ).toEqual({
      code: "verificationPending",
      memberTag: "dead_tunnel",
      tone: "warning",
    })
  })

  test("uses binding-specific wording only for an explicitly unattributed probe", () => {
    expect(
      outboundRuntimeIssue({
        tag: "tunnel",
        type: "interface",
        status: "unknown",
        interfaces: [
          {
            outbound_tag: "tunnel",
            status: "unknown",
            detail: "probe result is unattributed",
          },
        ],
      })
    ).toEqual({
      code: "cannotVerify",
      memberTag: "tunnel",
      tone: "warning",
    })

    expect(
      outboundRuntimeIssue({
        tag: "tunnel",
        type: "interface",
        status: "unknown",
        interfaces: [
          {
            outbound_tag: "tunnel",
            status: "unknown",
            detail: "probe result is stale",
          },
        ],
      })
    ).toEqual({
      code: "verificationStale",
      memberTag: "tunnel",
      tone: "warning",
    })
  })

  test("keeps a verified healthy outbound free of issues", () => {
    expect(
      outboundRuntimeIssues({
        tag: "live_tunnel",
        type: "interface",
        status: "healthy",
        interfaces: [
          { outbound_tag: "live_tunnel", status: "active", latency_ms: 84 },
        ],
      })
    ).toEqual([])
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
      tone: "error",
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
      { code: "selectionMismatch", tone: "error" },
      { code: "connectionRefused", memberTag: "primary", tone: "error" },
      { code: "degraded", memberTag: "backup", tone: "error" },
    ])
  })
})
