import { describe, expect, test } from "bun:test"

import type {
  ConfigObject,
  Outbound,
  RuntimeOutboundState,
  TransportStatus,
} from "@/api/generated/model"
import {
  collectRequiredOutboundTags,
  countEnabledRouteRuleListsByOutbound,
  selectDashboardRuntimeOutbounds,
} from "@/components/overview/dashboard-outbound-relevance"

const tunnelOutbound: Outbound = {
  tag: "techcorner_vless",
  type: "interface",
  interface: "vless1",
}

const unavailableRuntime: RuntimeOutboundState = {
  tag: tunnelOutbound.tag,
  type: "interface",
  status: "unavailable",
  interfaces: [
    {
      outbound_tag: tunnelOutbound.tag,
      interface_name: tunnelOutbound.interface,
      status: "unavailable",
      detail: "no available outbound",
    },
  ],
}

const stoppedTransport: TransportStatus = {
  tag: tunnelOutbound.tag,
  type: "sing-box",
  interface: tunnelOutbound.interface ?? "",
  state: "down",
  updated_at: "2026-08-08T12:00:00Z",
  desired_up: false,
}

function select(
  config: ConfigObject,
  transports: readonly TransportStatus[] = [stoppedTransport]
) {
  return selectDashboardRuntimeOutbounds({
    config,
    runtimeOutbounds: [unavailableRuntime],
    transports,
  })
}

describe("dashboard outbound relevance", () => {
  test("suppresses a stopped managed transport that has no active dependency", () => {
    expect(select({ outbounds: [tunnelOutbound] })).toEqual([])
  })

  test("a disabled route neither uses nor protects the stopped outbound", () => {
    const config: ConfigObject = {
      outbounds: [tunnelOutbound],
      route: {
        rules: [
          {
            enabled: false,
            outbound: tunnelOutbound.tag,
            list: ["instagram", "meta"],
          },
        ],
      },
    }

    expect(select(config)).toEqual([])
    expect(
      countEnabledRouteRuleListsByOutbound(config.route?.rules ?? [])
    ).toEqual(new Map())
  })

  test("keeps the failure when an enabled route uses the stopped transport", () => {
    const config: ConfigObject = {
      outbounds: [tunnelOutbound],
      route: {
        rules: [
          {
            enabled: true,
            outbound: tunnelOutbound.tag,
            list: ["instagram"],
          },
        ],
      },
    }

    expect(select(config)).toEqual([unavailableRuntime])
    expect(
      countEnabledRouteRuleListsByOutbound(config.route?.rules ?? [])
    ).toEqual(new Map([[tunnelOutbound.tag, 1]]))
  })

  test("keeps active DNS and list-refresh detour failures truthful", () => {
    const dnsConfig: ConfigObject = {
      outbounds: [tunnelOutbound],
      dns: {
        servers: [
          { tag: "dns_vpn", address: "8.8.8.8", detour: tunnelOutbound.tag },
        ],
        rules: [{ enabled: true, list: ["instagram"], server: "dns_vpn" }],
      },
    }
    expect(select(dnsConfig)).toEqual([unavailableRuntime])

    const refreshConfig: ConfigObject = {
      outbounds: [tunnelOutbound],
      lists: {
        instagram: {
          url: "https://example.invalid/instagram.srs",
          refresh_detour_mode: "inherit",
        },
      },
      list_refresh: { detour: tunnelOutbound.tag },
    }
    expect(select(refreshConfig)).toEqual([unavailableRuntime])
  })

  test("expands an active failover dependency to its stopped child", () => {
    const group: Outbound = {
      tag: "vless_group",
      type: "urltest",
      outbound_groups: [{ weight: 1, outbounds: [tunnelOutbound.tag] }],
    }
    const config: ConfigObject = {
      outbounds: [group, tunnelOutbound],
      route: { rules: [{ outbound: group.tag, list: ["instagram"] }] },
    }

    expect(collectRequiredOutboundTags(config)).toEqual(
      new Set([group.tag, tunnelOutbound.tag])
    )
    expect(select(config)).toEqual([unavailableRuntime])
  })

  test("does not hide native or expected-running failures", () => {
    expect(
      select({ outbounds: [tunnelOutbound] }, [
        { ...stoppedTransport, type: "native" },
      ])
    ).toEqual([unavailableRuntime])
    expect(
      select({ outbounds: [tunnelOutbound] }, [
        { ...stoppedTransport, desired_up: true },
      ])
    ).toEqual([unavailableRuntime])
  })

  test("stays conservative while config or transport inventory is missing", () => {
    expect(
      selectDashboardRuntimeOutbounds({
        runtimeOutbounds: [unavailableRuntime],
        transports: [stoppedTransport],
      })
    ).toEqual([unavailableRuntime])
    expect(
      selectDashboardRuntimeOutbounds({
        config: { outbounds: [tunnelOutbound] },
        runtimeOutbounds: [unavailableRuntime],
      })
    ).toEqual([unavailableRuntime])
  })
})
