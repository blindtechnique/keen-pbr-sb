import { describe, expect, test } from "bun:test"

import type {
  ConfigObject,
  Outbound,
  RuntimeOutboundState,
  TransportStatus,
} from "@/api/generated/model"
import {
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

function select(transports: readonly TransportStatus[] = [stoppedTransport]) {
  return selectDashboardRuntimeOutbounds({
    runtimeOutbounds: [unavailableRuntime],
    transports,
  })
}

describe("dashboard outbound relevance", () => {
  test("suppresses an intentionally stopped managed transport", () => {
    expect(select()).toEqual([])
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

    expect(select()).toEqual([])
    expect(
      countEnabledRouteRuleListsByOutbound(config.route?.rules ?? [])
    ).toEqual(new Map())
  })

  test("an explicit manual stop stays neutral when a route still references it", () => {
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

    expect(select()).toEqual([])
    expect(
      countEnabledRouteRuleListsByOutbound(config.route?.rules ?? [])
    ).toEqual(new Map([[tunnelOutbound.tag, 1]]))
  })

  test("does not hide native or expected-running failures", () => {
    expect(select([{ ...stoppedTransport, type: "native" }])).toEqual([
      unavailableRuntime,
    ])
    expect(select([{ ...stoppedTransport, desired_up: true }])).toEqual([
      unavailableRuntime,
    ])
  })

  test("keeps a selector visible while any matching managed child is expected up", () => {
    const selectorRuntime: RuntimeOutboundState = {
      tag: "vless_group",
      type: "urltest",
      status: "degraded",
      interfaces: [
        {
          outbound_tag: tunnelOutbound.tag,
          interface_name: tunnelOutbound.interface,
          status: "unavailable",
        },
        {
          outbound_tag: "backup_vless",
          interface_name: "vless2",
          status: "active",
        },
      ],
    }
    const runningBackup: TransportStatus = {
      ...stoppedTransport,
      tag: "backup_vless",
      interface: "vless2",
      state: "up",
      desired_up: true,
    }

    expect(
      selectDashboardRuntimeOutbounds({
        runtimeOutbounds: [selectorRuntime],
        transports: [stoppedTransport, runningBackup],
      })
    ).toEqual([selectorRuntime])
  })

  test("keeps a mixed selector visible when its native child is failing", () => {
    const selectorRuntime: RuntimeOutboundState = {
      tag: "mixed_group",
      type: "urltest",
      status: "degraded",
      interfaces: [
        {
          outbound_tag: tunnelOutbound.tag,
          interface_name: tunnelOutbound.interface,
          status: "unavailable",
        },
        {
          outbound_tag: "native_awg",
          interface_name: "nwg7",
          status: "unavailable",
        },
      ],
    }
    const failingNative: TransportStatus = {
      ...stoppedTransport,
      tag: "native_awg",
      type: "native",
      interface: "nwg7",
      desired_up: false,
    }

    expect(
      selectDashboardRuntimeOutbounds({
        runtimeOutbounds: [selectorRuntime],
        transports: [stoppedTransport, failingNative],
      })
    ).toEqual([selectorRuntime])
  })

  test("manual intent remains authoritative during a draft or failed apply", () => {
    expect(
      selectDashboardRuntimeOutbounds({
        runtimeOutbounds: [unavailableRuntime],
        transports: [stoppedTransport],
      })
    ).toEqual([])
  })

  test("stays conservative while transport inventory is missing", () => {
    expect(
      selectDashboardRuntimeOutbounds({
        runtimeOutbounds: [unavailableRuntime],
      })
    ).toEqual([unavailableRuntime])
  })
})
