import { describe, expect, test } from "bun:test"

import type {
  Outbound,
  RouteRule,
  RuntimeOutboundState,
} from "@/api/generated/model"
import {
  collectActiveTrafficPaths,
  formatConnectionDuration,
  interfaceConnectionState,
} from "@/components/overview/active-interface-traffic-model"

describe("dashboard active interface traffic", () => {
  test("uses the selected failover member and deduplicates shared interfaces", () => {
    const outbounds: Outbound[] = [
      {
        tag: "primary",
        display_name: "Основной",
        type: "interface",
        interface: "nwg1",
      },
      {
        tag: "backup",
        display_name: "Резервный",
        type: "interface",
        interface: "nwg2",
      },
      {
        tag: "failover",
        display_name: "Рабочий маршрут",
        type: "urltest",
        outbound_groups: [
          { weight: 1, outbounds: ["primary", "backup"] },
        ],
      },
    ]
    const rules: RouteRule[] = [
      { outbound: "failover" },
      { outbound: "failover" },
    ]
    const runtime = new Map<string, RuntimeOutboundState>([
      [
        "failover",
        {
          tag: "failover",
          type: "urltest",
          status: "healthy",
          interfaces: [
            {
              outbound_tag: "primary",
              interface_name: "nwg1",
              status: "backup",
            },
            {
              outbound_tag: "backup",
              interface_name: "nwg2",
              status: "active",
            },
          ],
        },
      ],
    ])

    expect(collectActiveTrafficPaths(outbounds, rules, runtime)).toEqual([
      { interfaceName: "nwg2", label: "Резервный" },
    ])
  })

  test("falls back to the configured interface before runtime arrives", () => {
    const outbounds: Outbound[] = [
      {
        tag: "vpn",
        display_name: "VPN",
        type: "interface",
        interface: "tun0",
      },
    ]

    expect(
      collectActiveTrafficPaths(
        outbounds,
        [{ outbound: "vpn" }],
        new Map()
      )
    ).toEqual([{ interfaceName: "tun0", label: "VPN" }])
  })

  test("uses the managed transport state transition as connected-since time", () => {
    expect(
      interfaceConnectionState("vless0", true, [
        {
          tag: "vless",
          display_name: "Основной VLESS",
          type: "sing-box",
          interface: "vless0",
          state: "up",
          updated_at: "2026-07-27T10:00:00Z",
          desired_up: true,
        },
      ])
    ).toEqual({
      connected: true,
      connectedAtUnixMs: Date.parse("2026-07-27T10:00:00Z"),
    })
  })

  test("does not claim an old uptime for a down managed transport", () => {
    expect(
      interfaceConnectionState("vless0", true, [
        {
          tag: "vless",
          type: "sing-box",
          interface: "vless0",
          state: "down",
          updated_at: "2026-07-27T10:00:00Z",
          desired_up: false,
        },
      ])
    ).toEqual({ connected: false, connectedAtUnixMs: undefined })
  })

  test("does not treat a native status refresh as its connection start", () => {
    expect(
      interfaceConnectionState("nwg2", true, [
        {
          tag: "native_nwg2",
          type: "native",
          interface: "nwg2",
          state: "up",
          updated_at: "2026-07-27T10:00:00Z",
          desired_up: false,
        },
      ])
    ).toEqual({ connected: true })
  })

  test("formats the compact Keenetic-style elapsed time", () => {
    expect(
      formatConnectionDuration(3 * 86_400 + 3 * 3_600 + 14 * 60 + 10, "д.")
    ).toBe("3 д. 03:14:10")
    expect(formatConnectionDuration(65, "d")).toBe("00:01:05")
  })
})
