import { describe, expect, test } from "bun:test"

import type {
  Outbound,
  RouteRule,
  RuntimeOutboundState,
} from "@/api/generated/model"
import {
  activeTrafficStatusTranslationKey,
  collectActiveTrafficPaths,
  interfaceConnectionState,
} from "@/components/overview/active-interface-traffic-model"

describe("dashboard active interface traffic", () => {
  test("uses the dashboard namespace for member status labels", () => {
    expect(activeTrafficStatusTranslationKey("active")).toBe(
      "overview.outbounds.member.active"
    )
    expect(activeTrafficStatusTranslationKey("degraded")).toBe(
      "overview.outbounds.member.degraded"
    )
  })

  test("includes active and backup failover members and deduplicates rules", () => {
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
        outbound_groups: [{ weight: 1, outbounds: ["primary", "backup"] }],
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
      {
        interfaceName: "nwg1",
        label: "Основной",
        status: "backup",
      },
      {
        interfaceName: "nwg2",
        label: "Резервный",
        status: "active",
      },
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
      collectActiveTrafficPaths(outbounds, [{ outbound: "vpn" }], new Map())
    ).toEqual([{ interfaceName: "tun0", label: "VPN", status: "active" }])
  })

  test("recursively expands nested selectors and survives cycles", () => {
    const outbounds: Outbound[] = [
      {
        tag: "primary",
        display_name: "Primary",
        type: "interface",
        interface: "nwg1",
      },
      {
        tag: "backup",
        display_name: "Backup",
        type: "interface",
        interface: "nwg2",
      },
      {
        tag: "nested",
        type: "urltest",
        outbound_groups: [{ weight: 1, outbounds: ["primary", "root"] }],
      },
      {
        tag: "root",
        type: "urltest",
        outbound_groups: [{ weight: 1, outbounds: ["nested", "backup"] }],
      },
    ]
    const runtime = new Map<string, RuntimeOutboundState>([
      [
        "root",
        {
          tag: "root",
          type: "urltest",
          status: "healthy",
          interfaces: [
            {
              outbound_tag: "nested",
              interface_name: "nwg1",
              status: "active",
            },
            {
              outbound_tag: "backup",
              interface_name: "nwg2",
              status: "backup",
            },
          ],
        },
      ],
      [
        "nested",
        {
          tag: "nested",
          type: "urltest",
          status: "healthy",
          interfaces: [
            {
              outbound_tag: "primary",
              interface_name: "nwg1",
              status: "active",
            },
          ],
        },
      ],
    ])

    expect(
      collectActiveTrafficPaths(outbounds, [{ outbound: "root" }], runtime)
    ).toEqual([
      { interfaceName: "nwg1", label: "Primary", status: "active" },
      { interfaceName: "nwg2", label: "Backup", status: "backup" },
    ])
  })

  test("deduplicates a shared physical interface and keeps its active role", () => {
    const outbounds: Outbound[] = [
      {
        tag: "one",
        display_name: "One",
        type: "interface",
        interface: "tun0",
      },
      {
        tag: "two",
        display_name: "Two",
        type: "interface",
        interface: "tun0",
      },
      {
        tag: "group",
        type: "urltest",
        outbound_groups: [{ weight: 1, outbounds: ["one", "two"] }],
      },
    ]
    const runtime = new Map<string, RuntimeOutboundState>([
      [
        "group",
        {
          tag: "group",
          type: "urltest",
          status: "healthy",
          interfaces: [
            {
              outbound_tag: "one",
              interface_name: "tun0",
              status: "backup",
            },
            {
              outbound_tag: "two",
              interface_name: "tun0",
              status: "active",
            },
          ],
        },
      ],
    ])

    expect(
      collectActiveTrafficPaths(outbounds, [{ outbound: "group" }], runtime)
    ).toEqual([{ interfaceName: "tun0", label: "Two", status: "active" }])
  })

  test("does not use a transport observation time as connected-since", () => {
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
    ).toEqual({ connected: true })
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
    ).toEqual({ connected: false })
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
})
