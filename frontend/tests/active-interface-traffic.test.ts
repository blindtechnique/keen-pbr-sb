import { describe, expect, test } from "bun:test"

import type {
  Outbound,
  RouteRule,
  RuntimeOutboundState,
} from "@/api/generated/model"
import { collectActiveTrafficPaths } from "@/components/overview/active-interface-traffic-model"

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
})
