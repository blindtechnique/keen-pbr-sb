import { describe, expect, test } from "bun:test"
import { QueryClient } from "@tanstack/react-query"

import {
  getGetHealthServiceQueryKey,
  getGetRuntimeInterfacesQueryKey,
  getGetRuntimeOutboundsQueryKey,
  type getRuntimeInterfacesResponseSuccess,
} from "../src/api/generated/keen-api"
import {
  applyInterfaceTrafficUpdate,
  applyStatusEvent,
  getTerminalConfigLifecycleOperationKey,
} from "../src/api/status-event-cache"
import type { RuntimeInterfaceInventoryResponse } from "../src/api/generated/model"

const service = (version: string) => ({ version })
const outbounds = (tag: string) => ({ outbounds: [{ tag }] })
const interfaces = (name: string) => ({ interfaces: [{ name }] })

describe("status event cache bridge", () => {
  test("snapshot hydrates and later snapshots resynchronize every dataset", () => {
    const client = new QueryClient()
    expect(
      applyStatusEvent(
        client,
        JSON.stringify({
          type: "snapshot",
          data: {
            service: service("1"),
            outbounds: outbounds("wan"),
            interfaces: interfaces("eth0"),
          },
        })
      )
    ).toBe(true)
    applyStatusEvent(
      client,
      JSON.stringify({
        type: "snapshot",
        data: {
          service: service("2"),
          outbounds: outbounds("vpn"),
          interfaces: interfaces("tun0"),
        },
      })
    )
    expect(client.getQueryData(getGetHealthServiceQueryKey())).toMatchObject({
      data: { version: "2" },
      status: 200,
    })
    expect(client.getQueryData(getGetRuntimeOutboundsQueryKey())).toMatchObject(
      {
        data: { outbounds: [{ tag: "vpn" }] },
      }
    )
    expect(
      client.getQueryData(getGetRuntimeInterfacesQueryKey())
    ).toMatchObject({
      data: { interfaces: [{ name: "tun0" }] },
    })
  })

  test("named events replace only their dataset and malformed data is ignored", () => {
    const client = new QueryClient()
    applyStatusEvent(
      client,
      JSON.stringify({
        type: "snapshot",
        data: {
          service: service("1"),
          outbounds: outbounds("wan"),
          interfaces: interfaces("eth0"),
        },
      })
    )
    const interfacesBefore = client.getQueryData(
      getGetRuntimeInterfacesQueryKey()
    )
    expect(
      applyStatusEvent(
        client,
        JSON.stringify({ type: "outbounds", data: outbounds("vpn") })
      )
    ).toBe(true)
    expect(client.getQueryData(getGetRuntimeInterfacesQueryKey())).toBe(
      interfacesBefore
    )
    expect(applyStatusEvent(client, "not json")).toBe(false)
  })

  test("connection revisions invalidate only connection queries", () => {
    const client = new QueryClient()
    const connectionKey = ["connections", "active", ""]
    const unrelatedKey = ["catalog"]
    client.setQueryData(connectionKey, { pages: [] })
    client.setQueryData(unrelatedKey, { items: [] })

    expect(
      applyStatusEvent(
        client,
        JSON.stringify({
          type: "connections",
          data: { revision: 42, changed_at: 1234, available: true },
        })
      )
    ).toBe(true)
    expect(client.getQueryState(connectionKey)?.isInvalidated).toBe(true)
    expect(client.getQueryState(unrelatedKey)?.isInvalidated).toBe(false)
  })

  test("compact traffic events append only the matching interface", () => {
    const client = new QueryClient()
    applyStatusEvent(
      client,
      JSON.stringify({
        type: "snapshot",
        data: {
          service: service("1"),
          outbounds: outbounds("vpn"),
          interfaces: {
            interfaces: [
              {
                name: "tun0",
                status: "up",
                traffic: {
                  sampled_at_unix_ms: 1_000,
                  rx_bytes: 100,
                  tx_bytes: 200,
                  history: [
                    {
                      age_ms: 0,
                      rx_bits_per_second: 10,
                      tx_bits_per_second: 20,
                    },
                  ],
                },
              },
              { name: "eth0", status: "up" },
            ],
          },
        },
      })
    )

    expect(
      applyStatusEvent(
        client,
        JSON.stringify({
          type: "interface_traffic",
          data: {
            sampled_at_unix_ms: 3_000,
            interfaces: [
              {
                name: "tun0",
                available: true,
                reset: false,
                rx_bytes: 130,
                tx_bytes: 260,
                rx_bits_per_second: 120,
                tx_bits_per_second: 240,
              },
            ],
          },
        })
      )
    ).toBe(true)

    const cached = client.getQueryData<getRuntimeInterfacesResponseSuccess>(
      getGetRuntimeInterfacesQueryKey()
    )
    expect(cached?.data.interfaces[0]?.traffic).toMatchObject({
      sampled_at_unix_ms: 3_000,
      rx_bytes: 130,
      tx_bytes: 260,
      history: [
        {
          age_ms: 2_000,
          rx_bits_per_second: 10,
          tx_bits_per_second: 20,
        },
        {
          age_ms: 0,
          rx_bits_per_second: 120,
          tx_bits_per_second: 240,
        },
      ],
    })
    expect(cached?.data.interfaces[1]).toEqual({
      name: "eth0",
      status: "up",
    })
  })

  test("counter resets and unavailable interfaces start clean graph segments", () => {
    const inventory: RuntimeInterfaceInventoryResponse = {
      interfaces: [
        {
          name: "tun0",
          status: "up",
          traffic: {
            sampled_at_unix_ms: 1_000,
            rx_bytes: 100,
            tx_bytes: 200,
            history: [
              {
                age_ms: 0,
                rx_bits_per_second: 10,
                tx_bits_per_second: 20,
              },
            ],
          },
        },
      ],
    }

    const reset = applyInterfaceTrafficUpdate(inventory, {
      sampled_at_unix_ms: 3_000,
      interfaces: [
        {
          name: "tun0",
          available: true,
          reset: true,
          rx_bytes: 2,
          tx_bytes: 3,
        },
      ],
    })
    expect(reset.interfaces[0]?.traffic?.history).toEqual([
      {
        age_ms: 0,
        rx_bits_per_second: 0,
        tx_bits_per_second: 0,
      },
    ])

    const unavailable = applyInterfaceTrafficUpdate(reset, {
      sampled_at_unix_ms: 5_000,
      interfaces: [
        {
          name: "tun0",
          available: false,
          reset: false,
        },
      ],
    })
    expect(unavailable.interfaces[0]?.traffic).toBeUndefined()
  })

  test("traffic before the first snapshot is discarded and reconnect hydrates fresh cache", () => {
    const client = new QueryClient()
    expect(
      applyStatusEvent(
        client,
        JSON.stringify({
          type: "interface_traffic",
          data: {
            sampled_at_unix_ms: 1_000,
            interfaces: [
              {
                name: "stale0",
                available: true,
                reset: false,
                rx_bytes: 10,
                tx_bytes: 20,
              },
            ],
          },
        })
      )
    ).toBe(true)
    expect(
      client.getQueryData(getGetRuntimeInterfacesQueryKey())
    ).toBeUndefined()

    applyStatusEvent(
      client,
      JSON.stringify({
        type: "snapshot",
        data: {
          service: service("2"),
          outbounds: outbounds("vpn"),
          interfaces: {
            interfaces: [
              {
                name: "tun0",
                status: "up",
                traffic: {
                  sampled_at_unix_ms: 5_000,
                  rx_bytes: 500,
                  tx_bytes: 600,
                  history: [],
                },
              },
            ],
          },
        },
      })
    )

    expect(
      client.getQueryData(getGetRuntimeInterfacesQueryKey())
    ).toMatchObject({
      data: {
        interfaces: [
          {
            name: "tun0",
            traffic: {
              sampled_at_unix_ms: 5_000,
              rx_bytes: 500,
              tx_bytes: 600,
            },
          },
        ],
      },
    })
  })

  test("only terminal config lifecycle events request a config resync", () => {
    expect(
      getTerminalConfigLifecycleOperationKey(
        JSON.stringify({
          type: "service",
          data: {
            lifecycle_operation: {
              id: "apply-1",
              type: "apply_config",
              status: "running",
            },
          },
        })
      )
    ).toBeNull()

    expect(
      getTerminalConfigLifecycleOperationKey(
        JSON.stringify({
          type: "service",
          data: {
            lifecycle_operation: {
              id: "start-1",
              type: "start",
              status: "succeeded",
            },
          },
        })
      )
    ).toBeNull()

    expect(
      getTerminalConfigLifecycleOperationKey(
        JSON.stringify({
          type: "service",
          data: {
            lifecycle_operation: {
              id: "apply-1",
              type: "apply_config",
              status: "succeeded",
            },
          },
        })
      )
    ).toBe("apply-1:succeeded")

    expect(
      getTerminalConfigLifecycleOperationKey(
        JSON.stringify({
          type: "snapshot",
          data: {
            service: {
              lifecycle_operation: {
                id: "rollback-1",
                type: "rollback_config",
                status: "failed",
              },
            },
            outbounds: {},
            interfaces: {},
          },
        })
      )
    ).toBe("rollback-1:failed")
  })
})
