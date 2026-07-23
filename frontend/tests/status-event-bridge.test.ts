import { describe, expect, test } from "bun:test"
import { QueryClient } from "@tanstack/react-query"

import {
  getGetHealthServiceQueryKey,
  getGetRuntimeInterfacesQueryKey,
  getGetRuntimeOutboundsQueryKey,
} from "../src/api/generated/keen-api"
import { applyStatusEvent } from "../src/api/status-event-cache"

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
    expect(client.getQueryData(getGetRuntimeOutboundsQueryKey())).toMatchObject({
      data: { outbounds: [{ tag: "vpn" }] },
    })
    expect(client.getQueryData(getGetRuntimeInterfacesQueryKey())).toMatchObject({
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
})
