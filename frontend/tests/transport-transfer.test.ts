import { describe, expect, spyOn, test } from "bun:test"
import { readFileSync } from "node:fs"
import {
  MutationObserver,
  QueryClient,
  QueryObserver,
} from "@tanstack/react-query"

import { getGetTransportConfigQueryOptions } from "../src/api/generated/keen-api"
import type {
  TransportConfigOperation,
  TransportSpec,
} from "../src/api/generated/model"
import {
  importTransportDefinitions,
  refreshTransportTransferInventory,
} from "../src/api/transport-transfer"
import { queryKeys } from "../src/api/query-keys"

const page = readFileSync(
  new URL("../src/pages/transports-page.tsx", import.meta.url),
  "utf8"
)
const transport = (tag: string): TransportSpec => ({
  type: "sing-box",
  tag,
  interface: `kpbr${tag}`,
  auto_start: false,
  link: "trojan://password@example.invalid:443",
})

describe("transport file transfer partial failure", () => {
  test("the page awaits inventory refresh on settlement, including errors", () => {
    const transfer = page.slice(
      page.indexOf("const transferMutation = useMutation("),
      page.indexOf("const exportTransports = async")
    )
    expect(transfer).toContain("await importTransportDefinitions(")
    expect(transfer).toMatch(
      /onSettled: async \(\) => \{[\s\S]*await refreshTransportTransferInventory\(queryClient\)/
    )
  })

  test("a failed second entry refreshes configured tags before the retry", async () => {
    const durable = new Map<string, TransportSpec>()
    const writes: string[] = []
    let rejectSecond = true
    const fetchSpy = spyOn(globalThis, "fetch").mockImplementation(
      async (url, options) => {
        expect(String(url)).toBe("/api/transports/config")
        if (options?.method !== "POST")
          return Response.json([...durable.values()])
        const request = JSON.parse(
          String(options.body)
        ) as TransportConfigOperation
        const spec = request.transport!
        writes.push(`${request.operation}:${spec.tag}`)
        if (spec.tag === "second" && rejectSecond) {
          return Response.json(
            { error: "invalid second transport" },
            { status: 400 }
          )
        }
        if (request.operation === "create" && durable.has(spec.tag)) {
          return Response.json({ error: "already exists" }, { status: 409 })
        }
        durable.set(spec.tag, spec)
        return Response.json({ status: "saved", tag: spec.tag })
      }
    )
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    const inventory = new QueryObserver(
      client,
      getGetTransportConfigQueryOptions()
    )
    const unsubscribe = inventory.subscribe(() => undefined)
    const transfer = new MutationObserver(client, {
      mutationFn: (specs: TransportSpec[]) => {
        const response = inventory.getCurrentResult().data
        const configured = response?.status === 200 ? response.data : []
        return importTransportDefinitions(
          specs,
          new Set(configured.map((item) => item.tag)),
          true
        )
      },
      onSettled: () => refreshTransportTransferInventory(client),
    })
    try {
      await inventory.refetch()
      await expect(
        transfer.mutate([transport("first"), transport("second")])
      ).rejects.toMatchObject({ status: 400 })
      expect([...durable.keys()]).toEqual(["first"])
      expect(client.getQueryData(queryKeys.transportConfig())).toMatchObject({
        data: [{ tag: "first" }],
      })
      expect(transfer.getCurrentResult().isPending).toBe(false)

      rejectSecond = false
      await transfer.mutate([transport("first"), transport("second")])
      expect(writes).toEqual([
        "create:first",
        "create:second",
        "update:first",
        "create:second",
      ])
      expect([...durable.keys()]).toEqual(["first", "second"])
      expect(inventory.getCurrentResult().data?.data).toHaveLength(2)
    } finally {
      unsubscribe()
      client.clear()
      fetchSpy.mockRestore()
    }
  })
})
