import { afterEach, describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import { QueryClient } from "@tanstack/react-query"

import {
  getGetHealthServiceQueryKey,
  getGetRuntimeOutboundsQueryKey,
  getGetTransportsQueryKey,
} from "../src/api/generated/keen-api"
import type { RuntimeOutboundState } from "../src/api/generated/model"
import {
  mountRuntimeEventObserver,
  RUNTIME_EVENTS_QUERY_KEY,
  type RuntimeEventFeed,
} from "../src/api/runtime-event-observer"

const cleanup: Array<() => void> = []
afterEach(() => {
  while (cleanup.length) cleanup.pop()?.()
})

function setup() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Infinity } },
  })
  let timestamp = 1_700_000_000_000
  const observer = mountRuntimeEventObserver(client, () => ++timestamp)
  cleanup.push(() => {
    observer.dispose()
    client.clear()
  })
  const feed = () =>
    client.getQueryData<RuntimeEventFeed>(RUNTIME_EVENTS_QUERY_KEY)!
  const outbounds = (child: string, latency = 20) =>
    client.setQueryData(getGetRuntimeOutboundsQueryKey(), {
      status: 200,
      data: {
        outbounds: [
          {
            tag: "group",
            type: "urltest",
            status: "healthy",
            interfaces: [
              { outbound_tag: child, status: "active", latency_ms: latency },
            ],
          } satisfies RuntimeOutboundState,
        ],
      },
    })
  return { client, observer, feed, outbounds }
}

describe("runtime history observes existing query writes", () => {
  test("does not create a request or an event for the first snapshot", () => {
    const s = setup()
    expect(s.client.isFetching()).toBe(0)
    s.outbounds("first") // Before authenticated stream connection.
    expect(s.feed().ready).toBe(false)
    s.observer.setConnected(true)
    s.outbounds("first")
    expect(s.feed().ready).toBe(true)
    expect(s.feed().events).toEqual([])
    expect(s.client.isFetching()).toBe(0)
  })

  test("records a concrete selection once, but ignores probes and unrelated traffic", () => {
    const s = setup()
    s.observer.setConnected(true)
    s.outbounds("first")
    s.outbounds("second")
    expect(s.feed().events).toHaveLength(1)
    expect(s.feed().events[0]).toMatchObject({
      kind: "groupSwitched",
      tag: "group",
      from: "first",
      to: "second",
    })
    const events = s.feed().events
    s.outbounds("second", 95)
    s.client.setQueryData(["/api/runtime/interfaces"], { traffic: 9999 })
    expect(s.feed().events).toEqual(events)
    expect(s.feed().events[0].observedAt).toBeGreaterThan(1_700_000_000_000)
  })

  test("connection gaps and snapshot replay reset comparison but keep bounded history", () => {
    const s = setup()
    s.observer.setConnected(true)
    s.outbounds("a")
    s.outbounds("b")
    s.observer.setConnected(false)
    s.outbounds("c")
    s.observer.setConnected(true)
    s.observer.resetRuntimeBaseline()
    s.outbounds("d")
    expect(s.feed().events).toHaveLength(1)
    s.outbounds("e")
    expect(s.feed().events[0]).toMatchObject({ from: "d", to: "e" })
    for (let index = 0; index < 40; ++index) s.outbounds(`next-${index}`)
    expect(s.feed().events).toHaveLength(20)
    expect(new Set(s.feed().events.map((event) => event.id)).size).toBe(20)
  })

  test("a failed query does not become a route-loss or recovery event", async () => {
    const s = setup()
    s.observer.setConnected(true)
    s.outbounds("a")
    await s.client
      .fetchQuery({
        queryKey: getGetRuntimeOutboundsQueryKey(),
        queryFn: () => {
          throw new Error("offline")
        },
      })
      .catch(() => undefined)
    expect(s.feed().partial).toBe(true)
    s.outbounds("b")
    expect(s.feed().partial).toBe(false)
    expect(s.feed().events).toEqual([])
    s.outbounds("c")
    expect(s.feed().events[0]).toMatchObject({ from: "b", to: "c" })
  })

  test("missing service fields and a non-success transport response do not break cache writes", () => {
    const s = setup()
    s.observer.setConnected(true)
    expect(() =>
      s.client.setQueryData(getGetHealthServiceQueryKey(), {
        status: 200,
        data: { version: "old" },
      })
    ).not.toThrow()
    s.client.setQueryData(getGetTransportsQueryKey(), {
      status: 503,
      data: { error: "private detail" },
    })
    expect(s.feed().partial).toBe(true)
    expect(s.feed().events).toEqual([])
    expect(JSON.stringify(s.feed())).not.toContain("private detail")
  })

  test("logout releases the observer and session history, without clearing source queries", () => {
    const s = setup()
    s.observer.setConnected(true)
    s.outbounds("a")
    s.outbounds("b")
    s.observer.dispose()
    expect(s.client.getQueryData(RUNTIME_EVENTS_QUERY_KEY)).toBeUndefined()
    expect(
      s.client.getQueryData(getGetRuntimeOutboundsQueryKey())
    ).toBeDefined()
    s.outbounds("c")
    expect(s.client.getQueryData(RUNTIME_EVENTS_QUERY_KEY)).toBeUndefined()
    const again = mountRuntimeEventObserver(s.client)
    cleanup.push(() => again.dispose())
    expect(s.feed().events).toEqual([])
  })

  test("bridge owns one observer; feed does not add a poller or persistence", () => {
    const source = (path: string) =>
      readFileSync(new URL(path, import.meta.url), "utf8")
    const observer = source("../src/api/runtime-event-observer.ts")
    expect(observer).not.toMatch(
      /\b(?:fetch|setInterval|setTimeout|localStorage|sessionStorage|invalidateQueries|refetchQueries)\s*\(/
    )
    const bridge = source("../src/api/status-event-session.ts")
    expect(
      bridge.match(/mountRuntimeEventObserver\(queryClient\)/g)
    ).toHaveLength(1)
    expect(bridge).toContain(
      'if (eventName === "snapshot") runtimeEvents.resetRuntimeBaseline()'
    )
    expect(bridge).toContain("runtimeEvents.dispose()")
    const feed = source("../src/components/overview/runtime-events-feed.tsx")
    expect(feed).toContain("enabled: false")
    expect(feed).not.toContain("refetchInterval")
  })
})
