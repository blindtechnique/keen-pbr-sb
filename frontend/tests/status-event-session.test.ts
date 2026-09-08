import { afterEach, describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import { QueryClient, QueryObserver } from "@tanstack/react-query"
import ts from "typescript"

import {
  getGetHealthServiceQueryKey,
  getGetRuntimeInterfacesQueryKey,
  getGetRuntimeOutboundsQueryKey,
  type getRuntimeInterfacesResponseSuccess,
  type getRuntimeOutboundsResponseSuccess,
} from "../src/api/generated/keen-api"
import { NOTIFICATION_STATE_QUERY_KEY } from "../src/api/notification-events"
import { resetRouterClock } from "../src/api/router-clock"
import { ROUTER_INFO_QUERY_KEY } from "../src/api/router-info-events"
import { getStatusEventConnectionState } from "../src/api/status-event-connection"
import { mountStatusEventSession } from "../src/api/status-event-session"
import { SUBSCRIPTION_CHANGE_QUERY_KEYS } from "../src/api/subscription-events"
import { collectActiveTrafficPaths } from "../src/components/overview/active-interface-traffic-model"
import { collectRouteTrafficShares } from "../src/components/overview/route-traffic-share-model"
import { buildTrafficSeries } from "../src/components/transports/interface-traffic-model"

const cleanupTasks: Array<() => void> = []

afterEach(() => {
  while (cleanupTasks.length > 0) cleanupTasks.pop()?.()
  resetRouterClock()
})

function browserSession() {
  let authenticated = false
  const sources: FakeEventSource[] = []
  const intervals = new Map<number, () => void>()
  const timeouts = new Map<number, { callback: () => void; delay: number }>()
  let timerId = 0
  const visibilityListeners = new Set<() => void>()
  const document = {
    visibilityState: "visible",
    addEventListener: (_: string, callback: () => void) =>
      visibilityListeners.add(callback),
    removeEventListener: (_: string, callback: () => void) =>
      visibilityListeners.delete(callback),
  }

  class FakeEventSource {
    readonly url: string
    readonly wasAuthenticated: boolean
    closed = false
    onopen: (() => void) | null = null
    onerror: (() => void) | null = null
    listeners = new Map<string, (event: { data: string }) => void>()

    constructor(url: string) {
      this.url = url
      this.wasAuthenticated = authenticated
      // A pre-login 401 permanently fails this EventSource; changing a cookie
      // does not restart it. Only a fresh authenticated mount can connect.
      this.closed = !authenticated
      sources.push(this)
    }

    addEventListener(
      name: string,
      listener: (event: { data: string }) => void
    ) {
      this.listeners.set(name, listener)
    }

    close() {
      this.closed = true
    }

    open() {
      if (!this.closed) this.onopen?.()
    }

    emit(type: string, data: unknown) {
      if (!this.closed) {
        this.listeners.get(type)?.({ data: JSON.stringify({ type, data }) })
      }
    }
  }

  const globals = {
    EventSource: FakeEventSource,
    document,
    setInterval: (callback: () => void) => {
      intervals.set(++timerId, callback)
      return timerId
    },
    clearInterval: (id: number) => intervals.delete(id),
    setTimeout: (callback: () => void, delay: number) => {
      timeouts.set(++timerId, { callback, delay })
      return timerId
    },
    clearTimeout: (id: number) => timeouts.delete(id),
  }
  for (const [key, value] of Object.entries(globals)) {
    const original = Object.getOwnPropertyDescriptor(globalThis, key)
    Object.defineProperty(globalThis, key, { configurable: true, value })
    cleanupTasks.push(() => {
      if (original) Object.defineProperty(globalThis, key, original)
      else Reflect.deleteProperty(globalThis, key)
    })
  }
  const client = new QueryClient({
    defaultOptions: { queries: { gcTime: Infinity, retry: false } },
  })
  let unmount: (() => void) | undefined
  cleanupTasks.push(() => {
    unmount?.()
    client.clear()
  })
  return {
    client,
    sources,
    intervals,
    timeouts,
    visibilityListeners,
    // The same mount/unmount used by the real bridge inside AuthGate, without
    // a second auth store or a test-only production networking path.
    renderAuthenticatedSubtree(nextAuthenticated: boolean) {
      authenticated = nextAuthenticated
      if (authenticated && !unmount) {
        unmount = mountStatusEventSession(client, { current: null })
      } else if (!authenticated && unmount) {
        unmount()
        unmount = undefined
      }
    },
    visibility(state: "visible" | "hidden") {
      document.visibilityState = state
      for (const callback of visibilityListeners) callback()
    },
  }
}

function snapshot(name = "nwg0") {
  return {
    service: { version: "test" },
    outbounds: {
      outbounds: [
        { tag: "vpn", type: "interface", status: "healthy", interfaces: [] },
      ],
    },
    interfaces: { interfaces: [{ name, status: "up" }] },
  }
}

function traffic(sampledAt: number, rx: number, tx: number) {
  return {
    sampled_at_unix_ms: sampledAt,
    interfaces: [
      {
        name: "nwg0",
        available: true,
        reset: false,
        rx_bytes: rx,
        tx_bytes: tx,
        rx_bits_per_second: 800,
        tx_bits_per_second: 400,
      },
    ],
  }
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: Error) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

function restResponse(data: unknown) {
  return { status: 200 as const, data, headers: new Headers() }
}

function observeDelayedBaseline(
  client: QueryClient,
  queryKey: readonly string[]
) {
  const requests: Array<{
    signal: AbortSignal
    response: ReturnType<typeof deferred<ReturnType<typeof restResponse>>>
  }> = []
  const observer = new QueryObserver(client, {
    queryKey,
    staleTime: Infinity,
    queryFn: ({ signal }) => {
      const response = deferred<ReturnType<typeof restResponse>>()
      requests.push({ signal, response })
      // Intentionally keep the transport promise alive after abort: the old
      // success/error may already be queued outside React Query's control.
      return response.promise
    },
  })
  const unsubscribe = observer.subscribe(() => {})
  cleanupTasks.push(unsubscribe)
  return requests
}

async function flushQueryMicrotasks() {
  // onopen invalidates three keys before refetching. Let that real chain and
  // the retryer/cancellation continuations settle without a timing sleep.
  for (let index = 0; index < 30; index += 1) await Promise.resolve()
}

const runtimeBaselineCases = [
  ["service", getGetHealthServiceQueryKey(), { version: "old" }],
  ["outbounds", getGetRuntimeOutboundsQueryKey(), { outbounds: [] }],
  ["interfaces", getGetRuntimeInterfacesQueryKey(), { interfaces: [] }],
] as const

describe("authenticated status stream lifecycle", () => {
  test("the one application bridge belongs to AuthGate, not the login bootstrap", () => {
    const findBridges = (file: string) => {
      const source = ts.createSourceFile(
        file,
        readFileSync(new URL(file, import.meta.url), "utf8"),
        ts.ScriptTarget.Latest,
        true,
        ts.ScriptKind.TSX
      )
      const gated: boolean[] = []
      const visit = (node: ts.Node, insideGate = false) => {
        const gate =
          insideGate ||
          (ts.isJsxElement(node) &&
            node.openingElement.tagName.getText(source) === "AuthGate")
        if (
          ts.isJsxSelfClosingElement(node) &&
          node.tagName.getText(source) === "StatusEventBridge"
        ) {
          gated.push(gate)
        }
        node.forEachChild((child) => visit(child, gate))
      }
      visit(source)
      return gated
    }
    expect(findBridges("../src/main.tsx")).toEqual([])
    expect(findBridges("../src/App.tsx")).toEqual([true])
  })

  test("cold login starts the first stream and fills both traffic-card models without reload", () => {
    const session = browserSession()
    session.renderAuthenticatedSubtree(false)
    expect(session.sources).toHaveLength(0)
    expect(session.intervals.size).toBe(0)

    session.renderAuthenticatedSubtree(true)
    const source = session.sources[0]
    expect(source.wasAuthenticated).toBe(true)
    expect(source.url).toBe("/api/status/events")
    source.open()
    source.emit("snapshot", snapshot())
    source.emit("interface_traffic", traffic(2_000, 100, 200))
    source.emit("interface_traffic", traffic(4_000, 300, 400))

    const inventory =
      session.client.getQueryData<getRuntimeInterfacesResponseSuccess>(
        getGetRuntimeInterfacesQueryKey()
      )!
    const runtime =
      session.client.getQueryData<getRuntimeOutboundsResponseSuccess>(
        getGetRuntimeOutboundsQueryKey()
      )!
    const byName = new Map(
      inventory.data.interfaces.map((entry) => [entry.name, entry])
    )
    const paths = collectActiveTrafficPaths(
      [
        {
          tag: "vpn",
          display_name: "Home VPN",
          type: "interface",
          interface: "nwg0",
        },
      ],
      [{ outbound: "vpn" }],
      new Map(runtime.data.outbounds.map((entry) => [entry.tag, entry]))
    )
    expect(paths.map((path) => path.interfaceName)).toEqual(["nwg0"])
    const chart = buildTrafficSeries(byName.get("nwg0")!.traffic!)
    expect(chart.samples).toHaveLength(2)
    expect(chart.hasTraffic).toBe(true)
    const shares = collectRouteTrafficShares(paths, byName, "Others")
    expect(shares.totalBytes).toBe(700)
    expect(shares.slices).toMatchObject([{ label: "Home VPN", share: 1 }])
    expect(session.sources).toHaveLength(1)
    expect(session.intervals.size).toBe(0)
  })

  test("a cold SSE snapshot supersedes every pending first REST baseline and keeps traffic visible", async () => {
    const session = browserSession()
    const pending = runtimeBaselineCases.map(([, key]) =>
      observeDelayedBaseline(session.client, key)
    )
    session.renderAuthenticatedSubtree(true)
    const source = session.sources[0]
    source.open()
    await flushQueryMicrotasks()
    expect(pending.map((requests) => requests.length)).toEqual([1, 1, 1])

    const current = snapshot()
    source.emit("snapshot", current)
    expect(pending.map((requests) => requests[0].signal.aborted)).toEqual([
      true,
      true,
      true,
    ])
    for (const [index, [, , oldData]] of runtimeBaselineCases.entries()) {
      pending[index][0].response.resolve(restResponse(oldData))
    }
    await flushQueryMicrotasks()
    for (const [kind, key] of runtimeBaselineCases) {
      expect(session.client.getQueryData(key)).toMatchObject({
        status: 200,
        data: current[kind],
      })
      expect(session.client.getQueryState(key)).toMatchObject({
        status: "success",
        fetchStatus: "idle",
        error: null,
      })
    }
    source.emit("interface_traffic", traffic(2_000, 100, 200))
    source.emit("interface_traffic", traffic(4_000, 300, 400))
    const inventory =
      session.client.getQueryData<getRuntimeInterfacesResponseSuccess>(
        getGetRuntimeInterfacesQueryKey()
      )!
    expect(inventory.data.interfaces.map((row) => row.name)).toEqual(["nwg0"])
    expect(
      buildTrafficSeries(inventory.data.interfaces[0].traffic!).hasTraffic
    ).toBe(true)
    expect(session.intervals.size).toBe(0)
  })

  test("a late failed first REST request cannot turn the accepted SSE snapshot into an error", async () => {
    const session = browserSession()
    const key = getGetRuntimeInterfacesQueryKey()
    const pending = observeDelayedBaseline(session.client, key)
    session.renderAuthenticatedSubtree(true)
    const source = session.sources[0]
    source.open()
    await flushQueryMicrotasks()
    source.emit("snapshot", snapshot())
    pending[0].response.reject(
      new Error("old REST request failed after snapshot")
    )
    await flushQueryMicrotasks()
    expect(pending[0].signal.aborted).toBe(true)
    expect(session.client.getQueryState(key)).toMatchObject({
      data: { data: snapshot().interfaces },
      status: "success",
      fetchStatus: "idle",
      error: null,
    })
  })

  test.each(runtimeBaselineCases)(
    "a full %s event cancels only its matching REST baseline",
    async (kind) => {
      const session = browserSession()
      const pending = runtimeBaselineCases.map(([, key]) =>
        observeDelayedBaseline(session.client, key)
      )
      session.renderAuthenticatedSubtree(true)
      const source = session.sources[0]
      source.open()
      await flushQueryMicrotasks()
      const current = snapshot()
      source.emit(kind, current[kind])
      for (const [
        index,
        [otherKind, , oldData],
      ] of runtimeBaselineCases.entries()) {
        expect(pending[index][0].signal.aborted).toBe(otherKind === kind)
        pending[index][0].response.resolve(restResponse(oldData))
      }
      await flushQueryMicrotasks()
      for (const [otherKind, key, oldData] of runtimeBaselineCases) {
        expect(session.client.getQueryData(key)).toMatchObject({
          data: otherKind === kind ? current[kind] : oldData,
        })
        expect(session.client.getQueryState(key)?.status).toBe("success")
      }
    }
  )

  test("a partial traffic event keeps the pending inventory REST baseline", async () => {
    const session = browserSession()
    const key = getGetRuntimeInterfacesQueryKey()
    const pending = observeDelayedBaseline(session.client, key)
    session.renderAuthenticatedSubtree(true)
    const source = session.sources[0]
    source.open()
    await flushQueryMicrotasks()
    source.emit("interface_traffic", traffic(2_000, 100, 200))
    expect(pending[0].signal.aborted).toBe(false)
    pending[0].response.resolve(restResponse(snapshot().interfaces))
    await flushQueryMicrotasks()
    expect(session.client.getQueryData(key)).toMatchObject({
      data: snapshot().interfaces,
    })
  })

  test("REST fallback still refreshes after an SSE snapshot cancelled the old first GET", async () => {
    const session = browserSession()
    const key = getGetRuntimeInterfacesQueryKey()
    const pending = observeDelayedBaseline(session.client, key)
    session.renderAuthenticatedSubtree(true)
    const source = session.sources[0]
    source.open()
    await flushQueryMicrotasks()
    source.emit("snapshot", snapshot())
    pending[0].response.resolve(restResponse({ interfaces: [] }))
    await flushQueryMicrotasks()

    source.onerror?.()
    await flushQueryMicrotasks()
    expect(pending).toHaveLength(2)
    expect(pending[1].signal.aborted).toBe(false)
    expect(session.intervals.size).toBe(1)
    pending[1].response.resolve(restResponse(snapshot("nwg1").interfaces))
    await flushQueryMicrotasks()
    expect(session.client.getQueryData(key)).toMatchObject({
      data: snapshot("nwg1").interfaces,
    })
    expect(session.client.getQueryState(key)?.fetchStatus).toBe("idle")
  })

  test("an existing session reconnects on the same source and retains notification SSE", () => {
    const session = browserSession()
    session.renderAuthenticatedSubtree(true)
    const source = session.sources[0]
    source.open()
    source.onerror?.()
    expect(getStatusEventConnectionState()).toBe("disconnected")
    expect(session.intervals.size).toBe(1)
    source.open()
    expect(getStatusEventConnectionState()).toBe("connected")
    expect(session.intervals.size).toBe(0)
    source.emit("notification_state", {
      revision: 5,
      log_ids: ["read-1"],
      update_ids: [],
    })
    expect(session.client.getQueryData(NOTIFICATION_STATE_QUERY_KEY)).toEqual({
      revision: 5,
      log_ids: ["read-1"],
      update_ids: [],
    })
    expect(session.sources).toHaveLength(1)
  })

  test("subscription changes use the authenticated stream without another timer or source", () => {
    const session = browserSession()
    session.renderAuthenticatedSubtree(true)
    const source = session.sources[0]
    source.open()
    for (const queryKey of SUBSCRIPTION_CHANGE_QUERY_KEYS) {
      session.client.setQueryData(queryKey, { current: true })
    }
    source.emit("subscriptions", undefined)
    for (const queryKey of SUBSCRIPTION_CHANGE_QUERY_KEYS) {
      expect(session.client.getQueryState(queryKey)?.isInvalidated).toBe(true)
    }
    expect(session.sources).toHaveLength(1)
    expect(session.intervals.size).toBe(0)
  })

  test("auth unmount closes the old source; the next login receives a fresh snapshot", () => {
    const session = browserSession()
    session.renderAuthenticatedSubtree(true)
    const first = session.sources[0]
    first.open()
    first.emit("snapshot", snapshot("old0"))
    session.renderAuthenticatedSubtree(false)
    expect(first.closed).toBe(true)
    expect(session.visibilityListeners.size).toBe(0)
    expect(session.intervals.size).toBe(0)
    session.visibility("visible")
    expect(session.sources).toHaveLength(1)

    session.renderAuthenticatedSubtree(true)
    const second = session.sources[1]
    second.open()
    second.emit("snapshot", snapshot("new0"))
    expect(
      session.client.getQueryData(getGetRuntimeInterfacesQueryKey())
    ).toMatchObject({
      data: { interfaces: [{ name: "new0" }] },
    })
    expect(first.closed).toBe(true)
    expect(second.closed).toBe(false)
  })

  test("a hidden authenticated page pauses and resumes its only stream", () => {
    const session = browserSession()
    session.renderAuthenticatedSubtree(true)
    session.sources[0].open()
    session.visibility("hidden")
    const pause = [...session.timeouts.values()].find(
      (timer) => timer.delay === 60_000
    )
    expect(pause).toBeDefined()
    pause!.callback()
    expect(session.sources[0].closed).toBe(true)
    expect(getStatusEventConnectionState()).toBe("paused")
    session.visibility("visible")
    expect(session.sources).toHaveLength(2)
    session.sources[1].open()
    expect(getStatusEventConnectionState()).toBe("connected")
  })

  test("open and router events share one targeted window, closed sessions cancel it", async () => {
    const session = browserSession()
    session.client.setQueryData(ROUTER_INFO_QUERY_KEY, { wan: "old" })
    session.client.setQueryData(["system-metrics"], { uptime: 10 })
    session.renderAuthenticatedSubtree(true)
    const first = session.sources[0]
    first.open()
    const window = [...session.timeouts.entries()].find(
      ([, timer]) => timer.delay === 5_000
    )
    expect(window).toBeDefined()
    first.emit("router_info", undefined)
    first.emit("router_info", undefined)
    expect(
      [...session.timeouts.entries()].filter(
        ([, timer]) => timer.delay === 5_000
      )
    ).toEqual([window!])
    expect(
      session.client.getQueryState(ROUTER_INFO_QUERY_KEY)?.isInvalidated
    ).toBe(false)
    session.timeouts.delete(window![0])
    window![1].callback()
    await flushQueryMicrotasks()
    expect(
      session.client.getQueryState(ROUTER_INFO_QUERY_KEY)?.isInvalidated
    ).toBe(true)
    expect(
      session.client.getQueryState(["system-metrics"])?.isInvalidated
    ).toBe(false)
    expect(session.intervals.size).toBe(0)

    first.emit("router_info", undefined)
    session.visibility("hidden")
    const pause = [...session.timeouts.entries()].find(
      ([, timer]) => timer.delay === 60_000
    )
    expect(pause).toBeDefined()
    session.timeouts.delete(pause![0])
    pause![1].callback()
    expect(first.closed).toBe(true)
    expect(
      [...session.timeouts.values()].filter((timer) => timer.delay === 5_000)
    ).toEqual([])

    session.client.setQueryData(ROUTER_INFO_QUERY_KEY, { wan: "cached" })
    session.visibility("visible")
    session.sources[1].open()
    const reconnect = [...session.timeouts.entries()].find(
      ([, timer]) => timer.delay === 5_000
    )
    expect(reconnect).toBeDefined()
    session.timeouts.delete(reconnect![0])
    reconnect![1].callback()
    await flushQueryMicrotasks()
    expect(
      session.client.getQueryState(ROUTER_INFO_QUERY_KEY)?.isInvalidated
    ).toBe(true)
    session.sources[1].emit("router_info", undefined)
    session.renderAuthenticatedSubtree(false)
    expect(session.sources[1].closed).toBe(true)
    expect(session.timeouts.size).toBe(0)
    expect(session.intervals.size).toBe(0)
  })
})
