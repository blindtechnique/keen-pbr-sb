import type { QueryClient } from "@tanstack/react-query"

import {
  getGetHealthServiceQueryKey,
  getGetRuntimeOutboundsQueryKey,
  getGetTransportsQueryKey,
} from "@/api/generated/keen-api"
import type {
  HealthResponse,
  RuntimeOutboundState,
  TransportStatus,
} from "@/api/generated/model"
import {
  createRuntimeEventHistory,
  type RuntimeEvent,
} from "@/components/overview/runtime-events-model"

export const RUNTIME_EVENTS_QUERY_KEY = ["runtime-events", "session"] as const

export type RuntimeEventFeed = Readonly<{
  events: readonly RuntimeEvent[]
  ready: boolean
  connected: boolean
  partial: boolean
}>

type Source = "service" | "outbounds" | "transports"

// Observes only successful writes already made by SSE and existing queries.
// It never fetches, invalidates a query, starts a timer, or persists history.
export function mountRuntimeEventObserver(
  client: QueryClient,
  now: () => number = Date.now
) {
  const history = createRuntimeEventHistory()
  let connected = false
  let ready = false
  let daemonPid: number | undefined
  let published: RuntimeEventFeed | undefined
  const failed = new Set<Source>()
  const sources = new Map<string, Source>([
    [getGetHealthServiceQueryKey()[0], "service"],
    [getGetRuntimeOutboundsQueryKey()[0], "outbounds"],
    [getGetTransportsQueryKey()[0], "transports"],
  ])
  const publish = () => {
    const events = history.getEvents()
    const partial = failed.size > 0
    if (
      published?.events === events &&
      published.connected === connected &&
      published.ready === ready &&
      published.partial === partial
    )
      return
    published = { events, connected, ready, partial }
    client.setQueryData<RuntimeEventFeed>(RUNTIME_EVENTS_QUERY_KEY, published)
  }
  client.setQueryDefaults(RUNTIME_EVENTS_QUERY_KEY, { gcTime: Infinity })
  publish()

  const unsubscribe = client.getQueryCache().subscribe((event) => {
    const key = event.query.queryKey
    const source =
      key.length === 1 && typeof key[0] === "string"
        ? sources.get(key[0])
        : undefined
    if (!source) return
    if (
      event.type === "removed" ||
      (event.type === "updated" && event.action.type === "error")
    ) {
      history.resetBaseline(source)
      if (source === "service") daemonPid = undefined
      failed.add(source)
      publish()
      return
    }
    if (
      !connected ||
      event.type !== "updated" ||
      event.action.type !== "success"
    )
      return
    const response = event.query.state.data as
      | { status?: number; data?: unknown }
      | undefined
    const data = response?.data
    if (response?.status !== 200 || !data || typeof data !== "object") {
      history.resetBaseline(source)
      failed.add(source)
      publish()
      return
    }
    if (
      source === "outbounds" &&
      "outbounds" in data &&
      Array.isArray(data.outbounds)
    ) {
      history.observeOutbounds(data.outbounds as RuntimeOutboundState[], now())
    } else if (source === "transports" && Array.isArray(data)) {
      history.observeTransports(data as TransportStatus[], now())
    } else if (source === "service" && "runtime_state" in data) {
      const pid = (data as HealthResponse).daemon_pid
      if (pid && daemonPid && pid !== daemonPid) {
        history.resetBaseline("outbounds")
        history.resetBaseline("transports")
      }
      daemonPid = pid
      history.observeService(data as HealthResponse, now())
    } else {
      history.resetBaseline(source)
      failed.add(source)
      publish()
      return
    }
    ready = true
    failed.delete(source)
    publish()
  })

  return {
    setConnected(value: boolean) {
      connected = value
      if (!value) {
        history.resetBaseline("all")
        daemonPid = undefined
        failed.clear()
      }
      publish()
    },
    // A fresh SSE snapshot is a baseline, not a replay of missed changes.
    resetRuntimeBaseline() {
      history.resetBaseline("service")
      history.resetBaseline("outbounds")
    },
    dispose() {
      unsubscribe()
      client.removeQueries({ queryKey: RUNTIME_EVENTS_QUERY_KEY, exact: true })
    },
  }
}
