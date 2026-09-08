import type { QueryClient } from "@tanstack/react-query"

import {
  applyStatusEvent,
  getTerminalConfigLifecycleOperationKey,
} from "@/api/status-event-cache"
import {
  getGetConfigQueryKey,
  getGetHealthServiceQueryKey,
  getGetRuntimeInterfacesQueryKey,
  getGetRuntimeOutboundsQueryKey,
} from "@/api/generated/keen-api"
import {
  hasStatusEventKeepAliveLease,
  setStatusEventConnectionState,
  subscribeStatusEventKeepAliveLease,
  type StatusEventConnectionState,
} from "@/api/status-event-connection"
import { createStatusQueryResilience } from "@/api/status-event-resilience"
import { mountRuntimeEventObserver } from "@/api/runtime-event-observer"
import { applyDnsProbeStatusEvent } from "@/api/dns-probe-events"
import { applyComponentTransactionStatusEvent } from "@/api/component-transaction-events"
import { applyListRefreshStatusEvent } from "@/api/list-refresh-events"
import { applyNotificationStatusEvent } from "@/api/notification-events"
import { applySubscriptionStatusEvent } from "@/api/subscription-events"
import {
  applyRouterInfoStatusEvent,
  createRouterInfoEventRefresh,
} from "@/api/router-info-events"
import {
  applySingBoxInstallStatusEvent,
  resetSingBoxInstallProgress,
} from "@/api/sing-box-install-events"

const HIDDEN_DISCONNECT_DELAY_MS = 60_000
const STATUS_EVENT_NAMES = [
  "snapshot",
  "service",
  "outbounds",
  "interfaces",
  "interface_traffic",
  "connections",
  "dns_probe",
  "list_refresh",
  "component_transaction",
  "sing_box_install",
  "notification_state",
  "subscriptions",
  "router_info",
] as const

/** Mounted only for the existing authenticated App subtree. */
export function mountStatusEventSession(
  queryClient: QueryClient,
  lastConfigResyncOperationRef: { current: string | null }
): () => void {
  let source: EventSource | null = null
  let hiddenTimer: ReturnType<typeof setTimeout> | null = null
  const runtimeEvents = mountRuntimeEventObserver(queryClient)
  const routerInfoRefresh = createRouterInfoEventRefresh(queryClient)
  const runtimeQueryKeys = [
    getGetHealthServiceQueryKey(),
    getGetRuntimeOutboundsQueryKey(),
    getGetRuntimeInterfacesQueryKey(),
  ]
  const resilience = createStatusQueryResilience({
    refresh: async () => {
      for (const queryKey of runtimeQueryKeys) {
        await queryClient.invalidateQueries({
          exact: true,
          queryKey,
          refetchType: "none",
        })
      }
      await Promise.all(
        runtimeQueryKeys.map((queryKey) =>
          queryClient.refetchQueries({
            exact: true,
            queryKey,
            type: "active",
          })
        )
      )
    },
  })
  const setConnectionState = (state: StatusEventConnectionState) => {
    runtimeEvents.setConnected(state === "connected")
    setStatusEventConnectionState(state)
    resilience.transition(state)
  }

  const connect = () => {
    if (source !== null) return
    setConnectionState("connecting")
    source = new EventSource("/api/status/events")
    source.onopen = () => {
      // Everything learned from the previous connection is stale by
      // definition, and the daemon re-sends what is still true as soon as
      // this one is registered - its subscribe() replays the cached frames
      // before any new ones. Clearing first and letting the replay restore
      // it is therefore correct in both directions.
      //
      // Without this, a daemon restarted during a sing-box install leaves
      // every open page believing one is still running: the new process has
      // no cached frame to replay, so nothing ever contradicts the last
      // "active" frame the old one sent, and the install button stays
      // disabled until someone reloads the page.
      resetSingBoxInstallProgress()
      setConnectionState("connected")
      // A lightweight change event is not replayed. Refresh once on connection
      // through the same fixed window, including after a hidden tab resumes.
      routerInfoRefresh.scheduleRefresh()
    }
    source.onerror = () => setConnectionState("disconnected")
    for (const eventName of STATUS_EVENT_NAMES) {
      source.addEventListener(eventName, (event) => {
        const data = (event as MessageEvent<string>).data
        if (eventName === "dns_probe") {
          applyDnsProbeStatusEvent(data)
        } else if (eventName === "list_refresh") {
          applyListRefreshStatusEvent(data)
        } else if (eventName === "component_transaction") {
          applyComponentTransactionStatusEvent(data)
        } else if (eventName === "sing_box_install") {
          applySingBoxInstallStatusEvent(data)
        } else if (eventName === "notification_state") {
          applyNotificationStatusEvent(queryClient, data)
        } else if (eventName === "subscriptions") {
          applySubscriptionStatusEvent(queryClient, data)
        } else if (eventName === "router_info") {
          applyRouterInfoStatusEvent(data, routerInfoRefresh.scheduleRefresh)
        } else {
          if (eventName === "snapshot") runtimeEvents.resetRuntimeBaseline()
          applyStatusEvent(queryClient, data)
          const terminalOperationKey =
            getTerminalConfigLifecycleOperationKey(data)
          if (
            terminalOperationKey &&
            terminalOperationKey !== lastConfigResyncOperationRef.current
          ) {
            lastConfigResyncOperationRef.current = terminalOperationKey
            void queryClient.invalidateQueries({
              queryKey: getGetConfigQueryKey(),
            })
          }
        }
      })
    }
  }

  const disconnect = (state: "disconnected" | "paused") => {
    source?.close()
    source = null
    routerInfoRefresh.cancelPending()
    setConnectionState(state)
  }

  const reconcileVisibility = () => {
    if (hiddenTimer !== null) clearTimeout(hiddenTimer)
    hiddenTimer = null
    if (
      document.visibilityState === "visible" ||
      hasStatusEventKeepAliveLease()
    ) {
      connect()
    } else {
      hiddenTimer = setTimeout(
        () => disconnect("paused"),
        HIDDEN_DISCONNECT_DELAY_MS
      )
    }
  }

  connect()
  reconcileVisibility()
  document.addEventListener("visibilitychange", reconcileVisibility)
  const unsubscribeKeepAlive =
    subscribeStatusEventKeepAliveLease(reconcileVisibility)
  return () => {
    document.removeEventListener("visibilitychange", reconcileVisibility)
    unsubscribeKeepAlive()
    if (hiddenTimer !== null) clearTimeout(hiddenTimer)
    resilience.dispose()
    routerInfoRefresh.dispose()
    disconnect("disconnected")
    runtimeEvents.dispose()
  }
}
