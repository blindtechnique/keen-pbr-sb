import { useEffect, useRef } from "react"
import { useQueryClient } from "@tanstack/react-query"

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
import { applyDnsProbeStatusEvent } from "@/api/dns-probe-events"
import { applyComponentTransactionStatusEvent } from "@/api/component-transaction-events"
import { applyListRefreshStatusEvent } from "@/api/list-refresh-events"
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
] as const

export function StatusEventBridge() {
  const queryClient = useQueryClient()
  const lastConfigResyncOperationRef = useRef<string | null>(null)

  useEffect(() => {
    let source: EventSource | null = null
    let hiddenTimer: ReturnType<typeof setTimeout> | null = null
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
          } else {
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
      disconnect("disconnected")
    }
  }, [queryClient])

  return null
}
