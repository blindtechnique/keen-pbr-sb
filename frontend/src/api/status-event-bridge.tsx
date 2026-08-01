import { useEffect } from "react"
import { useQueryClient } from "@tanstack/react-query"

import { applyStatusEvent } from "@/api/status-event-cache"
import {
  hasStatusEventKeepAliveLease,
  setStatusEventConnectionState,
  subscribeStatusEventKeepAliveLease,
} from "@/api/status-event-connection"
import { applyDnsProbeStatusEvent } from "@/api/dns-probe-events"

const HIDDEN_DISCONNECT_DELAY_MS = 60_000
const STATUS_EVENT_NAMES = [
  "snapshot",
  "service",
  "outbounds",
  "interfaces",
  "interface_traffic",
  "connections",
  "dns_probe",
] as const

export function StatusEventBridge() {
  const queryClient = useQueryClient()

  useEffect(() => {
    let source: EventSource | null = null
    let hiddenTimer: ReturnType<typeof setTimeout> | null = null

    const connect = () => {
      if (source !== null) return
      setStatusEventConnectionState("connecting")
      source = new EventSource("/api/status/events")
      source.onopen = () => setStatusEventConnectionState("connected")
      source.onerror = () => setStatusEventConnectionState("disconnected")
      for (const eventName of STATUS_EVENT_NAMES) {
        source.addEventListener(eventName, (event) => {
          const data = (event as MessageEvent<string>).data
          if (eventName === "dns_probe") {
            applyDnsProbeStatusEvent(data)
          } else {
            applyStatusEvent(queryClient, data)
          }
        })
      }
    }

    const disconnect = (state: "disconnected" | "paused") => {
      source?.close()
      source = null
      setStatusEventConnectionState(state)
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
      disconnect("disconnected")
    }
  }, [queryClient])

  return null
}
