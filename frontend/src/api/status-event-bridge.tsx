import { useEffect } from "react"
import { useQueryClient } from "@tanstack/react-query"

import { applyStatusEvent } from "@/api/status-event-cache"
import { setStatusEventConnectionState } from "@/api/status-event-connection"

const HIDDEN_DISCONNECT_DELAY_MS = 60_000
const STATUS_EVENT_NAMES = [
  "snapshot",
  "service",
  "outbounds",
  "interfaces",
  "interface_traffic",
  "connections",
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
          applyStatusEvent(queryClient, (event as MessageEvent<string>).data)
        })
      }
    }

    const disconnect = (state: "disconnected" | "paused") => {
      source?.close()
      source = null
      setStatusEventConnectionState(state)
    }

    const onVisibilityChange = () => {
      if (hiddenTimer !== null) clearTimeout(hiddenTimer)
      hiddenTimer = null
      if (document.visibilityState === "visible") {
        connect()
      } else {
        hiddenTimer = setTimeout(
          () => disconnect("paused"),
          HIDDEN_DISCONNECT_DELAY_MS
        )
      }
    }

    connect()
    onVisibilityChange()
    document.addEventListener("visibilitychange", onVisibilityChange)
    return () => {
      document.removeEventListener("visibilitychange", onVisibilityChange)
      if (hiddenTimer !== null) clearTimeout(hiddenTimer)
      disconnect("disconnected")
    }
  }, [queryClient])

  return null
}
