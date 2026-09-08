import { useMemo } from "react"
import { useQuery } from "@tanstack/react-query"
import { useTranslation } from "react-i18next"

import type { Outbound, TransportStatus } from "@/api/generated/model"
import { useStatusEventConnectionState } from "@/api/status-event-connection"
import {
  RUNTIME_EVENTS_QUERY_KEY,
  type RuntimeEventFeed,
} from "@/api/runtime-event-observer"
import { RuntimeEventsCard } from "@/components/overview/runtime-events-card"
import { presentRuntimeEvents } from "@/components/overview/runtime-events-presentation"

export function RuntimeEventsFeed({
  outbounds,
  transports,
}: {
  outbounds: readonly Outbound[]
  transports: readonly TransportStatus[]
}) {
  const { t, i18n } = useTranslation()
  const connection = useStatusEventConnectionState()
  // A disabled observer reads the authenticated session's in-memory cache.
  // Navigating to the dashboard does not create another request or poller.
  const { data } = useQuery<RuntimeEventFeed>({
    queryKey: RUNTIME_EVENTS_QUERY_KEY,
    enabled: false,
    gcTime: Infinity,
  })
  const events = useMemo(
    () =>
      presentRuntimeEvents(
        data?.events ?? [],
        outbounds,
        transports,
        t,
        i18n.resolvedLanguage ?? i18n.language
      ),
    [
      data?.events,
      outbounds,
      transports,
      t,
      i18n.resolvedLanguage,
      i18n.language,
    ]
  )
  const state =
    connection === "disconnected" || connection === "paused" || data?.partial
      ? "error"
      : connection === "connecting" || !data?.ready
        ? "loading"
        : "ready"
  return <RuntimeEventsCard events={events} state={state} />
}
