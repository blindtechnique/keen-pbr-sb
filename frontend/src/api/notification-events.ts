import type { QueryClient } from "@tanstack/react-query"
import type { NotificationDismissalState } from "@/api/generated/model"

export const NOTIFICATION_STATE_QUERY_KEY = ["notifications", "state"] as const

// A slow GET from before a phone's clear must not restore notices on the PC.
export function applyNotificationState(
  queryClient: QueryClient,
  state: NotificationDismissalState
) {
  queryClient.setQueryData<NotificationDismissalState | null>(
    NOTIFICATION_STATE_QUERY_KEY,
    (current) =>
      current && current.revision >= state.revision ? current : state
  )
}

export function applyNotificationStatusEvent(
  queryClient: QueryClient,
  serialized: string
): boolean {
  try {
    const event = JSON.parse(serialized)
    const state = event?.data
    if (
      event?.type !== "notification_state" ||
      !state ||
      !Number.isSafeInteger(state.revision) ||
      state.revision < 0 ||
      !Array.isArray(state.log_ids) ||
      !state.log_ids.every((id: unknown) => typeof id === "string") ||
      !Array.isArray(state.update_ids) ||
      !state.update_ids.every((id: unknown) => typeof id === "string")
    ) {
      return false
    }
    applyNotificationState(queryClient, state)
    return true
  } catch {
    return false
  }
}
