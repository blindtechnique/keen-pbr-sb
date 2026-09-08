import type { QueryClient } from "@tanstack/react-query"
import { getGetSubscriptionsQueryKey } from "@/api/generated/keen-api"
import { queryKeys } from "@/api/query-keys"

export const SUBSCRIPTION_CHANGE_QUERY_KEYS = [
  getGetSubscriptionsQueryKey(),
  ["logs", "notifications"],
  queryKeys.config(),
  queryKeys.transportConfig(),
  queryKeys.transports(),
  queryKeys.runtimeInterfaces(),
  queryKeys.runtimeOutbounds(),
] as const

export function invalidateSubscriptionQueries(queryClient: QueryClient): void {
  // A confirmed import/event makes these views stale, but fetching them is
  // independent of completing the user's mutation. Slow or failing status
  // endpoints must not turn a successful import into a pending/error dialog.
  void Promise.all(
    SUBSCRIPTION_CHANGE_QUERY_KEYS.map((queryKey) =>
      queryClient.invalidateQueries({ queryKey })
    )
  ).catch(() => undefined)
}

export function applySubscriptionStatusEvent(
  queryClient: QueryClient,
  serialized: string
): boolean {
  try {
    if (JSON.parse(serialized)?.type !== "subscriptions") return false
  } catch {
    return false
  }
  // The event carries no source URLs or transport credentials. Refetch active
  // views through their existing APIs; inactive views are simply marked stale.
  invalidateSubscriptionQueries(queryClient)
  return true
}
