import type { QueryClient } from "@tanstack/react-query"

import {
  getConfig,
  getGetSubscriptionsQueryKey,
} from "@/api/generated/keen-api"
import { queryKeys } from "@/api/query-keys"

export const BACKUP_RESTORE_QUERY_KEYS = [
  queryKeys.config(),
  queryKeys.transportConfig(),
  queryKeys.transports(),
  queryKeys.runtimeInterfaces(),
  queryKeys.runtimeOutbounds(),
  queryKeys.ndmsInterfaceInventory(),
  queryKeys.ndmsVpnServerServices(),
  queryKeys.healthService(),
  queryKeys.healthRouting(),
  queryKeys.dnsTest(),
  getGetSubscriptionsQueryKey(),
  ["logs", "notifications"],
  ["nfqws"],
  ["log-settings"],
] as const

/** A successful REST restore is sufficient; a transient SSE event may be lost. */
export async function refreshAfterBackupRestore(client: QueryClient) {
  // An older GET must not republish the pre-restore document after the new one.
  await Promise.all(
    BACKUP_RESTORE_QUERY_KEYS.map((queryKey) =>
      client.cancelQueries({ queryKey })
    )
  )
  await Promise.all(
    BACKUP_RESTORE_QUERY_KEYS.map((queryKey) =>
      client.invalidateQueries({ queryKey, refetchType: "none" })
    )
  )
  // The still-mounted settings editor needs a new baseline before the restore
  // dialog releases it. A failed GET puts that query into its normal error
  // state instead of letting a subsequent Save send the old document.
  await client.fetchQuery({
    queryKey: queryKeys.config(),
    queryFn: ({ signal }) => getConfig({ signal }),
    staleTime: 0,
    retry: false,
  })
  // Optional status views should refresh, but cannot delay a completed restore.
  void Promise.all(
    BACKUP_RESTORE_QUERY_KEYS.slice(1).map((queryKey) =>
      client.refetchQueries({ queryKey, type: "active" })
    )
  ).catch(() => undefined)
}
