import type { QueryClient } from "@tanstack/react-query"

import { postTransportConfig } from "@/api/generated/keen-api"
import {
  TransportConfigOperationOperation,
  type TransportSpec,
} from "@/api/generated/model"
import { queryKeys } from "@/api/query-keys"

// File transfer is deliberately sequential. Earlier successful entries remain
// committed when a later entry fails; both outcomes must refresh inventory.
export async function importTransportDefinitions(
  imported: readonly TransportSpec[],
  existingTags: ReadonlySet<string>,
  replaceConflicts: boolean
) {
  for (const transport of imported) {
    const exists = existingTags.has(transport.tag)
    if (exists && !replaceConflicts) continue
    const response = await postTransportConfig({
      operation: exists
        ? TransportConfigOperationOperation.update
        : TransportConfigOperationOperation.create,
      tag: exists ? transport.tag : undefined,
      transport,
    })
    if (response.status !== 200) {
      throw new Error(
        "error" in response.data
          ? response.data.error
          : `HTTP ${response.status}`
      )
    }
  }
}

export async function refreshTransportTransferInventory(client: QueryClient) {
  await Promise.all([
    client.invalidateQueries({ queryKey: queryKeys.transports() }),
    client.invalidateQueries({ queryKey: queryKeys.transportConfig() }),
  ])
}
