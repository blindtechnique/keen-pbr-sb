import type {
  NdmsInterfaceInventoryResponse,
  RuntimeInterfaceInventoryEntry,
} from "@/api/generated/model"
import { mapNativeInterfaces } from "@/lib/native-interfaces"

type Inventory = Pick<
  NdmsInterfaceInventoryResponse,
  "available" | "interfaces"
>

/** Stale catalog rows retain identity, not permission or current link health. */
export function nativeInventoryPresentation(
  inventory: Inventory | undefined,
  runtimeInterfaces: readonly RuntimeInterfaceInventoryEntry[]
) {
  const authoritative = inventory?.available === true
  const interfaces = mapNativeInterfaces(
    inventory?.interfaces ?? [],
    runtimeInterfaces
  )
  return {
    authoritative,
    interfaces: authoritative
      ? interfaces
      : interfaces.map((row) => ({
          ...row,
          connected: undefined,
          link: undefined,
        })),
  }
}

/** Retry a known catalog refresh, never poll permanently unsupported firmware. */
export function nativeInventoryRetryInterval(
  inventory:
    | Pick<NdmsInterfaceInventoryResponse, "available" | "catalog_status">
    | undefined
): number | false {
  return inventory?.available === false && inventory.catalog_status === "stale"
    ? 5_000
    : false
}
