import type { OutboundType } from "@/api/generated/model/outboundType"

export type CatalogPreset = {
  id: string
  name: string
  category?: string
  engines?: {
    dns?: {
      domains?: string[]
      subnets?: string[]
      subscriptionUrl?: string
    }
    singbox?: {
      action?: string
      ruleSets?: { tag?: string; url?: string }[]
    }
  }
}

export type CatalogSelectionMode = "empty" | "route" | "reject" | "mixed"

export interface CatalogPresetSourceSummary {
  readonly urlBacked: boolean
  readonly domainCount: number
  readonly cidrCount: number
}

/**
 * Fast UI affordance only. The backend planner remains authoritative and
 * repeats this check while producing and committing the candidate config.
 */
export function isCatalogRoutableOutboundType(
  type: OutboundType
): boolean {
  return type === "interface" || type === "table" || type === "urltest"
}

export function getCatalogSelectionMode(
  presets: readonly CatalogPreset[],
  selectedIds: ReadonlySet<string>
): CatalogSelectionMode {
  let hasRoute = false
  let hasReject = false

  for (const preset of presets) {
    if (!selectedIds.has(preset.id)) {
      continue
    }
    if (preset.engines?.singbox?.action === "reject") {
      hasReject = true
    } else {
      hasRoute = true
    }
  }

  if (hasRoute && hasReject) {
    return "mixed"
  }
  if (hasReject) {
    return "reject"
  }
  return hasRoute ? "route" : "empty"
}

export function getCatalogPresetSourceSummary(
  preset: CatalogPreset
): CatalogPresetSourceSummary {
  return {
    urlBacked: Boolean(
      preset.engines?.singbox?.ruleSets?.[0]?.url ||
        preset.engines?.dns?.subscriptionUrl
    ),
    domainCount: preset.engines?.dns?.domains?.length ?? 0,
    cidrCount: preset.engines?.dns?.subnets?.length ?? 0,
  }
}
