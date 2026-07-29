import type { ListConfig } from "@/api/generated/model/listConfig"
import type { OutboundType } from "@/api/generated/model/outboundType"

export type CatalogPreset = {
  id: string
  name: string
  catalog_identity?: string
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

/**
 * Fast visual hint only. The transactional backend planner repeats the exact
 * provenance/content comparison before changing the configuration.
 */
export function isCatalogPresetInstalled(
  preset: CatalogPreset,
  lists: Readonly<Record<string, ListConfig>> | undefined
): boolean {
  if (!lists) {
    return false
  }

  const configuredLists = Object.values(lists)
  if (
    preset.catalog_identity &&
    configuredLists.some(
      (list) => list.catalog_identity === preset.catalog_identity
    )
  ) {
    return true
  }

  const sourceUrl =
    preset.engines?.singbox?.ruleSets?.[0]?.url?.trim() ||
    preset.engines?.dns?.subscriptionUrl?.trim()
  const domains = normalizedValues(preset.engines?.dns?.domains)
  const cidrs = normalizedValues(preset.engines?.dns?.subnets)

  return configuredLists.some((list) => {
    if (list.catalog_identity) {
      return false
    }
    if (sourceUrl) {
      return list.url?.trim() === sourceUrl
    }
    if (list.url || list.file) {
      return false
    }
    return (
      sameValues(normalizedValues(list.domains), domains) &&
      sameValues(normalizedValues(list.ip_cidrs), cidrs)
    )
  })
}

function normalizedValues(values: readonly string[] | undefined): string[] {
  return [...new Set((values ?? []).map((value) => value.trim()))]
    .filter(Boolean)
    .sort()
}

function sameValues(left: readonly string[], right: readonly string[]): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  )
}
