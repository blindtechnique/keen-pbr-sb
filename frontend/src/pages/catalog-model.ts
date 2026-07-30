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
export function isCatalogRoutableOutboundType(type: OutboundType): boolean {
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
  return findCatalogPresetInstalledListId(preset, lists) !== undefined
}

/**
 * Resolves a catalogue item to its installed list without relying on a
 * user-editable technical ID. Provenance is authoritative; the exact legacy
 * source comparison only supports configs created before provenance existed.
 */
export function findCatalogPresetInstalledListId(
  preset: CatalogPreset,
  lists: Readonly<Record<string, ListConfig>> | undefined
): string | undefined {
  if (!lists) {
    return undefined
  }

  const configuredLists = Object.entries(lists)
  if (preset.catalog_identity) {
    const provenanceMatch = configuredLists.find(
      ([, list]) => list.catalog_identity === preset.catalog_identity
    )
    if (provenanceMatch) {
      return provenanceMatch[0]
    }
  }

  const sourceUrl =
    preset.engines?.singbox?.ruleSets?.[0]?.url?.trim() ||
    preset.engines?.dns?.subscriptionUrl?.trim()
  const domains = normalizedValues(preset.engines?.dns?.domains)
  const cidrs = normalizedValues(preset.engines?.dns?.subnets)
  if (!sourceUrl && domains.length === 0 && cidrs.length === 0) {
    return undefined
  }

  const legacyMatch = configuredLists.find(([, list]) => {
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

  return legacyMatch?.[0]
}

function normalizedValues(values: readonly string[] | undefined): string[] {
  return [...new Set((values ?? []).map((value) => value.trim()))]
    .filter(Boolean)
    .sort()
}

function sameValues(
  left: readonly string[],
  right: readonly string[]
): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  )
}
