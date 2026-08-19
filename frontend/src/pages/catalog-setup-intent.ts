import type {
  CatalogPreset,
  CatalogSelectionMode,
} from "@/pages/catalog-model"
import type {
  CatalogSetupIntent,
  CatalogSetupMode,
} from "@/api/generated/model"

export type {
  CatalogSetupDnsMode,
  CatalogSetupIntent,
  CatalogSetupMode,
} from "@/api/generated/model"

export function resolveCatalogDestination(
  selectedDestination: string,
  outboundTags: readonly string[],
  directDestination: string
): string {
  return selectedDestination || outboundTags[0] || directDestination
}

interface CreateCatalogSetupIntentOptions {
  readonly presets: readonly CatalogPreset[]
  readonly selectedIds: ReadonlySet<string>
  readonly selectionMode: CatalogSelectionMode
  readonly destination: string
  readonly directDestination: string
  readonly sourceDetour: string
  readonly combinedDisplayName: string
}

/**
 * Build the user's typed intent only. Catalogue payloads, technical IDs,
 * placement and config mutation remain server-owned so a stale browser cannot
 * overwrite a newer config or smuggle arbitrary URLs into quick setup.
 */
export function createCatalogSetupIntent({
  presets,
  selectedIds,
  selectionMode,
  destination,
  directDestination,
  sourceDetour,
  combinedDisplayName,
}: CreateCatalogSetupIntentOptions): CatalogSetupIntent | null {
  if (
    selectedIds.size === 0 ||
    selectionMode === "empty" ||
    selectionMode === "mixed"
  ) {
    return null
  }

  const selections = presets.flatMap((preset) =>
    selectedIds.has(preset.id)
      ? [
          {
            preset_id: preset.id,
            display_name: trimToUndefined(preset.name),
          },
        ]
      : []
  )
  if (selections.length !== selectedIds.size) {
    return null
  }

  const suggestedRuleName =
    selections.length === 1
      ? selections[0]?.display_name
      : trimToUndefined(combinedDisplayName)
  // A reject or direct preset names its own destination, so the picker's value
  // is not consulted for either: choosing an outbound for a list that is meant
  // to stay off every tunnel would be a contradiction the server refuses.
  const mode: CatalogSetupMode =
    selectionMode === "reject"
      ? "block"
      : selectionMode === "direct"
        ? "direct"
        : destination === directDestination
          ? "none"
          : "outbound"

  return {
    selections,
    mode,
    ...(mode === "outbound" ? { outbound_tag: destination } : {}),
    dns_mode: mode === "outbound" ? "automatic" : "none",
    ...(sourceDetour.trim()
      ? { source_detour_tag: sourceDetour.trim() }
      : {}),
    ...(mode !== "none" && suggestedRuleName
      ? { route_display_name: suggestedRuleName }
      : {}),
    ...(mode === "outbound" && suggestedRuleName
      ? { dns_display_name: suggestedRuleName }
      : {}),
  }
}

export function updateCatalogSetupSelectionName(
  intent: CatalogSetupIntent,
  presetId: string,
  displayName: string
): CatalogSetupIntent {
  return {
    ...intent,
    selections: intent.selections.map((selection) =>
      selection.preset_id === presetId
        ? {
            ...selection,
            display_name: trimToUndefined(displayName),
          }
        : selection
    ),
  }
}

export function updateCatalogSetupRuleName(
  intent: CatalogSetupIntent,
  field: "route_display_name" | "dns_display_name",
  displayName: string
): CatalogSetupIntent {
  const normalized = trimToUndefined(displayName)
  const next = { ...intent }
  if (normalized) {
    next[field] = normalized
  } else {
    delete next[field]
  }
  return next
}

function trimToUndefined(value: string): string | undefined {
  return value.trim() || undefined
}
