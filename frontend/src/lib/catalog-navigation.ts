// Only UI selection goes into browser history: never configs, subscription
// URLs, credentials or a new persistent draft. The existing planner still
// resolves catalogue IDs against the current server snapshot on confirmation.
export type CatalogSelectionContext = Readonly<{
  selectedIds: readonly string[]
  search: string
  category: string
  destination: string
  sourceDetour: string | null
}>

export function readCatalogSelectionContext(
  state: unknown
): CatalogSelectionContext | null {
  if (!state || typeof state !== "object" || !("catalogSelection" in state))
    return null
  const value = state.catalogSelection
  if (!value || typeof value !== "object" || !("selectedIds" in value))
    return null
  const record = value as Record<string, unknown>
  if (
    !Array.isArray(record.selectedIds) ||
    !record.selectedIds.every((id) => typeof id === "string")
  )
    return null
  return {
    selectedIds: [...record.selectedIds],
    search: typeof record.search === "string" ? record.search : "",
    category: typeof record.category === "string" ? record.category : "all",
    destination:
      typeof record.destination === "string" ? record.destination : "",
    sourceDetour:
      typeof record.sourceDetour === "string" ? record.sourceDetour : null,
  }
}

export function catalogNavigationOptions(selection: CatalogSelectionContext) {
  return {
    state: {
      catalogSelection: {
        ...selection,
        selectedIds: [...selection.selectedIds],
      },
    },
  }
}

export function catalogSelectionAfterCreate(
  previous: CatalogSelectionContext | null,
  outboundTag?: string
): CatalogSelectionContext {
  return {
    selectedIds: previous?.selectedIds ?? [],
    search: previous?.search ?? "",
    category: previous?.category ?? "all",
    sourceDetour: previous?.sourceDetour ?? null,
    destination: outboundTag ?? previous?.destination ?? "",
  }
}

export function catalogReturnHref(selection: CatalogSelectionContext) {
  const search = selection.search
    ? `?${new URLSearchParams({ search: selection.search })}`
    : ""
  return `/catalog${search}#${encodeURIComponent(selection.category)}`
}
