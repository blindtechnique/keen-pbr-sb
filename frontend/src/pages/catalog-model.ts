import type { ListConfig } from "@/api/generated/model/listConfig"
import type { OutboundType } from "@/api/generated/model/outboundType"

export type CatalogWarningCode = "broad_traffic_scope" | (string & {})

export interface CatalogWarning {
  readonly code: CatalogWarningCode
  readonly message?: string
  readonly requiresAcceptance?: boolean
}

export interface CatalogRoutingCompanion {
  readonly id: string
  readonly name: string
  readonly catalog_identity?: string
  readonly kind?: "ip" | (string & {})
  readonly url?: string
  readonly sourcePresetId?: string
  readonly include?: "ip_cidrs" | (string & {})
  readonly suppressDirectSelection?: boolean
}

export type CatalogPreset = {
  id: string
  name: string
  catalog_identity?: string
  category?: string
  hidden?: boolean
  notice?: string
  covers?: string[]
  routingCompanions?: CatalogRoutingCompanion[]
  warnings?: CatalogWarning[]
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
  readonly companionCount: number
  readonly hasIpCompanion: boolean
}

export interface CatalogRoutingCompanionSourceSummary {
  readonly id: string
  readonly name: string
  readonly urlBacked: boolean
  readonly cidrCount: number
}

export type CatalogPresetInstallKind =
  | "installed"
  | "partial"
  | "covered"
  | "missing"

export interface CatalogPresetInstallState {
  readonly kind: CatalogPresetInstallKind
  readonly primaryListId?: string
  readonly companionListIds: readonly string[]
  readonly missingCompanionIds: readonly string[]
  readonly coveredBy?: CatalogPreset
}

export function matchesCatalogSearch(
  preset: CatalogPreset,
  query: string
): boolean {
  const needle = query.trim().toLowerCase()
  if (!needle) {
    return true
  }
  return [preset.id, preset.name, preset.notice ?? ""].some((value) =>
    value.toLowerCase().includes(needle)
  )
}

export function canSelectCatalogPreset(
  installState: CatalogPresetInstallState | undefined,
  selectedAncestor: CatalogPreset | undefined
): boolean {
  return !selectedAncestor && installState?.kind !== "covered"
}

interface CatalogRelationIndex {
  readonly byId: ReadonlyMap<string, CatalogPreset>
  readonly parentsByChild: ReadonlyMap<string, ReadonlySet<string>>
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
  const companions = preset.routingCompanions ?? []

  return {
    urlBacked: Boolean(
      preset.engines?.singbox?.ruleSets?.[0]?.url ||
      preset.engines?.dns?.subscriptionUrl
    ),
    domainCount: preset.engines?.dns?.domains?.length ?? 0,
    cidrCount: preset.engines?.dns?.subnets?.length ?? 0,
    companionCount: companions.length,
    hasIpCompanion: companions.some(isIpRoutingCompanion),
  }
}

/**
 * Resolves the package-owned IP units that are installed atomically with a
 * visible catalogue entry. URL-backed companions (for example Telegram
 * GeoIP) deliberately remain IP units even though their CIDRs are not decoded
 * in the browser.
 */
export function getCatalogRoutingCompanionSourceSummaries(
  preset: CatalogPreset,
  presets: readonly CatalogPreset[]
): readonly CatalogRoutingCompanionSourceSummary[] {
  const byId = new Map(presets.map((candidate) => [candidate.id, candidate]))

  return (preset.routingCompanions ?? [])
    .filter(isIpRoutingCompanion)
    .map((companion) => {
      const source = companion.sourcePresetId
        ? byId.get(companion.sourcePresetId)
        : undefined
      return {
        id: companion.id,
        name: companion.name,
        urlBacked: Boolean(
          companion.url ||
          source?.engines?.singbox?.ruleSets?.[0]?.url ||
          source?.engines?.dns?.subscriptionUrl
        ),
        cidrCount: source?.engines?.dns?.subnets?.length ?? 0,
      }
    })
}

export function resolveSelectedCatalogRoutingCompanions(
  presets: readonly CatalogPreset[],
  selectedIds: ReadonlySet<string>
): ReadonlyMap<string, CatalogRoutingCompanionSourceSummary> {
  const result = new Map<string, CatalogRoutingCompanionSourceSummary>()
  for (const preset of presets) {
    if (!selectedIds.has(preset.id)) {
      continue
    }
    for (const companion of getCatalogRoutingCompanionSourceSummaries(
      preset,
      presets
    )) {
      result.set(companion.id, companion)
    }
  }
  return result
}

/**
 * Keeps catalogue selection semantic: a selected aggregate owns all of its
 * transitive descendants for this operation. Selecting the aggregate removes
 * redundant child selections; attempting to select a covered child is a no-op.
 */
export function applyCatalogSelectionToggle(
  presets: readonly CatalogPreset[],
  selectedIds: ReadonlySet<string>,
  presetId: string
): Set<string> {
  const next = normalizeCatalogSelection(presets, selectedIds)
  if (next.has(presetId)) {
    next.delete(presetId)
    return next
  }

  if (findNearestCatalogAncestor(presets, presetId, next)) {
    return next
  }

  next.add(presetId)
  for (const descendantId of getCatalogDescendantIds(presets, presetId)) {
    next.delete(descendantId)
  }
  return normalizeCatalogSelection(presets, next)
}

export function normalizeCatalogSelection(
  presets: readonly CatalogPreset[],
  selectedIds: ReadonlySet<string>
): Set<string> {
  const normalized = new Set(
    [...selectedIds].filter((id) => presets.some((preset) => preset.id === id))
  )

  const selectedAncestors = resolveCatalogAncestorMap(presets, normalized)
  for (const id of normalized) {
    if (selectedAncestors.has(id)) {
      normalized.delete(id)
    }
  }
  return normalized
}

export function getCatalogDescendantIds(
  presets: readonly CatalogPreset[],
  presetId: string
): Set<string> {
  const byId = new Map(presets.map((preset) => [preset.id, preset]))
  const descendants = new Set<string>()
  const pending = [...(byId.get(presetId)?.covers ?? [])].sort()

  while (pending.length > 0) {
    const current = pending.shift()
    if (!current || current === presetId || descendants.has(current)) {
      continue
    }
    descendants.add(current)
    pending.push(...[...(byId.get(current)?.covers ?? [])].sort())
  }
  return descendants
}

/**
 * Finds the closest selected/installed aggregate. Breadth-first traversal
 * gives the shortest relationship; sorting stable preset IDs resolves equal
 * depth deterministically and makes the result independent of API ordering.
 */
export function findNearestCatalogAncestor(
  presets: readonly CatalogPreset[],
  presetId: string,
  candidateIds: ReadonlySet<string>
): CatalogPreset | undefined {
  return findNearestCatalogAncestorInIndex(
    createCatalogRelationIndex(presets),
    presetId,
    candidateIds
  )
}

export function resolveCatalogAncestorMap(
  presets: readonly CatalogPreset[],
  candidateIds: ReadonlySet<string>
): ReadonlyMap<string, CatalogPreset> {
  const index = createCatalogRelationIndex(presets)
  const result = new Map<string, CatalogPreset>()
  for (const preset of presets) {
    const ancestor = findNearestCatalogAncestorInIndex(
      index,
      preset.id,
      candidateIds
    )
    if (ancestor) {
      result.set(preset.id, ancestor)
    }
  }
  return result
}

function findNearestCatalogAncestorInIndex(
  index: CatalogRelationIndex,
  presetId: string,
  candidateIds: ReadonlySet<string>
): CatalogPreset | undefined {
  const visited = new Set([presetId])
  let frontier = [presetId]
  while (frontier.length > 0) {
    const parents = [
      ...new Set(
        frontier.flatMap((id) => [...(index.parentsByChild.get(id) ?? [])])
      ),
    ]
      .filter((id) => !visited.has(id))
      .sort()

    const nearest = parents.find((id) => candidateIds.has(id))
    if (nearest) {
      return index.byId.get(nearest)
    }

    parents.forEach((id) => visited.add(id))
    frontier = parents
  }
  return undefined
}

/**
 * Produces a complete relation map without persisting derived catalogue state.
 * Only a fully installed aggregate covers descendants. A partial aggregate is
 * deliberately excluded so a missing IP companion cannot be mistaken for a
 * complete Meta/Telegram installation. An exact complete child still wins;
 * otherwise its fully installed ancestor is authoritative even when the child
 * happens to share one already-installed companion with that ancestor.
 */
export function resolveCatalogInstallStates(
  presets: readonly CatalogPreset[],
  lists: Readonly<Record<string, ListConfig>> | undefined
): ReadonlyMap<string, CatalogPresetInstallState> {
  const baseStates = new Map<string, CatalogPresetInstallState>()
  const fullyInstalledIds = new Set<string>()

  for (const preset of presets) {
    const primaryListId = findCatalogPresetInstalledListId(preset, lists)
    const companionListIds: string[] = []
    const missingCompanionIds: string[] = []

    for (const companion of preset.routingCompanions ?? []) {
      const listId = findListIdByCatalogIdentity(
        companion.catalog_identity,
        lists
      )
      if (listId) {
        companionListIds.push(listId)
      } else {
        missingCompanionIds.push(companion.id)
      }
    }

    const primaryRequired = hasCatalogPrimarySource(preset)
    const requiredCount =
      (primaryRequired ? 1 : 0) + (preset.routingCompanions?.length ?? 0)
    const installedCount = (primaryListId ? 1 : 0) + companionListIds.length
    const kind: CatalogPresetInstallKind =
      requiredCount > 0 && installedCount === requiredCount
        ? "installed"
        : installedCount > 0
          ? "partial"
          : "missing"

    if (kind === "installed") {
      fullyInstalledIds.add(preset.id)
    }
    baseStates.set(preset.id, {
      kind,
      primaryListId,
      companionListIds,
      missingCompanionIds,
    })
  }

  const result = new Map<string, CatalogPresetInstallState>()
  const installedAncestors = resolveCatalogAncestorMap(
    presets,
    fullyInstalledIds
  )
  for (const preset of presets) {
    const baseState = baseStates.get(preset.id)
    if (!baseState || baseState.kind === "installed") {
      result.set(
        preset.id,
        baseState ?? {
          kind: "missing",
          companionListIds: [],
          missingCompanionIds: [],
        }
      )
      continue
    }

    const coveredBy = installedAncestors.get(preset.id)
    result.set(
      preset.id,
      coveredBy ? { ...baseState, kind: "covered", coveredBy } : baseState
    )
  }

  return result
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

function hasCatalogPrimarySource(preset: CatalogPreset): boolean {
  const summary = getCatalogPresetSourceSummary(preset)
  return summary.urlBacked || summary.domainCount > 0 || summary.cidrCount > 0
}

function findListIdByCatalogIdentity(
  catalogIdentity: string | undefined,
  lists: Readonly<Record<string, ListConfig>> | undefined
): string | undefined {
  if (!catalogIdentity || !lists) {
    return undefined
  }
  return Object.entries(lists).find(
    ([, list]) => list.catalog_identity === catalogIdentity
  )?.[0]
}

function isIpRoutingCompanion(companion: CatalogRoutingCompanion): boolean {
  return (
    companion.kind === "ip" ||
    companion.include === "ip_cidrs" ||
    Boolean(companion.url)
  )
}

function createCatalogRelationIndex(
  presets: readonly CatalogPreset[]
): CatalogRelationIndex {
  const byId = new Map(presets.map((preset) => [preset.id, preset]))
  const parentsByChild = new Map<string, Set<string>>()
  for (const preset of presets) {
    for (const childId of preset.covers ?? []) {
      if (childId === preset.id || !byId.has(childId)) {
        continue
      }
      const parents = parentsByChild.get(childId) ?? new Set<string>()
      parents.add(preset.id)
      parentsByChild.set(childId, parents)
    }
  }
  return { byId, parentsByChild }
}
