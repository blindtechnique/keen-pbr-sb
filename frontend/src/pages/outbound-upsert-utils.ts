import type { ConfigObject } from "@/api/generated/model/configObject"
import type { Outbound } from "@/api/generated/model/outbound"

export type StrictEnforcementOption = "default" | "enabled" | "disabled"
export type UrltestSelectionMode = NonNullable<Outbound["selection_mode"]>
export type ConntrackOnSwitchMode = NonNullable<Outbound["conntrack_on_switch"]>
export type ConntrackOnSwitchOption = "default" | ConntrackOnSwitchMode

export type OutboundDraftValidationField =
  | "outboundGroups"
  | "probeUrl"
  | "interval"
  | "probeTimeout"
  | "tolerance"
  | "retryAttempts"
  | "retryInterval"
  | "circuitBreakerFailures"
  | "circuitBreakerSuccesses"
  | "circuitBreakerTimeout"
  | "circuitBreakerHalfOpen"
  | "conntrackOnSwitch"

export type OutboundDraftValidationIssue = {
  field: OutboundDraftValidationField
  code:
    | "groupRequired"
    | "groupStepRequired"
    | "groupDuplicate"
    | "groupMissingReference"
    | "groupCycle"
    | "urlRequired"
    | "urlHttpRequired"
    | "integerRange"
    | "conntrackNested"
    | "conntrackShared"
    | "conntrackRoute"
    | "conntrackDns"
    | "conntrackList"
  index?: number
  target?: string
  minimum?: number
  maximum?: number
}

export type OutboundGroupDraft = {
  outbounds: string[]
  weight: string
}

export type OutboundDraft = {
  displayName: string
  tag: string
  type: Outbound["type"]
  interfaceName: string
  gateway: string
  gateway6: string
  table: string
  outboundGroups: OutboundGroupDraft[]
  probeUrl: string
  interval: string
  probeTimeout: string
  tolerance: string
  selectionMode: UrltestSelectionMode
  conntrackOnSwitch: ConntrackOnSwitchOption
  retryAttempts: string
  retryInterval: string
  circuitBreakerFailures: string
  circuitBreakerSuccesses: string
  circuitBreakerTimeout: string
  circuitBreakerHalfOpen: string
  strictEnforcement: StrictEnforcementOption
}

export function createDefaultOutboundDraft(): OutboundDraft {
  return {
    displayName: "",
    tag: "",
    type: "interface",
    interfaceName: "",
    gateway: "",
    gateway6: "",
    table: "",
    outboundGroups: [{ outbounds: [], weight: "" }],
    probeUrl: "https://www.gstatic.com/generate_204",
    interval: "180000",
    probeTimeout: "5000",
    tolerance: "100",
    selectionMode: "latency",
    conntrackOnSwitch: "default",
    retryAttempts: "3",
    retryInterval: "1000",
    circuitBreakerFailures: "5",
    circuitBreakerSuccesses: "2",
    circuitBreakerTimeout: "30000",
    circuitBreakerHalfOpen: "1",
    strictEnforcement: "default",
  }
}

export function mapOutboundToDraft(outbound: Outbound): OutboundDraft {
  const defaults = createDefaultOutboundDraft()

  return {
    displayName: outbound.display_name ?? "",
    tag: outbound.tag,
    type: outbound.type,
    interfaceName: outbound.interface ?? "",
    gateway: outbound.gateway ?? "",
    gateway6: outbound.gateway6 ?? "",
    table: outbound.table?.toString() ?? "",
    outboundGroups:
      outbound.outbound_groups?.map((group) => ({
        outbounds: [...group.outbounds],
        weight: group.weight?.toString() ?? "",
      })) ?? defaults.outboundGroups,
    probeUrl: outbound.url ?? defaults.probeUrl,
    interval: outbound.interval_ms?.toString() ?? defaults.interval,
    probeTimeout:
      outbound.probe_timeout_ms?.toString() ?? defaults.probeTimeout,
    tolerance: outbound.tolerance_ms?.toString() ?? defaults.tolerance,
    selectionMode: outbound.selection_mode ?? defaults.selectionMode,
    conntrackOnSwitch: outbound.conntrack_on_switch ?? "default",
    retryAttempts:
      outbound.retry?.attempts?.toString() ?? defaults.retryAttempts,
    retryInterval:
      outbound.retry?.interval_ms?.toString() ?? defaults.retryInterval,
    circuitBreakerFailures:
      outbound.circuit_breaker?.failure_threshold?.toString() ??
      defaults.circuitBreakerFailures,
    circuitBreakerSuccesses:
      outbound.circuit_breaker?.success_threshold?.toString() ??
      defaults.circuitBreakerSuccesses,
    circuitBreakerTimeout:
      outbound.circuit_breaker?.timeout_ms?.toString() ??
      defaults.circuitBreakerTimeout,
    circuitBreakerHalfOpen:
      outbound.circuit_breaker?.half_open_max_requests?.toString() ??
      defaults.circuitBreakerHalfOpen,
    strictEnforcement: mapStrictEnforcementToOption(
      outbound.strict_enforcement
    ),
  }
}

/**
 * Produces the exact value persisted by the outbound form.
 *
 * Besides being the submit mapper, this is the semantic dirty-state
 * normalizer: inactive fields, harmless whitespace and alternative numeric
 * representations must not make the editor look modified.
 */
export function normalizeOutboundDraftForPersistence(
  draft: OutboundDraft
): Outbound {
  const tag = draft.tag.trim()
  const displayName = draft.displayName.trim() || undefined

  if (draft.type === "interface") {
    return {
      type: "interface",
      tag,
      ...(displayName ? { display_name: displayName } : {}),
      interface: draft.interfaceName.trim() || undefined,
      gateway: draft.gateway.trim() || undefined,
      gateway6: draft.gateway6.trim() || undefined,
      strict_enforcement: mapStrictEnforcementToBoolean(
        draft.strictEnforcement
      ),
    }
  }

  if (draft.type === "table") {
    return {
      type: "table",
      tag,
      ...(displayName ? { display_name: displayName } : {}),
      table: parseNumber(draft.table),
    }
  }

  if (draft.type === "urltest") {
    return {
      type: "urltest",
      tag,
      ...(displayName ? { display_name: displayName } : {}),
      url: draft.probeUrl.trim() || undefined,
      interval_ms: parseNumber(draft.interval),
      probe_timeout_ms: parseNumber(draft.probeTimeout),
      tolerance_ms: parseNumber(draft.tolerance),
      selection_mode:
        draft.selectionMode === "priority" ? "priority" : undefined,
      conntrack_on_switch:
        draft.conntrackOnSwitch === "default"
          ? undefined
          : draft.conntrackOnSwitch,
      outbound_groups: normalizeOutboundGroups(draft.outboundGroups).map(
        (group) => ({
          outbounds: group.outbounds,
          weight: parseNumber(group.weight),
        })
      ),
      retry: {
        attempts: parseNumber(draft.retryAttempts),
        interval_ms: parseNumber(draft.retryInterval),
      },
      circuit_breaker: {
        failure_threshold: parseNumber(draft.circuitBreakerFailures),
        success_threshold: parseNumber(draft.circuitBreakerSuccesses),
        timeout_ms: parseNumber(draft.circuitBreakerTimeout),
        half_open_max_requests: parseNumber(draft.circuitBreakerHalfOpen),
      },
    }
  }

  return {
    type: draft.type,
    tag,
    ...(displayName ? { display_name: displayName } : {}),
  }
}

export function normalizeOutboundGroups(
  groups: OutboundGroupDraft[]
): OutboundGroupDraft[] {
  if (!groups.length) {
    return [{ outbounds: [], weight: "" }]
  }

  return groups.map((group) => ({
    outbounds: group.outbounds.map((value) => value.trim()).filter(Boolean),
    weight: group.weight.trim(),
  }))
}

export function mapStrictEnforcementToOption(
  value: boolean | undefined
): StrictEnforcementOption {
  if (value === undefined) {
    return "default"
  }

  return value ? "enabled" : "disabled"
}

function mapStrictEnforcementToBoolean(
  value: StrictEnforcementOption
): boolean | undefined {
  if (value === "default") {
    return undefined
  }

  return value === "enabled"
}

function parseNumber(value: string): number | undefined {
  const trimmed = value.trim()

  if (!trimmed) {
    return undefined
  }

  const parsed = Number(trimmed)
  return Number.isFinite(parsed) ? parsed : undefined
}

const UINT32_MAX = 4_294_967_295
const INT32_MAX = 2_147_483_647

/**
 * Client-side mirror of the urltest constraints enforced by validate_config.
 * The server remains authoritative, but the editor must not offer a Save that
 * is already known to be rejected for the exact configuration being posted.
 */
export function validateUrltestOutboundDraft(
  draft: OutboundDraft,
  nextOutbounds: Outbound[],
  config: ConfigObject
): OutboundDraftValidationIssue[] {
  if (draft.type !== "urltest") {
    return []
  }

  const issues: OutboundDraftValidationIssue[] = []
  const addOnce = (issue: OutboundDraftValidationIssue) => {
    if (!issues.some((current) => current.field === issue.field)) {
      issues.push(issue)
    }
  }
  const groups = draft.outboundGroups.map((group) => ({
    outbounds: group.outbounds.map((value) => value.trim()).filter(Boolean),
    weight: group.weight.trim(),
  }))

  if (!groups.length) {
    addOnce({ field: "outboundGroups", code: "groupRequired" })
  }

  const knownTags = new Set(nextOutbounds.map((outbound) => outbound.tag))
  const usedChildren = new Set<string>()
  for (const [index, group] of groups.entries()) {
    if (!group.outbounds.length) {
      addOnce({
        field: "outboundGroups",
        code: "groupStepRequired",
        index: index + 1,
      })
    }

    validateIntegerRange(group.weight, 1, UINT32_MAX, "outboundGroups", addOnce)

    for (const child of group.outbounds) {
      if (usedChildren.has(child)) {
        addOnce({
          field: "outboundGroups",
          code: "groupDuplicate",
          target: child,
        })
      }
      usedChildren.add(child)

      if (!knownTags.has(child)) {
        addOnce({
          field: "outboundGroups",
          code: "groupMissingReference",
          target: child,
        })
      }
    }
  }

  const probeUrl = draft.probeUrl.trim()
  if (!probeUrl) {
    addOnce({ field: "probeUrl", code: "urlRequired" })
  } else if (!/^https?:\/\/.+/i.test(probeUrl)) {
    addOnce({ field: "probeUrl", code: "urlHttpRequired" })
  }

  validateIntegerRange(draft.interval, 1, UINT32_MAX, "interval", addOnce)
  validateIntegerRange(
    draft.probeTimeout,
    1,
    UINT32_MAX,
    "probeTimeout",
    addOnce
  )
  validateIntegerRange(draft.tolerance, 0, UINT32_MAX, "tolerance", addOnce)
  validateIntegerRange(draft.retryAttempts, 1, 1_000, "retryAttempts", addOnce)
  validateIntegerRange(
    draft.retryInterval,
    0,
    UINT32_MAX,
    "retryInterval",
    addOnce
  )
  validateIntegerRange(
    draft.circuitBreakerFailures,
    1,
    INT32_MAX,
    "circuitBreakerFailures",
    addOnce
  )
  validateIntegerRange(
    draft.circuitBreakerSuccesses,
    1,
    UINT32_MAX,
    "circuitBreakerSuccesses",
    addOnce
  )
  validateIntegerRange(
    draft.circuitBreakerTimeout,
    0,
    UINT32_MAX,
    "circuitBreakerTimeout",
    addOnce
  )
  validateIntegerRange(
    draft.circuitBreakerHalfOpen,
    1,
    UINT32_MAX,
    "circuitBreakerHalfOpen",
    addOnce
  )

  if (hasUrltestCycle(nextOutbounds)) {
    addOnce({ field: "outboundGroups", code: "groupCycle" })
  }

  const conntrackIssue = validateConntrackMode(
    draft.conntrackOnSwitch,
    groups.flatMap((group) => group.outbounds),
    nextOutbounds,
    config
  )
  if (conntrackIssue) {
    addOnce(conntrackIssue)
  }

  return issues
}

export function isOutboundGroupsValidationPath(path: string, tag: string) {
  const escapedTag = tag.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
  return new RegExp(
    `^outbounds\\.${escapedTag}\\.outbound_groups(?:\\[\\d+\\])?(?:\\.(?:weight|outbounds)(?:\\[\\d+\\])?)?$`
  ).test(path)
}

function validateIntegerRange(
  rawValue: string,
  minimum: number,
  maximum: number,
  field: OutboundDraftValidationField,
  addIssue: (issue: OutboundDraftValidationIssue) => void
) {
  const value = rawValue.trim()
  if (!value) {
    return
  }

  const parsed = Number(value)
  if (
    !Number.isFinite(parsed) ||
    !Number.isInteger(parsed) ||
    parsed < minimum ||
    parsed > maximum
  ) {
    addIssue({ field, code: "integerRange", minimum, maximum })
  }
}

function hasUrltestCycle(outbounds: Outbound[]) {
  const urltests = new Map(
    outbounds
      .filter((outbound) => outbound.type === "urltest")
      .map((outbound) => [outbound.tag, outbound] as const)
  )
  const visiting = new Set<string>()
  const visited = new Set<string>()

  const visit = (tag: string): boolean => {
    if (visiting.has(tag)) {
      return true
    }
    if (visited.has(tag)) {
      return false
    }

    visiting.add(tag)
    const outbound = urltests.get(tag)
    for (const child of (outbound?.outbound_groups ?? []).flatMap(
      (group) => group.outbounds
    )) {
      if (urltests.has(child) && visit(child)) {
        return true
      }
    }
    visiting.delete(tag)
    visited.add(tag)
    return false
  }

  return [...urltests.keys()].some(visit)
}

function validateConntrackMode(
  mode: ConntrackOnSwitchOption,
  children: string[],
  outbounds: Outbound[],
  config: ConfigObject
): OutboundDraftValidationIssue | null {
  if (mode === "default" || mode === "preserve") {
    return null
  }

  const outboundsByTag = new Map(
    outbounds.map((outbound) => [outbound.tag, outbound] as const)
  )
  const uniqueChildren = [...new Set(children)]
  const nested = uniqueChildren.find(
    (child) => outboundsByTag.get(child)?.type === "urltest"
  )
  if (nested) {
    return {
      field: "conntrackOnSwitch",
      code: "conntrackNested",
      target: nested,
    }
  }

  if (mode !== "delete") {
    return null
  }

  const parentsByChild = new Map<string, Set<string>>()
  for (const outbound of outbounds) {
    if (outbound.type !== "urltest") {
      continue
    }
    for (const child of (outbound.outbound_groups ?? []).flatMap(
      (group) => group.outbounds
    )) {
      const parents = parentsByChild.get(child) ?? new Set<string>()
      parents.add(outbound.tag)
      parentsByChild.set(child, parents)
    }
  }

  const shared = uniqueChildren.find(
    (child) => (parentsByChild.get(child)?.size ?? 0) > 1
  )
  if (shared) {
    return {
      field: "conntrackOnSwitch",
      code: "conntrackShared",
      target: shared,
    }
  }

  const directlyRouted = new Set(
    (config.route?.rules ?? []).map((rule) => rule.outbound)
  )
  const routed = uniqueChildren.find((child) => directlyRouted.has(child))
  if (routed) {
    return {
      field: "conntrackOnSwitch",
      code: "conntrackRoute",
      target: routed,
    }
  }

  const dnsDetours = new Set(
    (config.dns?.servers ?? [])
      .map((server) => server.detour)
      .filter((value): value is string => Boolean(value))
  )
  const dns = uniqueChildren.find((child) => dnsDetours.has(child))
  if (dns) {
    return {
      field: "conntrackOnSwitch",
      code: "conntrackDns",
      target: dns,
    }
  }

  const listDetours = collectEffectiveListDetours(config)
  const list = uniqueChildren.find((child) => listDetours.has(child))
  if (list) {
    return {
      field: "conntrackOnSwitch",
      code: "conntrackList",
      target: list,
    }
  }

  return null
}

function collectEffectiveListDetours(config: ConfigObject) {
  const detours = new Set<string>()
  const global = [
    config.list_refresh?.detour,
    ...(config.list_refresh?.fallback_detours ?? []),
  ].filter((value): value is string => Boolean(value))

  for (const list of Object.values(config.lists ?? {})) {
    if (!list.url) {
      continue
    }

    const hasLocalChain = Boolean(
      list.detour || (list.fallback_detours?.length ?? 0) > 0
    )
    const mode =
      list.refresh_detour_mode ?? (hasLocalChain ? "override" : "inherit")
    const effective =
      mode === "override"
        ? [list.detour, ...(list.fallback_detours ?? [])]
        : global
    for (const detour of effective) {
      if (detour) {
        detours.add(detour)
      }
    }
  }

  return detours
}

/**
 * Отличается ли тонкая настройка группы от умолчаний.
 *
 * Решает, раскрывать ли «Дополнительно» при редактировании: если человек уже
 * менял проверку доступности или circuit breaker, прятать их от него нечестно.
 * `selectionMode` и `conntrackOnSwitch` сюда не входят: по решению владельца
 * они видимы всегда — это поведение группы, а не тонкая настройка.
 */
export function urltestTuningIsDefault(
  draft: Pick<
    OutboundDraft,
    | "probeUrl"
    | "interval"
    | "probeTimeout"
    | "tolerance"
    | "retryAttempts"
    | "retryInterval"
    | "circuitBreakerFailures"
    | "circuitBreakerSuccesses"
    | "circuitBreakerTimeout"
    | "circuitBreakerHalfOpen"
  >
): boolean {
  const defaults = createDefaultOutboundDraft()
  return (
    draft.probeUrl === defaults.probeUrl &&
    draft.interval === defaults.interval &&
    draft.probeTimeout === defaults.probeTimeout &&
    draft.tolerance === defaults.tolerance &&
    draft.retryAttempts === defaults.retryAttempts &&
    draft.retryInterval === defaults.retryInterval &&
    draft.circuitBreakerFailures === defaults.circuitBreakerFailures &&
    draft.circuitBreakerSuccesses === defaults.circuitBreakerSuccesses &&
    draft.circuitBreakerTimeout === defaults.circuitBreakerTimeout &&
    draft.circuitBreakerHalfOpen === defaults.circuitBreakerHalfOpen
  )
}
