import type { Outbound } from "@/api/generated/model/outbound"

export type StrictEnforcementOption = "default" | "enabled" | "disabled"
export type UrltestSelectionMode = NonNullable<Outbound["selection_mode"]>
export type ConntrackOnSwitchMode = NonNullable<
  Outbound["conntrack_on_switch"]
>

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
  conntrackOnSwitch: ConntrackOnSwitchMode
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
    conntrackOnSwitch: "preserve",
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
    conntrackOnSwitch:
      outbound.conntrack_on_switch ?? defaults.conntrackOnSwitch,
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
        draft.conntrackOnSwitch === "preserve"
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
