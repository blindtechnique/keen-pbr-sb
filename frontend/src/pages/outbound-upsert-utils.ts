import type { Outbound } from "@/api/generated/model/outbound"

export type StrictEnforcementOption = "default" | "enabled" | "disabled"
export type UrltestSelectionMode = NonNullable<Outbound["selection_mode"]>

export type OutboundDraft = {
  tag: string
  type: Outbound["type"]
  interfaceName: string
  gateway: string
  gateway6: string
  table: string
  outbounds: string[][]
  probeUrl: string
  interval: string
  tolerance: string
  selectionMode: UrltestSelectionMode
  retryAttempts: string
  retryInterval: string
  circuitBreakerFailures: string
  circuitBreakerSuccesses: string
  circuitBreakerTimeout: string
  circuitBreakerHalfOpen: string
  strictEnforcement: StrictEnforcementOption
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

  if (draft.type === "interface") {
    return {
      type: "interface",
      tag,
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
      table: parseNumber(draft.table),
    }
  }

  if (draft.type === "urltest") {
    return {
      type: "urltest",
      tag,
      url: draft.probeUrl.trim() || undefined,
      interval_ms: parseNumber(draft.interval),
      tolerance_ms: parseNumber(draft.tolerance),
      selection_mode:
        draft.selectionMode === "priority" ? "priority" : undefined,
      outbound_groups: normalizeOutboundGroups(draft.outbounds).map(
        (group) => ({
          outbounds: group,
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
  }
}

export function normalizeOutboundGroups(groups: string[][]) {
  if (!groups.length) {
    return [[]]
  }

  return groups.map((group) =>
    group.map((value) => value.trim()).filter(Boolean)
  )
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
