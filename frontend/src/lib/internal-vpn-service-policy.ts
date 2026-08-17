import type { InternalVpnService } from "@/api/generated/model/internalVpnService"
import type { NdmsVpnServerKind } from "@/api/generated/model/ndmsVpnServerKind"
import type { NdmsVpnServerService } from "@/api/generated/model/ndmsVpnServerService"

export type InternalVpnServicePolicyOverride = Readonly<InternalVpnService>

export interface InternalVpnServiceOption {
  readonly key: string
  readonly serviceId: string
  readonly kind?: NdmsVpnServerKind
  readonly label: string
  readonly enabled: boolean
  readonly sourceCidrs: readonly string[]
  readonly boundInterfaceId?: string | null
  /**
   * Понятное имя интерфейса привязки из NDMS, если backend его отдал.
   * Поле опережает сгенерированную модель: сервер пока присылает только
   * `bound_interface_id`, но как только появится `bound_interface_label`,
   * интерфейс покажет его без дальнейших правок.
   */
  readonly boundInterfaceLabel?: string
  readonly missing: boolean
}

interface BuildOptions {
  readonly services: readonly NdmsVpnServerService[]
  readonly overrides?: readonly InternalVpnServicePolicyOverride[]
}

interface ProcessClientsOptions {
  readonly serviceId: string
  readonly overrides?: readonly InternalVpnServicePolicyOverride[]
  readonly legacyInboundInterfaces?: readonly string[]
}

interface UpdateOverrideOptions extends ProcessClientsOptions {
  readonly processClients: boolean
  readonly baselineOverrides?: readonly InternalVpnServicePolicyOverride[]
}

interface RemoveOverrideOptions {
  readonly serviceId: string
  readonly overrides?: readonly InternalVpnServicePolicyOverride[]
  readonly baselineOverrides?: readonly InternalVpnServicePolicyOverride[]
}

interface ReconcileOverridesOptions {
  readonly overrides?: readonly InternalVpnServicePolicyOverride[]
  readonly baselineOverrides?: readonly InternalVpnServicePolicyOverride[]
  readonly legacyInboundInterfaces?: readonly string[]
  readonly baselineLegacyInboundInterfaces?: readonly string[]
}

export function buildInternalVpnServiceOptions({
  services,
  overrides,
}: BuildOptions): InternalVpnServiceOption[] {
  const normalizedOverrides = normalizeInternalVpnServiceOverrides(
    overrides ?? []
  )
  const byId = new Map<string, InternalVpnServiceOption>()

  for (const service of services) {
    const serviceId = normalizeServiceId(service.id)
    if (!serviceId || byId.has(serviceId)) {
      continue
    }

    const boundInterfaceLabel = (
      service as NdmsVpnServerService & {
        bound_interface_label?: string | null
      }
    ).bound_interface_label
      ?.trim()

    byId.set(serviceId, {
      key: serviceId,
      serviceId,
      kind: service.kind,
      label: service.label.trim() || serviceId,
      enabled: service.enabled,
      sourceCidrs: normalizeCidrs(service.source_cidrs),
      boundInterfaceId: service.bound_interface_id,
      ...(boundInterfaceLabel ? { boundInterfaceLabel } : {}),
      missing: false,
    })
  }

  for (const override of normalizedOverrides) {
    if (byId.has(override.service_id)) {
      continue
    }

    byId.set(override.service_id, {
      key: override.service_id,
      serviceId: override.service_id,
      label: override.service_id,
      enabled: false,
      sourceCidrs: [],
      missing: true,
    })
  }

  return [...byId.values()].sort((left, right) => {
    const kindOrder =
      vpnServiceKindOrder(left.kind) - vpnServiceKindOrder(right.kind)
    return kindOrder || left.label.localeCompare(right.label)
  })
}

export function getInternalVpnServiceProcessClients({
  serviceId,
  overrides,
  legacyInboundInterfaces,
}: ProcessClientsOptions): boolean {
  const normalizedId = normalizeServiceId(serviceId)
  const explicit = normalizeInternalVpnServiceOverrides(overrides ?? []).find(
    (override) => override.service_id === normalizedId
  )
  if (explicit) {
    return explicit.process_clients
  }

  return normalizeInterfaceNames(legacyInboundInterfaces ?? []).length === 0
}

export function hasInternalVpnServiceOverride(
  serviceId: string,
  overrides?: readonly InternalVpnServicePolicyOverride[]
): boolean {
  const normalizedId = normalizeServiceId(serviceId)
  return normalizeInternalVpnServiceOverrides(overrides ?? []).some(
    (override) => override.service_id === normalizedId
  )
}

export function updateInternalVpnServiceOverride({
  serviceId,
  processClients,
  overrides,
  baselineOverrides,
  legacyInboundInterfaces,
}: UpdateOverrideOptions): InternalVpnServicePolicyOverride[] | undefined {
  const normalizedId = normalizeServiceId(serviceId)
  if (!normalizedId) {
    return compactOverrides(overrides, baselineOverrides)
  }

  const current = normalizeInternalVpnServiceOverrides(overrides ?? [])
  const baseline = normalizeInternalVpnServiceOverrides(baselineOverrides ?? [])
  const baselineMatch = baseline.find(
    (override) => override.service_id === normalizedId
  )
  const inheritedValue =
    normalizeInterfaceNames(legacyInboundInterfaces ?? []).length === 0
  const next = new Map(
    current.map((override) => [override.service_id, override] as const)
  )

  if (
    (baselineMatch && baselineMatch.process_clients === processClients) ||
    (!baselineMatch && inheritedValue === processClients)
  ) {
    next.delete(normalizedId)
    if (baselineMatch) {
      next.set(normalizedId, baselineMatch)
    }
  } else {
    next.set(normalizedId, {
      service_id: normalizedId,
      process_clients: processClients,
    })
  }

  return compactOverrides([...next.values()], baselineOverrides)
}

export function removeInternalVpnServiceOverride({
  serviceId,
  overrides,
  baselineOverrides,
}: RemoveOverrideOptions): InternalVpnServicePolicyOverride[] | undefined {
  const normalizedId = normalizeServiceId(serviceId)
  const next = new Map(
    normalizeInternalVpnServiceOverrides(overrides ?? []).map((override) => [
      override.service_id,
      override,
    ])
  )

  next.delete(normalizedId)
  return compactOverrides([...next.values()], baselineOverrides)
}

/**
 * Restore the exact saved representation when both the legacy ingress
 * allowlist and every service's effective policy return to their baseline.
 * This keeps Save/Cancel semantics stable after an intermediate edit.
 */
export function reconcileInternalVpnServiceOverrides({
  overrides,
  baselineOverrides,
  legacyInboundInterfaces,
  baselineLegacyInboundInterfaces,
}: ReconcileOverridesOptions): InternalVpnServicePolicyOverride[] | undefined {
  const normalized = normalizeInternalVpnServiceOverrides(overrides ?? [])
  const normalizedBaseline = normalizeInternalVpnServiceOverrides(
    baselineOverrides ?? []
  )

  if (
    !stringSetsEqual(
      normalizeInterfaceNames(legacyInboundInterfaces ?? []),
      normalizeInterfaceNames(baselineLegacyInboundInterfaces ?? [])
    )
  ) {
    return compactOverrides(normalized, baselineOverrides)
  }

  const serviceIds = new Set(
    [...normalized, ...normalizedBaseline].map(
      (override) => override.service_id
    )
  )
  const hasSameEffectivePolicy = [...serviceIds].every(
    (serviceId) =>
      getInternalVpnServiceProcessClients({
        serviceId,
        overrides: normalized,
        legacyInboundInterfaces,
      }) ===
      getInternalVpnServiceProcessClients({
        serviceId,
        overrides: normalizedBaseline,
        legacyInboundInterfaces: baselineLegacyInboundInterfaces,
      })
  )

  return hasSameEffectivePolicy
    ? baselineOverrides === undefined
      ? undefined
      : baselineOverrides.map((override) => ({ ...override }))
    : normalized.length === 0
      ? undefined
      : normalized
}

export function normalizeInternalVpnServiceOverrides(
  values: readonly InternalVpnServicePolicyOverride[]
): InternalVpnServicePolicyOverride[] {
  const byId = new Map<string, InternalVpnServicePolicyOverride>()
  for (const value of values) {
    const serviceId = normalizeServiceId(value.service_id)
    if (!serviceId) {
      continue
    }
    byId.set(serviceId, {
      service_id: serviceId,
      process_clients: value.process_clients === true,
    })
  }

  return [...byId.values()].sort((left, right) =>
    left.service_id.localeCompare(right.service_id)
  )
}

function compactOverrides(
  values: readonly InternalVpnServicePolicyOverride[] | undefined,
  baseline: readonly InternalVpnServicePolicyOverride[] | undefined
): InternalVpnServicePolicyOverride[] | undefined {
  const normalized = normalizeInternalVpnServiceOverrides(values ?? [])
  const normalizedBaseline = normalizeInternalVpnServiceOverrides(
    baseline ?? []
  )
  if (sameOverrides(normalized, normalizedBaseline)) {
    return baseline === undefined ? undefined : normalizedBaseline
  }
  return normalized.length === 0 ? undefined : normalized
}

function sameOverrides(
  left: readonly InternalVpnServicePolicyOverride[],
  right: readonly InternalVpnServicePolicyOverride[]
): boolean {
  return (
    left.length === right.length &&
    left.every(
      (value, index) =>
        value.service_id === right[index]?.service_id &&
        value.process_clients === right[index]?.process_clients
    )
  )
}

function stringSetsEqual(
  left: readonly string[],
  right: readonly string[]
): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  )
}

function normalizeServiceId(value: string): string {
  return value.trim()
}

function normalizeCidrs(values: readonly string[]): string[] {
  return [
    ...new Set(values.map((value) => value.trim()).filter(Boolean)),
  ].sort()
}

function normalizeInterfaceNames(values: readonly string[]): string[] {
  return [
    ...new Set(values.map((value) => value.trim()).filter(Boolean)),
  ].sort()
}

function vpnServiceKindOrder(kind?: NdmsVpnServerKind): number {
  switch (kind) {
    case "l2tp":
      return 0
    case "ikev1":
      return 1
    case "ikev2":
      return 2
    case "sstp":
      return 3
    case "openconnect":
      return 4
    default:
      return 5
  }
}
