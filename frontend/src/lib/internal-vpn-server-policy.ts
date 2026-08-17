import type {
  InternalVpnServer,
  NdmsVpnServerService,
  RuntimeInterfaceInventoryEntry,
} from "@/api/generated/model"
import type { NativeInterfaceModel } from "@/lib/native-interfaces"

/**
 * Readonly view used by the controlled settings field.
 */
export type InternalVpnServerPolicyOverride = Readonly<InternalVpnServer>

export interface InternalVpnServerOption {
  /** NDMS inventory ID for a real row; a synthetic key for a missing row. */
  readonly key: string
  readonly ndmsId?: string
  readonly interfaceName: string
  readonly label: string
  readonly logicalName?: string
  readonly protocol?: string
  readonly runtime?: RuntimeInterfaceInventoryEntry
  readonly requiresRoleConfirmation: boolean
  readonly missing: boolean
}

interface BuildServerOptions {
  readonly nativeInterfaces: readonly NativeInterfaceModel[]
  readonly overrides?: readonly InternalVpnServerPolicyOverride[]
  /**
   * Pass only a fresh, authoritative running-config observation. Pooled
   * L2TP/IKE/SSTP/OpenConnect services supersede their legacy interface row;
   * saved interface overrides remain untouched and return as fallback if the
   * service observation later disappears.
   */
  readonly authoritativeServices?: readonly NdmsVpnServerService[]
}

interface ProcessClientsOptions {
  readonly ndmsId?: string
  readonly interfaceName: string
  readonly overrides?: readonly InternalVpnServerPolicyOverride[]
  readonly legacyInboundInterfaces?: readonly string[]
}

interface UpdateOverrideOptions extends ProcessClientsOptions {
  readonly baselineOverrides?: readonly InternalVpnServerPolicyOverride[]
  readonly processClients: boolean
  /**
   * Persist the row even when the value equals the legacy derived value.
   * Used when a role-less WG/AWG candidate requires an explicit declaration.
   */
  readonly forceExplicit?: boolean
}

interface RemoveOverrideOptions {
  readonly ndmsId?: string
  readonly interfaceName: string
  readonly overrides?: readonly InternalVpnServerPolicyOverride[]
  readonly baselineOverrides?: readonly InternalVpnServerPolicyOverride[]
}

interface ReconcileOverridesOptions {
  readonly overrides?: readonly InternalVpnServerPolicyOverride[]
  readonly baselineOverrides?: readonly InternalVpnServerPolicyOverride[]
  readonly legacyInboundInterfaces?: readonly string[]
  readonly baselineLegacyInboundInterfaces?: readonly string[]
  readonly rolelessConfirmationNdmsIds?: readonly string[]
}

export type InternalVpnServerRuntimeState = "loading" | "ready" | "error"
export type InternalVpnServerStatus = "up" | "down" | "missing" | "unknown"

/**
 * NDMS is authoritative for the stable identity. Reported server roles remain
 * authoritative. KeeneticOS versions that omit the WG/AWG role can expose a
 * fail-closed structural candidate, but the user must explicitly confirm it;
 * legacy inherited behavior never counts as confirmation.
 * Management mutation readiness is intentionally irrelevant for this
 * read-only policy.
 *
 * Persisted overrides whose interface disappeared from inventory remain as
 * synthetic rows. A temporary RCI/kernel inventory failure must never make a
 * saved policy impossible to inspect or remove.
 */
export function buildInternalVpnServerOptions({
  nativeInterfaces,
  overrides,
  authoritativeServices,
}: BuildServerOptions): InternalVpnServerOption[] {
  const options: InternalVpnServerOption[] = []
  const normalizedOverrides = normalizeInternalVpnServerOverrides(
    overrides ?? []
  )
  const consumedOverrides = new Set<string>()
  const visibleNdmsIds = new Set<string>()
  const visibleInterfaces = new Set<string>()
  const supersededNdmsIds = new Set<string>()
  const supersededInterfaces = new Set<string>()

  for (const nativeInterface of nativeInterfaces) {
    const ndmsId = normalizeOptionalValue(nativeInterface.source.id)
    if (
      nativeVpnInterfaceIsSupersededByService(
        nativeInterface,
        authoritativeServices ?? []
      )
    ) {
      if (ndmsId) {
        supersededNdmsIds.add(ndmsId)
      }
      if (nativeInterface.kernelName) {
        supersededInterfaces.add(nativeInterface.kernelName)
      }
      continue
    }
    if (
      !nativeInterface.source.internal_vpn_server_candidate ||
      !isSupportedNativeVpnServerKind(nativeInterface.source.kind) ||
      !nativeInterface.kernelName ||
      (ndmsId ? visibleNdmsIds.has(ndmsId) : false) ||
      visibleInterfaces.has(nativeInterface.kernelName)
    ) {
      continue
    }

    if (ndmsId) {
      visibleNdmsIds.add(ndmsId)
    }
    visibleInterfaces.add(nativeInterface.kernelName)
    const matchedOverride = findInternalVpnServerOverride(normalizedOverrides, {
      ndmsId,
      interfaceName: nativeInterface.kernelName,
    })
    if (matchedOverride) {
      consumedOverrides.add(internalVpnServerOverrideKey(matchedOverride))
    }
    options.push({
      key: nativeInterface.id,
      ndmsId,
      interfaceName: nativeInterface.kernelName,
      label: nativeInterface.label,
      logicalName: nativeInterface.logicalName,
      protocol: nativeInterface.protocol.label,
      runtime: nativeInterface.runtime,
      requiresRoleConfirmation:
        nativeInterface.source.internal_vpn_server_role_confirmation_required,
      missing: false,
    })
  }

  for (const override of normalizedOverrides) {
    if (consumedOverrides.has(internalVpnServerOverrideKey(override))) {
      continue
    }

    const ndmsId = normalizeOptionalValue(override.ndms_id)
    if (
      (ndmsId && supersededNdmsIds.has(ndmsId)) ||
      supersededInterfaces.has(override.interface)
    ) {
      continue
    }
    options.push({
      key: ndmsId ? `missing:ndms:${ndmsId}` : `missing:${override.interface}`,
      ndmsId,
      interfaceName: override.interface,
      label: override.interface,
      requiresRoleConfirmation: false,
      missing: true,
    })
  }

  return options
}

export function nativeVpnInterfaceIsSupersededByService(
  nativeInterface: NativeInterfaceModel,
  authoritativeServices: readonly NdmsVpnServerService[]
): boolean {
  const identifiers = new Set(
    [
      nativeInterface.source.id,
      nativeInterface.source.firmware_interface_name,
      nativeInterface.logicalName,
      nativeInterface.kernelName,
    ]
      .map(normalizeOptionalValue)
      .filter((value): value is string => Boolean(value))
  )

  return authoritativeServices.some((service) => {
    const boundInterface = normalizeOptionalValue(service.bound_interface_id)
    if (boundInterface && identifiers.has(boundInterface)) {
      return true
    }
    switch (service.kind) {
      case "l2tp":
        return nativeInterface.source.kind === "l2tp"
      case "ikev1":
      case "ikev2":
        return nativeInterface.source.kind === "ike"
      case "sstp":
        return nativeInterface.source.kind === "sstp"
      case "openconnect":
        return nativeInterface.source.kind === "openconnect"
    }
    return false
  })
}

/**
 * Explicit overrides win. Without one, preserve the exact legacy behavior:
 * omitted/empty `route.inbound_interfaces` processes every ingress; a
 * non-empty list processes only exact Linux interface-name matches.
 */
export function getInternalVpnServerProcessClients({
  ndmsId,
  interfaceName,
  overrides,
  legacyInboundInterfaces,
}: ProcessClientsOptions): boolean {
  const normalizedInterface = interfaceName.trim()
  const explicit = findInternalVpnServerOverride(
    normalizeInternalVpnServerOverrides(overrides ?? []),
    {
      ndmsId,
      interfaceName: normalizedInterface,
    }
  )
  if (explicit) {
    return explicit.process_clients
  }

  return getLegacyProcessClients(normalizedInterface, legacyInboundInterfaces)
}

/**
 * Update one override without materializing all values derived from the legacy
 * allowlist. If the edited value returns to a baseline that had no explicit
 * row, the row is removed. If all rows then equal the original baseline, the
 * exact baseline representation (including `undefined`) is returned so the
 * parent form becomes pristine again.
 */
export function updateInternalVpnServerOverride({
  ndmsId,
  interfaceName,
  processClients,
  forceExplicit = false,
  overrides,
  baselineOverrides,
  legacyInboundInterfaces,
}: UpdateOverrideOptions): InternalVpnServerPolicyOverride[] | undefined {
  const normalizedInterface = interfaceName.trim()
  if (!normalizedInterface) {
    return restoreExactBaselineWhenEqual(overrides, baselineOverrides)
  }

  const normalizedNdmsId = normalizeOptionalValue(ndmsId)
  const normalizedOverrides = normalizeInternalVpnServerOverrides(
    overrides ?? []
  )
  const normalizedBaseline = normalizeInternalVpnServerOverrides(
    baselineOverrides ?? []
  )
  const currentMatch = findInternalVpnServerOverride(normalizedOverrides, {
    ndmsId: normalizedNdmsId,
    interfaceName: normalizedInterface,
  })
  const baselineMatch = findInternalVpnServerOverride(normalizedBaseline, {
    ndmsId: normalizedNdmsId,
    interfaceName: normalizedInterface,
  })
  const next = new Map(
    normalizedOverrides.map((override) => [
      internalVpnServerOverrideKey(override),
      override,
    ])
  )
  const legacyValue = getLegacyProcessClients(
    normalizedInterface,
    legacyInboundInterfaces
  )

  if (currentMatch) {
    next.delete(internalVpnServerOverrideKey(currentMatch))
  }
  next.delete(
    internalVpnServerSelectorKey({
      ndmsId: normalizedNdmsId,
      interfaceName: normalizedInterface,
    })
  )

  if (baselineMatch && processClients === baselineMatch.process_clients) {
    next.set(internalVpnServerOverrideKey(baselineMatch), baselineMatch)
  } else if (
    !baselineMatch &&
    processClients === legacyValue &&
    !forceExplicit
  ) {
    // Returning to inherited behavior removes a newly-created explicit row.
  } else {
    const effectiveNdmsId =
      normalizedNdmsId ?? normalizeOptionalValue(currentMatch?.ndms_id)
    // A policy-only edit must not silently migrate the persisted Linux
    // fallback when NDMS reports the same stable server under a new kernel
    // name. Besides making an unrelated change, that can collide with the
    // fallback of another saved server after interface renumbering. Fallback
    // migration belongs to a separate operation that can validate the whole
    // collection before replacing the old name.
    const persistedInterface =
      currentMatch?.interface ?? baselineMatch?.interface ?? normalizedInterface
    const nextOverride: InternalVpnServerPolicyOverride = {
      interface: persistedInterface,
      process_clients: processClients,
      ...(effectiveNdmsId ? { ndms_id: effectiveNdmsId } : {}),
    }
    next.set(internalVpnServerOverrideKey(nextOverride), nextOverride)
  }

  return restoreExactBaselineWhenEqual([...next.values()], baselineOverrides)
}

export function hasInternalVpnServerOverride(
  interfaceName: string,
  overrides?: readonly InternalVpnServerPolicyOverride[],
  ndmsId?: string
): boolean {
  const normalizedInterface = interfaceName.trim()
  return Boolean(
    findInternalVpnServerOverride(
      normalizeInternalVpnServerOverrides(overrides ?? []),
      {
        ndmsId,
        interfaceName: normalizedInterface,
      }
    )
  )
}

/**
 * Remove an explicit row so the server follows the legacy ingress policy
 * again. An empty result is represented by `undefined`, which omits the
 * optional override collection instead of persisting a misleading empty row.
 */
export function removeInternalVpnServerOverride({
  ndmsId,
  interfaceName,
  overrides,
  baselineOverrides,
}: RemoveOverrideOptions): InternalVpnServerPolicyOverride[] | undefined {
  const normalizedInterface = interfaceName.trim()
  if (!normalizedInterface) {
    return restoreExactBaselineWhenEqual(overrides, baselineOverrides)
  }

  const normalized = normalizeInternalVpnServerOverrides(overrides ?? [])
  const matchedOverride = findInternalVpnServerOverride(normalized, {
    ndmsId,
    interfaceName: normalizedInterface,
  })
  if (!matchedOverride) {
    return restoreExactBaselineWhenEqual(normalized, baselineOverrides)
  }

  const matchedKey = internalVpnServerOverrideKey(matchedOverride)
  const next = normalized.filter(
    (override) => internalVpnServerOverrideKey(override) !== matchedKey
  )
  if (next.length === 0) {
    return baselineOverrides?.length === 0 ? [] : undefined
  }
  return restoreExactBaselineWhenEqual(next, baselineOverrides)
}

/**
 * Restore the exact baseline representation after the user returns both the
 * legacy ingress allowlist and every explicit server policy to their original
 * effective meaning. While the allowlist is still different, explicit choices
 * are preserved so an intermediate edit cannot silently erase user intent.
 */
export function reconcileInternalVpnServerOverrides({
  overrides,
  baselineOverrides,
  legacyInboundInterfaces,
  baselineLegacyInboundInterfaces,
  rolelessConfirmationNdmsIds,
}: ReconcileOverridesOptions): InternalVpnServerPolicyOverride[] | undefined {
  const normalized = normalizeInternalVpnServerOverrides(overrides ?? [])
  const normalizedBaseline = normalizeInternalVpnServerOverrides(
    baselineOverrides ?? []
  )

  if (
    !interfaceNameSetsEqual(
      legacyInboundInterfaces,
      baselineLegacyInboundInterfaces
    )
  ) {
    return restoreExactBaselineWhenEqual(normalized, baselineOverrides)
  }

  // A stable-ID row absent from the baseline can represent the user's
  // explicit confirmation of a role-less WG/AWG server. Even when its
  // process_clients value equals the legacy policy, restoring the baseline
  // would silently erase that declaration.
  const rolelessConfirmationIds = new Set(
    (rolelessConfirmationNdmsIds ?? [])
      .map((value) => normalizeOptionalValue(value))
      .filter((value): value is string => Boolean(value))
  )
  const baselineStableIds = new Set(
    normalizedBaseline
      .map((override) => normalizeOptionalValue(override.ndms_id))
      .filter((value): value is string => Boolean(value))
  )
  const hasNewStableDeclaration = normalized.some((override) => {
    const ndmsId = normalizeOptionalValue(override.ndms_id)
    return Boolean(
      ndmsId &&
        rolelessConfirmationIds.has(ndmsId) &&
        !baselineStableIds.has(ndmsId)
    )
  })
  if (hasNewStableDeclaration) {
    return normalized
  }

  const selectors = new Map<
    string,
    { readonly ndmsId?: string; readonly interfaceName: string }
  >()
  for (const override of [...normalized, ...normalizedBaseline]) {
    const selector = {
      ndmsId: normalizeOptionalValue(override.ndms_id),
      interfaceName: override.interface,
    }
    selectors.set(internalVpnServerSelectorKey(selector), selector)
  }
  const hasSameEffectivePolicy = [...selectors.values()].every(
    ({ ndmsId, interfaceName }) =>
      getInternalVpnServerProcessClients({
        ndmsId,
        interfaceName,
        overrides: normalized,
        legacyInboundInterfaces,
      }) ===
      getInternalVpnServerProcessClients({
        ndmsId,
        interfaceName,
        overrides: normalizedBaseline,
        legacyInboundInterfaces: baselineLegacyInboundInterfaces,
      })
  )

  return hasSameEffectivePolicy
    ? baselineOverrides === undefined
      ? undefined
      : baselineOverrides.map((override) => ({ ...override }))
    : normalized
}

export function getInternalVpnServerStatus({
  server,
  inventoryReady,
  runtimeState,
}: {
  readonly server: InternalVpnServerOption
  readonly inventoryReady: boolean
  readonly runtimeState: InternalVpnServerRuntimeState
}): InternalVpnServerStatus {
  if (!inventoryReady) {
    return "unknown"
  }
  if (server.missing) {
    return "missing"
  }
  if (runtimeState !== "ready") {
    return "unknown"
  }
  return server.runtime?.status === "up" ? "up" : "down"
}

export function normalizeInternalVpnServerInterfaceNames(
  values: readonly string[]
): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))].sort(
    (left, right) => left.localeCompare(right)
  )
}

export function normalizeInternalVpnServerOverrides(
  values: readonly InternalVpnServerPolicyOverride[]
): InternalVpnServerPolicyOverride[] {
  const byIdentity = new Map<string, InternalVpnServerPolicyOverride>()
  for (const value of values) {
    const interfaceName = value.interface.trim()
    if (!interfaceName) {
      continue
    }
    const ndmsId = normalizeOptionalValue(value.ndms_id)
    const normalized: InternalVpnServerPolicyOverride = {
      interface: interfaceName,
      process_clients: value.process_clients,
      ...(ndmsId ? { ndms_id: ndmsId } : {}),
    }
    byIdentity.set(internalVpnServerOverrideKey(normalized), normalized)
  }

  return [...byIdentity.values()].sort((left, right) =>
    internalVpnServerOverrideKey(left).localeCompare(
      internalVpnServerOverrideKey(right)
    )
  )
}

function getLegacyProcessClients(
  interfaceName: string,
  legacyInboundInterfaces?: readonly string[]
): boolean {
  const legacyNames = normalizeInternalVpnServerInterfaceNames(
    legacyInboundInterfaces ?? []
  )
  return legacyNames.length === 0 || legacyNames.includes(interfaceName)
}

function interfaceNameSetsEqual(
  left?: readonly string[],
  right?: readonly string[]
): boolean {
  const normalizedLeft = normalizeInternalVpnServerInterfaceNames(left ?? [])
  const normalizedRight = normalizeInternalVpnServerInterfaceNames(right ?? [])
  return (
    normalizedLeft.length === normalizedRight.length &&
    normalizedLeft.every((value, index) => value === normalizedRight[index])
  )
}

function findInternalVpnServerOverride(
  overrides: readonly InternalVpnServerPolicyOverride[],
  {
    ndmsId,
    interfaceName,
  }: {
    readonly ndmsId?: string
    readonly interfaceName: string
  }
): InternalVpnServerPolicyOverride | undefined {
  const normalizedNdmsId = normalizeOptionalValue(ndmsId)
  const normalizedInterface = interfaceName.trim()

  if (normalizedNdmsId) {
    const stableMatch = overrides.find(
      (override) =>
        normalizeOptionalValue(override.ndms_id) === normalizedNdmsId
    )
    if (stableMatch) {
      return stableMatch
    }

    return overrides.find(
      (override) =>
        !normalizeOptionalValue(override.ndms_id) &&
        override.interface === normalizedInterface
    )
  }

  return overrides.find(
    (override) => override.interface === normalizedInterface
  )
}

function internalVpnServerOverrideKey(
  override: InternalVpnServerPolicyOverride
): string {
  return internalVpnServerSelectorKey({
    ndmsId: override.ndms_id,
    interfaceName: override.interface,
  })
}

function internalVpnServerSelectorKey({
  ndmsId,
  interfaceName,
}: {
  readonly ndmsId?: string
  readonly interfaceName: string
}): string {
  const normalizedNdmsId = normalizeOptionalValue(ndmsId)
  return normalizedNdmsId
    ? `ndms:${normalizedNdmsId}`
    : `interface:${interfaceName.trim()}`
}

function isSupportedNativeVpnServerKind(kind: string): boolean {
  return (
    kind === "wireguard" ||
    kind === "amnezia_wireguard" ||
    kind === "openvpn" ||
    kind === "ike" ||
    kind === "l2tp" ||
    kind === "sstp" ||
    kind === "openconnect"
  )
}

function normalizeOptionalValue(value?: string | null): string | undefined {
  const normalized = value?.trim()
  return normalized ? normalized : undefined
}

function restoreExactBaselineWhenEqual(
  values: readonly InternalVpnServerPolicyOverride[] | undefined,
  baseline: readonly InternalVpnServerPolicyOverride[] | undefined
): InternalVpnServerPolicyOverride[] | undefined {
  const normalized = normalizeInternalVpnServerOverrides(values ?? [])
  const normalizedBaseline = normalizeInternalVpnServerOverrides(baseline ?? [])
  if (overridesEqual(normalized, normalizedBaseline)) {
    return baseline === undefined
      ? undefined
      : baseline.map((value) => ({ ...value }))
  }
  return normalized
}

function overridesEqual(
  left: readonly InternalVpnServerPolicyOverride[],
  right: readonly InternalVpnServerPolicyOverride[]
): boolean {
  return (
    left.length === right.length &&
    left.every(
      (value, index) =>
        value.interface === right[index]?.interface &&
        value.ndms_id === right[index]?.ndms_id &&
        value.process_clients === right[index]?.process_clients
    )
  )
}
