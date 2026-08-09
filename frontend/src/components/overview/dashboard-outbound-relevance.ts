import type {
  RouteRule,
  RuntimeOutboundState,
  TransportStatus,
} from "@/api/generated/model"

/**
 * Runtime keeps reporting the last state of a managed transport after the user
 * intentionally stops it. That observation is useful on the transport page,
 * but an explicit manual stop is a lifecycle state, not a global failure.
 *
 * The explicit transport-manager desired state remains authoritative while a
 * configuration draft exists. A failed or unrelated Apply must not resurrect
 * an intentionally stopped transport as a global failure. Active routing
 * breakage is reported independently by routing health; the transport page
 * continues to show the stopped lifecycle state.
 *
 * Without the transport inventory we cannot prove intent, so keep every
 * runtime failure visible.
 */
export function selectDashboardRuntimeOutbounds({
  runtimeOutbounds,
  transports,
}: {
  runtimeOutbounds: readonly RuntimeOutboundState[]
  transports?: readonly TransportStatus[]
}): RuntimeOutboundState[] {
  if (!transports) return [...runtimeOutbounds]

  const disabledManagedTransports = transports.filter(
    (transport) => transport.type !== "native" && !transport.desired_up
  )
  return runtimeOutbounds.filter(
    (runtime) =>
      !isBackedOnlyByDisabledManagedTransports({
        runtime,
        disabledManagedTransports,
        allTransports: transports,
      })
  )
}

/** Enabled rules only: a disabled rule must not make an outbound look used. */
export function countEnabledRouteRuleListsByOutbound(
  rules: readonly RouteRule[]
): Map<string, number> {
  const result = new Map<string, number>()
  for (const rule of rules) {
    if (rule.enabled === false || !rule.outbound) continue
    result.set(
      rule.outbound,
      (result.get(rule.outbound) ?? 0) + (rule.list?.length ?? 0)
    )
  }
  return result
}

function isBackedOnlyByDisabledManagedTransports({
  runtime,
  disabledManagedTransports,
  allTransports,
}: {
  runtime: RuntimeOutboundState
  disabledManagedTransports: readonly TransportStatus[]
  allTransports: readonly TransportStatus[]
}): boolean {
  const identities = new Set<string>([runtime.tag])
  for (const member of runtime.interfaces) {
    if (member.outbound_tag) identities.add(member.outbound_tag)
    if (member.interface_name) identities.add(member.interface_name)
  }

  const matchingTransports = allTransports.filter((transport) =>
    transportMatchesIdentities(transport, identities)
  )
  if (matchingTransports.length === 0) return false

  return matchingTransports.every((transport) =>
    disabledManagedTransports.some(
      (disabled) =>
        disabled.tag === transport.tag &&
        disabled.interface === transport.interface
    )
  )
}

function transportMatchesIdentities(
  transport: TransportStatus,
  identities: ReadonlySet<string>
): boolean {
  return identities.has(transport.tag) || identities.has(transport.interface)
}
