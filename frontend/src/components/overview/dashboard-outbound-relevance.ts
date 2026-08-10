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

/**
 * Списки, которым больше некуда идти.
 *
 * Красный на дашборде должен значить, что у человека действительно что-то не
 * работает, а не что где-то в конфигурации лежит нерабочий туннель. Упавший
 * маршрут ломает трафик ровно тогда, когда на нём висит хотя бы один список
 * включённого правила: этот список осиротел. Туннель без списков и участник
 * группы, которого группа уже заменила, ничего не ломают — это замечание.
 *
 * Маршрут, которого в переданном списке нет вовсе, сиротой НЕ считается:
 * этот список уже отфильтрован `selectDashboardRuntimeOutbounds`, и
 * намеренно остановленный транспорт из него исчезает. Считать исчезновение
 * поломкой значило бы вернуть красный ровно тем, кто сам выключил туннель.
 * Правило, ссылающееся на несуществующий маршрут, — ошибка конфигурации,
 * и о ней сообщает свой блок «отсутствующие ссылки».
 */
export function countOrphanedLists({
  rules,
  outbounds,
}: {
  rules: readonly RouteRule[]
  outbounds: readonly Pick<RuntimeOutboundState, "status" | "tag">[]
}): number {
  const statusByTag = new Map(
    outbounds.map((outbound) => [outbound.tag, outbound.status])
  )
  let orphaned = 0
  for (const [tag, listCount] of countEnabledRouteRuleListsByOutbound(rules)) {
    if (listCount === 0) continue
    if (statusByTag.get(tag) === "unavailable") {
      orphaned += listCount
    }
  }
  return orphaned
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
