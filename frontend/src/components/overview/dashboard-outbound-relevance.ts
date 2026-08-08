import type {
  ConfigObject,
  Outbound,
  RouteRule,
  RuntimeOutboundState,
  TransportStatus,
} from "@/api/generated/model"
import { getEffectiveListRefreshRouteChain } from "@/lib/list-refresh-route"

/**
 * Runtime keeps reporting the last state of a managed transport after the user
 * intentionally stops it. That observation is useful on the transport page,
 * but it must not turn the global dashboard red when nothing active depends on
 * the stopped path.
 *
 * Stay conservative: without both an applied configuration and the transport
 * inventory, keep every runtime failure visible.
 */
export function selectDashboardRuntimeOutbounds({
  config,
  runtimeOutbounds,
  transports,
}: {
  config?: ConfigObject
  runtimeOutbounds: readonly RuntimeOutboundState[]
  transports?: readonly TransportStatus[]
}): RuntimeOutboundState[] {
  if (!config || !transports) return [...runtimeOutbounds]

  const requiredTags = collectRequiredOutboundTags(config)
  const outboundsByTag = new Map(
    (config.outbounds ?? []).map((outbound) => [outbound.tag, outbound])
  )
  const disabledManagedTransports = transports.filter(
    (transport) => transport.type !== "native" && !transport.desired_up
  )

  return runtimeOutbounds.filter((runtime) => {
    if (requiredTags.has(runtime.tag)) return true

    return !isBackedOnlyByDisabledManagedTransports({
      runtime,
      configured: outboundsByTag.get(runtime.tag),
      outboundsByTag,
      disabledManagedTransports,
      allManagedTransports: transports.filter(
        (transport) => transport.type !== "native"
      ),
    })
  })
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

/**
 * Outbounds required by active routing, DNS and URL-list refresh dependencies.
 * Selector children are expanded recursively, so an intentionally stopped
 * member of an in-use failover group remains a truthful error.
 */
export function collectRequiredOutboundTags(config: ConfigObject): Set<string> {
  const roots = new Set<string>()

  for (const rule of config.route?.rules ?? []) {
    if (rule.enabled !== false && rule.outbound) roots.add(rule.outbound)
  }

  const activeDnsServerTags = new Set(config.dns?.fallback ?? [])
  for (const rule of config.dns?.rules ?? []) {
    if (rule.enabled !== false && rule.server) {
      activeDnsServerTags.add(rule.server)
    }
  }
  for (const server of config.dns?.servers ?? []) {
    if (activeDnsServerTags.has(server.tag) && server.detour) {
      roots.add(server.detour)
    }
  }

  for (const list of Object.values(config.lists ?? {})) {
    if (!list.url) continue
    const route = getEffectiveListRefreshRouteChain(list, config.list_refresh)
    if (route.detour) roots.add(route.detour)
    for (const fallback of route.fallbackDetours) roots.add(fallback)
  }

  const outboundsByTag = new Map(
    (config.outbounds ?? []).map((outbound) => [outbound.tag, outbound])
  )
  const required = new Set<string>()
  const visit = (tag: string) => {
    if (!tag || required.has(tag)) return
    required.add(tag)
    const outbound = outboundsByTag.get(tag)
    for (const child of outboundChildren(outbound)) visit(child)
  }
  for (const tag of roots) visit(tag)
  return required
}

function isBackedOnlyByDisabledManagedTransports({
  runtime,
  configured,
  outboundsByTag,
  disabledManagedTransports,
  allManagedTransports,
}: {
  runtime: RuntimeOutboundState
  configured?: Outbound
  outboundsByTag: ReadonlyMap<string, Outbound>
  disabledManagedTransports: readonly TransportStatus[]
  allManagedTransports: readonly TransportStatus[]
}): boolean {
  const identities = collectOutboundTransportIdentities(
    runtime.tag,
    configured,
    outboundsByTag
  )
  for (const member of runtime.interfaces) {
    if (member.outbound_tag) identities.add(member.outbound_tag)
    if (member.interface_name) identities.add(member.interface_name)
  }

  const matchingManaged = allManagedTransports.filter((transport) =>
    transportMatchesIdentities(transport, identities)
  )
  if (matchingManaged.length === 0) return false

  return matchingManaged.every((transport) =>
    disabledManagedTransports.some(
      (disabled) =>
        disabled.tag === transport.tag &&
        disabled.interface === transport.interface
    )
  )
}

function collectOutboundTransportIdentities(
  rootTag: string,
  root: Outbound | undefined,
  outboundsByTag: ReadonlyMap<string, Outbound>
): Set<string> {
  const identities = new Set<string>([rootTag])
  const visited = new Set<string>()
  const visit = (outbound: Outbound | undefined) => {
    if (!outbound || visited.has(outbound.tag)) return
    visited.add(outbound.tag)
    identities.add(outbound.tag)
    if (outbound.interface) identities.add(outbound.interface)
    for (const childTag of outboundChildren(outbound)) {
      identities.add(childTag)
      visit(outboundsByTag.get(childTag))
    }
  }
  visit(root)
  return identities
}

function outboundChildren(outbound: Outbound | undefined): string[] {
  return (outbound?.outbound_groups ?? []).flatMap((group) => group.outbounds)
}

function transportMatchesIdentities(
  transport: TransportStatus,
  identities: ReadonlySet<string>
): boolean {
  return identities.has(transport.tag) || identities.has(transport.interface)
}
