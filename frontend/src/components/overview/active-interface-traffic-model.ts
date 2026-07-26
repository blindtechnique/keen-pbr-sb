import type {
  Outbound,
  RouteRule,
  RuntimeOutboundState,
} from "@/api/generated/model"
import {
  createOutboundDisplayNameMap,
  getOutboundDisplayName,
} from "@/lib/outbound-display"

export type ActiveTrafficPath = Readonly<{
  interfaceName: string
  label: string
}>

export function collectActiveTrafficPaths(
  outbounds: readonly Outbound[],
  rules: readonly RouteRule[],
  runtimeByTag: ReadonlyMap<string, RuntimeOutboundState>
): ActiveTrafficPath[] {
  const outboundsByTag = new Map(outbounds.map((item) => [item.tag, item]))
  const displayNames = createOutboundDisplayNameMap(outbounds)
  const paths = new Map<string, ActiveTrafficPath>()

  for (const rule of rules) {
    const configured = outboundsByTag.get(rule.outbound)
    if (!configured) continue

    const runtime = runtimeByTag.get(rule.outbound)
    const active =
      runtime?.interfaces.find((candidate) => candidate.status === "active") ??
      (runtime?.interfaces.length === 1 ? runtime.interfaces[0] : undefined)
    const interfaceName = active?.interface_name ?? configured.interface
    if (!interfaceName || paths.has(interfaceName)) continue

    paths.set(interfaceName, {
      interfaceName,
      label:
        (active?.outbound_tag
          ? displayNames.get(active.outbound_tag)
          : undefined) ?? getOutboundDisplayName(configured),
    })
  }

  return [...paths.values()]
}
