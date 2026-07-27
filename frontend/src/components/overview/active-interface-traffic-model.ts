import type {
  Outbound,
  RouteRule,
  RuntimeOutboundState,
  TransportStatus,
} from "@/api/generated/model"
import {
  createOutboundDisplayNameMap,
  getOutboundDisplayName,
} from "@/lib/outbound-display"

export type ActiveTrafficPath = Readonly<{
  interfaceName: string
  label: string
}>

export type InterfaceConnectionState = Readonly<{
  connected: boolean
  connectedAtUnixMs?: number
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

export function interfaceConnectionState(
  interfaceName: string,
  runtimeUp: boolean,
  transports: readonly TransportStatus[]
): InterfaceConnectionState {
  const transport = transports.find(
    (candidate) =>
      candidate.interface === interfaceName && candidate.type !== "native"
  )
  if (transport) {
    return {
      connected: transport.state === "up",
      connectedAtUnixMs:
        transport.state === "up"
          ? parseTimestamp(transport.updated_at)
          : undefined,
    }
  }
  return { connected: runtimeUp }
}

/**
 * Keenetic uses a compact `D.HH:MM:SS`-style duration in its connection badge.
 * Keeping the formatter locale-neutral avoids rerunning Intl on every second.
 */
export function formatConnectionDuration(
  totalSeconds: number,
  daySuffix: string
): string {
  const safeSeconds = Math.max(0, Math.floor(totalSeconds))
  const days = Math.floor(safeSeconds / 86_400)
  const hours = Math.floor((safeSeconds % 86_400) / 3_600)
  const minutes = Math.floor((safeSeconds % 3_600) / 60)
  const seconds = safeSeconds % 60
  const clock = [hours, minutes, seconds]
    .map((part) => part.toString().padStart(2, "0"))
    .join(":")
  return days > 0 ? `${days} ${daySuffix} ${clock}` : clock
}

function parseTimestamp(value: string): number | undefined {
  const parsed = Date.parse(value)
  return Number.isFinite(parsed) ? parsed : undefined
}
