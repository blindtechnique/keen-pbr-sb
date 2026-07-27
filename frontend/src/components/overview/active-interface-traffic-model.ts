import type {
  Outbound,
  RouteRule,
  RuntimeInterfaceState,
  RuntimeInterfaceStatus,
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
  status: RuntimeInterfaceStatus
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
    collectPhysicalPaths({
      tag: rule.outbound,
      inheritedStatus: "active",
      ancestorRuntime: [],
      visiting: new Set(),
      outboundsByTag,
      displayNames,
      runtimeByTag,
      paths,
    })
  }

  return [...paths.values()]
}

type CollectPhysicalPathsContext = Readonly<{
  tag: string
  inheritedStatus: RuntimeInterfaceStatus
  ancestorRuntime: readonly (readonly RuntimeInterfaceState[])[]
  visiting: ReadonlySet<string>
  outboundsByTag: ReadonlyMap<string, Outbound>
  displayNames: ReadonlyMap<string, string>
  runtimeByTag: ReadonlyMap<string, RuntimeOutboundState>
  paths: Map<string, ActiveTrafficPath>
}>

function collectPhysicalPaths({
  tag,
  inheritedStatus,
  ancestorRuntime,
  visiting,
  outboundsByTag,
  displayNames,
  runtimeByTag,
  paths,
}: CollectPhysicalPathsContext): void {
  if (visiting.has(tag)) return

  const configured = outboundsByTag.get(tag)
  if (!configured) return

  const runtime = runtimeByTag.get(tag)
  const nextVisiting = new Set(visiting)
  nextVisiting.add(tag)
  const runtimeLayers = runtime
    ? [...ancestorRuntime, runtime.interfaces]
    : ancestorRuntime

  if (configured.type === "interface" && configured.interface) {
    const status = runtimeStatusForLeaf(
      tag,
      configured.interface,
      inheritedStatus,
      runtimeLayers
    )
    mergePhysicalPath(paths, {
      interfaceName: configured.interface,
      label: getOutboundDisplayName(configured),
      status,
    })
    return
  }

  if (configured.type === "urltest") {
    const childTags = uniqueChildTags(configured)
    for (const childTag of childTags) {
      const child = outboundsByTag.get(childTag)
      const candidate = runtime?.interfaces.find(
        (item) =>
          item.outbound_tag === childTag ||
          (child?.interface !== undefined &&
            item.interface_name === child.interface)
      )
      collectPhysicalPaths({
        tag: childTag,
        inheritedStatus: combineRuntimeStatus(
          inheritedStatus,
          candidate?.status ?? "unknown"
        ),
        ancestorRuntime: runtimeLayers,
        visiting: nextVisiting,
        outboundsByTag,
        displayNames,
        runtimeByTag,
        paths,
      })
    }
  }

  // Runtime inventory can resolve a table or a nested selector to a physical
  // interface even when the static configuration does not carry that mapping.
  // Keep these entries as a compatibility fallback and deduplicate them with
  // the recursively discovered configured leaves.
  for (const candidate of runtime?.interfaces ?? []) {
    if (!candidate.interface_name) continue
    mergePhysicalPath(paths, {
      interfaceName: candidate.interface_name,
      label:
        displayNames.get(candidate.outbound_tag) ??
        getOutboundDisplayName(configured),
      status: combineRuntimeStatus(inheritedStatus, candidate.status),
    })
  }
}

function uniqueChildTags(outbound: Outbound): string[] {
  const seen = new Set<string>()
  const result: string[] = []
  for (const group of outbound.outbound_groups ?? []) {
    for (const tag of group.outbounds) {
      if (seen.has(tag)) continue
      seen.add(tag)
      result.push(tag)
    }
  }
  return result
}

function runtimeStatusForLeaf(
  tag: string,
  interfaceName: string,
  inheritedStatus: RuntimeInterfaceStatus,
  runtimeLayers: readonly (readonly RuntimeInterfaceState[])[]
): RuntimeInterfaceStatus {
  let status = inheritedStatus
  for (const layer of runtimeLayers) {
    const candidate = layer.find(
      (item) =>
        item.outbound_tag === tag || item.interface_name === interfaceName
    )
    if (candidate) {
      status = combineRuntimeStatus(status, candidate.status)
    }
  }
  return status
}

function combineRuntimeStatus(
  parent: RuntimeInterfaceStatus,
  child: RuntimeInterfaceStatus
): RuntimeInterfaceStatus {
  if (parent === "unavailable") return "unavailable"
  if (parent === "degraded") {
    return child === "unavailable" ? "unavailable" : "degraded"
  }
  if (parent === "backup") {
    if (child === "unavailable" || child === "degraded") return child
    return "backup"
  }
  if (parent === "unknown") return child
  return child
}

function mergePhysicalPath(
  paths: Map<string, ActiveTrafficPath>,
  next: ActiveTrafficPath
): void {
  const current = paths.get(next.interfaceName)
  if (
    !current ||
    statusPriority(next.status) > statusPriority(current.status)
  ) {
    paths.set(next.interfaceName, next)
  }
}

function statusPriority(status: RuntimeInterfaceStatus): number {
  switch (status) {
    case "active":
      return 5
    case "backup":
      return 4
    case "degraded":
      return 3
    case "unavailable":
      return 2
    case "unknown":
      return 1
  }
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
