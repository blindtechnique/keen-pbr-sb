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
}>

export type TrafficChartPreferences = Readonly<{
  initialized: boolean
  states: Readonly<Record<string, boolean>>
}>

export const TRAFFIC_CHART_PREFERENCES_STORAGE_KEY =
  "keen-pbr.dashboard.traffic-charts.v1"

const TRAFFIC_CHART_PREFERENCES_VERSION = 1

const ACTIVE_TRAFFIC_STATUS_TRANSLATION_KEYS = {
  active: "overview.outbounds.member.active",
  backup: "overview.outbounds.member.backup",
  degraded: "overview.outbounds.member.degraded",
  unavailable: "overview.outbounds.member.unavailable",
  unknown: "overview.outbounds.member.unknown",
} as const satisfies Record<RuntimeInterfaceStatus, string>

export function activeTrafficStatusTranslationKey(
  status: RuntimeInterfaceStatus
) {
  return ACTIVE_TRAFFIC_STATUS_TRANSLATION_KEYS[status]
}

export function parseTrafficChartPreferences(
  raw: string | null
): TrafficChartPreferences {
  if (!raw) return emptyTrafficChartPreferences()

  try {
    const parsed: unknown = JSON.parse(raw)
    if (
      !isRecord(parsed) ||
      parsed.version !== TRAFFIC_CHART_PREFERENCES_VERSION
    ) {
      return emptyTrafficChartPreferences()
    }
    if (!isRecord(parsed.states)) return emptyTrafficChartPreferences()

    const states: Record<string, boolean> = {}
    for (const [interfaceName, expanded] of Object.entries(parsed.states)) {
      if (interfaceName.length > 0 && typeof expanded === "boolean") {
        states[interfaceName] = expanded
      }
    }
    return { initialized: true, states }
  } catch {
    return emptyTrafficChartPreferences()
  }
}

export function serializeTrafficChartPreferences(
  preferences: TrafficChartPreferences
): string {
  return JSON.stringify({
    version: TRAFFIC_CHART_PREFERENCES_VERSION,
    states: preferences.states,
  })
}

export function isTrafficChartExpanded(
  preferences: TrafficChartPreferences,
  interfaceName: string,
  index: number
): boolean {
  const stored = preferences.states[interfaceName]
  if (stored !== undefined) return stored
  return !preferences.initialized && index < 2
}

export function toggleTrafficChartPreference(
  preferences: TrafficChartPreferences,
  interfaceNames: readonly string[],
  interfaceName: string
): TrafficChartPreferences {
  const states: Record<string, boolean> = { ...preferences.states }
  for (const [index, currentName] of interfaceNames.entries()) {
    if (states[currentName] === undefined) {
      states[currentName] = isTrafficChartExpanded(
        preferences,
        currentName,
        index
      )
    }
  }
  states[interfaceName] = !isTrafficChartExpanded(
    preferences,
    interfaceName,
    interfaceNames.indexOf(interfaceName)
  )
  return { initialized: true, states }
}

function emptyTrafficChartPreferences(): TrafficChartPreferences {
  return { initialized: false, states: {} }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

export function collectActiveTrafficPaths(
  outbounds: readonly Outbound[],
  rules: readonly RouteRule[],
  runtimeByTag: ReadonlyMap<string, RuntimeOutboundState>
): ActiveTrafficPath[] {
  const outboundsByTag = new Map(outbounds.map((item) => [item.tag, item]))
  const displayNames = createOutboundDisplayNameMap(outbounds)
  const paths = new Map<string, ActiveTrafficPath>()

  for (const rule of rules) {
    if (rule.enabled === false) continue
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
    return { connected: transport.state === "up" }
  }
  return { connected: runtimeUp }
}

// TransportStatus.updated_at is the latest state observation, not a
// connected-since timestamp. Until runtime exposes an authoritative field, the
// dashboard reports only the live connected state instead of inventing uptime.
