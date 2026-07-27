import type { RuntimeOutboundState } from "@/api/generated/model"

export type LatencyProbe = Readonly<{
  success: boolean
  latency_ms: number
  age_seconds: number
}>

export type InterfaceLatencyProbe = LatencyProbe &
  Readonly<{
    interface?: string
  }>

export type VisibleLatency = Readonly<{
  milliseconds: number
  ageSeconds?: number
}>

type RankedLatency = Readonly<{
  milliseconds: number
  rank: number
}>

/**
 * Runtime state can expose the same interface twice: once as its standalone
 * interface outbound and once as a member of a URL-test group. Prefer the
 * explicitly bound standalone outbound. A failed URL-test historically
 * carried latency_ms=0, so zero and unavailable candidates must never replace
 * a successful measurement.
 */
export function collectRuntimeLatencyByInterface(
  outbounds: readonly RuntimeOutboundState[],
  preferredOutboundTagByInterface: ReadonlyMap<string, string>
): Map<string, number> {
  const selected = new Map<string, RankedLatency>()

  for (const outbound of outbounds) {
    for (const candidate of outbound.interfaces) {
      const interfaceName = candidate.interface_name
      const milliseconds = candidate.latency_ms
      if (
        !interfaceName ||
        !isLatency(milliseconds) ||
        (candidate.status !== "active" && candidate.status !== "backup")
      ) {
        continue
      }

      const preferredTag = preferredOutboundTagByInterface.get(interfaceName)
      const rank =
        outbound.type === "interface" && outbound.tag === preferredTag
          ? 40
          : candidate.outbound_tag === preferredTag
            ? 30
            : outbound.type === "interface"
              ? 20
              : candidate.status === "active"
                ? 11
                : 10
      const current = selected.get(interfaceName)
      if (
        !current ||
        rank > current.rank ||
        (rank === current.rank && milliseconds < current.milliseconds)
      ) {
        selected.set(interfaceName, { milliseconds, rank })
      }
    }
  }

  return new Map(
    [...selected].map(([interfaceName, value]) => [
      interfaceName,
      value.milliseconds,
    ])
  )
}

/**
 * The detailed probe endpoint is keyed by outbound tag, while transport cards
 * are keyed by interface. Resolve collisions deterministically: a successful
 * probe with a real positive latency beats a failed/stale entry, and the
 * explicitly bound standalone outbound wins over a group member.
 */
export function collectProbeByInterface<T extends InterfaceLatencyProbe>(
  probes: Readonly<Record<string, T>>,
  preferredOutboundTagByInterface: ReadonlyMap<string, string>
): Map<string, T> {
  const selected = new Map<
    string,
    Readonly<{ probe: T; preferred: boolean }>
  >()

  for (const [outboundTag, probe] of Object.entries(probes)) {
    const interfaceName = probe.interface
    if (
      !interfaceName ||
      probe.success !== true ||
      !isLatency(probe.latency_ms)
    ) {
      continue
    }

    const preferred =
      preferredOutboundTagByInterface.get(interfaceName) === outboundTag
    const current = selected.get(interfaceName)
    if (
      !current ||
      (preferred && !current.preferred) ||
      (preferred === current.preferred &&
        probe.age_seconds < current.probe.age_seconds)
    ) {
      selected.set(interfaceName, { probe, preferred })
    }
  }

  return new Map(
    [...selected].map(([interfaceName, value]) => [
      interfaceName,
      value.probe,
    ])
  )
}

/**
 * Runtime outbound state is delivered by the shared SSE stream as soon as a
 * probe round completes. Prefer it over the slower probe-details query so a
 * manual measurement never waits for that query's refresh interval.
 */
export function selectVisibleLatency(
  probe: LatencyProbe | undefined,
  runtimeMilliseconds: number | undefined
): VisibleLatency | undefined {
  if (isLatency(runtimeMilliseconds)) {
    return {
      milliseconds: runtimeMilliseconds,
      ageSeconds:
        probe?.success === true && probe.latency_ms === runtimeMilliseconds
          ? nonNegativeInteger(probe.age_seconds)
          : undefined,
    }
  }
  if (probe?.success === true && isLatency(probe.latency_ms)) {
    return {
      milliseconds: probe.latency_ms,
      ageSeconds: nonNegativeInteger(probe.age_seconds),
    }
  }
  return undefined
}

function isLatency(value: number | undefined): value is number {
  return typeof value === "number" && Number.isFinite(value) && value > 0
}

function nonNegativeInteger(value: number): number {
  return Number.isFinite(value) ? Math.max(0, Math.floor(value)) : 0
}
