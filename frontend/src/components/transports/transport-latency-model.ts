export type LatencyProbe = Readonly<{
  success: boolean
  latency_ms: number
  age_seconds: number
}>

export type VisibleLatency = Readonly<{
  milliseconds: number
  ageSeconds?: number
}>

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
  return typeof value === "number" && Number.isFinite(value) && value >= 0
}

function nonNegativeInteger(value: number): number {
  return Number.isFinite(value) ? Math.max(0, Math.floor(value)) : 0
}
