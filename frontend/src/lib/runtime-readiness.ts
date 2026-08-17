export type RuntimeReadinessHealth = {
  status: "running" | "stopped"
  runtime_state:
    | "starting"
    | "running"
    | "restart_required"
    | "applying"
    | "stopped"
    | "broken"
    | "shutting_down"
  resolver_config_hash?: string
  resolver_live_status: "healthy" | "degraded" | "unavailable" | "unknown"
  resolver_config_sync_state?: "converging" | "converged" | "stale"
  runtime_state_reason?: string
}

export type RuntimeReadinessRouting = {
  overall: "ok" | "degraded" | "error"
}

export type RuntimeReadinessTransport = {
  tag: string
  state: "down" | "starting" | "up" | "degraded"
  error?: string
}

export type RuntimeReadinessProbe = {
  health: () => Promise<RuntimeReadinessHealth>
  routing: () => Promise<RuntimeReadinessRouting>
  transports?: () => Promise<RuntimeReadinessTransport[]>
}

type WaitOptions = {
  expectedTransportTags?: readonly string[]
  intervalMs?: number
  timeoutMs?: number
  sleep?: (durationMs: number) => Promise<void>
}

const defaultSleep = (durationMs: number) =>
  new Promise<void>((resolve) => globalThis.setTimeout(resolve, durationMs))

export function describeRuntimeNotReady(
  health: RuntimeReadinessHealth,
  routing: RuntimeReadinessRouting,
  transports: readonly RuntimeReadinessTransport[],
  expectedTransportTags: readonly string[]
): string | null {
  if (health.status !== "running" || health.runtime_state !== "running") {
    return (
      health.runtime_state_reason?.trim() ||
      `routing runtime is ${health.runtime_state}`
    )
  }

  if (
    health.resolver_config_hash &&
    (health.resolver_live_status !== "healthy" ||
      health.resolver_config_sync_state !== "converged")
  ) {
    return health.resolver_config_sync_state === "stale"
      ? "dnsmasq is serving a stale resolver configuration"
      : "dnsmasq resolver configuration is still converging"
  }

  if (routing.overall !== "ok") {
    return `routing health is ${routing.overall}`
  }

  const byTag = new Map(transports.map((transport) => [transport.tag, transport]))
  for (const tag of expectedTransportTags) {
    const transport = byTag.get(tag)
    if (!transport) return `transport ${tag} is missing`
    if (transport.state !== "up") {
      return (
        transport.error?.trim() ||
        `transport ${tag} is ${transport.state}`
      )
    }
  }

  return null
}

/**
 * A lifecycle POST returning 2xx only proves that the control task completed.
 * The dashboard must not report success until routes, firewall, dnsmasq and
 * every explicitly restarted transport agree on the resulting live state.
 */
export async function waitForRuntimeReadiness(
  probe: RuntimeReadinessProbe,
  options: WaitOptions = {}
): Promise<void> {
  const timeoutMs = options.timeoutMs ?? 20_000
  const intervalMs = options.intervalMs ?? 400
  const sleep = options.sleep ?? defaultSleep
  const expectedTransportTags = options.expectedTransportTags ?? []
  const deadline = Date.now() + timeoutMs
  let lastReason = "runtime readiness was not observed"

  do {
    try {
      const [health, routing, transports] = await Promise.all([
        probe.health(),
        probe.routing(),
        expectedTransportTags.length > 0 && probe.transports
          ? probe.transports()
          : Promise.resolve([]),
      ])
      const reason = describeRuntimeNotReady(
        health,
        routing,
        transports,
        expectedTransportTags
      )
      if (!reason) return
      lastReason = reason
    } catch (error) {
      lastReason =
        error instanceof Error ? error.message : "runtime readiness probe failed"
    }

    if (Date.now() >= deadline) break
    await sleep(intervalMs)
  } while (Date.now() < deadline)

  throw new Error(`Runtime did not become ready: ${lastReason}`)
}
