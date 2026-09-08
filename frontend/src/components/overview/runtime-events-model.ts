import type { HealthResponse } from "@/api/generated/model/healthResponse"
import type { RuntimeOutboundState } from "@/api/generated/model/runtimeOutboundState"
import type { TransportStatus } from "@/api/generated/model/transportStatus"

export type RuntimeEventKind =
  | "groupSwitched"
  | "routeDegraded"
  | "routeUnavailable"
  | "routeRecovered"
  | "dnsChanged"
  | "dnsProblem"
  | "dnsRecovered"
  | "runtimeFailed"
  | "runtimeRecovered"
  | "serviceRestarted"
  | "transportUnavailable"
  | "transportRecovered"
  | "transportRestarted"

export type RuntimeEvent = Readonly<{
  id: string
  observedAt: number
  kind: RuntimeEventKind
  tag?: string
  from?: string
  to?: string
}>

type RouteObservation = {
  type: RuntimeOutboundState["type"]
  status: RuntimeOutboundState["status"]
  active?: string
}
type Availability = "healthy" | "failed"
type ServiceObservation = {
  pid?: number
  runtime?: Availability
  dns?: Availability
  dnsHash?: string
  dnsHashAt?: number
}
type TransportObservation = {
  type: string
  availability?: Availability
  pid?: number
}

const HISTORY_LIMIT = 20
const positiveInteger = (value: number | undefined): number | undefined =>
  value !== undefined && Number.isSafeInteger(value) && value > 0
    ? value
    : undefined

function dnsAvailability(service: HealthResponse): Availability | undefined {
  const probe = service.resolver_config_probe_status
  if (
    probe === "query_failed" &&
    service.resolver_live_status === "unavailable"
  )
    return "failed"
  if (
    (service.resolver_live_status === "degraded" &&
      (probe === "missing_txt" || probe === "invalid_txt")) ||
    (service.resolver_live_status === "healthy" &&
      probe === "success" &&
      service.resolver_config_sync_state === "stale")
  )
    return "failed"
  if (
    service.resolver_live_status === "healthy" &&
    probe === "success" &&
    service.resolver_config_sync_state === "converged"
  )
    return "healthy"
  return undefined
}

// Read-only presentation history, not a runtime coordinator or durable audit.
// Callers reset the corresponding baseline after a disconnect/query failure.
// Only compact observation fields survive each sample, never response bodies.
export function createRuntimeEventHistory() {
  let events: readonly RuntimeEvent[] = Object.freeze([])
  let sequence = 0
  let outbounds = new Map<string, RouteObservation>()
  let serviceBaseline: ServiceObservation | undefined
  let transports = new Map<string, TransportObservation>()

  function append(
    kind: RuntimeEventKind,
    now: number,
    fields: Pick<RuntimeEvent, "tag" | "from" | "to"> = {}
  ) {
    const event = Object.freeze({
      id: `runtime:${++sequence}`,
      observedAt: now,
      kind,
      ...fields,
    })
    events = Object.freeze([event, ...events].slice(0, HISTORY_LIMIT))
  }

  function observeOutbounds(
    sample: readonly RuntimeOutboundState[],
    now: number
  ): readonly RuntimeEvent[] {
    if (!Number.isFinite(now)) return events
    const next = new Map<string, RouteObservation>()
    for (const outbound of sample) {
      // Table/blackhole/ignore status does not establish VPN path health.
      if (outbound.type !== "interface" && outbound.type !== "urltest") continue
      const previous = outbounds.get(outbound.tag)
      const comparable = previous?.type === outbound.type ? previous : undefined
      const activeChildren = outbound.interfaces.filter(
        (child) => child.status === "active"
      )
      // Backend ACTIVE means the kernel-selected child also passed its probe
      // (health/runtime_outbound_state.cpp), not the manager's private candidate.
      const active =
        outbound.type === "urltest" && activeChildren.length === 1
          ? activeChildren[0].outbound_tag
          : undefined
      const known = outbound.status !== "unknown"
      const previousKnown =
        comparable && comparable.status !== "unknown" ? comparable : undefined
      if (known && previousKnown) {
        if (active && previousKnown.active && active !== previousKnown.active) {
          append("groupSwitched", now, {
            tag: outbound.tag,
            from: previousKnown.active,
            to: active,
          })
        }
        if (outbound.status !== previousKnown.status) {
          if (outbound.status === "healthy") {
            append("routeRecovered", now, { tag: outbound.tag })
          } else if (outbound.status === "unavailable") {
            append("routeUnavailable", now, { tag: outbound.tag })
          } else if (outbound.status === "degraded") {
            append("routeDegraded", now, { tag: outbound.tag })
          }
        }
      }
      next.set(outbound.tag, {
        type: outbound.type,
        status: outbound.status,
        // A known failure can separate two verified selections. An unknown
        // sample breaks continuity; latency/detail changes never enter it.
        active: known
          ? (active ??
            (activeChildren.length === 0 && outbound.status !== "healthy"
              ? previousKnown?.active
              : undefined))
          : undefined,
      })
    }
    outbounds = next
    return events
  }

  function observeService(
    service: HealthResponse,
    now: number
  ): readonly RuntimeEvent[] {
    if (!Number.isFinite(now)) return events
    const pid = positiveInteger(service.daemon_pid)
    let previous = serviceBaseline
    if (pid && previous?.pid && pid !== previous.pid) {
      append("serviceRestarted", now)
      // A replacement process starts a new observation epoch. It is not proof
      // that every previously failed route or DNS operation recovered.
      previous = undefined
    }
    const runtime: Availability | undefined =
      service.runtime_state === "broken"
        ? "failed"
        : service.runtime_state === "running"
          ? "healthy"
          : undefined
    if (runtime && previous?.runtime && runtime !== previous.runtime)
      append(runtime === "failed" ? "runtimeFailed" : "runtimeRecovered", now)

    const dns = dnsAvailability(service)
    if (dns && previous?.dns && dns !== previous.dns)
      append(dns === "failed" ? "dnsProblem" : "dnsRecovered", now)
    const confirmedHash =
      dns === "healthy" &&
      /^[a-f0-9]{32}$/i.test(service.resolver_config_hash_actual ?? "")
        ? service.resolver_config_hash_actual!.toLowerCase()
        : undefined
    const confirmedAt = positiveInteger(service.resolver_config_hash_actual_ts)
    const currentHash =
      confirmedHash &&
      confirmedAt &&
      (!previous?.dnsHashAt || confirmedAt >= previous.dnsHashAt)
        ? confirmedHash
        : undefined
    if (currentHash && previous?.dnsHash && currentHash !== previous.dnsHash)
      append("dnsChanged", now)

    const converging =
      service.resolver_config_sync_state === "converging" &&
      service.resolver_config_probe_status === "success" &&
      service.resolver_live_status === "healthy"
    serviceBaseline = {
      pid,
      // Recovery commonly bridges broken -> applying -> running. Explicit
      // stop/start resets the baseline instead of fabricating a recovery.
      runtime:
        runtime ??
        (service.runtime_state === "applying" ? previous?.runtime : undefined),
      dns: dns ?? (converging ? previous?.dns : undefined),
      dnsHash:
        currentHash ?? (dns || converging ? previous?.dnsHash : undefined),
      dnsHashAt:
        currentHash && confirmedAt
          ? confirmedAt
          : dns || converging
            ? previous?.dnsHashAt
            : undefined,
    }
    return events
  }

  function observeTransports(
    sample: readonly TransportStatus[],
    now: number
  ): readonly RuntimeEvent[] {
    if (!Number.isFinite(now)) return events
    const next = new Map<string, TransportObservation>()
    for (const transport of sample) {
      // Native administrative up does not prove peer health. Its live route
      // observation above is authoritative; this source describes processes.
      if (transport.type === "native" || !transport.desired_up) continue
      const old = transports.get(transport.tag)
      const previous = old?.type === transport.type ? old : undefined
      const availability: Availability | undefined =
        transport.state === "up"
          ? "healthy"
          : transport.state === "down" || transport.state === "degraded"
            ? "failed"
            : undefined
      const pid =
        transport.state === "up" ? positiveInteger(transport.pid) : undefined
      if (availability && previous?.availability) {
        if (availability !== previous.availability) {
          append(
            availability === "failed"
              ? "transportUnavailable"
              : "transportRecovered",
            now,
            { tag: transport.tag }
          )
        } else if (
          availability === "healthy" &&
          pid &&
          previous.pid &&
          pid !== previous.pid
        ) {
          append("transportRestarted", now, { tag: transport.tag })
        }
      }
      next.set(transport.tag, {
        type: transport.type,
        availability: availability ?? previous?.availability,
        // Preserve the last UP PID across an observed starting state, never
        // across a missing entry, disabled transport or caller baseline reset.
        pid:
          pid ?? (transport.state === "starting" ? previous?.pid : undefined),
      })
    }
    transports = next
    return events
  }

  function resetBaseline(
    source: "outbounds" | "service" | "transports" | "all"
  ) {
    if (source === "all" || source === "outbounds") outbounds.clear()
    if (source === "all" || source === "service") serviceBaseline = undefined
    if (source === "all" || source === "transports") transports.clear()
  }

  return {
    observeOutbounds,
    observeService,
    observeTransports,
    resetBaseline,
    getEvents: () => events,
  }
}
