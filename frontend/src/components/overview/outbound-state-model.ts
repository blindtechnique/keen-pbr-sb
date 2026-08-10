import type {
  Outbound,
  RuntimeInterfaceState,
  RuntimeOutboundState,
} from "@/api/generated/model"

export type OutboundRuntimeIssue = Readonly<{
  code:
    | "interfaceUnreachable"
    | "routeMissing"
    | "selectionMismatch"
    | "probeTimeout"
    | "connectionRefused"
    | "networkUnreachable"
    | "dnsFailed"
    | "permissionDenied"
    | "verificationPending"
    | "verificationStale"
    | "cannotVerify"
    | "degraded"
    | "unavailable"
  memberTag?: string
  tone: "warning" | "error"
}>

/**
 * Куда ведёт «Открыть …» из диагностики выхода: тот же раздел, что и в меню,
 * и та вкладка, где эта запись живёт.
 *
 * Раньше это был `/outbounds#interfaces` — путь и якорь той поры, когда
 * туннели и маршруты были разными страницами. Он ещё работает ради старых
 * закладок, но ссылка внутри панели должна вести на нынешний `/transports`:
 * иначе адресная строка после нажатия показывает раздел, которого в меню
 * давно нет. Подпись ссылки берётся из `overview.outbounds.issue.open` и
 * обязана совпадать с названием пункта меню — человек ищет глазами именно
 * его.
 */
export function outboundManagementHref(
  outbound: Pick<Outbound, "type">
): string {
  if (outbound.type === "urltest") return "/transports#failover"
  if (outbound.type === "interface") return "/transports#tunnels"
  return "/transports#system"
}

export function outboundTrafficBucket(
  outbound: Pick<Outbound, "type">,
  protocol: string
): "tunnels" | "direct" | "blocked" {
  if (outbound.type === "blackhole") {
    return "blocked"
  }
  return protocol ? "tunnels" : "direct"
}

export function activeOutboundMember(
  runtime: RuntimeOutboundState | undefined
): RuntimeInterfaceState | undefined {
  return runtime?.interfaces.find((member) => member.status === "active")
}

export function outboundRuntimeIssue(
  runtime: RuntimeOutboundState | undefined
): OutboundRuntimeIssue | undefined {
  return outboundRuntimeIssues(runtime)[0]
}

/**
 * Runtime may report both a selector-wide mismatch and individual failed
 * candidates. Translate those details into a small, stable UI vocabulary:
 * arbitrary stderr from a probe belongs in diagnostics, not on the dashboard.
 *
 * "unknown" is included deliberately. It means the daemon could not attribute
 * a measurement to this outbound, and staying silent about that would leave
 * the card looking as settled as a verified one.
 */
export function outboundRuntimeIssues(
  runtime: RuntimeOutboundState | undefined
): OutboundRuntimeIssue[] {
  if (
    runtime === undefined ||
    (runtime.status !== "degraded" &&
      runtime.status !== "unavailable" &&
      runtime.status !== "unknown")
  ) {
    return []
  }

  const issues: OutboundRuntimeIssue[] = []
  if (runtime.detail?.trim()) {
    issues.push({
      code: runtimeDetailCode(runtime.detail, runtime.status),
      tone: issueTone(runtime.status),
    })
  }

  for (const member of runtime.interfaces) {
    if (
      member.status !== "degraded" &&
      member.status !== "unavailable" &&
      member.status !== "unknown"
    ) {
      continue
    }
    issues.push({
      code: runtimeDetailCode(member.detail, member.status),
      memberTag: member.outbound_tag,
      tone: issueTone(member.status),
    })
  }

  if (issues.length > 0) {
    return deduplicateIssues(issues)
  }

  // A bare "unknown" with nothing to explain it is not an unverified probe.
  // The daemon also reports UNKNOWN for shapes it never probes at all - a
  // table outbound whose externally managed table holds no default, or a group
  // with no resolvable members - so claiming the route "has not been checked
  // yet" there would be permanently false. Say nothing instead.
  if (runtime.status === "unknown") {
    return []
  }

  return [
    {
      code: fallbackIssueCode(runtime.status),
      tone: issueTone(runtime.status),
    },
  ]
}

function fallbackIssueCode(status: string): OutboundRuntimeIssue["code"] {
  if (status === "unavailable") return "unavailable"
  // UNKNOWN is deliberately not a failure. Older daemons collapse a pending,
  // stale and genuinely unattributable probe into the same state, so the
  // dashboard must use neutral wording unless the detail proves which one it
  // was.
  if (status === "unknown") return "verificationPending"
  return "degraded"
}

function issueTone(status: string): OutboundRuntimeIssue["tone"] {
  return status === "unknown" ? "warning" : "error"
}

function runtimeDetailCode(
  detail: string | undefined,
  fallbackStatus: "degraded" | "unavailable" | string
): OutboundRuntimeIssue["code"] {
  const normalized = detail?.trim().toLocaleLowerCase("en-US") ?? ""
  // Newer daemons can distinguish why there is no current measurement. Keep
  // the binding-specific warning for an explicitly unattributed result only.
  // The legacy "no attributable probe result" text is intentionally handled
  // as pending below: that backend phrase also covered missing and stale data.
  if (
    normalized.includes("probe result is unattributed") ||
    normalized.includes("probe could not be bound to outbound interface")
  ) {
    return "cannotVerify"
  }
  if (
    normalized.includes("probe result is stale") ||
    normalized.includes("stale probe result") ||
    normalized.includes("last attributable measurement is too old")
  ) {
    return "verificationStale"
  }
  if (
    normalized.includes("probe pending") ||
    normalized.includes("no probe result") ||
    normalized.includes("cannot verify")
  ) {
    return "verificationPending"
  }
  if (
    normalized.includes(
      "interface is not reachable from the main routing table"
    )
  ) {
    return "interfaceUnreachable"
  }
  if (
    normalized.includes(
      "no active default route is installed in the outbound table"
    )
  ) {
    return "routeMissing"
  }
  if (
    normalized.includes(
      "live route selection differs from urltest manager selection"
    )
  ) {
    return "selectionMismatch"
  }
  if (
    normalized.includes("timed out") ||
    normalized.includes("timeout") ||
    normalized.includes("deadline exceeded")
  ) {
    return "probeTimeout"
  }
  if (normalized.includes("connection refused")) {
    return "connectionRefused"
  }
  if (
    normalized.includes("network is unreachable") ||
    normalized.includes("no route to host")
  ) {
    return "networkUnreachable"
  }
  if (
    normalized.includes("name resolution") ||
    normalized.includes("resolve host") ||
    normalized.includes("could not resolve") ||
    normalized.includes("dns")
  ) {
    return "dnsFailed"
  }
  if (
    normalized.includes("permission denied") ||
    normalized.includes("operation not permitted")
  ) {
    return "permissionDenied"
  }
  return fallbackIssueCode(fallbackStatus)
}

function deduplicateIssues(
  issues: readonly OutboundRuntimeIssue[]
): OutboundRuntimeIssue[] {
  const seen = new Set<string>()
  return issues.filter((issue) => {
    const key = `${issue.memberTag ?? "group"}:${issue.code}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}
