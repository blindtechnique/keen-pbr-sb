import type {
  Outbound,
  RuntimeInterfaceState,
  RuntimeOutboundState,
} from "@/api/generated/model"

export type OutboundRuntimeIssue =
  Readonly<{
    code:
      | "interfaceUnreachable"
      | "routeMissing"
      | "selectionMismatch"
      | "probeTimeout"
      | "connectionRefused"
      | "networkUnreachable"
      | "dnsFailed"
      | "permissionDenied"
      | "degraded"
      | "unavailable"
    memberTag?: string
  }>

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
 */
export function outboundRuntimeIssues(
  runtime: RuntimeOutboundState | undefined
): OutboundRuntimeIssue[] {
  if (
    runtime === undefined ||
    (runtime.status !== "degraded" && runtime.status !== "unavailable")
  ) {
    return []
  }

  const issues: OutboundRuntimeIssue[] = []
  if (runtime.detail?.trim()) {
    issues.push({
      code: runtimeDetailCode(runtime.detail, runtime.status),
    })
  }

  for (const member of runtime.interfaces) {
    if (
      member.status !== "degraded" &&
      member.status !== "unavailable"
    ) {
      continue
    }
    issues.push({
      code: runtimeDetailCode(member.detail, member.status),
      memberTag: member.outbound_tag,
    })
  }

  return issues.length > 0
    ? deduplicateIssues(issues)
    : [
        {
          code:
            runtime.status === "unavailable" ? "unavailable" : "degraded",
        },
      ]
}

function runtimeDetailCode(
  detail: string | undefined,
  fallbackStatus: "degraded" | "unavailable" | string
): OutboundRuntimeIssue["code"] {
  const normalized = detail?.trim().toLocaleLowerCase("en-US") ?? ""
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
  return fallbackStatus === "unavailable" ? "unavailable" : "degraded"
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
