import type { Outbound } from "@/api/generated/model/outbound"
import type { RouteRule } from "@/api/generated/model/routeRule"

export type RouteFailurePolicy = NonNullable<RouteRule["failure_policy"]>

export function normalizeRouteFailurePolicy(
  policy?: RouteFailurePolicy | null,
  fallbackOutbound?: string | null
): Pick<RouteRule, "failure_policy" | "fallback_outbound"> {
  if (policy === "fallback") {
    return {
      failure_policy: "fallback",
      fallback_outbound: fallbackOutbound?.trim() || undefined,
    }
  }
  return policy === "block" ? { failure_policy: "block" } : {}
}

export function getRouteFailureFallbackOutbounds(
  outbounds: readonly Outbound[],
  primaryOutbound: string
): Outbound[] {
  return outbounds.filter(
    (outbound) =>
      outbound.tag !== primaryOutbound.trim() &&
      (outbound.type === "interface" || outbound.type === "urltest")
  )
}

export function supportsRouteFailurePolicy(
  outbounds: readonly Outbound[],
  primaryOutbound: string
): boolean {
  const primary = outbounds.find(
    (outbound) => outbound.tag === primaryOutbound.trim()
  )
  return primary?.type === "interface" || primary?.type === "urltest"
}

export function getRouteFailurePolicyPrimaryValidationMessage(
  policy: RouteFailurePolicy | null | undefined,
  primaryOutbound: string,
  outbounds: readonly Outbound[],
  t: (key: string) => string
): string | undefined {
  if (!policy || policy === "inherit" || !primaryOutbound.trim())
    return undefined
  return supportsRouteFailurePolicy(outbounds, primaryOutbound)
    ? undefined
    : t("routeFailurePolicy.unsupportedPrimary")
}

// Configuration validity only. A temporarily unavailable VPN remains a valid
// choice; checking its live state must not prevent saving a routing rule.
export function getRouteFailurePolicyValidationMessage(
  policy: RouteFailurePolicy | null | undefined,
  fallbackOutbound: string | null | undefined,
  primaryOutbound: string,
  outbounds: readonly Outbound[],
  t: (key: string) => string
): string | undefined {
  if (
    policy !== "fallback" ||
    !supportsRouteFailurePolicy(outbounds, primaryOutbound)
  ) {
    return undefined
  }
  const fallback = fallbackOutbound?.trim()
  if (!fallback) return t("routeFailurePolicy.fallbackRequired")
  if (fallback === primaryOutbound.trim()) {
    return t("routeFailurePolicy.fallbackMustDiffer")
  }
  if (
    !getRouteFailureFallbackOutbounds(outbounds, primaryOutbound).some(
      (outbound) => outbound.tag === fallback
    )
  ) {
    return t("routeFailurePolicy.fallbackUnavailable")
  }
  return undefined
}
