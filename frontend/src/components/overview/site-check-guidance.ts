import type { SiteProbeState } from "./site-probe-model"

type RoutingCheckStatus = "idle" | "pending" | "success" | "error"

export type SiteCheckGuidance = "deviceOnly" | "dns" | "service" | null

export function siteCheckPresentation({
  inputTarget,
  activeTarget,
  routingStatus,
  browserProbe,
  routerProbe,
}: {
  inputTarget: string | null
  activeTarget: string | null
  routingStatus: RoutingCheckStatus
  browserProbe: SiteProbeState
  routerProbe: SiteProbeState
}): { retry: boolean; guidance: SiteCheckGuidance } {
  const settled =
    Boolean(activeTarget) &&
    (routingStatus === "success" || routingStatus === "error") &&
    probeSettled(browserProbe) &&
    probeSettled(routerProbe)
  const retry = settled && inputTarget === activeTarget

  if (!settled) return { retry, guidance: null }

  // A failed panel request is not evidence that the website or its DNS failed.
  if (
    routingStatus === "error" ||
    (routerProbe.status === "unconfirmed" &&
      (routerProbe.reason === "request" ||
        routerProbe.reason === "invalidResponse"))
  ) {
    return { retry, guidance: "service" }
  }

  if (routerProbe.status === "unconfirmed" && routerProbe.reason === "dns") {
    return { retry, guidance: "dns" }
  }

  // no-cors cannot distinguish a browser restriction from a network failure.
  // Offer a diagnostic next step without claiming a client-side cause.
  if (
    routerProbe.status === "responded" &&
    browserProbe.status === "unconfirmed"
  ) {
    return { retry, guidance: "deviceOnly" }
  }

  return { retry, guidance: null }
}

function probeSettled(probe: SiteProbeState): boolean {
  return probe.status === "responded" || probe.status === "unconfirmed"
}
