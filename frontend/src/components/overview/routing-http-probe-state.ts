import type { MutationObserverResult } from "@tanstack/react-query"
import type { postRoutingTestResponse } from "@/api/generated/keen-api"
import type {
  RoutingTestHttpProbe,
  RoutingTestRequest,
  RoutingTestResponse,
} from "@/api/generated/model"
import { sameRoutingEvidenceAddress } from "./routing-evidence-model"

export type RoutingHttpProbeControls = {
  onHttpProbe?: (ip: string) => void
  httpProbe?: RoutingTestHttpProbe
  httpPendingIp?: string
  httpError?: { ip: string }
}

export const routingHttpProbeMutationOptions = {
  mutation: { retry: false },
} as const

export function routingHttpProbeState(
  base: RoutingTestResponse | undefined,
  probeBase: RoutingTestResponse | null,
  mutation: Pick<
    MutationObserverResult<
      postRoutingTestResponse,
      unknown,
      { data: RoutingTestRequest }
    >,
    "status" | "data" | "variables"
  >
): Omit<RoutingHttpProbeControls, "onHttpProbe"> {
  // The same target can have a new DNS/routing snapshot. Only the exact base
  // that initiated this manual probe may display its separate result.
  if (!base || base !== probeBase) return {}
  const ip = mutation.variables?.data.http_probe_ip
  if (!ip || !base.results.some((entry) => entry.ip === ip)) return {}
  if (mutation.status === "pending") return { httpPendingIp: ip }
  if (mutation.status === "idle") return {}
  const response = mutation.data
  if (
    mutation.status === "success" &&
    response?.status === 200 &&
    response.data.target === base.target &&
    response.data.http_probe &&
    sameRoutingEvidenceAddress(response.data.http_probe.ip, ip)
  ) {
    return { httpProbe: response.data.http_probe }
  }
  return { httpError: { ip } }
}
