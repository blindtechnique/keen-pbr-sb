import type {
  RuntimeOutboundState,
  TransportStatus,
} from "@/api/generated/model"

export type TransportOperationalState = Readonly<{
  key:
    | "down"
    | "starting"
    | "supervisorDegraded"
    | "processRunning"
    | "verificationPending"
    | "healthy"
    | "runtimeDegraded"
    | "runtimeUnavailable"
    | "runtimeUnknown"
  healthy: boolean
  detail?: string
}>

/**
 * A running process is not proof that traffic can leave through its tunnel.
 * For a transport linked to an interface outbound, the runtime route/probe
 * verdict is the same source of truth used by the dashboard.  Supervisor state
 * still wins while the process is stopped, starting, or degraded.
 */
export function transportOperationalState(
  transport: Pick<TransportStatus, "desired_up" | "interface" | "state">,
  boundRuntime: RuntimeOutboundState | undefined,
  isBoundToOutbound: boolean
): TransportOperationalState {
  if (!transport.desired_up || transport.state === "down") {
    return { key: "down", healthy: false }
  }
  if (transport.state === "starting") {
    return { key: "starting", healthy: false }
  }
  if (transport.state === "degraded") {
    return { key: "supervisorDegraded", healthy: false }
  }
  if (!isBoundToOutbound) {
    return { key: "processRunning", healthy: false }
  }
  if (!boundRuntime) {
    return { key: "verificationPending", healthy: false }
  }

  const detail =
    boundRuntime.detail ??
    boundRuntime.interfaces.find(
      (candidate) => candidate.interface_name === transport.interface
    )?.detail ??
    boundRuntime.interfaces.find((candidate) => candidate.detail)?.detail

  switch (boundRuntime.status) {
    case "healthy":
      return { key: "healthy", healthy: true }
    case "degraded":
      return {
        key: "runtimeDegraded",
        healthy: false,
        detail,
      }
    case "unavailable":
      return {
        key: "runtimeUnavailable",
        healthy: false,
        detail,
      }
    default:
      return {
        key: "runtimeUnknown",
        healthy: false,
        detail,
      }
  }
}
