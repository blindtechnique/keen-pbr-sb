import type { HealthResponse } from "@/api/generated/model"

export type RoutingRecoveryAction = "start" | "restart"

/**
 * status is the API projection of routing_runtime_active, not merely the
 * daemon process status. A broken cold boot therefore needs START, while an
 * active runtime (including restart_required) can accept RESTART.
 */
export function selectRoutingRecoveryAction(
  health: Pick<HealthResponse, "status" | "runtime_state">
): RoutingRecoveryAction {
  return health.status === "running" ? "restart" : "start"
}
