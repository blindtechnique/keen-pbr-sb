import type {
  RoutingHealthErrorResponse,
  RoutingHealthResponse,
} from "@/api/generated/model"

/** Older daemons return a diagnostic error body with HTTP 200. */
export function selectOverviewRoutingHealth(
  response:
    | {
        status: number
        data: RoutingHealthResponse | RoutingHealthErrorResponse
      }
    | undefined
): {
  report?: RoutingHealthResponse
  error?: RoutingHealthErrorResponse
} {
  if (response?.status !== 200) return {}
  if ("error" in response.data && response.data.overall === "error") {
    return { error: response.data }
  }
  // Do not manufacture empty rule arrays: an unsuccessful check is not an
  // empty or healthy routing configuration.
  return { report: response.data as RoutingHealthResponse }
}

/** Keep server diagnostics available without presenting raw English as UI copy. */
export function routingHealthErrorPresentation(
  error: unknown,
  t: (key: string) => string
): { summary: string; detail?: string } {
  const value =
    error && typeof error === "object"
      ? (error as { error?: unknown; message?: unknown })
      : undefined
  const raw = value?.error ?? value?.message
  const detail = typeof raw === "string" && raw.trim() ? raw : undefined
  return {
    summary:
      detail ===
      "runtime routing inventory is not authoritative; waiting for reconciliation"
        ? t("overview.routing.inventoryUnavailable")
        : t("overview.routing.loadError"),
    detail,
  }
}
