import type {
  HealthResponse,
  RouteRule,
  RuntimeOutboundState,
} from "@/api/generated/model"
import { countOrphanedLists } from "@/components/overview/dashboard-outbound-relevance"

export const dashboardSectionIds = {
  service: "dashboard-services",
  dns: "dashboard-dns",
  routing: "dashboard-routing",
  outbounds: "dashboard-outbounds",
} as const

export type DashboardAttentionItem = Readonly<{
  id: keyof typeof dashboardSectionIds
  targetId: (typeof dashboardSectionIds)[keyof typeof dashboardSectionIds]
  tone: "warning" | "error"
  count?: number
}>

export function collectDashboardAttentionItems({
  outbounds,
  outboundsQueryFailed = false,
  routeRules,
  routingOverall,
  service,
  serviceQueryFailed = false,
}: {
  outbounds?: readonly RuntimeOutboundState[]
  outboundsQueryFailed?: boolean
  /** Без правил безобидность упавшего маршрута доказать нечем — см. ниже. */
  routeRules?: readonly RouteRule[]
  routingOverall?: string
  service?: HealthResponse
  serviceQueryFailed?: boolean
}): DashboardAttentionItem[] {
  const items: DashboardAttentionItem[] = []

  if (serviceQueryFailed) {
    items.push({
      id: "service",
      targetId: dashboardSectionIds.service,
      tone: "error",
    })
  } else if (service) {
    const serviceFailed =
      service.status === "stopped" ||
      service.runtime_state === "stopped" ||
      service.runtime_state === "broken" ||
      service.lifecycle_operation?.status === "failed"
    const serviceWaiting =
      !serviceFailed &&
      (service.runtime_state !== "running" ||
        service.lifecycle_operation?.status === "running")

    if (serviceFailed || serviceWaiting) {
      items.push({
        id: "service",
        targetId: dashboardSectionIds.service,
        tone: serviceFailed ? "error" : "warning",
      })
    }

    const dnsFailed =
      service.resolver_live_status === "degraded" ||
      service.resolver_live_status === "unavailable" ||
      service.resolver_config_probe_status === "missing_txt" ||
      service.resolver_config_probe_status === "invalid_txt" ||
      service.resolver_config_probe_status === "query_failed"
    const dnsWaiting =
      !dnsFailed &&
      (service.resolver_live_status !== "healthy" ||
        service.resolver_config_sync_state !== "converged")

    if (dnsFailed || dnsWaiting) {
      items.push({
        id: "dns",
        targetId: dashboardSectionIds.dns,
        tone: dnsFailed ? "error" : "warning",
      })
    }
  }

  if (routingOverall !== undefined && routingOverall !== "ok") {
    items.push({
      id: "routing",
      targetId: dashboardSectionIds.routing,
      tone: routingOverall === "error" ? "error" : "warning",
    })
  }

  if (outboundsQueryFailed) {
    items.push({
      id: "outbounds",
      targetId: dashboardSectionIds.outbounds,
      tone: "error",
    })
  } else if (outbounds) {
    const unavailable = outbounds.filter(
      (outbound) => outbound.status === "unavailable"
    ).length
    const degraded = outbounds.filter(
      (outbound) =>
        outbound.status === "degraded" || outbound.status === "unknown"
    ).length
    const count = unavailable + degraded
    // Красным — только когда упавший маршрут везёт список включённого правила
    // (список осиротел). Упавший туннель, к которому не привязан ни один
    // список, и участник группы, которого группа уже заменила, — жёлтые:
    // посмотреть стоит, но ничего не сломалось.
    const orphanedLists = routeRules
      ? countOrphanedLists({ rules: routeRules, outbounds })
      : undefined
    const broken = orphanedLists === undefined ? unavailable > 0 : orphanedLists > 0
    if (count > 0) {
      items.push({
        id: "outbounds",
        targetId: dashboardSectionIds.outbounds,
        tone: broken ? "error" : "warning",
        count,
      })
    }
  }

  return items
}
