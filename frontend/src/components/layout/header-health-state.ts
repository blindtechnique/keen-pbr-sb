import type {
  HealthResponse,
  RouteRule,
  RuntimeOutboundState,
} from "@/api/generated/model"
import type { StatusEventConnectionState } from "@/api/status-event-connection"
import { countOrphanedLists } from "@/components/overview/dashboard-outbound-relevance"

export type HeaderHealthTone = "healthy" | "attention" | "failed"

type HeaderHealthService = Pick<
  HealthResponse,
  | "config_is_draft"
  | "lifecycle_operation"
  | "resolver_config_probe_status"
  | "resolver_config_sync_state"
  | "resolver_live_status"
  | "runtime_state"
  | "status"
>

type HeaderHealthOutbound = Pick<RuntimeOutboundState, "status" | "tag">

export function getHeaderHealthTone({
  outbounds,
  outboundsQueryFailed = false,
  routeRules,
  service,
  serviceQueryFailed = false,
  statusEvents,
}: {
  outbounds?: readonly HeaderHealthOutbound[]
  outboundsQueryFailed?: boolean
  /**
   * Правила маршрутизации. По ним видно, висит ли на упавшем маршруте хотя бы
   * один список. Без правил безобидность падения доказать нечем, поэтому там
   * сохраняется прежнее строгое поведение: любой `unavailable` — красный.
   */
  routeRules?: readonly RouteRule[]
  service?: HeaderHealthService
  serviceQueryFailed?: boolean
  statusEvents?: StatusEventConnectionState
}): HeaderHealthTone {
  if (serviceQueryFailed || outboundsQueryFailed) return "failed"
  if (!service || !outbounds) return "attention"

  const hardServiceFailure =
    service.status === "stopped" ||
    service.runtime_state === "stopped" ||
    service.runtime_state === "broken" ||
    service.lifecycle_operation?.status === "failed"
  if (hardServiceFailure) return "failed"

  const serviceTransitioning =
    service.runtime_state !== "running" ||
    service.lifecycle_operation?.status === "running"
  const dnsFailed =
    service.resolver_live_status === "degraded" ||
    service.resolver_live_status === "unavailable" ||
    service.resolver_config_probe_status === "missing_txt" ||
    service.resolver_config_probe_status === "invalid_txt" ||
    service.resolver_config_probe_status === "query_failed"
  // Красный — только когда упавший маршрут действительно везёт трафик: на нём
  // висит список включённого правила. Туннель без списков и участник группы,
  // которого группа уже заменила, работу не ломают — это «внимание», а не
  // «сломано». Раньше любой `unavailable` красил индикатор в красный, и он
  // пугал при полностью рабочей маршрутизации.
  const outboundFailed = routeRules
    ? countOrphanedLists({ rules: routeRules, outbounds }) > 0
    : outbounds.some((outbound) => outbound.status === "unavailable")

  // During a transactional apply, DNS and outbound paths legitimately
  // disappear for a moment. That is an attention state, not a red failure.
  if (!serviceTransitioning && (dnsFailed || outboundFailed)) return "failed"

  const serviceNeedsAttention = serviceTransitioning || service.config_is_draft
  const dnsNeedsAttention =
    service.resolver_live_status !== "healthy" ||
    service.resolver_config_sync_state !== "converged"
  const outboundNeedsAttention = outbounds.some(
    (outbound) => outbound.status !== "healthy"
  )
  const streamNeedsAttention =
    statusEvents !== undefined && statusEvents !== "connected"

  return serviceNeedsAttention ||
    dnsNeedsAttention ||
    outboundNeedsAttention ||
    streamNeedsAttention
    ? "attention"
    : "healthy"
}
