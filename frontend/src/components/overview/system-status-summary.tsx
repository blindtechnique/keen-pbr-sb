import {
  ChevronRight,
  CircleAlert,
  CircleCheckBig,
  CircleX,
  LoaderCircle,
} from "lucide-react"
import type { ReactNode } from "react"
import { useTranslation } from "react-i18next"

import type {
  HealthResponse,
  RouteRule,
  RuntimeOutboundState,
} from "@/api/generated/model"
import { useStatusEventConnectionState } from "@/api/status-event-connection"
import { getHeaderHealthTone } from "@/components/layout/header-health-state"
import { collectDashboardAttentionItems } from "@/components/overview/system-status-summary-model"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

/**
 * `warning` — своя ступень между «получаем состояние» и «сломано».
 *
 * Раньше их было три, и всё, что не «Всё в порядке» и не загрузка, красилось
 * в красное «Требуется внимание»: упавший туннель без списков, участник
 * группы, которого группа уже заменила, несохранённый черновик. Красный при
 * работающих службах и работающей маршрутизации не сообщает ничего — он
 * просто перестаёт значить «сломалось».
 */
type SummaryTone = "healthy" | "waiting" | "warning" | "degraded"

export function SystemStatusSummary({
  configIsDraft,
  listCount,
  outbounds,
  outboundsQueryFailed = false,
  routeRules,
  routingOverall,
  ruleCount,
  service,
  serviceQueryFailed = false,
  children,
}: {
  configIsDraft: boolean
  listCount: number
  outbounds?: readonly RuntimeOutboundState[]
  outboundsQueryFailed?: boolean
  /** Правила: по ним видно, осиротел ли список из-за упавшего маршрута. */
  routeRules?: readonly RouteRule[]
  routingOverall?: string
  ruleCount: number
  service?: HealthResponse
  serviceQueryFailed?: boolean
  children?: ReactNode
}) {
  const { t } = useTranslation()
  const statusEvents = useStatusEventConnectionState()
  const sharedHealthTone = getHeaderHealthTone({
    outbounds,
    outboundsQueryFailed,
    routeRules,
    service,
    serviceQueryFailed,
    statusEvents,
  })
  const serviceFailed =
    serviceQueryFailed ||
    service?.status === "stopped" ||
    service?.runtime_state === "stopped" ||
    service?.runtime_state === "broken" ||
    service?.lifecycle_operation?.status === "failed"
  const dnsFailed =
    service?.resolver_live_status === "degraded" ||
    service?.resolver_live_status === "unavailable" ||
    service?.resolver_config_probe_status === "missing_txt" ||
    service?.resolver_config_probe_status === "invalid_txt" ||
    service?.resolver_config_probe_status === "query_failed"
  const dnsWaiting =
    !service ||
    service.resolver_live_status !== "healthy" ||
    service.resolver_config_sync_state !== "converged"
  const routingFailed = routingOverall !== undefined && routingOverall !== "ok"
  // «Получаем состояние» — только пока данных действительно нет. Раньше в эту
  // же ветку падало всё «внимание», и карточка с крутящимся кружком уверяла,
  // что опрашивает службы, когда опрос давно закончился.
  const stillLoading =
    (!service && !serviceQueryFailed) ||
    (!outbounds && !outboundsQueryFailed) ||
    routingOverall === undefined
  const tone: SummaryTone = stillLoading
    ? "waiting"
    : routingFailed || sharedHealthTone === "failed"
      ? "degraded"
      : sharedHealthTone === "attention" || configIsDraft
        ? "warning"
        : "healthy"
  const attentionItems = collectDashboardAttentionItems({
    outbounds,
    outboundsQueryFailed,
    routeRules,
    routingOverall,
    service,
    serviceQueryFailed,
  })

  return (
    <section
      data-slot="card"
      className={cn(
        "rounded-[6px] border bg-card px-4 py-3",
        tone === "degraded" && "border-destructive/40",
        (tone === "waiting" || tone === "warning") && "border-warning/40"
      )}
    >
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex min-w-0 items-center gap-3">
          <StatusIcon tone={tone} />
          <div className="min-w-0">
            <h1
              className="text-[20px] leading-7 font-bold text-foreground"
              id="page-title"
            >
              {t(`overview.summary.${tone}.title`)}
            </h1>
            <p className="text-[13px] leading-5 text-muted-foreground">
              {t(`overview.summary.${tone}.description`)}
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-1.5 sm:justify-end">
          <Badge
            size="xs"
            variant={
              serviceFailed
                ? "destructive"
                : service === undefined
                  ? "secondary"
                  : "success"
            }
          >
            keen-pbr
          </Badge>
          <Badge
            size="xs"
            variant={
              routingFailed
                ? "destructive"
                : routingOverall
                  ? "success"
                  : "secondary"
            }
          >
            {t("overview.summary.routing")}
          </Badge>
          <Badge
            size="xs"
            variant={
              dnsFailed ? "destructive" : dnsWaiting ? "warning" : "success"
            }
          >
            DNS
          </Badge>
          <Badge size="xs" variant="secondary">
            {t("overview.summary.configuration", {
              lists: listCount,
              rules: ruleCount,
            })}
          </Badge>
          {configIsDraft ? (
            <Badge size="xs" variant="warning">
              {t("overview.summary.draft")}
            </Badge>
          ) : null}
        </div>
      </div>
      {attentionItems.length > 0 ? (
        <nav
          aria-label={t("overview.summary.attention.ariaLabel")}
          className="mt-3 flex flex-wrap gap-1.5 border-t border-border pt-2.5"
        >
          {attentionItems.map((item) => (
            <a
              className={cn(
                "inline-flex min-h-7 items-center gap-1.5 rounded-[4px] border px-2 py-1 text-xs font-medium transition-colors outline-none focus-visible:ring-2 focus-visible:ring-ring",
                item.tone === "error"
                  ? "border-destructive/25 bg-destructive/5 text-destructive hover:bg-destructive/10"
                  : "border-warning/30 bg-warning/5 text-warning-foreground hover:bg-warning/10"
              )}
              href={`#${item.targetId}`}
              key={item.id}
            >
              <CircleAlert aria-hidden="true" className="size-3.5" />
              <span>
                {t(`overview.summary.attention.${item.id}`, {
                  count: item.count,
                })}
              </span>
              <ChevronRight
                aria-hidden="true"
                className="size-3.5 opacity-60"
              />
            </a>
          ))}
        </nav>
      ) : null}
      {children ? (
        <div className="mt-3 border-t border-border pt-3">{children}</div>
      ) : null}
    </section>
  )
}

function StatusIcon({ tone }: { tone: SummaryTone }) {
  if (tone === "healthy") {
    return (
      <span className="flex size-9 shrink-0 items-center justify-center rounded-full bg-success/10 text-success">
        <CircleCheckBig className="size-5" />
      </span>
    )
  }
  if (tone === "degraded") {
    // Крест, а не восклицательный знак: «сломано» и «посмотрите» должны
    // отличаться и значком, а не только цветом — это те же две иконки, что
    // у индикатора в шапке.
    return (
      <span className="flex size-9 shrink-0 items-center justify-center rounded-full bg-destructive/10 text-destructive">
        <CircleX className="size-5" />
      </span>
    )
  }
  if (tone === "warning") {
    return (
      <span className="flex size-9 shrink-0 items-center justify-center rounded-full bg-warning/10 text-warning-foreground">
        <CircleAlert className="size-5" />
      </span>
    )
  }
  return (
    // Не `text-warning`: на собственной подложке `bg-warning/10` это 2.22:1 —
    // ниже порога 3:1 для значащей графики. `--warning-foreground` там же
    // даёт 6.22:1.
    <span className="flex size-9 shrink-0 items-center justify-center rounded-full bg-warning/10 text-warning-foreground">
      <LoaderCircle className="size-5 animate-spin" />
    </span>
  )
}
