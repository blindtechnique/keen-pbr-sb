import {
  CircleAlert,
  CircleCheckBig,
  LoaderCircle,
} from "lucide-react"
import { useTranslation } from "react-i18next"

import type {
  HealthResponse,
  RuntimeOutboundState,
} from "@/api/generated/model"
import { useStatusEventConnectionState } from "@/api/status-event-connection"
import { getHeaderHealthTone } from "@/components/layout/header-health-state"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

type SummaryTone = "healthy" | "waiting" | "degraded"

export function SystemStatusSummary({
  configIsDraft,
  listCount,
  outbounds,
  routingOverall,
  ruleCount,
  service,
}: {
  configIsDraft: boolean
  listCount: number
  outbounds?: readonly RuntimeOutboundState[]
  routingOverall?: string
  ruleCount: number
  service?: HealthResponse
}) {
  const { t } = useTranslation()
  const statusEvents = useStatusEventConnectionState()
  const sharedHealthTone = getHeaderHealthTone({
    outbounds,
    service,
    statusEvents,
  })
  const serviceFailed =
    service?.status === "stopped" ||
    service?.runtime_state === "stopped" ||
    service?.runtime_state === "broken"
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
  const routingFailed =
    routingOverall !== undefined && routingOverall !== "ok"
  const tone: SummaryTone =
    routingFailed || sharedHealthTone === "failed"
      ? "degraded"
      : sharedHealthTone === "attention" ||
          routingOverall === undefined ||
          configIsDraft
        ? "waiting"
        : "healthy"

  return (
    <section
      data-slot="card"
      className={cn(
        "flex flex-col gap-3 rounded-[6px] border bg-card px-4 py-3 sm:flex-row sm:items-center sm:justify-between",
        tone === "degraded" && "border-destructive/40",
        tone === "waiting" && "border-warning/40"
      )}
    >
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
            service === undefined
              ? "secondary"
              : serviceFailed
                ? "destructive"
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
    return (
      <span className="flex size-9 shrink-0 items-center justify-center rounded-full bg-destructive/10 text-destructive">
        <CircleAlert className="size-5" />
      </span>
    )
  }
  return (
    <span className="flex size-9 shrink-0 items-center justify-center rounded-full bg-warning/10 text-warning">
      <LoaderCircle className="size-5 animate-spin" />
    </span>
  )
}
