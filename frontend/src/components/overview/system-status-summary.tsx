import {
  CircleAlert,
  CircleCheckBig,
  LoaderCircle,
} from "lucide-react"
import { useTranslation } from "react-i18next"

import type { DnsCheckStatus } from "@/hooks/use-dns-check"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

type SummaryTone = "healthy" | "waiting" | "degraded"

export function SystemStatusSummary({
  configIsDraft,
  dnsProbeEnabled,
  dnsStatus,
  listCount,
  routingOverall,
  ruleCount,
  serviceStatus,
}: {
  configIsDraft: boolean
  dnsProbeEnabled: boolean
  dnsStatus: DnsCheckStatus
  listCount: number
  routingOverall?: string
  ruleCount: number
  serviceStatus?: string
}) {
  const { t } = useTranslation()
  const dnsFailed =
    dnsProbeEnabled &&
    (dnsStatus === "browser-fail" || dnsStatus === "sse-fail")
  const dnsWaiting =
    dnsProbeEnabled && (dnsStatus === "idle" || dnsStatus === "checking")
  const serviceFailed =
    serviceStatus !== undefined && serviceStatus !== "running"
  const routingFailed =
    routingOverall !== undefined && routingOverall !== "ok"
  const waiting =
    serviceStatus === undefined || routingOverall === undefined || dnsWaiting
  const tone: SummaryTone =
    serviceFailed || routingFailed || dnsFailed
      ? "degraded"
      : waiting
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
            serviceStatus === undefined
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
        {dnsProbeEnabled ? (
          <Badge
            size="xs"
            variant={
              dnsFailed
                ? "destructive"
                : dnsWaiting
                  ? "warning"
                  : "success"
            }
          >
            DNS
          </Badge>
        ) : null}
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
