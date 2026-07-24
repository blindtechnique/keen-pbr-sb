import { useQuery } from "@tanstack/react-query"
import { useTranslation } from "react-i18next"

import { SectionCard } from "@/components/shared/section-card"
import { Skeleton } from "@/components/ui/skeleton"

type RouterInfo = {
  available?: boolean
  model?: string
  vendor?: string
  hw_id?: string
  region?: string
  arch?: string
  firmware_title?: string
  firmware_release?: string
  firmware_channel?: string
  firmware_date?: string
  cpu_model?: string
  cpu_load_percent?: number
  cpu_temperature_c?: number
  memory_total_mb?: number
  memory_used_mb?: number
  memory_used_percent?: number
  disk_total_mb?: number
  disk_used_mb?: number
  disk_used_percent?: number
  uptime_seconds?: number
  load_average?: number[]
  internet?: boolean
  wan_address?: string
  clients_active?: number
  clients_total?: number
}

/**
 * Hardware and firmware facts about the router itself. Everything here is
 * read-only: the controls it used to share the card with now live in the
 * services card, so this stays a place to look rather than to click.
 */
export function RouterInfoCard() {
  const { t } = useTranslation()

  const query = useQuery<RouterInfo>({
    queryKey: ["system-router"],
    queryFn: async () => {
      const response = await fetch("/api/system/router")
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      return response.json()
    },
    refetchInterval: 15_000,
    refetchIntervalInBackground: false,
  })

  const info = query.data

  return (
    <SectionCard
      className="h-full"
      contentClassName="flex flex-1 flex-col"
      title={t("overview.router.title")}
    >
      {query.isLoading ? (
        <div className="space-y-2">
          <Skeleton className="h-6 w-2/3" />
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-5/6" />
          <Skeleton className="h-4 w-4/6" />
        </div>
      ) : null}

      {!query.isLoading && !info?.available ? (
        <p className="text-sm text-muted-foreground">
          {t("overview.router.unavailable")}
        </p>
      ) : null}

      {info?.available ? (
        <div className="space-y-4">
          <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
            <div className="text-[16px] leading-6 font-medium">
              {[info.vendor, info.model].filter(Boolean).join(" ")}
            </div>
            <div className="text-xs text-muted-foreground">
              {[info.hw_id, info.region, info.arch].filter(Boolean).join(" · ")}
            </div>
          </div>

          <dl className="grid grid-cols-2 border-y border-border sm:grid-cols-4 xl:grid-cols-7">
            <Metric label={t("overview.router.cpu")}>
              {formatCpuSummary(info)}
            </Metric>
            <Metric label={t("overview.router.memory")}>
              {formatMemory(info, t)}
            </Metric>
            {typeof info.disk_used_percent === "number" ? (
              <Metric label={t("overview.router.disk")}>
                {formatDisk(info, t)}
              </Metric>
            ) : null}
            {typeof info.clients_total === "number" ? (
              <Metric label={t("overview.router.clients")}>
                <span className="inline-flex items-center gap-2">
                  <span
                    aria-hidden="true"
                    className="size-2 shrink-0 rounded-full bg-success"
                  />
                  {t("overview.router.clientsValue", {
                    active: info.clients_active ?? 0,
                    total: info.clients_total,
                  })}
                </span>
              </Metric>
            ) : null}
            {info.firmware_title ? (
              <Metric label={t("overview.router.firmware")}>
                {info.firmware_title}
              </Metric>
            ) : null}
            {typeof info.uptime_seconds === "number" ? (
              <Metric label={t("overview.router.uptime")}>
                {formatUptime(info.uptime_seconds, t)}
              </Metric>
            ) : null}
            {info.load_average?.length === 3 ? (
              <Metric label={t("overview.router.loadAverage")}>
                <span className="font-mono text-xs tabular-nums">
                  {info.load_average.map((v) => v.toFixed(2)).join("  ")}
                </span>
              </Metric>
            ) : null}
          </dl>
          {info.cpu_model ? (
            <p className="truncate text-xs text-muted-foreground">
              {info.cpu_model}
            </p>
          ) : null}
        </div>
      ) : null}
    </SectionCard>
  )
}

function Metric({
  label,
  children,
}: {
  label: string
  children: React.ReactNode
}) {
  return (
    <div className="min-w-0 border-b border-border px-3 py-2.5 last:border-b-0 sm:border-r xl:border-b-0 xl:last:border-r-0 sm:[&:nth-child(4n)]:border-r-0 xl:[&:nth-child(4n)]:border-r">
      <dt className="text-[12px] leading-5 text-muted-foreground">{label}</dt>
      <dd className="truncate text-[13px] leading-5 font-medium text-foreground">
        {children}
      </dd>
    </div>
  )
}

function formatCpuSummary(info: RouterInfo): string {
  const parts: string[] = []
  if (typeof info.cpu_load_percent === "number") {
    parts.push(`${info.cpu_load_percent}%`)
  }
  if (typeof info.cpu_temperature_c === "number") {
    parts.push(`${info.cpu_temperature_c}°C`)
  }
  return parts.join(" · ") || info.arch || "—"
}

function formatMemory(
  info: RouterInfo,
  t: (key: string, options?: Record<string, unknown>) => string
): string {
  if (typeof info.memory_total_mb !== "number") {
    return "—"
  }
  if (typeof info.memory_used_mb !== "number") {
    return t("overview.router.memoryTotalOnly", { total: info.memory_total_mb })
  }
  return t("overview.router.memoryValueCompact", {
    used: info.memory_used_mb,
    total: info.memory_total_mb,
    percent: info.memory_used_percent ?? 0,
  })
}

function formatDisk(
  info: RouterInfo,
  t: (key: string, options?: Record<string, unknown>) => string
): string {
  return t("overview.router.diskValueCompact", {
    used: formatCapacityMb(info.disk_used_mb ?? 0, t),
    total: formatCapacityMb(info.disk_total_mb ?? 0, t),
    percent: info.disk_used_percent ?? 0,
  })
}

function formatUptime(
  seconds: number,
  t: (key: string, options?: Record<string, unknown>) => string
): string {
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  if (days > 0) {
    return t("overview.router.uptimeValue", { days, hours, minutes })
  }
  if (hours > 0) {
    return t("overview.router.uptimeHoursValue", { hours, minutes })
  }
  return t("overview.router.uptimeMinutesValue", { minutes })
}

function formatCapacityMb(
  value: number,
  t: (key: string, options?: Record<string, unknown>) => string
): string {
  if (value < 1024) {
    return t("overview.router.capacityMb", { value: Math.round(value) })
  }

  return t("overview.router.capacityGb", {
    value: new Intl.NumberFormat(undefined, {
      maximumFractionDigits: 1,
    }).format(value / 1024),
  })
}
