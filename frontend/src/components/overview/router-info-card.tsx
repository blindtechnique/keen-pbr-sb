import type { ReactNode } from "react"

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
        <div className="space-y-3">
          <div>
            <div className="text-lg font-semibold leading-tight">
              {[info.vendor, info.model].filter(Boolean).join(" ")}
            </div>
            {info.hw_id ? (
              <div className="text-xs text-muted-foreground">
                {info.hw_id}
                {info.region ? ` · ${info.region}` : null}
              </div>
            ) : null}
          </div>

          <dl className="space-y-1.5 text-sm">
            <Row label={t("overview.router.cpu")}>
              <span className="truncate">{describeCpu(info)}</span>
            </Row>
            <Row label={t("overview.router.memory")}>
              {formatMemory(info, t)}
            </Row>
            {typeof info.disk_used_percent === "number" ? (
              <Row label={t("overview.router.disk")}>{formatDisk(info, t)}</Row>
            ) : null}
            {info.wan_address ? (
              <Row label={t("overview.router.wan")}>
                <span className="font-mono text-xs">{info.wan_address}</span>
              </Row>
            ) : null}
            {typeof info.clients_total === "number" ? (
              <Row label={t("overview.router.clients")}>
                {t("overview.router.clientsValue", {
                  active: info.clients_active ?? 0,
                  total: info.clients_total,
                })}
              </Row>
            ) : null}
            {info.firmware_title ? (
              <Row label={t("overview.router.firmware")}>
                {info.firmware_title}
                {info.firmware_release ? (
                  <span className="text-muted-foreground">
                    {" "}
                    ({info.firmware_release})
                  </span>
                ) : null}
              </Row>
            ) : null}
            {typeof info.uptime_seconds === "number" ? (
              <Row label={t("overview.router.uptime")}>
                {formatUptime(info.uptime_seconds, t)}
              </Row>
            ) : null}
            {info.load_average?.length === 3 ? (
              <Row label={t("overview.router.loadAverage")}>
                <span className="font-mono text-xs tabular-nums">
                  {info.load_average.map((v) => v.toFixed(2)).join("  ")}
                </span>
              </Row>
            ) : null}
          </dl>
        </div>
      ) : null}
    </SectionCard>
  )
}

function Row({
  label,
  children,
}: {
  label: string
  children: ReactNode
}) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <dt className="shrink-0 text-muted-foreground">{label}</dt>
      <dd className="min-w-0 text-right">{children}</dd>
    </div>
  )
}

function describeCpu(info: RouterInfo): string {
  const parts: string[] = []
  if (info.cpu_model) {
    parts.push(info.cpu_model)
  } else if (info.arch) {
    parts.push(info.arch)
  }
  if (typeof info.cpu_load_percent === "number") {
    parts.push(`${info.cpu_load_percent}%`)
  }
  if (typeof info.cpu_temperature_c === "number") {
    parts.push(`${info.cpu_temperature_c}°C`)
  }
  return parts.join(" · ")
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
  return t("overview.router.memoryValue", {
    used: info.memory_used_mb,
    total: info.memory_total_mb,
    percent: info.memory_used_percent ?? 0,
  })
}

function formatDisk(
  info: RouterInfo,
  t: (key: string, options?: Record<string, unknown>) => string
): string {
  return t("overview.router.diskValue", {
    used: info.disk_used_mb ?? 0,
    total: info.disk_total_mb ?? 0,
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
  return t("overview.router.uptimeValue", { days, hours, minutes })
}
