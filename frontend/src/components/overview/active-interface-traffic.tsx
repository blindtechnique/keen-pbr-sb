import { useEffect, useState } from "react"
import { useTranslation } from "react-i18next"

import type {
  Outbound,
  RouteRule,
  RuntimeInterfaceInventoryEntry,
  RuntimeOutboundState,
  TransportStatus,
} from "@/api/generated/model"
import {
  activeTrafficStatusTranslationKey,
  collectActiveTrafficPaths,
  formatConnectionDuration,
  interfaceConnectionState,
  type ActiveTrafficPath,
} from "@/components/overview/active-interface-traffic-model"
import { KeeneticStatus } from "@/components/shared/keenetic-status"
import { InterfaceTraffic } from "@/components/transports/interface-traffic"
import { Badge } from "@/components/ui/badge"
import { useInterfaceProtocols } from "@/hooks/use-interface-protocols"
import { cn } from "@/lib/utils"

export function ActiveInterfaceTraffic({
  outbounds,
  rules,
  runtimeByTag,
  runtimeInterfaceByName,
  transports,
}: {
  readonly outbounds: readonly Outbound[]
  readonly rules: readonly RouteRule[]
  readonly runtimeByTag: ReadonlyMap<string, RuntimeOutboundState>
  readonly runtimeInterfaceByName: ReadonlyMap<
    string,
    RuntimeInterfaceInventoryEntry
  >
  readonly transports: readonly TransportStatus[]
}) {
  const { i18n, t } = useTranslation()
  const { protocolOf } = useInterfaceProtocols()
  const [expandedInterfaces, setExpandedInterfaces] = useState<
    ReadonlySet<string>
  >(() => new Set())
  const nowUnixMs = useSecondTicker()
  const paths = collectActiveTrafficPaths(outbounds, rules, runtimeByTag)

  if (paths.length === 0) {
    return null
  }

  return (
    <div className="mt-3 border-t pt-3">
      <div className="mb-2 text-xs font-semibold tracking-wide text-muted-foreground uppercase">
        {t("overview.outbounds.liveTraffic")}
      </div>
      <div className="grid gap-3 lg:grid-cols-2">
        {paths.map((path) => {
          const protocol = protocolOf(path.interfaceName)
          const expanded = expandedInterfaces.has(path.interfaceName)
          const chartId = `dashboard-traffic-${safeDomId(path.interfaceName)}`
          const runtimeInterface = runtimeInterfaceByName.get(
            path.interfaceName
          )
          const connection = interfaceConnectionState(
            path.interfaceName,
            runtimeInterface?.status === "up",
            transports
          )
          const connectedSeconds =
            connection.connectedAtUnixMs === undefined
              ? undefined
              : Math.max(
                  0,
                  Math.floor((nowUnixMs - connection.connectedAtUnixMs) / 1_000)
                )
          return (
            <div className="min-w-0" key={path.interfaceName}>
              <div className="flex min-w-0 items-center justify-between gap-3">
                <div className="flex min-w-0 flex-wrap items-center gap-2">
                  <span className="truncate text-sm font-medium">
                    {path.label}
                  </span>
                  <Badge
                    className="shrink-0"
                    size="xs"
                    variant={statusBadgeVariant(path.status)}
                  >
                    {t(activeTrafficStatusTranslationKey(path.status))}
                  </Badge>
                  <KeeneticStatus
                    className="shrink-0"
                    tone={connection.connected ? "success" : "neutral"}
                  >
                    {connection.connected
                      ? connectedSeconds === undefined
                        ? t("overview.outbounds.connected")
                        : t("overview.outbounds.connectedFor", {
                            duration: formatConnectionDuration(
                              connectedSeconds,
                              t("overview.outbounds.dayShort")
                            ),
                          })
                      : t("overview.outbounds.disconnected")}
                  </KeeneticStatus>
                </div>
                <button
                  aria-controls={chartId}
                  aria-label={
                    expanded
                      ? t("transports.traffic.hideChart")
                      : t("transports.traffic.showChart")
                  }
                  aria-expanded={expanded}
                  className={cn(
                    "grid size-8 shrink-0 place-items-center rounded-[4px] border bg-success/15 text-foreground transition-[border-color,background-color] outline-none focus-visible:ring-2 focus-visible:ring-ring",
                    expanded ? "border-success" : "border-success/15"
                  )}
                  onClick={() =>
                    setExpandedInterfaces((current) =>
                      toggledSet(current, path.interfaceName)
                    )
                  }
                  title={
                    expanded
                      ? t("transports.traffic.hideChart")
                      : t("transports.traffic.showChart")
                  }
                  type="button"
                >
                  <TrafficChartToggleIcon />
                </button>
              </div>
              {expanded ? (
                <div id={chartId}>
                  {protocol ? (
                    <Badge
                      className="mt-2 shrink-0 font-mono text-[10px]"
                      size="xs"
                      variant="outline"
                    >
                      {protocol}
                    </Badge>
                  ) : null}
                  <InterfaceTraffic
                    className="mt-1"
                    labels={{
                      receive: t("transports.traffic.receive"),
                      transmit: t("transports.traffic.transmit"),
                      received: t("transports.traffic.received"),
                      transmitted: t("transports.traffic.transmitted"),
                      chart: t("transports.traffic.chart"),
                    }}
                    locale={i18n.resolvedLanguage ?? i18n.language}
                    showChart
                    traffic={runtimeInterface?.traffic}
                  />
                  {!runtimeInterface?.traffic ? (
                    <p className="mt-2 text-xs text-muted-foreground">
                      {t("overview.outbounds.waitingForTraffic")}
                    </p>
                  ) : null}
                </div>
              ) : null}
            </div>
          )
        })}
      </div>
    </div>
  )
}

function statusBadgeVariant(
  status: ActiveTrafficPath["status"]
): "success" | "warning" | "destructive" | "outline" {
  switch (status) {
    case "active":
      return "success"
    case "degraded":
      return "warning"
    case "unavailable":
      return "destructive"
    case "backup":
    case "unknown":
      return "outline"
  }
}

function TrafficChartToggleIcon() {
  return (
    <svg aria-hidden="true" className="size-5" fill="none" viewBox="0 0 24 24">
      <path
        d="M5 4v15h15M7.5 14l3-4 3.25 3 3.75-6"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.35"
      />
    </svg>
  )
}

function toggledSet(
  current: ReadonlySet<string>,
  value: string
): ReadonlySet<string> {
  const next = new Set(current)
  if (next.has(value)) {
    next.delete(value)
  } else {
    next.add(value)
  }
  return next
}

function safeDomId(value: string): string {
  return value.replaceAll(/[^a-zA-Z0-9_-]/g, "-")
}

function useSecondTicker(): number {
  const [nowUnixMs, setNowUnixMs] = useState(() => Date.now())

  useEffect(() => {
    const timer = window.setInterval(() => setNowUnixMs(Date.now()), 1_000)
    return () => window.clearInterval(timer)
  }, [])

  return nowUnixMs
}
