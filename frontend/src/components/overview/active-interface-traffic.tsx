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
  interfaceConnectionState,
  isTrafficChartExpanded,
  parseTrafficChartPreferences,
  serializeTrafficChartPreferences,
  toggleTrafficChartPreference,
  TRAFFIC_CHART_PREFERENCES_STORAGE_KEY,
  type ActiveTrafficPath,
} from "@/components/overview/active-interface-traffic-model"
import { KeeneticStatus } from "@/components/shared/keenetic-status"
import { formatUptimeSince } from "@/lib/uptime-format"
import { InterfaceTraffic } from "@/components/transports/interface-traffic"
import { Badge } from "@/components/ui/badge"
import { useInterfaceProtocols } from "@/hooks/use-interface-protocols"
import { safeStorageGet, safeStorageSet } from "@/lib/safe-storage"
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
  const [chartPreferences, setChartPreferences] = useState(() =>
    parseTrafficChartPreferences(
      typeof window === "undefined"
        ? null
        : safeStorageGet(
            () => window.localStorage,
            TRAFFIC_CHART_PREFERENCES_STORAGE_KEY
          )
    )
  )
  const paths = collectActiveTrafficPaths(outbounds, rules, runtimeByTag)

  useEffect(() => {
    if (!chartPreferences.initialized || typeof window === "undefined") return
    safeStorageSet(
      () => window.localStorage,
      TRAFFIC_CHART_PREFERENCES_STORAGE_KEY,
      serializeTrafficChartPreferences(chartPreferences)
    )
  }, [chartPreferences])

  if (paths.length === 0) {
    return null
  }

  return (
    <div className="mt-3 border-t pt-3">
      <div className="mb-2 text-xs font-semibold tracking-wide text-muted-foreground uppercase">
        {t("overview.outbounds.liveTraffic")}
      </div>
      <p className="mb-3 max-w-3xl text-xs leading-5 text-muted-foreground">
        {t("overview.outbounds.trafficCountersHint")}
      </p>
      <div className="grid gap-3 lg:grid-cols-2">
        {paths.map((path, index) => {
          const protocol = protocolOf(path.interfaceName)
          const expanded = isTrafficChartExpanded(
            chartPreferences,
            path.interfaceName,
            index
          )
          const chartId = `dashboard-traffic-${safeDomId(path.interfaceName)}`
          const runtimeInterface = runtimeInterfaceByName.get(
            path.interfaceName
          )
          const connection = interfaceConnectionState(
            path.interfaceName,
            runtimeInterface?.status === "up",
            transports
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
                    {connectedLabel(
                      connection.connected,
                      runtimeInterface?.link_up_since_unix_ms,
                      t
                    )}
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
                    "grid size-8 shrink-0 place-items-center rounded-[4px] border transition-[border-color,background-color,color] outline-none focus-visible:ring-2 focus-visible:ring-ring",
                    expanded
                      ? "border-success bg-success/15 text-foreground"
                      : "border-input bg-card text-muted-foreground hover:bg-muted/40 hover:text-foreground"
                  )}
                  onClick={() =>
                    setChartPreferences((current) =>
                      toggleTrafficChartPreference(
                        current,
                        paths.map((candidate) => candidate.interfaceName),
                        path.interfaceName
                      )
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
                      noTraffic: t("transports.traffic.noTraffic"),
          stale: t("transports.traffic.stale"),
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

/**
 * Labels the connection badge, adding how long the link has been up when the
 * backend knows.
 *
 * A connected interface with no anchor keeps the plain "connected" label. The
 * badge states connection, not duration, so saying nothing about the duration
 * is accurate - whereas borrowing the router's or the daemon's uptime to fill
 * the gap would not be. The details panel spells the gap out as "unknown".
 */
function connectedLabel(
  connected: boolean,
  upSinceUnixMs: number | undefined,
  t: (key: string, options?: Record<string, unknown>) => string
): string {
  if (!connected) {
    return t("overview.outbounds.disconnected")
  }
  if (typeof upSinceUnixMs !== "number") {
    return t("overview.outbounds.connected")
  }
  return t("overview.outbounds.connectedFor", {
    duration: formatUptimeSince(upSinceUnixMs, t),
  })
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

function safeDomId(value: string): string {
  return value.replaceAll(/[^a-zA-Z0-9_-]/g, "-")
}
