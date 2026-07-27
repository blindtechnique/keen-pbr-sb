import { useState } from "react"
import { useTranslation } from "react-i18next"

import type {
  Outbound,
  RouteRule,
  RuntimeInterfaceInventoryEntry,
  RuntimeOutboundState,
} from "@/api/generated/model"
import { collectActiveTrafficPaths } from "@/components/overview/active-interface-traffic-model"
import { InterfaceTraffic } from "@/components/transports/interface-traffic"
import { Badge } from "@/components/ui/badge"
import { useInterfaceProtocols } from "@/hooks/use-interface-protocols"
import { cn } from "@/lib/utils"

export function ActiveInterfaceTraffic({
  outbounds,
  rules,
  runtimeByTag,
  runtimeInterfaceByName,
}: {
  readonly outbounds: readonly Outbound[]
  readonly rules: readonly RouteRule[]
  readonly runtimeByTag: ReadonlyMap<string, RuntimeOutboundState>
  readonly runtimeInterfaceByName: ReadonlyMap<
    string,
    RuntimeInterfaceInventoryEntry
  >
}) {
  const { i18n, t } = useTranslation()
  const { protocolOf } = useInterfaceProtocols()
  const [hiddenCharts, setHiddenCharts] = useState<ReadonlySet<string>>(
    () => new Set()
  )
  const paths = collectActiveTrafficPaths(
    outbounds,
    rules,
    runtimeByTag
  ).filter((path) => runtimeInterfaceByName.get(path.interfaceName)?.traffic)

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
          const chartVisible = !hiddenCharts.has(path.interfaceName)
          const chartId = `dashboard-traffic-${safeDomId(path.interfaceName)}`
          return (
            <div className="min-w-0" key={path.interfaceName}>
              <div className="flex min-w-0 items-start justify-between gap-3">
                <div className="flex min-w-0 items-center gap-2 pt-1">
                  <span className="truncate text-sm font-medium">
                    {path.label}
                  </span>
                  {protocol ? (
                    <Badge
                      className="shrink-0 font-mono text-[10px]"
                      size="xs"
                      variant="outline"
                    >
                      {protocol}
                    </Badge>
                  ) : null}
                </div>
                <button
                  aria-controls={chartId}
                  aria-label={
                    chartVisible
                      ? t("transports.traffic.hideChart")
                      : t("transports.traffic.showChart")
                  }
                  aria-pressed={chartVisible}
                  className={cn(
                    "grid size-8 shrink-0 place-items-center rounded-[4px] border bg-success/15 text-foreground transition-[border-color,background-color] outline-none focus-visible:ring-2 focus-visible:ring-ring",
                    chartVisible ? "border-success" : "border-success/15"
                  )}
                  onClick={() =>
                    setHiddenCharts((current) =>
                      toggledSet(current, path.interfaceName)
                    )
                  }
                  title={
                    chartVisible
                      ? t("transports.traffic.hideChart")
                      : t("transports.traffic.showChart")
                  }
                  type="button"
                >
                  <TrafficChartToggleIcon />
                </button>
              </div>
              <div id={chartId}>
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
                  showChart={chartVisible}
                  traffic={
                    runtimeInterfaceByName.get(path.interfaceName)?.traffic
                  }
                />
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
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
