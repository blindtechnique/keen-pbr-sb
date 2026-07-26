import type { RuntimeInterfaceTraffic } from "@/api/generated/model/runtimeInterfaceTraffic"
import {
  buildTrafficSeries,
  formatBitRate,
  formatTrafficBytes,
} from "@/components/transports/interface-traffic-model"
import { cn } from "@/lib/utils"

const CHART_WIDTH = 120
const CHART_HEIGHT = 36
const CHART_PADDING = 2

export function InterfaceTraffic({
  traffic,
  locale,
  labels,
  className,
}: {
  readonly traffic?: RuntimeInterfaceTraffic
  readonly locale: string
  readonly labels: Readonly<{
    receive: string
    transmit: string
    received: string
    transmitted: string
    chart: string
  }>
  readonly className?: string
}) {
  if (!traffic) {
    return null
  }

  const series = buildTrafficSeries(traffic)
  const hasChart = traffic.history.length >= 2

  return (
    <div className={cn("mt-2 min-w-0 border-t pt-2", className)}>
      <div className="grid min-w-0 grid-cols-2 gap-x-4 gap-y-1 sm:grid-cols-4">
        <TrafficValue
          label={labels.receive}
          value={formatBitRate(traffic.rx_bits_per_second, locale)}
        />
        <TrafficValue
          label={labels.transmit}
          value={formatBitRate(traffic.tx_bits_per_second, locale)}
        />
        <TrafficValue
          label={labels.received}
          value={formatTrafficBytes(traffic.rx_bytes, locale)}
        />
        <TrafficValue
          label={labels.transmitted}
          value={formatTrafficBytes(traffic.tx_bytes, locale)}
        />
      </div>
      {hasChart ? (
        <svg
          aria-label={labels.chart}
          className="mt-2 h-12 w-full overflow-visible"
          preserveAspectRatio="none"
          role="img"
          viewBox={`0 0 ${CHART_WIDTH} ${CHART_HEIGHT}`}
        >
          <line
            className="stroke-border"
            vectorEffect="non-scaling-stroke"
            x1={CHART_PADDING}
            x2={CHART_WIDTH - CHART_PADDING}
            y1={CHART_HEIGHT - CHART_PADDING}
            y2={CHART_HEIGHT - CHART_PADDING}
          />
          <polyline
            className="fill-none stroke-sky-500"
            points={series.rx}
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth="1.5"
            vectorEffect="non-scaling-stroke"
          />
          <polyline
            className="fill-none stroke-emerald-600 dark:stroke-emerald-400"
            points={series.tx}
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth="1.5"
            vectorEffect="non-scaling-stroke"
          />
        </svg>
      ) : null}
    </div>
  )
}

function TrafficValue({
  label,
  value,
}: {
  readonly label: string
  readonly value: string
}) {
  return (
    <div className="min-w-0">
      <div className="truncate text-xs text-muted-foreground">{label}</div>
      <div className="truncate text-sm font-medium tabular-nums" title={value}>
        {value}
      </div>
    </div>
  )
}
