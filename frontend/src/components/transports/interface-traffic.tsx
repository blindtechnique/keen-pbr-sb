import { useId } from "react"

import type { RuntimeInterfaceTraffic } from "@/api/generated/model/runtimeInterfaceTraffic"
import {
  buildTrafficSeries,
  formatBitRate,
  formatTrafficBytes,
  TRAFFIC_CHART_HEIGHT,
  TRAFFIC_CHART_WIDTH,
} from "@/components/transports/interface-traffic-model"
import { cn } from "@/lib/utils"

export function InterfaceTraffic({
  traffic,
  locale,
  labels,
  className,
  showChart = false,
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
  readonly showChart?: boolean
}) {
  if (!traffic) {
    return null
  }

  return (
    <div className={cn("mt-2 min-w-0 border-t pt-2", className)}>
      {showChart && traffic.history.length >= 2 ? (
        <KeeneticTrafficChart
          labels={labels}
          locale={locale}
          traffic={traffic}
        />
      ) : null}
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
    </div>
  )
}

function KeeneticTrafficChart({
  traffic,
  locale,
  labels,
}: {
  readonly traffic: RuntimeInterfaceTraffic
  readonly locale: string
  readonly labels: Readonly<{
    receive: string
    transmit: string
    chart: string
  }>
}) {
  const series = buildTrafficSeries(traffic)
  const generatedId = useId().replaceAll(":", "")
  const receiveGradientId = `traffic-rx-${generatedId}`
  const transmitGradientId = `traffic-tx-${generatedId}`

  return (
    <figure aria-label={labels.chart} className="mb-3 min-w-0" role="img">
      <div className="relative mt-2">
        <span className="absolute -top-2 right-0 z-10 bg-card pl-2 text-xs leading-4 text-muted-foreground tabular-nums">
          {formatBitRate(series.maximum, locale)}
        </span>
        <svg
          className="h-[162px] w-full overflow-visible"
          preserveAspectRatio="none"
          viewBox={`0 0 ${TRAFFIC_CHART_WIDTH} ${TRAFFIC_CHART_HEIGHT}`}
        >
          <defs>
            <linearGradient id={receiveGradientId} x1="0" x2="0" y1="0" y2="1">
              <stop offset="0" stopColor="var(--traffic-rx-fill-start)" />
              <stop offset="1" stopColor="var(--traffic-rx-fill-end)" />
            </linearGradient>
            <linearGradient id={transmitGradientId} x1="0" x2="0" y1="0" y2="1">
              <stop offset="0" stopColor="var(--traffic-tx-fill-start)" />
              <stop offset="1" stopColor="var(--traffic-tx-fill-end)" />
            </linearGradient>
          </defs>
          <path
            d={`M 0 ${TRAFFIC_CHART_HEIGHT} V 0 H ${TRAFFIC_CHART_WIDTH} V ${TRAFFIC_CHART_HEIGHT}`}
            fill="none"
            stroke="var(--traffic-frame)"
            strokeDasharray="2 2"
            strokeWidth="2"
            vectorEffect="non-scaling-stroke"
          />
          <path
            d={series.rxArea}
            fill={`url(#${receiveGradientId})`}
            stroke="none"
          />
          <path
            d={series.txArea}
            fill={`url(#${transmitGradientId})`}
            stroke="none"
          />
          <polyline
            fill="none"
            points={series.rx}
            stroke="var(--traffic-rx-line)"
            strokeLinejoin="round"
            strokeWidth="1"
            vectorEffect="non-scaling-stroke"
          />
          <polyline
            fill="none"
            points={series.tx}
            stroke="var(--traffic-tx-line)"
            strokeLinejoin="round"
            strokeWidth="1"
            vectorEffect="non-scaling-stroke"
          />
        </svg>
      </div>
      <figcaption className="grid min-w-0 grid-cols-[auto_minmax(0,1fr)_auto] items-start gap-2 text-xs leading-4 text-muted-foreground">
        <time className="tabular-nums">
          {formatSampleTime(series.oldestSampledAt, locale)}
        </time>
        <span className="flex min-w-0 flex-wrap items-center justify-center gap-x-4 gap-y-1 text-center">
          <span className="whitespace-nowrap">
            <TrafficLegendDot className="bg-[var(--traffic-rx-line)]" />
            {labels.receive}:{" "}
            {formatBitRate(traffic.rx_bits_per_second, locale)}
          </span>
          <span className="whitespace-nowrap">
            <TrafficLegendDot className="bg-[var(--traffic-tx-line)]" />
            {labels.transmit}:{" "}
            {formatBitRate(traffic.tx_bits_per_second, locale)}
          </span>
        </span>
        <time className="tabular-nums">
          {formatSampleTime(series.newestSampledAt, locale)}
        </time>
      </figcaption>
    </figure>
  )
}

function TrafficLegendDot({ className }: { readonly className: string }) {
  return (
    <span
      aria-hidden="true"
      className={cn("mr-1 inline-block size-2 rounded-full", className)}
    />
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

function formatSampleTime(
  timestamp: number | undefined,
  locale: string
): string {
  if (timestamp === undefined) {
    return "—"
  }
  return new Intl.DateTimeFormat(locale, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(timestamp)
}
