import { useId, useState } from "react"
import type { KeyboardEvent, PointerEvent } from "react"

import type { RuntimeInterfaceTraffic } from "@/api/generated/model/runtimeInterfaceTraffic"
import {
  buildTrafficSeries,
  findNearestTrafficSampleIndex,
  formatBitRate,
  formatTrafficBytes,
  TRAFFIC_CHART_HEIGHT,
  TRAFFIC_CHART_WIDTH,
  trafficTooltipTop,
  type TrafficChartSample,
} from "@/components/transports/interface-traffic-model"
import { cn } from "@/lib/utils"

const TRAFFIC_TOOLTIP_HEIGHT = 78
const TRAFFIC_TOOLTIP_BOUNDARY_HEIGHT = 191

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
  const [activeCursor, setActiveCursor] = useState<Readonly<{
    sampleIndex: number
    pointerY: number
  }> | null>(null)
  const activeSample =
    activeCursor === null ? undefined : series.samples[activeCursor.sampleIndex]

  const selectPointerSample = (event: PointerEvent<HTMLDivElement>) => {
    const bounds = event.currentTarget.getBoundingClientRect()
    const chartX =
      ((event.clientX - bounds.left) / Math.max(1, bounds.width)) *
      TRAFFIC_CHART_WIDTH
    const pointerY = Math.max(
      0,
      Math.min(
        TRAFFIC_CHART_HEIGHT,
        ((event.clientY - bounds.top) / Math.max(1, bounds.height)) *
          TRAFFIC_CHART_HEIGHT
      )
    )
    const nearest = findNearestTrafficSampleIndex(series.samples, chartX)
    if (nearest !== undefined) {
      setActiveCursor((current) =>
        current?.sampleIndex === nearest &&
        Math.abs(current.pointerY - pointerY) < 2
          ? current
          : { sampleIndex: nearest, pointerY }
      )
    }
  }

  const selectKeyboardSample = (event: KeyboardEvent<HTMLDivElement>) => {
    const lastIndex = series.samples.length - 1
    if (lastIndex < 0) {
      return
    }

    const current = activeCursor?.sampleIndex ?? lastIndex
    let next: number | undefined
    switch (event.key) {
      case "ArrowLeft":
        next = Math.max(0, current - 1)
        break
      case "ArrowRight":
        next = Math.min(lastIndex, current + 1)
        break
      case "Home":
        next = 0
        break
      case "End":
        next = lastIndex
        break
      default:
        return
    }
    event.preventDefault()
    const sample = series.samples[next]
    if (!sample) {
      return
    }
    setActiveCursor({
      sampleIndex: next,
      pointerY: trafficSampleKeyboardAnchor(sample),
    })
  }

  return (
    <figure aria-label={labels.chart} className="mb-3 min-w-0">
      <div
        aria-label={labels.chart}
        className="relative mt-2 touch-pan-y outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
        onBlur={() => setActiveCursor(null)}
        onFocus={() =>
          setActiveCursor((current) => {
            if (current !== null) {
              return current
            }
            const sampleIndex = series.samples.length - 1
            const sample = series.samples[sampleIndex]
            return sample
              ? {
                  sampleIndex,
                  pointerY: trafficSampleKeyboardAnchor(sample),
                }
              : null
          })
        }
        onKeyDown={selectKeyboardSample}
        onPointerLeave={() => setActiveCursor(null)}
        onPointerMove={selectPointerSample}
        role="group"
        tabIndex={0}
      >
        <span className="absolute -top-2 right-0 z-10 bg-card pl-2 text-xs leading-4 text-muted-foreground tabular-nums">
          {formatBitRate(series.maximum, locale)}
        </span>
        <svg
          className="block h-[162px] w-full overflow-visible"
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
          {activeSample ? <TrafficChartCursor sample={activeSample} /> : null}
        </svg>
        {activeSample ? (
          <>
            <TrafficChartMarkers sample={activeSample} />
            <TrafficSampleTooltip
              labels={labels}
              locale={locale}
              pointerY={activeCursor?.pointerY ?? 0}
              sample={activeSample}
            />
          </>
        ) : null}
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

function TrafficChartCursor({
  sample,
}: {
  readonly sample: TrafficChartSample
}) {
  return (
    <g aria-hidden="true" className="pointer-events-none">
      <line
        stroke="currentColor"
        strokeDasharray="2 2"
        strokeWidth="1"
        vectorEffect="non-scaling-stroke"
        x1={sample.x}
        x2={sample.x}
        y1={0}
        y2={TRAFFIC_CHART_HEIGHT}
      />
    </g>
  )
}

function TrafficChartMarkers({
  sample,
}: {
  readonly sample: TrafficChartSample
}) {
  const left = `${(sample.x / TRAFFIC_CHART_WIDTH) * 100}%`
  return (
    <>
      <TrafficChartMarker
        color="#379dd8"
        halo="#99c7e1"
        left={left}
        top={`${(sample.rxY / TRAFFIC_CHART_HEIGHT) * 100}%`}
      />
      <TrafficChartMarker
        color="#1e7049"
        halo="#80ba9e"
        left={left}
        top={`${(sample.txY / TRAFFIC_CHART_HEIGHT) * 100}%`}
      />
    </>
  )
}

function TrafficChartMarker({
  color,
  halo,
  left,
  top,
}: {
  readonly color: string
  readonly halo: string
  readonly left: string
  readonly top: string
}) {
  return (
    <span
      aria-hidden="true"
      className="pointer-events-none absolute grid size-4 -translate-x-1/2 -translate-y-1/2 place-items-center rounded-full"
      style={{ backgroundColor: halo, left, top }}
    >
      <span
        className="size-2 rounded-full border border-white"
        style={{ backgroundColor: color }}
      />
    </span>
  )
}

function TrafficSampleTooltip({
  sample,
  locale,
  labels,
  pointerY,
}: {
  readonly sample: TrafficChartSample
  readonly locale: string
  readonly labels: Readonly<{
    receive: string
    transmit: string
  }>
  readonly pointerY: number
}) {
  const horizontalPosition = (sample.x / TRAFFIC_CHART_WIDTH) * 100
  const top = trafficTooltipTop(
    pointerY,
    TRAFFIC_TOOLTIP_HEIGHT,
    TRAFFIC_TOOLTIP_BOUNDARY_HEIGHT
  )
  const transform =
    horizontalPosition > 70
      ? "translateX(calc(-100% - 10px))"
      : "translateX(10px)"

  return (
    <div
      className="pointer-events-none absolute z-50 rounded-[4px] bg-white p-2 font-sans text-xs text-[#222] shadow-[0_0_10px_rgba(0,0,0,0.16)] dark:bg-popover dark:text-popover-foreground"
      role="status"
      style={{
        left: `${horizontalPosition}%`,
        top,
        transform,
      }}
    >
      <time className="mb-1 block leading-[14px] text-[#6e6e6e] tabular-nums dark:text-muted-foreground">
        {formatSampleTime(sample.sampledAtUnixMs, locale)}
      </time>
      <TrafficTooltipRate
        direction="receive"
        label={labels.receive}
        value={formatBitRate(sample.rxBitsPerSecond, locale)}
      />
      <TrafficTooltipRate
        direction="transmit"
        label={labels.transmit}
        value={formatBitRate(sample.txBitsPerSecond, locale)}
      />
    </div>
  )
}

function trafficSampleKeyboardAnchor(sample: TrafficChartSample): number {
  return (sample.rxY + sample.txY) / 2
}

function TrafficTooltipRate({
  direction,
  label,
  value,
}: {
  readonly direction: "receive" | "transmit"
  readonly label: string
  readonly value: string
}) {
  const receive = direction === "receive"
  return (
    <div
      aria-label={`${label}: ${value}`}
      className="flex h-[22px] items-center whitespace-nowrap"
    >
      <span
        aria-hidden="true"
        className={cn(
          "grid size-3 shrink-0 place-items-center rounded-full text-white",
          receive ? "bg-[#379dd8]" : "bg-[#1e7049]"
        )}
      >
        <svg className="size-2" fill="none" viewBox="0 0 8 8">
          <path
            d={receive ? "M4 1v5M2 4l2 2 2-2" : "M4 7V2M2 4l2-2 2 2"}
            stroke="currentColor"
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth="1"
          />
        </svg>
      </span>
      <span className="ml-1 leading-[22px] tabular-nums">{value}</span>
    </div>
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
