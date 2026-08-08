import type { RuntimeInterfaceTraffic } from "@/api/generated/model/runtimeInterfaceTraffic"

export const TRAFFIC_CHART_WIDTH = 744
export const TRAFFIC_CHART_HEIGHT = 162

export type TrafficChartSample = Readonly<{
  x: number
  rxY: number
  txY: number
  rxBitsPerSecond: number
  txBitsPerSecond: number
  sampledAtUnixMs?: number
}>

export type TrafficSeries = Readonly<{
  rx: string
  tx: string
  rxArea: string
  txArea: string
  samples: readonly TrafficChartSample[]
  maximum: number
  hasTraffic: boolean
  oldestSampledAt?: number
  newestSampledAt?: number
}>

export function buildTrafficSeries(
  traffic: Pick<RuntimeInterfaceTraffic, "history" | "sampled_at_unix_ms">
): TrafficSeries {
  const retained = traffic.history.slice(-120)
  const rawMaximum = Math.max(
    0,
    ...retained.flatMap((point) => [
      finiteNonNegative(point.rx_bits_per_second),
      finiteNonNegative(point.tx_bits_per_second),
    ])
  )
  const maximum = niceMaximum(rawMaximum)
  const newestSampledAt = finiteTimestamp(traffic.sampled_at_unix_ms)
  const samples = chartSamples(retained, maximum, newestSampledAt)
  const rx = samples
    .map((sample) => `${sample.x.toFixed(2)},${sample.rxY.toFixed(2)}`)
    .join(" ")
  const tx = samples
    .map((sample) => `${sample.x.toFixed(2)},${sample.txY.toFixed(2)}`)
    .join(" ")
  const oldestAge = retained.reduce(
    (oldest, point) => Math.max(oldest, finiteNonNegative(point.age_ms)),
    0
  )

  return {
    rx,
    tx,
    rxArea: area(rx),
    txArea: area(tx),
    samples,
    maximum,
    hasTraffic: rawMaximum > 0,
    oldestSampledAt:
      newestSampledAt === undefined ? undefined : newestSampledAt - oldestAge,
    newestSampledAt,
  }
}

export function findNearestTrafficSampleIndex(
  samples: readonly TrafficChartSample[],
  chartX: number
): number | undefined {
  if (samples.length === 0 || !Number.isFinite(chartX)) {
    return undefined
  }

  const target = Math.max(0, Math.min(TRAFFIC_CHART_WIDTH, chartX))
  let low = 0
  let high = samples.length - 1

  while (low < high) {
    const middle = Math.floor((low + high) / 2)
    if (samples[middle].x < target) {
      low = middle + 1
    } else {
      high = middle
    }
  }

  if (low === 0) {
    return 0
  }

  const before = samples[low - 1]
  const after = samples[low]
  return target - before.x <= after.x - target ? low - 1 : low
}

export function trafficTooltipTop(
  pointerY: number,
  tooltipHeight: number,
  containerHeight: number
): number {
  const safeContainerHeight =
    Number.isFinite(containerHeight) && containerHeight > 0
      ? containerHeight
      : 0
  const safeTooltipHeight =
    Number.isFinite(tooltipHeight) && tooltipHeight > 0
      ? Math.min(tooltipHeight, safeContainerHeight)
      : 0
  const maximumTop = Math.max(0, safeContainerHeight - safeTooltipHeight)
  const anchor = Number.isFinite(pointerY)
    ? Math.max(0, Math.min(safeContainerHeight, pointerY))
    : 0
  return Math.max(0, Math.min(maximumTop, anchor + 16))
}

export function formatBitRate(
  value: number | undefined,
  locale: string
): string {
  if (!Number.isFinite(value) || value === undefined || value < 0) {
    return "—"
  }
  return formatScaled(
    value,
    locale,
    locale.toLowerCase().startsWith("ru")
      ? ["бит/с", "кбит/с", "Мбит/с", "Гбит/с"]
      : ["bit/s", "kbit/s", "Mbit/s", "Gbit/s"],
    1000
  )
}

export function formatTrafficBytes(
  value: number | undefined,
  locale: string
): string {
  if (!Number.isFinite(value) || value === undefined || value < 0) {
    return "—"
  }
  return formatScaled(
    value,
    locale,
    locale.toLowerCase().startsWith("ru")
      ? ["Б", "КБ", "МБ", "ГБ", "ТБ"]
      : ["B", "KB", "MB", "GB", "TB"],
    1024
  )
}

function chartSamples(
  points: RuntimeInterfaceTraffic["history"],
  maximum: number,
  newestSampledAt: number | undefined
): readonly TrafficChartSample[] {
  if (points.length === 0) {
    return []
  }

  const maximumAge = Math.max(
    ...points.map((point) => finiteNonNegative(point.age_ms))
  )
  const minimumAge = Math.min(
    ...points.map((point) => finiteNonNegative(point.age_ms))
  )
  const ageSpan = maximumAge - minimumAge
  const divisor = Math.max(1, points.length - 1)
  return points.map((point, index) => {
    const ageMs = finiteNonNegative(point.age_ms)
    const relativeX =
      ageSpan > 0 ? (maximumAge - ageMs) / ageSpan : index / divisor
    const x = Math.max(0, Math.min(1, relativeX)) * TRAFFIC_CHART_WIDTH
    const rxBitsPerSecond = finiteNonNegative(point.rx_bits_per_second)
    const txBitsPerSecond = finiteNonNegative(point.tx_bits_per_second)
    return {
      x,
      rxY:
        TRAFFIC_CHART_HEIGHT -
        (rxBitsPerSecond / maximum) * TRAFFIC_CHART_HEIGHT,
      txY:
        TRAFFIC_CHART_HEIGHT -
        (txBitsPerSecond / maximum) * TRAFFIC_CHART_HEIGHT,
      rxBitsPerSecond,
      txBitsPerSecond,
      sampledAtUnixMs:
        newestSampledAt === undefined ? undefined : newestSampledAt - ageMs,
    }
  })
}

function area(points: string): string {
  if (!points) {
    return ""
  }
  return `M 0 ${TRAFFIC_CHART_HEIGHT} L ${points.replaceAll(" ", " L ")} L ${TRAFFIC_CHART_WIDTH} ${TRAFFIC_CHART_HEIGHT} Z`
}

function niceMaximum(rawMaximum: number): number {
  if (!Number.isFinite(rawMaximum) || rawMaximum <= 0) {
    return 1
  }

  const exponent = Math.floor(Math.log10(rawMaximum))
  const magnitude = 10 ** exponent
  const normalized = rawMaximum / magnitude
  const step =
    normalized <= 1 ? 1 : normalized <= 2 ? 2 : normalized <= 5 ? 5 : 10
  return step * magnitude
}

function finiteNonNegative(value: number): number {
  return Number.isFinite(value) && value > 0 ? value : 0
}

function finiteTimestamp(value: number | undefined): number | undefined {
  return value !== undefined && Number.isFinite(value) && value >= 0
    ? value
    : undefined
}

function formatScaled(
  rawValue: number,
  locale: string,
  units: readonly string[],
  base: number
): string {
  let value = rawValue
  let unitIndex = 0
  while (value >= base && unitIndex < units.length - 1) {
    value /= base
    unitIndex += 1
  }
  return `${new Intl.NumberFormat(locale, {
    maximumFractionDigits: value >= 100 ? 0 : value >= 10 ? 1 : 2,
  }).format(value)} ${units[unitIndex]}`
}
