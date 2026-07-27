import type { RuntimeInterfaceTraffic } from "@/api/generated/model/runtimeInterfaceTraffic"

export const TRAFFIC_CHART_WIDTH = 744
export const TRAFFIC_CHART_HEIGHT = 162

export type TrafficSeries = Readonly<{
  rx: string
  tx: string
  rxArea: string
  txArea: string
  maximum: number
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
  const rx = polyline(
    retained.map((point) => ({
      ageMs: finiteNonNegative(point.age_ms),
      value: finiteNonNegative(point.rx_bits_per_second),
    })),
    maximum
  )
  const tx = polyline(
    retained.map((point) => ({
      ageMs: finiteNonNegative(point.age_ms),
      value: finiteNonNegative(point.tx_bits_per_second),
    })),
    maximum
  )
  const newestSampledAt = finiteTimestamp(traffic.sampled_at_unix_ms)
  const oldestAge = retained.reduce(
    (oldest, point) => Math.max(oldest, finiteNonNegative(point.age_ms)),
    0
  )

  return {
    rx,
    tx,
    rxArea: area(rx),
    txArea: area(tx),
    maximum,
    oldestSampledAt:
      newestSampledAt === undefined ? undefined : newestSampledAt - oldestAge,
    newestSampledAt,
  }
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

function polyline(
  samples: readonly Readonly<{ ageMs: number; value: number }>[],
  maximum: number
): string {
  if (samples.length === 0) {
    return ""
  }

  const maximumAge = Math.max(...samples.map((sample) => sample.ageMs))
  const minimumAge = Math.min(...samples.map((sample) => sample.ageMs))
  const ageSpan = maximumAge - minimumAge
  const divisor = Math.max(1, samples.length - 1)
  return samples
    .map((sample, index) => {
      const relativeX =
        ageSpan > 0 ? (maximumAge - sample.ageMs) / ageSpan : index / divisor
      const x = Math.max(0, Math.min(1, relativeX)) * TRAFFIC_CHART_WIDTH
      const y =
        TRAFFIC_CHART_HEIGHT - (sample.value / maximum) * TRAFFIC_CHART_HEIGHT
      return `${x.toFixed(2)},${y.toFixed(2)}`
    })
    .join(" ")
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
