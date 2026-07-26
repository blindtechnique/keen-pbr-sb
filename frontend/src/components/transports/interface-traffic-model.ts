import type { RuntimeInterfaceTraffic } from "@/api/generated/model/runtimeInterfaceTraffic"

const CHART_WIDTH = 120
const CHART_HEIGHT = 36
const CHART_PADDING = 2

export type TrafficSeries = Readonly<{
  rx: string
  tx: string
}>

export function buildTrafficSeries(
  traffic: Pick<RuntimeInterfaceTraffic, "history">
): TrafficSeries {
  const retained = traffic.history.slice(-120)
  const maximum = Math.max(
    1,
    ...retained.flatMap((point) => [
      finiteNonNegative(point.rx_bits_per_second),
      finiteNonNegative(point.tx_bits_per_second),
    ])
  )

  return {
    rx: polyline(
      retained.map((point) => ({
        ageMs: finiteNonNegative(point.age_ms),
        value: finiteNonNegative(point.rx_bits_per_second),
      })),
      maximum
    ),
    tx: polyline(
      retained.map((point) => ({
        ageMs: finiteNonNegative(point.age_ms),
        value: finiteNonNegative(point.tx_bits_per_second),
      })),
      maximum
    ),
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

  const usableWidth = CHART_WIDTH - CHART_PADDING * 2
  const usableHeight = CHART_HEIGHT - CHART_PADDING * 2
  const maximumAge = Math.max(...samples.map((sample) => sample.ageMs))
  const minimumAge = Math.min(...samples.map((sample) => sample.ageMs))
  const ageSpan = maximumAge - minimumAge
  const divisor = Math.max(1, samples.length - 1)
  return samples
    .map((sample, index) => {
      const relativeX =
        ageSpan > 0
          ? (maximumAge - sample.ageMs) / ageSpan
          : index / divisor
      const x =
        CHART_PADDING +
        Math.max(0, Math.min(1, relativeX)) * usableWidth
      const y =
        CHART_HEIGHT -
        CHART_PADDING -
        (sample.value / maximum) * usableHeight
      return `${x.toFixed(2)},${y.toFixed(2)}`
    })
    .join(" ")
}

function finiteNonNegative(value: number): number {
  return Number.isFinite(value) && value > 0 ? value : 0
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
